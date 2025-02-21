import os
import csv
import logging
import argparse
from collections import defaultdict
from typing import Dict, Tuple, List, Optional


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FlowLogProcessor:
    """
    Process the flow logs (AWS Flow Logs format) based on the mapping rules and write the specific metrics to an output file.

    Attributes:
    flow_log_file (str): Path to the flow log file.
    mapping_file (str): Path to the mapping rules file.
    output_file (str): Path to the output file.
    delimiter (str): Delimiter for flow log file.
    log_field_names (List[str]): Field names for flow log file.
    protocol_mapping_file (str): Path to IANA protocol mapping CSV file.
    mapping_rules (Dict[Tuple[str, str], str]): Mapping rules
    tag_counts (Dict[str, int]): Tag counts
    port_protocol_counts (Dict[Tuple[str, str], int]): Port/Protocol combination counts
    untagged_count (int): Untagged count
    processed_lines (int): Processed lines count
    skipped_lines (int): Skipped lines
    """

    FIELD_MAPPING = {
        "version": (0, int), "account-id": (1, str), "interface-id": (2, str), "srcaddr": (3, str),
        "dstaddr": (4, str), "srcport": (5, int), "dstport": (6, int), "protocol": (7, int),
        "packets": (8, int), "bytes": (9, int), "start": (10, int), "end": (11, int),
        "action": (12, str), "log-status": (13, str), "vpc-id": (14, str), "subnet-id": (15, str),
        "instance-id": (16, str), "tcp-flags": (17, int), "type": (18, str),
        "pkt-srcaddr": (19, str), "pkt-dstaddr": (20, str), "region": (21, str),
        "az-id": (22, str), "sublocation-type": (23, str), "sublocation-id": (24, str),
        "pkt-src-aws-service": (25, str), "pkt-dst-aws-service": (26, str),
        "flow-direction": (27, str), "traffic-path": (28, int), "ecs-cluster-arn": (29, str),
        "ecs-cluster-name": (30, str), "ecs-container-instance-arn": (31, str),
        "ecs-container-instance-id": (32, str), "ecs-container-id": (33, str),
        "ecs-second-container-id": (34, str), "ecs-service-name": (35, str),
        "ecs-task-definition-arn": (36, str), "ecs-task-arn": (37, str),
        "ecs-task-id": (38, str), "reject-reason": (39, str),
    }

    # Protocol number to name mapping will be loaded from CSV if available
    PROTOCOL_NUMBER_TO_NAME = {}

    def __init__(self, flow_log_file: str, mapping_file: str, output_file: str,
                 delimiter: str = ' ', log_field_names: Optional[List[str]] = None,
                 protocol_mapping_file: Optional[str] = None):
        self.flow_log_file = flow_log_file
        self.mapping_file = mapping_file
        self.output_file = output_file
        self.delimiter = delimiter
        self.log_field_names = log_field_names
        self.protocol_mapping_file = protocol_mapping_file
        self.mapping_rules: Dict[Tuple[str, str], str] = {}
        self.tag_counts: Dict[str, int] = defaultdict(int)
        self.port_protocol_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        self.untagged_count: int = 0
        self.processed_lines: int = 0
        self.skipped_lines: int = 0
        
        # Load protocol mappings
        self.load_protocol_mappings()

    def _sanitize_value(self, value: str, data_type):
        """
        Convert the value to the specified data type.
        If the value is "-", return None.
        If the conversion fails, return None.
        """
        if value == "-":
            return None
        try:
            return data_type(value)
        except ValueError:
            return None

    def load_protocol_mappings(self) -> None:
        """
        Load protocol mappings from CSV file if available.
        Falls back to common protocols if file not available.
        """
        # Start with common protocols as fallback
        common_protocols = {
            "1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", 
            "51": "ah", "58": "ipv6-icmp", "132": "sctp"
        }
        
        # First try to load from specified file
        if self.protocol_mapping_file and os.path.isfile(self.protocol_mapping_file):
            try:
                with open(self.protocol_mapping_file, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        if 'Decimal' in row and 'Keyword' in row:
                            number = row['Decimal'].strip()
                            name = row['Keyword'].strip().lower()
                            if number and name:
                                self.PROTOCOL_NUMBER_TO_NAME[number] = name
                                
                logging.info(f"Loaded {len(self.PROTOCOL_NUMBER_TO_NAME)} protocol mappings from {self.protocol_mapping_file}")
                return
            except Exception as e:
                logging.warning(f"Error loading protocol mappings from file: {e}")
                
        # If no file or error loading, use common protocols
        self.PROTOCOL_NUMBER_TO_NAME = common_protocols
        logging.info("Using built-in protocol mappings")
        
    def _protocol_number_to_name(self, protocol_number: str) -> str:
        """Convert a protocol number to its name using IANA registry mapping."""
        return self.PROTOCOL_NUMBER_TO_NAME.get(protocol_number, protocol_number)

    def load_mapping_rules(self) -> None:
        """Load mapping rules from the mapping file."""
        try:
            if not os.path.isfile(self.mapping_file):
                raise FileNotFoundError(f"Mapping file '{self.mapping_file}' not found.")

            with open(self.mapping_file, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    dstport = self._sanitize_value(row.get('dstport', ''), int)
                    protocol = row.get('protocol', '').lower().strip()
                    tag = row.get('tag', '').strip()

                    if dstport is not None and protocol and tag:
                        self.mapping_rules[(str(dstport), protocol)] = tag
                    else:
                        logging.warning(f"Invalid mapping rule: {row}")

        except FileNotFoundError as e:
            logging.error(f"Mapping rules error: {e}")
            raise
        except csv.Error as e:
            logging.error(f"CSV error in mapping rules: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error loading mapping rules: {e}")
            raise

    def process_flow_logs(self) -> None:
        """Process the flow logs and update the tag counts and port/protocol combination counts."""
        try:
            if not os.path.isfile(self.flow_log_file):
                raise FileNotFoundError(f"Flow log file '{self.flow_log_file}' not found.")

            with open(self.flow_log_file, 'r', encoding='utf-8') as logfile:
                for line_number, line in enumerate(logfile, 1):
                    self.processed_lines += 1
                    parts = [part.strip() for part in line.strip().split(self.delimiter)]

                    if self.log_field_names:
                        if len(parts) != len(self.log_field_names):
                            logging.warning(f"Line {line_number}: Field count mismatch. Skipped.")
                            self.skipped_lines += 1
                            continue
                        log_entry = {}
                        for i, field_name in enumerate(self.log_field_names):
                            if field_name in self.FIELD_MAPPING:
                                data_type = self.FIELD_MAPPING[field_name][1]
                                log_entry[field_name] = self._sanitize_value(parts[i], data_type)
                            else:
                                logging.warning(f"Line {line_number}: Unknown field name: {field_name}. Skipped.")
                                self.skipped_lines += 1
                                continue
                        dstport = str(log_entry.get('dstport'))
                        
                        # Get protocol number and convert to protocol name
                        protocol_number = str(log_entry.get('protocol'))
                        protocol_name = self._protocol_number_to_name(protocol_number)
                    else:
                        # Default V2 flow log format
                        if len(parts) >= 14:
                            dstport = parts[6]
                            # Get protocol number and convert to protocol name
                            protocol_number = parts[7]
                            protocol_name = self._protocol_number_to_name(protocol_number)
                        else:
                            logging.warning(f"Line {line_number}: Malformed default v2 line. Skipped.")
                            self.skipped_lines += 1
                            continue

                    if dstport and protocol_name:
                        # Store counts using both protocol number and name for debugging
                        self.port_protocol_counts[(dstport, protocol_name)] += 1
                        
                        # Look up tag using protocol name (from mapping file)
                        tag = self.mapping_rules.get((dstport, protocol_name))
                        if tag:
                            self.tag_counts[tag] += 1
                        else:
                            # If not found with protocol name, log for debugging
                            logging.debug(f"Line {line_number}: No tag for port={dstport}, protocol={protocol_name} (number={protocol_number})")
                            self.untagged_count += 1
                    else:
                        logging.warning(f"Line {line_number}: Missing dstport or protocol. Skipped.")
                        self.skipped_lines += 1

        except FileNotFoundError as e:
            logging.error(f"Flow log error: {e}")
            raise
        except Exception as e:
            logging.error(f"Error processing flow logs: {e}")
            raise

    def generate_reports(self) -> None:
        """Generate reports and write to the output file."""
        try:
            with open(self.output_file, 'w', encoding='utf-8') as outfile:
                outfile.write("Tag Counts:\n")
                outfile.write("Tag,Count\n")
                for tag, count in sorted(self.tag_counts.items()):
                    outfile.write(f"{tag},{count}\n")
                outfile.write(f"Untagged,{self.untagged_count}\n\n")

                outfile.write("Port/Protocol Combination Counts:\n")
                outfile.write("Port,Protocol,Count\n")
                for (port, protocol), count in sorted(self.port_protocol_counts.items()):
                    outfile.write(f"{port},{protocol},{count}\n")

                outfile.write(f"\nProcessed Lines: {self.processed_lines}\n")
                outfile.write(f"Skipped Lines: {self.skipped_lines}\n")

        except Exception as e:
            logging.error(f"Error writing reports: {e}")
            raise

    def run(self) -> None:
        """Run the flow log processing."""
        try:
            self.load_mapping_rules()
            self.process_flow_logs()
            self.generate_reports()
            logging.info("Flow log processing completed successfully.")

        except Exception as e:
            logging.error(f"Flow log processing failed: {e}")

if __name__ == "__main__":
    """
    Example usage: 
    python flowLogProcessor.py flow_logs.txt mapping.csv output.txt --delimiter ' ' --log_field_names version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
    """
    parser = argparse.ArgumentParser(description="Process flow logs.")
    parser.add_argument("flow_log_file", help="Path to the flow log file.")
    parser.add_argument("mapping_file", help="Path to the mapping rules file.")
    parser.add_argument("output_file", help="Path to the output file.")
    parser.add_argument("--delimiter", default=" ", help="Delimiter for flow log file.")
    parser.add_argument("--log_field_names", nargs='+', help="Field names for custom log format.")
    parser.add_argument("--protocol_mapping_file", help="Path to IANA protocol mapping CSV file.")
    args = parser.parse_args()

    processor = FlowLogProcessor(
        args.flow_log_file,
        args.mapping_file,
        args.output_file,
        delimiter=args.delimiter,
        log_field_names=args.log_field_names,
        protocol_mapping_file=args.protocol_mapping_file
    )
    processor.run()