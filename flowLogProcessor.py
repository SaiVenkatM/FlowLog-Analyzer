import csv
from collections import defaultdict
from typing import Dict, Tuple, List, Optional
import os
import logging
import argparse

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
    mapping_rules (Dict[Tuple[str, str], str]): Mapping rules
    tag_counts (Dict[str, int]): Tag counts
    port_protocol_counts (Dict[Tuple[str, str], int]): Port/Protocol combination counts
    untagged_count (int): Untagged count
    processed_lines (int): Processed lines count
    skipped_lines (int): Skipped lines
    """

    def __init__(self, flow_log_file: str, mapping_file: str, output_file: str,
                 delimiter: str = ' ', log_field_names: Optional[List[str]] = None):
        """
        Intialize the FlowLogProcessor object with File paths and other attributes.

        """
        self.flow_log_file = flow_log_file
        self.mapping_file = mapping_file
        self.output_file = output_file
        self.delimiter = delimiter
        self.log_field_names = log_field_names
        self.mapping_rules: Dict[Tuple[str, str], str] = {}
        self.tag_counts: Dict[str, int] = defaultdict(int)
        self.port_protocol_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        self.untagged_count: int = 0
        self.processed_lines: int = 0
        self.skipped_lines: int = 0

    def _sanitize_string(self, value: str) -> str:
        """
        Remove leading and trailing whitespaces from a string.

        Args:
        value (str): Input string

        Returns:
        str: Sanitized string        
        """
        return value.strip()

    def _sanitize_integer(self, value: str) -> Optional[int]:
        """
        Convert a string to an integer if possible.
        
        Args:
        value (str): Input string     
        
        Returns:
        Optional[int]: Integer value
        """
        try:
            return int(self._sanitize_string(value))
        except ValueError:
            return None

    def load_mapping_rules(self) -> None:
        """
        Load the mapping rules from the mapping file into a dictionary.
        """
        try:
            if not os.path.isfile(self.mapping_file):
                raise FileNotFoundError(f"Mapping file '{self.mapping_file}' not found.")

            with open(self.mapping_file, 'r', newline='', encoding='ascii') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    dstport = self._sanitize_integer(row.get('dstport'))
                    protocol = self._sanitize_string(row.get('protocol', '').lower())
                    tag = self._sanitize_string(row.get('tag'))

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
        """
        Process the flow logs and update the tag and port/protocol counts based on the mapping rules.
        """
        try:
            if not os.path.isfile(self.flow_log_file):
                raise FileNotFoundError(f"Flow log file '{self.flow_log_file}' not found.")

            with open(self.flow_log_file, 'r', encoding='ascii') as logfile:
                for line_number, line in enumerate(logfile, 1):
                    self.processed_lines += 1
                    parts = [self._sanitize_string(part) for part in line.strip().split(self.delimiter)]

                    if self.log_field_names:
                        if len(parts) != len(self.log_field_names):
                            logging.warning(f"Line {line_number}: Field count mismatch. Skipped.")
                            self.skipped_lines += 1
                            continue
                        log_entry = dict(zip(self.log_field_names, parts))
                        dstport = str(log_entry.get('dstport'))
                        protocol = log_entry.get('protocol', '').lower()

                    else:
                        if len(parts) >= 8:
                            dstport = parts[5]
                            protocol = parts[7].lower()
                        else:
                            logging.warning(f"Line {line_number}: Malformed line. Skipped.")
                            self.skipped_lines += 1
                            continue

                    if dstport and protocol:
                        self.port_protocol_counts[(dstport, protocol)] += 1
                        tag = self.mapping_rules.get((dstport, protocol))
                        if tag:
                            self.tag_counts[tag] += 1
                        else:
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

    def generate_report(self) -> None:
        """
        Generate the reports and write them to the output file.
        """
        try:
            with open(self.output_file, 'w', encoding='ascii') as outfile:
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
        try:
            self.load_mapping_rules()
            self.process_flow_logs()
            self.generate_report()
            logging.info("Flow log processing completed successfully.")
        except Exception as e:
            logging.critical(f"Flow log processing failed: {e}")
            raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process flow logs.")
    parser.add_argument("flow_log_file", help="Path to the flow log file.")
    parser.add_argument("mapping_file", help="Path to the mapping rules file.")
    parser.add_argument("output_file", help="Path to the output file.")
    parser.add_argument("--delimiter", default=" ", help="Delimiter for flow log file.")
    args = parser.parse_args()

    processor = FlowLogProcessor(
        args.flow_log_file,
        args.mapping_file,
        args.output_file,
        delimiter=args.delimiter,
    )
    processor.run()