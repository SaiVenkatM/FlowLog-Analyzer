import csv
import random
import os
import json
import argparse
from typing import List, Dict, Any, Tuple

class FlowLogGenerator:
    """Generate AWS VPC Flow Logs in different versions and formats."""
    
    def __init__(self):
        # Base field definitions with their data types and generation functions
        self.field_definitions = {
            # Version 2 fields
            "version": (int, lambda: random.choice([2, 3, 4, 5, 7])),
            "account-id": (str, lambda: str(random.randint(100000000000, 999999999999))),
            "interface-id": (str, lambda: f"eni-{random.randint(1000000, 9999999)}b8ca{random.randint(100000000, 999999999)}"),
            "srcaddr": (str, lambda: f"172.31.{random.randint(0, 255)}.{random.randint(0, 255)}"),
            "dstaddr": (str, lambda: f"172.31.{random.randint(0, 255)}.{random.randint(0, 255)}"),
            "srcport": (int, lambda: random.randint(1024, 65535)),
            "dstport": (int, lambda: random.choice(self.common_ports + [random.randint(1024, 65535)])),
            "protocol": (int, lambda: random.choice([6, 17, 1])),  # TCP, UDP, ICMP
            "packets": (int, lambda: random.randint(1, 10000)),
            "bytes": (int, lambda: random.randint(64, 1500000)),
            "start": (int, lambda: random.randint(1612345600, 1612345600 + 86400*30)),  # One month range
            "end": (int, lambda: random.randint(1612345600, 1612345600 + 86400*30)),
            "action": (str, lambda: random.choice(["ACCEPT", "REJECT"])),
            "log-status": (str, lambda: random.choice(["OK", "NODATA", "SKIPDATA"])),
            
            # Version 3 fields
            "vpc-id": (str, lambda: f"vpc-{random.randint(1000000, 9999999)}"),
            "subnet-id": (str, lambda: f"subnet-{random.randint(1000000, 9999999)}"),
            "instance-id": (str, lambda: random.choice([f"i-{random.randint(1000000, 9999999)}", "-"])),
            "tcp-flags": (int, lambda: random.choice([0, 1, 2, 4, 18, 19])),  # Various TCP flag combinations
            "type": (str, lambda: random.choice(["IPv4", "IPv6"])),
            "pkt-srcaddr": (str, lambda: f"172.31.{random.randint(0, 255)}.{random.randint(0, 255)}"),
            "pkt-dstaddr": (str, lambda: f"172.31.{random.randint(0, 255)}.{random.randint(0, 255)}"),
            
            # Version 4 fields
            "region": (str, lambda: random.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"])),
            "az-id": (str, lambda: random.choice([f"use1-az{random.randint(1, 6)}", "-"])),
            "sublocation-type": (str, lambda: random.choice(["wavelength", "outpost", "localzone", "-"])),
            "sublocation-id": (str, lambda: random.choice([f"subnet-{random.randint(1000000, 9999999)}", "-"])),
            
            # Version 5 fields
            "pkt-src-aws-service": (str, lambda: random.choice(["AMAZON", "S3", "DYNAMODB", "EC2", "-"])),
            "pkt-dst-aws-service": (str, lambda: random.choice(["AMAZON", "S3", "DYNAMODB", "EC2", "-"])),
            "flow-direction": (str, lambda: random.choice(["ingress", "egress"])),
            "traffic-path": (int, lambda: random.choice([1, 2, 3, 4, 5, 6, 7, 8, "-"])),
            
            # Version 7 fields (ECS)
            "ecs-cluster-arn": (str, lambda: random.choice([f"arn:aws:ecs:region:account:cluster/cluster-{random.randint(1000, 9999)}", "-"])),
            "ecs-cluster-name": (str, lambda: random.choice([f"cluster-{random.randint(1000, 9999)}", "-"])),
            "ecs-container-instance-arn": (str, lambda: random.choice([f"arn:aws:ecs:region:account:container-instance/{random.randint(1000000, 9999999)}", "-"])),
            "ecs-container-instance-id": (str, lambda: random.choice([f"{random.randint(1000000, 9999999)}", "-"])),
            "ecs-container-id": (str, lambda: random.choice([f"{random.randint(1000000, 9999999)}", "-"])),
            "ecs-second-container-id": (str, lambda: random.choice([f"{random.randint(1000000, 9999999)}", "-"])),
            "ecs-service-name": (str, lambda: random.choice([f"service-{random.randint(1000, 9999)}", "-"])),
            "ecs-task-definition-arn": (str, lambda: random.choice([f"arn:aws:ecs:region:account:task-definition/task-{random.randint(1000, 9999)}", "-"])),
            "ecs-task-arn": (str, lambda: random.choice([f"arn:aws:ecs:region:account:task/{random.randint(1000000, 9999999)}", "-"])),
            "ecs-task-id": (str, lambda: random.choice([f"{random.randint(1000000, 9999999)}", "-"])),
            
            # Additional fields
            "reject-reason": (str, lambda: random.choice(["BPA", "-"]))
        }
        
        # Common ports for realistic distribution
        self.common_ports = [22, 25, 53, 80, 110, 123, 143, 443, 465, 993, 995, 3306, 3389, 5432, 8080]
        
        # Define field sets for each version
        self.version_fields = {
            2: [
                "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", 
                "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status"
            ],
            3: [
                "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", 
                "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status",
                "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr"
            ],
            4: [
                "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", 
                "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status",
                "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr",
                "region", "az-id", "sublocation-type", "sublocation-id"
            ],
            5: [
                "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", 
                "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status",
                "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr",
                "region", "az-id", "sublocation-type", "sublocation-id",
                "pkt-src-aws-service", "pkt-dst-aws-service", "flow-direction", "traffic-path"
            ],
            7: [
                "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", 
                "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status",
                "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr",
                "region", "az-id", "sublocation-type", "sublocation-id",
                "pkt-src-aws-service", "pkt-dst-aws-service", "flow-direction", "traffic-path",
                "ecs-cluster-arn", "ecs-cluster-name", "ecs-container-instance-arn", "ecs-container-instance-id",
                "ecs-container-id", "ecs-second-container-id", "ecs-service-name", "ecs-task-definition-arn",
                "ecs-task-arn", "ecs-task-id", "reject-reason"
            ]
        }
        
        # Custom field sets for specific testing scenarios
        self.custom_field_sets = {
            "network_security": [
                "account-id", "vpc-id", "srcaddr", "dstaddr", "srcport", "dstport", 
                "protocol", "action", "tcp-flags", "flow-direction"
            ],
            "traffic_analysis": [
                "start", "end", "srcaddr", "dstaddr", "packets", "bytes", 
                "flow-direction", "traffic-path", "pkt-src-aws-service", "pkt-dst-aws-service"
            ],
            "container_tracking": [
                "account-id", "vpc-id", "srcaddr", "dstaddr", "srcport", "dstport", 
                "protocol", "action", "ecs-cluster-name", "ecs-service-name", "ecs-task-id"
            ],
            "minimal": [
                "srcaddr", "dstaddr", "dstport", "protocol", "action"
            ]
        }
        
        # Define protocol name to number mapping based on IANA protocol numbers
        # Comprehensive mapping from the IANA registry
        self.protocol_map = {
            "hopopt": 0, "icmp": 1, "igmp": 2, "ggp": 3, "ipv4": 4, "st": 5, 
            "tcp": 6, "cbt": 7, "egp": 8, "igp": 9, "bbn-rcc-mon": 10, 
            "nvp-ii": 11, "pup": 12, "argus": 13, "emcon": 14, "xnet": 15, 
            "chaos": 16, "udp": 17, "mux": 18, "dcn-meas": 19, "hmp": 20, 
            "prm": 21, "xns-idp": 22, "trunk-1": 23, "trunk-2": 24, "leaf-1": 25, 
            "leaf-2": 26, "rdp": 27, "irtp": 28, "iso-tp4": 29, "netblt": 30, 
            "mfe-nsp": 31, "merit-inp": 32, "dccp": 33, "3pc": 34, "idpr": 35, 
            "xtp": 36, "ddp": 37, "idpr-cmtp": 38, "tp++": 39, "il": 40, 
            "ipv6": 41, "sdrp": 42, "ipv6-route": 43, "ipv6-frag": 44, "idrp": 45, 
            "rsvp": 46, "gre": 47, "dsr": 48, "bna": 49, "esp": 50, 
            "ah": 51, "i-nlsp": 52, "swipe": 53, "narp": 54, "min-ipv4": 55, 
            "tlsp": 56, "skip": 57, "ipv6-icmp": 58, "ipv6-nonxt": 59, "ipv6-opts": 60, 
            "cftp": 62, "sat-expak": 64, "kryptolan": 65, "rvd": 66, "ippc": 67, 
            "sat-mon": 69, "visa": 70, "ipcv": 71, "cpnx": 72, "cphb": 73, 
            "wsn": 74, "pvp": 75, "br-sat-mon": 76, "sun-nd": 77, "wb-mon": 78, 
            "wb-expak": 79, "iso-ip": 80, "vmtp": 81, "secure-vmtp": 82, "vines": 83, 
            "iptm": 84, "nsfnet-igp": 85, "dgp": 86, "tcf": 87, "eigrp": 88, 
            "ospfigp": 89, "sprite-rpc": 90, "larp": 91, "mtp": 92, "ax.25": 93, 
            "ipip": 94, "micp": 95, "scc-sp": 96, "etherip": 97, "encap": 98, 
            "gmtp": 100, "ifmp": 101, "pnni": 102, "pim": 103, "aris": 104, 
            "scps": 105, "qnx": 106, "a/n": 107, "ipcomp": 108, "snp": 109, 
            "compaq-peer": 110, "ipx-in-ip": 111, "vrrp": 112, "pgm": 113, 
            "l2tp": 115, "ddx": 116, "iatp": 117, "stp": 118, "srp": 119, 
            "uti": 120, "smp": 121, "sm": 122, "ptp": 123, "isis": 124, 
            "fire": 125, "crtp": 126, "crudp": 127, "sscopmce": 128, "iplt": 129, 
            "sps": 130, "pipe": 131, "sctp": 132, "fc": 133, "rsvp-e2e-ignore": 134, 
            "mobility": 135, "udplite": 136, "mpls-in-ip": 137, "manet": 138, "hip": 139, 
            "shim6": 140, "wesp": 141, "rohc": 142, "ethernet": 143, "aggfrag": 144,
            "nsh": 145, "homa": 146, "bit-emu": 147
        }
        
        # Reverse mapping (number to name) for generating logs
        self.number_to_protocol = {v: k for k, v in self.protocol_map.items()}
        
    def generate_mapping_file(self, filename: str, num_entries: int = 20) -> None:
        """Generate a mapping file for port/protocol combinations."""
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["dstport", "protocol", "tag"])
            
            # Add common service mappings with protocol names
            entries = [
                (25, "tcp", "mail_smtp"),
                (53, "udp", "dns"),
                (80, "tcp", "http"),
                (443, "tcp", "https"),
                (22, "tcp", "ssh"),
                (3389, "tcp", "rdp"),
                (0, "icmp", "ping"),
                (110, "tcp", "mail_pop3"),
                (993, "tcp", "mail_imap_ssl"),
                (143, "tcp", "mail_imap"),
                (3306, "tcp", "mysql"),
                (5432, "tcp", "postgresql"),
                (1433, "tcp", "mssql"),
                (8080, "tcp", "http_alt"),
                (8443, "tcp", "https_alt")
            ]
            
            # Add additional random entries with protocol names
            services = ["app", "api", "auth", "cache", "db", "storage", "streaming"]
            # Define protocol names with their weights
            protocols = [
                ("tcp", 90),   # TCP - 90% probability
                ("udp", 8),    # UDP - 8% probability
                ("icmp", 1),   # ICMP - 1% probability
                ("sctp", 1)    # SCTP - 1% probability
            ]
            
            for _ in range(num_entries - len(entries)):
                port = random.randint(1024, 65535)
                # Select protocol based on weighted probability
                protocol = random.choices(
                    [p[0] for p in protocols],
                    weights=[p[1] for p in protocols]
                )[0]
                tag = f"{random.choice(services)}_svc{random.randint(1, 99)}"
                entries.append((port, protocol, tag))
                
            writer.writerows(entries)
        
        print(f"Created mapping file: {filename} with {num_entries} entries")
            
    def generate_flow_log_entry(self, version: int = 2, custom_fields: List[str] = None) -> Dict[str, Any]:
        """Generate a single flow log entry with fields appropriate for the specified version."""
        
        # Generate a base record with all possible fields
        record = {}
        for field, (_, generator) in self.field_definitions.items():
            record[field] = generator()
        
        # For protocol field, always use numeric values based on IANA protocol numbers
        if "protocol" in record:
            # If it's already a string representation of a number, convert it
            if isinstance(record["protocol"], str) and record["protocol"].isdigit():
                record["protocol"] = int(record["protocol"])
            # If it's a protocol name string, map it to its number
            elif isinstance(record["protocol"], str) and record["protocol"].lower() in self.protocol_map:
                record["protocol"] = self.protocol_map[record["protocol"].lower()]
            # Make sure it's an integer between 0-255
            if isinstance(record["protocol"], int):
                record["protocol"] = max(0, min(record["protocol"], 255))
            
        # Adjust the version field to match the requested version
        record["version"] = version
            
        # Pick fields based on version or custom field set
        if custom_fields is not None:
            fields_to_include = custom_fields
        else:
            fields_to_include = self.version_fields.get(version, self.version_fields[2])
            
        # Create the final record with only the relevant fields
        final_record = {field: record[field] for field in fields_to_include if field in record}
        
        return final_record
    
    def generate_flow_logs(self, 
                          output_dir: str, 
                          versions: List[int] = None, 
                          custom_sets: List[str] = None,
                          mixed_file: bool = True,
                          num_logs_per_file: int = 10000,
                          include_csv_header: bool = False) -> None:
        """Generate flow log files for specified versions and custom field sets."""
        
        os.makedirs(output_dir, exist_ok=True)
        
        if versions is None:
            versions = [2]
            
        # Generate version-specific log files
        for version in versions:
            filename = os.path.join(output_dir, f"flow_logs_v{version}.txt")
            with open(filename, "w", encoding="utf-8") as f:
                if include_csv_header:
                    f.write(" ".join(self.version_fields[version]) + "\n")
                    
                for _ in range(num_logs_per_file):
                    record = self.generate_flow_log_entry(version=version)
                    f.write(" ".join(str(record[field]) for field in self.version_fields[version]) + "\n")
                    
            print(f"Created {num_logs_per_file} Version {version} flow logs in {filename}")
                
        # Generate custom field set log files
        if custom_sets:
            for custom_set in custom_sets:
                if custom_set in self.custom_field_sets:
                    filename = os.path.join(output_dir, f"flow_logs_custom_{custom_set}.txt")
                    fields = self.custom_field_sets[custom_set]
                    
                    with open(filename, "w", encoding="utf-8") as f:
                        if include_csv_header:
                            f.write(" ".join(fields) + "\n")
                            
                        for _ in range(num_logs_per_file):
                            record = self.generate_flow_log_entry(custom_fields=fields)
                            f.write(" ".join(str(record[field]) for field in fields) + "\n")
                            
                    print(f"Created {num_logs_per_file} custom '{custom_set}' flow logs in {filename}")
        
        # Generate a mixed version log file if requested
        if mixed_file and len(versions) > 1:
            filename = os.path.join(output_dir, "flow_logs_mixed.txt")
            with open(filename, "w", encoding="utf-8") as f:
                for _ in range(num_logs_per_file):
                    version = random.choice(versions)
                    record = self.generate_flow_log_entry(version=version)
                    f.write(" ".join(str(record[field]) for field in self.version_fields[version]) + "\n")
                    
            print(f"Created {num_logs_per_file} mixed version flow logs in {filename}")
        
        # Generate a JSON format log file for completeness
        filename = os.path.join(output_dir, "flow_logs_json.json")
        with open(filename, "w", encoding="utf-8") as f:
            records = []
            for _ in range(num_logs_per_file // 10):  # Smaller for readability
                version = random.choice(versions)
                record = self.generate_flow_log_entry(version=version)
                records.append(record)
            
            json.dump(records, f, indent=2)
            
        print(f"Created {num_logs_per_file // 10} flow logs in JSON format in {filename}")
                
def main():
    parser = argparse.ArgumentParser(description="Generate AWS VPC Flow Logs for testing")
    parser.add_argument("--output_dir", default="flow_logs", help="Directory to store generated log files")
    parser.add_argument("--versions", type=int, nargs="+", default=[2, 3, 4, 5, 7], 
                        help="Flow log versions to generate (2, 3, 4, 5, 7)")
    parser.add_argument("--custom_sets", nargs="+", 
                        choices=["network_security", "traffic_analysis", "container_tracking", "minimal"],
                        help="Custom field sets to generate")
    parser.add_argument("--logs_per_file", type=int, default=10000, help="Number of log entries per file")
    parser.add_argument("--mapping_file", default="mapping.csv", help="Path to generate the mapping file")
    parser.add_argument("--no_mixed", action="store_false", dest="mixed_file", 
                        help="Don't generate a mixed-version log file")
    parser.add_argument("--include_headers", action="store_true", help="Include CSV headers in log files")
    
    args = parser.parse_args()
    
    generator = FlowLogGenerator()
    
    # Generate mapping file
    generator.generate_mapping_file(args.mapping_file)
    
    # Generate flow logs
    generator.generate_flow_logs(
        output_dir=args.output_dir,
        versions=args.versions,
        custom_sets=args.custom_sets,
        mixed_file=args.mixed_file,
        num_logs_per_file=args.logs_per_file,
        include_csv_header=args.include_headers
    )
    
if __name__ == "__main__":
    main()