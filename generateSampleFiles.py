import csv
import random


# File paths
mapping_file_path = "mapping.csv"
flow_logs_file_path = "flow_logs.txt"

# Generate mapping file data based on the provided sample from description
mapping_entries = [
    (25, "tcp", "sv_P1"),
    (68, "udp", "sv_P2"),
    (23, "tcp", "sv_P1"),
    (31, "udp", "SV_P3"),
    (443, "tcp", "sv_P2"),
    (22, "tcp", "sv_P4"),
    (3389, "tcp", "sv_P5"),
    (0, "icmp", "sv_P5"),
    (110, "tcp", "email"),
    (993, "tcp", "email"),
    (143, "tcp", "email"),
]

# Write mapping file
with open(mapping_file_path, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["dstport", "protocol", "tag"])
    writer.writerows(mapping_entries)

num_lines = 50000 # Can be adjusted to fit size range

flow_log_template = "{version} {account_id} {eni_id} {src_ip} {dst_ip} {srcport} {dstport} {protocol} {packets} {bytes} {start} {end} {action} {status}\n"

# Possible values for flow log fields based on the description and sample provided
versions = [2]
account_ids = [str(random.randint(100000000000, 999999999999)) for _ in range(10)]
eni_ids = [f"eni-{random.randint(1000000, 9999999)}b8ca{random.randint(100000000, 999999999)}" for _ in range(10)]
ips = [f"172.31.{random.randint(0, 255)}.{random.randint(0, 255)}" for _ in range(50)]
ports = [entry[0] for entry in mapping_entries] + [random.randint(1000, 65000) for _ in range(20)]
protocols = ["tcp", "udp", "icmp"]
actions = ["ACCEPT", "REJECT"]
statuses = ["OK", "FAIL"]

# Write flow logs
with open(flow_logs_file_path, "w", encoding="ascii") as logfile:
    for _ in range(num_lines):
        line = flow_log_template.format(
            version=random.choice(versions),
            account_id=random.choice(account_ids),
            eni_id=random.choice(eni_ids),
            src_ip=random.choice(ips),
            dst_ip=random.choice(ips),
            srcport=random.choice(ports),
            dstport=random.choice(ports),
            protocol=random.choice(protocols),
            packets=random.randint(1, 1000),
            bytes=random.randint(64, 1500),
            start=random.randint(1418530000, 1418539999),
            end=random.randint(1418530000, 1418539999),
            action=random.choice(actions),
            status=random.choice(statuses),
        )
        logfile.write(line)

# Return generated file paths
mapping_file_path, flow_logs_file_path
