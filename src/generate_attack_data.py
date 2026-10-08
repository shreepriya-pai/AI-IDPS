import csv
import random

OUTPUT_FILE = "dataset/attack_traffic.csv"

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)

    # Header
    writer.writerow([
        "total_packets",
        "unique_ports",
        "syn_packets",
        "syn_ratio",
        "avg_packet_size",
        "packet_rate"
    ])

    # Generate 200 attack samples
    for _ in range(200):
        total_packets = random.randint(100, 500)
        unique_ports = random.randint(20, 100)
        syn_packets = random.randint(50, total_packets)
        syn_ratio = syn_packets / total_packets
        avg_packet_size = random.uniform(200, 1500)
        packet_rate = random.uniform(50, 300)

        writer.writerow([
            total_packets,
            unique_ports,
            syn_packets,
            syn_ratio,
            avg_packet_size,
            packet_rate
        ])

print("Attack dataset generated.")