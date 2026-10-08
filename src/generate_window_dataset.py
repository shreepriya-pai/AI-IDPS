from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict
import numpy as np
import csv

WINDOW_SIZE = 5  # seconds
CAPTURE_DURATION = 120  # 2 minutes

traffic_data = defaultdict(list)
start_time = time.time()
global_start = time.time()

output_file = open("dataset/window_traffic.csv", "w", newline="")
writer = csv.writer(output_file)

# Write header
writer.writerow([
    "total_packets",
    "unique_ports",
    "syn_packets",
    "syn_ratio",
    "avg_packet_size",
    "packet_rate"
])


def process_packet(packet):
    global start_time

    if IP in packet:
        src_ip = packet[IP].src
        packet_size = len(packet)

        syn_flag = 0
        dst_port = 0

        if TCP in packet:
            dst_port = packet[TCP].dport
            syn_flag = int(packet[TCP].flags == "S")

        traffic_data[src_ip].append({
            "size": packet_size,
            "dst_port": dst_port,
            "syn_flag": syn_flag
        })

    # Window expired
    if time.time() - start_time >= WINDOW_SIZE:
        analyze_window()
        traffic_data.clear()
        start_time = time.time()

    # Stop entire capture after duration
    if time.time() - global_start >= CAPTURE_DURATION:
        output_file.close()
        print("Window dataset generation complete.")
        exit()


def analyze_window():
    for src_ip, packets in traffic_data.items():
        total_packets = len(packets)
        unique_ports = len(set(p["dst_port"] for p in packets))
        syn_packets = sum(p["syn_flag"] for p in packets)
        avg_packet_size = np.mean([p["size"] for p in packets])

        syn_ratio = syn_packets / total_packets if total_packets > 0 else 0
        packet_rate = total_packets / WINDOW_SIZE

        writer.writerow([
            total_packets,
            unique_ports,
            syn_packets,
            syn_ratio,
            avg_packet_size,
            packet_rate
        ])


print("Generating window-based dataset...")
sniff(prn=process_packet, store=False)
