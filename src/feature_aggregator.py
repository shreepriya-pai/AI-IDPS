from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict
import numpy as np
from rule_engine import rule_based_detection
from hybrid_detector import hybrid_detection



WINDOW_SIZE = 5  # seconds

# Data structure to store packets per source IP
traffic_data = defaultdict(list)

start_time = time.time()


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

        # Store packet info
        traffic_data[src_ip].append({
            "size": packet_size,
            "dst_port": dst_port,
            "syn_flag": syn_flag
        })

    # Check if window expired
    if time.time() - start_time >= WINDOW_SIZE:
        analyze_window()
        traffic_data.clear()
        start_time = time.time()


def analyze_window():
    print("\n--- Analyzing 5-second Window ---")

    for src_ip, packets in traffic_data.items():
        total_packets = len(packets)
        unique_ports = len(set(p["dst_port"] for p in packets))
        syn_packets = sum(p["syn_flag"] for p in packets)
        avg_packet_size = np.mean([p["size"] for p in packets])

        syn_ratio = syn_packets / total_packets if total_packets > 0 else 0
        packet_rate = total_packets / WINDOW_SIZE

        
        feature_vector = [
          total_packets,
          unique_ports,
          syn_packets,
          syn_ratio,
         avg_packet_size,
         packet_rate
         ]

        hybrid_detection(src_ip, feature_vector)

        
        rule_result = rule_based_detection(feature_vector)

        if rule_result:
           print(f"⚠️ RULE ALERT for {src_ip}: {rule_result}")

        print(f"IP: {src_ip}")
        print(f"Features: {feature_vector}")
       
    #  DEMO ATTACK SIMULATION (temporary for presentation)
    import random

    # Simulate attack every few windows
    if True:
        fake_ip = f"192.168.0.{random.randint(100,250)}"
        attack_features = [
        500,
        80,
        350,
        0.75,
        1200,
        250
        ]

        print("\n⚠️ Simulated Attack Traffic Injected ⚠️")
        hybrid_detection(fake_ip, attack_features)
    

print("Starting Behavioral Traffic Aggregator...")
sniff(prn=process_packet, store=False, iface="Wi-Fi")