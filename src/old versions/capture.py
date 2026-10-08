from scapy.all import sniff, IP, TCP
import csv
import time

OUTPUT_FILE = "dataset/normal_traffic.csv"
CAPTURE_TIME = 120  # seconds

start_time = time.time()

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "syn_flag"])

    def process_packet(packet):
        if IP in packet and TCP in packet:
            timestamp = time.time()
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            syn_flag = int(packet[TCP].flags == "S")

            writer.writerow([timestamp, src_ip, dst_ip, dst_port, syn_flag])

        if time.time() - start_time > CAPTURE_TIME:
            return True

    print("Capturing NORMAL traffic...")
    sniff(prn=process_packet, store=False,stop_filter=lambda x: time.time() - start_time > CAPTURE_TIME)


print("Dataset collection complete.")
