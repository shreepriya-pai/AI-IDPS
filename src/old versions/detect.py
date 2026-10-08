from scapy.all import sniff, IP, TCP
import joblib
import numpy as np
import time
import pandas as pd

# Load trained model
model = joblib.load("model.pkl")

print("AI Intrusion Detection System Started...")
print("Monitoring network traffic...\n")

def process_packet(packet):
    if IP in packet and TCP in packet:
        dst_port = packet[TCP].dport
        syn_flag = int(packet[TCP].flags == "S")
        
        features = pd.DataFrame(
          [[dst_port, syn_flag]],
           columns=["dst_port", "syn_flag"] )

        prediction = model.predict(features)


        if prediction[0] == -1:
         print(f"⚠️ ALERT: Suspicious activity detected on port {dst_port}")


# Start sniffing
sniff(prn=process_packet, store=False)
