
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix
import joblib

model = joblib.load("models/window_model.pkl")

normal_data = pd.read_csv("dataset/window_traffic.csv")
attack_data = pd.read_csv("dataset/attack_traffic.csv")

normal_data["actual"] = 0
attack_data["actual"] = 1

data = pd.concat([normal_data, attack_data], ignore_index=True)

features = data[[
    "total_packets",
    "unique_ports",
    "syn_packets",
    "syn_ratio",
    "avg_packet_size",
    "packet_rate"
]]

pred = model.predict(features)
data["predicted"] = [0 if x == 1 else 1 for x in pred]

cm = confusion_matrix(data["actual"], data["predicted"])

plt.figure(figsize=(6,5))
plt.imshow(cm)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")

for i in range(len(cm)):
    for j in range(len(cm)):
        plt.text(j, i, cm[i][j], ha='center', va='center', fontsize=14)

plt.colorbar()
plt.tight_layout()

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
save_path = os.path.join(BASE_DIR, "static", "confusion_matrix.png")

plt.savefig(save_path)
print("Saved at:", save_path)