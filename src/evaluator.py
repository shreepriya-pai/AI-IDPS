
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load model
model = joblib.load("models/window_model.pkl")

# Load datasets
normal_data = pd.read_csv("dataset/window_traffic.csv")
attack_data = pd.read_csv("dataset/attack_traffic.csv")

# Add labels
normal_data["actual"] = 0
attack_data["actual"] = 1

# Combine datasets
data = pd.concat([normal_data, attack_data], ignore_index=True)

# Extract features
features = data[[
    "total_packets",
    "unique_ports",
    "syn_packets",
    "syn_ratio",
    "avg_packet_size",
    "packet_rate"
]]

# Predictions
predictions = model.predict(features)

# Convert predictions
data["predicted"] = predictions
data["predicted"] = data["predicted"].apply(lambda x: 0 if x == 1 else 1)

# Evaluate
y_true = data["actual"]
y_pred = data["predicted"]

print("\n📊 Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))

print("\n📊 Classification Report:")
print(classification_report(y_true, y_pred))