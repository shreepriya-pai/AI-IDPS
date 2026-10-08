import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load dataset
data = pd.read_csv("dataset/normal_traffic.csv")

# Select useful numerical features
features = data[["dst_port", "syn_flag"]]

# Create Isolation Forest model
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,  # assume 1% anomalies
    random_state=42
)

# Train the model
model.fit(features)

# Save the trained model
joblib.dump(model, "model.pkl")

print("Model trained and saved as model.pkl")
