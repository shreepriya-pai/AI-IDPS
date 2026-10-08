import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load window-based dataset
data = pd.read_csv("dataset/window_traffic.csv")

# Create model
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,  # assume 5% anomalies
    random_state=42
)

# Train model
model.fit(data)

# Save model
joblib.dump(model, "models/window_model.pkl")

print("Behavioral model trained and saved.")
