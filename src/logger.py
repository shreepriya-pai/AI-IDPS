import csv
import os
from datetime import datetime

LOG_FILE = "logs/security_log.csv"


def initialize_log():
    
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp",
                "IP",
                "Threat Level",
                "Rule Trigger",
                "ML Flag",
                "Feature Vector"
            ])


def log_event(ip, threat_level, rule_result, ml_flag, feature_vector):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp,
            ip,
            threat_level,
            rule_result if rule_result else "None",
            "Yes" if ml_flag else "No",
            feature_vector
        ])