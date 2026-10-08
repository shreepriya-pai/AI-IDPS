import joblib
import pandas as pd
from rule_engine import rule_based_detection
from prevention import block_ip, is_blocked
from logger import log_event, initialize_log
initialize_log()

model = joblib.load("models/window_model.pkl")


def hybrid_detection(src_ip, feature_vector):
    
    if is_blocked(src_ip):
       return

    """
    feature_vector format:
    [
        total_packets,
        unique_ports,
        syn_packets,
        syn_ratio,
        avg_packet_size,
        packet_rate
    ]
    """

    # --- RULE ENGINE ---
    rule_result = rule_based_detection(feature_vector)

    # --- ML ENGINE ---
    df = pd.DataFrame(
        [feature_vector],
        columns=[
            "total_packets",
            "unique_ports",
            "syn_packets",
            "syn_ratio",
            "avg_packet_size",
            "packet_rate"
        ]
    )

    ml_prediction = model.predict(df)[0]  # 1 = normal, -1 = anomaly

    # --- DECISION FUSION ---
    if rule_result and ml_prediction == -1:
        threat_level = "CRITICAL"
    elif rule_result:
        threat_level = "HIGH"
    elif ml_prediction == -1:
        threat_level = "MEDIUM"
    else:
        threat_level = None

    # --- OUTPUT ---
    if threat_level:
        print("\n🚨 HYBRID ALERT 🚨")
        print(f"IP: {src_ip}")
        print(f"Threat Level: {threat_level}")
    if rule_result:
        print(f"Rule Triggered: {rule_result}")
    if ml_prediction == -1:
        print("ML Engine: Anomalous Behavior Detected")
    print("Feature Vector:", feature_vector)
    print("-" * 40)

    if threat_level in ["HIGH", "CRITICAL"]:
        block_ip(src_ip)

    log_event(
        src_ip,
        threat_level,
        rule_result,
        ml_prediction == -1,
        feature_vector
    )

    return threat_level