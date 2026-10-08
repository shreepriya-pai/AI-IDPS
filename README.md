# AI-Based Intrusion Detection and Prevention System (AI-IDPS)

## 📌 Project Overview

AI-IDPS is an AI-based Intrusion Detection and Prevention System designed to monitor network traffic, identify suspicious behavior, classify potential threats, and take preventive action against detected attacks.

The system combines **rule-based detection** with **machine learning-based anomaly detection** to improve threat identification.

Network traffic is analyzed in short time windows and converted into behavioral features such as packet rate, SYN packet ratio, and number of unique destination ports.

---

## 🎯 Objectives

- Monitor network traffic in real time.
- Detect suspicious network behavior.
- Identify common patterns such as port scans and SYN-flood-like activity.
- Use machine learning to detect anomalous traffic.
- Combine rule-based and ML-based detection.
- Assign threat levels to detected activity.
- Temporarily block IP addresses associated with high-risk activity.
- Maintain security logs for detected events.
- Evaluate the ML model using a confusion matrix and classification report.

---

## ⚙️ How the System Works

The system follows these main steps:

### 1. Network Traffic Capture

Network packets are captured using **Scapy**.

The system collects information such as:

- Source IP address
- Packet size
- Destination port
- TCP SYN flag

### 2. Feature Aggregation

Traffic is grouped into **5-second windows**.

For each source IP, the following features are calculated:

- Total packets
- Number of unique ports
- Number of SYN packets
- SYN ratio
- Average packet size
- Packet rate

### 3. Rule-Based Detection

The rule engine checks traffic against predefined conditions.

Examples include:

- **Port Scan Detection**
- **SYN Flood Detection**
- **Traffic Burst Detection**

### 4. Machine Learning Detection

The project uses an **Isolation Forest** model for behavioral anomaly detection.

The model analyzes the extracted traffic features and determines whether the observed behavior is normal or anomalous.

### 5. Hybrid Decision Making

The rule-based engine and ML engine work together.

Threat levels are assigned as:

| Condition | Threat Level |
|---|---|
| Rule + ML anomaly | CRITICAL |
| Rule detected | HIGH |
| ML anomaly | MEDIUM |
| No threat | Normal |

### 6. Prevention

High and critical threats can result in the source IP being temporarily blocked.

The current implementation maintains a list of blocked IPs and automatically removes an IP after the configured block duration.

### 7. Logging

Detected events are stored in:

```text
logs/security_log.csv