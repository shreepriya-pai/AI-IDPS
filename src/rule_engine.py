def rule_based_detection(features):
    """
    features format:
    [
        total_packets,
        unique_ports,
        syn_packets,
        syn_ratio,
        avg_packet_size,
        packet_rate
    ]
    """

    total_packets, unique_ports, syn_packets, syn_ratio, avg_packet_size, packet_rate = features

    # Port scan detection
    if unique_ports > 3:
        return "Port Scan Detected"

    # SYN flood detection
    if syn_ratio > 0.5 and total_packets > 50:
        return "SYN Flood Suspected"

    # Traffic burst detection
    if packet_rate > 10:
        return "Traffic Burst Detected"

    return None