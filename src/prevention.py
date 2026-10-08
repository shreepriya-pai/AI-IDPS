import time

# Store blocked IPs
blocked_ips = {}

BLOCK_DURATION = 200  # seconds


def block_ip(ip):
    blocked_ips[ip] = time.time()
    print(f"🛑 IP {ip} has been BLOCKED for {BLOCK_DURATION} seconds.")


def is_blocked(ip):
    if ip in blocked_ips:
        if time.time() - blocked_ips[ip] > BLOCK_DURATION:
            # Auto-unblock
            print(f"✅ IP {ip} has been unblocked.")
            del blocked_ips[ip]
            return False
        return True
    return False
