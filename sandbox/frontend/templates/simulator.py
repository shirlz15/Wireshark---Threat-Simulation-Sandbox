"""
simulator.py
Two modes:
  1. Simulated  — fake log events (no real network needed)
  2. Live       — reads a .pcap file captured by Wireshark
"""

import random
import os
from datetime import datetime, timedelta

# ── Simulated scenarios ──────────────────────────────────────────────────────

SCENARIOS = {
    "brute_force": {
        "label": "Brute Force Login",
        "description": "Automated password guessing from a single IP",
        "icon": "key",
        "color": "red",
        "events": [
            {"type": "login_attempt", "status": "safe",       "detail": "Login attempt from {ip} — credentials submitted"},
            {"type": "login_failed",  "status": "safe",       "detail": "Wrong password from {ip} — 1st failure"},
            {"type": "login_failed",  "status": "suspicious", "detail": "2nd failure from {ip} within 30s"},
            {"type": "login_failed",  "status": "suspicious", "detail": "3rd failure — {ip} matching wordlist pattern"},
            {"type": "login_failed",  "status": "attack",     "detail": "5 failures / 60s from {ip} — brute force confirmed"},
            {"type": "block_ip",      "status": "response",   "detail": "IP {ip} blocked 30 min — account locked"},
        ]
    },
    "port_scan": {
        "label": "Port Scan",
        "description": "Sequential port probing to map open services",
        "icon": "scan",
        "color": "amber",
        "events": [
            {"type": "port_probe",  "status": "safe",       "detail": "Probe on port 22 (SSH) from {ip}"},
            {"type": "port_probe",  "status": "safe",       "detail": "Probe on port 80 (HTTP) from {ip}"},
            {"type": "port_probe",  "status": "suspicious", "detail": "DB ports 3306/5432 probed by {ip}"},
            {"type": "port_probe",  "status": "suspicious", "detail": "8 ports in 10s from {ip} — scan pattern"},
            {"type": "port_probe",  "status": "attack",     "detail": "Full port scan confirmed — {ip} mapping services"},
            {"type": "close_ports", "status": "response",   "detail": "Unused ports closed — {ip} rate-limited"},
        ]
    },
    "account_takeover": {
        "label": "Account Takeover",
        "description": "Stolen credentials used from unusual location",
        "icon": "user",
        "color": "purple",
        "events": [
            {"type": "login_attempt",   "status": "safe",       "detail": "Login from {ip} — valid credentials accepted"},
            {"type": "geo_flag",        "status": "suspicious", "detail": "Geo anomaly — account normally in IN, now {ip} (RU)"},
            {"type": "time_flag",       "status": "suspicious", "detail": "Login at 03:17 AM — outside normal window"},
            {"type": "behavior_flag",   "status": "attack",     "detail": "Bulk export: 4,000 records in 3 min from {ip}"},
            {"type": "restrict_access", "status": "response",   "detail": "Session revoked — MFA challenge sent to owner"},
        ]
    },
    "ddos": {
        "label": "DDoS Flood",
        "description": "High-volume flood to exhaust server resources",
        "icon": "zap",
        "color": "orange",
        "events": [
            {"type": "traffic_spike", "status": "safe",       "detail": "Traffic from {ip} — 200 req/min (normal)"},
            {"type": "traffic_spike", "status": "suspicious", "detail": "Spike to 2,000 req/min from {ip}"},
            {"type": "traffic_spike", "status": "suspicious", "detail": "8,000 req/min — server latency 450ms"},
            {"type": "traffic_spike", "status": "attack",     "detail": "50,000 req/min from {ip} — DDoS confirmed"},
            {"type": "rate_limit",    "status": "response",   "detail": "CDN throttle applied — {ip} capped at 10 req/min"},
        ]
    }
}


def fake_ip():
    return f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def run_scenario(name: str) -> list:
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {name}")
    sc = SCENARIOS[name]
    ip = fake_ip()
    base = datetime.now()
    events = []
    for i, tmpl in enumerate(sc["events"]):
        offset = sum(random.randint(8, 15) for _ in range(i))
        ts = base + timedelta(seconds=offset)
        events.append({
            "id": i + 1,
            "timestamp": ts.strftime("%H:%M:%S"),
            "type": tmpl["type"],
            "status": tmpl["status"],
            "detail": tmpl["detail"].format(ip=ip),
            "ip": ip,
            "scenario": name,
            "source": "simulated",
        })
    return events


def list_scenarios() -> dict:
    return {
        k: {
            "label": v["label"],
            "description": v["description"],
            "icon": v["icon"],
            "color": v["color"],
        }
        for k, v in SCENARIOS.items()
    }


# ── Wireshark / pcap reader ──────────────────────────────────────────────────

def parse_pcap(filepath: str) -> list:
    """
    Reads a .pcap file saved by Wireshark and converts packets
    into the same event format as simulated scenarios.
    Requires: pip install scapy
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        return [{"error": "scapy not installed — run: pip install scapy"}]

    if not os.path.exists(filepath):
        return [{"error": f"File not found: {filepath}"}]

    packets = rdpcap(filepath)
    events = []
    port_counts = {}
    ip_counts = {}

    for i, pkt in enumerate(packets[:200]):   # cap at 200 for performance
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)

        ip_counts[src] = ip_counts.get(src, 0) + 1
        port_counts[(src, dport)] = port_counts.get((src, dport), 0) + 1

        # Determine status by simple heuristics
        status = "safe"
        if ip_counts[src] > 30:
            status = "attack"
        elif ip_counts[src] > 10:
            status = "suspicious"
        elif dport in (3306, 5432, 6379, 27017, 8080):
            status = "suspicious"

        events.append({
            "id": i + 1,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "type": f"{proto.lower()}_packet",
            "status": status,
            "detail": f"{proto} {src} → {dst}:{dport}  (packet #{i+1})",
            "ip": src,
            "scenario": "pcap_live",
            "source": "wireshark",
            "dport": dport,
        })

    return events
