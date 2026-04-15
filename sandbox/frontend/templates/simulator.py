"""
simulator.py v3.0
Three modes:
  1. Simulated  — fake log events (no real network needed)
  2. Pcap File  — reads a .pcap file captured by Wireshark
  3. LIVE       — real-time packet capture using Scapy
"""

import random
import os
import sys
import time
from datetime import datetime, timedelta

# Try to import Scapy for live capture
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


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
    if not SCAPY_AVAILABLE:
        return [{"error": "scapy not installed — run: pip install scapy --break-system-packages"}]

    if not os.path.exists(filepath):
        return [{"error": f"File not found: {filepath}"}]

    try:
        from scapy.all import rdpcap
        packets = rdpcap(filepath)
    except Exception as e:
        return [{"error": f"Failed to read pcap: {str(e)}"}]

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


# ── LIVE PACKET CAPTURE (NEW) ─────────────────────────────────────────────────

def check_capture_permissions() -> dict:
    """
    Check if we have the necessary permissions for live packet capture.
    Returns: {"ok": True/False, "error": "message"}
    """
    if not SCAPY_AVAILABLE:
        return {
            "ok": False,
            "error": "Scapy not installed. Run: pip install scapy --break-system-packages"
        }
    
    # Check if running as root/admin
    if os.name == 'posix':  # Linux/Mac
        if os.geteuid() != 0:
            return {
                "ok": False,
                "error": "Root privileges required. Run with: sudo python3 app.py"
            }
    elif os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return {
                    "ok": False,
                    "error": "Admin privileges required. Run as Administrator."
                }
        except:
            return {
                "ok": False,
                "error": "Unable to check admin status on Windows"
            }
    
    return {"ok": True, "error": None}


def capture_live_packets(callback, running_flag):
    """
    LIVE PACKET CAPTURE using Scapy
    
    Captures real network traffic and extracts ONLY metadata:
    - Source IP
    - Destination IP
    - Destination Port
    - Protocol
    - Timestamp
    
    NO PAYLOAD DATA IS CAPTURED (educational/safety)
    
    Args:
        callback: Function to call with each packet's metadata
        running_flag: Boolean or function that returns whether to keep capturing
    """
    if not SCAPY_AVAILABLE:
        print("⚠️  Scapy not available for live capture")
        return
    
    print("🔴 Starting live packet capture...")
    print("   Capturing metadata only (no payload)")
    print("   Press Ctrl+C to stop")
    
    def packet_handler(packet):
        """Process each captured packet - extract metadata only"""
        try:
            # Only process IP packets
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Determine protocol and port
            if packet.haslayer(TCP):
                protocol = "TCP"
                dst_port = packet[TCP].dport
                packet_size = len(packet)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                dst_port = packet[UDP].dport
                packet_size = len(packet)
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                dst_port = 0
                packet_size = len(packet)
            else:
                protocol = "OTHER"
                dst_port = 0
                packet_size = len(packet)
            
            # Create metadata packet (NO PAYLOAD)
            packet_data = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "size": packet_size,
            }
            
            # Send to callback for processing
            callback(packet_data)
            
        except Exception as e:
            print(f"⚠️  Error processing packet: {e}")
    
    try:
        # Start sniffing
        # filter="ip" - only capture IP packets
        # prn=packet_handler - process each packet
        # store=0 - don't store packets in memory (safety)
        # stop_filter - stop when running_flag becomes False
        sniff(
            filter="ip",
            prn=packet_handler,
            store=0,  # Don't store packets (memory safety)
            stop_filter=lambda x: not running_flag
        )
    except KeyboardInterrupt:
        print("\n🛑 Live capture stopped by user")
    except PermissionError:
        print("❌ Permission denied. Run with sudo/admin privileges")
    except Scapy_Exception as e:
        print(f"❌ Scapy error: {e}")
    except Exception as e:
        print(f"❌ Capture error: {e}")


# ── CLI test mode ─────────────────────────────────────────────────────────────

def test_live_capture():
    """Test function to verify live capture works independently"""
    print("\n" + "="*60)
    print("LIVE CAPTURE TEST MODE")
    print("="*60)
    
    # Check permissions
    perm = check_capture_permissions()
    if not perm["ok"]:
        print(f"❌ {perm['error']}")
        return
    
    print("✓ Permissions OK")
    print("\nCapturing 10 packets for testing...")
    print("(Generate some network traffic - browse web, ping, etc.)\n")
    
    packet_count = [0]  # Use list to modify in nested function
    
    def test_callback(packet_data):
        packet_count[0] += 1
        print(f"  [{packet_count[0]}] {packet_data['protocol']:4} "
              f"{packet_data['src_ip']:15} → {packet_data['dst_ip']:15}:{packet_data['dst_port']:<5}  "
              f"{packet_data['size']} bytes")
        
        if packet_count[0] >= 10:
            return True  # Stop after 10 packets
    
    try:
        sniff(
            filter="ip",
            prn=lambda pkt: test_callback({
                "src_ip": pkt[IP].src if pkt.haslayer(IP) else "unknown",
                "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "unknown",
                "dst_port": pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0),
                "protocol": "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER"),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "size": len(pkt)
            }),
            count=10,
            store=0
        )
        print("\n✓ Test completed successfully!")
        print("  Live capture is working correctly")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")


if __name__ == "__main__":
    # If run directly, test live capture
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_live_capture()
    else:
        print("Usage:")
        print("  python simulator.py test    # Test live capture")
