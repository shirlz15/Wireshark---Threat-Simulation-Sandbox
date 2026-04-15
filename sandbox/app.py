"""
app.py — Threat Simulation Sandbox v3.0
Flask server + live simulation engine + LIVE PACKET CAPTURE
Run: python3 app.py (simulation mode)
Run: sudo python3 app.py (for live capture mode)
Open: http://localhost:5000
"""

import sys, os, json, random, threading, time
from datetime import datetime
from flask import Flask, jsonify, render_template, request
from collections import defaultdict, deque

# ── Setup ─────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(__file__)
sys.path.insert(0, BASE_DIR)

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "frontend", "templates"))

# Try to import detector from backend/ folder, fallback to same dir
try:
    from backend.detector import DetectionEngine
except ImportError:
    from detector import DetectionEngine

# Import live capture module
try:
    from simulator import capture_live_packets, check_capture_permissions
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Warning: Scapy not installed. Live mode unavailable.")
    print("   Install: pip install scapy --break-system-packages")

# ── Global State ───────────────────────────────────────────────────────────
engine          = DetectionEngine()
events          = []
running         = False
MODE            = "simulation"  # "simulation" or "live"
traffic_history = deque(maxlen=60)
geo_hits        = defaultdict(int)
attack_log      = []
live_capture_thread = None
permission_warning  = None

# ── Simulation config ──────────────────────────────────────────────────────
ATTACKER_IPS = [
    "192.168.1.10",
    "10.0.0.5",
    "172.16.0.3",
    "45.33.32.156",
    "104.21.8.9",
    "198.51.100.42",
]
NORMAL_IPS = ["192.168.1.20", "192.168.1.30", "8.8.8.8", "1.1.1.1"]
PORTS = [22, 23, 80, 443, 3306, 8080, 3389, 21, 5432, 8443, 53, 8888, 6379, 27017, 445]

PLAYBOOK = {
    "PORT_SCAN":     ["LOG", "MONITOR", "BLOCK", "ALERT"],
    "BRUTE_FORCE":   ["LOG", "RATE_LIMIT", "BLOCK", "ALERT", "NOTIFY_ADMIN"],
    "TRAFFIC_FLOOD": ["LOG", "RATE_LIMIT", "NULL_ROUTE", "ALERT"],
    "SENSITIVE_PORT":["LOG", "MONITOR"],
    "PORT_SPREAD":   ["LOG", "MONITOR"],
    "NORMAL":        [],
}

MITRE = {
    "PORT_SCAN":     "T1046 - Network Service Discovery",
    "BRUTE_FORCE":   "T1110 - Brute Force",
    "TRAFFIC_FLOOD": "T1499 - Endpoint Denial of Service",
    "SENSITIVE_PORT":"T1021 - Remote Services",
    "PORT_SPREAD":   "T1046 - Network Service Discovery",
    "NORMAL":        "-",
}

# ── Packet bucket (for pkt/sec rate) ──────────────────────────────────────
_packet_bucket  = []
_bucket_lock    = threading.Lock()
_last_flush     = time.time()


# ── Event factory (SIMULATION MODE) ────────────────────────────────────────
def make_event():
    """Generate simulated event (original functionality)"""
    global _last_flush

    is_attack = random.random() < 0.45
    src  = random.choice(ATTACKER_IPS) if is_attack else random.choice(NORMAL_IPS)
    # Concentrate ~60% of attacks from the primary attacker IP
    if is_attack and random.random() < 0.6:
        src = ATTACKER_IPS[0]
    port = random.choice(PORTS[:10]) if is_attack else random.choice([80, 443, 53])

    raw    = {"src_ip": src, "dst_ip": "192.168.1.1", "dst_port": port}
    result = engine.analyze(raw)
    actions = PLAYBOOK.get(result["threat_type"], [])

    # Update pkt/sec bucket
    with _bucket_lock:
        _packet_bucket.append(1)
        now = time.time()
        if now - _last_flush >= 1.0:
            traffic_history.append(len(_packet_bucket))
            _packet_bucket.clear()
            _last_flush = now

    geo_hits[src] += 1

    ev = {
        "id":      len(events),
        "time":    datetime.now().strftime("%H:%M:%S"),
        "ms":      int(time.time() * 1000),
        "src":     src,
        "dst":     "192.168.1.1",
        "port":    port,
        "level":   result["threat_level"],
        "type":    result["threat_type"],
        "detail":  result["detail"],
        "actions": actions,
        "mitre":   MITRE.get(result["threat_type"], "-"),
        "proto":   random.choice(["TCP", "TCP", "TCP", "UDP"]),
        "size":    random.randint(40, 1500),
        "mode":    "simulation",
    }

    if ev["level"] in ("critical", "suspicious"):
        attack_log.append({"t": int(time.time()), "level": ev["level"], "type": ev["type"]})
        if len(attack_log) > 200:
            attack_log.pop(0)

    return ev


# ── Process live packet (LIVE MODE) ────────────────────────────────────────
def process_live_packet(packet_data):
    """Process a single live packet and create an event"""
    global _last_flush
    
    raw = {
        "src_ip": packet_data["src_ip"],
        "dst_ip": packet_data["dst_ip"],
        "dst_port": packet_data["dst_port"]
    }
    
    result = engine.analyze(raw)
    actions = PLAYBOOK.get(result["threat_type"], [])
    
    # Update pkt/sec bucket
    with _bucket_lock:
        _packet_bucket.append(1)
        now = time.time()
        if now - _last_flush >= 1.0:
            traffic_history.append(len(_packet_bucket))
            _packet_bucket.clear()
            _last_flush = now
    
    geo_hits[packet_data["src_ip"]] += 1
    
    ev = {
        "id":      len(events),
        "time":    packet_data["timestamp"],
        "ms":      int(time.time() * 1000),
        "src":     packet_data["src_ip"],
        "dst":     packet_data["dst_ip"],
        "port":    packet_data["dst_port"],
        "level":   result["threat_level"],
        "type":    result["threat_type"],
        "detail":  result["detail"],
        "actions": actions,
        "mitre":   MITRE.get(result["threat_type"], "-"),
        "proto":   packet_data["protocol"],
        "size":    packet_data.get("size", 0),
        "mode":    "live",
    }
    
    if ev["level"] in ("critical", "suspicious"):
        attack_log.append({"t": int(time.time()), "level": ev["level"], "type": ev["type"]})
        if len(attack_log) > 200:
            attack_log.pop(0)
    
    return ev


# ── Live capture callback ──────────────────────────────────────────────────
def live_packet_callback(packet_data):
    """Callback for live packet capture - adds event to queue"""
    if running and MODE == "live":
        ev = process_live_packet(packet_data)
        events.append(ev)
        if len(events) > 1000:
            events.pop(0)


# ── Simulation/Live loop ───────────────────────────────────────────────────
def simulation_loop():
    """Main loop - switches between simulation and live mode"""
    global running, MODE, live_capture_thread, permission_warning
    
    while running:
        if MODE == "simulation":
            # Original simulation mode
            events.append(make_event())
            if len(events) > 1000:
                events.pop(0)
            time.sleep(random.uniform(0.15, 0.55))
            
        elif MODE == "live":
            # Live capture mode
            if not SCAPY_AVAILABLE:
                print("⚠️  Scapy not available, falling back to simulation mode")
                MODE = "simulation"
                continue
            
            # Check permissions
            perm_check = check_capture_permissions()
            if not perm_check["ok"]:
                permission_warning = perm_check["error"]
                print(f"⚠️  {permission_warning}")
                print("   Falling back to simulation mode")
                MODE = "simulation"
                continue
            
            # Start live capture in background if not already running
            if live_capture_thread is None or not live_capture_thread.is_alive():
                print("🔴 LIVE CAPTURE MODE ACTIVE")
                live_capture_thread = threading.Thread(
                    target=capture_live_packets,
                    args=(live_packet_callback, running),
                    daemon=True
                )
                live_capture_thread.start()
            
            # Keep loop alive but let capture thread do the work
            time.sleep(0.5)


# ── Routes ─────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/start", methods=["POST"])
def start():
    global running
    if not running:
        running = True
        threading.Thread(target=simulation_loop, daemon=True).start()
    return jsonify({"ok": True, "running": running, "mode": MODE})


@app.route("/api/stop", methods=["POST"])
def stop():
    global running, live_capture_thread
    running = False
    live_capture_thread = None  # Will be cleaned up by daemon
    return jsonify({"ok": True, "running": running, "mode": MODE})


@app.route("/api/reset", methods=["POST"])
def reset():
    global running, events, engine, live_capture_thread
    running = False
    events  = []
    engine  = DetectionEngine()
    traffic_history.clear()
    geo_hits.clear()
    attack_log.clear()
    live_capture_thread = None
    return jsonify({"ok": True})


@app.route("/api/mode", methods=["POST"])
def set_mode():
    """Switch between simulation and live mode"""
    global MODE, permission_warning
    
    data = request.get_json()
    requested_mode = data.get("mode", "simulation")
    
    if requested_mode not in ["simulation", "live"]:
        return jsonify({"ok": False, "error": "Invalid mode. Use 'simulation' or 'live'"}), 400
    
    # Check if live mode is available
    if requested_mode == "live":
        if not SCAPY_AVAILABLE:
            return jsonify({
                "ok": False,
                "error": "Scapy not installed. Install with: pip install scapy --break-system-packages",
                "mode": MODE
            }), 400
        
        # Check permissions
        perm_check = check_capture_permissions()
        if not perm_check["ok"]:
            return jsonify({
                "ok": False,
                "error": perm_check["error"],
                "mode": MODE
            }), 403
    
    MODE = requested_mode
    permission_warning = None
    
    return jsonify({
        "ok": True,
        "mode": MODE,
        "message": f"Switched to {MODE} mode"
    })


@app.route("/api/events")
def get_events():
    since   = int(request.args.get("since", -1))
    new_evs = [e for e in events if e["id"] > since]
    total   = len(events)
    crit    = sum(1 for e in events if e["level"] == "critical")
    susp    = sum(1 for e in events if e["level"] == "suspicious")
    safe    = sum(1 for e in events if e["level"] == "safe")

    return jsonify({
        "events":          new_evs,
        "running":         running,
        "mode":            MODE,
        "stats":           {"total": total, "critical": crit, "suspicious": susp, "safe": safe},
        "traffic_history": list(traffic_history),
        "top_attackers":   sorted(geo_hits.items(), key=lambda x: -x[1])[:5],
        "attack_log":      attack_log[-60:],
        "permission_warning": permission_warning,
        "scapy_available": SCAPY_AVAILABLE,
    })


@app.route("/api/status")
def status():
    return jsonify({
        "running": running,
        "mode": MODE,
        "total_events": len(events),
        "engine": "DetectionEngine v3",
        "scapy_available": SCAPY_AVAILABLE,
        "permission_warning": permission_warning,
    })


@app.route("/api/report")
def report():
    """Download a plain-text incident report."""
    lines = [
        "=" * 60,
        "  THREAT SIMULATION SANDBOX — INCIDENT REPORT",
        "=" * 60,
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Mode      : {MODE.upper()}",
        f"  Total     : {len(events)} events",
        f"  Critical  : {sum(1 for e in events if e['level']=='critical')}",
        f"  Suspicious: {sum(1 for e in events if e['level']=='suspicious')}",
        f"  Safe      : {sum(1 for e in events if e['level']=='safe')}",
        "=" * 60,
        "",
    ]
    for e in events[-100:]:
        actions = ", ".join(e["actions"]) if e["actions"] else "—"
        mode_badge = f"[{e.get('mode', 'sim').upper()}]"
        lines.append(
            f"[{e['time']}] {mode_badge:<7} {e['level'].upper():<12}  {e['type']:<20}"
            f"  src={e['src']}  port={e['port']}  {e['detail']}"
            f"  | actions: {actions}"
        )
    body = "\n".join(lines)
    return body, 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f"attachment; filename=incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    }


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "capture"), exist_ok=True)

    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║   THREAT SIMULATION SANDBOX  v3.0        ║")
    print("  ║   → http://localhost:5000                ║")
    print("  ╚══════════════════════════════════════════╝")
    print()
    print(f"  Mode: {MODE}")
    
    if SCAPY_AVAILABLE:
        print("  ✓ Scapy available - Live mode ready")
        perm = check_capture_permissions()
        if not perm["ok"]:
            print(f"  ⚠️  {perm['error']}")
            print("     Live mode requires: sudo python3 app.py")
    else:
        print("  ⚠️  Scapy not installed - Simulation mode only")
        print("     Install: pip install scapy --break-system-packages")
    
    print()

    app.run(debug=False, port=5000, threaded=True, host="0.0.0.0")
