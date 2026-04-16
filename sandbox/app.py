"""
app.py — Cyber Threat Simulation Sandbox v4.0
============================================================
Modes:
  Simulation  — synthetic traffic with behavioral patterns
  tshark Live — real packet capture via Wireshark CLI (no scapy needed)
  Scenario    — inject structured attack scenarios on demand

Run:
  python3 app.py               # simulation mode
  sudo python3 app.py          # enables live tshark capture
  open http://localhost:5000
"""

import sys, os, json, random, threading, time, subprocess, shutil
from datetime import datetime
from flask import Flask, jsonify, render_template, request, Response
from collections import defaultdict, deque

BASE_DIR = os.path.dirname(__file__)
sys.path.insert(0, BASE_DIR)

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "frontend", "templates"))

try:
    from backend.detector import DetectionEngine
except ImportError:
    from detector import DetectionEngine

# ── Constants ──────────────────────────────────────────────────────────────
MAX_EVENTS   = 500   # rolling window kept in memory
REPLAY_MAX   = 500   # events available for replay slider

ATTACKER_IPS = [
    "192.168.1.10", "10.0.0.5", "172.16.0.3",
    "45.33.32.156", "104.21.8.9", "198.51.100.42",
    "185.220.101.1", "91.108.4.1",
]
NORMAL_IPS  = ["192.168.1.20", "192.168.1.30", "8.8.8.8", "1.1.1.1", "172.217.14.206"]

PLAYBOOK = {
    "PORT_SCAN":      ["LOG", "MONITOR", "BLOCK", "ALERT"],
    "BRUTE_FORCE":    ["LOG", "RATE_LIMIT", "BLOCK", "ALERT", "NOTIFY_ADMIN"],
    "TRAFFIC_FLOOD":  ["LOG", "RATE_LIMIT", "NULL_ROUTE", "ALERT"],
    "SENSITIVE_PORT": ["LOG", "MONITOR"],
    "PORT_SPREAD":    ["LOG", "MONITOR"],
    "RECON_SEQUENCE": ["LOG", "MONITOR", "BLOCK"],
    "NORMAL":         [],
}

# ── Scenario definitions ────────────────────────────────────────────────────
SCENARIOS = {
    "port_scan": {
        "label": "Coordinated Port Scan",
        "desc":  "Systematic recon across common service ports",
        "steps": [
            {"port": 80,    "delay": 0.05},
            {"port": 443,   "delay": 0.05},
            {"port": 22,    "delay": 0.05},
            {"port": 8080,  "delay": 0.05},
            {"port": 3306,  "delay": 0.05},
            {"port": 5432,  "delay": 0.05},
            {"port": 3389,  "delay": 0.05},
            {"port": 27017, "delay": 0.05},
            {"port": 6379,  "delay": 0.05},
            {"port": 21,    "delay": 0.05},
            {"port": 445,   "delay": 0.05},
            {"port": 135,   "delay": 0.05},
        ],
    },
    "brute_force": {
        "label": "SSH Brute Force",
        "desc":  "High-rate credential stuffing against SSH",
        "steps": [{"port": 22, "delay": 0.08}] * 15,
    },
    "db_harvest": {
        "label": "Database Harvest Sequence",
        "desc":  "Recon → DB port targeting → credential attack",
        "steps": (
            [{"port": p, "delay": 0.1} for p in [80, 443, 8080, 8443]]   # web recon
            + [{"port": p, "delay": 0.1} for p in [3306, 5432, 27017]]   # db probe
            + [{"port": 3306, "delay": 0.05}] * 12                        # brute
        ),
    },
    "ddos": {
        "label": "Volumetric DDoS",
        "desc":  "Packet flood to saturate target bandwidth",
        "steps": [{"port": 80, "delay": 0.02}] * 40,
    },
    "lateral_movement": {
        "label": "Lateral Movement",
        "desc":  "SMB + RDP + SSH chaining across network",
        "steps": [
            {"port": 445,  "delay": 0.12},
            {"port": 3389, "delay": 0.12},
            {"port": 22,   "delay": 0.12},
            {"port": 5900, "delay": 0.12},
            {"port": 135,  "delay": 0.12},
            {"port": 139,  "delay": 0.12},
            {"port": 22,   "delay": 0.06},
        ] * 2,
    },
}

# ── Global state ────────────────────────────────────────────────────────────
engine          = DetectionEngine()
events          = []
running         = False
MODE            = "simulation"
traffic_history = deque(maxlen=60)
geo_hits        = defaultdict(int)
attack_log      = []
_packet_bucket  = []
_bucket_lock    = threading.Lock()
_last_flush     = time.time()
_tshark_proc    = None
tshark_warning  = None
TSHARK_AVAILABLE = shutil.which("tshark") is not None


def _flush_bucket(now):
    global _last_flush
    with _bucket_lock:
        if now - _last_flush >= 1.0:
            traffic_history.append(len(_packet_bucket))
            _packet_bucket.clear()
            _last_flush = now


# ── Event builder ───────────────────────────────────────────────────────────
def _build_event(src_ip: str, dst_ip: str, port: int,
                 proto: str = "TCP", size: int = None,
                 mode_tag: str = "simulation") -> dict:
    now = time.time()
    with _bucket_lock:
        _packet_bucket.append(1)
    _flush_bucket(now)

    raw    = {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": port}
    result = engine.analyze(raw)
    actions = PLAYBOOK.get(result["threat_type"], [])
    geo_hits[src_ip] += 1

    ev = {
        "id":          len(events),
        "time":        datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "ms":          int(now * 1000),
        "src":         src_ip,
        "dst":         dst_ip,
        "port":        port,
        "proto":       proto,
        "size":        size or random.randint(40, 1500),
        "level":       result["threat_level"],
        "type":        result["threat_type"],
        "detail":      result["detail"],
        "explanation": result.get("explanation", ""),
        "confidence":  result.get("confidence", 50),
        "mitre":       result.get("mitre", "-"),
        "mitre_name":  result.get("mitre_name", "—"),
        "phase":       result.get("phase_hint", "idle"),
        "actions":     actions,
        "mode":        mode_tag,
    }

    if ev["level"] in ("critical", "suspicious"):
        attack_log.append({
            "t":     int(now),
            "level": ev["level"],
            "type":  ev["type"],
            "src":   src_ip,
        })
        if len(attack_log) > 300:
            attack_log.pop(0)

    return ev


def _append(ev):
    events.append(ev)
    if len(events) > MAX_EVENTS:
        events.pop(0)
        # Re-index
        for i, e in enumerate(events):
            e["id"] = i


# ── Simulation loop ──────────────────────────────────────────────────────────
PORTS_SIM = [22, 23, 80, 443, 3306, 8080, 3389, 21, 5432, 8443, 53, 8888, 6379, 27017, 445, 135, 139]

def simulation_loop():
    global running
    while running and MODE == "simulation":
        is_attack = random.random() < 0.42
        src = random.choice(ATTACKER_IPS) if is_attack else random.choice(NORMAL_IPS)
        if is_attack and random.random() < 0.55:
            src = ATTACKER_IPS[0]
        port = random.choice(PORTS_SIM[:12]) if is_attack else random.choice([80, 443, 53, 8080])
        proto = random.choice(["TCP", "TCP", "TCP", "UDP"])
        ev = _build_event(src, "192.168.1.1", port, proto, mode_tag="simulation")
        _append(ev)
        time.sleep(random.uniform(0.12, 0.45))


# ── tshark live capture ──────────────────────────────────────────────────────
def _parse_tshark_line(line: str) -> dict | None:
    """Parse a tshark TSV output line into packet metadata."""
    try:
        parts = line.strip().split("\t")
        if len(parts) < 5:
            return None
        _ts, src, dst, tcp_port, udp_port = parts[:5]
        if not src or not dst:
            return None
        # Determine port and protocol
        if tcp_port:
            raw_ports = tcp_port.split(",")
            port = int(raw_ports[-1]) if raw_ports[-1].isdigit() else 0
            proto = "TCP"
        elif udp_port:
            raw_ports = udp_port.split(",")
            port = int(raw_ports[-1]) if raw_ports[-1].isdigit() else 0
            proto = "UDP"
        else:
            return None
        if port == 0:
            return None
        return {"src": src.strip(), "dst": dst.strip(), "port": port, "proto": proto}
    except Exception:
        return None


def tshark_loop():
    global running, _tshark_proc, tshark_warning, MODE

    iface = _detect_interface()
    cmd = [
        "tshark", "-i", iface,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-l",   # line-buffered
        "-q",   # quiet
        "ip",   # capture filter
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        _tshark_proc = proc
        tshark_warning = None

        for line in proc.stdout:
            if not running or MODE != "live":
                break
            pkt = _parse_tshark_line(line)
            if pkt:
                ev = _build_event(pkt["src"], pkt["dst"], pkt["port"],
                                   pkt["proto"], mode_tag="live")
                _append(ev)

        proc.terminate()
    except FileNotFoundError:
        tshark_warning = "tshark not found. Install Wireshark/tshark."
        MODE = "simulation"
    except PermissionError:
        tshark_warning = "Permission denied. Run: sudo python3 app.py"
        MODE = "simulation"
    except Exception as e:
        tshark_warning = f"tshark error: {e}"
        MODE = "simulation"
    finally:
        _tshark_proc = None


def _detect_interface() -> str:
    """Auto-detect the primary active network interface."""
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().splitlines()
        # Prefer eth0/ens/wlan over loopback
        for line in lines:
            if any(k in line.lower() for k in ["eth", "ens", "wlan", "en0", "en1"]):
                return line.split(".")[0].strip().split()[-1]
        return "1"  # fallback: first interface
    except Exception:
        return "eth0"


# ── Master control loop ──────────────────────────────────────────────────────
def control_loop():
    global running, MODE
    while running:
        if MODE == "simulation":
            simulation_loop()
        elif MODE == "live":
            if not TSHARK_AVAILABLE:
                tshark_warning_set("tshark not installed.")
                MODE = "simulation"
                continue
            tshark_loop()
        time.sleep(0.1)


def tshark_warning_set(msg):
    global tshark_warning
    tshark_warning = msg


# ── Scenario injection ───────────────────────────────────────────────────────
def run_scenario_thread(name: str):
    sc = SCENARIOS[name]
    src = f"{random.randint(45,200)}.{random.randint(10,240)}.{random.randint(1,250)}.{random.randint(2,250)}"
    for step in sc["steps"]:
        if not running:
            break
        ev = _build_event(src, "192.168.1.1", step["port"],
                           mode_tag=f"scenario:{name}")
        _append(ev)
        time.sleep(step["delay"])


# ── Flask routes ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/start", methods=["POST"])
def start():
    global running
    if not running:
        running = True
        threading.Thread(target=control_loop, daemon=True).start()
    return jsonify({"ok": True, "running": running, "mode": MODE})


@app.route("/api/stop", methods=["POST"])
def stop():
    global running, _tshark_proc
    running = False
    if _tshark_proc:
        _tshark_proc.terminate()
        _tshark_proc = None
    return jsonify({"ok": True, "running": running})


@app.route("/api/reset", methods=["POST"])
def reset():
    global running, events, engine, _tshark_proc
    running = False
    if _tshark_proc:
        _tshark_proc.terminate()
        _tshark_proc = None
    events = []
    engine = DetectionEngine()
    traffic_history.clear()
    geo_hits.clear()
    attack_log.clear()
    return jsonify({"ok": True})


@app.route("/api/mode", methods=["POST"])
def set_mode():
    global MODE, tshark_warning
    data = request.get_json() or {}
    new_mode = data.get("mode", "simulation")
    if new_mode not in ("simulation", "live"):
        return jsonify({"ok": False, "error": "Invalid mode"}), 400
    if new_mode == "live" and not TSHARK_AVAILABLE:
        return jsonify({"ok": False, "error": "tshark not installed. Install Wireshark."}), 400
    MODE = new_mode
    tshark_warning = None
    return jsonify({"ok": True, "mode": MODE})


@app.route("/api/simulate", methods=["POST"])
def simulate():
    """Inject a named attack scenario into the live event stream."""
    data = request.get_json() or {}
    name = data.get("type", "port_scan")
    if name not in SCENARIOS:
        return jsonify({"ok": False, "error": f"Unknown scenario. Use: {list(SCENARIOS.keys())}"}), 400
    threading.Thread(
        target=run_scenario_thread,
        args=(name,),
        daemon=True
    ).start()
    sc = SCENARIOS[name]
    return jsonify({"ok": True, "scenario": name, "label": sc["label"], "steps": len(sc["steps"])})


@app.route("/api/scenarios")
def list_scenarios():
    return jsonify({
        k: {"label": v["label"], "desc": v["desc"], "steps": len(v["steps"])}
        for k, v in SCENARIOS.items()
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
        "events":           new_evs,
        "running":          running,
        "mode":             MODE,
        "stats":            {"total": total, "critical": crit, "suspicious": susp, "safe": safe},
        "traffic_history":  list(traffic_history),
        "top_attackers":    sorted(geo_hits.items(), key=lambda x: -x[1])[:6],
        "attack_log":       attack_log[-80:],
        "tshark_available": TSHARK_AVAILABLE,
        "tshark_warning":   tshark_warning,
    })


@app.route("/api/replay")
def replay():
    """Return up to last REPLAY_MAX events for the replay slider."""
    pct   = float(request.args.get("pct", 100)) / 100.0
    pool  = events[-REPLAY_MAX:]
    count = max(1, int(len(pool) * pct))
    return jsonify({"events": pool[:count], "total": len(pool)})


@app.route("/api/fingerprint/<ip>")
def fingerprint(ip):
    fp = engine.get_fingerprint(ip)
    hits = geo_hits.get(ip, 0)
    return jsonify({"ip": ip, "hits": hits, "fingerprint": fp})


@app.route("/api/status")
def status():
    return jsonify({
        "running":          running,
        "mode":             MODE,
        "total_events":     len(events),
        "engine":           "DetectionEngine v4",
        "tshark_available": TSHARK_AVAILABLE,
        "tshark_warning":   tshark_warning,
        "scenarios":        list(SCENARIOS.keys()),
    })


@app.route("/api/report")
def report():
    lines = [
        "=" * 72,
        "  CYBER THREAT SANDBOX — BEHAVIORAL INCIDENT REPORT  v4.0",
        "=" * 72,
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Mode      : {MODE.upper()}",
        f"  Total     : {len(events)} events",
        f"  Critical  : {sum(1 for e in events if e['level']=='critical')}",
        f"  Suspicious: {sum(1 for e in events if e['level']=='suspicious')}",
        f"  Safe      : {sum(1 for e in events if e['level']=='safe')}",
        "=" * 72,
        f"  {'Time':<12} {'Mode':<12} {'Level':<12} {'Type':<20} {'Conf':>5}  {'Src IP':<18} P  {'MITRE':<8}  Detail",
        "-" * 120,
    ]
    for e in events[-200:]:
        conf_str = f"{e.get('confidence', '?')}%"
        mode_str = e.get('mode', 'sim')[:10]
        lines.append(
            f"  {e['time']:<12} {mode_str:<12} {e['level'].upper():<12} {e['type']:<20} "
            f"{conf_str:>5}  {e['src']:<18} {e['port']:<6} {e.get('mitre','-'):<8}  {e['detail']}"
        )
        if e.get("explanation"):
            lines.append(f"    ↳ {e['explanation'][:110]}")
    body = "\n".join(lines)
    return body, 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f"attachment; filename=threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "capture"), exist_ok=True)

    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║   CYBER THREAT SANDBOX  v4.0                     ║")
    print("  ║   Behavioral Analysis + Live Capture + Replay    ║")
    print("  ║   → http://localhost:5000                        ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()
    if TSHARK_AVAILABLE:
        print("  ✓ tshark found — live capture available (sudo required)")
    else:
        print("  ⚠  tshark not found — simulation mode only")
        print("     Install: sudo apt install tshark  (Kali/Ubuntu)")
    print()

    app.run(debug=False, port=5000, threaded=True, host="0.0.0.0")
