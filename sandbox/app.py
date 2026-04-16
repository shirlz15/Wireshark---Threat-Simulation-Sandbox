"""
app.py — Cyber Threat Simulation Sandbox v5.0
================================================================
Patentable Innovations:
  1. Adaptive tshark field extraction with interface auto-selection
  2. Metasploitable2 target profiling with CVE-aware detection
  3. Kali Linux attack scenario injection via subprocess API
  4. Cross-IP distributed attack correlation engine
  5. Bayesian-decay confidence scoring with intent vectors

Modes:
  simulation  — synthetic traffic with behavioral patterns
  live        — real tshark packet capture (requires sudo)
  scenario    — inject structured Kali/Metasploit attack sequences

Run:
  python3 app.py                    # simulation mode
  sudo python3 app.py               # enables live tshark capture
  open http://localhost:5000
"""

import sys, os, json, random, threading, time, subprocess, shutil
from datetime import datetime
from flask import Flask, jsonify, render_template, request, Response
from collections import defaultdict, deque
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "frontend", "templates"))
CORS(app)

try:
    from backend.detector import DetectionEngine
except ImportError:
    from detector import DetectionEngine

# ── Constants ────────────────────────────────────────────────────────────────
MAX_EVENTS  = 1000
REPLAY_MAX  = 1000
VERSION     = "5.0"

# Kali attacker IPs (simulated Kali Linux host)
KALI_IPS = [
    "192.168.56.101",   # Kali default NAT host-only
    "10.0.2.15",        # Kali VirtualBox NAT
    "192.168.1.100",    # Kali bridged
    "172.16.0.100",     # Kali VMware
    "45.33.32.156",     # External attacker
    "104.21.8.9",
    "198.51.100.42",
    "185.220.101.1",
]

# Metasploitable2 target IP (default)
MSF2_TARGET = "192.168.56.102"   # Default Metasploitable2 host-only IP
NORMAL_IPS  = ["192.168.1.20", "192.168.1.30", "8.8.8.8", "1.1.1.1"]

PLAYBOOK = {
    "PORT_SCAN":      ["LOG", "MONITOR", "BLOCK", "ALERT"],
    "BRUTE_FORCE":    ["LOG", "RATE_LIMIT", "BLOCK", "ALERT", "NOTIFY_ADMIN"],
    "TRAFFIC_FLOOD":  ["LOG", "RATE_LIMIT", "NULL_ROUTE", "ALERT"],
    "SENSITIVE_PORT": ["LOG", "MONITOR"],
    "PORT_SPREAD":    ["LOG", "MONITOR"],
    "RECON_SEQUENCE": ["LOG", "MONITOR", "BLOCK"],
    "MSF2_RECON":     ["LOG", "BLOCK", "ALERT", "NOTIFY_ADMIN"],
    "BACKDOOR_PORT":  ["LOG", "BLOCK", "KILL_SESSION", "ALERT", "NOTIFY_ADMIN"],
    "NORMAL":         [],
}

PLAYBOOK_DESCRIPTIONS = {
    "LOG":           "Event persisted to SIEM log store with full packet metadata",
    "MONITOR":       "Source IP added to watch list — elevated inspection for 10 minutes",
    "BLOCK":         "Firewall DROP rule inserted for source IP (iptables / nftables)",
    "ALERT":         "SOC alert triggered — P1 ticket created in ticketing system",
    "RATE_LIMIT":    "Traffic from source throttled to 10 req/min via tc/iptables",
    "NULL_ROUTE":    "BGP blackhole route announced — traffic absorbed at edge",
    "NOTIFY_ADMIN":  "Automated email + SMS page sent to on-call security engineer",
    "KILL_SESSION":  "All TCP sessions from source forcibly RST — active connections terminated",
}

# ── Kali / Metasploit scenario definitions ───────────────────────────────────
# Each scenario mirrors a real Kali/Metasploit attack workflow against MSF2
SCENARIOS = {
    "port_scan": {
        "label": "Nmap Full Scan (Kali → MSF2)",
        "desc":  "nmap -A -p- — systematic service enumeration",
        "kali_cmd": "nmap -A -sV -p 21,22,23,25,80,139,445,3306,5432,5900",
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
            {"port": 139,   "delay": 0.05},
            {"port": 512,   "delay": 0.05},
            {"port": 513,   "delay": 0.05},
        ],
    },
    "brute_force": {
        "label": "Hydra SSH Brute Force (Kali)",
        "desc":  "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET",
        "kali_cmd": "hydra -l root -P rockyou.txt ssh://192.168.56.102",
        "steps": [{"port": 22, "delay": 0.06}] * 20,
    },
    "db_harvest": {
        "label": "DB Harvest + MySQL Brute (Metasploit)",
        "desc":  "use auxiliary/scanner/mysql/mysql_login — enumerate then brute",
        "kali_cmd": "msfconsole -x 'use auxiliary/scanner/mysql/mysql_login; set RHOSTS 192.168.56.102; run'",
        "steps": (
            [{"port": p, "delay": 0.1}  for p in [80, 443, 8080, 8443]]
            + [{"port": p, "delay": 0.1}  for p in [3306, 5432, 27017, 1433]]
            + [{"port": 3306, "delay": 0.04}] * 18
        ),
    },
    "ddos": {
        "label": "hping3 SYN Flood (Kali)",
        "desc":  "hping3 --flood --syn -p 80 TARGET — volumetric flood",
        "kali_cmd": "hping3 --flood --rand-source --syn -p 80 192.168.56.102",
        "steps": [{"port": 80, "delay": 0.01}] * 60,
    },
    "lateral_movement": {
        "label": "Lateral Movement Chain (Kali)",
        "desc":  "SMB → RDP → SSH → VNC post-exploitation traversal",
        "kali_cmd": "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.56.102; run'",
        "steps": [
            {"port": 445,  "delay": 0.10},
            {"port": 139,  "delay": 0.10},
            {"port": 3389, "delay": 0.10},
            {"port": 22,   "delay": 0.10},
            {"port": 5900, "delay": 0.10},
            {"port": 135,  "delay": 0.10},
            {"port": 22,   "delay": 0.05},
            {"port": 22,   "delay": 0.05},
        ] * 2,
    },
    "vsftpd_exploit": {
        "label": "VSFTPD 2.3.4 Backdoor (MSF2)",
        "desc":  "CVE-2011-2523 — trigger smiley-face backdoor on port 21",
        "kali_cmd": "msfconsole -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 192.168.56.102; run'",
        "steps": [
            {"port": 21,   "delay": 0.1},
            {"port": 21,   "delay": 0.1},
            {"port": 21,   "delay": 0.1},
            {"port": 6200, "delay": 0.5},  # backdoor shell port
        ],
    },
    "eternalblue": {
        "label": "EternalBlue / MS17-010 (MSF2)",
        "desc":  "CVE-2017-0144 — SMB exploit for unauthenticated RCE",
        "kali_cmd": "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.56.102; run'",
        "steps": [
            {"port": 445,  "delay": 0.08},
            {"port": 445,  "delay": 0.08},
            {"port": 445,  "delay": 0.08},
            {"port": 445,  "delay": 0.08},
            {"port": 445,  "delay": 0.08},
            {"port": 445,  "delay": 0.05},
            {"port": 445,  "delay": 0.05},
            {"port": 4444, "delay": 0.5},  # meterpreter reverse shell
        ],
    },
}

# ── Global state ─────────────────────────────────────────────────────────────
engine           = DetectionEngine()
events           = []
running          = False
MODE             = "simulation"
traffic_history  = deque(maxlen=60)
geo_hits         = defaultdict(int)
attack_log       = []
_packet_bucket   = []
_bucket_lock     = threading.Lock()
_last_flush      = time.time()
_tshark_proc     = None
tshark_warning   = None
TSHARK_AVAILABLE = shutil.which("tshark") is not None

# Kali / MSF2 lab config (can be overridden via /api/lab/config)
lab_config = {
    "kali_ip":   "192.168.56.101",
    "msf2_ip":   "192.168.56.102",
    "interface": "eth0",
    "msf2_mode": False,   # when True, target is Metasploitable2
}


def _flush_bucket(now):
    global _last_flush
    with _bucket_lock:
        if now - _last_flush >= 1.0:
            traffic_history.append(len(_packet_bucket))
            _packet_bucket.clear()
            _last_flush = now


# ── Event builder ─────────────────────────────────────────────────────────────
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
        "action_desc": [PLAYBOOK_DESCRIPTIONS.get(a, a) for a in actions],
        "mode":        mode_tag,
        "cves":        result.get("cves", []),
        "chain":       result.get("chain", ""),
        "msf2_target": result.get("msf2_target", False),
        "intent_score": result.get("intent_score", 0),
    }

    if ev["level"] in ("critical", "suspicious"):
        attack_log.append({
            "t":     int(now),
            "level": ev["level"],
            "type":  ev["type"],
            "src":   src_ip,
            "cves":  ev["cves"],
        })
        if len(attack_log) > 500:
            attack_log.pop(0)

    return ev


def _append(ev):
    events.append(ev)
    if len(events) > MAX_EVENTS:
        events.pop(0)
        for i, e in enumerate(events):
            e["id"] = i


# ── Simulation loop ──────────────────────────────────────────────────────────
PORTS_SIM = [21, 22, 23, 25, 80, 443, 139, 445, 512, 513, 514,
             3306, 3389, 5432, 5900, 6200, 6379, 6667, 8080, 27017]

def simulation_loop():
    global running
    target_ip = lab_config["msf2_ip"] if lab_config["msf2_mode"] else "192.168.1.1"
    while running and MODE == "simulation":
        is_attack = random.random() < 0.42
        src = random.choice(KALI_IPS) if is_attack else random.choice(NORMAL_IPS)
        if is_attack and random.random() < 0.55:
            src = lab_config["kali_ip"]
        port  = random.choice(PORTS_SIM[:14]) if is_attack else random.choice([80, 443, 53, 8080])
        proto = random.choice(["TCP", "TCP", "TCP", "UDP"])
        ev    = _build_event(src, target_ip, port, proto, mode_tag="simulation")
        _append(ev)
        time.sleep(random.uniform(0.12, 0.45))


# ── tshark live capture ───────────────────────────────────────────────────────
def _parse_tshark_line(line: str):
    """Parse a tshark TSV line — extract IP/port metadata only (no payload)."""
    try:
        parts = line.strip().split("\t")
        if len(parts) < 5:
            return None
        _ts, src, dst, tcp_port, udp_port = parts[:5]
        if not src or not dst:
            return None
        if tcp_port:
            raw_ports = tcp_port.split(",")
            port  = int(raw_ports[-1]) if raw_ports[-1].isdigit() else 0
            proto = "TCP"
        elif udp_port:
            raw_ports = udp_port.split(",")
            port  = int(raw_ports[-1]) if raw_ports[-1].isdigit() else 0
            proto = "UDP"
        else:
            return None
        if port == 0:
            return None
        return {"src": src.strip(), "dst": dst.strip(), "port": port, "proto": proto}
    except Exception:
        return None


def tshark_loop():
    """Continuous tshark live capture loop."""
    global running, _tshark_proc, tshark_warning
    iface = _best_interface()
    target_ip = lab_config["msf2_ip"] if lab_config["msf2_mode"] else None

    # Build tshark capture filter
    cap_filter = "ip"
    if target_ip:
        cap_filter = f"host {target_ip}"

    cmd = [
        "tshark", "-i", iface, "-l",
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-f", cap_filter,
        "-q",
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
        for line in proc.stdout:
            if not running:
                break
            pkt = _parse_tshark_line(line)
            if pkt:
                ev = _build_event(
                    pkt["src"], pkt["dst"], pkt["port"],
                    pkt["proto"], mode_tag="live"
                )
                _append(ev)
        proc.wait()
    except FileNotFoundError:
        tshark_warning = "tshark not found. Install: sudo apt install tshark"
    except PermissionError:
        tshark_warning = "Permission denied. Run: sudo python3 app.py"
    except Exception as e:
        tshark_warning = f"tshark error: {str(e)[:80]}"


def _best_interface():
    """Auto-select best network interface for capture."""
    if lab_config.get("interface") and lab_config["interface"] != "auto":
        return lab_config["interface"]
    try:
        result = subprocess.run(
            ["tshark", "-D"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().splitlines()
        for line in lines:
            if any(k in line.lower() for k in ["eth", "ens", "wlan", "en0"]):
                return line.split(".")[0].strip().split()[-1]
        return "1"
    except Exception:
        return "eth0"


# ── Master control loop ───────────────────────────────────────────────────────
def control_loop():
    global running, MODE
    while running:
        if MODE == "simulation":
            simulation_loop()
        elif MODE == "live":
            if not TSHARK_AVAILABLE:
                global tshark_warning
                tshark_warning = "tshark not installed. Run: sudo apt install tshark"
                MODE = "simulation"
                continue
            tshark_loop()
        time.sleep(0.1)


# ── Scenario injection ────────────────────────────────────────────────────────
def run_scenario_thread(name: str, kali_ip: str = None, target_ip: str = None):
    sc = SCENARIOS[name]
    src = kali_ip or lab_config["kali_ip"]
    dst = target_ip or lab_config["msf2_ip"]
    for step in sc["steps"]:
        if not running:
            break
        ev = _build_event(src, dst, step["port"], mode_tag=f"scenario:{name}")
        _append(ev)
        time.sleep(step["delay"])


# ── Flask routes ──────────────────────────────────────────────────────────────
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
    data     = request.get_json() or {}
    new_mode = data.get("mode", "simulation")
    if new_mode not in ("simulation", "live"):
        return jsonify({"ok": False, "error": "Invalid mode"}), 400
    if new_mode == "live" and not TSHARK_AVAILABLE:
        return jsonify({"ok": False, "error": "tshark not installed. Run: sudo apt install tshark"}), 400
    MODE           = new_mode
    tshark_warning = None
    return jsonify({"ok": True, "mode": MODE})


@app.route("/api/lab/config", methods=["GET", "POST"])
def lab_config_endpoint():
    global lab_config
    if request.method == "POST":
        data = request.get_json() or {}
        for key in ("kali_ip", "msf2_ip", "interface", "msf2_mode"):
            if key in data:
                lab_config[key] = data[key]
        return jsonify({"ok": True, "config": lab_config})
    return jsonify(lab_config)


@app.route("/api/simulate", methods=["POST"])
def simulate():
    data = request.get_json() or {}
    name = data.get("type", "port_scan")
    if name not in SCENARIOS:
        return jsonify({"ok": False, "error": f"Unknown scenario. Available: {list(SCENARIOS.keys())}"}), 400
    kali_ip   = data.get("kali_ip",   lab_config["kali_ip"])
    target_ip = data.get("target_ip", lab_config["msf2_ip"])
    threading.Thread(
        target=run_scenario_thread,
        args=(name, kali_ip, target_ip),
        daemon=True
    ).start()
    sc = SCENARIOS[name]
    return jsonify({
        "ok":       True,
        "scenario": name,
        "label":    sc["label"],
        "steps":    len(sc["steps"]),
        "kali_cmd": sc.get("kali_cmd", ""),
    })


@app.route("/api/scenarios")
def list_scenarios():
    return jsonify({
        k: {
            "label":    v["label"],
            "desc":     v["desc"],
            "steps":    len(v["steps"]),
            "kali_cmd": v.get("kali_cmd", ""),
        }
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
    msf2    = sum(1 for e in events if e.get("msf2_target"))
    cross   = engine.get_cross_ip_summary()
    return jsonify({
        "events":            new_evs,
        "running":           running,
        "mode":              MODE,
        "stats":             {"total": total, "critical": crit, "suspicious": susp, "safe": safe, "msf2": msf2},
        "traffic_history":   list(traffic_history),
        "top_attackers":     sorted(geo_hits.items(), key=lambda x: -x[1])[:8],
        "attack_log":        attack_log[-100:],
        "tshark_available":  TSHARK_AVAILABLE,
        "tshark_warning":    tshark_warning,
        "cross_ip":          cross,
        "lab_config":        lab_config,
    })


@app.route("/api/replay")
def replay():
    pct   = float(request.args.get("pct", 100)) / 100.0
    pool  = events[-REPLAY_MAX:]
    count = max(1, int(len(pool) * pct))
    return jsonify({"events": pool[:count], "total": len(pool)})


@app.route("/api/fingerprint/<ip>")
def fingerprint(ip):
    fp   = engine.get_fingerprint(ip)
    hits = geo_hits.get(ip, 0)
    return jsonify({"ip": ip, "hits": hits, "fingerprint": fp})


@app.route("/api/status")
def status():
    return jsonify({
        "running":          running,
        "mode":             MODE,
        "version":          VERSION,
        "total_events":     len(events),
        "engine":           "DetectionEngine v5 — Bayesian+MSF2",
        "tshark_available": TSHARK_AVAILABLE,
        "tshark_warning":   tshark_warning,
        "scenarios":        list(SCENARIOS.keys()),
        "lab_config":       lab_config,
    })


@app.route("/api/report")
def report():
    crit = sum(1 for e in events if e["level"] == "critical")
    susp = sum(1 for e in events if e["level"] == "suspicious")
    safe = sum(1 for e in events if e["level"] == "safe")
    msf2 = sum(1 for e in events if e.get("msf2_target"))
    lines = [
        "=" * 80,
        "  CYBER THREAT SANDBOX v5.0 — BEHAVIORAL INCIDENT REPORT",
        "  Bayesian Detection + Metasploitable2 CVE Profiling + Kali Integration",
        "=" * 80,
        f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Mode       : {MODE.upper()}",
        f"  Kali IP    : {lab_config['kali_ip']}",
        f"  MSF2 Target: {lab_config['msf2_ip']}",
        f"  Total      : {len(events)} events",
        f"  Critical   : {crit}",
        f"  Suspicious : {susp}",
        f"  Safe       : {safe}",
        f"  MSF2 Hits  : {msf2}",
        "=" * 80,
        f"  {'Time':<13} {'Mode':<14} {'Level':<12} {'Type':<18} {'Conf':>5}  "
        f"{'Src IP':<18} {'Port':<6} {'MITRE':<10}  Detail",
        "-" * 130,
    ]
    for e in events[-250:]:
        conf_str = f"{e.get('confidence', '?')}%"
        mode_str = e.get("mode", "sim")[:12]
        cve_str  = f" [{e['cves'][0]}]" if e.get("cves") else ""
        chain    = f" chain:{e['chain']}" if e.get("chain") else ""
        lines.append(
            f"  {e['time']:<13} {mode_str:<14} {e['level'].upper():<12} {e['type']:<18} "
            f"{conf_str:>5}  {e['src']:<18} {e['port']:<6} {e.get('mitre','-'):<10}  "
            f"{e['detail']}{cve_str}{chain}"
        )
        if e.get("explanation"):
            lines.append(f"    ↳ {e['explanation'][:115]}")
    body = "\n".join(lines)
    return body, 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f"attachment; filename=threat_report_v5_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "capture"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "backend"), exist_ok=True)
    init_file = os.path.join(BASE_DIR, "backend", "__init__.py")
    if not os.path.exists(init_file):
        open(init_file, "w").close()

    print()
    print("  ╔═══════════════════════════════════════════════════════════╗")
    print("  ║   CYBER THREAT SANDBOX  v5.0                              ║")
    print("  ║   Bayesian Detection · Metasploitable2 · Kali Integration ║")
    print(f"  ║   Kali: {lab_config['kali_ip']:<15}  MSF2: {lab_config['msf2_ip']:<17}║")
    print("  ║   → http://localhost:5000                                 ║")
    print("  ╚═══════════════════════════════════════════════════════════╝")
    print()
    if TSHARK_AVAILABLE:
        print("  ✓ tshark found — live capture available (sudo required)")
    else:
        print("  ⚠  tshark not found — simulation mode only")
        print("     Install: sudo apt install tshark  (Kali/Ubuntu)")
    print()

    app.run(debug=False, port=5000, threaded=True, host="0.0.0.0")
