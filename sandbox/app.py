"""
app.py v5.0 — Cyber Threat Simulation Sandbox
=============================================
Novel Patent-Worthy Features:
  1. Kali Tool Behavioral Signature Engine (KTBSE)
  2. Metasploitable2 Vulnerability Surface Mapper (MVSM)
  3. Multi-Phase Kill Chain Predictor (MKCP)
  4. Cross-IP Botnet Correlation Engine (CIBCE)
  5. Adaptive Defense Playbook (ADP)
  6. tshark subprocess capture — no Scapy/root dependency
"""

import subprocess
import threading
import time
import json
import os
import shutil
import random
from datetime import datetime, timedelta
from collections import defaultdict, deque
from flask import Flask, jsonify, request, render_template, send_file
from flask_cors import CORS

from detector import DetectionEngine
from simulator import run_scenario, list_scenarios, METASPLOITABLE2_SCENARIOS, KALI_SCENARIOS
from response_engine import get_response, get_compare, ADAPTIVE_PLAYBOOK
from explainer import explain_event, KALI_TOOL_EXPLANATIONS
from report_generator import generate_pdf

# ── App setup ────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="frontend/templates")
CORS(app)

# ── Global state ─────────────────────────────────────────────────────────────
events       = deque(maxlen=1000)
engine       = DetectionEngine()
running      = False
MODE         = "simulation"          # simulation | live
event_id_ctr = 0
lock         = threading.Lock()

# ── Novel Feature State ───────────────────────────────────────────────────────
ip_attack_groups  = defaultdict(set)   # CIBCE: tracks coordinated IP sets
kill_chain_state  = defaultdict(dict)  # MKCP: per-IP kill chain position
adaptive_scores   = defaultdict(int)   # ADP: per-IP sophistication score

# ── tshark check ─────────────────────────────────────────────────────────────
TSHARK_PATH     = shutil.which("tshark") or shutil.which("tshark.exe")
TSHARK_AVAILABLE = TSHARK_PATH is not None

# ─────────────────────────────────────────────────────────────────────────────
# NOVEL FEATURE 1: Kali Tool Behavioral Signature Engine (KTBSE)
# Identifies specific Kali Linux tools by traffic timing/port patterns
# ─────────────────────────────────────────────────────────────────────────────
KALI_TOOL_SIGNATURES = {
    "nmap_syn_scan": {
        "pattern": lambda ports, rate: len(ports) > 10 and rate > 5,
        "tool": "Nmap SYN Scan (-sS)",
        "cve_risk": "Information Disclosure",
        "confidence_boost": 20,
    },
    "nmap_service_ver": {
        "pattern": lambda ports, rate: len(ports) > 5 and rate < 2,
        "tool": "Nmap Service Version (-sV)",
        "cve_risk": "Service Enumeration",
        "confidence_boost": 15,
    },
    "hydra_ssh": {
        "pattern": lambda ports, rate: 22 in ports and rate > 10,
        "tool": "Hydra SSH Brute Force",
        "cve_risk": "Credential Attack",
        "confidence_boost": 25,
    },
    "hydra_ftp": {
        "pattern": lambda ports, rate: 21 in ports and rate > 8,
        "tool": "Hydra FTP Brute Force",
        "cve_risk": "Credential Attack",
        "confidence_boost": 25,
    },
    "sqlmap": {
        "pattern": lambda ports, rate: 80 in ports or 8080 in ports and rate > 3,
        "tool": "SQLMap Web Attack",
        "cve_risk": "SQL Injection",
        "confidence_boost": 18,
    },
    "metasploit_msf": {
        "pattern": lambda ports, rate: 4444 in ports or 5555 in ports,
        "tool": "Metasploit Framework",
        "cve_risk": "Remote Code Execution",
        "confidence_boost": 30,
    },
    "nikto_scan": {
        "pattern": lambda ports, rate: 80 in ports and rate > 4 and rate < 8,
        "tool": "Nikto Web Scanner",
        "cve_risk": "Web Vulnerability Scan",
        "confidence_boost": 12,
    },
    "medusa_rdp": {
        "pattern": lambda ports, rate: 3389 in ports and rate > 5,
        "tool": "Medusa RDP Attack",
        "cve_risk": "Remote Desktop Attack",
        "confidence_boost": 22,
    },
}

def identify_kali_tool(src_ip: str, recent_ports: set, pkt_rate: float) -> dict | None:
    """NOVEL: Identify specific Kali tool from traffic behavioral signature."""
    for sig_name, sig in KALI_TOOL_SIGNATURES.items():
        if sig["pattern"](recent_ports, pkt_rate):
            return {
                "kali_tool": sig["tool"],
                "signature": sig_name,
                "cve_risk":  sig["cve_risk"],
                "confidence_boost": sig["confidence_boost"],
            }
    return None

# ─────────────────────────────────────────────────────────────────────────────
# NOVEL FEATURE 2: Multi-Phase Kill Chain Predictor (MKCP)
# Predicts the NEXT likely attack step with probability
# Based on MITRE ATT&CK kill chain progression
# ─────────────────────────────────────────────────────────────────────────────
KILL_CHAIN_TRANSITIONS = {
    "idle":    [("recon",   0.85), ("idle",    0.15)],
    "recon":   [("exploit", 0.72), ("recon",   0.20), ("impact", 0.08)],
    "exploit": [("impact",  0.65), ("persist", 0.25), ("exploit", 0.10)],
    "persist": [("exfil",   0.70), ("impact",  0.20), ("persist", 0.10)],
    "impact":  [("exfil",   0.60), ("impact",  0.40)],
    "exfil":   [("exfil",   0.80), ("impact",  0.20)],
}

KILL_CHAIN_LABELS = {
    "idle":    "Quiet / Dormant",
    "recon":   "Reconnaissance",
    "exploit": "Exploitation",
    "persist": "Persistence",
    "impact":  "Impact / DoS",
    "exfil":   "Data Exfiltration",
}

def predict_next_phase(ip: str, current_phase: str) -> list:
    """NOVEL: Predict next attack phases with probabilities."""
    transitions = KILL_CHAIN_TRANSITIONS.get(current_phase, [])
    return [
        {
            "phase": phase,
            "label": KILL_CHAIN_LABELS.get(phase, phase),
            "probability": round(prob * 100),
        }
        for phase, prob in transitions
    ]

# ─────────────────────────────────────────────────────────────────────────────
# NOVEL FEATURE 3: Cross-IP Botnet Correlation Engine (CIBCE)
# Detects coordinated multi-source attacks
# ─────────────────────────────────────────────────────────────────────────────
ip_first_seen = {}
ip_target_ports = defaultdict(set)
coordination_window = deque(maxlen=500)  # (timestamp, src_ip, dst_port)

def check_botnet_coordination(src_ip: str, dst_port: int) -> dict | None:
    """NOVEL: Detect coordinated attacks from multiple IPs."""
    now = time.time()
    coordination_window.append((now, src_ip, dst_port))
    cutoff = now - 30  # 30-second window

    # IPs targeting same port in last 30s
    recent = [(t, ip, p) for (t, ip, p) in coordination_window if t > cutoff and p == dst_port]
    unique_ips = {ip for (_, ip, _) in recent}

    if len(unique_ips) >= 3 and dst_port in {22, 3306, 5432, 3389, 21, 6379}:
        return {
            "botnet_detected": True,
            "coordinated_ips": len(unique_ips),
            "target_port": dst_port,
            "detail": f"Coordinated attack: {len(unique_ips)} IPs targeting port {dst_port}",
        }
    return None

# ─────────────────────────────────────────────────────────────────────────────
# NOVEL FEATURE 4: Adaptive Defense Playbook (ADP)
# Response escalation based on attacker sophistication score
# ─────────────────────────────────────────────────────────────────────────────
def compute_sophistication(ip: str) -> int:
    """NOVEL: Score attacker sophistication 0–100."""
    fp = engine.get_fingerprint(ip)
    score = 0
    phase_scores = {"idle": 0, "recon": 20, "exploit": 50, "persist": 70, "impact": 60, "exfil": 90}
    score += phase_scores.get(fp.get("phase", "idle"), 0)
    score += min(30, fp.get("total_pkts", 0) // 10)
    unique_ports = len(set(fp.get("port_seq", [])))
    score += min(20, unique_ports * 2)
    return min(100, score)

def get_adaptive_response(ip: str, threat_type: str) -> dict:
    """NOVEL: Adapt response based on attacker sophistication."""
    score = compute_sophistication(ip)
    adaptive_scores[ip] = score

    if score >= 75:
        level = "CRITICAL_RESPONSE"
        actions = ["Block IP globally", "Honeypot redirect", "Threat intel share", "Incident ticket auto-create"]
        color = "#ef4444"
    elif score >= 50:
        level = "ELEVATED_RESPONSE"
        actions = ["Rate limit aggressive", "Session invalidation", "MFA challenge", "SIEM alert"]
        color = "#f59e0b"
    elif score >= 25:
        level = "MODERATE_RESPONSE"
        actions = ["Temporary rate limit", "Log to SIEM", "Watch list addition"]
        color = "#eab308"
    else:
        level = "BASELINE_RESPONSE"
        actions = ["Log event", "Continue monitoring"]
        color = "#22c55e"

    return {
        "level": level,
        "sophistication_score": score,
        "actions": actions,
        "color": color,
        "next_phases": predict_next_phase(ip, engine.get_fingerprint(ip).get("phase", "idle")),
    }

# ─────────────────────────────────────────────────────────────────────────────
# tshark Live Capture (NOVEL: no root Scapy, uses system tshark)
# ─────────────────────────────────────────────────────────────────────────────
tshark_proc = None

def start_tshark_capture():
    """Start tshark subprocess for live packet capture. Metadata only."""
    global tshark_proc
    if not TSHARK_AVAILABLE:
        return False

    cmd = [
        TSHARK_PATH,
        "-l",                          # line-buffered
        "-T", "fields",                # field extraction mode
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-E", "separator=|",
        "-E", "header=n",
        "-f", "ip",                    # BPF filter: IP only
    ]

    try:
        tshark_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        return True
    except Exception as e:
        print(f"tshark start error: {e}")
        return False

def tshark_reader_thread():
    """Reads tshark output, parses fields, feeds DetectionEngine."""
    global tshark_proc
    if not tshark_proc:
        return

    for line in tshark_proc.stdout:
        if not running or MODE != "live":
            break
        line = line.strip()
        if not line:
            continue

        parts = line.split("|")
        if len(parts) < 5:
            continue

        src_ip   = parts[0] or "unknown"
        dst_ip   = parts[1] or "unknown"
        tcp_dport = parts[2]
        udp_dport = parts[3]
        proto_num = parts[4]
        frame_len = parts[5] if len(parts) > 5 else "0"

        dport = 0
        if tcp_dport:
            try: dport = int(tcp_dport)
            except: pass
        elif udp_dport:
            try: dport = int(udp_dport)
            except: pass

        proto = "TCP" if tcp_dport else ("UDP" if udp_dport else "OTHER")

        pkt = {
            "src_ip":  src_ip,
            "dst_ip":  dst_ip,
            "dst_port": dport,
            "protocol": proto,
            "size":    int(frame_len) if frame_len.isdigit() else 0,
        }

        _process_packet(pkt, source="tshark")

def stop_tshark():
    global tshark_proc
    if tshark_proc:
        try:
            tshark_proc.terminate()
            tshark_proc = None
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# Event Processing Core
# ─────────────────────────────────────────────────────────────────────────────
def _process_packet(pkt: dict, source: str = "simulation"):
    """Central event processor — applies all novel features."""
    global event_id_ctr

    src_ip  = pkt.get("src_ip", "unknown")
    dport   = int(pkt.get("dst_port", 0))

    # Core detection
    det = engine.analyze(pkt)

    # Kali tool identification (KTBSE)
    fp = engine.get_fingerprint(src_ip)
    recent_ports = set(fp.get("port_seq", []))
    recent_pkt_count = fp.get("total_pkts", 0)
    pkt_rate = recent_pkt_count / 30.0  # rough rate
    kali_id = identify_kali_tool(src_ip, recent_ports, pkt_rate)

    # Botnet correlation (CIBCE)
    botnet = check_botnet_coordination(src_ip, dport)

    # Adaptive response (ADP)
    adaptive = get_adaptive_response(src_ip, det.get("threat_type", "NORMAL"))

    # Kill chain prediction (MKCP)
    predictions = predict_next_phase(src_ip, fp.get("phase", "idle"))

    # Build unified event
    with lock:
        event_id_ctr += 1
        ev = {
            "id":            event_id_ctr,
            "timestamp":     datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip":        src_ip,
            "dst_port":      dport,
            "protocol":      pkt.get("protocol", "TCP"),
            "size":          pkt.get("size", 0),
            "threat_level":  det["threat_level"],
            "threat_type":   det["threat_type"],
            "confidence":    det["confidence"],
            "detail":        det["detail"],
            "explanation":   det["explanation"],
            "mitre":         det["mitre"],
            "mitre_name":    det["mitre_name"],
            "phase":         fp.get("phase", "idle"),
            "source":        source,
            # Novel features
            "kali_tool":     kali_id,
            "botnet":        botnet,
            "adaptive":      adaptive,
            "predictions":   predictions,
            "sophistication": adaptive["sophistication_score"],
        }
        events.append(ev)

def make_simulation_event():
    """Generate a synthetic simulation event."""
    import random
    from simulator import run_scenario, SCENARIOS

    scenario_key = random.choice(list(SCENARIOS.keys()))
    scenario_events = run_scenario(scenario_key)
    if scenario_events:
        raw = random.choice(scenario_events)
        src_ip = raw.get("ip", f"{random.randint(10,220)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}")

        # Map scenario type to a port
        port_map = {
            "brute_force":      random.choice([22, 3389, 21]),
            "port_scan":        random.choice([22, 80, 443, 3306, 5432, 8080, 27017]),
            "account_takeover": random.choice([443, 80]),
            "ddos":             random.choice([80, 443]),
            "db_harvest":       random.choice([3306, 5432, 27017, 6379]),
            "lateral_movement": random.choice([445, 3389, 22]),
        }
        dport = port_map.get(scenario_key, random.choice([22, 80, 443, 3306, 3389]))

        _process_packet({
            "src_ip":   src_ip,
            "dst_port": dport,
            "protocol": "TCP",
            "size":     random.randint(40, 1500),
        }, source="simulation")

# ─────────────────────────────────────────────────────────────────────────────
# Background simulation loop
# ─────────────────────────────────────────────────────────────────────────────
def simulation_loop():
    while True:
        if running:
            if MODE == "simulation":
                make_simulation_event()
                time.sleep(random.uniform(0.5, 1.5))
            elif MODE == "live" and not TSHARK_AVAILABLE:
                # Fallback: simulation if tshark not found
                make_simulation_event()
                time.sleep(1.0)
        else:
            time.sleep(0.2)

sim_thread = threading.Thread(target=simulation_loop, daemon=True)
sim_thread.start()

# ─────────────────────────────────────────────────────────────────────────────
# Flask Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/status")
def status():
    return jsonify({
        "running":           running,
        "mode":              MODE,
        "total_events":      len(events),
        "engine":            "DetectionEngine v5.0",
        "tshark_available":  TSHARK_AVAILABLE,
        "tshark_path":       TSHARK_PATH,
        "novel_features": [
            "Kali Tool Behavioral Signature Engine",
            "Metasploitable2 Vulnerability Surface Mapper",
            "Multi-Phase Kill Chain Predictor",
            "Cross-IP Botnet Correlation Engine",
            "Adaptive Defense Playbook",
        ],
    })

@app.route("/api/start", methods=["POST"])
def start():
    global running
    running = True
    if MODE == "live" and TSHARK_AVAILABLE:
        if start_tshark_capture():
            t = threading.Thread(target=tshark_reader_thread, daemon=True)
            t.start()
    return jsonify({"ok": True, "mode": MODE})

@app.route("/api/stop", methods=["POST"])
def stop():
    global running
    running = False
    stop_tshark()
    return jsonify({"ok": True})

@app.route("/api/reset", methods=["POST"])
def reset():
    global running, events, event_id_ctr
    running = False
    stop_tshark()
    with lock:
        events.clear()
        event_id_ctr = 0
    engine._fp.clear()
    engine._windows.clear()
    ip_attack_groups.clear()
    kill_chain_state.clear()
    adaptive_scores.clear()
    coordination_window.clear()
    return jsonify({"ok": True})

@app.route("/api/mode", methods=["POST"])
def set_mode():
    global MODE
    data = request.get_json(silent=True) or {}
    new_mode = data.get("mode", "simulation")
    if new_mode not in ("simulation", "live"):
        return jsonify({"ok": False, "error": "Invalid mode"}), 400
    if new_mode == "live" and not TSHARK_AVAILABLE:
        return jsonify({
            "ok":    False,
            "error": "tshark not found. Install with: sudo apt install tshark",
            "mode":  MODE,
        }), 200
    MODE = new_mode
    return jsonify({"ok": True, "mode": MODE})

@app.route("/api/events")
def get_events():
    since = int(request.args.get("since", 0))
    with lock:
        ev_list = [e for e in events if e["id"] > since]
    stats = _compute_stats()
    return jsonify({
        "events":     ev_list,
        "running":    running,
        "mode":       MODE,
        "stats":      stats,
        "top_attackers": _top_attackers(),
        "botnet_alerts": _botnet_summary(),
        "tshark_available": TSHARK_AVAILABLE,
    })

@app.route("/api/replay")
def replay():
    pct = float(request.args.get("pct", 0)) / 100.0
    with lock:
        ev_list = list(events)
    if not ev_list:
        return jsonify({"events": [], "count": 0})
    end_idx = max(1, int(len(ev_list) * pct))
    return jsonify({
        "events": ev_list[:end_idx],
        "count":  end_idx,
        "total":  len(ev_list),
    })

@app.route("/api/simulate", methods=["POST"])
def inject_scenario():
    """Inject a named scenario into the live event stream."""
    data = request.get_json(silent=True) or {}
    stype = data.get("type", "port_scan")

    all_scenarios = {**list_scenarios(), **METASPLOITABLE2_SCENARIOS, **KALI_SCENARIOS}
    if stype not in all_scenarios:
        return jsonify({"ok": False, "error": f"Unknown scenario: {stype}"}), 400

    def inject():
        from simulator import run_scenario as rs, METASPLOITABLE2_SCENARIOS as ms, KALI_SCENARIOS as ks
        if stype in ms:
            from simulator import run_metasploitable2_scenario
            evts = run_metasploitable2_scenario(stype)
        elif stype in ks:
            from simulator import run_kali_scenario
            evts = run_kali_scenario(stype)
        else:
            evts = rs(stype)

        for e in evts:
            if not running:
                break
            _process_packet({
                "src_ip":   e.get("ip", "10.0.0.1"),
                "dst_port": e.get("dport", 80),
                "protocol": "TCP",
                "size":     random.randint(40, 1500),
            }, source="injected_scenario")
            time.sleep(random.uniform(0.3, 0.8))

    threading.Thread(target=inject, daemon=True).start()
    return jsonify({"ok": True, "scenario": stype})

@app.route("/api/scenarios")
def scenarios():
    base  = list_scenarios()
    msf   = {k: {"label": v["label"], "description": v["description"], "source": "metasploitable2"}
             for k, v in METASPLOITABLE2_SCENARIOS.items()}
    kali  = {k: {"label": v["label"], "description": v["description"], "source": "kali"}
             for k, v in KALI_SCENARIOS.items()}
    return jsonify({"simulation": base, "metasploitable2": msf, "kali": kali})

@app.route("/api/fingerprint/<ip>")
def fingerprint(ip):
    fp   = engine.get_fingerprint(ip)
    adp  = get_adaptive_response(ip, "NORMAL")
    preds = predict_next_phase(ip, fp.get("phase", "idle"))
    return jsonify({
        "ip":            ip,
        "fingerprint":   fp,
        "sophistication": adaptive_scores.get(ip, 0),
        "adaptive":      adp,
        "predictions":   preds,
    })

@app.route("/api/report", methods=["POST"])
def report():
    data    = request.get_json(silent=True) or {}
    with lock:
        ev_list = list(events)

    stats = _compute_stats()
    report_data = {
        "scenario":      data.get("scenario", "Live Capture"),
        "timeline":      [_ev_to_report(e) for e in ev_list[-50:]],
        "summary":       stats,
        "compare":       get_compare(data.get("scenario", "port_scan")),
        "ai_explanation": data.get("ai_explanation", ""),
        "novel_detections": {
            "kali_tools_detected": [e["kali_tool"]["kali_tool"] for e in ev_list if e.get("kali_tool")],
            "botnet_alerts": sum(1 for e in ev_list if e.get("botnet")),
            "top_sophistication": max((e["sophistication"] for e in ev_list), default=0),
        }
    }
    path = generate_pdf(report_data)
    return send_file(path, as_attachment=True, download_name="incident_report.pdf")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _compute_stats() -> dict:
    with lock:
        ev_list = list(events)
    if not ev_list:
        return {"total_events": 0, "attacks_detected": 0, "suspicious_events": 0,
                "threat_level": "safe", "unique_ips": 0, "responses_taken": 0}
    attacks    = sum(1 for e in ev_list if e["threat_level"] == "critical")
    suspicious = sum(1 for e in ev_list if e["threat_level"] == "suspicious")
    ips        = {e["src_ip"] for e in ev_list}
    tl = "critical" if attacks > 0 else ("suspicious" if suspicious > 0 else "safe")
    return {
        "total_events":      len(ev_list),
        "attacks_detected":  attacks,
        "suspicious_events": suspicious,
        "threat_level":      tl,
        "unique_ips":        len(ips),
        "responses_taken":   attacks,
        "kali_detections":   sum(1 for e in ev_list if e.get("kali_tool")),
        "botnet_alerts":     sum(1 for e in ev_list if e.get("botnet")),
    }

def _top_attackers() -> list:
    with lock:
        ev_list = list(events)
    ip_counts = defaultdict(int)
    ip_max_threat = defaultdict(str)
    for e in ev_list:
        ip = e["src_ip"]
        ip_counts[ip] += 1
        if e["threat_level"] == "critical":
            ip_max_threat[ip] = "critical"
        elif e["threat_level"] == "suspicious" and ip_max_threat[ip] != "critical":
            ip_max_threat[ip] = "suspicious"
        else:
            ip_max_threat.setdefault(ip, "safe")
    top = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return [{"ip": ip, "count": cnt, "threat": ip_max_threat[ip],
             "sophistication": adaptive_scores.get(ip, 0)} for ip, cnt in top]

def _botnet_summary() -> list:
    alerts = []
    with lock:
        ev_list = list(events)
    for e in ev_list[-100:]:
        if e.get("botnet"):
            alerts.append(e["botnet"])
    return alerts[-5:]  # last 5 botnet alerts

def _ev_to_report(e: dict) -> dict:
    return {
        "timestamp":  e["timestamp"],
        "status":     e["threat_level"],
        "detail":     e["detail"],
        "explanation": e["explanation"],
        "mitre":      e["mitre"],
    }

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    os.makedirs("frontend/templates", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    print("="*60)
    print("  Cyber Threat Simulation Sandbox v5.0")
    print(f"  tshark: {'✓ Found at ' + TSHARK_PATH if TSHARK_AVAILABLE else '✗ Not found (simulation only)'}")
    print("  Novel features: KTBSE · MVSM · MKCP · CIBCE · ADP")
    print("="*60)
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
