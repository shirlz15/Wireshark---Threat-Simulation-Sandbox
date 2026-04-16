"""
simulator.py v5.0
Three event sources:
  1. Simulated       — synthetic scenarios (original)
  2. Metasploitable2 — realistic attack chains against known vulns
  3. Kali Linux      — tool-specific attack signatures
  4. tshark Live     — real packets via subprocess (handled in app.py)
"""

import random
from datetime import datetime, timedelta


# ── Metasploitable2 IP (configurable) ────────────────────────────────────────
METASPLOITABLE2_IP = "192.168.1.100"   # Change to your VM's IP
ATTACKER_IP        = "192.168.1.200"   # Kali Linux IP

def fake_ip():
    return f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ── Original Scenarios ────────────────────────────────────────────────────────
SCENARIOS = {
    "port_scan": {
        "label": "Port Scan",
        "description": "12-port systematic sweep",
        "icon": "scan", "color": "amber",
        "events": [
            {"type": "port_probe", "status": "safe",       "detail": "Probe on port 22 (SSH) from {ip}",              "dport": 22},
            {"type": "port_probe", "status": "safe",       "detail": "Probe on port 80 (HTTP) from {ip}",             "dport": 80},
            {"type": "port_probe", "status": "suspicious", "detail": "DB ports 3306/5432 probed by {ip}",             "dport": 3306},
            {"type": "port_probe", "status": "suspicious", "detail": "8 ports in 10s from {ip} — scan pattern",       "dport": 443},
            {"type": "port_probe", "status": "attack",     "detail": "Full port scan confirmed — {ip} mapping services","dport": 27017},
            {"type": "close_ports","status": "response",   "detail": "Unused ports closed — {ip} rate-limited",       "dport": 0},
        ],
    },
    "brute_force": {
        "label": "Brute Force Login",
        "description": "SSH/RDP credential stuffing",
        "icon": "key", "color": "red",
        "events": [
            {"type": "login_attempt", "status": "safe",       "detail": "Login attempt from {ip}",                    "dport": 22},
            {"type": "login_failed",  "status": "safe",       "detail": "Wrong password from {ip} — 1st failure",     "dport": 22},
            {"type": "login_failed",  "status": "suspicious", "detail": "3rd failure from {ip} within 30s",           "dport": 22},
            {"type": "login_failed",  "status": "attack",     "detail": "10 failures/60s from {ip} — Hydra pattern",  "dport": 22},
            {"type": "block_ip",      "status": "response",   "detail": "IP {ip} blocked — account locked",           "dport": 0},
        ],
    },
    "account_takeover": {
        "label": "Account Takeover",
        "description": "Stolen credentials + anomaly",
        "icon": "user", "color": "purple",
        "events": [
            {"type": "login_attempt",   "status": "safe",       "detail": "Login from {ip} — valid credentials",      "dport": 443},
            {"type": "geo_flag",        "status": "suspicious", "detail": "Geo anomaly — account normally IN, now RU", "dport": 443},
            {"type": "time_flag",       "status": "suspicious", "detail": "Login at 03:17 AM — unusual hour",         "dport": 443},
            {"type": "behavior_flag",   "status": "attack",     "detail": "Bulk export 4,000 records in 3min",        "dport": 443},
            {"type": "restrict_access", "status": "response",   "detail": "Session revoked — MFA challenge sent",     "dport": 0},
        ],
    },
    "ddos": {
        "label": "DDoS Flood",
        "description": "Volumetric flood attack",
        "icon": "zap", "color": "orange",
        "events": [
            {"type": "traffic_spike", "status": "safe",       "detail": "Traffic 200 req/min — normal",               "dport": 80},
            {"type": "traffic_spike", "status": "suspicious", "detail": "Spike to 2,000 req/min",                     "dport": 80},
            {"type": "traffic_spike", "status": "attack",     "detail": "50,000 req/min — DDoS confirmed",            "dport": 80},
            {"type": "rate_limit",    "status": "response",   "detail": "CDN throttle — capped at 10 req/min",        "dport": 0},
        ],
    },
    "db_harvest": {
        "label": "DB Harvest",
        "description": "Web recon → DB credential attack",
        "icon": "database", "color": "teal",
        "events": [
            {"type": "port_probe", "status": "safe",       "detail": "HTTP probe from {ip}",          "dport": 80},
            {"type": "port_probe", "status": "suspicious", "detail": "MySQL port 3306 probed by {ip}","dport": 3306},
            {"type": "port_probe", "status": "suspicious", "detail": "MongoDB 27017 probed by {ip}",  "dport": 27017},
            {"type": "login_failed","status": "attack",    "detail": "DB brute force from {ip}",      "dport": 3306},
            {"type": "block_ip",   "status": "response",   "detail": "DB ports isolated — {ip} blocked","dport": 0},
        ],
    },
    "lateral_movement": {
        "label": "Lateral Movement",
        "description": "SMB + RDP + SSH pivot chain",
        "icon": "arrows", "color": "blue",
        "events": [
            {"type": "port_probe", "status": "safe",       "detail": "SMB port 445 probed from {ip}", "dport": 445},
            {"type": "port_probe", "status": "suspicious", "detail": "RDP 3389 probed by {ip}",       "dport": 3389},
            {"type": "port_probe", "status": "attack",     "detail": "SSH 22 probed — lateral chain detected","dport": 22},
            {"type": "block_ip",   "status": "response",   "detail": "Lateral movement blocked",       "dport": 0},
        ],
    },
}


def run_scenario(name: str) -> list:
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {name}")
    sc   = SCENARIOS[name]
    ip   = fake_ip()
    base = datetime.now()
    events = []
    for i, tmpl in enumerate(sc["events"]):
        offset = sum(random.randint(5, 12) for _ in range(i))
        ts = base + timedelta(seconds=offset)
        events.append({
            "id":        i + 1,
            "timestamp": ts.strftime("%H:%M:%S"),
            "type":      tmpl["type"],
            "status":    tmpl["status"],
            "detail":    tmpl["detail"].format(ip=ip),
            "ip":        ip,
            "dport":     tmpl.get("dport", 0),
            "scenario":  name,
            "source":    "simulated",
        })
    return events


def list_scenarios() -> dict:
    return {k: {"label": v["label"], "description": v["description"],
                "icon": v["icon"], "color": v["color"]} for k, v in SCENARIOS.items()}


# ── Metasploitable2 Scenarios ─────────────────────────────────────────────────
METASPLOITABLE2_SCENARIOS = {
    "vsftpd_backdoor": {
        "label": "vsFTPd 2.3.4 Backdoor (CVE-2011-2523)",
        "description": "Exploit the smiley-face backdoor in vsFTPd 2.3.4 for shell access",
        "icon": "terminal",
        "color": "red",
        "events": [
            {"dport": 21,  "detail": "FTP banner grab on port 21 — vsftpd 2.3.4 identified",          "status": "suspicious"},
            {"dport": 21,  "detail": "CVE-2011-2523: Sending backdoor trigger sequence :)",            "status": "attack"},
            {"dport": 6200,"detail": "Backdoor shell opened on port 6200 from {ip}",                   "status": "attack"},
            {"dport": 6200,"detail": "Meterpreter session established — full shell access",            "status": "attack"},
            {"dport": 0,   "detail": "FTP service isolated — inbound port 6200 blocked",               "status": "response"},
        ],
    },
    "samba_cmd_injection": {
        "label": "Samba usermap_script (CVE-2007-2447)",
        "description": "Exploit Samba 3.x username map script for unauthenticated RCE",
        "icon": "code",
        "color": "red",
        "events": [
            {"dport": 139, "detail": "SMB probe on port 139 — Samba 3.0.20 identified",              "status": "suspicious"},
            {"dport": 139, "detail": "CVE-2007-2447: Malformed username with shell metacharacters",   "status": "attack"},
            {"dport": 139, "detail": "Command injection executed — reverse shell payload sent",        "status": "attack"},
            {"dport": 4444, "detail": "Reverse shell on port 4444 — attacker has root access",        "status": "attack"},
            {"dport": 0,    "detail": "Samba patched — port 139 firewall rule added",                 "status": "response"},
        ],
    },
    "distcc_rce": {
        "label": "distcc RCE (CVE-2004-2687)",
        "description": "Exploit distcc daemon for arbitrary command execution",
        "icon": "cpu",
        "color": "orange",
        "events": [
            {"dport": 3632, "detail": "distcc probe on port 3632 — daemon detected",                  "status": "suspicious"},
            {"dport": 3632, "detail": "CVE-2004-2687: Malicious compile job with embedded command",   "status": "attack"},
            {"dport": 3632, "detail": "RCE payload executed as daemon user",                           "status": "attack"},
            {"dport": 0,    "detail": "distcc service terminated — port 3632 closed",                 "status": "response"},
        ],
    },
    "unrealircd_backdoor": {
        "label": "UnrealIRCd Backdoor (CVE-2010-2075)",
        "description": "Exploit backdoor in UnrealIRCd 3.2.8.1",
        "icon": "message",
        "color": "purple",
        "events": [
            {"dport": 6667, "detail": "IRC port 6667 probed — UnrealIRCd 3.2.8.1 identified",       "status": "suspicious"},
            {"dport": 6667, "detail": "CVE-2010-2075: Sending backdoor magic bytes AB;",             "status": "attack"},
            {"dport": 6667, "detail": "Backdoor triggered — command executed on server",              "status": "attack"},
            {"dport": 0,    "detail": "IRC service terminated — port 6667 blocked",                  "status": "response"},
        ],
    },
    "mysql_anon_auth": {
        "label": "MySQL Anonymous Auth (CVE-2012-2122)",
        "description": "MySQL 5.x authentication bypass for full DB access",
        "icon": "database",
        "color": "amber",
        "events": [
            {"dport": 3306, "detail": "MySQL port 3306 open — version 5.0.51a detected",             "status": "suspicious"},
            {"dport": 3306, "detail": "CVE-2012-2122: Auth bypass with repeated wrong password",     "status": "attack"},
            {"dport": 3306, "detail": "Authentication succeeded — full database access granted",      "status": "attack"},
            {"dport": 3306, "detail": "SELECT * FROM users — credentials exfiltrated",               "status": "attack"},
            {"dport": 0,    "detail": "MySQL isolated — anonymous auth disabled",                    "status": "response"},
        ],
    },
    "postgres_rce": {
        "label": "PostgreSQL RCE (CVE-2013-1899)",
        "description": "PostgreSQL arbitrary file overwrite → command execution",
        "icon": "database",
        "color": "blue",
        "events": [
            {"dport": 5432, "detail": "PostgreSQL 8.3 detected on port 5432",                        "status": "suspicious"},
            {"dport": 5432, "detail": "CVE-2013-1899: Connecting with malformed database name",      "status": "attack"},
            {"dport": 5432, "detail": "Config file overwrite — RCE via COPY TO/FROM",               "status": "attack"},
            {"dport": 0,    "detail": "PostgreSQL patched — external connections restricted",         "status": "response"},
        ],
    },
    "vnc_auth_bypass": {
        "label": "VNC Auth Bypass (CVE-2006-2369)",
        "description": "Connect to VNC with no password required",
        "icon": "monitor",
        "color": "green",
        "events": [
            {"dport": 5900, "detail": "VNC port 5900 open — RealVNC 3.3 detected",                  "status": "suspicious"},
            {"dport": 5900, "detail": "CVE-2006-2369: Null authentication byte sent",               "status": "attack"},
            {"dport": 5900, "detail": "VNC desktop session opened — no password required",           "status": "attack"},
            {"dport": 0,    "detail": "VNC service terminated — password authentication enforced",   "status": "response"},
        ],
    },
    "tomcat_default_creds": {
        "label": "Tomcat Manager Default Creds",
        "description": "Login with tomcat/tomcat — upload WAR webshell",
        "icon": "server",
        "color": "orange",
        "events": [
            {"dport": 8180, "detail": "Tomcat 5.5 Manager detected on port 8180",                   "status": "suspicious"},
            {"dport": 8180, "detail": "Attempting default credentials: tomcat/tomcat",               "status": "attack"},
            {"dport": 8180, "detail": "Login succeeded — Manager interface accessible",              "status": "attack"},
            {"dport": 8180, "detail": "WAR file uploaded — webshell deployed",                       "status": "attack"},
            {"dport": 0,    "detail": "Tomcat credentials reset — Manager UI restricted to localhost","status": "response"},
        ],
    },
}


def run_metasploitable2_scenario(name: str) -> list:
    if name not in METASPLOITABLE2_SCENARIOS:
        raise ValueError(f"Unknown Metasploitable2 scenario: {name}")
    sc   = METASPLOITABLE2_SCENARIOS[name]
    ip   = ATTACKER_IP
    base = datetime.now()
    events = []
    for i, tmpl in enumerate(sc["events"]):
        offset = sum(random.randint(3, 8) for _ in range(i))
        ts = base + timedelta(seconds=offset)
        events.append({
            "id":        i + 1,
            "timestamp": ts.strftime("%H:%M:%S"),
            "type":      "exploit_attempt",
            "status":    tmpl["status"],
            "detail":    tmpl["detail"].format(ip=ip),
            "ip":        ip,
            "dport":     tmpl.get("dport", 0),
            "target":    METASPLOITABLE2_IP,
            "scenario":  name,
            "source":    "metasploitable2",
        })
    return events


# ── Kali Linux Tool Scenarios ─────────────────────────────────────────────────
KALI_SCENARIOS = {
    "nmap_full_scan": {
        "label": "Nmap Full Scan (-sV -O)",
        "description": "Service version + OS fingerprint scan from Kali",
        "icon": "radar",
        "color": "cyan",
        "events": [
            {"dport": 22,   "detail": "Nmap SYN probe on port 22 (SSH)",                            "status": "safe"},
            {"dport": 80,   "detail": "Nmap SYN probe on port 80 (HTTP)",                           "status": "safe"},
            {"dport": 443,  "detail": "Nmap SYN probe on port 443 (HTTPS)",                         "status": "suspicious"},
            {"dport": 3306, "detail": "Nmap service probe on port 3306 — MySQL 5.0 identified",     "status": "suspicious"},
            {"dport": 5432, "detail": "Nmap service probe on port 5432 — PostgreSQL detected",      "status": "suspicious"},
            {"dport": 8180, "detail": "Nmap: Apache Tomcat 5.5 on port 8180",                      "status": "suspicious"},
            {"dport": 6667, "detail": "Nmap: UnrealIRCd on port 6667",                             "status": "attack"},
            {"dport": 3632, "detail": "Nmap: distcc on port 3632 — RCE risk flagged",              "status": "attack"},
        ],
    },
    "hydra_ssh_attack": {
        "label": "Hydra SSH Brute Force",
        "description": "Hydra dictionary attack against SSH from Kali",
        "icon": "key",
        "color": "red",
        "events": [
            {"dport": 22, "detail": "Hydra: SSH attempt — user:root pass:admin",                    "status": "safe"},
            {"dport": 22, "detail": "Hydra: SSH attempt — user:root pass:root",                     "status": "safe"},
            {"dport": 22, "detail": "Hydra: SSH attempt — user:msfadmin pass:msfadmin",             "status": "suspicious"},
            {"dport": 22, "detail": "Hydra: 8 attempts/10s — rate threshold exceeded",              "status": "attack"},
            {"dport": 22, "detail": "Hydra: Password found — msfadmin:msfadmin",                    "status": "attack"},
            {"dport": 0,  "detail": "SSH rate-limited — fail2ban triggered",                        "status": "response"},
        ],
    },
    "sqlmap_attack": {
        "label": "SQLMap Web Injection",
        "description": "Automated SQL injection scan via SQLMap from Kali",
        "icon": "code",
        "color": "yellow",
        "events": [
            {"dport": 80,  "detail": "SQLMap: GET /index.php?id=1 — normal request",               "status": "safe"},
            {"dport": 80,  "detail": "SQLMap: GET /index.php?id=1 AND 1=1 — boolean test",        "status": "suspicious"},
            {"dport": 80,  "detail": "SQLMap: Time-based blind injection detected",                 "status": "attack"},
            {"dport": 80,  "detail": "SQLMap: UNION SELECT dump — credentials extracted",          "status": "attack"},
            {"dport": 0,   "detail": "WAF rule activated — SQLi patterns blocked",                  "status": "response"},
        ],
    },
    "nikto_web_scan": {
        "label": "Nikto Web Vulnerability Scan",
        "description": "Nikto web scanner checking for 6,700+ known issues",
        "icon": "search",
        "color": "blue",
        "events": [
            {"dport": 80,  "detail": "Nikto: robots.txt enumeration",                               "status": "safe"},
            {"dport": 80,  "detail": "Nikto: /admin/ directory found — 403 response",              "status": "suspicious"},
            {"dport": 80,  "detail": "Nikto: /phpmyadmin/ accessible — default creds",             "status": "suspicious"},
            {"dport": 80,  "detail": "Nikto: Apache mod_status exposed at /server-status",         "status": "attack"},
            {"dport": 0,   "detail": "Web scan detected — IP throttled via WAF",                   "status": "response"},
        ],
    },
    "metasploit_handler": {
        "label": "Metasploit Reverse Shell Handler",
        "description": "MSF multi/handler waiting for reverse meterpreter",
        "icon": "terminal",
        "color": "red",
        "events": [
            {"dport": 4444, "detail": "Metasploit: multi/handler listening on port 4444",           "status": "suspicious"},
            {"dport": 4444, "detail": "Metasploit: Meterpreter stage sent to victim",               "status": "attack"},
            {"dport": 4444, "detail": "Metasploit: Session opened — Meterpreter active",            "status": "attack"},
            {"dport": 4444, "detail": "Metasploit: hashdump executed — /etc/shadow grabbed",        "status": "attack"},
            {"dport": 0,    "detail": "Reverse shell blocked — egress port 4444 firewalled",        "status": "response"},
        ],
    },
    "aircrack_mitm": {
        "label": "Aircrack-ng + MITM",
        "description": "ARP spoofing + packet capture (simulated)",
        "icon": "wifi",
        "color": "purple",
        "events": [
            {"dport": 80,  "detail": "ARP spoofing started — gateway MAC poisoned",                 "status": "suspicious"},
            {"dport": 80,  "detail": "HTTP traffic intercepted — cleartext credentials visible",    "status": "attack"},
            {"dport": 443, "detail": "SSL stripping attempt — HTTPS downgraded to HTTP",            "status": "attack"},
            {"dport": 0,   "detail": "ARP inspection enabled — spoofing blocked",                   "status": "response"},
        ],
    },
}


def run_kali_scenario(name: str) -> list:
    if name not in KALI_SCENARIOS:
        raise ValueError(f"Unknown Kali scenario: {name}")
    sc   = KALI_SCENARIOS[name]
    ip   = ATTACKER_IP
    base = datetime.now()
    events = []
    for i, tmpl in enumerate(sc["events"]):
        offset = sum(random.randint(2, 6) for _ in range(i))
        ts = base + timedelta(seconds=offset)
        events.append({
            "id":        i + 1,
            "timestamp": ts.strftime("%H:%M:%S"),
            "type":      "kali_tool",
            "status":    tmpl["status"],
            "detail":    tmpl["detail"],
            "ip":        ip,
            "dport":     tmpl.get("dport", 0),
            "target":    METASPLOITABLE2_IP,
            "scenario":  name,
            "source":    "kali",
        })
    return events
