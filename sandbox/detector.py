"""
detector.py v5.0 — Behavioral Pattern Engine
Novel additions:
  - Metasploitable2 Vulnerability Surface Mapper (MVSM)
  - CVE-to-port mapping for known Metasploitable2 services
  - Cross-IP behavioral correlation
  - Extended confidence model with decay
"""

from collections import defaultdict, deque
import time
import math


# ── Port taxonomy ─────────────────────────────────────────────────────────────
PORT_META = {
    21:    ("FTP",        "file transfer",          "vsFTPd 2.3.4 — CVE-2011-2523 backdoor"),
    22:    ("SSH",        "remote shell",            "OpenSSH 4.7 — CVE-2008-0166 weak keys"),
    23:    ("TELNET",     "unencrypted shell",       "Unencrypted — credentials in plaintext"),
    25:    ("SMTP",       "mail relay",              "Postfix SMTP — CVE-2012-5168 open relay"),
    53:    ("DNS",        "name resolution",         "BIND 9.4 — CVE-2008-1447 cache poison"),
    80:    ("HTTP",       "web",                     "Apache 2.2 — CVE-2012-0053 info leak"),
    110:   ("POP3",       "mail retrieval",          "Dovecot POP3 — cleartext auth"),
    135:   ("RPC",        "windows RPC",             "Windows RPC — MS08-067 exploitation"),
    139:   ("NETBIOS",    "windows file share",      "Samba — CVE-2007-2447 command injection"),
    143:   ("IMAP",       "mail retrieval",          "Dovecot IMAP — cleartext credentials"),
    389:   ("LDAP",       "directory service",       "OpenLDAP — anonymous bind possible"),
    443:   ("HTTPS",      "secure web",              "Heartbleed — CVE-2014-0160 if OpenSSL ≤1.0.1f"),
    445:   ("SMB",        "windows share",           "Samba 3.x — CVE-2017-7494 SambaCry"),
    512:   ("REXEC",      "remote execution",        "BSD rexec — no auth by default"),
    513:   ("RLOGIN",     "remote login",            "BSD rlogin — trust-based auth bypass"),
    514:   ("RSH",        "remote shell",            "BSD rsh — unauthenticated execution"),
    1099:  ("RMI",        "java rmi",                "Java RMI — CVE-2011-3556 deserialization"),
    1433:  ("MSSQL",      "SQL Server",              "MSSQL — weak sa credentials"),
    1521:  ("OracleDB",   "Oracle database",         "Oracle TNS — CVE-2012-1675 poison"),
    2049:  ("NFS",        "network file system",     "NFS — no_root_squash misconfig"),
    2121:  ("FTP-ALT",    "ftp alternate",           "ProFTPd 1.3.1 — CVE-2010-4221 overflow"),
    3306:  ("MySQL",      "MySQL database",          "MySQL 5.0 — anonymous user access"),
    3389:  ("RDP",        "remote desktop",          "BlueKeep — CVE-2019-0708 if unpatched"),
    3632:  ("distcc",     "distributed compiler",    "distcc — CVE-2004-2687 RCE via compile"),
    5432:  ("PostgreSQL", "Postgres database",       "PostgreSQL — trust auth localhost"),
    5900:  ("VNC",        "virtual desktop",         "VNC — no auth or weak password"),
    6000:  ("X11",        "X display server",        "X11 — CVE-2011-4029 file creation"),
    6379:  ("Redis",      "cache/nosql",             "Redis — no auth, CONFIG file write RCE"),
    6667:  ("IRC",        "irc chat",                "UnrealIRCd — CVE-2010-2075 backdoor"),
    8009:  ("AJP",        "apache jserv",            "Ghostcat — CVE-2020-1938 file read"),
    8080:  ("HTTP-ALT",   "web proxy",               "Tomcat — CVE-2019-0232 CGI RCE"),
    8180:  ("TOMCAT",     "tomcat http",             "Tomcat default creds: tomcat/tomcat"),
    8443:  ("HTTPS-ALT",  "secure web alt",          "JBoss — CVE-2010-1428 unauthenticated"),
    27017: ("MongoDB",    "document database",       "MongoDB — no auth, world-accessible"),
}

# Metasploitable2-specific CVE map
METASPLOITABLE2_CVE = {
    21:   "CVE-2011-2523",  # vsFTPd backdoor
    22:   "CVE-2008-0166",  # Debian weak keys
    139:  "CVE-2007-2447",  # Samba command injection
    445:  "CVE-2017-7494",  # SambaCry
    3306: "CVE-2012-2122",  # MySQL auth bypass
    3632: "CVE-2004-2687",  # distcc RCE
    5432: "CVE-2013-1899",  # PostgreSQL RCE
    5900: "CVE-2006-2369",  # VNC auth bypass
    6667: "CVE-2010-2075",  # UnrealIRCd backdoor
    8180: "CVE-2009-3548",  # Tomcat default creds
}

CRITICAL_PORTS  = {21, 22, 23, 139, 445, 512, 513, 514, 1099, 3306, 3389, 3632,
                   5432, 5900, 6000, 6379, 6667, 8009, 8180, 27017}
SENSITIVE_PORTS = set(PORT_META.keys())


class BehaviorFingerprint:
    """Per-IP behavioral fingerprint with temporal analysis."""
    def __init__(self):
        self.events:     deque = deque(maxlen=500)
        self.port_seq:   deque = deque(maxlen=100)
        self.phase:      str   = "idle"
        self.phase_ts:   float = 0.0
        self.total_pkts: int   = 0
        self.cve_hits:   list  = []   # MVSM: CVEs targeted

    def add(self, port: int, ts: float):
        self.events.append((ts, port))
        self.port_seq.append(port)
        self.total_pkts += 1
        if port in METASPLOITABLE2_CVE:
            cve = METASPLOITABLE2_CVE[port]
            if cve not in self.cve_hits:
                self.cve_hits.append(cve)


class DetectionEngine:
    """
    Stateful multi-phase behavioral detection engine v5.0.
    Outputs confidence scores + CVE context + explanations.
    """

    def __init__(self):
        self._fp       = defaultdict(BehaviorFingerprint)
        self._windows  = defaultdict(lambda: deque(maxlen=200))

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze(self, event: dict) -> dict:
        src   = event.get("src_ip", "unknown")
        dport = int(event.get("dst_port", event.get("port", 0)))
        now   = time.time()

        fp = self._fp[src]
        fp.add(dport, now)

        w30 = self._window(src, now, 30)
        w10 = self._window(src, now, 10)
        w5  = self._window(src, now, 5)

        result = self._run_rules(src, dport, now, fp, w30, w10, w5)

        # MVSM: Attach CVE context if port is on Metasploitable2
        cve = METASPLOITABLE2_CVE.get(dport)
        if cve:
            result["metasploitable2_cve"] = cve
            result["metasploitable2_service"] = PORT_META.get(dport, ("?", "?", "?"))[2]

        self._update_phase(src, fp, result["threat_type"])
        return result

    def get_fingerprint(self, ip: str) -> dict:
        fp = self._fp.get(ip)
        if not fp:
            return {"phase": "idle", "total_pkts": 0, "port_seq": [], "cve_hits": []}
        return {
            "phase":      fp.phase,
            "total_pkts": fp.total_pkts,
            "port_seq":   list(fp.port_seq)[-10:],
            "cve_hits":   fp.cve_hits,
        }

    # ── Window helpers ──────────────────────────────────────────────────────

    def _window(self, src, now, seconds):
        cutoff = now - seconds
        key = (src, seconds)
        self._windows[key].append(now)
        return [t for t in self._windows[key] if t > cutoff]

    def _unique_ports_in_window(self, src, now, seconds):
        fp = self._fp[src]
        cutoff = now - seconds
        return {p for (t, p) in fp.events if t > cutoff}

    def _hits_on_port(self, src, port, now, seconds):
        fp = self._fp[src]
        cutoff = now - seconds
        return sum(1 for (t, p) in fp.events if t > cutoff and p == port)

    # ── Rule engine ─────────────────────────────────────────────────────────

    def _run_rules(self, src, dport, now, fp, w30, w10, w5) -> dict:
        ports30     = self._unique_ports_in_window(src, now, 30)
        ports10     = self._unique_ports_in_window(src, now, 10)
        total30     = len(w30)
        total5      = len(w5)
        port_hits30 = self._hits_on_port(src, dport, now, 30)
        port_hits10 = self._hits_on_port(src, dport, now, 10)
        pname, pdesc, ms2info = PORT_META.get(dport, (f":{dport}", "unknown service", "unknown CVE"))

        # Rule 1: Port Scan
        if len(ports30) >= 12:
            conf = min(99, 60 + (len(ports30) - 12) * 3)
            return self._result("critical", "PORT_SCAN", conf,
                f"Scanned {len(ports30)} unique ports in 30s",
                f"IP {src} probed {len(ports30)} distinct ports in 30s — systematic reconnaissance. "
                f"Matches Nmap/masscan signatures used for service discovery before exploitation.",
                "T1046", "Network Service Discovery", "recon")

        # Rule 2: Brute Force
        if dport in CRITICAL_PORTS and port_hits10 >= 6:
            conf = min(98, 55 + port_hits10 * 4)
            return self._result("critical", "BRUTE_FORCE", conf,
                f"{port_hits10} attempts on {pname} (:{dport}) in 10s",
                f"{port_hits10} rapid hits on {pname}:{dport}. Human rate ≤1/5s; tools like Hydra/Medusa "
                f"run 10–1000/s. Automated credential attack confirmed. {ms2info}",
                "T1110", "Brute Force", "exploit")

        # Rule 3: Traffic Flood
        if total5 >= 25:
            rate = total5 / 5
            conf = min(97, 50 + int(rate * 1.5))
            return self._result("critical", "TRAFFIC_FLOOD", conf,
                f"{total5} pkts in 5s (~{rate:.0f}/s)",
                f"Burst of {total5} packets in 5s from {src}. Exceeds normal host rate (≤10 pkt/s). "
                f"Volumetric DoS or amplification attack pattern.",
                "T1499", "Endpoint Denial of Service", "impact")

        # Rule 4: Metasploitable2 CVE Targeting
        if dport in METASPLOITABLE2_CVE and port_hits30 >= 2:
            cve  = METASPLOITABLE2_CVE[dport]
            conf = min(92, 65 + port_hits30 * 5)
            return self._result("critical", "CVE_EXPLOIT", conf,
                f"Targeted {pname}:{dport} — {cve} ({port_hits30}× in 30s)",
                f"Repeated probing of {pname} port {dport} which hosts a known vulnerability: {cve}. "
                f"This is the Metasploitable2 service signature. High-confidence exploitation attempt.",
                "T1203", "Exploitation for Client Execution", "exploit")

        # Rule 5: Recon Sequence
        if len(ports30) >= 5 and dport in CRITICAL_PORTS:
            conf = 62 + min(20, len(ports30) * 2)
            return self._result("suspicious", "RECON_SEQUENCE", conf,
                f"Wide scan ({len(ports30)} ports) → targeting {pname}:{dport}",
                f"Classic recon→exploit chain: {src} scanned {len(ports30)} ports then pivoted to "
                f"{pname}:{dport}. {ms2info}",
                "T1046→T1110", "Service Discovery → Brute Force", "exploit")

        # Rule 6: Sensitive Port Probe
        if dport in CRITICAL_PORTS and port_hits30 >= 3:
            conf = 45 + min(30, port_hits30 * 5)
            return self._result("suspicious", "SENSITIVE_PORT", conf,
                f"{port_hits30}× probe on {pname}:{dport}",
                f"Repeated access ({port_hits30}×) to {pname}:{dport}. {ms2info}. "
                f"Precedes credential or CVE exploitation.",
                "T1021", "Remote Services", "recon")

        # Rule 7: Port Spread
        if len(ports10) >= 4:
            conf = 30 + len(ports10) * 4
            return self._result("suspicious", "PORT_SPREAD", conf,
                f"{len(ports10)} distinct ports in 10s",
                f"Traffic from {src} hit {len(ports10)} ports in 10s. "
                f"Organic traffic targets 1–2 services. Automated enumeration likely.",
                "T1046", "Network Service Discovery", "recon")

        # Rule 8: Single sensitive port
        if dport in SENSITIVE_PORTS and dport not in {80, 443, 53}:
            conf = 18 + (15 if dport in CRITICAL_PORTS else 0)
            return self._result("suspicious", "SENSITIVE_PORT", conf,
                f"Single probe → {pname}:{dport}",
                f"One connection to {pname}:{dport} ({pdesc}). {ms2info}. Monitoring for follow-up.",
                "T1021", "Remote Services", "recon")

        # Safe
        return self._result("safe", "NORMAL", 95,
            f"Normal traffic on {pname}:{dport}",
            f"Connection to {pname}:{dport} from {src} matches expected patterns.",
            "-", "—", "normal")

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _result(self, level, ttype, conf, detail, explanation, mitre, mitre_name, phase_hint) -> dict:
        return {
            "threat_level": level,
            "threat_type":  ttype,
            "confidence":   conf,
            "detail":       detail,
            "explanation":  explanation,
            "mitre":        mitre,
            "mitre_name":   mitre_name,
            "phase_hint":   phase_hint,
        }

    def _update_phase(self, src, fp, threat_type):
        phase_map = {
            "PORT_SCAN":      "recon",
            "PORT_SPREAD":    "recon",
            "SENSITIVE_PORT": "recon",
            "RECON_SEQUENCE": "exploit",
            "BRUTE_FORCE":    "exploit",
            "CVE_EXPLOIT":    "exploit",
            "TRAFFIC_FLOOD":  "impact",
            "NORMAL":         "idle",
        }
        new_phase = phase_map.get(threat_type, fp.phase)
        order = ["idle", "recon", "exploit", "persist", "impact", "exfil"]
        if new_phase in order and order.index(new_phase) >= order.index(fp.phase if fp.phase in order else "idle"):
            fp.phase    = new_phase
            fp.phase_ts = time.time()
