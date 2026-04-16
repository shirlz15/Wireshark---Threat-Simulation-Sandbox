"""
detector.py v4.0 — Behavioral Pattern Engine
Novel threat detection with:
  - Confidence scoring (not just binary labels)
  - Multi-phase attack sequence recognition
  - Temporal pattern analysis
  - Behavioral fingerprinting
"""

from collections import defaultdict, deque
import time
import math


# ── Sensitive port taxonomy ────────────────────────────────────────────────
PORT_META = {
    21:    ("FTP",       "file transfer"),
    22:    ("SSH",       "remote shell"),
    23:    ("TELNET",    "unencrypted shell"),
    25:    ("SMTP",      "mail relay"),
    53:    ("DNS",       "name resolution"),
    80:    ("HTTP",      "web"),
    110:   ("POP3",      "mail retrieval"),
    135:   ("RPC",       "windows RPC"),
    139:   ("NETBIOS",   "windows file share"),
    143:   ("IMAP",      "mail retrieval"),
    389:   ("LDAP",      "directory service"),
    443:   ("HTTPS",     "secure web"),
    445:   ("SMB",       "windows share"),
    1433:  ("MSSQL",     "SQL Server"),
    1521:  ("OracleDB",  "Oracle database"),
    3306:  ("MySQL",     "MySQL database"),
    3389:  ("RDP",       "remote desktop"),
    5432:  ("PostgreSQL","Postgres database"),
    5900:  ("VNC",       "virtual desktop"),
    6379:  ("Redis",     "cache/nosql"),
    8080:  ("HTTP-ALT",  "web proxy"),
    8443:  ("HTTPS-ALT", "secure web alt"),
    27017: ("MongoDB",   "document database"),
}

CRITICAL_PORTS = {22, 23, 3389, 5432, 3306, 27017, 6379, 445, 8443, 1433, 1521, 5900}
SENSITIVE_PORTS = set(PORT_META.keys())


class BehaviorFingerprint:
    """Per-IP behavioral fingerprint with temporal analysis."""

    def __init__(self):
        self.events:     deque = deque(maxlen=500)    # (timestamp, port)
        self.port_seq:   deque = deque(maxlen=100)    # port sequence
        self.bursts:     list  = []                   # [(start, end, count)]
        self.phase:      str   = "idle"               # idle/recon/exploit/exfil
        self.phase_ts:   float = 0.0
        self.total_pkts: int   = 0

    def add(self, port: int, ts: float):
        self.events.append((ts, port))
        self.port_seq.append(port)
        self.total_pkts += 1


class DetectionEngine:
    """
    Stateful multi-phase behavioral detection engine.
    Outputs confidence scores + explanations, not just labels.
    """

    # Attack sequence patterns (ordered port access patterns)
    SEQUENCE_PATTERNS = {
        "recon_then_exploit": {
            "phases": [("scan_wide", 3), ("sensitive_probe", 1), ("rapid_hit", 5)],
            "desc":   "reconnaissance → sensitive probe → brute access",
        },
        "lateral_movement": {
            "phases": [("ssh_probe", 1), ("smb_probe", 1), ("rdp_probe", 1)],
            "desc":   "SSH + SMB + RDP probing → possible lateral movement",
        },
        "db_harvest": {
            "phases": [("db_probe", 2), ("rapid_hit", 10)],
            "desc":   "database port scanning → credential attack",
        },
    }

    def __init__(self):
        self._fp:         dict = defaultdict(BehaviorFingerprint)
        self._windows:    dict = defaultdict(lambda: deque(maxlen=200))
        self._seq_state:  dict = defaultdict(dict)
        self._global_ts:  float = time.time()

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze(self, event: dict) -> dict:
        src   = event.get("src_ip", "unknown")
        dport = int(event.get("dst_port", event.get("port", 0)))
        now   = time.time()

        fp = self._fp[src]
        fp.add(dport, now)

        w30  = self._window(src, now, 30)
        w10  = self._window(src, now, 10)
        w5   = self._window(src, now, 5)

        result = self._run_rules(src, dport, now, fp, w30, w10, w5)
        self._update_phase(src, fp, result["threat_type"])

        return result

    def get_fingerprint(self, ip: str) -> dict:
        fp = self._fp.get(ip)
        if not fp:
            return {}
        return {
            "phase":      fp.phase,
            "total_pkts": fp.total_pkts,
            "port_seq":   list(fp.port_seq)[-10:],
        }

    # ── Window helpers ──────────────────────────────────────────────────────

    def _window(self, src: str, now: float, seconds: int) -> list:
        cutoff = now - seconds
        key = (src, seconds)
        self._windows[key].append(now)
        return [t for t in self._windows[key] if t > cutoff]

    def _unique_ports_in_window(self, src: str, now: float, seconds: int) -> set:
        fp = self._fp[src]
        cutoff = now - seconds
        return {p for (t, p) in fp.events if t > cutoff}

    def _hits_on_port(self, src: str, port: int, now: float, seconds: int) -> int:
        fp = self._fp[src]
        cutoff = now - seconds
        return sum(1 for (t, p) in fp.events if t > cutoff and p == port)

    # ── Rule engine ─────────────────────────────────────────────────────────

    def _run_rules(self, src, dport, now, fp, w30, w10, w5) -> dict:
        ports30 = self._unique_ports_in_window(src, now, 30)
        ports10 = self._unique_ports_in_window(src, now, 10)
        total30 = len(w30)
        total10 = len(w10)
        total5  = len(w5)
        port_hits30 = self._hits_on_port(src, dport, now, 30)
        port_hits10 = self._hits_on_port(src, dport, now, 10)
        pname, pdesc = PORT_META.get(dport, (f":{dport}", "unknown service"))

        # ── Rule 1: Distributed Port Scan ───────────────────────────────────
        if len(ports30) >= 12:
            conf = min(99, 60 + (len(ports30) - 12) * 3)
            return {
                "threat_level": "critical",
                "threat_type":  "PORT_SCAN",
                "confidence":   conf,
                "detail":       f"Scanned {len(ports30)} unique ports in 30s",
                "explanation":  (
                    f"IP {src} probed {len(ports30)} distinct ports within 30 seconds. "
                    f"Systematic port enumeration is the first stage of network reconnaissance, "
                    f"used to map available services before targeted exploitation. "
                    f"Rapid sequential probing (not organic browsing) is a definitive scan signature."
                ),
                "mitre": "T1046",
                "mitre_name": "Network Service Discovery",
                "phase_hint": "recon",
            }

        # ── Rule 2: Credential Brute Force ──────────────────────────────────
        if dport in CRITICAL_PORTS and port_hits10 >= 6:
            conf = min(98, 55 + port_hits10 * 4)
            return {
                "threat_level": "critical",
                "threat_type":  "BRUTE_FORCE",
                "confidence":   conf,
                "detail":       f"{port_hits10} attempts on {pname} (:{dport}) in 10s",
                "explanation":  (
                    f"{port_hits10} connection attempts hit {pname} port {dport} in under 10 seconds. "
                    f"Human login rates peak at ~1 attempt per 5 seconds. "
                    f"Automated credential stuffing or dictionary attacks run at 10–1000 per second. "
                    f"This rate ({port_hits10}/10s) indicates scripted automation."
                ),
                "mitre": "T1110",
                "mitre_name": "Brute Force",
                "phase_hint": "exploit",
            }

        # ── Rule 3: Traffic Flood / DDoS ────────────────────────────────────
        if total5 >= 25:
            rate = total5 / 5
            conf = min(97, 50 + int(rate * 1.5))
            return {
                "threat_level": "critical",
                "threat_type":  "TRAFFIC_FLOOD",
                "confidence":   conf,
                "detail":       f"{total5} pkts in 5s from {src} (~{rate:.0f}/s)",
                "explanation":  (
                    f"Packet burst of {total5} in 5 seconds ({rate:.0f} pkt/s) from {src}. "
                    f"Normal application traffic rarely exceeds 10 pkt/s per host. "
                    f"This volume suggests resource exhaustion intent (volumetric DoS) "
                    f"or a reflective amplification attack."
                ),
                "mitre": "T1499",
                "mitre_name": "Endpoint Denial of Service",
                "phase_hint": "impact",
            }

        # ── Rule 4: Suspicious Sequence — scan then probe ───────────────────
        if len(ports30) >= 5 and dport in CRITICAL_PORTS:
            conf = 62 + min(20, len(ports30) * 2)
            return {
                "threat_level": "suspicious",
                "threat_type":  "RECON_SEQUENCE",
                "confidence":   conf,
                "detail":       f"Wide scan ({len(ports30)} ports) → now targeting {pname} :{dport}",
                "explanation":  (
                    f"Behavioral sequence detected: {src} first scanned {len(ports30)} ports, "
                    f"then pivoted to attack {pname} (:{dport}), a high-value service. "
                    f"This recon-then-exploit pattern is the hallmark of targeted intrusion attempts."
                ),
                "mitre": "T1046→T1110",
                "mitre_name": "Service Discovery → Brute Force",
                "phase_hint": "exploit",
            }

        # ── Rule 5: Database / Admin Port Probe ─────────────────────────────
        if dport in CRITICAL_PORTS and port_hits30 >= 3:
            conf = 45 + min(30, port_hits30 * 5)
            return {
                "threat_level": "suspicious",
                "threat_type":  "SENSITIVE_PORT",
                "confidence":   conf,
                "detail":       f"{port_hits30}× probe on {pname} :{dport}",
                "explanation":  (
                    f"Repeated access ({port_hits30} times in 30s) to {pname} port {dport}. "
                    f"{pdesc.title()} services should not receive repeated unsolicited probes. "
                    f"This pattern precedes credential attacks or CVE exploitation attempts."
                ),
                "mitre": "T1021",
                "mitre_name": "Remote Services",
                "phase_hint": "recon",
            }

        # ── Rule 6: Port Spread ─────────────────────────────────────────────
        if len(ports10) >= 4:
            conf = 30 + len(ports10) * 4
            return {
                "threat_level": "suspicious",
                "threat_type":  "PORT_SPREAD",
                "confidence":   conf,
                "detail":       f"{len(ports10)} distinct ports in 10s window",
                "explanation":  (
                    f"Traffic from {src} spread across {len(ports10)} ports in 10 seconds. "
                    f"Organic traffic typically targets 1–2 services. "
                    f"Multi-port access in short windows often indicates automated enumeration."
                ),
                "mitre": "T1046",
                "mitre_name": "Network Service Discovery",
                "phase_hint": "recon",
            }

        # ── Rule 7: Single sensitive port touch ─────────────────────────────
        if dport in SENSITIVE_PORTS and dport not in {80, 443, 53}:
            conf = 18 + (15 if dport in CRITICAL_PORTS else 0)
            return {
                "threat_level": "suspicious",
                "threat_type":  "SENSITIVE_PORT",
                "confidence":   conf,
                "detail":       f"Single probe → {pname} :{dport} ({pdesc})",
                "explanation":  (
                    f"One connection attempt to {pname} port {dport} ({pdesc}). "
                    f"Isolated probes may be benign misconfiguration or initial reconnaissance. "
                    f"Monitoring for follow-up activity from this source."
                ),
                "mitre": "T1021",
                "mitre_name": "Remote Services",
                "phase_hint": "recon",
            }

        # ── Safe ────────────────────────────────────────────────────────────
        return {
            "threat_level": "safe",
            "threat_type":  "NORMAL",
            "confidence":   95,
            "detail":       f"Normal traffic on {pname} :{dport}",
            "explanation":  (
                f"Connection to {pname} port {dport} from {src} matches expected traffic patterns. "
                f"No anomalous rate, port spread, or behavioral sequence detected."
            ),
            "mitre":      "-",
            "mitre_name": "—",
            "phase_hint": "normal",
        }

    def _update_phase(self, src: str, fp: BehaviorFingerprint, threat_type: str):
        phase_map = {
            "PORT_SCAN":      "recon",
            "PORT_SPREAD":    "recon",
            "SENSITIVE_PORT": "recon",
            "RECON_SEQUENCE": "exploit",
            "BRUTE_FORCE":    "exploit",
            "TRAFFIC_FLOOD":  "impact",
            "NORMAL":         "idle",
        }
        new_phase = phase_map.get(threat_type, fp.phase)
        # Only advance phase, never retreat (recon → exploit → impact)
        order = ["idle", "recon", "exploit", "impact"]
        if order.index(new_phase) >= order.index(fp.phase):
            fp.phase = new_phase
            fp.phase_ts = time.time()
