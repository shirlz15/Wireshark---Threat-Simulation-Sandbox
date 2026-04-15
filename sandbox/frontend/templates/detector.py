"""
detector.py — Stateful threat detection engine
"""
from collections import defaultdict
import time


class DetectionEngine:
    def __init__(self):
        self._ports   = defaultdict(set)
        self._hits    = defaultdict(list)
        self._all     = defaultdict(list)

    def analyze(self, event: dict) -> dict:
        src   = event.get("src_ip", "unknown")
        dport = event.get("dst_port", event.get("port", 0))
        now   = time.time()
        cutoff = now - 30  # 30-second sliding window

        # Record
        self._all[src].append(now)
        self._hits[(src, dport)].append(now)

        # Prune old
        self._all[src]           = [t for t in self._all[src]           if t > cutoff]
        self._hits[(src, dport)] = [t for t in self._hits[(src, dport)] if t > cutoff]

        # Metrics
        recent_ports = len({p for (ip, p) in list(self._hits.keys()) if ip == src and self._hits.get((ip, p))})
        total        = len(self._all[src])
        port_hits    = len(self._hits[(src, dport)])

        SENSITIVE = {21, 22, 23, 3389, 5432, 3306, 27017, 6379, 445, 8443}

        # Rules (priority order)
        if recent_ports >= 8:
            return {"threat_level": "critical",   "threat_type": "PORT_SCAN",
                    "detail": f"Scanned {recent_ports} unique ports in 30s"}
        if dport in SENSITIVE and port_hits >= 8:
            return {"threat_level": "critical",   "threat_type": "BRUTE_FORCE",
                    "detail": f"{port_hits} rapid attempts on port {dport}"}
        if total >= 40:
            return {"threat_level": "critical",   "threat_type": "TRAFFIC_FLOOD",
                    "detail": f"{total} packets/30s from {src}"}
        if dport in SENSITIVE:
            return {"threat_level": "suspicious", "threat_type": "SENSITIVE_PORT",
                    "detail": f"Probe on sensitive port {dport}"}
        if recent_ports >= 4:
            return {"threat_level": "suspicious", "threat_type": "PORT_SPREAD",
                    "detail": f"{recent_ports} ports accessed in window"}
        return {"threat_level": "safe",        "threat_type": "NORMAL",
                "detail": "Normal traffic pattern"}
