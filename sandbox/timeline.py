"""
timeline.py v5.0
"""

from simulator import run_scenario, parse_pcap if hasattr(__import__('simulator'), 'parse_pcap') else None
from response_engine import get_response, get_compare
from explainer import explain_event


def build_timeline(scenario_name: str) -> dict:
    raw     = run_scenario(scenario_name)
    timeline = []
    for e in raw:
        entry = dict(e)
        entry["explanation"] = explain_event(e)
        timeline.append(entry)
    return {
        "scenario": scenario_name,
        "timeline": timeline,
        "summary":  _summarize(raw),
        "compare":  get_compare(scenario_name),
    }


def _summarize(events: list) -> dict:
    attacks    = sum(1 for e in events if e.get("status") in ("attack",))
    suspicious = sum(1 for e in events if e.get("status") == "suspicious")
    ips        = {e.get("ip") for e in events if e.get("ip")}
    tl = "critical" if attacks > 0 else ("suspicious" if suspicious > 0 else "safe")
    return {
        "total_events":      len(events),
        "attacks_detected":  attacks,
        "suspicious_events": suspicious,
        "threat_level":      tl,
        "unique_ips":        len(ips),
        "responses_taken":   sum(1 for e in events if e.get("status") == "response"),
    }
