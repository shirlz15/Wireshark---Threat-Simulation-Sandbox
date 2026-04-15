"""
timeline.py
Assembles simulate → detect → respond → explain into one clean dict.
"""

from simulator import run_scenario, parse_pcap
from detector import detect, get_summary
from response_engine import get_response, get_compare
from explainer import explain_event


def build_timeline(scenario_name: str) -> dict:
    raw    = run_scenario(scenario_name)
    events = detect(raw)

    timeline = []
    for e in events:
        entry = dict(e)
        entry["explanation"] = explain_event(e)
        if e.get("detection"):
            entry["response"] = get_response(e["detection"]["rule"])
        else:
            entry["response"] = None
        timeline.append(entry)

    return {
        "scenario": scenario_name,
        "timeline": timeline,
        "summary":  get_summary(events),
        "compare":  get_compare(scenario_name),
    }


def build_pcap_timeline(filepath: str) -> dict:
    raw    = parse_pcap(filepath)
    if raw and "error" in raw[0]:
        return {"error": raw[0]["error"]}
    events = detect(raw)

    timeline = []
    for e in events:
        entry = dict(e)
        entry["explanation"] = explain_event(e)
        entry["response"]    = None
        timeline.append(entry)

    return {
        "scenario": "pcap_live",
        "timeline": timeline,
        "summary":  get_summary(events),
        "compare":  {"without": "—", "with": "—"},
    }
