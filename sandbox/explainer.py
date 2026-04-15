"""
explainer.py
Plain-English explanations for each event type.
Also provides the prompt for the AI explanation feature.
"""

EXPLANATIONS = {
    "login_attempt":   "A login request was received. Single attempts are completely normal - every user logs in.",
    "login_failed":    "Wrong password entered. One failure could be a typo. But rapid failures from one IP suggest an automated script cycling through a password list.",
    "port_probe":      "A connection attempt on a specific port. Probing many ports quickly is how attackers look for unlocked doors - called a port scan.",
    "geo_flag":        "Login came from a country that doesn't match this account's normal activity. Alone it's weak signal - combined with other flags it suggests stolen credentials.",
    "time_flag":       "Login at an unusual hour (e.g. 3 AM). Attackers often strike outside business hours hoping to avoid immediate response.",
    "behavior_flag":   "Post-login activity looks automated - bulk data requests, unusual file access, or actions no human would do at that speed.",
    "traffic_spike":   "Request volume from this source jumped sharply. A gradual climb could be viral traffic; a sudden spike from one IP is a flood attack.",
    "block_ip":        "The source IP was added to a firewall blocklist. Future packets from that IP are dropped before reaching the application.",
    "close_ports":     "Unnecessary ports were closed, shrinking the attack surface. The scanning IP was also rate-limited to make further probing impractical.",
    "restrict_access": "The session was paused and all active tokens invalidated. The legitimate user gets an MFA challenge - an attacker without the device cannot proceed.",
    "rate_limit":      "The CDN capped requests from this source. Legitimate users (lower volume) are unaffected. The flood traffic hits a wall and stops.",
    "tcp_packet":      "A standard TCP connection packet captured from real network traffic.",
    "udp_packet":      "A UDP datagram captured from live traffic - often DNS or streaming.",
}

STATUS_NOTES = {
    "safe":       "Normal system activity - no action needed.",
    "suspicious": "Something looks off. Not confirmed yet, but the system is watching closely.",
    "attack":     "Pattern matches a known attack signature. Automated response triggered.",
    "response":   "Defensive action taken. Threat contained (simulated - no real commands run).",
}


def explain_event(event: dict) -> str:
    base = EXPLANATIONS.get(event.get("type", ""), "No specific explanation for this event type.")
    note = STATUS_NOTES.get(event.get("status", ""), "")
    return f"{base} - {note}" if note else base


def build_ai_prompt(events: list, scenario: str) -> str:
    """Builds a prompt for Claude AI to explain the full attack chain."""
    lines = "\n".join(
        f"[{e['timestamp']}] {e['status'].upper()} - {e['detail']}"
        for e in events
    )
    return f"""You are a cybersecurity educator explaining an attack to a student.

Scenario: {scenario.replace('_', ' ').title()}

Event log:
{lines}

In 3–4 short paragraphs:
1. What attack is this and how does it work?
2. What signals gave it away?
3. What did the defense do and why does it work?
4. One real-world example of this attack type.

Keep it simple, specific, and direct. No jargon. No bullet points."""
