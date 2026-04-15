"""
response_engine.py
Maps detected threats to simulated defensive actions.
Nothing here runs real system commands.
"""

ACTIONS = {
    "brute_force": {
        "action":  "Block IP + Lock Account",
        "detail":  "Source IP added to blocklist for 30 min. Account locked pending owner verification.",
        "symbol":  "shield",
        "severity": "high",
    },
    "port_scan": {
        "action":  "Close Ports + Rate Limit",
        "detail":  "Unused ports closed. Scanning IP throttled to 1 req/min via firewall rule.",
        "symbol":  "lock",
        "severity": "medium",
    },
    "account_takeover": {
        "action":  "Revoke Session + Force MFA",
        "detail":  "All active tokens invalidated. Step-up authentication challenge sent to account owner.",
        "symbol":  "alert",
        "severity": "critical",
    },
    "ddos": {
        "action":  "CDN Rate Limit + Traffic Scrubbing",
        "detail":  "CDN absorbs flood traffic. Source throttled. Scrubbing centre filters malformed packets.",
        "symbol":  "filter",
        "severity": "high",
    },
}

COMPARE = {
    "brute_force": {
        "without": "Attacker eventually guesses the correct password. Full account access granted.",
        "with":    "IP blocked after 5 failures. Account locked. Attacker gets nothing.",
    },
    "port_scan": {
        "without": "Attacker maps all open services and finds an exposed MongoDB on port 27017.",
        "with":    "Scan data becomes incomplete. Attack surface reduced. Attacker moves on.",
    },
    "account_takeover": {
        "without": "Session stays active. Attacker exfiltrates all accessible data silently.",
        "with":    "Session frozen at step 3. Only partial data exposed before lockout.",
    },
    "ddos": {
        "without": "Server exhausted in ~2 min. Site goes down. Users cannot access service.",
        "with":    "CDN absorbs flood. Server stays up. Legitimate users unaffected.",
    },
}


def get_response(rule: str) -> dict:
    return ACTIONS.get(rule, {
        "action": "Log and Monitor",
        "detail": "Event logged for manual security review.",
        "symbol": "log",
        "severity": "low",
    })


def get_compare(scenario: str) -> dict:
    return COMPARE.get(scenario, {
        "without": "Threat succeeds undetected.",
        "with":    "Threat neutralised by automated response.",
    })
