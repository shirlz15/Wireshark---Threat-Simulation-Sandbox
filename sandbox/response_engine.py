"""
response_engine.py v5.0
Adaptive Defense Playbook — response intensity scales with sophistication score.
"""

ACTIONS = {
    "brute_force": {
        "action": "Block IP + Lock Account",
        "detail": "Source IP added to blocklist 30 min. Account locked pending owner verification.",
        "symbol": "shield", "severity": "high",
    },
    "port_scan": {
        "action": "Close Ports + Rate Limit",
        "detail": "Unused ports closed. Scanning IP throttled to 1 req/min via firewall.",
        "symbol": "lock", "severity": "medium",
    },
    "account_takeover": {
        "action": "Revoke Session + Force MFA",
        "detail": "All active tokens invalidated. Step-up authentication sent to account owner.",
        "symbol": "alert", "severity": "critical",
    },
    "ddos": {
        "action": "CDN Rate Limit + Traffic Scrubbing",
        "detail": "CDN absorbs flood. Source throttled. Scrubbing filters malformed packets.",
        "symbol": "filter", "severity": "high",
    },
    "cve_exploit": {
        "action": "Service Isolation + Emergency Patch",
        "detail": "Vulnerable service taken offline. Emergency patch queue created. WAF rule added.",
        "symbol": "patch", "severity": "critical",
    },
    "lateral_movement": {
        "action": "Network Segmentation + Host Isolation",
        "detail": "Affected host quarantined. East-west traffic blocked. Forensic snapshot taken.",
        "symbol": "segment", "severity": "critical",
    },
}

COMPARE = {
    "brute_force": {
        "without": "Attacker guesses password. Full account access granted.",
        "with":    "IP blocked after 5 failures. Account locked. Attacker gets nothing.",
    },
    "port_scan": {
        "without": "Attacker maps all open services and finds exposed MongoDB on port 27017.",
        "with":    "Scan data incomplete. Attack surface reduced. Attacker moves on.",
    },
    "account_takeover": {
        "without": "Session stays active. Attacker exfiltrates all accessible data silently.",
        "with":    "Session frozen. Only partial data exposed before lockout.",
    },
    "ddos": {
        "without": "Server exhausted in ~2 min. Site goes down.",
        "with":    "CDN absorbs flood. Server stays up. Users unaffected.",
    },
    "vsftpd_backdoor": {
        "without": "Backdoor shell opened — attacker has full unauthenticated root access.",
        "with":    "CVE-2011-2523 signature detected. FTP service isolated. Backdoor blocked.",
    },
    "samba_cmd_injection": {
        "without": "Command injection succeeds. Attacker executes arbitrary OS commands as root.",
        "with":    "CVE-2007-2447 pattern blocked. Samba patched. Shell connection refused.",
    },
    "mysql_anon_auth": {
        "without": "Auth bypass succeeds. Full database read/write. All credentials stolen.",
        "with":    "CVE-2012-2122 blocked. Auth hardened. Anonymous access disabled.",
    },
    "hydra_ssh_attack": {
        "without": "Password found after 500 attempts. SSH access granted.",
        "with":    "fail2ban triggers at attempt 5. IP blocked. Remaining attempts useless.",
    },
    "nmap_full_scan": {
        "without": "Full service map obtained. Attacker knows all vulnerable services.",
        "with":    "Scan detected. Unnecessary ports closed. Attacker gets partial map only.",
    },
}

# Adaptive playbook — escalating responses based on sophistication score
ADAPTIVE_PLAYBOOK = {
    "BASELINE_RESPONSE": {
        "description": "Low sophistication attacker — standard logging",
        "actions": ["Log to SIEM", "Add to watchlist"],
        "auto_execute": True,
    },
    "MODERATE_RESPONSE": {
        "description": "Medium sophistication — rate limiting + alerting",
        "actions": ["Rate limit IP (100 req/min)", "Alert SOC team", "Watchlist upgrade"],
        "auto_execute": True,
    },
    "ELEVATED_RESPONSE": {
        "description": "High sophistication — active countermeasures",
        "actions": ["Block IP (60 min)", "Invalidate sessions", "Force MFA", "SIEM critical alert", "Threat intel feed update"],
        "auto_execute": True,
    },
    "CRITICAL_RESPONSE": {
        "description": "Elite attacker / APT — full incident response",
        "actions": ["Global IP block", "Host quarantine", "Honeypot redirect", "IR team page", "Evidence preservation", "Threat intel share"],
        "auto_execute": False,  # Requires human approval for APT-level response
    },
}


def get_response(rule: str) -> dict:
    return ACTIONS.get(rule, {
        "action": "Log and Monitor",
        "detail": "Event logged for manual security review.",
        "symbol": "log", "severity": "low",
    })


def get_compare(scenario: str) -> dict:
    return COMPARE.get(scenario, {
        "without": "Threat succeeds undetected.",
        "with":    "Threat neutralized by automated response.",
    })
