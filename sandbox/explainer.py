"""
explainer.py v5.0
Plain-English + Kali tool specific explanations
"""

EXPLANATIONS = {
    "login_attempt":    "A login request was received. Single attempts are normal.",
    "login_failed":     "Wrong password. Rapid failures from one IP indicate automated credential stuffing.",
    "port_probe":       "A connection attempt on a specific port. Multiple rapid probes = port scan.",
    "geo_flag":         "Login from unusual country. Weak signal alone; strong with other flags.",
    "time_flag":        "Login at unusual hour. Attackers strike outside business hours.",
    "behavior_flag":    "Post-login activity looks automated — bulk data access or rapid file ops.",
    "traffic_spike":    "Sudden request volume jump from one IP = probable flood attack.",
    "block_ip":         "Source IP added to firewall blocklist. All future packets dropped.",
    "close_ports":      "Unnecessary ports closed, attack surface reduced.",
    "restrict_access":  "Session invalidated. Legitimate user gets MFA challenge.",
    "rate_limit":       "CDN capped requests. Flood hits a wall; legitimate users unaffected.",
    "exploit_attempt":  "Known CVE exploit pattern detected against a specific service.",
    "kali_tool":        "Traffic signature matches a specific Kali Linux offensive tool.",
}

STATUS_NOTES = {
    "safe":       "Normal activity — no action needed.",
    "suspicious": "Anomalous pattern — system is monitoring closely.",
    "attack":     "Confirmed attack pattern — automated response triggered.",
    "response":   "Defensive action executed — threat neutralized.",
}

KALI_TOOL_EXPLANATIONS = {
    "nmap_syn_scan":     "Nmap SYN scan (-sS) sends TCP SYN packets without completing the handshake, probing which ports respond. It's the most common reconnaissance tool.",
    "nmap_service_ver":  "Nmap service version detection (-sV) sends probe strings to each open port to identify software versions, enabling targeted CVE exploitation.",
    "hydra_ssh":         "Hydra is an automated login cracker. It cycles through password lists at machine speed against SSH, trying thousands of combinations per minute.",
    "hydra_ftp":         "Hydra targeting FTP credentials. FTP transmits passwords in cleartext AND is susceptible to brute force — double risk.",
    "sqlmap":            "SQLMap automatically tests web forms for SQL injection. It escalates from detection → extraction → OS command execution.",
    "metasploit_msf":    "Metasploit Framework is the industry-standard exploitation platform. Port 4444 is the default reverse shell listener port.",
    "nikto_scan":        "Nikto tests web servers for 6,700+ vulnerabilities including misconfigs, default files, and outdated software.",
    "medusa_rdp":        "Medusa parallel login brute-forcer targeting Remote Desktop Protocol. Successful RDP compromise = full graphical desktop access.",
}


def explain_event(event: dict) -> str:
    base = EXPLANATIONS.get(event.get("type", ""), "No explanation for this event type.")
    note = STATUS_NOTES.get(event.get("status", ""), "")
    return f"{base} — {note}" if note else base


def build_ai_prompt(events: list, scenario: str) -> str:
    lines = "\n".join(
        f"[{e['timestamp']}] {e.get('threat_level','?').upper()} - {e.get('detail','')}"
        for e in events
    )
    return f"""You are a cybersecurity educator explaining an attack to a student.

Scenario: {scenario.replace('_', ' ').title()}

Event log:
{lines}

In 3–4 paragraphs explain:
1. What attack is this and how does it work technically?
2. What behavioral signals gave it away?
3. What did the defense do and why does it work?
4. One real-world breach caused by this exact technique.

Keep it specific, direct, and jargon-free."""
