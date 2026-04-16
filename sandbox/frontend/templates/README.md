# Cyber Threat Simulation Sandbox v4.0
## Behavioral Analysis + Live Capture + Scenario Injection

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: Packet Capture                                     │
│  tshark subprocess → TSV field extraction → packet metadata  │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: Behavioral Pattern Engine                          │
│  Per-IP BehaviorFingerprint · Sliding windows (5/10/30s)    │
│  7-rule priority chain · Confidence scoring · Phase tracking │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: Simulation Engine                                  │
│  5 named attack scenarios · Synthetic event injection        │
│  Defender playbook with automated responses                  │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: Flask API                                          │
│  /api/events  /api/simulate  /api/replay  /api/fingerprint  │
├─────────────────────────────────────────────────────────────┤
│  LAYER 5: Visualization                                      │
│  Canvas topology · Live feed · Replay slider · Scenario UI  │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Install dependencies
pip install flask --break-system-packages

# 2. Run (simulation mode — no privileges needed)
python3 app.py

# 3. Run with live capture (requires tshark)
sudo apt install tshark
sudo python3 app.py

# 4. Open browser
firefox http://localhost:5000
```

## Project Structure

```
sandbox/
├── app.py                          ← Flask server + all logic
├── backend/
│   ├── __init__.py
│   └── detector.py                 ← Behavioral pattern engine v4
├── frontend/
│   └── templates/
│       └── dashboard.html          ← Full UI (tabs, replay, scenarios)
├── capture/                        ← Drop pcap files here
├── reports/                        ← Exported incident reports
├── requirements.txt
└── README.md
```

## Detection Rules

| Rule | Trigger | Level | Confidence |
|------|---------|-------|------------|
| PORT_SCAN | 12+ unique ports in 30s | CRITICAL | 60–99% |
| BRUTE_FORCE | 6+ hits on critical port in 10s | CRITICAL | 55–98% |
| TRAFFIC_FLOOD | 25+ packets in 5s | CRITICAL | 50–97% |
| RECON_SEQUENCE | Wide scan → sensitive port pivot | SUSPICIOUS | 62–82% |
| SENSITIVE_PORT | Repeated DB/admin access | SUSPICIOUS | 45–75% |
| PORT_SPREAD | 4+ distinct ports in 10s | SUSPICIOUS | 30–50% |
| NORMAL | No pattern detected | SAFE | 95% |

## API Reference

```
GET  /api/events?since=N         Poll new events
GET  /api/replay?pct=0-100       Replay last 500 events at position
POST /api/simulate               Inject scenario: {type: "port_scan"}
GET  /api/scenarios              List available scenarios
GET  /api/fingerprint/:ip        Get behavioral fingerprint for IP
POST /api/mode                   Switch mode: {mode: "simulation"|"live"}
GET  /api/report                 Download incident report (text)
GET  /api/status                 System health check
```

## Available Scenarios

- `port_scan` — 12-port systematic sweep
- `brute_force` — 15-hit SSH credential attack
- `db_harvest` — Web recon → DB probe → MySQL brute
- `ddos` — 40-packet volumetric flood
- `lateral_movement` — SMB + RDP + SSH chain

## Attack Phase Tracking

Each attacker IP moves through a lifecycle that only advances forward:

```
IDLE → RECON → EXPLOIT → IMPACT
```

This enables detection of multi-stage attacks even when individual
packets appear benign in isolation.

## Novel Features (v4.0)

1. **Confidence Scoring** — Every detection outputs 0–100% confidence
   with rule-based reasoning (not labels)

2. **Behavioral Sequence Detection** — Detects recon-then-exploit chains
   as a single threat, not separate events

3. **Explainable Detections** — Every event includes a plain-English
   explanation of *why* it was flagged

4. **tshark Integration** — Uses Wireshark CLI instead of Scapy,
   requiring only system package install

5. **Replay System** — Slider-based event replay for post-incident analysis

6. **Scenario Injection API** — POST /api/simulate injects realistic
   multi-step attack sequences into the live stream

## Live Capture (Linux/Kali)

```bash
# Install tshark
sudo apt install tshark

# Start with live capture
sudo python3 app.py

# Toggle to LIVE mode in UI
# Or via API:
curl -X POST http://localhost:5000/api/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "live"}'
```

## Inject an Attack Scenario

```bash
# Port scan (triggers CRITICAL in ~3 seconds)
curl -X POST http://localhost:5000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"type": "port_scan"}'

# Database harvest sequence
curl -X POST http://localhost:5000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"type": "db_harvest"}'
```

## Replay

Navigate to the **Replay** tab and drag the slider from 0–100%
to replay any time window of the last 500 captured events.
Useful for post-incident analysis and training exercises.
