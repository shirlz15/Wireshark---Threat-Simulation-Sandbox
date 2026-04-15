# ⬡ Threat Simulation Sandbox — Live Network Security Lab

A real-time network threat detection and visualization dashboard built on Kali Linux, combining Python Flask, animated canvas visualizations, and a rule-based detection engine.

## 🖥 Dashboard Features

| Panel | What it shows |
|---|---|
| **Network Topology** | Live animated graph — attacker nodes orbit target, packet animations fly along links, nodes glow red/yellow/green by threat level |
| **Traffic Waveform** | Real-time packets/sec graph with attack spikes highlighted in red |
| **Live Packet Feed** | Scrolling event table with timestamps, IPs, protocol, detail, and MITRE mapping on hover |
| **Threat Distribution** | 5 animated progress bars — Port Scan / Brute Force / Flood / Sensitive Port / Normal |
| **Attacker vs Defender** | Split battle log — attacker actions left, automated defender responses right |
| **Top Attackers** | Live ranked list of most active source IPs with hit bars |
| **Attack Heatmap** | 2D intensity grid showing attack concentration over time |

## 🚀 Quick Start

```bash
cd /home/kali/sandbox
pip install flask --break-system-packages
python3 app.py
```

Open Firefox → `http://localhost:5000` → click **▶ START**

## 🔬 Real Traffic Mode (Metasploit + Wireshark)

**Terminal 1 — tcpdump:**
```bash
sudo tcpdump -i eth0 -n -l -tttt ip > /home/kali/sandbox/capture/live.log
```

**Terminal 2 — sandbox:**
```bash
python3 /home/kali/sandbox/app.py
```

**Terminal 3 — Metasploit port scan (triggers CRITICAL in ~3 seconds):**
```bash
sudo msfconsole
use auxiliary/scanner/portscan/syn
set RHOSTS 10.1.17.239     # your Kali IP
set PORTS 21-443
set THREADS 10
run
```

**Wireshark filter to see the scan:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

## 🕵 Detection Rules

| Rule | Trigger | Level |
|---|---|---|
| PORT_SCAN | 8+ unique ports in 30s | CRITICAL |
| BRUTE_FORCE | 8+ hits on SSH/RDP/DB port in 30s | CRITICAL |
| TRAFFIC_FLOOD | 40+ packets from one IP in 30s | CRITICAL |
| SENSITIVE_PORT | Any probe on port 21/22/23/3389/3306 etc | SUSPICIOUS |
| PORT_SPREAD | 4–7 unique ports in window | SUSPICIOUS |

## 🗂 Project Structure

```
sandbox/
├── app.py                     ← Flask server + simulation engine
├── backend/
│   ├── __init__.py
│   └── detector.py            ← Stateful detection engine
├── frontend/
│   └── templates/
│       └── dashboard.html     ← Full animated UI (canvas graphs)
├── capture/                   ← Drop pcap/tcpdump files here
├── reports/                   ← Exported incident reports
└── README.md
```

## 📊 MITRE ATT&CK Mapping

| Detection | MITRE ID |
|---|---|
| PORT_SCAN | T1046 — Network Service Discovery |
| BRUTE_FORCE | T1110 — Brute Force |
| TRAFFIC_FLOOD | T1499 — Endpoint Denial of Service |
| SENSITIVE_PORT | T1021 — Remote Services |

## 🔧 Requirements

- Python 3.8+
- Flask (`pip install flask --break-system-packages`)
- Kali Linux (or any Linux with tcpdump/tshark available)
- Firefox or Chromium for the dashboard
