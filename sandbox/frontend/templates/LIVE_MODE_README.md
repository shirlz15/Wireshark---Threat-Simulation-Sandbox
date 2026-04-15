# 🔴 LIVE PACKET CAPTURE MODE - Complete Guide

## 📋 Overview

Your cybersecurity dashboard now supports **two modes**:

1. **SIMULATION MODE** (default) - Generates fake attack events for learning
2. **LIVE MODE** (new) - Captures real network packets from your system

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install Scapy
pip install scapy --break-system-packages

# Or with pip3
pip3 install scapy --break-system-packages
```

### Running in LIVE MODE

```bash
# Linux/Mac (requires root)
sudo python3 app.py

# Windows (run as Administrator)
python app.py
```

### Switching Modes

**Via UI:**
- Click the **SIMULATION/LIVE toggle** in the dashboard
- When live mode activates, you'll see: **"🔴 LIVE CAPTURE ACTIVE"**

**Via API:**
```bash
# Switch to live mode
curl -X POST http://localhost:5000/api/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "live"}'

# Switch back to simulation
curl -X POST http://localhost:5000/api/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "simulation"}'
```

---

## 🔒 Safety & Privacy

### What is Captured
✅ **Captured (metadata only):**
- Source IP address
- Destination IP address
- Destination port
- Protocol (TCP/UDP/ICMP)
- Packet size
- Timestamp

❌ **NOT captured:**
- Packet payload
- Message contents
- Passwords
- Personal data
- Application data

### Code Implementation
```python
# From simulator.py - NO PAYLOAD CAPTURED
packet_data = {
    "src_ip": src_ip,
    "dst_ip": dst_ip,
    "dst_port": dst_port,
    "protocol": protocol,
    "timestamp": datetime.now().strftime("%H:%M:%S"),
    "size": packet_size,
    # NO PAYLOAD DATA HERE
}
```

### Local Only
- All captured data stays on your machine
- Nothing is sent to external servers
- Educational use only
- Complies with ethical security research practices

---

## 🧪 Testing Live Capture

### Test 1: Verify Scapy Installation

```bash
python3 simulator.py test
```

**Expected output:**
```
============================================================
LIVE CAPTURE TEST MODE
============================================================
✓ Permissions OK

Capturing 10 packets for testing...
(Generate some network traffic - browse web, ping, etc.)

  [1] TCP  192.168.1.100  → 142.250.80.46  :443   1420 bytes
  [2] TCP  142.250.80.46  → 192.168.1.100  :443   60 bytes
  [3] UDP  192.168.1.100  → 8.8.8.8        :53    72 bytes
  ...
✓ Test completed successfully!
```

### Test 2: Generate Test Traffic

**Terminal 1 - Start Dashboard:**
```bash
sudo python3 app.py
```

**Terminal 2 - Generate Traffic:**
```bash
# Ping generates ICMP packets
ping google.com

# DNS lookups generate UDP packets
nslookup github.com

# Web browsing generates TCP packets
curl https://example.com

# Port scan (triggers CRITICAL detection)
nmap -F localhost
```

**Terminal 3 - Watch Dashboard:**
```bash
# Open browser
firefox http://localhost:5000

# Click toggle to switch to LIVE mode
# Click START
# Watch real packets appear!
```

---

## 🎯 What to Expect

### Normal Traffic
When browsing the web or using apps normally:
- **Status:** SAFE (green)
- **Packets:** 5-20 per second
- **Sources:** Mix of your local IP and external servers
- **Ports:** Mostly 80, 443, 53 (HTTP, HTTPS, DNS)

### Port Scan Detection
When running `nmap localhost`:
- **Status:** CRITICAL (red) within seconds
- **Detection:** PORT_SCAN
- **Details:** "Scanned 8+ unique ports in 30s"
- **MITRE:** T1046 - Network Service Discovery

### Brute Force Simulation
When connecting repeatedly to SSH:
```bash
# This will trigger BRUTE_FORCE detection
for i in {1..10}; do nc localhost 22; done
```
- **Status:** CRITICAL (red)
- **Detection:** BRUTE_FORCE
- **Details:** "8 rapid attempts on port 22"

---

## 🐛 Troubleshooting

### Problem: "Scapy not installed"

**Solution:**
```bash
pip install scapy --break-system-packages
```

### Problem: "Root privileges required"

**Linux/Mac Solution:**
```bash
sudo python3 app.py
```

**Windows Solution:**
1. Right-click Command Prompt
2. Select "Run as Administrator"
3. `python app.py`

### Problem: No packets appearing in live mode

**Checklist:**
1. ✓ Did you click START after switching to live mode?
2. ✓ Is there network traffic? (Open a website, ping something)
3. ✓ Check terminal for errors
4. ✓ Run `python3 simulator.py test` to verify capture works

**Debug Mode:**
```python
# In app.py, add this to simulation_loop():
print(f"MODE: {MODE}, RUNNING: {running}")
```

### Problem: Too many packets, dashboard slows down

**Solution:** The dashboard auto-limits to 1000 events. If still slow:

```python
# In simulator.py, add packet filtering:
def packet_handler(packet):
    # Only capture specific traffic
    if packet.haslayer(TCP) and packet[TCP].dport in [22, 80, 443]:
        # ... process packet
```

### Problem: Permission denied on Windows

**Solution:**
1. Install Npcap (required for Windows): https://npcap.com/
2. During installation, check "Install Npcap in WinPcap API-compatible mode"
3. Restart terminal
4. Run as Administrator

---

## 📊 API Reference

### GET /api/status
Returns current system status including mode.

**Response:**
```json
{
  "running": true,
  "mode": "live",
  "total_events": 247,
  "engine": "DetectionEngine v3",
  "scapy_available": true,
  "permission_warning": null
}
```

### POST /api/mode
Switch between simulation and live mode.

**Request:**
```json
{
  "mode": "live"  // or "simulation"
}
```

**Success Response:**
```json
{
  "ok": true,
  "mode": "live",
  "message": "Switched to live mode"
}
```

**Error Response (no permissions):**
```json
{
  "ok": false,
  "error": "Root privileges required. Run with: sudo python3 app.py",
  "mode": "simulation"
}
```

### GET /api/events
Includes mode in response.

**Response:**
```json
{
  "events": [...],
  "running": true,
  "mode": "live",
  "stats": {...},
  "traffic_history": [...],
  "top_attackers": [...],
  "scapy_available": true,
  "permission_warning": null
}
```

---

## 🎓 Educational Use Cases

### Scenario 1: Port Scan Detection Lab

**Goal:** Understand how port scans are detected

**Steps:**
1. Switch to LIVE mode
2. Click START
3. In another terminal: `nmap -F localhost`
4. Watch dashboard detect the scan in real-time
5. Observe: Multiple ports hit rapidly → CRITICAL status

**Learning:** Port scans probe many ports quickly. The detection engine tracks unique ports per IP in a 30-second window.

### Scenario 2: Normal vs Suspicious Traffic

**Goal:** See the difference between normal and suspicious traffic

**Steps:**
1. Switch to LIVE mode, click START
2. Browse a few websites (normal traffic)
3. Then probe database ports: `nc localhost 3306`, `nc localhost 5432`
4. Watch status change from SAFE to SUSPICIOUS

**Learning:** Connections to sensitive ports (databases, admin services) trigger alerts even if isolated.

### Scenario 3: Traffic Flood Detection

**Goal:** Trigger a flood detection

**Steps:**
1. Switch to LIVE mode, click START
2. Generate rapid traffic:
```bash
# 100 rapid HTTP requests
for i in {1..100}; do curl http://localhost:5000/api/status; done
```
3. Watch the dashboard detect TRAFFIC_FLOOD

**Learning:** Detection engine counts packets per IP. 40+ packets in 30s triggers CRITICAL.

---

## 🔧 Advanced Configuration

### Custom Packet Filtering

Edit `simulator.py` to filter specific traffic:

```python
def packet_handler(packet):
    # Only capture HTTP/HTTPS traffic
    if packet.haslayer(TCP):
        port = packet[TCP].dport
        if port not in [80, 443]:
            return  # Ignore non-web traffic
    
    # ... rest of handler
```

### Adjust Detection Thresholds

Edit `detector.py` to tune sensitivity:

```python
# In DetectionEngine.analyze():
if recent_ports >= 5:  # Changed from 8 (more sensitive)
    return {"threat_level": "critical", "threat_type": "PORT_SCAN", ...}
```

### Custom Network Interface

By default, Scapy captures from all interfaces. To specify one:

```python
# In simulator.py, modify sniff():
sniff(
    filter="ip",
    iface="eth0",  # Specify interface
    prn=packet_handler,
    store=0
)
```

---

## 📝 Code Structure

```
app.py
├── MODE = "simulation" | "live"     # Global mode switch
├── simulation_loop()                 # Main loop
│   ├── if MODE == "simulation"      # Use make_event()
│   └── if MODE == "live"            # Use capture_live_packets()
├── make_event()                     # Generate fake events
├── process_live_packet()            # Process real packets
└── /api/mode                        # Mode switch endpoint

simulator.py
├── capture_live_packets()           # Scapy packet capture
├── check_capture_permissions()      # Permission validator
├── packet_handler()                 # Extract metadata
└── test_live_capture()              # CLI test mode
```

---

## ⚠️ Limitations

1. **Requires elevated privileges** (root/admin)
2. **Local traffic only** (cannot capture remote networks)
3. **Performance:** High traffic (1000+ pps) may slow dashboard
4. **No encryption bypass:** HTTPS payload is encrypted (we only see metadata anyway)
5. **Educational only:** Not a production IDS

---

## 🆘 Support

### Get Help

**Issue:** Mode won't switch to live
```bash
# Check status
curl http://localhost:5000/api/status

# Check logs in terminal running app.py
```

**Issue:** Packets captured but not appearing
- Verify browser is polling: check Network tab in DevTools
- Refresh the page
- Check if START was clicked

**Issue:** Dashboard shows wrong mode
- Mode state is server-side
- Refresh page to sync UI with backend
- Check `/api/status` endpoint

---

## 📜 License & Ethics

This tool is for **educational purposes only**:
- ✅ Learn about network security
- ✅ Test your own systems
- ✅ Understand attack detection
- ❌ Do NOT use on networks you don't own
- ❌ Do NOT capture others' traffic
- ❌ Do NOT use for malicious purposes

**Legal Notice:** Packet capture may be subject to local laws. Only use on networks you own or have explicit permission to monitor.

---

## 🎉 What's Next?

### Suggested Experiments

1. **Compare modes:** Run same test in simulation vs live - see the difference
2. **Real attack detection:** Use Metasploit to generate scans
3. **Custom rules:** Modify detection engine for your use case
4. **Log analysis:** Export reports with live vs simulated data

### Future Enhancements

- Filter by protocol (TCP only, UDP only)
- Select network interface in UI
- Packet count limiter in UI
- Export live capture to PCAP
- Integration with real firewall rules

---

**Version:** 3.0  
**Last Updated:** 2026-04-15  
**Author:** Cybersecurity Dashboard Team
