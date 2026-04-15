# ⚡ LIVE MODE - 5-Minute Quick Start

## 🎯 Goal
Get live packet capture running in 5 minutes.

---

## Step 1: Install Dependencies (30 seconds)

```bash
cd /path/to/your/project
pip install scapy --break-system-packages
```

---

## Step 2: Test Permissions (30 seconds)

```bash
# Linux/Mac
sudo python3 simulator.py test

# Windows (run as Admin)
python simulator.py test
```

**Expected:** You should see 10 packets captured
**If error:** See troubleshooting at bottom

---

## Step 3: Start Server with Elevated Privileges (30 seconds)

```bash
# Linux/Mac
sudo python3 app.py

# Windows (Admin Command Prompt)
python app.py
```

**Look for:**
```
✓ Scapy available - Live mode ready
```

---

## Step 4: Open Dashboard (30 seconds)

```
http://localhost:5000
```

---

## Step 5: Switch to Live Mode (30 seconds)

1. Click the **SIMULATION/LIVE toggle** button
2. Wait for **"🔴 LIVE CAPTURE ACTIVE"** indicator
3. Click **START**

---

## Step 6: Generate Traffic & Watch (2 minutes)

Open another terminal:

```bash
# Simple traffic test
ping google.com

# Browse a website
curl https://example.com

# Trigger a PORT SCAN (CRITICAL alert)
nmap -F localhost
```

**Watch the dashboard:**
- Normal pings → SAFE (green)
- Port scan → CRITICAL (red) in ~3 seconds

---

## ✅ Success Checklist

- [ ] Scapy installed (`pip install scapy`)
- [ ] Server running with sudo/admin
- [ ] Dashboard open at localhost:5000
- [ ] Toggle switched to LIVE
- [ ] START button clicked
- [ ] Packets appearing in dashboard

---

## 🐛 Quick Fixes

### "Scapy not installed"
```bash
pip install scapy --break-system-packages
# or
pip3 install scapy --break-system-packages
```

### "Root privileges required"
```bash
# Linux/Mac
sudo python3 app.py

# Windows: Right-click CMD → Run as Administrator
python app.py
```

### "No packets appearing"
1. Did you generate traffic? (ping, browse web)
2. Did you click START?
3. Try refreshing the page

### Windows: "Permission denied"
1. Install Npcap: https://npcap.com/
2. Check "WinPcap API-compatible mode" during install
3. Restart terminal as Admin

---

## 🎓 First Experiment

**Goal:** Detect a real port scan

**Terminal 1:**
```bash
sudo python3 app.py
```

**Browser:**
```
http://localhost:5000
Toggle to LIVE → Click START
```

**Terminal 2:**
```bash
nmap -F localhost
```

**Expected Result:**
Within 3-5 seconds, dashboard shows:
- Status: CRITICAL (red)
- Type: PORT_SCAN
- Detail: "Scanned 8+ unique ports in 30s"
- MITRE: T1046

**What happened:**
Nmap probed multiple ports rapidly. The detection engine tracked:
- Source IP
- Unique ports hit
- Time window

When 8+ ports were hit in 30s → CRITICAL alert triggered.

---

## 📚 Next Steps

1. Read full documentation: `LIVE_MODE_README.md`
2. Try different attacks (see educational scenarios)
3. Customize detection thresholds in `detector.py`
4. Compare simulation vs live mode side-by-side

---

## 🆘 Still Not Working?

**Check server logs:**
Look at the terminal running `app.py` for error messages.

**Check API status:**
```bash
curl http://localhost:5000/api/status
```

**Test Scapy directly:**
```bash
python3 simulator.py test
```

**Get detailed help:**
See `LIVE_MODE_README.md` for comprehensive troubleshooting.

---

**You're now capturing real network traffic! 🎉**
