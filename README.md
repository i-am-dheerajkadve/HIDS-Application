# 🛡️ Sentinel HIDS — Enhanced Dashboard

## Host-Based Intrusion Detection System
### Next-Generation Security Monitoring Platform

---

## Features

### 🎯 Dashboard
- Real-time threat level indicator (SECURE / ELEVATED / HIGH RISK / CRITICAL)
- Animated alert severity counters (Critical, High, Medium, Low)
- Live threat distribution donut chart
- System vitals gauges (CPU, Memory, Disk)
- 30-point CPU & Memory history charts
- Recent alert feed with click-to-expand details


### 🚨 Alerts Panel
- Full alert history with severity filtering
- Click any alert to expand JSON details
- Toast notifications for new threats
- Scan statistics (processes, files, connections scanned)

### ⚙️ Process Monitor
- Live table of all running processes
- CPU & Memory usage bar meters
- Suspicious process highlighting (red row)
- Search & sort by any column
- Threat / Clean status badges

### 🌐 Network Monitor
- Active connections with threat detection
- Bytes sent/received sparkline charts
- Suspicious port flagging with threat labels

### 💻 System Health
- Animated ring gauges (CPU, Memory, Disk)
- 30-point history charts
- System information panel (OS, hostname, uptime, Python version)

### 📂 File Scanner
- Scan any directory for malware
- Animated terminal progress display
- Quick scan targets (Home, /tmp, Downloads)

### 🧬 Signature Database
- Suspicious process names viewer
- Known malicious ports viewer
- Malicious keyword database
- Known malware hash count

---

## Installation

```bash
pip install flask flask-cors psutil
python app.py
```

Then open: http://127.0.0.1:5000

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Engine status, scan count, alert stats |
| `/api/system` | GET | CPU, memory, disk, network I/O |
| `/api/alerts` | GET | Alert history (filter by severity) |
| `/api/processes` | GET | Running process list |
| `/api/connections` | GET | Active network connections |
| `/api/scan` | POST | Trigger a scan |
| `/api/start` | POST | Start continuous monitoring |
| `/api/stop` | POST | Stop monitoring |
| `/api/clear_alerts` | POST | Clear alert history |
| `/api/signatures` | GET | Threat signature database |
