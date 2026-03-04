# Honeypot Attack Detection System

## Overview
A **low-interaction honeypot** built in Python that simulates fake SSH, Telnet, and FTP services to detect and analyze brute-force attacks and attacker behavior.

Designed for **Blue Team / Defensive Security** learning and portfolio demonstrations.

---

## Features
- **Multi-Protocol Honeypots** — Listens on SSH (port 2222), Telnet (port 23), and FTP (port 21) simultaneously.
- **Advanced Interactive Shell** — A stateful fake Linux shell that attackers can explore (`cd`, `ls`, `cat`, `wget`, etc.)
- **Payload Capture** — Detects and logs `wget`/`curl` commands to capture attacker-supplied malware URLs.
- **Real-Time Web Dashboard** — A dark-themed SOC dashboard showing live logs, incident reports, severity stats, and the attack graph.
- **Severity Classification** — Automatically classifies each attacker as LOW, MEDIUM, or HIGH severity.
- **Geo-IP Tagging** — Tags each attacker IP as Local, Private, or Unknown.
- **IDS Alerts** — HIGH severity attacks and payload captures are escalated and written to `ids_alerts.txt`.
- **Incident Reports** — Auto-generated per-IP incident reports.
- **Attack Graphs** — Matplotlib bar chart of attack attempts per IP, refreshed in the dashboard.
- **File Trap** — Detects file tampering in the `file_trap/` directory (simulates ransomware detection).

---

## Architecture
Everything runs from a **single file** (`Honeypot.py`). No separate directories or files are required.

When launched, the following four services start concurrently:

| Service | Port | Description |
|---|---|---|
| SSH Honeypot | 2222 | Fake SSH with interactive shell |
| Telnet Honeypot | 23 | Fake Telnet with interactive shell |
| FTP Honeypot | 21 | Fake FTP capturing credentials |
| Web Dashboard | 5000 | Live SOC dashboard (Flask) |

---

## Technologies
- Python (Socket, Threading, Socket Programming)
- Flask (Dashboard backend)
- Matplotlib (Attack graphs)
- Vanilla HTML/CSS/JS (Dashboard frontend, embedded in script)

---

## How to Run

### 1. Install dependencies
```bash
pip install flask matplotlib
```

### 2. Run the script
```bash
python Honeypot.py
```

> **Note:** Ports 21 (FTP) and 23 (Telnet) require **Administrator** privileges on Windows.  
> Run your terminal as Administrator to enable all three honeypot services.

### 3. Access the Dashboard
Open `http://localhost:5000` in your browser.

---

## Generated Files

| File | Description |
|---|---|
| `honeypot.log` | All raw attack activity logs |
| `incident_report.txt` | Structured per-IP incident report |
| `ids_alerts.txt` | Escalated HIGH severity and payload capture alerts |
| `attack_graph.png` | Bar chart of attempts per IP |
| `file_trap/` | Monitored directory for ransomware detection |

---

## Testing

Connect to each service and simulate attacks:

```bash
# SSH (any TCP client)
ncat 127.0.0.1 2222

# Telnet
telnet 127.0.0.1 23

# FTP
ftp 127.0.0.1 21
```

Shell commands supported: `ls`, `cd`, `pwd`, `cat`, `whoami`, `id`, `uname`, `wget`, `curl`, `ifconfig`, `history`, `exit`
