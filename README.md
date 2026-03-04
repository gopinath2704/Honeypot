# Honeypot Attack Detection System

## Overview
A **low-interaction honeypot** built in Python that simulates fake SSH, Telnet, and FTP services to detect and analyze brute-force attacks and attacker behavior.

Designed for **Blue Team / Defensive Security** learning and portfolio demonstrations.

---

## Features
- **Multi-Protocol Honeypots** — Listens on SSH (port 2223), Telnet (port 2323), and FTP (port 2121) simultaneously.
- **Advanced Interactive Shell** — A stateful fake Linux shell that attackers can explore (`cd`, `ls`, `cat`, `wget`, etc.)
- **Payload Capture** — Detects and logs `wget`/`curl` commands to capture attacker-supplied malware URLs.
- **Real-Time Web Dashboard** — A dark-themed SOC dashboard showing live logs, incident reports, severity stats, and the attack graph.
- **Severity Classification** — Automatically classifies each attacker as LOW, MEDIUM, or HIGH severity.
- **Geo-IP Tagging** — Tags each attacker IP as Local, Private, or Unknown.
- **IDS Alerts** — HIGH severity attacks and payload captures are escalated and written to `ids_alerts.txt`.
- **Incident Reports** — Auto-generated per-IP incident reports.
- **Live Attack Graphs** — Dynamic, animated Chart.js bar chart of attack attempts per IP.
- **File Trap** — Detects file tampering in the `file_trap/` directory (simulates ransomware detection).

---

## Architecture
Everything runs from a **single file** (`Honeypot.py`). No separate directories or files are required.

When launched, the following four services start concurrently:

| Service | Port | Description |
|---|---|---|
| SSH Honeypot | 2223 | Fake SSH with interactive shell |
| Telnet Honeypot | 2323 | Fake Telnet with interactive shell |
| FTP Honeypot | 2121 | Fake FTP capturing credentials |
| Web Dashboard | 5001 | Live SOC dashboard (Flask) |

---

## Technologies
- Python (Socket, Threading, Socket Programming)
- Flask (Dashboard backend)
- Chart.js (Live animated attack graphs)
- Vanilla HTML/CSS/JS (Dashboard frontend, embedded in script)

---

## How to Run

### 1. Install dependencies
```bash
pip install flask
```

### 2. Run the script
```bash
python Honeypot.py
```

> **Note:** Ports 21 (FTP) and 23 (Telnet) require **Administrator** privileges on Windows.  
> Run your terminal as Administrator to enable all three honeypot services.

### 3. Access the Dashboard
Open `http://localhost:5001` in your browser.

---

## Generated Files

| File | Description |
|---|---|
| `honeypot.log` | All raw attack activity logs |
| `incident_report.txt` | Structured per-IP incident report |
| `ids_alerts.txt` | Escalated HIGH severity and payload capture alerts |
| `file_trap/` | Monitored directory for ransomware detection |

---

## Testing

Connect to each service and simulate attacks manually:

```bash
# SSH (any TCP client)
ncat 127.0.0.1 2223

# Telnet
telnet 127.0.0.1 2323

# FTP
ftp 127.0.0.1 2121
```

Or run the automated attack simulator (simulates multiple brute-force sessions and payload drops):
```bash
python simulate_attack.py
```

Shell commands supported: `ls`, `cd`, `pwd`, `cat`, `whoami`, `id`, `uname`, `wget`, `curl`, `ifconfig`, `history`, `exit`
