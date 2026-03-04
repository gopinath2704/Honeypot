# Honeypot Attack Detection System

## Overview
This project implements a **low-interaction honeypot** using Python to simulate a fake SSH-like service.  
It is designed for **Blue Team / Defensive Security learning**, focusing on detecting brute-force attacks and analyzing attacker behavior.

The script has been modernized to include a **standalone dashboard**, meaning the web UI and honeypot server run concurrently entirely entirely from a single Python file.

The honeypot records:
- Attacker IP addresses
- Username & password attempts
- Number of attempts per IP
- Attack severity levels
- Incident reports
- Traffic visualization graphs

---

## Features Added
- **Beautiful Web Dashboard:** A responsive dashboard combining live log monitoring, stat tracking, and real-time attack distribution visualizations.
- **Unified Architecture:** All backend (Flask app) and frontend (glassmorphism UI with HTML/CSS/JS) logic is packaged dynamically within `Honeypot.py` for maximum portability and minimalism. It requires no separate directory structures.

---

## Objectives
- Detect brute-force login attempts
- Log attacker activity for forensic analysis
- Assign severity based on attack intensity
- Generate incident reports automatically
- Visualize attack patterns in a dynamic, locally hosted dashboard view

---

## Technologies Used
- Python (Socket Programming, Multithreading)
- Flask (For the Dashboard UI backend)
- Vanilla HTML/CSS/JS (Stored as literal strings for portability)
- Matplotlib (Graphs)
- File-based logging

---

## How to Run

1. Install dependencies:
`pip install flask matplotlib`

2. Run the honeypot unified script:
`python Honeypot.py`

3. The script will automatically start TWO concurrent services:
- The Fake SSH honeypot listening on port `2222`.
- The interactive cyber-dashboard viewable at: `http://localhost:5000`
