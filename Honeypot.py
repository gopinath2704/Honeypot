import socket
import threading
import time
import os
import logging
from datetime import datetime
from collections import defaultdict
import matplotlib
matplotlib.use('Agg') # Ensure it runs headlessly
import matplotlib.pyplot as plt
from flask import Flask, jsonify, send_file, render_template_string

# Set werkzeug logger to ERROR to reduce spam in the console
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ================= CONFIG =================
HOST = "0.0.0.0"
PORT = 2222

BLOCK_THRESHOLD = 5
MEDIUM_THRESHOLD = 3

LOG_FILE = "honeypot.log"
INCIDENT_REPORT = "incident_report.txt"
IDS_ALERTS = "ids_alerts.txt"
GRAPH_FILE = "attack_graph.png"
FILE_TRAP_DIR = "file_trap"   # Feature 5

# ============== DATA ======================
attempt_counter = defaultdict(int)
severity_map = {}
geo_map = {}

# ============== GEO-IP (FEATURE 4) =======
def geo_lookup(ip):
    if ip.startswith("192.168"):
        return "Local Network"
    elif ip.startswith("10."):
        return "Private Network"
    else:
        return "Unknown"

# ============== LOGGING ===================
def log_attack(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def export_ids_alert(msg):
    with open(IDS_ALERTS, "a") as f:
        f.write(msg + "\n")

# ============== SEVERITY ==================
def classify_severity(ip):
    count = attempt_counter[ip]
    if count >= BLOCK_THRESHOLD:
        sev = "HIGH"
    elif count >= MEDIUM_THRESHOLD:
        sev = "MEDIUM"
    else:
        sev = "LOW"
    severity_map[ip] = sev
    return sev

# ============== INCIDENT REPORT ===========
def write_incident_report():
    with open(INCIDENT_REPORT, "w") as f:
        f.write("HONEYPOT INCIDENT REPORT\n")
        f.write("========================\n\n")
        for ip in severity_map:
            f.write(f"IP Address : {ip}\n")
            f.write(f"Country    : {geo_map.get(ip, 'Unknown')}\n")
            f.write(f"Attempts   : {attempt_counter[ip]}\n")
            f.write(f"Severity   : {severity_map[ip]}\n")
            f.write("----------------------------\n")

# ============== GRAPH (FEATURE 1) =========
def generate_graph():
    if not attempt_counter:
        return
    plt.bar(attempt_counter.keys(), attempt_counter.values())
    plt.title("Honeypot Attack Attempts per IP")
    plt.xlabel("IP Address")
    plt.ylabel("Attempts")
    plt.tight_layout()
    plt.savefig(GRAPH_FILE)
    plt.close()

# ============== FAKE COMMANDS (FEATURE 2) =
def fake_command_response(cmd):
    fake_fs = {
        "ls": "bin  etc  home  var\n",
        "whoami": "root\n",
        "pwd": "/root\n"
    }
    return fake_fs.get(cmd, "command not found\n")

# ============== FILE TRAP (FEATURE 5) =====
def setup_file_trap():
    if not os.path.exists(FILE_TRAP_DIR):
        os.makedirs(FILE_TRAP_DIR)
        with open(os.path.join(FILE_TRAP_DIR, "important.doc"), "w") as f:
            f.write("Sensitive File\n")

def monitor_file_trap():
    baseline = {
        f: os.path.getmtime(os.path.join(FILE_TRAP_DIR, f))
        for f in os.listdir(FILE_TRAP_DIR)
    }

    while True:
        time.sleep(3)
        for f in os.listdir(FILE_TRAP_DIR):
            path = os.path.join(FILE_TRAP_DIR, f)
            if os.path.getmtime(path) != baseline.get(f):
                alert = "[ALERT] FILE TAMPERING DETECTED (Possible Ransomware)"
                print(alert)
                log_attack(alert)
                export_ids_alert(alert)
                baseline[f] = os.path.getmtime(path)

# ============== CLIENT HANDLER ============
def handle_client(conn, addr):
    ip, port = addr
    attempt_counter[ip] += 1

    geo_map[ip] = geo_lookup(ip)
    severity = classify_severity(ip)

    base_log = f"{datetime.now()} | {ip}:{port} | Attempt {attempt_counter[ip]} | Severity={severity}"
    log_attack(base_log)

    if severity == "HIGH":
        export_ids_alert(f"[IDS ALERT] {base_log}")

    try:
        conn.sendall(b"Welcome to Secure Server v1.2\n")
        conn.sendall(b"Username: ")
        user = conn.recv(1024).decode(errors="ignore").strip()

        conn.sendall(b"Password: ")
        pwd = conn.recv(1024).decode(errors="ignore").strip()

        log_attack(f"{datetime.now()} | LOGIN FAIL | IP={ip} USER={user} PASS={pwd}")
        conn.sendall(b"Login failed\n")

        # Fake shell
        conn.sendall(b"$ ")
        cmd = conn.recv(1024).decode(errors="ignore").strip()
        conn.sendall(fake_command_response(cmd).encode())

        log_attack(f"{datetime.now()} | CMD | IP={ip} CMD={cmd}")

        if severity == "HIGH":
            conn.sendall(b"\n[!] Too many attempts detected. Logged.\n")
            time.sleep(3)

    except Exception as e:
        log_attack(f"Error: {e}")

    finally:
        write_incident_report()
        generate_graph()
        conn.close()

# ============== DASHBOARD FRONTEND ========
CSS_CONTENT = """
:root {
    --bg-dark: #0f172a; --bg-panel: #1e293b; --bg-panel-hover: #334155;
    --text-primary: #f8fafc; --text-secondary: #94a3b8;
    --accent-blue: #3b82f6; --accent-blue-hover: #60a5fa;
    --accent-red: #ef4444; --accent-red-hover: #f87171;
    --accent-orange: #f59e0b; --accent-green: #10b981;
    --border-color: rgba(255,255,255,0.1);
    --glass-bg: rgba(30, 41, 59, 0.7); --glass-border: rgba(255, 255, 255, 0.1);
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
body { background-color: var(--bg-dark); color: var(--text-primary); display: flex; height: 100vh; overflow: hidden; }
.sidebar { width: 250px; background-color: var(--bg-panel); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; padding: 20px 0; transition: all 0.3s ease; }
.logo { display: flex; align-items: center; gap: 15px; padding: 0 25px 30px; font-size: 1.5rem; font-weight: 700; color: var(--accent-blue); border-bottom: 1px solid var(--border-color); margin-bottom: 20px; }
.nav-links { list-style: none; }
.nav-links li { padding: 10px 25px; margin: 5px 15px; border-radius: 8px; transition: all 0.2s ease; }
.nav-links li a { color: var(--text-secondary); text-decoration: none; display: flex; align-items: center; gap: 15px; font-weight: 600; transition: color 0.2s ease; }
.nav-links li:hover { background-color: var(--bg-panel-hover); } .nav-links li:hover a { color: var(--text-primary); }
.nav-links li.active { background-color: rgba(59, 130, 246, 0.15); border-left: 4px solid var(--accent-blue); } .nav-links li.active a { color: var(--accent-blue); }
.dashboard { flex-grow: 1; display: flex; flex-direction: column; overflow-y: auto; padding: 30px; }
header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
h1 { font-size: 1.8rem; font-weight: 700; letter-spacing: -0.5px; }
.status-indicator { display: flex; align-items: center; gap: 10px; background: var(--glass-bg); padding: 8px 16px; border-radius: 20px; border: 1px solid var(--glass-border); backdrop-filter: blur(10px); font-size: 0.9rem; font-weight: 600; color: var(--accent-green); }
.dot { width: 10px; height: 10px; background-color: var(--accent-green); border-radius: 50%; display: inline-block; }
.pulse { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); animation: pulse 2s infinite; }
@keyframes pulse { 0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); } 70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); } 100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); } }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
.stat-card { background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; display: flex; align-items: center; gap: 20px; transition: transform 0.2s ease, box-shadow 0.2s ease; }
.stat-card:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
.stat-icon { font-size: 2rem; color: var(--accent-blue); background: rgba(59, 130, 246, 0.1); width: 60px; height: 60px; border-radius: 12px; display: flex; align-items: center; justify-content: center; }
.stat-info h3 { font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 5px; font-weight: 600; } .stat-info p { font-size: 1.8rem; font-weight: 700; }
.stat-card.danger .stat-icon { color: var(--accent-red); background: rgba(239, 68, 68, 0.1); } .stat-card.danger .stat-info p { color: var(--accent-red-hover); }
.stat-card.warning .stat-icon { color: var(--accent-orange); background: rgba(245, 158, 11, 0.1); } .stat-card.warning .stat-info p { color: var(--accent-orange); }
.main-content { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; flex-grow: 1; } .content-left { display: flex; flex-direction: column; gap: 20px; }
.panel { background: var(--bg-panel); border: 1px solid var(--border-color); border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; }
.panel-header { padding: 15px 20px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.1); }
.panel-header h2 { font-size: 1.1rem; font-weight: 600; display: flex; align-items: center; gap: 10px; } .panel-body { padding: 20px; flex-grow: 1; overflow-y: auto; }
.icon-btn { background: none; border: none; color: var(--text-secondary); cursor: pointer; font-size: 1.1rem; transition: color 0.2s; } .icon-btn:hover { color: var(--text-primary); }
.graph-panel { flex: 1; min-height: 350px; } .graph-panel .panel-body { display: flex; align-items: center; justify-content: center; background: #ffffff; padding: 0; }
#attack-graph { max-width: 100%; max-height: 100%; object-fit: contain; }
.report-panel { flex: 1; min-height: 250px; } .table-container { padding: 0 !important; }
.data-table { width: 100%; border-collapse: collapse; text-align: left; } .data-table th, .data-table td { padding: 12px 20px; border-bottom: 1px solid var(--border-color); }
.data-table th { background: var(--bg-panel-hover); font-weight: 600; color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
.data-table tbody tr:hover { background: rgba(255,255,255,0.02); }
.badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }
.badge-high { background: rgba(239, 68, 68, 0.2); color: var(--accent-red-hover); }
.badge-medium { background: rgba(245, 158, 11, 0.2); color: var(--accent-orange); }
.badge-low { background: rgba(59, 130, 246, 0.2); color: var(--accent-blue-hover); }
.terminal-panel { height: 100%; } .terminal-body { background: #000; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; line-height: 1.5; overflow-y: auto; padding: 15px; display: flex; flex-direction: column; gap: 5px; }
.log-entry { margin-bottom: 4px; word-break: break-all; } .log-time { color: var(--text-secondary); margin-right: 10px; }
.log-ip { color: var(--accent-blue-hover); font-weight: 700; } .log-alert { color: var(--accent-red-hover); font-weight: 700; }
.log-cmd { color: var(--accent-green); } .log-misc { color: var(--text-primary); }
.filters .filter-btn { background: none; border: 1px solid var(--border-color); color: var(--text-secondary); padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; cursor: pointer; transition: all 0.2s; }
.filters .filter-btn.active { background: var(--border-color); color: var(--text-primary); }
.danger-text { color: var(--accent-red) !important; border-color: rgba(239, 68, 68, 0.3) !important; } .filters .filter-btn.danger-text.active { background: rgba(239, 68, 68, 0.2) !important; }
::-webkit-scrollbar { width: 8px; height: 8px; } ::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--bg-panel-hover); border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #475569; }
@media (max-width: 1024px) { .main-content { grid-template-columns: 1fr; } .content-left { height: auto; } .terminal-panel { min-height: 400px; mt: 20px; } }
"""

JS_CONTENT = r"""
document.addEventListener('DOMContentLoaded', () => { refreshData(); setInterval(refreshData, 5000); });
let currentLogFilter = 'all';
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
        currentLogFilter = e.target.dataset.filter;
        fetchLogs();
    });
});
async function refreshData() { await Promise.all([ fetchStats(), fetchReport(), fetchLogs(), fetchGraph() ]); }
async function fetchStats() {
    try {
        const response = await fetch('/api/stats'); const data = await response.json();
        animateValue('total-attacks', parseInt(document.getElementById('total-attacks').innerText), data.total_attacks, 500);
        animateValue('unique-ips', parseInt(document.getElementById('unique-ips').innerText), data.unique_ips, 500);
        animateValue('high-severity', parseInt(document.getElementById('high-severity').innerText), data.severity.high, 500);
        animateValue('medium-severity', parseInt(document.getElementById('medium-severity').innerText), data.severity.medium, 500);
    } catch (error) { console.error("Error fetching stats:", error); }
}
async function fetchReport() {
    try {
        const response = await fetch('/api/report'); const data = await response.json();
        const tbody = document.getElementById('report-table-body');
        tbody.innerHTML = '';
        data.forEach(item => {
            const tr = document.createElement('tr');
            let badgeClass = 'badge-low';
            if (item.Severity === 'HIGH') badgeClass = 'badge-high';
            else if (item.Severity === 'MEDIUM') badgeClass = 'badge-medium';
            tr.innerHTML = `<td><strong>${item['IP Address']}</strong></td><td>${item.Country}</td><td>${item.Attempts}</td><td><span class="badge ${badgeClass}">${item.Severity}</span></td>`;
            tbody.appendChild(tr);
        });
    } catch (error) { console.error("Error fetching report:", error); }
}
async function fetchLogs() {
    try {
        const response = await fetch('/api/logs'); const data = await response.json();
        const terminal = document.getElementById('log-terminal');
        const isScrolledToBottom = terminal.scrollHeight - terminal.clientHeight <= terminal.scrollTop + 1;
        terminal.innerHTML = '';
        let logsToRender = (currentLogFilter === 'all') ? data.honeypot_logs : data.ids_alerts;
        logsToRender.forEach(log => {
            const div = document.createElement('div'); div.className = 'log-entry'; div.innerHTML = formatLog(log); terminal.appendChild(div);
        });
        if (isScrolledToBottom) { terminal.scrollTop = terminal.scrollHeight; }
    } catch (error) { console.error("Error fetching logs:", error); }
}
function formatLog(logLine) {
    let isAlert = logLine.includes('[IDS ALERT]') || logLine.includes('ALERT');
    let colorized = logLine.replace(/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?)/g, '<span class="log-ip">$1</span>');
    if (isAlert) { return `<span class="log-alert">${colorized}</span>`; }
    else if (logLine.includes('CMD=')) {
        colorized = colorized.replace(/(CMD=.*)/, '<span class="log-cmd">$1</span>');
        return `<span class="log-misc">${colorized}</span>`;
    } else { return `<span class="log-misc">${colorized}</span>`; }
}
async function fetchGraph() { const img = document.getElementById('attack-graph'); img.src = '/api/graph?' + new Date().getTime(); }
function animateValue(id, start, end, duration) {
    if (isNaN(start)) start = 0;
    if (start === end) { document.getElementById(id).innerText = end; return; }
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        document.getElementById(id).innerText = Math.floor(progress * (end - start) + start);
        if (progress < 1) { window.requestAnimationFrame(step); }
        else { document.getElementById(id).innerText = end; }
    };
    window.requestAnimationFrame(step);
}
"""

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>{{ css_content|safe }}</style>
</head>
<body class="dark-theme">
    <nav class="sidebar">
        <div class="logo"><i class="fa-solid fa-shield-halved"></i><span>AuraSec</span></div>
        <ul class="nav-links">
            <li class="active"><a href="#"><i class="fa-solid fa-chart-line"></i> Dashboard</a></li>
            <li><a href="#"><i class="fa-solid fa-list-check"></i> Incident Reports</a></li>
            <li><a href="#"><i class="fa-solid fa-terminal"></i> Live Logs</a></li>
            <li><a href="#"><i class="fa-solid fa-gear"></i> Settings</a></li>
        </ul>
    </nav>
    <main class="dashboard">
        <header>
            <h1>Security Operations Center (SOC)</h1>
            <div class="status-indicator"><span class="dot pulse"></span><span>Honeypot Active</span></div>
        </header>
        <section class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon"><i class="fa-solid fa-skull-crossbones"></i></div>
                <div class="stat-info"><h3>Total Attacks</h3><p id="total-attacks">0</p></div>
            </div>
            <div class="stat-card">
                <div class="stat-icon"><i class="fa-solid fa-network-wired"></i></div>
                <div class="stat-info"><h3>Unique IPs</h3><p id="unique-ips">0</p></div>
            </div>
            <div class="stat-card danger">
                <div class="stat-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
                <div class="stat-info"><h3>High Severity</h3><p id="high-severity">0</p></div>
            </div>
            <div class="stat-card warning">
                <div class="stat-icon"><i class="fa-solid fa-circle-exclamation"></i></div>
                <div class="stat-info"><h3>Medium Severity</h3><p id="medium-severity">0</p></div>
            </div>
        </section>
        <section class="main-content">
            <div class="content-left">
                <div class="panel graph-panel">
                    <div class="panel-header"><h2><i class="fa-solid fa-chart-bar"></i> Attack Distribution</h2><button class="icon-btn" onclick="refreshData()"><i class="fa-solid fa-rotate-right"></i></button></div>
                    <div class="panel-body"><img id="attack-graph" src="/api/graph" alt="Attack Graph"></div>
                </div>
                <div class="panel report-panel">
                    <div class="panel-header"><h2><i class="fa-solid fa-file-contract"></i> Incident Report</h2></div>
                    <div class="panel-body table-container">
                        <table class="data-table">
                            <thead><tr><th>IP Address</th><th>Country</th><th>Attempts</th><th>Severity</th></tr></thead>
                            <tbody id="report-table-body"></tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="content-right">
                <div class="panel terminal-panel">
                    <div class="panel-header"><h2><i class="fa-solid fa-terminal"></i> Live Terminal</h2><div class="filters"><button class="filter-btn active" data-filter="all">All</button><button class="filter-btn danger-text" data-filter="alert">Alerts</button></div></div>
                    <div class="panel-body terminal-body" id="log-terminal"></div>
                </div>
            </div>
        </section>
    </main>
    <script>{{ js_content|safe }}</script>
</body>
</html>
"""

# ======== FLASK APP ========
app = Flask(__name__)

def read_tail(filename, num_lines=50):
    if not os.path.exists(filename):
        return []
    with open(filename, 'r') as f:
        lines = f.readlines()
        return [line.strip() for line in lines[-num_lines:]]

@app.route('/')
def index():
    return render_template_string(HTML_CONTENT, css_content=CSS_CONTENT, js_content=JS_CONTENT)

@app.route('/api/stats')
def get_stats():
    total_attacks = 0
    unique_ips = 0
    high_sev = 0
    med_sev = 0
    low_sev = 0
    
    if os.path.exists(INCIDENT_REPORT):
        with open(INCIDENT_REPORT, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith("IP Address"):
                    unique_ips += 1
                elif line.startswith("Attempts"):
                    try:
                        total_attacks += int(line.split(":")[1].strip())
                    except:
                        pass
                elif line.startswith("Severity"):
                    sev = line.split(":")[1].strip()
                    if sev == "HIGH":
                        high_sev += 1
                    elif sev == "MEDIUM":
                        med_sev += 1
                    elif sev == "LOW":
                        low_sev += 1

    return jsonify({
        "total_attacks": total_attacks,
        "unique_ips": unique_ips,
        "severity": { "high": high_sev, "medium": med_sev, "low": low_sev }
    })

@app.route('/api/logs')
def get_logs():
    return jsonify({
        "honeypot_logs": read_tail(LOG_FILE, 100),
        "ids_alerts": read_tail(IDS_ALERTS, 50)
    })

@app.route('/api/report')
def get_report():
    report_data = []
    if os.path.exists(INCIDENT_REPORT):
        with open(INCIDENT_REPORT, 'r') as f:
            content = f.read()
            blocks = content.split("----------------------------")
            for block in blocks:
                if "IP Address" in block:
                    entry = {}
                    # Note split on newline character literal logic:
                    for line in block.strip().split('\n'):
                        if ":" in line:
                            key, val = line.split(":", 1)
                            entry[key.strip()] = val.strip()
                    if entry:
                        report_data.append(entry)
                        
    return jsonify(report_data)

@app.route('/api/graph')
def get_graph():
    if os.path.exists(GRAPH_FILE):
        return send_file(GRAPH_FILE, mimetype='image/png')
    else:
        return "Graph not found", 404

def start_flask():
    app.run(debug=False, port=5000, host="0.0.0.0", use_reloader=False)

# ============== MAIN SERVER ====================
def start_honeypot():
    setup_file_trap()
    threading.Thread(target=monitor_file_trap, daemon=True).start()
    
    # Start the Dashboard concurrently
    threading.Thread(target=start_flask, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allows address reuse so we don't get "Address already in use" quickly testing it
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[+] Honeypot running on {HOST}:{PORT}")
    print(f"[+] Dashboard running on http://127.0.0.1:5000")

    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[!] Shutting down...")
            break

# ============== MAIN ENTRY ====================
if __name__ == "__main__":
    start_honeypot()
