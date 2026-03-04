import socket
import threading
import time
import os
import logging
from datetime import datetime
from collections import defaultdict
from flask import Flask, jsonify, send_file, render_template_string

# Set werkzeug logger to ERROR to reduce spam in the console
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ================= CONFIG =================
HOST = "0.0.0.0"
PORT_SSH   = 2223
PORT_TELNET = 2323
PORT_FTP   = 2121

BLOCK_THRESHOLD = 5
MEDIUM_THRESHOLD = 3

LOG_FILE = "honeypot.log"
INCIDENT_REPORT = "incident_report.txt"
IDS_ALERTS = "ids_alerts.txt"
FILE_TRAP_DIR = "file_trap"

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
# Static graph generation removed in favor of live Chart.js component


# ============== ADVANCED VIRTUAL SHELL ====
FAKE_FS = {
    "/": ["bin", "boot", "etc", "home", "root", "tmp", "var", "usr"],
    "/root": [".bash_history", ".ssh", "secret.txt"],
    "/etc": ["passwd", "shadow", "hostname", "ssh"],
    "/etc/ssh": ["sshd_config", "ssh_host_rsa_key"],
    "/home": ["admin", "user"],
    "/home/admin": [".bash_history", "notes.txt"],
    "/home/user": [".bash_history"],
    "/tmp": [],
    "/var": ["log", "www"],
    "/var/log": ["syslog", "auth.log"],
    "/var/www": ["html"],
    "/usr": ["bin", "local", "share"],
}

FAKE_FILE_CONTENTS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n",
    "/etc/hostname": "ubuntu-server\n",
    "/root/secret.txt": "db_password=Sup3rS3cr3t!\napi_key=sk-1234567890abcdef\n",
    "/home/admin/notes.txt": "TODO: change passwords\n",
    "/etc/shadow": r"root:$6$randomsalt$hashedpassword:18000:0:99999:7:::" + "\n",

}

class VirtualShell:
    def __init__(self, ip):
        self.ip = ip
        self.cwd = "/root"

    def get_prompt(self):
        user = "root" if self.cwd.startswith("/root") else "admin"
        return f"{user}@ubuntu-server:{self.cwd}# ".encode()

    def execute(self, raw_cmd):
        """Execute a command and return (output_str, log_note)."""
        parts = raw_cmd.strip().split()
        if not parts:
            return "", None
        cmd = parts[0]
        args = parts[1:]

        if cmd == "pwd":
            return self.cwd + "\n", None

        elif cmd == "whoami":
            return "root\n", None

        elif cmd == "uname":
            return "Linux ubuntu-server 5.15.0-78-generic #85-Ubuntu x86_64 GNU/Linux\n", None

        elif cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)\n", None

        elif cmd == "ls":
            path = args[0] if args else self.cwd
            if path and not path.startswith("/"):
                path = self.cwd.rstrip("/") + "/" + path
            contents = FAKE_FS.get(path)
            if contents is None:
                return f"ls: cannot access '{path}': No such file or directory\n", None
            return "  ".join(contents) + "\n" if contents else "\n", None

        elif cmd == "cd":
            target = args[0] if args else "/root"
            if target == "..":
                parent = "/".join(self.cwd.rstrip("/").split("/")[:-1])
                target = parent if parent else "/"
            elif not target.startswith("/"):
                target = self.cwd.rstrip("/") + "/" + target
            # Normalize double slashes
            target = target.replace("//", "/")
            if target in FAKE_FS:
                self.cwd = target
                return "", None
            else:
                return f"bash: cd: {target}: No such file or directory\n", None

        elif cmd == "cat":
            if not args:
                return "cat: missing operand\n", None
            path = args[0] if args[0].startswith("/") else self.cwd.rstrip("/") + "/" + args[0]
            content = FAKE_FILE_CONTENTS.get(path)
            if content:
                return content, f"READ SENSITIVE FILE {path}"
            return f"cat: {args[0]}: No such file or directory\n", None

        elif cmd in ("wget", "curl"):
            url = args[0] if args else "<unknown>"
            note = f"[PAYLOAD CAPTURE] {cmd.upper()} ATTEMPT | URL={url}"
            return f"Connecting to {url}... connected.\nHTTP request sent, awaiting response... 200 OK\n", note

        elif cmd == "exit":
            return "logout\n", "SESSION_END"

        elif cmd == "history":
            return "    1  ls\n    2  cd /etc\n    3  cat passwd\n", None

        elif cmd == "ifconfig" or cmd == "ip":
            return "eth0: inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n", None

        else:
            return f"bash: {cmd}: command not found\n", None

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

# ============== SSH CLIENT HANDLER ============
def handle_client(conn, addr):
    ip, port = addr
    attempt_counter[ip] += 1
    geo_map[ip] = geo_lookup(ip)
    severity = classify_severity(ip)

    base_log = f"{datetime.now()} | SSH | {ip}:{port} | Attempt {attempt_counter[ip]} | Severity={severity}"
    log_attack(base_log)
    if severity == "HIGH":
        export_ids_alert(f"[IDS ALERT] {base_log}")

    try:
        conn.sendall(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)\r\n\r\n")
        conn.sendall(b"login: ")
        user = conn.recv(1024).decode(errors="ignore").strip()
        conn.sendall(b"Password: ")
        pwd = conn.recv(1024).decode(errors="ignore").strip()

        log_attack(f"{datetime.now()} | SSH | LOGIN | IP={ip} USER={user} PASS={pwd}")
        conn.sendall(b"\r\nLast login: Mon Mar  4 09:12:44 2026 from 10.0.0.1\r\n")

        # Advanced interactive shell loop
        shell = VirtualShell(ip)
        conn.sendall(shell.get_prompt())

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                cmd_str = data.decode(errors="ignore").strip()
                out, note = shell.execute(cmd_str)
                if note:
                    log_attack(f"{datetime.now()} | SSH | CMD | IP={ip} CMD={cmd_str} NOTE={note}")
                    if "PAYLOAD" in note:
                        export_ids_alert(f"[IDS ALERT] {note} from IP={ip}")
                else:
                    log_attack(f"{datetime.now()} | SSH | CMD | IP={ip} CMD={cmd_str}")
                conn.sendall(out.encode())
                if note == "SESSION_END":
                    break
                conn.sendall(shell.get_prompt())
            except Exception:
                break

        if severity == "HIGH":
            conn.sendall(b"\r\n[!] Too many attempts detected. Connection logged.\r\n")

    except Exception as e:
        log_attack(f"Error: {e}")
    finally:
        write_incident_report()
        generate_graph()
        conn.close()

# ============== TELNET CLIENT HANDLER =========
def handle_telnet_client(conn, addr):
    ip, port = addr
    attempt_counter[ip] += 1
    geo_map[ip] = geo_lookup(ip)
    severity = classify_severity(ip)

    base_log = f"{datetime.now()} | TELNET | {ip}:{port} | Attempt {attempt_counter[ip]} | Severity={severity}"
    log_attack(base_log)
    if severity == "HIGH":
        export_ids_alert(f"[IDS ALERT] {base_log}")

    try:
        # Telnet negotiation bytes (will suppress option negotiation from client)
        conn.sendall(bytes([255, 251, 3, 255, 251, 1]))  # IAC WILL SGA, IAC WILL ECHO
        conn.sendall(b"\r\nUbuntu 22.04 LTS\r\nubuntu-server login: ")
        user = conn.recv(1024).decode(errors="ignore").strip()
        conn.sendall(b"Password: ")
        pwd = conn.recv(1024).decode(errors="ignore").strip()

        log_attack(f"{datetime.now()} | TELNET | LOGIN | IP={ip} USER={user} PASS={pwd}")
        conn.sendall(b"\r\nWelcome to Ubuntu 22.04.3 LTS!\r\n")

        shell = VirtualShell(ip)
        conn.sendall(shell.get_prompt())

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                cmd_str = data.decode(errors="ignore").strip()
                out, note = shell.execute(cmd_str)
                if note:
                    log_attack(f"{datetime.now()} | TELNET | CMD | IP={ip} CMD={cmd_str} NOTE={note}")
                    if "PAYLOAD" in note:
                        export_ids_alert(f"[IDS ALERT] {note} from IP={ip}")
                else:
                    log_attack(f"{datetime.now()} | TELNET | CMD | IP={ip} CMD={cmd_str}")
                conn.sendall(out.encode())
                if note == "SESSION_END":
                    break
                conn.sendall(shell.get_prompt())
            except Exception:
                break

    except Exception as e:
        log_attack(f"Telnet Error: {e}")
    finally:
        write_incident_report()
        conn.close()

# ============== FTP CLIENT HANDLER ============
def handle_ftp_client(conn, addr):
    ip, port = addr
    attempt_counter[ip] += 1
    geo_map[ip] = geo_lookup(ip)
    severity = classify_severity(ip)

    base_log = f"{datetime.now()} | FTP | {ip}:{port} | Attempt {attempt_counter[ip]} | Severity={severity}"
    log_attack(base_log)
    if severity == "HIGH":
        export_ids_alert(f"[IDS ALERT] {base_log}")

    try:
        conn.sendall(b"220 ProFTPD 1.3.5 Server (ubuntu-ftp) ready.\r\n")
        user = ""
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                line = data.decode(errors="ignore").strip()
                cmd = line.split()[0].upper() if line.split() else ""
                arg = line[len(cmd):].strip() if cmd else ""

                if cmd == "USER":
                    user = arg
                    conn.sendall(f"331 Password required for {user}.\r\n".encode())
                elif cmd == "PASS":
                    log_attack(f"{datetime.now()} | FTP | LOGIN | IP={ip} USER={user} PASS={arg}")
                    conn.sendall(b"530 Login incorrect.\r\n")
                    break
                elif cmd == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                elif cmd == "SYST":
                    conn.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd == "FEAT":
                    conn.sendall(b"211-Features:\r\n UTF8\r\n211 End\r\n")
                else:
                    conn.sendall(b"530 Please login with USER and PASS.\r\n")
            except Exception:
                break

    except Exception as e:
        log_attack(f"FTP Error: {e}")
    finally:
        write_incident_report()
        conn.close()

# ============== PROTOCOL SERVERS ==============
def start_server(port, handler, label):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, port))
        server.listen(5)
        print(f"[+] {label} honeypot listening on {HOST}:{port}")
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handler, args=(conn, addr), daemon=True).start()
            except Exception:
                break
    except PermissionError:
        print(f"[!] Permission denied for port {port}. Run as Administrator to bind ports < 1024.")
    except Exception as e:
        print(f"[!] Error on {label} server: {e}")

# ============== DASHBOARD FRONTEND ========
CSS_CONTENT = """
:root {
    --bg-dark: #080f1f; --bg-panel: #0f1c35;
    --bg-panel-hover: #1a2d4a;
    --text-primary: #e2e8f0; --text-secondary: #64748b;
    --accent-blue: #38bdf8; --accent-blue-hover: #7dd3fc;
    --accent-red: #f43f5e; --accent-red-hover: #fb7185;
    --accent-orange: #f59e0b; --accent-green: #10b981;
    --accent-purple: #a78bfa; --accent-teal: #2dd4bf;
    --border-color: rgba(56, 189, 248, 0.1);
    --glass-bg: rgba(15, 28, 53, 0.75); --glass-border: rgba(56, 189, 248, 0.15);
    --neon-blue: 0 0 8px rgba(56, 189, 248, 0.4), 0 0 20px rgba(56, 189, 248, 0.15);
    --neon-red: 0 0 8px rgba(244, 63, 94, 0.5), 0 0 20px rgba(244, 63, 94, 0.2);
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
body { background: radial-gradient(ellipse at 20% 50%, #0a1628 0%, #080f1f 60%); color: var(--text-primary); display: flex; height: 100vh; overflow: hidden; }
.sidebar { width: 240px; background: var(--glass-bg); border-right: 1px solid var(--glass-border); display: flex; flex-direction: column; padding: 20px 0; backdrop-filter: blur(16px); }
.logo { display: flex; align-items: center; gap: 12px; padding: 0 20px 28px; font-size: 1.4rem; font-weight: 700; color: var(--accent-blue); border-bottom: 1px solid var(--glass-border); margin-bottom: 20px; text-shadow: var(--neon-blue); }
.logo i { font-size: 1.6rem; }
.nav-links { list-style: none; }
.nav-links li { padding: 10px 20px; margin: 4px 12px; border-radius: 8px; transition: all 0.2s ease; }
.nav-links li a { color: var(--text-secondary); text-decoration: none; display: flex; align-items: center; gap: 14px; font-size: 0.9rem; font-weight: 600; transition: color 0.2s ease; }
.nav-links li:hover { background: rgba(56, 189, 248, 0.07); } .nav-links li:hover a { color: var(--text-primary); }
.nav-links li.active { background: rgba(56, 189, 248, 0.12); border-left: 3px solid var(--accent-blue); box-shadow: inset var(--neon-blue); } .nav-links li.active a { color: var(--accent-blue); }
.dashboard { flex-grow: 1; display: flex; flex-direction: column; overflow-y: auto; padding: 28px; }
header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px; }
h1 { font-size: 1.6rem; font-weight: 700; letter-spacing: -0.5px; }
.status-indicator { display: flex; align-items: center; gap: 10px; background: var(--glass-bg); padding: 8px 16px; border-radius: 20px; border: 1px solid rgba(16,185,129,0.3); backdrop-filter: blur(10px); font-size: 0.85rem; font-weight: 600; color: var(--accent-green); box-shadow: 0 0 12px rgba(16,185,129,0.1); }
.dot { width: 9px; height: 9px; background-color: var(--accent-green); border-radius: 50%; display: inline-block; }
.pulse { animation: pulse 2s infinite; }
@keyframes pulse { 0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); } 70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); } 100% { transform: scale(0.95); } }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 12px; padding: 18px; display: flex; align-items: center; gap: 18px; transition: transform 0.2s ease, box-shadow 0.2s ease; backdrop-filter: blur(10px); }
.stat-card:hover { transform: translateY(-4px); box-shadow: var(--neon-blue); }
.stat-icon { font-size: 1.6rem; color: var(--accent-blue); background: rgba(56, 189, 248, 0.1); width: 52px; height: 52px; border-radius: 10px; display: flex; align-items: center; justify-content: center; border: 1px solid rgba(56,189,248,0.2); }
.stat-info h3 { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 4px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; } .stat-info p { font-size: 1.7rem; font-weight: 700; }
.stat-card.danger { border-color: rgba(244,63,94,0.2); } .stat-card.danger:hover { box-shadow: var(--neon-red); } .stat-card.danger .stat-icon { color: var(--accent-red); background: rgba(244, 63, 94, 0.1); border-color: rgba(244,63,94,0.2); } .stat-card.danger .stat-info p { color: var(--accent-red-hover); }
.stat-card.warning .stat-icon { color: var(--accent-orange); background: rgba(245, 158, 11, 0.1); } .stat-card.warning .stat-info p { color: var(--accent-orange); }
.header-actions { display: flex; align-items: center; gap: 12px; }
.clear-all-btn { display: flex; align-items: center; gap: 7px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.35); color: var(--accent-red-hover); padding: 7px 16px; border-radius: 20px; font-size: 0.82rem; font-weight: 600; cursor: pointer; transition: all 0.2s ease; }
.clear-all-btn:hover { background: rgba(244,63,94,0.25); box-shadow: 0 0 12px rgba(244,63,94,0.3); transform: translateY(-1px); }
.clear-all-btn i { font-size: 0.8rem; }
.main-content { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; flex-grow: 1; min-height: 0; } .content-left { display: flex; flex-direction: column; gap: 16px; min-height: 0; }
.panel { background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; backdrop-filter: blur(10px); }
.panel-header { padding: 13px 18px; border-bottom: 1px solid var(--glass-border); display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.15); flex-shrink: 0; }
.panel-header h2 { font-size: 1rem; font-weight: 600; display: flex; align-items: center; gap: 10px; color: var(--accent-blue-hover); } .panel-body { padding: 16px; flex-grow: 1; overflow-y: auto; min-height: 0; }
.icon-btn { background: none; border: 1px solid var(--glass-border); color: var(--text-secondary); cursor: pointer; font-size: 0.9rem; padding: 4px 8px; border-radius: 6px; transition: all 0.2s; } .icon-btn:hover { color: var(--accent-blue); border-color: var(--accent-blue); }
.graph-panel { flex: 0 0 300px; } .graph-panel .panel-body { display: flex; align-items: center; justify-content: center; background: #fff; padding: 0; }
#attack-graph { max-width: 100%; object-fit: contain; }
.report-panel { flex: 1; overflow: hidden; } .table-container { padding: 0 !important; overflow-y: auto; height: 100%; }
.data-table { width: 100%; border-collapse: collapse; text-align: left; } .data-table th, .data-table td { padding: 10px 16px; border-bottom: 1px solid var(--glass-border); white-space: nowrap; }
.data-table thead { position: sticky; top: 0; z-index: 1; } .data-table th { background: var(--bg-panel-hover); font-weight: 600; color: var(--text-secondary); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px; }
.data-table tbody tr { transition: background 0.15s; } .data-table tbody tr:hover { background: rgba(56,189,248,0.04); }
.badge { padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.3px; }
.badge-high { background: rgba(244, 63, 94, 0.2); color: var(--accent-red-hover); border: 1px solid rgba(244,63,94,0.3); }
.badge-medium { background: rgba(245, 158, 11, 0.15); color: var(--accent-orange); border: 1px solid rgba(245,158,11,0.3); }
.badge-low { background: rgba(56, 189, 248, 0.1); color: var(--accent-blue-hover); border: 1px solid rgba(56,189,248,0.2); }
.content-right { display: flex; flex-direction: column; gap: 16px; min-height: 0; }
.terminal-panel { flex: 1; min-height: 0; }
.terminal-body { background: #020810; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; line-height: 1.6; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 2px; height: 100%; border-radius: 0 0 12px 12px; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
.log-entry { animation: fadeIn 0.3s ease; word-break: break-all; }
.log-ip { color: var(--accent-blue-hover); font-weight: 700; }
.log-alert { color: var(--accent-red-hover); font-weight: 700; text-shadow: 0 0 6px rgba(244,63,94,0.5); }
.log-cmd { color: var(--accent-green); }
.log-misc { color: #4ade80; }
.log-ftp { color: var(--accent-purple); font-weight: 600; }
.log-telnet { color: var(--accent-teal); font-weight: 600; }
.log-ssh { color: var(--accent-blue-hover); font-weight: 600; }
.terminal-cursor { display: inline-block; width: 7px; height: 13px; background: #4ade80; margin-left: 2px; animation: blink 1s step-end infinite; vertical-align: middle; }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
.filters { display: flex; gap: 6px; align-items: center; }
.filter-btn { background: none; border: 1px solid var(--glass-border); color: var(--text-secondary); padding: 3px 9px; border-radius: 12px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s; }
.filter-btn.active { background: rgba(56,189,248,0.15); color: var(--accent-blue); border-color: rgba(56,189,248,0.3); }
.clear-btn { background: none; border: 1px solid rgba(100,116,139,0.3); color: var(--text-secondary); padding: 3px 9px; border-radius: 12px; font-size: 0.75rem; cursor: pointer; transition: all 0.2s; } .clear-btn:hover { color: var(--accent-red); border-color: var(--accent-red); }
.danger-text { color: var(--accent-red) !important; border-color: rgba(244, 63, 94, 0.3) !important; } .filter-btn.danger-text.active { background: rgba(244, 63, 94, 0.15) !important; color: var(--accent-red-hover) !important; }
.content-right { display: flex; flex-direction: column; gap: 16px; min-height: 0; overflow: hidden; }
.terminal-panel { display: flex; flex-direction: column; overflow: hidden; }
.terminal-wrap { position: relative; flex-grow: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
.terminal-body { background: #020810; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; line-height: 1.6; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 2px; max-height: 480px; border-radius: 0 0 12px 12px; }
.scroll-btn { position: absolute; bottom: 12px; right: 12px; width: 30px; height: 30px; border-radius: 50%; background: rgba(56,189,248,0.2); border: 1px solid rgba(56,189,248,0.4); color: var(--accent-blue); cursor: pointer; display: none; align-items: center; justify-content: center; font-size: 0.85rem; z-index: 10; transition: all 0.2s ease; box-shadow: 0 0 8px rgba(56,189,248,0.3); }
.scroll-btn:hover { background: rgba(56,189,248,0.35); transform: translateY(2px); }
.scroll-btn.visible { display: flex; }
.alerts-panel { flex: 0 0 auto; }
.alert-ticker { padding: 10px; display: flex; flex-direction: column; gap: 6px; max-height: 160px; overflow-y: auto; }
.alert-item { display: flex; align-items: flex-start; gap: 8px; padding: 8px 10px; background: rgba(244,63,94,0.07); border: 1px solid rgba(244,63,94,0.2); border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--accent-red-hover); animation: fadeIn 0.4s ease; word-break: break-all; }
.alert-item i { color: var(--accent-red); margin-top: 2px; flex-shrink: 0; }
.no-alerts { color: var(--text-secondary); font-size: 0.8rem; text-align: center; padding: 16px; }
::-webkit-scrollbar { width: 5px; height: 5px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: var(--bg-panel-hover); border-radius: 3px; }
@media (max-width: 1024px) { .main-content { grid-template-columns: 1fr; } .terminal-panel { min-height: 300px; } }
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
function clearAll() {
    if (!confirm('Clear all logs and reset the dashboard?')) return;
    fetch('/api/clear-logs', { method: 'POST' })
        .then(() => {
            // Reset terminal
            document.getElementById('log-terminal').innerHTML = '<span class="terminal-cursor"></span>';
            // Reset alerts panel
            document.getElementById('alerts-ticker').innerHTML = '<p class="no-alerts"><i class="fa-solid fa-shield-check"></i>&nbsp; No active alerts</p>';
            // Reset stat counters
            ['total-attacks','unique-ips','high-severity','medium-severity'].forEach(id => document.getElementById(id).innerText = '0');
            // Reset incident report table
            document.getElementById('report-table-body').innerHTML = '';
            // Reset graph instance
            if (attackChart) {
                attackChart.destroy();
                attackChart = null;
            }
        })
        .catch(err => console.error('Clear failed:', err));
}
// Keep clearTerminal as alias for the in-console eraser button
function clearTerminal() { clearAll(); }
function scrollTerminalToBottom() {
    const t = document.getElementById('log-terminal');
    t.scrollTop = t.scrollHeight;
}
document.addEventListener('DOMContentLoaded', () => {
    const terminal = document.getElementById('log-terminal');
    const scrollBtn = document.getElementById('scroll-btn');
    if (terminal && scrollBtn) {
        terminal.addEventListener('scroll', () => {
            const atBottom = terminal.scrollHeight - terminal.clientHeight <= terminal.scrollTop + 20;
            scrollBtn.classList.toggle('visible', !atBottom);
        });
    }
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
            tr.innerHTML = `<td><strong>${item['IP Address'] || ''}</strong></td><td>${item.Country || ''}</td><td>${item.Attempts || ''}</td><td><span class="badge ${badgeClass}">${item.Severity || ''}</span></td>`;
            tbody.appendChild(tr);
        });
    } catch (error) { console.error("Error fetching report:", error); }
}
async function fetchLogs() {
    try {
        const response = await fetch('/api/logs'); const data = await response.json();
        const terminal = document.getElementById('log-terminal');
        const isScrolledToBottom = terminal.scrollHeight - terminal.clientHeight <= terminal.scrollTop + 5;
        terminal.innerHTML = '';
        let logsToRender = (currentLogFilter === 'all') ? data.honeypot_logs : data.ids_alerts;
        logsToRender.forEach(log => {
            const div = document.createElement('div'); div.className = 'log-entry'; div.innerHTML = formatLog(log); terminal.appendChild(div);
        });
        const cursor = document.createElement('span'); cursor.className = 'terminal-cursor'; terminal.appendChild(cursor);
        if (isScrolledToBottom) { terminal.scrollTop = terminal.scrollHeight; }
        // Also update the alerts panel
        updateAlertsPanel(data.ids_alerts);
    } catch (error) { console.error("Error fetching logs:", error); }
}
function updateAlertsPanel(alerts) {
    const panel = document.getElementById('alerts-ticker');
    if (!panel) return;
    panel.innerHTML = '';
    if (!alerts || alerts.length === 0) { panel.innerHTML = '<p class="no-alerts"><i class="fa-solid fa-shield-check"></i>&nbsp; No active alerts</p>'; return; }
    alerts.slice(-5).reverse().forEach(alert => {
        const div = document.createElement('div'); div.className = 'alert-item';
        div.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i><span>${alert}</span>`;
        panel.appendChild(div);
    });
}
function getProtocolClass(logLine) {
    if (logLine.includes('| FTP |')) return 'log-ftp';
    if (logLine.includes('| TELNET |')) return 'log-telnet';
    if (logLine.includes('| SSH |')) return 'log-ssh';
    return '';
}
function formatLog(logLine) {
    let isAlert = logLine.includes('[IDS ALERT]') || logLine.includes('[ALERT]')|| logLine.includes('[PAYLOAD');
    let colorized = logLine.replace(/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?)/g, '<span class="log-ip">$1</span>');
    if (isAlert) { return `<span class="log-alert">${colorized}</span>`; }
    const protoClass = getProtocolClass(logLine);
    if (logLine.includes('CMD=')) {
        colorized = colorized.replace(/(CMD=\S+)/, '<span class="log-cmd">$1</span>');
    }
    if (logLine.includes('| SSH |')) colorized = colorized.replace('| SSH |', `| <span class="log-ssh">SSH</span> |`);
    else if (logLine.includes('| TELNET |')) colorized = colorized.replace('| TELNET |', `| <span class="log-telnet">TELNET</span> |`);
    else if (logLine.includes('| FTP |')) colorized = colorized.replace('| FTP |', `| <span class="log-ftp">FTP</span> |`);
    return `<span class="log-misc">${colorized}</span>`;
}
let attackChart = null;
async function fetchGraph() {
    try {
        const response = await fetch('/api/chart-data');
        const data = await response.json();
        const ctx = document.getElementById('attackChart');
        if (!ctx) return;
        
        if (attackChart) {
            attackChart.data.labels = data.labels;
            attackChart.data.datasets[0].data = data.values;
            attackChart.update();
        } else {
            attackChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.labels,
                    datasets: [{
                        label: 'Attack Attempts',
                        data: data.values,
                        backgroundColor: 'rgba(56, 189, 248, 0.8)',
                        borderColor: 'rgb(56, 189, 248)',
                        borderWidth: 1,
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 500, easing: 'easeOutQuart' },
                    plugins: {
                        legend: { display: false },
                        tooltip: { backgroundColor: 'rgba(2, 8, 16, 0.9)', titleColor: '#38bdf8' }
                    },
                    scales: {
                        y: { 
                            beginAtZero: true, 
                            grid: { color: 'rgba(100, 116, 139, 0.1)', borderDash: [5, 5] },
                            ticks: { color: 'rgba(148, 163, 184, 0.8)', stepSize: 1 }
                        },
                        x: { 
                            grid: { display: false },
                            ticks: { color: 'rgba(148, 163, 184, 0.8)' }
                        }
                    }
                }
            });
        }
    } catch (error) { console.error("Error fetching chart data:", error); }
}
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
    <title>AuraSec &mdash; Honeypot SOC Dashboard</title>
    <meta name="description" content="Real-time Security Operations Center dashboard for Honeypot attack monitoring.">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>{{ css_content|safe }}</style>
</head>
<body class="dark-theme">
    <nav class="sidebar">
        <div class="logo"><i class="fa-solid fa-shield-halved"></i><span>AuraSec</span></div>
        <ul class="nav-links">
            <li class="active"><a href="#"><i class="fa-solid fa-chart-line"></i> Dashboard</a></li>
            <li><a href="#"><i class="fa-solid fa-list-check"></i> Incidents</a></li>
            <li><a href="#"><i class="fa-solid fa-terminal"></i> Console</a></li>
            <li><a href="#"><i class="fa-solid fa-gear"></i> Settings</a></li>
        </ul>
    </nav>
    <main class="dashboard">
        <header>
            <h1><i class="fa-solid fa-radar" style="font-size:1.2rem;color:var(--accent-blue);margin-right:10px;"></i>Security Operations Center</h1>
            <div class="header-actions">
                <button class="clear-all-btn" onclick="clearAll()" title="Clear all logs and reset dashboard">
                    <i class="fa-solid fa-trash-can"></i> Clear All
                </button>
                <div class="status-indicator"><span class="dot pulse"></span><span>Honeypot Active</span></div>
            </div>
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
                    <div class="panel-header">
                        <h2><i class="fa-solid fa-chart-bar"></i> Attack Distribution</h2>
                        <div class="filters">
                            <button class="icon-btn" onclick="refreshData()" title="Refresh"><i class="fa-solid fa-rotate-right"></i> Refresh</button>
                            <button class="clear-btn" onclick="clearAll()" title="Clear Graph"><i class="fa-solid fa-eraser"></i></button>
                        </div>
                    </div>
                    <div class="panel-body" style="position: relative; height: 300px; padding: 10px;">
                        <canvas id="attackChart"></canvas>
                    </div>
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
                <div class="panel alerts-panel">
                    <div class="panel-header"><h2><i class="fa-solid fa-bell" style="color:var(--accent-red);"></i>&nbsp;High Alerts</h2></div>
                    <div class="alert-ticker" id="alerts-ticker"><p class="no-alerts"><i class="fa-solid fa-shield-check"></i>&nbsp; No active alerts</p></div>
                </div>
                <div class="panel terminal-panel">
                    <div class="panel-header">
                        <h2><i class="fa-solid fa-terminal"></i> Live Console</h2>
                        <div class="filters">
                            <button class="filter-btn active" data-filter="all">All</button>
                            <button class="filter-btn danger-text" data-filter="alert">Alerts</button>
                            <button class="clear-btn" onclick="clearTerminal()" title="Clear view"><i class="fa-solid fa-eraser"></i></button>
                        </div>
                    </div>
                    <div class="terminal-wrap">
                        <div class="panel-body terminal-body" id="log-terminal"><span class="terminal-cursor"></span></div>
                        <button class="scroll-btn" id="scroll-btn" onclick="scrollTerminalToBottom()" title="Scroll to bottom"><i class="fa-solid fa-angles-down"></i></button>
                    </div>
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

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    """Wipe all log files and reset the incident report."""
    for f in [LOG_FILE, IDS_ALERTS, INCIDENT_REPORT]:
        try:
            open(f, 'w').close()
        except Exception:
            pass
    return jsonify({"status": "cleared"})

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

@app.route('/api/chart-data')
def get_chart_data():
    """Returns JSON array of attack attempt frequencies for Chart.js"""
    labels = list(attempt_counter.keys())
    values = list(attempt_counter.values())
    return jsonify({
        "labels": labels,
        "values": values
    })

def start_flask():
    app.run(debug=False, port=5001, host="0.0.0.0", use_reloader=False)

# ============== MAIN SERVER ====================
def start_honeypot():
    setup_file_trap()
    threading.Thread(target=monitor_file_trap, daemon=True).start()

    # Start the web dashboard concurrently
    threading.Thread(target=start_flask, daemon=True).start()

    # Start Telnet and FTP honeypots in background threads
    threading.Thread(target=start_server, args=(PORT_TELNET, handle_telnet_client, "Telnet"), daemon=True).start()
    threading.Thread(target=start_server, args=(PORT_FTP, handle_ftp_client, "FTP"), daemon=True).start()

    # SSH honeypot runs in main thread
    print(f"[+] Dashboard running on http://127.0.0.1:5001")
    start_server(PORT_SSH, handle_client, "SSH")

# ============== MAIN ENTRY ====================
if __name__ == "__main__":
    try:
        start_honeypot()
    except KeyboardInterrupt:
        print("\n[!] Shutting down all honeypot services...")
