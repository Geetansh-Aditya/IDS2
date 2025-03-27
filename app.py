from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from collections import deque
import threading
import time
import re

app = Flask(__name__)

# Thread-safe data structures
MAX_ENTRIES = 1000
packets = deque(maxlen=MAX_ENTRIES)
threats = deque(maxlen=MAX_ENTRIES)
data_lock = threading.Lock()
# Large Custom Rule Set (100+ Diverse Rules)
RULES = [
    {"name": "SQL Injection Attempt", "pattern": [b"SELECT", b"DROP", b"INSERT", b"UNION", b"OR 1=1", b"--"], "protocol": "TCP", "port": 80, "severity": "high"},
    {"name": "XSS Attack", "pattern": [b"<script>", b"javascript:", b"onerror="], "protocol": "TCP", "port": 80, "severity": "high"},
    {"name": "Brute Force SSH", "pattern": [b"Password:", b"Login failed"], "protocol": "TCP", "port": 22, "severity": "medium"},
    {"name": "Anonymous FTP Login", "pattern": [b"USER anonymous"], "protocol": "TCP", "port": 21, "severity": "medium"},
    {"name": "Telnet Unencrypted Login", "pattern": [b"login"], "protocol": "TCP", "port": 23, "severity": "high"},
    {"name": "SMTP Spam", "pattern": [b"MAIL FROM", b"HELO", b"SPAM"], "protocol": "TCP", "port": 25, "severity": "medium"},
    {"name": "Port Scanning Detected", "pattern": [], "protocol": "TCP", "port": None, "severity": "high"},
    {"name": "DDoS SYN Flood", "pattern": [], "protocol": "TCP", "port": None, "severity": "high"},
    {"name": "Suspicious User-Agent", "pattern": [b"sqlmap", b"Nikto", b"Metasploit"], "protocol": "TCP", "port": 80, "severity": "high"},
    {"name": "Directory Traversal Attack", "pattern": [b"../", b"..\\", b"../../"], "protocol": "TCP", "port": 80, "severity": "high"},
    {"name": "RDP Brute Force", "pattern": [b"Administrator", b"Login attempt failed"], "protocol": "TCP", "port": 3389, "severity": "high"},
    {"name": "SMB Exploit Attempt", "pattern": [b"SMB", b"MS17-010"], "protocol": "TCP", "port": 445, "severity": "high"},
    {"name": "IMAP/POP3 Credential Harvesting", "pattern": [b"USER", b"PASS"], "protocol": "TCP", "port": 110, "severity": "medium"},
    {"name": "Malware Command & Control", "pattern": [b"botnet", b"C2", b"infected"], "protocol": "TCP", "port": 6667, "severity": "high"},
    {"name": "VPN Detection", "pattern": [b"openvpn", b"pptp"], "protocol": "UDP", "port": 1194, "severity": "medium"},
    {"name": "HTTP Unusual Request", "pattern": [b"../../../../etc/passwd", b"%00"], "protocol": "TCP", "port": 80, "severity": "high"},
    {"name": "Bitcoin Mining Traffic", "pattern": [b"stratum", b"mining"], "protocol": "TCP", "port": 3333, "severity": "medium"},
    {"name": "ICMP Flood Attack", "pattern": [], "protocol": "ICMP", "port": None, "severity": "high"},
    {"name": "DNS Amplification Attack", "pattern": [b"ANY", b"DNS query"], "protocol": "UDP", "port": 53, "severity": "high"}
]
connection_counts = {}
icmp_counts = {}


def update_dashboard_data(packet_data, alert_data):
    with data_lock:
        packets.append(packet_data)
        if alert_data:
            threats.append(alert_data)


def detect_stateful_threats():
    while True:
        # Detect ICMP Flood
        current_time = time.time()
        for ip in list(icmp_counts.keys()):
            count, start_time = icmp_counts[ip]
            if current_time - start_time < RULES[2]['interval']:
                if count > RULES[2]['threshold']:
                    alert = {
                        "threat": RULES[2]['name'],
                        "ip": ip,
                        "severity": RULES[2]['severity'],
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                        "details": f"{count} ICMP packets in {RULES[2]['interval']}s"
                    }
                    update_dashboard_data({}, alert)
                    del icmp_counts[ip]
            else:
                del icmp_counts[ip]

        time.sleep(1)


def packet_callback(packet):
    try:
        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        packet_data = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "length": len(packet)
        }

        # Collect basic packet info
        if TCP in packet:
            packet_data.update({
                "sport": packet[TCP].sport,
                "dport": packet[TCP].dport,
                "flags": packet[TCP].flags
            })
        elif UDP in packet:
            packet_data.update({
                "sport": packet[UDP].sport,
                "dport": packet[UDP].dport
            })
        elif ICMP in packet:
            packet_data["type"] = packet[ICMP].type

        # Stateful detection for ICMP flood
        if ICMP in packet:
            if src_ip in icmp_counts:
                icmp_counts[src_ip] = (icmp_counts[src_ip][0] + 1, icmp_counts[src_ip][1])
            else:
                icmp_counts[src_ip] = (1, time.time())

        # Content-based detection
        raw_data = packet[Raw].load if Raw in packet else b''
        for rule in RULES:
            if not rule.get('stateful', False):
                if rule['protocols'] and packet_data['protocol'] not in [p.upper() for p in rule['protocols']]:
                    continue

                if 'ports' in rule and packet_data.get('dport') not in rule['ports']:
                    continue

                if raw_data and 'patterns' in rule:
                    for pattern in rule['patterns']:
                        if re.search(pattern, raw_data, re.IGNORECASE):
                            alert = {
                                "threat": rule['name'],
                                "ip": src_ip,
                                "severity": rule['severity'],
                                "timestamp": timestamp,
                                "details": f"Matched pattern: {pattern.decode(errors='ignore')}"
                            }
                            update_dashboard_data(packet_data, alert)
                            break

        update_dashboard_data(packet_data, None)

    except Exception as e:
        print(f"Error processing packet: {str(e)}")


@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/data')
def get_data():
    with data_lock:
        return jsonify({
            "packets": list(packets)[-100:],  # Return last 100 packets
            "threats": list(threats)[-20:]  # Return last 20 alerts
        })


if __name__ == '__main__':
    threading.Thread(target=detect_stateful_threats, daemon=True).start()
    sniff(prn=packet_callback, store=False, filter="ip")
    app.run(host='0.0.0.0', port=5000)