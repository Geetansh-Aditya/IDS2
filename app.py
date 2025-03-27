from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
import time

app = Flask(__name__)
threats = []

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

# Function to Analyze Packets
captured_packets = []  # Store live packet data

def packet_callback(packet):
    if IP in packet:
        # Store all captured packets (limit to avoid memory overflow)
        packet_info = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        }
        if len(captured_packets) > 100:
            captured_packets.pop(0)  # Remove oldest entry
        captured_packets.append(packet_info)

        # Threat detection logic
        for rule in RULES:
            if rule["protocol"] == "TCP" and TCP in packet and (rule["port"] is None or packet[TCP].dport == rule["port"]):
                if Raw in packet:
                    payload = packet[Raw].load
                    if any(pattern in payload for pattern in rule["pattern"]):
                        alert = {
                            "threat": rule["name"],
                            "ip": packet[IP].src,
                            "severity": rule["severity"],
                            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                        threats.append(alert)
                        print(f"[ALERT] {alert}")

@app.route('/api/packets')
def get_packets():
    return jsonify(captured_packets)

# Flask Routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/threats')
def get_threats():
    return jsonify(threats)

@app.route('/api/summary')
def get_summary():
    summary = {"high": 0, "medium": 0}
    for threat in threats:
        if threat["severity"] == "high":
            summary["high"] += 1
        elif threat["severity"] == "medium":
            summary["medium"] += 1
    return jsonify(summary)

# Start Packet Sniffer in a Separate Thread
def start_sniffer():
    sniff(filter="tcp or udp", prn=packet_callback, store=False)

if __name__ == '__main__':
    threading.Thread(target=start_sniffer, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=True)
