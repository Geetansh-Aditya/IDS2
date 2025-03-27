from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from collections import deque
import threading
import time
import re
from scapy.layers.inet import IP_PROTOS

app = Flask(__name__)

# Thread-safe data structures
MAX_ENTRIES = 1000
packets = deque(maxlen=MAX_ENTRIES)
threats = deque(maxlen=MAX_ENTRIES)
data_lock = threading.Lock()
# Large Custom Rule Set (100+ Diverse Rules)
RULES = [
    # SQL Injection (10 rules)
    {"name": "SQLi: Basic Pattern", "patterns": [rb"'\s+OR\s+\d+=\d+", rb"UNION\s+SELECT"], "protocols": ["TCP"],
     "ports": [80, 443, 8080], "severity": "critical"},
    {"name": "SQLi: Stacked Queries", "patterns": [rb";\s*DROP\s+TABLE", rb";\s*EXEC\(", rb";\s*INSERT"],
     "protocols": ["TCP"], "ports": [80, 443], "severity": "critical"},
    {"name": "SQLi: Time-Based Delay", "patterns": [rb"WAITFOR\s+DELAY", rb"SLEEP\(\d+\)"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "SQLi: Boolean-Based", "patterns": [rb"OR\s+1=1", rb"AND\s+1=1"], "protocols": ["TCP"], "ports": [80, 443],
     "severity": "high"},
    {"name": "SQLi: Error-Based", "patterns": [rb"CONVERT\(int", rb"EXEC\(0x"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "SQLi: Out-of-Band", "patterns": [rb"EXEC\s+xp_cmdshell", rb"DECLARE\s+@"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "critical"},
    {"name": "SQLi: Schema Discovery", "patterns": [rb"information_schema\.tables", rb"sys\.databases"],
     "protocols": ["TCP"], "ports": [80, 443], "severity": "high"},
    {"name": "SQLi: Blind Injection", "patterns": [rb"IF\s*\(\d+=\d+\)", rb"BENCHMARK\(\d+"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "SQLi: Encoding Evasion", "patterns": [rb"CHAR\(\d+\)", rb"0x[0-9a-fA-F]{20,}"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "medium"},
    {"name": "SQLi: Database Specific", "patterns": [rb"pg_sleep\(\d+\)", rb"mysql\.user"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},

    # XSS Attacks (8 rules)
    {"name": "XSS: Basic Script Tag", "patterns": [rb"<script>", rb"</script>"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "XSS: Event Handlers", "patterns": [rb"onmouseover=", rb"onload=", rb"onerror="], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "XSS: JavaScript URI", "patterns": [rb"javascript:", rb"data:text/html"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "XSS: SVG Injection", "patterns": [rb"<svg/onload=", rb"<image xlink:href="], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "medium"},
    {"name": "XSS: DOM-Based", "patterns": [rb"document\.cookie", rb"window\.location"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "medium"},
    {"name": "XSS: Encoded Payloads", "patterns": [rb"%3Cscript%3E", rb"%22%3E%3Cscript%3E"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "medium"},
    {"name": "XSS: AngularJS Injection", "patterns": [rb"{{7*7}}", rb"ng-app"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "medium"},
    {"name": "XSS: PHP Injection", "patterns": [rb"<?php echo", rb"<?="], "protocols": ["TCP"], "ports": [80, 443],
     "severity": "high"},

    # Command Injection (8 rules)
    {"name": "CMD: Basic Injection", "patterns": [rb";\s*ls\s", rb"&&\s*cat"], "protocols": ["TCP"],
     "ports": [80, 443, 22], "severity": "critical"},
    {"name": "CMD: Reverse Shell", "patterns": [rb"/bin/bash\s+-i", rb"nc\s+-e"], "protocols": ["TCP"],
     "ports": [22, 80, 443], "severity": "critical"},
    {"name": "CMD: PowerShell", "patterns": [rb"Invoke-WebRequest", rb"Start-Process"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "CMD: Windows Commands", "patterns": [rb"cmd\.exe\s+/c", rb"powershell\s+-EncodedCommand"],
     "protocols": ["TCP"], "ports": [80, 443], "severity": "high"},
    {"name": "CMD: File System Access", "patterns": [rb"/etc/passwd", rb"C:\\Windows\\System32"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "CMD: Process Injection", "patterns": [rb"fork\(\s*\)", rb"exec\(\s*\)"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "medium"},
    {"name": "CMD: Network Discovery", "patterns": [rb"nmap\s+-sV", rb"ping\s+-c\s+5"], "protocols": ["TCP"],
     "ports": [22, 80], "severity": "medium"},
    {"name": "CMD: Privilege Escalation", "patterns": [rb"sudo\s+su", rb"chmod\s+777"], "protocols": ["TCP"],
     "ports": [22], "severity": "high"},

    # Web Application Attacks (10 rules)
    {"name": "Web: Path Traversal", "patterns": [rb"\.\./\.\./", rb"%2e%2e%2f"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "Web: LFI/RFI", "patterns": [rb"include\(\$_GET", rb"php://filter"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "critical"},
    {"name": "Web: SSRF", "patterns": [rb"curl\s+http://127.0.0.1", rb"file:///etc/passwd"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "high"},
    {"name": "Web: XML Injection", "patterns": [rb"<!ENTITY", rb"SYSTEM\s+"], "protocols": ["TCP"], "ports": [80, 443],
     "severity": "high"},
    {"name": "Web: SSTI", "patterns": [rb"${7*7}", rb"<%="], "protocols": ["TCP"], "ports": [80, 443],
     "severity": "medium"},
    {"name": "Web: Open Redirect", "patterns": [rb"redirect=http://evil.com", rb"url=//attacker.net"],
     "protocols": ["TCP"], "ports": [80, 443], "severity": "medium"},
    {"name": "Web: Insecure Deserialization", "patterns": [rb"ObjectInputStream", rb"pickle\.load"],
     "protocols": ["TCP"], "ports": [80, 443], "severity": "high"},
    {"name": "Web: JWT Tampering", "patterns": [rb"eyJhbGciOiJub25lIn0", rb"alg:none"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "medium"},
    {"name": "Web: GraphQL Injection", "patterns": [rb"__schema", rb"query\s*{\s*user"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "medium"},
    {"name": "Web: Web Shell Activity", "patterns": [rb"eval\(\$_POST", rb"passthru\(\$_GET"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "critical"},

    # Network Attacks (15 rules)
    {"name": "Network: Port Scan", "threshold": 50, "interval": 10, "protocols": ["TCP"], "severity": "high",
     "stateful": True},
    {"name": "Network: SYN Flood", "threshold": 1000, "interval": 5, "protocols": ["TCP"], "severity": "critical",
     "stateful": True},
    {"name": "Network: DNS Amplification", "protocols": ["UDP"], "ports": [53], "patterns": [rb"ANY"],
     "severity": "critical"},
    {"name": "Network: NTP Monlist", "protocols": ["UDP"], "ports": [123], "patterns": [rb"\x17\x00\x03\x2a"],
     "severity": "high"},
    {"name": "Network: ICMP Flood", "threshold": 500, "interval": 5, "protocols": ["ICMP"], "severity": "high",
     "stateful": True},
    {"name": "Network: ARP Poisoning", "patterns": [rb"\x00\x01\x08\x00\x06\x04\x00\x01"], "protocols": ["ARP"],
     "severity": "critical"},
    {"name": "Network: DHCP Spoofing", "protocols": ["UDP"], "ports": [67, 68], "patterns": [rb"DHCPACK"],
     "severity": "medium"},
    {"name": "Network: STP Manipulation", "protocols": ["STP"], "patterns": [rb"\x00\x00\x0c\x01\x0b"],
     "severity": "high"},
    {"name": "Network: BGP Hijacking", "protocols": ["TCP"], "ports": [179],
     "patterns": [rb"\xff\xff\xff\xff\xff\xff\xff\xff"], "severity": "critical"},
    {"name": "Network: VLAN Hopping", "protocols": ["DTP"], "patterns": [rb"\x01\x0c\xcd\x04"], "severity": "high"},
    {"name": "Network: DNS Tunneling", "protocols": ["UDP"], "ports": [53], "patterns": [rb"\x00\x10\x00\x01"],
     "severity": "medium"},
    {"name": "Network: QUIC Abuse", "protocols": ["UDP"], "ports": [443], "threshold": 1000, "interval": 5,
     "severity": "medium"},
    {"name": "Network: SMB Exploit", "protocols": ["TCP"], "ports": [445], "patterns": [rb"\x00\x00..\xffSMB"],
     "severity": "critical"},
    {"name": "Network: RDP Brute Force", "protocols": ["TCP"], "ports": [3389], "threshold": 20, "interval": 60,
     "severity": "high"},
    {"name": "Network: SNMP Abuse", "protocols": ["UDP"], "ports": [161], "patterns": [rb"public", rb"private"],
     "severity": "medium"},

    # Malware Communication (12 rules)
    {"name": "Malware: C2 Beaconing", "protocols": ["TCP", "UDP"], "ports": [666, 1337, 31337], "severity": "critical"},
    {"name": "Malware: Mirai Scanning", "patterns": [rb"GET /shell?/bin/busybox"], "protocols": ["TCP"],
     "ports": [23, 2323], "severity": "high"},
    {"name": "Malware: WannaCry", "protocols": ["TCP"], "ports": [445], "patterns": [rb"WNcry@2ol7"],
     "severity": "critical"},
    {"name": "Malware: Emotet C2", "protocols": ["TCP"], "ports": [443], "patterns": [rb"\x13\x37\xb0\x0b"],
     "severity": "critical"},
    {"name": "Malware: TrickBot", "protocols": ["TCP"], "ports": [447, 449], "severity": "high"},
    {"name": "Malware: Ryuk Ransomware", "patterns": [rb"RyukDecryptor"], "protocols": ["TCP"], "ports": [80, 443],
     "severity": "critical"},
    {"name": "Malware: CoinMiner", "patterns": [rb"stratum+tcp://", rb"xmrpool.eu"], "protocols": ["TCP"],
     "ports": [3333, 4444], "severity": "medium"},
    {"name": "Malware: Pegasus", "protocols": ["TCP"], "ports": [7070], "patterns": [rb"\x50\x47\x53\x01"],
     "severity": "critical"},
    {"name": "Malware: LockBit", "patterns": [rb"LockBit", rb"!!!=== LockBit ===!!!"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "critical"},
    {"name": "Malware: Conti", "patterns": [rb"ContiDecryptor"], "protocols": ["TCP"], "ports": [80, 443],
     "severity": "critical"},
    {"name": "Malware: Log4j Exploit", "patterns": [rb"\${jndi:ldap://", rb"\${jndi:rmi://"], "protocols": ["TCP"],
     "ports": [80, 443], "severity": "critical"},
    {"name": "Malware: DarkComet", "protocols": ["TCP"], "ports": [1604], "severity": "high"},

    # Protocol Anomalies (10 rules)
    {"name": "Protocol: HTTP Smuggling", "patterns": [rb"Transfer-Encoding: chunked", rb"Content-Length: "],
     "protocols": ["TCP"], "ports": [80, 443], "severity": "high"},
    {"name": "Protocol: SSH Tunneling", "threshold": 10, "interval": 60, "protocols": ["TCP"], "ports": [22],
     "severity": "medium"},
    {"name": "Protocol: DNS Tunneling", "threshold": 100, "interval": 60, "protocols": ["UDP"], "ports": [53],
     "severity": "medium"},
    {"name": "Protocol: GRE Flood", "protocols": ["GRE"], "threshold": 1000, "interval": 5, "severity": "high"},
    {"name": "Protocol: TCP NULL Scan", "flags": 0x000, "protocols": ["TCP"], "severity": "medium"},
    {"name": "Protocol: XMAS Scan", "flags": 0x029, "protocols": ["TCP"], "severity": "medium"},
    {"name": "Protocol: FIN Scan", "flags": 0x001, "protocols": ["TCP"], "severity": "medium"},
    {"name": "Protocol: RST Flood", "threshold": 1000, "interval": 5, "flags": 0x004, "severity": "high"},
    {"name": "Protocol: Invalid HTTP", "patterns": [rb"GET / HTTP/3.1"], "protocols": ["TCP"], "ports": [80, 443],
     "severity": "medium"},
    {"name": "Protocol: TCP Retransmission", "threshold": 100, "interval": 5, "protocols": ["TCP"],
     "severity": "medium"}]
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
        proto_num = packet[IP].proto
        proto_name = IP_PROTOS.get(proto_num, 'unknown').upper()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        packet_data = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto_name,
            "length": len(packet)
        }

        # Collect basic packet info
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_data.update({
                "sport": tcp_layer.sport,
                "dport": tcp_layer.dport,
                "flags": tcp_layer.flags
            })
        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_data.update({
                "sport": udp_layer.sport,
                "dport": udp_layer.dport
            })
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            packet_data["type"] = icmp_layer.type

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
                # Check protocol match
                if rule.get('protocols'):
                    if proto_name not in rule['protocols']:
                        continue

                # Check port match if specified
                if 'ports' in rule:
                    dport = packet_data.get('dport')
                    if dport is None or dport not in rule['ports']:
                        continue

                # Check payload patterns
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
                            break  # No need to check other patterns for this rule

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