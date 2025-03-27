import socket
import time
import requests
import threading
from scapy.all import *

TARGET_IP = "10.1.107.133"  # Change this to your IDS machine IP

# Function to send a SYN scan (Port Scanning Detection)
def syn_scan():
    print("[*] Sending SYN Scan...")
    for port in range(20, 1025):  # Common ports
        ip = IP(dst=TARGET_IP)
        tcp = TCP(dport=port, flags="S")  # SYN flag
        send(ip/tcp, verbose=False)
    print("[*] SYN Scan Sent.")

# Function to simulate SSH brute-force attack
def ssh_brute_force():
    print("[*] Simulating SSH Brute Force...")
    for _ in range(10):  # Simulate multiple login attempts
        ip = IP(dst=TARGET_IP)
        tcp = TCP(dport=22, flags="P")  # Push flag
        raw = Raw(load="root:password123\n")  # Fake credentials
        send(ip/tcp/raw, verbose=False)
        time.sleep(0.5)
    print("[*] SSH Brute Force Attempted.")

# Function to send an HTTP request with SQL injection payload
def sql_injection():
    print("[*] Sending SQL Injection Payload...")
    ip = IP(dst=TARGET_IP)
    tcp = TCP(dport=80, flags="P")  # Push flag
    raw = Raw(load="GET /login?username=admin' OR '1'='1&password=pass HTTP/1.1\r\nHost: example.com\r\n\r\n")
    send(ip/tcp/raw, verbose=False)
    print("[*] SQL Injection Sent.")

# Function to send an XSS attack payload
def xss_attack():
    print("[*] Sending XSS Payload...")
    ip = IP(dst=TARGET_IP)
    tcp = TCP(dport=80, flags="P")  # Push flag
    raw = Raw(load="GET /comment?message=<script>alert('Hacked');</script> HTTP/1.1\r\nHost: example.com\r\n\r\n")
    send(ip/tcp/raw, verbose=False)
    print("[*] XSS Attack Sent.")

# Function to simulate a SYN Flood attack (DDoS)
def syn_flood():
    print("[*] Launching SYN Flood Attack...")
    for _ in range(500):  # 500 SYN packets to port 80
        ip = IP(dst=TARGET_IP)
        tcp = TCP(dport=80, flags="S")  # SYN flag
        send(ip/tcp, verbose=False)
    print("[*] SYN Flood Attack Completed.")

# Function to simulate anonymous FTP login
def ftp_anonymous():
    print("[*] Trying Anonymous FTP Login...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_IP, 21))
    s.send(b"USER anonymous\r\n")
    s.send(b"PASS anonymous\r\n")
    s.close()
    print("[*] Anonymous FTP Login Attempted.")

# Function to launch all attacks
def attack_ids():
    threads = [
        threading.Thread(target=syn_scan),
        threading.Thread(target=ssh_brute_force),
        threading.Thread(target=sql_injection),
        threading.Thread(target=xss_attack),
        threading.Thread(target=syn_flood),
        threading.Thread(target=ftp_anonymous)
    ]

    for thread in threads:
        thread.start()
        time.sleep(1)  # Small delay to avoid instant bursts

    for thread in threads:
        thread.join()

    print("[*] IDS Attack Simulation Completed.")

# Run the attack
attack_ids()
