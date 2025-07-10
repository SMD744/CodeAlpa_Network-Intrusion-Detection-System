# Suricata Network Intrusion Detection System (NIDS)
**Project for CodeAlpha**  
*A real-time network monitoring system with threat detection and automated responses*

---

## 📌 Project Overview
This repository contains a complete implementation of a **Suricata-based NIDS** that:
- Monitors network traffic in real-time
- Detects malicious activity using custom rules
- Implements automated responses (email alerts/IP blocking)
- Logs all security events for analysis

---

## 🛠️ File Structure

CodeAlpha_ProjectName/
├── config/
│ └── suricata.yaml # Main configuration file
├── rules/
│ └── local.rules # Custom detection rules
├── scripts/
│ ├── monitor_alerts.sh # Email notification script
│ └── auto_block.sh # IP blocking script
├── docs/
│ └── setup_guide.md # Detailed installation steps
└── README.md # This file


---

## 🚀 Quick Start

### Prerequisites
- Linux system (Kali/Ubuntu recommended)
- Root/sudo access
- Internet connection

### Installation
```bash
# 1. Install Suricata and dependencies
sudo apt update && sudo apt install -y suricata jq mailutils

# 2. Clone this repository
git clone https://github.com/yourusername/CodeAlpha_ProjectName.git
cd CodeAlpha_ProjectName

# 3. Deploy configurations
sudo cp config/suricata.yaml /etc/suricata/
sudo cp rules/local.rules /etc/suricata/rules/


🔧 Configuration

#runinng it on parrticular interface
# Start Suricata (replace eth0 with your interface)
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

Response Options (Choose One)
#monitor( Email Alerts)
chmod +x scripts/monitor_alerts.sh
./scripts/monitor_alerts.sh
Configures email alerts for all threats

#Auto-Blocking
chmod +x scripts/auto_block.sh
sudo ./scripts/auto_block.sh
Automatically blocks malicious IPs using iptables


📜 Custom Rules

Example rules in rules/local.rules:
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)
alert tcp any any -> any any (msg:"Nmap TCP SYN scan detected"; flags:S; threshold:type limit, track by_src, count 5, seconds 60; sid:1000002; rev:1;)

# Example: Detect SSH brute force
alert ssh any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000001; rev:1;)

# Example: Block known malicious IPs
alert ip [146.19.236.204,149.104.88.27] any -> any any (msg:"Known Malicious IP"; sid:1000002; rev:1;)


📊 Monitoring & Verification

# View alerts in real-time
tail -f /var/log/suricata/fast.log

🧪 Testing Your Setup
# Port scan (should trigger alerts)
nmap -sS YOUR_IP
ping IP_Address

# Malicious IP test (if in your rules)
curl http://testmaliciousdomain.com




