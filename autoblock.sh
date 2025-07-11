#!/bin/bash

FAST_LOG="/var/log/suricata/fast.log"
BLOCKED_IPS="/tmp/blocked_ips.txt"  # Now just a log of detected IPs (not blocked)
EMAIL="youremail@gmail.com"

sudo touch "$BLOCKED_IPS"
sudo chmod 666 "$BLOCKED_IPS"

echo "[*] Monitoring Suricata alerts live (NO BLOCKING - LOGGING ONLY)..."

tail -F "$FAST_LOG" | while read -r line; do
    # Extract IPs from each new alert line
    ips=$(echo "$line" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')

    for ip in $ips; do
        if grep -q "$ip" "$BLOCKED_IPS"; then
            echo "[-] Previously detected: $ip"
        else
            echo "[!] NEW THREAT DETECTED: $ip (Monitoring mode - not blocked)"
            echo "$ip" >> "$BLOCKED_IPS"

            # Send email alert (optional)
            echo -e "Suricata Alert:\nSuspicious activity from $ip\nTime: $(date)\nAction: Logged (No block)" \
                | mail -s "Suricata Alert - Detected IP: $ip" "$EMAIL"
        fi
    done
done

