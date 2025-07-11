#!/bin/bash

FAST_LOG="/var/log/suricata/fast.log"
DETECTED_IPS="/tmp/detected_ips.txt"
EMAIL="youremail@gmail.com"

# Whitelist configuration (simple IPs or ranges)
WHITELIST=(
    "64.233.184."   # Partial match for Google
    "142.250."      # Partial match for Google
    "146.19."
    "149.104."
)

# Clear log file if older than 24 hours
if [ -f "$DETECTED_IPS" ] && [ $(find "$DETECTED_IPS" -mtime +1 -print) ]; then
    echo "[*] Clearing old IP log..."
    > "$DETECTED_IPS"
fi

echo "[*] Starting Suricata monitoring (ALERTS ONLY - NO BLOCKING)..."

# New whitelist check function (no ipcalc needed)
is_whitelisted() {
    local ip=$1
    for range in "${WHITELIST[@]}"; do
        if [[ "$ip" == "$range"* ]]; then
            return 0
        fi
    done
    return 1
}

tail -F "$FAST_LOG" | while read -r line; do
    ips=$(echo "$line" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')

    for ip in $ips; do
        if is_whitelisted "$ip"; then
            echo "[.] Whitelisted IP detected: $ip (Ignoring)"
            continue
        fi

        if grep -q "$ip" "$DETECTED_IPS"; then
            echo "[-] Already detected: $ip (No action taken)"
        else
            echo "$ip" >> "$DETECTED_IPS"
            echo "[!] NEW THREAT DETECTED: $ip (Alert sent)"
            echo -e "Suricata Monitoring Alert\n\nSuspicious activity from: $ip\nTime: $(date)\nStatus: Logged (No blocking action taken)" \
                | mail -s "SURICATA ALERT: Threat Detected from $ip" "$EMAIL"
        fi
    done
done
