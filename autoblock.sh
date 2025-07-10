#!/bin/bash
# Auto-block malicious IPs
tail -f /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .src_ip' | while read ip; do
    sudo iptables -A INPUT -s "$ip" -j DROP && \
    echo "$(date) Blocked $ip" >> blocked_ips.log
done
