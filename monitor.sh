#!/bin/bash
# Monitor and email alerts
FAST_LOG="/var/log/suricata/fast.log"
EMAIL="your@email.com"

tail -F "$FAST_LOG" | while read -r line; do
    echo -e "ALERT: $line" | mail -s "SURICATA ALERT" "$EMAIL"
done
