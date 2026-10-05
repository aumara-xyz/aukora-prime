#!/bin/bash
# staging only: supplemental control-plane probe, guest / host-as-auma / root control
set -u
P=/root/cp-probe.py
ABS=$(awk 'NR>1 && $NF ~ /^@/ {print $NF}' /proc/net/unix | sort -u | python3 -c 'import sys,json;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
PIDS=$(pgrep -u auma | python3 -c 'import sys,json;print(json.dumps([int(l) for l in sys.stdin if l.strip()]))')
ARGS="{\"abstract\": $ABS, \"pids\": $PIDS}"
B64=$(base64 -w0 $P)
echo "CP PROBE $(date -u '+%F %T') UTC  probe sha256 $(sha256sum $P | cut -c1-16)  abstract targets $(echo $ABS | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')  auma pids $PIDS"
echo; echo "== REAL: guest (auma-ws via sbx-exec)"
runuser -u aukora-host -- sudo -n -u auma /usr/local/lib/aukora-boundary/sbx-exec 120 "python3 -I -c \"import base64,sys;sys.argv=['p',sys.argv[1]];exec(base64.b64decode('$B64'))\" '$ARGS'"
echo "guest rc=$?"
echo; echo "== REAL: host as auma (guest-escape depth)"
cp $P /tmp/cp-probe-auma.py; chmod 644 /tmp/cp-probe-auma.py
( cd /tmp && runuser -u auma -- env XDG_RUNTIME_DIR=/run/user/1001 python3 -I /tmp/cp-probe-auma.py "$ARGS" ) | grep -v '^MOUNT'
echo; echo "== CONTROL: root, no confinement (targets must be live: ALLOWED expected)"
python3 -I $P "$ARGS" | grep -v '^MOUNT' | grep -v '^proc-mem' ; python3 -I $P "$ARGS" | grep '^proc-mem' | head -3
rm -f /tmp/cp-probe-auma.py
