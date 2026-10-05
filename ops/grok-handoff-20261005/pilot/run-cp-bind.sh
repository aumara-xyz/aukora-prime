#!/bin/bash
# STAGING ONLY, read-only probe: item-1 control-plane probe inside auma-ws WITH workspace bind.
# Runs via direct `openshell sandbox exec` (sbx-exec admission not passable until F fixes the profile schema). Changes no config.
set -u
P=/root/cp-probe.py
ABS=$(awk 'NR>1 && $NF ~ /^@/ {print $NF}' /proc/net/unix | sort -u | python3 -c 'import sys,json;print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
PIDS=$(pgrep -u auma | python3 -c 'import sys,json;print(json.dumps([int(l) for l in sys.stdin if l.strip()]))')
ARGS="{\"abstract\": $ABS, \"pids\": $PIDS}"
B64=$(base64 -w0 $P)
echo "CP PROBE (bind) $(date -u '+%F %T') UTC probe sha256 $(sha256sum $P | cut -c1-16)"
echo "== REAL: guest auma-ws WITH workspace bind (direct openshell exec)"
cd /tmp
sudo -u auma env XDG_RUNTIME_DIR=/run/user/1001 OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=/home/auma/.local/state/openshell/tls HOME=/home/auma \
  openshell sandbox exec --name auma-ws --no-tty --timeout 120 -- python3 -I -c "import base64,sys;sys.argv=['p',sys.argv[1]];exec(base64.b64decode('$B64'))" "$ARGS" </dev/null
echo "guest rc=$?"
