#!/usr/bin/env bash
# The check for North Star step 2 on the node itself. Run as an admin with sudo. Exit 0 only if:
# the relay answers on loopback, nothing of aukora-buzz listens off loopback, and the harness units are
# still running. It does not show that an app joined or a message round-tripped; that is checked from the Mac.
set -uo pipefail
. <(sudo cat /var/lib/aukora-buzz/node.env)
fail=0
say() { printf '%s  %s\n' "$1" "$2"; [ "$1" = PASS ] || fail=1; }

curl -sf -o /dev/null "http://127.0.0.1:${PORT}/health" && say PASS "relay /health on 127.0.0.1:${PORT}" \
  || say FAIL "relay /health on 127.0.0.1:${PORT}"

UID_BUZZ=$(id -u aukora-buzz)
OFF=$(sudo ss -ltnpH | awk '$4 !~ /^(127\.|\[::1\])/' | while read -r line; do
  pid=$(printf %s "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
  [ -n "$pid" ] && [ "$(stat -c %u "/proc/$pid" 2>/dev/null)" = "$UID_BUZZ" ] && echo "$line"
done)
[ -z "$OFF" ] && say PASS "no aukora-buzz listener off loopback" || say FAIL "aukora-buzz listens off loopback: $OFF"

for unit in aukora-genesis aukora-boundary-gate aukora-openshell-gateway aukora-openviking aukora-relay; do
  [ "$(systemctl is-active "$unit")" = active ] && say PASS "$unit active" || say FAIL "$unit not active"
done
exit $fail
