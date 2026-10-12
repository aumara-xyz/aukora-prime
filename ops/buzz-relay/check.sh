#!/usr/bin/env bash
# The check for North Star step 2 on the node itself. Run as an admin with sudo. Exit 0 only if:
# the relay answers on loopback, nothing of aukora-buzz listens off loopback, and the harness units are
# still running. It does not show that an app joined or a message round-tripped; that is checked from the Mac.
set -uo pipefail
. <(sudo cat /var/lib/aukora-buzz/node.env)
fail=0
say() { printf '%s  %s\n' "$1" "$2"; [ "$1" = PASS ] || fail=1; }

UID_BUZZ=$(id -u aukora-buzz)
pod() { (cd /tmp && sudo -u aukora-buzz -H env XDG_RUNTIME_DIR="/run/user/$UID_BUZZ" podman "$@"); }

for c in buzz-postgres buzz-redis buzz-relay; do
  [ "$(pod inspect "$c" --format '{{.State.Running}}' 2>/dev/null)" = true ] && say PASS "$c running" || say FAIL "$c not running"
done
curl -sf -o /dev/null "http://127.0.0.1:${PORT}/health" && say PASS "relay /health on 127.0.0.1:${PORT}" \
  || say FAIL "relay /health on 127.0.0.1:${PORT}"

# Every listening socket on the machine that belongs to a process of aukora-buzz must be on loopback.
if LISTEN=$(sudo ss -ltnpH) && [ -n "$LISTEN" ]; then
  OFF=$(printf '%s\n' "$LISTEN" | awk '$4 !~ /^(127\.|\[::1\])/' | while read -r line; do
    for pid in $(printf %s "$line" | grep -oE 'pid=[0-9]+' | cut -d= -f2); do
      owner=$(sudo stat -c %u "/proc/$pid" 2>/dev/null) || owner=unknown
      [ "$owner" = "$UID_BUZZ" ] && echo "$line"
    done
  done)
  MINE=$(printf '%s\n' "$LISTEN" | grep -c ":${PORT} ")
  [ -z "$OFF" ] && [ "$MINE" = 1 ] && say PASS "aukora-buzz listens only on 127.0.0.1:${PORT}" \
    || say FAIL "listeners: off loopback '$OFF', sockets on port ${PORT}: $MINE"
else
  say FAIL "could not list listening sockets"
fi

for unit in aukora-genesis aukora-boundary-gate aukora-openshell-gateway aukora-openviking aukora-relay; do
  [ "$(systemctl is-active "$unit")" = active ] && say PASS "$unit active" || say FAIL "$unit not active"
done
exit $fail
