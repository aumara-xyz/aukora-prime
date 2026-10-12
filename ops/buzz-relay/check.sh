#!/usr/bin/env bash
# The check for North Star step 2 on the node itself. Run as an admin with sudo. Exit 0 only if:
# the relay answers on loopback, nothing of aukora-buzz listens off loopback, and the harness units are
# still running. It does not show that an app joined or a message round-tripped; that is checked from the Mac.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-full}"
case "$MODE" in full|--health|--watch) ;; *) echo "usage: check.sh [--health|--watch]" >&2; exit 2 ;; esac
fail=0
say() { printf '%s  %s\n' "$1" "$2"; [ "$1" = PASS ] || fail=1; }
# Recover failed starts too, without undoing an intentional stop or an ongoing transition.
if [ "$MODE" = --watch ]; then
  STATE=$(systemctl show --property=ActiveState --value aukora-buzz.service) || exit 1
  case "$STATE" in
    active) ;;
    failed) say FAIL "aukora-buzz.service failed" ;;
    *) exit 0 ;;
  esac
fi
PORT=$(sudo cat /var/lib/aukora-buzz/node.env | bash "$HERE/read-setting.sh" PORT) || exit 1

UID_BUZZ=$(id -u aukora-buzz)
pod() { (cd /tmp && sudo -u aukora-buzz -H env XDG_RUNTIME_DIR="/run/user/$UID_BUZZ" timeout 10s podman "$@"); }

for c in buzz-postgres buzz-redis buzz-relay; do
  [ "$(pod inspect "$c" --format '{{.State.Running}}' 2>/dev/null)" = true ] && say PASS "$c running" || say FAIL "$c not running"
done
pod exec buzz-postgres pg_isready -U buzz -d buzz >/dev/null 2>&1 && say PASS "Postgres ready" || say FAIL "Postgres not ready"
# A reinstall does not restart old containers: retain their env-backed health probe until explicit restart.
[ "$(pod exec buzz-redis sh -c '{ printf "AUTH "; if [ -r /run/secrets/redis.conf ]; then sed -n "s/^requirepass //p" /run/secrets/redis.conf; else printf "%s\n" "$REDIS_PASSWORD"; fi; printf "PING\n"; } | redis-cli --raw | tail -n 1' 2>/dev/null)" = PONG ] \
  && say PASS "Redis ready" || say FAIL "Redis not ready"
curl --connect-timeout 2 --max-time 5 -sf -o /dev/null "http://127.0.0.1:${PORT}/health" && say PASS "relay /health on 127.0.0.1:${PORT}" \
  || say FAIL "relay /health on 127.0.0.1:${PORT}"
if [ "$MODE" != full ]; then
  if [ "$MODE" = --watch ] && [ "$fail" != 0 ]; then systemctl --no-block restart aukora-buzz.service || exit 1; fi
  exit "$fail"
fi

# Membership probes are informational; an open relay does not fail the health check.
MEMBER="$HERE/member/ops/buzz-relay/member.mjs"
[ -f "$MEMBER" ] || MEMBER="$HERE/member.mjs"
if node "$MEMBER" verify-closed --relay "http://localhost:${PORT}" >/dev/null 2>&1; then
  printf 'PASS  closed\n'
else
  printf 'OPEN  closed (not proved)\n'
fi

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
