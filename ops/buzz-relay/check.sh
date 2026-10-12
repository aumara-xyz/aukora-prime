#!/usr/bin/env bash
# Checks relay health, recorded closure intent and opt-in admission service listeners.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-full}"
case "$MODE" in full|--health|--watch|--admission) ;; *) echo "usage: check.sh [--health|--watch|--admission]" >&2; exit 2 ;; esac
fail=0
say() { printf '%s  %s\n' "$1" "$2"; [ "$1" = PASS ] || fail=1; }
ROOT=/var/lib/aukora-buzz
if [ "$MODE" = --admission ]; then
  [ "$(systemctl is-active aukora-admission.service)" = active ] \
    && say PASS 'aukora-admission.service active' || say FAIL 'aukora-admission.service not active'
  UID_ADMISSION=$(id -u aukora-admission) || exit 1
  admission_port=0 off_loopback=0
  if LISTEN=$(sudo ss -ltnpH) && [ -n "$LISTEN" ]; then
    while read -r line; do
      socket=$(printf '%s\n' "$line" | awk '{print $4}')
      for pid in $(printf %s "$line" | grep -oE 'pid=[0-9]+' | cut -d= -f2); do
        owner=$(sudo stat -c %u "/proc/$pid" 2>/dev/null) || owner=unknown
        [ "$owner" = "$UID_ADMISSION" ] || continue
        case "$socket" in 127.*:*|\[::1\]:*) ;; *) off_loopback=1 ;; esac
        [ "$socket" != 127.0.0.1:3100 ] || admission_port=$((admission_port + 1))
      done
    done <<< "$LISTEN"
    [ "$off_loopback" = 0 ] && [ "$admission_port" = 1 ] \
      && say PASS 'aukora-admission listens only on loopback, port 3100' || say FAIL 'aukora-admission listener not proved'
  else
    say FAIL 'aukora-admission listeners unavailable'
  fi
  PORT=$(sudo cat "$ROOT/node.env" | bash "$HERE/read-setting.sh" PORT) || exit 1
  MEMBER="$HERE/member/ops/buzz-relay/member.mjs"
  [ -f "$MEMBER" ] || MEMBER="$HERE/member.mjs"
  NODE="$HERE/node-v24.11.1/node"
  [ -x "$NODE" ] || NODE=node
  "$NODE" "$MEMBER" verify-closed --relay "http://localhost:${PORT}" >/dev/null 2>&1 \
    && say PASS 'admission relay closed' || say FAIL 'admission relay closure not proved'
  exit "$fail"
fi
closed_intent=0 close_failed=0 watch_stopped=0
sudo test ! -e "$ROOT/closed" || closed_intent=1
sudo test ! -e "$ROOT/close-failed" || close_failed=1
[ "$close_failed" = 0 ] || say FAIL 'close-failed: run a successful close or close.sh --acknowledge'
intent_fail=$fail
fail=0
# Recover failed starts too, without undoing an intentional stop or an ongoing transition.
if [ "$MODE" = --watch ]; then
  STATE=$(systemctl show --property=ActiveState --value aukora-buzz.service) || exit 1
  case "$STATE" in
    active) ;;
    failed) say FAIL "aukora-buzz.service failed" ;;
    *) [ "$closed_intent" = 1 ] || [ "$close_failed" = 1 ] || exit 0; watch_stopped=1 ;;
  esac
fi
PORT=$(sudo cat "$ROOT/node.env" | bash "$HERE/read-setting.sh" PORT) || exit 1

UID_BUZZ=$(id -u aukora-buzz)
pod() { (cd /tmp && sudo -u aukora-buzz -H env XDG_RUNTIME_DIR="/run/user/$UID_BUZZ" timeout 10s podman "$@"); }

if [ "$watch_stopped" = 0 ]; then
for c in buzz-postgres buzz-redis buzz-relay; do
  [ "$(pod inspect "$c" --format '{{.State.Running}}' 2>/dev/null)" = true ] && say PASS "$c running" || say FAIL "$c not running"
done
pod exec buzz-postgres pg_isready -U buzz -d buzz >/dev/null 2>&1 && say PASS "Postgres ready" || say FAIL "Postgres not ready"
# A reinstall does not restart old containers: retain their env-backed health probe until explicit restart.
[ "$(pod exec buzz-redis sh -c '{ printf "AUTH "; if [ -r /run/secrets/redis.conf ]; then sed -n "s/^requirepass //p" /run/secrets/redis.conf; else printf "%s\n" "$REDIS_PASSWORD"; fi; printf "PING\n"; } | redis-cli --raw | tail -n 1' 2>/dev/null)" = PONG ] \
  && say PASS "Redis ready" || say FAIL "Redis not ready"
curl --connect-timeout 2 --max-time 5 -sf -o /dev/null "http://127.0.0.1:${PORT}/health" && say PASS "relay /health on 127.0.0.1:${PORT}" \
  || say FAIL "relay /health on 127.0.0.1:${PORT}"
fi
health_fail=$fail
[ "$intent_fail" = 0 ] || fail=1

MEMBER="$HERE/member/ops/buzz-relay/member.mjs"
[ -f "$MEMBER" ] || MEMBER="$HERE/member.mjs"
if [ "$MODE" = full ] || [ "$closed_intent" = 1 ]; then
if node "$MEMBER" verify-closed --relay "http://localhost:${PORT}" >/dev/null 2>&1; then
  say PASS closed
elif [ "$closed_intent" = 1 ]; then
  say FAIL 'closed intent: verify-closed did not pass; relay may be OPEN'
else
  printf 'OPEN  closed (not proved)\n'
fi
fi
if [ "$MODE" != full ]; then
  if [ "$MODE" = --watch ] && [ "$health_fail" != 0 ]; then systemctl --no-block restart aukora-buzz.service || exit 1; fi
  exit "$fail"
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
