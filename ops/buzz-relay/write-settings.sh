#!/usr/bin/env bash
# Write relay settings atomically; closing preserves all unrelated settings.
set -euo pipefail
ROOT="$1" OWNER="$2" PORT="${3:-}"
cd "$ROOT"
umask 077
if [ -z "$OWNER" ] && [ -f relay.env ]; then OWNER=$(sed -n 's/^RELAY_OWNER_PUBKEY=//p' relay.env); fi
[[ -z "$OWNER" || "$OWNER" =~ ^[0-9a-f]{64}$ ]] || { echo 'buzz-settings:invalid-owner' >&2; exit 1; }
NEXT=$(mktemp "$ROOT/.relay.env.XXXXXX")
trap 'rm -f "$NEXT"' EXIT
{
  if [ -z "$PORT" ]; then
    sed '/^RELAY_OWNER_PUBKEY=/d; /^BUZZ_REQUIRE_RELAY_MEMBERSHIP=/d' relay.env
  else
    echo 'BUZZ_BIND_ADDR=0.0.0.0:3000'
    echo 'BUZZ_HEALTH_PORT=8080'
    echo 'BUZZ_METRICS_PORT=9102'
    echo "RELAY_URL=${AUKORA_BUZZ_RELAY_URL:-ws://localhost:3000}"
    echo 'BUZZ_AUTO_MIGRATE=true'
    echo 'BUZZ_GIT_REPO_PATH=/data/git'
    echo 'BUZZ_PUSH_ENABLED=false'
    echo 'BUZZ_GIT_CONFORMANCE_PROBE=false'
    echo 'RUST_LOG=info'
  fi
  if [ -n "$OWNER" ]; then
    echo "RELAY_OWNER_PUBKEY=$OWNER"
    echo 'BUZZ_REQUIRE_RELAY_MEMBERSHIP=true'
  fi
} > "$NEXT"
chmod 0600 "$NEXT"
mv -f "$NEXT" relay.env
if [ -n "$PORT" ]; then printf 'PORT=%s\n' "$PORT" > node.env; fi
