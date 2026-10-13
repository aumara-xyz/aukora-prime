#!/usr/bin/env bash
# Write relay settings atomically; closing preserves all unrelated settings.
set -euo pipefail
ROOT="$1" OWNER="$2" PORT="${3:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
if [ -n "$PORT" ]; then
  INTENDED_MEMBERSHIP=closed
  if [ -f node.env ]; then
    INTENDED_MEMBERSHIP=$(bash "$HERE/read-setting.sh" INTENDED_MEMBERSHIP < node.env 2>/dev/null) || INTENDED_MEMBERSHIP=''
  fi
  NODE_NEXT=$(mktemp "$ROOT/.node.env.XXXXXX")
  { printf 'PORT=%s\n' "$PORT"; [ -z "$INTENDED_MEMBERSHIP" ] || printf 'INTENDED_MEMBERSHIP=%s\n' "$INTENDED_MEMBERSHIP"; } > "$NODE_NEXT"
  chmod 0600 "$NODE_NEXT"
  mv -f "$NODE_NEXT" node.env
fi
