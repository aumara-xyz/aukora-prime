#!/usr/bin/env bash
# Buzz relay beside the harness (North Star step 2). Run on the node as an admin with sudo.
# Creates the `aukora-buzz` user, its state under /var/lib/aukora-buzz, generated secrets (0600, never
# printed) and the aukora-buzz.service unit. Touches no other user, unit or port. Safe to run again.
# Usage: install.sh [--owner-pubkey <64 hex>]   (closed relay owned by that Nostr key; without it, open)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
U=aukora-buzz
ROOT=/var/lib/aukora-buzz
LIB=/usr/local/lib/aukora-buzz
PORT="${AUKORA_BUZZ_PORT:-18740}"
OWNER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --owner-pubkey) OWNER="$(printf %s "$2" | tr 'A-F' 'a-f')"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [ -n "$OWNER" ] && ! printf %s "$OWNER" | grep -qE '^[0-9a-f]{64}$'; then
  echo "--owner-pubkey must be 64 hex characters" >&2; exit 2
fi
if ! id "$U" >/dev/null 2>&1 && sudo ss -ltnH | awk '{print $4}' | grep -qE ":${PORT}\$"; then
  echo "port ${PORT} is already in use on this machine" >&2; exit 1
fi

if ! id "$U" >/dev/null 2>&1; then
  sudo useradd --system --create-home --home-dir "$ROOT" --shell /usr/sbin/nologin "$U"
fi
# Rootless Podman needs a subordinate id range; take the next free 65536 block.
if ! grep -q "^$U:" /etc/subuid; then
  NEXT=$(awk -F: 'BEGIN{m=100000} {e=$2+$3; if (e>m) m=e} END{print m}' /etc/subuid /etc/subgid)
  sudo usermod --add-subuids "${NEXT}-$((NEXT + 65535))" --add-subgids "${NEXT}-$((NEXT + 65535))" "$U"
fi
sudo loginctl enable-linger "$U"
sudo chmod 0750 "$ROOT"
sudo -u "$U" mkdir -p "$ROOT/data/postgres" "$ROOT/data/redis" "$ROOT/data/git" "$ROOT/src"

# Secrets are made here, on the node, and stay in files only aukora-buzz can read.
sudo -u "$U" env ROOT="$ROOT" OWNER="$OWNER" PORT="$PORT" bash -s <<'EOS'
set -euo pipefail
umask 077
cd "$ROOT"
if [ ! -f postgres.env ]; then
  PG=$(openssl rand -hex 24); RD=$(openssl rand -hex 24)
  printf 'POSTGRES_DB=buzz\nPOSTGRES_USER=buzz\nPOSTGRES_PASSWORD=%s\nPGDATA=/var/lib/postgresql/data/pgdata\n' "$PG" > postgres.env
  printf 'REDIS_PASSWORD=%s\n' "$RD" > redis.env
  {
    printf 'DATABASE_URL=postgres://buzz:%s@127.0.0.1:5432/buzz\n' "$PG"
    printf 'REDIS_URL=redis://:%s@127.0.0.1:6379\n' "$RD"
    printf 'BUZZ_RELAY_PRIVATE_KEY=%s\n' "$(openssl rand -hex 32)"
    printf 'BUZZ_GIT_HOOK_HMAC_SECRET=%s\n' "$(openssl rand -hex 32)"
  } > relay-secrets.env
fi
# Settings that are not secret; rewritten on every install so the repository stays the source.
{
  echo 'BUZZ_BIND_ADDR=0.0.0.0:3000'
  echo 'BUZZ_HEALTH_PORT=8080'
  echo 'BUZZ_METRICS_PORT=9102'
  echo "RELAY_URL=${AUKORA_BUZZ_RELAY_URL:-ws://localhost:3000}"
  echo 'BUZZ_AUTO_MIGRATE=true'
  echo 'BUZZ_GIT_REPO_PATH=/data/git'
  echo 'BUZZ_PUSH_ENABLED=false'
  echo 'BUZZ_GIT_CONFORMANCE_PROBE=false'
  echo 'RUST_LOG=info'
  if [ -n "$OWNER" ]; then
    echo "RELAY_OWNER_PUBKEY=$OWNER"
    echo 'BUZZ_REQUIRE_RELAY_MEMBERSHIP=true'
  fi
} > relay.env
printf 'PORT=%s\n' "$PORT" > node.env
EOS

sudo install -d -m 0755 "$LIB"
sudo install -m 0755 "$HERE/up.sh" "$HERE/down.sh" "$HERE/build.sh" "$HERE/check.sh" "$LIB/"
sudo install -m 0644 "$HERE/aukora-buzz.service" /etc/systemd/system/aukora-buzz.service
sudo systemctl daemon-reload
echo "installed: user $U, state $ROOT, unit aukora-buzz.service (not started), port 127.0.0.1:${PORT}"
