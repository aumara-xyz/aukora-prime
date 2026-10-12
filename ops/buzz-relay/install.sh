#!/usr/bin/env bash
# Buzz relay beside the harness (North Star step 2). Run on the node as an admin with sudo.
# Creates the `aukora-buzz` user, its state under /var/lib/aukora-buzz, private credentials (0600 originals,
# 0444 container files under a 0700 directory, never printed) and service/health-watch units.
# Touches no unrelated user, unit or port.
# Safe to run again with the same port: preserves data and credentials, rewrites settings/scripts/units,
# and never starts or restarts the service. Refuses an occupied port unless its listener is verified as
# this pod's; stop the service first when changing ports or when listener ownership cannot be verified.
# Usage: install.sh [--owner-pubkey <64 hex>]   (closed relay owned by that Nostr key; without it, open)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
U=aukora-buzz
ROOT=/var/lib/aukora-buzz
LIB=/usr/local/lib/aukora-buzz
# Buzz binds a community to the host name a client asks for, so every client must dial the same name the relay
# was told it has (RELAY_URL). On the node and through a tunnel alike that is localhost:3000.
PORT="${AUKORA_BUZZ_PORT:-3000}"
PORT=$(printf 'PORT=%s\n' "$PORT" | bash "$HERE/read-setting.sh" PORT)
# Opt in only after checking that the rootless user's cgroup v2 memory controller is delegated.
MEMORY_LIMITS="${AUKORA_BUZZ_MEMORY_LIMITS:-0}"
[[ "$MEMORY_LIMITS" =~ ^[01]$ ]] || { echo "AUKORA_BUZZ_MEMORY_LIMITS must be 0 or 1" >&2; exit 2; }
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
bash "$HERE/check-port.sh" "$PORT"

# An account of this name that this script did not make is someone else's: leave it alone.
if id "$U" >/dev/null 2>&1 && { [ "$(getent passwd "$U" | cut -d: -f6)" != "$ROOT" ] || ! sudo test -f "$ROOT/node.env"; } \
   && ! sudo test -d "$ROOT/src"; then
  echo "an account named $U already exists and was not made by this script" >&2; exit 1
fi
if ! id "$U" >/dev/null 2>&1; then
  sudo useradd --system --create-home --home-dir "$ROOT" --shell /usr/sbin/nologin "$U"
fi
# Rootless Podman needs a subordinate id range; take the next free 65536 block.
NEXT=$(awk -F: 'BEGIN{m=100000} {e=$2+$3; if (e>m) m=e} END{print m}' /etc/subuid /etc/subgid)
grep -q "^$U:" /etc/subuid || sudo usermod --add-subuids "${NEXT}-$((NEXT + 65535))" "$U"
grep -q "^$U:" /etc/subgid || sudo usermod --add-subgids "${NEXT}-$((NEXT + 65535))" "$U"
sudo loginctl enable-linger "$U"
sudo chmod 0750 "$ROOT"
sudo -u "$U" mkdir -p "$ROOT/data/postgres" "$ROOT/data/redis" "$ROOT/data/git" "$ROOT/src"

# The images consume derived files; legacy credentials remain authoritative for existing database data.
sudo -u "$U" bash "$HERE/prepare-secrets.sh" "$ROOT"
sudo -u "$U" env ROOT="$ROOT" OWNER="$OWNER" PORT="$PORT" bash -s <<'EOS'
set -euo pipefail
umask 077
cd "$ROOT"
# Settings that are not secret; rewritten on every install so the repository stays the source.
# A relay that was closed stays closed with the same owner unless a new owner is named.
if [ -z "$OWNER" ] && [ -f relay.env ]; then OWNER=$(sed -n 's/^RELAY_OWNER_PUBKEY=//p' relay.env); fi
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

# Buzz's Dockerfile names its base images without a registry; resolve those to Docker Hub for this user only.
sudo -u "$U" sh -c 'mkdir -p ~/.config/containers && printf "unqualified-search-registries = [\"docker.io\"]\nshort-name-mode = \"permissive\"\n" > ~/.config/containers/registries.conf'

sudo install -d -m 0755 "$LIB"
sudo install -m 0755 "$HERE/up.sh" "$HERE/down.sh" "$HERE/build.sh" "$HERE/check.sh" "$HERE/read-setting.sh" "$LIB/"
sed -e "s/@UID@/$(id -u "$U")/g" -e "s/@MEMORY_LIMITS@/$MEMORY_LIMITS/g" "$HERE/aukora-buzz.service" \
  | sudo install -m 0644 /dev/stdin /etc/systemd/system/aukora-buzz.service
sudo install -m 0644 "$HERE/aukora-buzz-watch.service" "$HERE/aukora-buzz-watch.timer" /etc/systemd/system/
sudo systemctl daemon-reload
echo "installed: user $U, state $ROOT, unit aukora-buzz.service (not started), port 127.0.0.1:${PORT}"
