#!/usr/bin/env bash
# Buzz relay beside the harness (North Star step 2). Run on the node as an admin with sudo.
# Creates the `aukora-buzz` user, its state under /var/lib/aukora-buzz, private credentials (0600 originals,
# 0444 container files under a 0700 directory, never printed) and service/health-watch units.
# Touches no unrelated user, unit or port.
# Safe to run again with the same port: preserves data and credentials, rewrites settings/scripts/units,
# and never starts or restarts the service. Refuses an occupied port unless its listener is verified as
# this pod's; stop the service first when changing ports or when listener ownership cannot be verified.
# Usage: install.sh [--owner-pubkey <64 hex>] [--with-admission] (admission is installed, never started)
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
OWNER="" WITH_ADMISSION=0
while [ $# -gt 0 ]; do
  case "$1" in
    --owner-pubkey) OWNER="$(printf %s "$2" | tr 'A-F' 'a-f')"; shift 2 ;;
    --with-admission) WITH_ADMISSION=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [ -n "$OWNER" ] && ! printf %s "$OWNER" | grep -qE '^[0-9a-f]{64}$'; then
  echo "--owner-pubkey must be 64 hex characters" >&2; exit 2
fi
if [ "$WITH_ADMISSION" = 1 ]; then
  [ -f "$HERE/admission-server.mjs" ] && [ -f "$HERE/../../packages/invites/index.mjs" ] \
    && [ -f "$HERE/../../plugins/aukora-buzz-door/lib/index.mjs" ] \
    || { echo 'buzz-admission:full-checkout-required' >&2; exit 2; }
  ADMISSION_NODE=$(command -v node) || { echo 'buzz-admission:node-24.11.1-required' >&2; exit 2; }
  [ "$("$ADMISSION_NODE" --version)" = v24.11.1 ] || { echo 'buzz-admission:node-24.11.1-required' >&2; exit 2; }
  [ "$PORT" != 3100 ] || { echo 'buzz-admission:port-conflict' >&2; exit 2; }
  if id aukora-admission >/dev/null 2>&1 && { [ "$(getent passwd aukora-admission | cut -d: -f6)" != /var/lib/aukora-admission ] \
    || ! sudo test -f /etc/systemd/system/aukora-admission.service; }; then
    echo 'buzz-admission:account-exists' >&2; exit 2
  fi
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
sudo -u "$U" bash "$HERE/write-settings.sh" "$ROOT" "$OWNER" "$PORT"

# Buzz's Dockerfile names its base images without a registry; resolve those to Docker Hub for this user only.
sudo -u "$U" sh -c 'mkdir -p ~/.config/containers && printf "unqualified-search-registries = [\"docker.io\"]\nshort-name-mode = \"permissive\"\n" > ~/.config/containers/registries.conf'

sudo install -d -m 0755 "$LIB"
# Keep the verifier's relative imports and notices when installing from a full checkout.
if [ -f "$HERE/../../plugins/aukora-buzz-door/lib/index.mjs" ]; then
  sudo install -d -m 0755 "$LIB/member/ops/buzz-relay" "$LIB/member/plugins/aukora-buzz-door/lib" "$LIB/member/plugins/aukora-nostr/lib/vendor"
  sudo install -m 0644 "$HERE/member.mjs" "$LIB/member/ops/buzz-relay/"
  # The member tool imports the door for its request signing, and the door imports its receipt code and two gate
  # files: everything in that closure is copied, or the installed tool cannot load (close.test.mjs checks it).
  sudo install -m 0644 "$HERE/../../plugins/aukora-buzz-door/lib/index.mjs" "$HERE/../../plugins/aukora-buzz-door/lib/receipt.mjs" "$LIB/member/plugins/aukora-buzz-door/lib/"
  sudo install -d -m 0755 "$LIB/member/packages/boundary-gate/src"
  sudo install -m 0644 "$HERE/../../packages/boundary-gate/src/receipts.mjs" "$HERE/../../packages/boundary-gate/src/ledger.mjs" "$LIB/member/packages/boundary-gate/src/"
  sudo install -m 0644 "$HERE/../../plugins/aukora-nostr/lib/event.mjs" "$LIB/member/plugins/aukora-nostr/lib/"
  sudo cp -R "$HERE/../../plugins/aukora-nostr/lib/vendor/noble-curves" "$LIB/member/plugins/aukora-nostr/lib/vendor/"
fi
if [ "$WITH_ADMISSION" = 1 ]; then
  if ! id aukora-admission >/dev/null 2>&1; then
    sudo useradd --system --user-group --create-home --home-dir /var/lib/aukora-admission --shell /usr/sbin/nologin aukora-admission
  fi
  sudo install -d -o aukora-admission -g aukora-admission -m 0700 /var/lib/aukora-admission
  sudo install -d -m 0755 "$LIB/member/packages/invites" "$LIB/member/packages/contracts/src" "$LIB/node-v24.11.1"
  sudo install -m 0644 "$HERE/admit.mjs" "$HERE/admission-server.mjs" "$LIB/member/ops/buzz-relay/"
  sudo install -m 0644 "$HERE/../../packages/invites/index.mjs" "$LIB/member/packages/invites/"
  sudo install -m 0644 "$HERE/../../packages/contracts/src/json.mjs" "$LIB/member/packages/contracts/src/"
  sudo install -m 0755 "$ADMISSION_NODE" "$LIB/node-v24.11.1/node"
  sed -e "s/@RELAY_PORT@/$PORT/g" "$HERE/units/aukora-admission.service" \
    | sudo install -m 0644 /dev/stdin /etc/systemd/system/aukora-admission.service
fi
sudo install -m 0755 "$HERE/up.sh" "$HERE/down.sh" "$HERE/build.sh" "$HERE/check.sh" "$HERE/read-setting.sh" "$LIB/"
sed -e "s/@UID@/$(id -u "$U")/g" -e "s/@MEMORY_LIMITS@/$MEMORY_LIMITS/g" "$HERE/aukora-buzz.service" \
  | sudo install -m 0644 /dev/stdin /etc/systemd/system/aukora-buzz.service
sudo install -m 0644 "$HERE/aukora-buzz-watch.service" "$HERE/aukora-buzz-watch.timer" /etc/systemd/system/
sudo systemctl daemon-reload
echo "installed: user $U, state $ROOT, unit aukora-buzz.service (not started), port 127.0.0.1:${PORT}"
[ "$WITH_ADMISSION" = 0 ] || echo 'installed: aukora-admission.service (not enabled or started), port 127.0.0.1:3100; isolated owner.key still required'
