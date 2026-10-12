#!/usr/bin/env bash
# Back up before closing; restore settings and restart if closure is not proved.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
U=aukora-buzz
ROOT=/var/lib/aukora-buzz
OWNER='' KEY_FILE=''
refuse() { echo "buzz-close:$1" >&2; exit 1; }
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || refuse invalid-input
  case "$1" in
    --owner-pubkey) [ -z "$OWNER" ] || refuse invalid-input; OWNER="$2" ;;
    --key-file) [ -z "$KEY_FILE" ] || refuse invalid-input; KEY_FILE="$2" ;;
    *) refuse invalid-input ;;
  esac
  shift 2
done
[[ "$OWNER" =~ ^[0-9a-fA-F]{64}$ && "$KEY_FILE" = /* ]] || refuse owner-and-door-key-required
OWNER=$(printf %s "$OWNER" | tr 'A-F' 'a-f')
NODE=$(command -v node) || refuse node-required
[ "$(id -u)" = 0 ] || exec sudo env PATH="$PATH" bash "$HERE/close.sh" --owner-pubkey "$OWNER" --key-file "$KEY_FILE"
# The lock is outside service-owned state; no stale lock survives a process exit.
umask 077
exec 9>/run/aukora-buzz-close.lock
flock -n 9 || refuse already-running
KEY_USER=$(stat -c %U "$KEY_FILE" 2>/dev/null) || refuse door-key-required
AGENT=$(sudo -u "$KEY_USER" -H "$NODE" --input-type=module - "$HERE" "$KEY_FILE" 2>/dev/null <<'JS'
import { pathToFileURL } from 'node:url'
const here = pathToFileURL(process.argv[2] + '/')
const { loadKey } = await import(new URL('../../plugins/aukora-buzz-door/lib/index.mjs', here))
const { publicKeyOf } = await import(new URL('../../plugins/aukora-nostr/lib/event.mjs', here))
process.stdout.write(publicKeyOf(loadKey(process.argv[3])))
JS
) || refuse invalid-door-key
[[ "$AGENT" =~ ^[0-9a-f]{64}$ ]] || refuse invalid-door-key
PORT=$(sudo -u "$U" cat "$ROOT/node.env" | bash "$HERE/read-setting.sh" PORT) || refuse invalid-port
EXISTING=$(sudo -u "$U" sed -n 's/^RELAY_OWNER_PUBKEY=//p' "$ROOT/relay.env") || refuse settings-unavailable
[[ -z "$EXISTING" || "$EXISTING" = "$OWNER" ]] || refuse different-owner
UID_BUZZ=$(id -u "$U") || refuse service-account-required
pod() { (cd / && sudo -u "$U" -H env XDG_RUNTIME_DIR="/run/user/$UID_BUZZ" timeout 120s podman "$@"); }
PUB=$(pod pod inspect aukora-buzz --format '{{range $k, $v := .InfraConfig.PortBindings}}{{range $v}}{{.HostIP}}:{{.HostPort}}->{{$k}} {{end}}{{end}}' 2>/dev/null) || refuse pod-unavailable
[ "$PUB" = "127.0.0.1:${PORT}->3000/tcp " ] || refuse loopback-required
# A pending snapshot survives an interrupted restart even when Postgres is no longer running.
PENDING="$ROOT/close-pending"
if sudo -u "$U" test -e "$PENDING"; then
  SAVED=$(sudo -u "$U" cat "$PENDING") || refuse invalid-pending-backup
  [[ "$SAVED" =~ ^close-backup\.[a-zA-Z0-9]{6}$ ]] || refuse invalid-pending-backup
  BACKUP="$ROOT/$SAVED"
  sudo -u "$U" test -s "$BACKUP/relay.env" && sudo -u "$U" test -s "$BACKUP/relay.dump" || refuse invalid-pending-backup
  [ "$(sudo -u "$U" cat "$BACKUP/owner.pubkey")" = "$OWNER" ] || refuse pending-owner-mismatch
  [ "$(sudo -u "$U" cat "$BACKUP/agent.pubkey")" = "$AGENT" ] || refuse pending-agent-mismatch
else
  BACKUP=$(sudo -u "$U" mktemp -d "$ROOT/close-backup.XXXXXX") || refuse backup-failed
  sudo -u "$U" bash -s -- "$ROOT" "$BACKUP" "$UID_BUZZ" >/dev/null 2>&1 <<'EOS' || refuse backup-failed
set -euo pipefail
umask 077
cd "$1"
cp "$1/relay.env" "$2/relay.env"
chmod 0600 "$2/relay.env"
export XDG_RUNTIME_DIR="/run/user/$3"
timeout 120s podman exec buzz-postgres pg_dump -U buzz -d buzz --format=custom > "$2/relay.dump.partial"
test -s "$2/relay.dump.partial"
chmod 0600 "$2/relay.dump.partial"
mv "$2/relay.dump.partial" "$2/relay.dump"
EOS
  printf '%s\n' "$AGENT" | sudo -u "$U" sh -c 'umask 077; cat > "$1/agent.pubkey"' sh "$BACKUP" || refuse backup-failed
  printf '%s\n' "$OWNER" | sudo -u "$U" sh -c 'umask 077; cat > "$1/owner.pubkey"' sh "$BACKUP" || refuse backup-failed
  printf '%s\n' "${BACKUP##*/}" | sudo -u "$U" sh -c 'umask 077; cat > "$1/close-pending.next" && mv "$1/close-pending.next" "$1/close-pending"' sh "$ROOT" || refuse backup-failed
fi
printf 'Saved pre-change environment and logical dump: %s\n' "$BACKUP"
rollback() {
  code=$?
  trap - EXIT HUP INT TERM
  if [ "$code" != 0 ]; then
    if sudo -u "$U" bash -s -- "$ROOT" "$BACKUP" >/dev/null 2>&1 <<'EOS'
set -euo pipefail
umask 077
NEXT=$(mktemp "$1/.relay.restore.XXXXXX")
cp "$2/relay.env" "$NEXT"
chmod 0600 "$NEXT"
mv -f "$NEXT" "$1/relay.env"
EOS
    then
      if sudo systemctl restart aukora-buzz.service >/dev/null 2>&1; then
        sudo -u "$U" rm -f "$PENDING" || echo 'buzz-close:pending-cleanup-failed' >&2
        echo 'buzz-close:settings-restored; unit restarted; startup membership writes retained; previous relay may be OPEN; keep the door disabled' >&2
      else
        echo 'buzz-close:rollback-restart-failed; admin must restart aukora-buzz.service; keep the door disabled' >&2
      fi
    else
      echo 'buzz-close:rollback-settings-failed; admin must restore the saved relay.env; keep the door disabled' >&2
    fi
  fi
  exit "$code"
}
trap rollback EXIT
trap 'exit 1' HUP INT TERM
sudo -u "$U" bash "$HERE/write-settings.sh" "$ROOT" "$OWNER" >/dev/null 2>&1 || refuse settings-failed
sudo systemctl restart aukora-buzz.service >/dev/null 2>&1 || refuse restart-failed
healthy=0
for _ in $(seq 1 60); do
  if curl --connect-timeout 2 --max-time 5 -sf -o /dev/null "http://127.0.0.1:${PORT}/health"; then healthy=1; break; fi
  sleep 1
done
[ "$healthy" = 1 ] || refuse health-timeout
"$NODE" "$HERE/member.mjs" verify-closed --relay "http://localhost:$PORT" >/dev/null 2>&1 || refuse closed-not-proved
sudo -u "$U" rm -f "$PENDING" || refuse pending-cleanup-failed
trap - EXIT HUP INT TERM
printf 'PASS closed (non-member refused by /query and /events). Backup: %s\n' "$BACKUP"
cat <<'MSG'
Channels, messages and existing channel roles are retained. The configured owner is bootstrapped into relay_members at startup; do not add that owner again.
Existing channel members need relay admission too. The channel creator retains its channel-owner role; a different relay owner does not inherit channel authority.
Source: aukora-buzz PIN 9def3e9, crates/buzz-relay/src/main.rs:446-491; crates/buzz-db/src/store/relay_members.rs:501-520,800-850; crates/buzz-db/src/store/channel.rs:148-163; crates/buzz-relay/src/handlers/channel_authz.rs:119-155.
On your OWN machine, keep your owner key there. Copy only agent.pubkey from the backup above, set OWNER_KEY_FILE to your isolated owner key file, CHANNEL_UUID to the existing channel, and RELAY_HTTP to your loopback tunnel URL (normally http://localhost:3000). In the Prime checkout run:
AGENT_PUBKEY="$(cat agent.pubkey)"
node ops/buzz-relay/member.mjs add --key-file "$OWNER_KEY_FILE" --pubkey "$AGENT_PUBKEY" --role member --relay "$RELAY_HTTP"
node ops/buzz-relay/member.mjs put-user --key-file "$OWNER_KEY_FILE" --pubkey "$AGENT_PUBKEY" --channel "$CHANNEL_UUID" --role bot --relay "$RELAY_HTTP"
Use the channel creator's key, or a key with that channel's permission, for put-user. Relay ownership alone is insufficient.
This checks two HTTP refusals, not WebSocket admission, restored backups or harness wake containment. Keep the door disabled until owner membership commands and channel access are checked.
MSG
