#!/usr/bin/env bash
# Record verified closure and failed attempts; only explicit reopen clears closure intent.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
U=aukora-buzz
ROOT=/var/lib/aukora-buzz
OWNER='' KEY_FILE=''
MODE=close
ARGS=("$@")
refuse() { echo "buzz-close:$1" >&2; exit 1; }
case "${1:-}" in
  --reopen|--acknowledge|--acknowledge-open) [ $# = 1 ] || refuse invalid-input; MODE="${1#--}"; shift ;;
esac
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || refuse invalid-input
  case "$1" in
    --owner-pubkey) [ -z "$OWNER" ] || refuse invalid-input; OWNER="$2" ;;
    --key-file) [ -z "$KEY_FILE" ] || refuse invalid-input; KEY_FILE="$2" ;;
    *) refuse invalid-input ;;
  esac
  shift 2
done
if [ "$MODE" = close ]; then
  [[ "$OWNER" =~ ^[0-9a-fA-F]{64}$ && "$KEY_FILE" = /* ]] || refuse owner-and-door-key-required
fi
OWNER=$(printf %s "$OWNER" | tr 'A-F' 'a-f')
NODE=$(command -v node) || refuse node-required
[ "$(id -u)" = 0 ] || exec sudo env PATH="$PATH" bash "$HERE/close.sh" "${ARGS[@]}"
# The lock is outside service-owned state; no stale lock survives a process exit.
umask 077
exec 9>/run/aukora-buzz-close.lock
flock -n 9 || refuse already-running
write_marker() {
  "$NODE" --input-type=module - "$ROOT" "$1" 2>/dev/null <<'JS'
import { openSync, writeFileSync, fchownSync, fchmodSync, fsyncSync, closeSync, renameSync, rmSync, constants } from 'node:fs'
import { randomUUID } from 'node:crypto'
const root = process.argv[2], marker = process.argv[3], next = `${root}/.close-marker.${randomUUID()}`
let fd
try {
  fd = openSync(next, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)
  writeFileSync(fd, marker + '\n')
  fchownSync(fd, 0, 0)
  fchmodSync(fd, 0o600)
  fsyncSync(fd)
  closeSync(fd); fd = undefined
  renameSync(next, `${root}/${marker}`)
  fd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY)
  fsyncSync(fd)
} finally {
  if (fd !== undefined) closeSync(fd)
  rmSync(next, { force: true })
}
JS
}
if [ "$MODE" = acknowledge ]; then
  rm -f "$ROOT/close-failed" || refuse acknowledgement-failed
  echo 'PASS close-failed acknowledged; closure intent unchanged'
  exit 0
fi
PORT=$(sudo -u "$U" cat "$ROOT/node.env" | bash "$HERE/read-setting.sh" PORT) || refuse invalid-port
write_intent() {
  sudo -u "$U" bash -s -- "$ROOT" "$PORT" "$1" <<'EOS'
set -euo pipefail
umask 077
NEXT=$(mktemp "$1/.node.env.XXXXXX")
trap 'rm -f "$NEXT"' EXIT
printf 'PORT=%s\nINTENDED_MEMBERSHIP=%s\n' "$2" "$3" > "$NEXT"
chmod 0600 "$NEXT"
mv -f "$NEXT" "$1/node.env"
EOS
}
if [ "$MODE" = acknowledge-open ]; then
  write_intent open-acknowledged || refuse open-acknowledgement-failed
  echo 'PASS INTENDED_MEMBERSHIP=open-acknowledged; relay settings and closure alarms unchanged'
  exit 0
fi
if [ "$MODE" = reopen ]; then
  sudo -u "$U" test ! -e "$ROOT/close-pending" || refuse close-pending
  sudo -u "$U" bash -s -- "$ROOT" <<'EOS' || refuse reopen-settings-failed
set -euo pipefail
umask 077
NEXT=$(mktemp "$1/.relay.reopen.XXXXXX")
trap 'rm -f "$NEXT"' EXIT
sed '/^RELAY_OWNER_PUBKEY=/d; /^BUZZ_REQUIRE_RELAY_MEMBERSHIP=/d' "$1/relay.env" > "$NEXT"
chmod 0600 "$NEXT"
mv -f "$NEXT" "$1/relay.env"
EOS
  sudo systemctl restart aukora-buzz.service >/dev/null 2>&1 || refuse reopen-restart-failed
  write_intent open-acknowledged || refuse reopen-intent-failed
  rm -f "$ROOT/closed" || refuse reopen-marker-failed
  echo 'PASS explicit reopen; closed intent removed; any close-failed still needs --acknowledge'
  exit 0
fi
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
    write_marker close-failed || echo 'buzz-close:close-failed-marker-failed' >&2
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
        echo 'buzz-close:settings-restored; unit restarted; startup membership writes retained; keep the door disabled' >&2
      else
        echo 'buzz-close:rollback-restart-failed; admin must restart aukora-buzz.service; keep the door disabled' >&2
      fi
    else
      echo 'buzz-close:rollback-settings-failed; admin must restore the saved relay.env; keep the door disabled' >&2
    fi
    if RESULT=$("$NODE" "$HERE/member.mjs" verify-closed --relay "http://localhost:$PORT" 2>/dev/null); then
      echo 'buzz-close:relay is CLOSED (unauthenticated and non-member HTTP probes)' >&2
    elif printf '%s' "$RESULT" | "$NODE" --input-type=module -e '
      import { readFileSync } from "node:fs"
      try { const result = JSON.parse(readFileSync(0, "utf8")); process.exit(result.state === "OPEN" ? 0 : 1) } catch { process.exit(1) }
    '; then
      echo 'buzz-close:relay is OPEN; keep the door disabled' >&2
    else
      echo 'buzz-close:relay state UNKNOWN; closure not proved; keep the door disabled' >&2
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
write_intent closed || refuse closed-intent-failed
sudo -u "$U" rm -f "$PENDING" || refuse pending-cleanup-failed
rm -f "$ROOT/close-failed" || refuse failure-marker-cleanup-failed
write_marker closed || refuse closed-marker-failed
trap - EXIT HUP INT TERM
printf 'PASS closed (unauthenticated and non-member refused by /query and /events). Backup: %s\n' "$BACKUP"
cat <<'MSG'
Channels, messages and existing channel roles are retained. The configured owner is bootstrapped into relay_members at startup; do not add that owner again.
Existing channel members need relay admission too. The channel creator retains its channel-owner role; a different relay owner does not inherit channel authority.
Source: aukora-buzz PIN 9def3e9, crates/buzz-relay/src/main.rs:446-491; crates/buzz-db/src/store/relay_members.rs:501-520,800-850; crates/buzz-db/src/store/channel.rs:148-163; crates/buzz-relay/src/handlers/channel_authz.rs:119-155.
On your OWN machine, keep your owner key there. Copy only agent.pubkey from the backup above, set OWNER_KEY_FILE to your isolated owner key file, CHANNEL_UUID to the existing channel, and RELAY_HTTP to your loopback tunnel URL (normally http://localhost:3000). In the Prime checkout run:
AGENT_PUBKEY="$(cat agent.pubkey)"
node ops/buzz-relay/member.mjs add --key-file "$OWNER_KEY_FILE" --pubkey "$AGENT_PUBKEY" --role member --relay "$RELAY_HTTP"
node ops/buzz-relay/member.mjs put-user --key-file "$OWNER_KEY_FILE" --pubkey "$AGENT_PUBKEY" --channel "$CHANNEL_UUID" --role bot --relay "$RELAY_HTTP"
Use the channel creator's key, or a key with that channel's permission, for put-user. Relay ownership alone is insufficient.
This checks HTTP refusals, not WebSocket admission, restored backups or harness wake containment. Keep the door disabled until owner membership commands and channel access are checked.
MSG
