#!/usr/bin/env bash
# Called before install changes anything. A matching username or stale pod mapping alone is not ownership.
set -euo pipefail
PORT="${1:?usage: check-port.sh PORT}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=$(printf 'PORT=%s\n' "$PORT" | bash "$HERE/read-setting.sh" PORT)
refuse() { echo "port $PORT is in use or ownership cannot be verified; stop its listener before installing" >&2; exit 1; }
LISTEN=$(sudo ss -ltnpH "sport = :$PORT") || refuse
[ -n "$LISTEN" ] || exit 0
UID_BUZZ=$(id -u aukora-buzz 2>/dev/null) || refuse
[[ "$UID_BUZZ" =~ ^[0-9]+$ ]] || refuse
pod() { sudo -u aukora-buzz -H env XDG_RUNTIME_DIR="/run/user/$UID_BUZZ" timeout 10s podman "$@"; }
PUB=$(pod pod inspect aukora-buzz --format '{{range $k, $v := .InfraConfig.PortBindings}}{{range $v}}{{.HostIP}}:{{.HostPort}}->{{$k}} {{end}}{{end}}' 2>/dev/null) || refuse
[ "$PUB" = "127.0.0.1:${PORT}->3000/tcp " ] || refuse
INFRA=$(pod pod inspect aukora-buzz --format '{{.InfraContainerID}}' 2>/dev/null) || refuse
[[ "$INFRA" =~ ^[0-9a-f]{64}$ ]] || refuse
CONMON=$(pod inspect "$INFRA" --format '{{.State.ConmonPid}}' 2>/dev/null) || refuse
[[ "$CONMON" =~ ^[1-9][0-9]*$ ]] || refuse
while IFS= read -r line; do
  [ "$(printf '%s\n' "$line" | awk '{print $4}')" = "127.0.0.1:$PORT" ] || refuse
  PIDS=$(printf '%s\n' "$line" | grep -oE 'pid=[0-9]+' | cut -d= -f2) || refuse
  [ -n "$PIDS" ] || refuse
  for pid in $PIDS; do
    [ "$(sudo stat -c %u "/proc/$pid" 2>/dev/null)" = "$UID_BUZZ" ] || refuse
    # Rootlessport/slirp4netns inherit fd 3, the exit pipe whose other end belongs to this infra conmon.
    # This links the actual listening process to this pod, even if an unrelated listener has the same uid.
    sudo bash -s -- "$pid" "$CONMON" <<'EOS' || refuse
set -euo pipefail
pipe=$(readlink "/proc/$1/fd/3")
[[ "$pipe" =~ ^pipe:\[[0-9]+\]$ ]] || exit 1
for fd in /proc/"$2"/fd/*; do
  [ "$(readlink "$fd" 2>/dev/null)" != "$pipe" ] || exit 0
done
exit 1
EOS
  done
done <<< "$LISTEN"
