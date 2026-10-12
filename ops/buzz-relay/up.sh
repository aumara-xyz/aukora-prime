#!/usr/bin/env bash
# Start Postgres, Redis and the Buzz relay in one rootless pod. Run as aukora-buzz (the unit does).
# One pod because this node's Podman has no container DNS: the three reach each other on the pod's localhost.
# The only port published to the machine is the relay, on 127.0.0.1.
set -euo pipefail
# No login session exists for this user; point Podman at the lingering user manager, as the node's other
# rootless Podman service does.
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
ROOT=/var/lib/aukora-buzz
POD=aukora-buzz
cd "$ROOT"
. "$ROOT/node.env"
. "$ROOT/image.env"

podman pod exists "$POD" || podman pod create --name "$POD" -p "127.0.0.1:${PORT}:3000" >/dev/null

run() {
  local name="$1"; shift
  if podman container exists "$name"; then podman start "$name" >/dev/null
  else podman run -d --pod "$POD" --name "$name" --restart=on-failure "$@" >/dev/null; fi
}

run buzz-postgres --env-file "$ROOT/postgres.env" \
  -v "$ROOT/data/postgres:/var/lib/postgresql/data" docker.io/library/postgres:17-alpine
# Redis reads its settings from stdin so the password is never in a process's arguments.
run buzz-redis --env-file "$ROOT/redis.env" -v "$ROOT/data/redis:/data" docker.io/library/redis:7-alpine \
  sh -c 'printf "appendonly yes\nrequirepass %s\n" "$REDIS_PASSWORD" | exec redis-server -'

for _ in $(seq 1 60); do
  podman exec buzz-postgres pg_isready -U buzz -d buzz >/dev/null 2>&1 && break
  sleep 1
done
podman exec buzz-postgres pg_isready -U buzz -d buzz >/dev/null

run buzz-relay --env-file "$ROOT/relay.env" --env-file "$ROOT/relay-secrets.env" \
  -v "$ROOT/data/git:/data/git:U" "$IMAGE"

for _ in $(seq 1 90); do
  curl -sf -o /dev/null "http://127.0.0.1:${PORT}/health" && { echo "relay answering on 127.0.0.1:${PORT}"; exit 0; }
  sleep 1
done
echo "relay did not answer on 127.0.0.1:${PORT} within 90s" >&2
podman logs --tail 40 buzz-relay >&2 || true
exit 1
