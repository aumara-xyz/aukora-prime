#!/usr/bin/env bash
# Start Postgres, Redis and the Buzz relay in one rootless pod. Run as aukora-buzz (the unit does).
# One pod because this node's Podman has no container DNS: the three reach each other on the pod's localhost.
# The only port published to the machine is the relay, on 127.0.0.1.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# No login session exists for this user; point Podman at the lingering user manager, as the node's other
# rootless Podman service does.
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
ROOT=/var/lib/aukora-buzz
POD=aukora-buzz
cd "$ROOT"
PORT=$(bash "$HERE/read-setting.sh" PORT < "$ROOT/node.env")
IMAGE=$(bash "$HERE/read-setting.sh" IMAGE < "$ROOT/image.env")
MEMORY_LIMITS="${AUKORA_BUZZ_MEMORY_LIMITS:-0}"
[[ "$MEMORY_LIMITS" =~ ^[01]$ ]] || { echo "AUKORA_BUZZ_MEMORY_LIMITS must be 0 or 1" >&2; exit 2; }
for secret in postgres-password redis.conf; do
  [ -f "$ROOT/secrets/$secret" ] && [ -r "$ROOT/secrets/$secret" ] || {
    echo "database credential mounts are missing; run install.sh before starting" >&2; exit 1;
  }
done

podman pod exists "$POD" || podman pod create --name "$POD" -p "127.0.0.1:${PORT}:3000" >/dev/null
# A pod left from an earlier setting must publish exactly this loopback port, or we do not start in it.
PUB=$(podman pod inspect "$POD" --format '{{range $k, $v := .InfraConfig.PortBindings}}{{range $v}}{{.HostIP}}:{{.HostPort}}->{{$k}} {{end}}{{end}}')
[ "$PUB" = "127.0.0.1:${PORT}->3000/tcp " ] || { echo "pod $POD publishes '$PUB', expected 127.0.0.1:${PORT}->3000/tcp; remove the pod and start again" >&2; exit 1; }

run() {
  local name="$1" memory="$2"; shift 2
  if [ "$MEMORY_LIMITS" = 1 ]; then set -- --memory "$memory" "$@"; fi
  # Recreate containers so restart policy and limits also replace old settings; data stays in mounts.
  if podman container exists "$name"; then podman rm -f "$name" >/dev/null; fi
  podman run -d --pod "$POD" --name "$name" --restart=always "$@" >/dev/null
}

run buzz-postgres 1g --env POSTGRES_DB=buzz --env POSTGRES_USER=buzz \
  --env PGDATA=/var/lib/postgresql/data/pgdata --env POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password \
  -v "$ROOT/secrets/postgres-password:/run/secrets/postgres-password:ro" \
  -v "$ROOT/data/postgres:/var/lib/postgresql/data" docker.io/library/postgres:17-alpine
# Redis reads a read-only config; neither its configured environment nor its argv contains the password.
run buzz-redis 256m -v "$ROOT/secrets/redis.conf:/run/secrets/redis.conf:ro" \
  -v "$ROOT/data/redis:/data" docker.io/library/redis:7-alpine redis-server /run/secrets/redis.conf

for _ in $(seq 1 60); do
  timeout 10s podman exec buzz-postgres pg_isready -U buzz -d buzz >/dev/null 2>&1 && break
  sleep 1
done
timeout 10s podman exec buzz-postgres pg_isready -U buzz -d buzz >/dev/null
redis_ready() {
  [ "$(timeout 10s podman exec buzz-redis sh -c '{ printf "AUTH "; sed -n "s/^requirepass //p" /run/secrets/redis.conf; printf "PING\n"; } | redis-cli --raw | tail -n 1' 2>/dev/null)" = PONG ]
}
for _ in $(seq 1 60); do
  redis_ready && break
  sleep 1
done
redis_ready || { echo "Redis did not become ready after 60 attempts" >&2; exit 1; }

# The relay keeps no state of its own in the container; make it fresh so a changed setting or image takes effect.
run buzz-relay 1g --env-file "$ROOT/relay.env" --env-file "$ROOT/relay-secrets.env" \
  -v "$ROOT/data/git:/data/git:U" "$IMAGE"

for _ in $(seq 1 90); do
  curl --connect-timeout 2 --max-time 5 -sf -o /dev/null "http://127.0.0.1:${PORT}/health" && { echo "relay answering on 127.0.0.1:${PORT}"; exit 0; }
  sleep 1
done
echo "relay did not answer on 127.0.0.1:${PORT} after 90 attempts" >&2
exit 1
