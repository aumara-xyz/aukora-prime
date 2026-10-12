#!/usr/bin/env bash
# Run as aukora-buzz. Keep the original credentials authoritative across reinstalls and existing data.
set -euo pipefail
cd "${1:?usage: prepare-secrets.sh STATE_DIRECTORY}"
umask 077
have=0; for f in postgres.env redis.env relay-secrets.env; do [ -s "$f" ] && have=$((have + 1)); done
if [ "$have" != 0 ] && [ "$have" != 3 ]; then echo "incomplete secret files; not regenerating" >&2; exit 1; fi
if [ "$have" = 0 ]; then
  # Replacing a lost password beside initialized databases would strand their existing data.
  for data in data/postgres data/redis; do
    if [ -L "$data" ]; then
      echo "cannot inspect symlinked database data; restore the original secrets" >&2; exit 1
    fi
    if [ -e "$data" ]; then
      contents=$(find "$data" -mindepth 1 -print -quit 2>/dev/null) || {
        echo "cannot inspect database data; restore the original secrets" >&2; exit 1;
      }
      if [ -n "$contents" ]; then
        echo "database data exists without secret files; restore the original secrets" >&2; exit 1
      fi
    fi
  done
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
# Never source service-owned files. Original installs generated precisely 48 lowercase hex characters.
password() {
  local key="$1" file="$2" value="" line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="*)
        [ -z "$value" ] || { echo "duplicate database password setting" >&2; return 1; }
        value="${line#*=}"
        [[ "$value" =~ ^[0-9a-f]{48}$ ]] || { echo "invalid database password setting" >&2; return 1; }
        ;;
    esac
  done < "$file"
  [ -n "$value" ] || { echo "missing database password setting" >&2; return 1; }
  printf %s "$value"
}
PG=$(password POSTGRES_PASSWORD postgres.env)
RD=$(password REDIS_PASSWORD redis.env)
chmod 0600 postgres.env redis.env relay-secrets.env
mkdir -p secrets
chmod 0700 secrets
# The host directory is private; 0444 files let the images' unprivileged database users read the mounts.
# Atomic replacement also leaves a running container's existing read-only mount intact until restart.
pg_tmp=$(mktemp secrets/.postgres.XXXXXX)
redis_tmp=$(mktemp secrets/.redis.XXXXXX)
trap 'rm -f "$pg_tmp" "$redis_tmp"' EXIT
printf '%s\n' "$PG" > "$pg_tmp"
printf 'appendonly yes\nrequirepass %s\n' "$RD" > "$redis_tmp"
chmod 0444 "$pg_tmp" "$redis_tmp"
mv -f "$pg_tmp" secrets/postgres-password
mv -f "$redis_tmp" secrets/redis.conf
