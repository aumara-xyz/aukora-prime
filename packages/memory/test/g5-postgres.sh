#!/bin/sh
# Disposable synthetic cluster only. No system service, TCP listener, credentials or system users.
set -eu
if [ -z "${PRIME_MEMORY_POSTGRES_BINDIR:-}" ]; then
  echo 'UNPERFORMED G5: set PRIME_MEMORY_POSTGRES_BINDIR to an existing approved official PostgreSQL bin directory.' >&2
  exit 2
fi
for task_pg_binary in initdb pg_ctl postgres; do
  if [ ! -x "$PRIME_MEMORY_POSTGRES_BINDIR/$task_pg_binary" ]; then
    echo 'UNPERFORMED G5: official PostgreSQL initdb/pg_ctl/postgres closure is unavailable.' >&2
    exit 2
  fi
done
if ! node --input-type=module -e 'await import("pg")' >/dev/null 2>&1; then
  echo 'UNPERFORMED G5: the Prime-owned node-postgres (pg) Pool dependency is unavailable.' >&2
  exit 2
fi
task_pg_root=$(mktemp -d /tmp/prime-memory-pg.XXXXXX)
task_pg_cleanup() {
  "$PRIME_MEMORY_POSTGRES_BINDIR/pg_ctl" -D "$task_pg_root/data" -m fast -w -t 30 stop >/dev/null 2>&1 || true
  rm -rf "$task_pg_root"
}
trap task_pg_cleanup EXIT HUP INT TERM
mkdir "$task_pg_root/socket"
chmod 700 "$task_pg_root" "$task_pg_root/socket"
printf 'prime-memory-synthetic-v1\n' > "$task_pg_root/.prime-memory-owned-synthetic"
"$PRIME_MEMORY_POSTGRES_BINDIR/initdb" --no-locale --encoding=UTF8 -A trust -D "$task_pg_root/data" >/dev/null
"$PRIME_MEMORY_POSTGRES_BINDIR/pg_ctl" -D "$task_pg_root/data" -l "$task_pg_root/server.log" \
  -o "-h '' -k $task_pg_root/socket -p 55434 -c fsync=on -c full_page_writes=on -c synchronous_commit=on" -w -t 30 start >/dev/null
export PRIME_MEMORY_DISPOSABLE_SOCKET_DIR="$task_pg_root/socket"
export PRIME_MEMORY_DISPOSABLE_DATA_DIR="$task_pg_root/data"
node --test "$(dirname "$0")/memory.test.mjs"
