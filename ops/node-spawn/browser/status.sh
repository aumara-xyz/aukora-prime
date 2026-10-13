#!/usr/bin/env bash
# Read the installed package, floor and service status.
set -euo pipefail
umask 022
for name in NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT; do
  ! declare -p "$name" >/dev/null 2>&1 || { printf 'REFUSED BROWSER_PRELOAD_FORBIDDEN\n' >&2; exit 1; }
done
here=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)
exec /usr/bin/python3 -I -S -B "$here/node.py" status "$@"
