#!/bin/sh
# Boot a private clone with pinned inputs and real temporary approval.
set -eu
if ! command -v python3 >/dev/null 2>&1; then
    printf 'UNPERFORMED: python3-unavailable\nTOTAL 0.00s | UNPERFORMED\n'
    exit 2
fi
fresh_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -B "$fresh_root/fresh-clone-driver.py" "$@"
