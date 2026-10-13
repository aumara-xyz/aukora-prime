#!/bin/sh
# Export only checked public evidence into a new private directory.
set -eu
umask 077
unset NODE_OPTIONS NODE_PATH
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec node "$SCRIPT_DIR/export-pilot-evidence.mjs" "$@"
