#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Admission checks only: an operator-qualified producer must create the exact
# protected workspace binding before this script can accept a Ready sandbox.
# The pinned OpenShell producer provisions/uploads/chowns a managed workspace;
# reusing it for a host bind could overwrite or change the host workspace.
# Never snapshot/restore that volume into the registered workspace, recreate a
# mismatched sandbox, or adopt a new mount/process baseline from live inspect.
set -eu
bootstrap=0
if [ "$#" -ne 0 ]; then
  [ "$#" -eq 1 ] && [ "$1" = --bootstrap-profile ] || {
    echo "REFUSING: unsupported preparation arguments" >&2
    exit 2
  }
  bootstrap=1
fi
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export OPENSHELL_TELEMETRY_ENABLED=false
export OPENSHELL_LOCAL_TLS_DIR=$HOME/.local/state/openshell/tls
INVENTORY=/usr/local/lib/aukora-boundary/openshell/sandbox-inventory.py
[ -r "$INVENTORY" ] || {
  echo "REFUSING: sandbox inventory helper missing" >&2
  exit 5
}
if [ "$bootstrap" = 1 ]; then
  # Preparation validates only protected public schema/pin/range/registration
  # inputs. It neither creates a sandbox nor installs a profile or admission.
  /usr/bin/python3 -I -S "$INVENTORY" auma-ws bootstrap || {
    echo "REFUSING: reviewed generation inputs missing" >&2
    exit 7
  }
  echo "REFUSING: registered workspace requires a qualified mount producer and fresh reviewed inventory" >&2
  exit 7
fi
# Refuse missing custody before querying the backend. A profile cannot confer
# workspace DAC access, qualify identity mapping, or replace kernel readback.
/usr/bin/python3 -I -S "$INVENTORY" auma-ws profile || {
  echo "REFUSING: reviewed deployment profile or workspace registration missing" >&2
  exit 7
}
exec 9>>"$XDG_RUNTIME_DIR/aukora-sbx-exec.lock" || exit 7
/usr/bin/flock -w 30 9 || {
  echo "REFUSING: sandbox admission lock unavailable" >&2
  exit 7
}
/usr/bin/python3 -I -S "$INVENTORY" auma-ws check || {
  echo "REFUSING: registered workspace deployment inventory unavailable" >&2
  exit 7
}
