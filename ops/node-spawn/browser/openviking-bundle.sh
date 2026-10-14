#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build a Linux x86_64 offline bundle from the repository's artifact pins.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
exec python3 -I -S -B "$REPO/ops/node-spawn/browser/openviking-bundle.py" "$@"
