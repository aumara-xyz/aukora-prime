#!/bin/zsh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
cd -- "${0:A:h}"
configuration="${PRIME_PILOT_CONFIG:-${0:A:h}/.runtime/pilot.json}"
if [[ ! -f "$configuration" ]]; then configuration="${PRIME_PILOT_CONFIG:-$HOME/.config/aukora-prime/pilot.json}"; fi
for executable in "${PRIME_NODE_BIN:-}" /opt/homebrew/bin/node /usr/local/bin/node; do
 if [[ -n "$executable" && -x "$executable" ]]; then
  exec "$executable" pilot-launch.cjs "$configuration"
 fi
done
exec /usr/bin/env node pilot-launch.cjs "$configuration"
