#!/bin/bash
# Peter YES 11:49 WITA: raise ONE owner card for release 77ee324 (plugin set). Raise only; Peter clicks.
set -euo pipefail
R=/opt/aukora-genesis/release-77ee324; L=/usr/local/lib/aukora-boundary
G="env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C /usr/bin/python3 -I -S $L/gate-bootstrap"
cd /tmp
O="sudo -u aukora-gate /opt/aukora-node/bin/node --no-warnings /opt/aukora-boundary-gate/bin/owner-cli.mjs"
echo "pending before:"; $O pending --socket /run/aukora-gate/owner.sock 2>&1 | grep -v base64 | head -5
SHOW=$($G approval show --release-dir $R 2>&1 | grep -viE "experimental|trace-warn|base64"); echo "$SHOW" | head -20
OP=$(echo "$SHOW" | awk '/^OPERATION/{print $2}'); REC=$(echo "$SHOW" | awk '/^RECORD/{print $2}')
[ -n "$OP" ] && [ -n "$REC" ] || { echo NO_OPERATION; exit 1; }
RAISE=$($G approval raise --release-dir $R --operation $OP 2>&1 | grep -viE "base64|experimental|trace-warn" || true); echo "$RAISE"
echo "pending after:"; $O pending --socket /run/aukora-gate/owner.sock 2>&1 | grep -v base64 | head -5
