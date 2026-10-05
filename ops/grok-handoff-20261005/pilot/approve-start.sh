#!/bin/bash
set -euo pipefail
C=$1; S=${C:0:7}; R=/opt/aukora-genesis/release-$S
G="python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap"
OP=$($G approval show --release-dir $R 2>/dev/null | awk '/^OPERATION/{print $2}')
REC=$($G approval show --release-dir $R 2>/dev/null | awk '/^RECORD/{print $2}')
echo OP=$OP REC=$REC
RAISE=$($G approval raise --release-dir $R --operation $OP 2>&1 | grep -v base64 || true); echo "$RAISE" | grep -E "PENDING|refused|Error" || true
ID=$(echo "$RAISE" | awk '/^PENDING/{print $2}'); [ -n "$ID" ]
cd /tmp; O="sudo -u aukora-gate /opt/aukora-node/bin/node --no-warnings /opt/aukora-boundary-gate/bin/owner-cli.mjs"
LINE=$($O pending --socket /run/aukora-gate/owner.sock 2>&1 | grep "^${ID:0:8} " | head -1); echo "PENDING: $LINE"; NEW=$(echo "$LINE" | awk '{print $6}')
echo "approve $ID $NEW"
$O approve $ID $NEW --socket /run/aukora-gate/owner.sock 2>&1 | grep -v base64 | tail -2
mkdir -p /etc/aukora-approvals/$C/state
$G approval install --release-dir $R --operation $OP --out /etc/aukora-approvals/$C/state/gate-state 2>&1 | grep -E "INSTALLED|FLOOR|refused|Error" | grep -v base64
cat > /etc/aukora-genesis/release.env <<EOT
AUKORA_RELEASE_DIR=$R
AUKORA_APPROVAL_ROOT=/etc/aukora-approvals/$C/state
AUKORA_RECORD_SHA=$REC
EOT
cat /etc/aukora-genesis/release.env
