#!/bin/bash
set -e
S=f9c7a87; N=/opt/aukora-node/bin/node; G=/opt/aukora-boundary-gate
T=$(mktemp -d); tar -xzf ~/aukora-zip/gate-$S.tgz -C $T
sudo cp -a $G $G.bak-pre-$S
sudo cp -a /etc/systemd/system/aukora-genesis.service /etc/systemd/system/aukora-genesis.service.bak-pre-$S
sudo rsync -a --delete $T/packages/boundary-gate/ $G/
sudo chown -R root:root $G && sudo chmod -R go-w $G
rm -rf $T
sudo systemctl restart aukora-boundary-gate; for i in $(seq 1 30); do sudo test -S /run/aukora-gate/owner.sock && systemctl is-active -q aukora-boundary-gate && break; sleep 1; done; echo gate $(systemctl is-active aukora-boundary-gate); sudo journalctl -u aukora-boundary-gate --since "-1min" --no-pager | tail -3 | cut -c1-200
echo "--- trusted CLI from the fixed install (expect card):"
sudo env -i PATH=/usr/bin:/bin $N $G/bin/plugin-set-approval.mjs show --release-dir /opt/aukora-genesis/release-5f0601f 2>&1 | grep -v -i -E "experimental|trace-warnings"
. <(sudo cat /etc/aukora-genesis/release.env)
echo "--- floor check as aukora-host (expect OK):"
sudo -u aukora-host env -i PATH=/usr/bin:/bin $N $G/bin/release-floor.mjs check --release-dir $AUKORA_RELEASE_DIR --approval-state-root $AUKORA_APPROVAL_ROOT 2>&1 | grep -v -i -E "experimental|trace-warnings"
echo "--- preload refused (expect REFUSED trusted-node-environment):"
sudo env -i PATH=/usr/bin:/bin NODE_OPTIONS=--no-warnings $N $G/bin/plugin-set-approval.mjs show --release-dir /opt/aukora-genesis/release-5f0601f 2>&1 | grep -o "REFUSED.*" || true
echo "--- checkout copy refused (expect REFUSED trusted-entrypoint):"
C=$(mktemp -d); sudo cp -a $G/bin $C/; sudo env -i PATH=/usr/bin:/bin $N $C/bin/plugin-set-approval.mjs show --release-dir /opt/aukora-genesis/release-5f0601f 2>&1 | grep -o "REFUSED.*" || true; sudo rm -rf $C
sudo install -m 0644 -o root -g root $G/host/systemd/aukora-genesis.service /etc/systemd/system/aukora-genesis.service
sudo systemctl daemon-reload
cmp /etc/systemd/system/aukora-genesis.service $G/host/systemd/aukora-genesis.service && echo UNIT-IDENTICAL-TO-MAIN
sudo systemctl stop aukora-genesis
for i in $(seq 1 40); do n=$(ss -tan | grep -c ":18735 " || true); [ "$n" = 0 ] && break; sleep 2; done; echo drained $n
T0=$(date -u +"%Y-%m-%d %H:%M:%S"); sudo systemctl start aukora-genesis
for i in $(seq 1 60); do sudo journalctl -u aukora-genesis --since "$T0" --no-pager | grep -q "launcher: AUKORA plugin set ENFORCE" && break; sleep 3; done
sudo journalctl -u aukora-genesis --since "$T0" --no-pager | grep -v "systemd\[1\]" | grep -E "release-floor|selfcheck: PASSED|plugin set ENFORCE|REFUSED|rror" | cut -c1-200 | tail -5
systemctl is-active aukora-genesis
