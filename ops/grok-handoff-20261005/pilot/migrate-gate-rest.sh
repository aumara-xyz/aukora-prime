#!/bin/bash
set -euo pipefail
S=0e11c37; N=/opt/aukora-node/bin/node; G=/opt/aukora-boundary-gate; E=/etc/aukora-boundary-gate
CLEAN="env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C"
P=/opt/aukora-boundary-gate
. <(sudo cat /etc/aukora-genesis/release.env)
sudo sed s/SKGATE_GID/1003/ $P/host/systemd/aukora-boundary-gate.service | sudo tee /etc/systemd/system/aukora-boundary-gate.service >/dev/null
sudo install -o root -g root -m 0644 $P/host/systemd/aukora-genesis.service /etc/systemd/system/aukora-genesis.service
sudo systemctl daemon-reload
echo "== 4 check-package, restart gate"
sudo $CLEAN /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package
sudo systemctl start aukora-boundary-gate; for i in $(seq 1 30); do sudo test -S /run/aukora-gate/owner.sock && systemctl is-active -q aukora-boundary-gate && break; sleep 1; done
echo "gate $(systemctl is-active aukora-boundary-gate) pid $(systemctl show -p MainPID --value aukora-boundary-gate) cmd: $(ps -o user=,args= -p $(systemctl show -p MainPID --value aukora-boundary-gate) | cut -c1-160)"
sudo journalctl -u aukora-boundary-gate --since -1min --no-pager -o cat | grep -viE "experimental|trace-warn" | tail -3 | cut -c1-200
echo "== 5 migrate legacy floor (exact proof, seq 115)"
sudo $CLEAN /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap approval migrate-clock-floor --release-dir /opt/aukora-genesis/release-5f0601f --out $AUKORA_APPROVAL_ROOT/gate-state 2>&1 | grep -viE "experimental|trace-warn"
sudo python3 -c 'import json;d=json.load(open("/etc/aukora-approvals/release-floor.json"));print("floor:",{k:d.get(k) for k in ("kind","release_dir","signer_epoch","sequence","epoch","signed_sequence")})'
echo "== 6 floor check as aukora-host, start genesis"
sudo -u aukora-host env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap floor check --release-dir $AUKORA_RELEASE_DIR --approval-state-root $AUKORA_APPROVAL_ROOT 2>&1 | grep -viE "experimental|trace-warn"
T0=$(date -u +"%Y-%m-%d %H:%M:%S"); sudo systemctl start aukora-genesis
for i in $(seq 1 60); do sudo journalctl -u aukora-genesis --since "$T0" --no-pager | grep -q "plugin set ENFORCE" && break; sleep 3; done
sudo journalctl -u aukora-genesis --since "$T0" --no-pager -o cat | grep -E "PACKAGE_VERIFIED|release-floor|selfcheck: PASSED|plugin set ENFORCE|REFUSED|rror" | cut -c1-220 | tail -8
echo "genesis $(systemctl is-active aukora-genesis)"; cmp /etc/systemd/system/aukora-genesis.service $G/host/systemd/aukora-genesis.service && echo GENESIS-UNIT-IDENTICAL-TO-MAIN
sudo sh -c "rm -rf /root/stage-0e11c37.*"
