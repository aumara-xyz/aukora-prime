#!/bin/bash
# H runbook steps 1-6 on the pilot (current runtime release-5f0601f). Grok, 2026-10-04.
set -euo pipefail
S=0e11c37; N=/opt/aukora-node/bin/node; G=/opt/aukora-boundary-gate; B=/root/aukora-backup-pre-$S; E=/etc/aukora-boundary-gate
CLEAN="env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C"
echo "== 1 backup"
sudo install -d -m 0700 -o root -g root $B
sudo cp -a $G $B/opt-aukora-boundary-gate
sudo cp -a /usr/local/lib/aukora-boundary $B/usr-local-lib-aukora-boundary
sudo cp -a /etc/systemd/system/aukora-genesis.service /etc/systemd/system/aukora-boundary-gate.service /etc/aukora-genesis/release.env $B/
sudo cp -a /etc/aukora-approvals $B/etc-aukora-approvals
sudo test -d $E && sudo cp -a $E $B/etc-aukora-boundary-gate || true
sudo sh -c "cd $B && find . -type f -print0 | sort -z | xargs -0 sha256sum > $B/SHA256SUMS"; echo "backup files: $(sudo wc -l < $B/SHA256SUMS)"
. <(sudo cat /etc/aukora-genesis/release.env)
[ "$AUKORA_RELEASE_DIR" = /opt/aukora-genesis/release-5f0601f ] || { echo "UNEXPECTED RELEASE $AUKORA_RELEASE_DIR"; exit 1; }
sudo grep -q '"kind"' /etc/aukora-approvals/release-floor.json && echo "legacy floor: $(sudo python3 -c 'import json;d=json.load(open("/etc/aukora-approvals/release-floor.json"));print(d.get("kind"),d.get("release_dir"))')"
echo "== 2 stage package + epoch registry + manifest"
ST=$(sudo mktemp -d /root/stage-$S.XXXX); sudo tar -xzf ~/aukora-zip/gate-$S.tgz -C $ST; P=$ST/packages/boundary-gate
FULL=$(sudo $N -e 'const c=require("node:crypto");const k=c.createPublicKey(require("fs").readFileSync("/run/aukora-gate/receipt-ed25519.pub"));process.stdout.write(c.createHash("sha256").update(k.export({type:"spki",format:"der"})).digest("hex"))')
[ "${FULL:0:16}" = 6cdce2bbeb7b725c ] && [ "$FULL" = 6cdce2bbeb7b725cf02493af784a71047e18d5fa9384c1518c948c2377fd4e63 ] || { echo "KEY MISMATCH $FULL"; exit 1; }
printf '{"version":1,"kind":"aukora-signer-epochs/v1","epochs":[{"epoch":1,"gate_pubkey_sha256":"%s"}]}\n' $FULL | sudo tee $ST/signer-epochs.json >/dev/null
sudo /usr/bin/python3 -I -S $P/host/install/generate-manifest.py --package $P --signer-epochs $ST/signer-epochs.json --output $ST/gate-package-manifest.json
echo "manifest entries: $(sudo python3 -c "import json;d=json.load(open('$ST/gate-package-manifest.json'));print({k:(len(v) if isinstance(v,(list,dict)) else v) for k,v in d.items()})")"
echo "== 3 install (services quiescent)"
sudo systemctl stop aukora-genesis
for i in $(seq 1 40); do n=$(ss -tan | grep -c ":18735 " || true); [ "$n" = 0 ] && break; sleep 2; done; echo "genesis stopped, drained $n"
sudo systemctl stop aukora-boundary-gate
sudo rsync -a --delete $P/ $G/ && sudo chown -R root:root $G && sudo chmod -R go-w $G
sudo install -o root -g root -m 0755 $P/host/install/gate-bootstrap.py /usr/local/lib/aukora-boundary/gate-bootstrap
sudo install -d -o root -g root -m 0755 $E
sudo install -o root -g root -m 0644 $ST/signer-epochs.json $ST/gate-package-manifest.json $E/
sed 's/SKGATE_GID/1003/' $P/host/systemd/aukora-boundary-gate.service | sudo tee /etc/systemd/system/aukora-boundary-gate.service >/dev/null
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
sudo rm -rf $ST
