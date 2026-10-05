#!/bin/bash
# R1 switch: install owner-approved approval, update gate package (D host/aura + A fd custody) from main 3ac3509, switch release.
set -euo pipefail
C=3ac3509a25fbfd03fd50a670f1fcdfef2aa5470e; S=3ac3509; N=/opt/aukora-node/bin/node; G=/opt/aukora-boundary-gate; E=/etc/aukora-boundary-gate
REL=/opt/aukora-genesis/release-$S; R=/etc/aukora-approvals/$C/state; L=/usr/local/lib/aukora-boundary; B=/root/aukora-backup-pre-$S
CLEAN="env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C"; BOOT="$CLEAN /usr/bin/python3 -I -S $L/gate-bootstrap"
[ "$(sudo git -c safe.directory=* -C /opt/aukora-genesis/src rev-parse HEAD)" = $C ] && echo "src $C"
echo "== 1 install the owner-approved approval"
sudo install -d -o root -g root -m 0755 /etc/aukora-approvals/$C $R $R/gate-state
OUT=$(sudo $BOOT approval install --release-dir $REL --out $R/gate-state 2>&1); echo "$OUT" | grep -viE "experimental|trace-warn"
REC=$(echo "$OUT" | awk '/^RECORD/{print $2; exit}'); [ ${#REC} = 64 ] || { echo NO-RECORD; exit 1; }
echo "== 2 backup"
sudo install -d -m 0700 -o root -g root $B
sudo cp -a $G $B/opt-aukora-boundary-gate; sudo cp -a $L $B/usr-local-lib-aukora-boundary; sudo cp -a $E $B/etc-aukora-boundary-gate
sudo cp -a /etc/aukora-genesis/release.env $B/
echo "== 3 stage package + manifest (existing epoch registry)"
ST=$(sudo mktemp -d /root/stage-$S.XXXX); sudo tar -xzf /home/ubuntu/aukora-zip/gate-$S.tgz -C $ST; P=$ST/packages/boundary-gate
sudo /usr/bin/python3 -I -S $P/host/install/generate-manifest.py --package $P --signer-epochs $E/signer-epochs.json --output $ST/gate-package-manifest.json
echo "== 4 quiesce, install"
sudo systemctl stop aukora-genesis
for i in $(seq 1 40); do n=$(ss -tan | grep -c ":18735 " || true); [ "$n" = 0 ] && break; sleep 2; done; echo "genesis stopped, drained $n"
sudo systemctl stop aukora-boundary-gate
sudo rsync -a --delete $P/ $G/ && sudo chown -R root:root $G && sudo chmod -R go-w $G
sudo install -o root -g root -m 0644 $ST/gate-package-manifest.json $E/gate-package-manifest.json
sudo install -o root -g root -m 0755 $P/host/sbx-exec $L/sbx-exec
sudo install -d -o root -g root -m 0755 $L/openshell/custody
sudo install -o root -g root -m 0755 $P/host/openshell/custody/exec_fds.py $L/openshell/custody/exec_fds.py
sudo install -o root -g root -m 0644 $P/host/openshell/custody/sbx_exec_body.sh $L/openshell/custody/sbx_exec_body.sh
cmp $P/host/install/gate-bootstrap.py $L/gate-bootstrap && echo BOOTSTRAP-UNCHANGED
cmp /etc/systemd/system/aukora-genesis.service $G/host/systemd/aukora-genesis.service && echo GENESIS-UNIT-IDENTICAL-TO-MAIN
echo "== 5 check-package, start gate"
sudo $BOOT check-package
sudo systemctl start aukora-boundary-gate; for i in $(seq 1 30); do sudo test -S /run/aukora-gate/owner.sock && systemctl is-active -q aukora-boundary-gate && break; sleep 1; done
echo "gate $(systemctl is-active aukora-boundary-gate)"
echo "== 6 release.env + floor"
sudo cp -a /etc/aukora-genesis/release.env /etc/aukora-genesis/release.env.bak-pre-$S
printf 'AUKORA_RELEASE_DIR=%s\nAUKORA_APPROVAL_ROOT=%s\nAUKORA_RECORD_SHA=%s\n' $REL $R $REC | sudo tee /etc/aukora-genesis/release.env.new >/dev/null
sudo chmod 0644 /etc/aukora-genesis/release.env.new && sudo mv /etc/aukora-genesis/release.env.new /etc/aukora-genesis/release.env
sudo -u aukora-host env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -S $L/gate-bootstrap floor check --release-dir $REL --approval-state-root $R 2>&1 | grep -viE "experimental|trace-warn"
echo "== 7 start genesis"
sudo systemctl reset-failed aukora-genesis || true
T0=$(date -u +"%Y-%m-%d %H:%M:%S"); sudo systemctl start aukora-genesis
for i in $(seq 1 60); do sudo journalctl -u aukora-genesis --since "$T0" --no-pager | grep -q "plugin set ENFORCE" && break; sleep 3; done
sudo journalctl -u aukora-genesis --since "$T0" --no-pager -o cat | grep -E "PACKAGE_VERIFIED|release-floor|selfcheck: PASSED|plugin set ENFORCE|REFUSED|rror" | cut -c1-220 | tail -8
echo "genesis $(systemctl is-active aukora-genesis)"; cat /etc/aukora-genesis/release.env
sudo rm -rf $ST
