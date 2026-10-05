#!/bin/bash
# R2 switch (reduced scope, Peter yes 23:18 WITA): install owner-approved approval for cdfb55f, release.env + floor, hardened OpenViking unit, restart genesis. Gate package unchanged from 3ac3509.
set -euo pipefail
C=cdfb55ff2ed5d3f4ceb8d6734cc4997241a1f2ff; S=cdfb55f; E=/etc/aukora-boundary-gate
REL=/opt/aukora-genesis/release-$S; R=/etc/aukora-approvals/$C/state; L=/usr/local/lib/aukora-boundary; B=/root/aukora-backup-pre-$S
CLEAN="env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C"; BOOT="$CLEAN /usr/bin/python3 -I -S $L/gate-bootstrap"
[ "$(sudo git -c safe.directory=* -C /opt/aukora-genesis/src rev-parse HEAD)" = $C ] && echo "src $C"
echo "== 1 install the owner-approved approval"
sudo install -d -o root -g root -m 0755 /etc/aukora-approvals/$C $R $R/gate-state
OUT=$(sudo $BOOT approval install --release-dir $REL --out $R/gate-state 2>&1); echo "$OUT" | grep -viE "experimental|trace-warn"
REC=$(echo "$OUT" | awk '/^RECORD/{print $2; exit}'); [ ${#REC} = 64 ] || { echo NO-RECORD; exit 1; }
echo "== 2 backup"
sudo install -d -m 0700 -o root -g root $B
sudo cp -a /etc/aukora-genesis/release.env $B/; sudo cp -a /etc/systemd/system/aukora-openviking.service $B/
sudo cp -a /etc/aukora-approvals/release-floor.json $B/
echo "== 3 gate package unchanged check"
sudo $BOOT check-package
echo "== 4 quiesce genesis"
sudo systemctl stop aukora-genesis
for i in $(seq 1 40); do n=$(ss -tan | grep -c ":18735 " || true); [ "$n" = 0 ] && break; sleep 2; done; echo "genesis stopped, drained $n"
echo "== 5 release.env + floor"
sudo cp -a /etc/aukora-genesis/release.env /etc/aukora-genesis/release.env.bak-pre-$S
printf 'AUKORA_RELEASE_DIR=%s\nAUKORA_APPROVAL_ROOT=%s\nAUKORA_RECORD_SHA=%s\n' $REL $R $REC | sudo tee /etc/aukora-genesis/release.env.new >/dev/null
sudo chmod 0644 /etc/aukora-genesis/release.env.new && sudo mv /etc/aukora-genesis/release.env.new /etc/aukora-genesis/release.env
sudo -u aukora-host env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -S $L/gate-bootstrap floor check --release-dir $REL --approval-state-root $R 2>&1 | grep -viE "experimental|trace-warn"
echo "== 6 hardened OpenViking unit from main"
sudo install -o root -g root -m 0644 /opt/aukora-genesis/src/host/units/aukora-openviking.service /etc/systemd/system/aukora-openviking.service
sudo systemctl daemon-reload
cmp /etc/systemd/system/aukora-openviking.service /opt/aukora-genesis/src/host/units/aukora-openviking.service && echo OV-UNIT-IDENTICAL-TO-MAIN
sudo systemctl restart aukora-openviking; sleep 8; echo "openviking $(systemctl is-active aukora-openviking)"
echo "== 7 start genesis"
sudo systemctl reset-failed aukora-genesis || true
T0=$(date -u +"%Y-%m-%d %H:%M:%S"); sudo systemctl start aukora-genesis
for i in $(seq 1 60); do sudo journalctl -u aukora-genesis --since "$T0" --no-pager | grep -q "plugin set ENFORCE" && break; sleep 3; done
sudo journalctl -u aukora-genesis --since "$T0" --no-pager -o cat | grep -E "PACKAGE_VERIFIED|release-floor|selfcheck: PASSED|plugin set ENFORCE|REFUSED|rror" | cut -c1-220 | tail -8
echo "genesis $(systemctl is-active aukora-genesis)"; cat /etc/aukora-genesis/release.env; cat /etc/aukora-approvals/release-floor.json | head -c 400; echo
