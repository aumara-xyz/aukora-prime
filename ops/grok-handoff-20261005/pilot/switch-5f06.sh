#!/bin/bash
set -e
C=5f0601feae249af5290386523c794a3a560bc7ff; PREV=ea66a0a9fa6c5a8d8133f66cb0d2e813296c3713
N=/opt/aukora-node/bin/node; G=/opt/aukora-boundary-gate; REL=/opt/aukora-genesis/release-5f0601f; R=/etc/aukora-approvals/$C/state
sudo install -d -o root -g root -m 0755 /etc/aukora-approvals/$C $R $R/gate-state
OUT=$(sudo $N $G/bin/plugin-set-approval.mjs install --release-dir $REL --out $R/gate-state 2>&1); echo "$OUT" | grep -v -i -E "experimental|trace-warnings"
REC=$(echo "$OUT" | awk '/^RECORD/{print $2; exit}'); [ ${#REC} = 64 ] || { echo NO-RECORD; exit 1; }
sudo cp -a /etc/aukora-genesis/release.env /etc/aukora-genesis/release.env.bak-pre-5f0601f
printf 'AUKORA_RELEASE_DIR=%s\nAUKORA_APPROVAL_ROOT=%s\nAUKORA_RECORD_SHA=%s\n' $REL $R $REC | sudo tee /etc/aukora-genesis/release.env.new >/dev/null
sudo chmod 0644 /etc/aukora-genesis/release.env.new && sudo mv /etc/aukora-genesis/release.env.new /etc/aukora-genesis/release.env
cat /etc/aukora-genesis/release.env
cmp /etc/systemd/system/aukora-genesis.service $G/host/systemd/aukora-genesis.service && echo UNIT-IDENTICAL-TO-MAIN
sudo git -c safe.directory=* -C /opt/aukora-genesis/src tag -f rollback/pre-5f0601f $PREV >/dev/null; echo src-head $(sudo git -c safe.directory=* -C /opt/aukora-genesis/src rev-parse HEAD)
echo "--- old release now below floor (expect REFUSED):"
sudo -u aukora-host $N $G/bin/release-floor.mjs check --release-dir /opt/aukora-genesis/release-ea66a0a --approval-state-root /etc/aukora-approvals/$PREV/state 2>&1 | grep -o "REFUSED.*" | cut -c1-140 || true
sudo systemctl stop aukora-genesis
for i in $(seq 1 40); do n=$(ss -tan | grep -c ":18735 " || true); [ "$n" = 0 ] && break; sleep 2; done; echo drained $n
T0=$(date -u +"%Y-%m-%d %H:%M:%S"); sudo systemctl start aukora-genesis
for i in $(seq 1 60); do sudo journalctl -u aukora-genesis --since "$T0" --no-pager | grep -q "plugin set ENFORCE" && break; sleep 3; done
sudo journalctl -u aukora-genesis --since "$T0" --no-pager | grep -E "release-floor|selfcheck: PASSED|plugin set|ENFORCE|REFUSED|rror" | cut -c1-240 | tail -6
systemctl is-active aukora-genesis
