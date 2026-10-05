#!/bin/bash
# Auma relay switch (Peter approved card 2f042be0 at 07:52 WITA): cdfb55f -> 4c24fd0.
# gate package = packages/boundary-gate at 4c24fd0 (+ relay_record), new manifest; owner-approved approval install + floor;
# fresh live AUMA key as aukora-host (never printed; digest only into relay auth.json); start genesis.
set -euo pipefail
C=4c24fd06e8f07b399b714aed547ef7646390f53e; S=4c24fd0; PREV=cdfb55ff2ed5d3f4ceb8d6734cc4997241a1f2ff
REL=/opt/aukora-genesis/release-$S; R=/etc/aukora-approvals/$C/state; L=/usr/local/lib/aukora-boundary; E=/etc/aukora-boundary-gate
TS=$(date -u +%Y%m%d-%H%M); B=/root/aukora-backup-pre-$S-$TS
CLEAN="env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C"; BOOT="$CLEAN /usr/bin/python3 -I -S $L/gate-bootstrap"
SRC=/opt/aukora-genesis/src; G="git -c safe.directory=* -C $SRC"
echo "== 0 preflight"
[ "$($G rev-parse HEAD)" = $PREV ] && echo "src at $PREV"
[ -z "$($G status --porcelain)" ] && echo SRC_CLEAN
cd /tmp; PEND=$(sudo -u aukora-gate /opt/aukora-node/bin/node --no-warnings /opt/aukora-boundary-gate/bin/owner-cli.mjs pending --socket /run/aukora-gate/owner.sock 2>&1 | grep -v base64 | head -3); echo "pending: $PEND"
echo "== 1 backup -> $B"
install -d -m 0700 -o root -g root $B
cp -a /etc/aukora-genesis/release.env /etc/aukora-approvals/release-floor.json $E/gate-package-manifest.json $B/
cp -a /opt/aukora-boundary-gate $B/opt-aukora-boundary-gate
cp -a /etc/systemd/system/aukora-genesis.service /etc/systemd/system/aukora-boundary-gate.service $B/
cp -a /var/lib/aukora-relay/auth.json $B/relay-auth.json
echo "== 5 install the owner-approved approval (advances floor)"
install -d -o root -g root -m 0755 /etc/aukora-approvals/$C $R $R/gate-state
OUT=$($BOOT approval install --release-dir $REL --out $R/gate-state 2>&1) || { echo "$OUT" | grep -v base64; echo INSTALL_FAILED; exit 1; }; echo "$OUT" | grep -viE "experimental|trace-warn|base64" || true
REC=$(echo "$OUT" | awk '/^RECORD/{print $2; exit}'); [ "$REC" = 53e9ef03277605b11879116811c36b8804df447e2df955891facbb8353f40b2f ] || { echo RECORD-MISMATCH; exit 1; }
echo "== 2 src -> $S"
$G fetch -q /home/ubuntu/aukora-zip/auma-relay2.bundle release/auma-relay:refs/heads/release/auma-relay
$G tag -f rollback/pre-$S $PREV >/dev/null
$G -c advice.detachedHead=false checkout -q --detach $C
[ "$($G rev-parse HEAD)" = $C ] && [ -z "$($G status --porcelain)" ] && echo "src at $C clean"
echo "== 3 quiesce genesis"
systemctl stop aukora-genesis
for i in $(seq 1 40); do n=$(ss -tan | grep -c ":18735 " || true); [ "$n" = 0 ] && break; sleep 2; done; echo "genesis stopped, drained $n"
echo "== 4 gate package -> packages/boundary-gate@$S"
rm -rf /root/pkg-$S && mkdir -m 700 /root/pkg-$S && $G archive $C packages/boundary-gate | tar -x -C /root/pkg-$S
diff -rq /opt/aukora-boundary-gate /root/pkg-$S/packages/boundary-gate || true
rm -rf /opt/aukora-boundary-gate.new && cp -a /root/pkg-$S/packages/boundary-gate /opt/aukora-boundary-gate.new
chown -R root:root /opt/aukora-boundary-gate.new && chmod -R u+rwX,go+rX,go-w /opt/aukora-boundary-gate.new
systemctl stop aukora-boundary-gate
mv /opt/aukora-boundary-gate /root/pkg-cdfb55f-old-$TS && mv /opt/aukora-boundary-gate.new /opt/aukora-boundary-gate
$CLEAN /usr/bin/python3 -I -S $SRC/packages/boundary-gate/host/install/generate-manifest.py --package /opt/aukora-boundary-gate --signer-epochs $E/signer-epochs.json --output /root/manifest-$S.json
install -o root -g root -m 644 /root/manifest-$S.json $E/gate-package-manifest.json
$BOOT check-package
systemctl start aukora-boundary-gate; sleep 4; echo "gate $(systemctl is-active aukora-boundary-gate)"
journalctl -u aukora-boundary-gate -n 4 --no-pager -o cat | cut -c1-200 || true
echo "== 5b release.env + floor check"
printf 'AUKORA_RELEASE_DIR=%s\nAUKORA_APPROVAL_ROOT=%s\nAUKORA_RECORD_SHA=%s\n' $REL $R $REC > /etc/aukora-genesis/release.env.new
chmod 0644 /etc/aukora-genesis/release.env.new && mv /etc/aukora-genesis/release.env.new /etc/aukora-genesis/release.env
sudo -u aukora-host env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -S $L/gate-bootstrap floor check --release-dir $REL --approval-state-root $R 2>&1 | grep -viE "experimental|trace-warn" || true
echo "== 6 fresh live AUMA key (aukora-host, 0600, never printed)"
sudo -u aukora-host bash -c 'umask 077; install -d -m 0700 "$HOME/.config" "$HOME/.config/aukora-relay"; K="$HOME/.config/aukora-relay/auma.key"; [ -e "$K" ] && { echo KEY_EXISTS; exit 1; }; head -c 48 /dev/urandom | base64 | tr "+/" "-_" | tr -d "=\n" > "$K"; stat -c "%U %a %s %n" "$K"'
D=$(tr -d '\n' < /home/aukora-host/.config/aukora-relay/auma.key | sha256sum | cut -d' ' -f1); echo "live auma digest prefix ${D:0:8}"
sudo -u aukora-relay python3 - /var/lib/aukora-relay/auth.json "$D" <<'PY'
import json,sys,os
p,d=sys.argv[1],sys.argv[2]
a=json.load(open(p)); assert 'auma' in a['tokenDigests']; assert d not in a['tokenDigests'].values()
a['tokenDigests']['auma']=d
tmp=p+'.new'; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,json.dumps(a,indent=2).encode()+b'\n'); os.close(fd); os.replace(tmp,p)
print('principals', sorted(a['tokenDigests']), 'auma', d[:8])
PY
systemctl restart aukora-relay; sleep 2; echo "relay $(systemctl is-active aukora-relay)"
echo "== 7 start genesis"
systemctl reset-failed aukora-genesis || true
T0=$(date -u +"%Y-%m-%d %H:%M:%S"); systemctl start aukora-genesis
for i in $(seq 1 60); do journalctl -u aukora-genesis --since "$T0" --no-pager | grep -q -E "plugin set ENFORCE|AUKORA_RELAY_AUMA" && sleep 6 && break; sleep 3; done
journalctl -u aukora-genesis --since "$T0" --no-pager -o cat | grep -E "PACKAGE_VERIFIED|release-floor|selfcheck: PASSED|plugin set ENFORCE|AUKORA_RELAY|REFUSED|rror" | cut -c1-220 | tail -12 || true
echo "genesis $(systemctl is-active aukora-genesis)"; echo "openviking $(systemctl is-active aukora-openviking)"; cat /etc/aukora-genesis/release.env; head -c 300 /etc/aukora-approvals/release-floor.json; echo
echo SWITCH_DONE $B
