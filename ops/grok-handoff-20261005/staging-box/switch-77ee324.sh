#!/bin/bash
# Live switch 4c24fd0 -> 77ee324 AFTER Peter's card click. Release/plugin set only: gate package, keys, relay auth unchanged
# (same combination as RAN on staging). Backup first; rollback = restore release.env from backup + src rollback tag.
set -euo pipefail
C=77ee324bef7d1ced5178922c434b3652e2b659b9; S=77ee324; PREV=4c24fd06e8f07b399b714aed547ef7646390f53e
REL=/opt/aukora-genesis/release-$S; R=/etc/aukora-approvals/$C/state; L=/usr/local/lib/aukora-boundary
TS=$(date -u +%Y%m%d-%H%M); B=/root/aukora-backup-pre-$S-$TS
CLEAN="env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C"; BOOT="$CLEAN /usr/bin/python3 -I -S $L/gate-bootstrap"
SRC=/opt/aukora-genesis/src; G="git -c safe.directory=* -C $SRC"
EXPECT_REC=${1:?expected record sha from materialize}
echo "== 0 preflight"
[ "$($G rev-parse HEAD)" = $PREV ] && echo "src at $PREV"; [ -z "$($G status --porcelain)" ] && echo SRC_CLEAN
grep -q "release-4c24fd0" /etc/aukora-genesis/release.env && echo "running 4c24fd0"
echo "== 1 backup -> $B"
install -d -m 0700 -o root -g root $B
cp -a /etc/aukora-genesis/release.env /etc/aukora-approvals/release-floor.json $B/
echo "== 2 install the owner-approved approval (advances floor)"
install -d -o root -g root -m 0755 /etc/aukora-approvals/$C $R $R/gate-state
OUT=$($BOOT approval install --release-dir $REL --out $R/gate-state 2>&1) || { echo "$OUT" | grep -v base64; echo INSTALL_FAILED; exit 1; }
echo "$OUT" | grep -viE "experimental|trace-warn|base64" || true
REC=$(echo "$OUT" | awk '/^RECORD/{print $2; exit}'); [ "$REC" = "$EXPECT_REC" ] || { echo "RECORD-MISMATCH $REC"; exit 1; }
echo "== 3 src -> $S"
$G fetch -q /home/ubuntu/aukora-zip/hygiene-77ee324.bundle release/hygiene:refs/heads/release/hygiene
$G tag -f rollback/pre-$S $PREV >/dev/null
$G -c advice.detachedHead=false checkout -q --detach $C
[ "$($G rev-parse HEAD)" = $C ] && [ -z "$($G status --porcelain)" ] && echo "src at $C clean"
echo "== 4 quiesce genesis, release.env, floor check"
systemctl stop aukora-genesis
for i in $(seq 1 40); do n=$(ss -tan | grep -c ":18735 " || true); [ "$n" = 0 ] && break; sleep 2; done; echo "genesis stopped, drained $n"
printf 'AUKORA_RELEASE_DIR=%s\nAUKORA_APPROVAL_ROOT=%s\nAUKORA_RECORD_SHA=%s\n' $REL $R $REC > /etc/aukora-genesis/release.env.new
chmod 0644 /etc/aukora-genesis/release.env.new && mv /etc/aukora-genesis/release.env.new /etc/aukora-genesis/release.env
sudo -u aukora-host env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -S $L/gate-bootstrap floor check --release-dir $REL --approval-state-root $R 2>&1 | grep -viE "experimental|trace-warn" || true
echo "== 5 start genesis"
systemctl reset-failed aukora-genesis || true
T0=$(date -u +"%Y-%m-%d %H:%M:%S"); systemctl start aukora-genesis
for i in $(seq 1 60); do journalctl -u aukora-genesis --since "$T0" --no-pager | grep -q -E "plugin set ENFORCE|AUKORA_RELAY_AUMA" && sleep 6 && break; sleep 3; done
journalctl -u aukora-genesis --since "$T0" --no-pager -o cat | grep -E "PACKAGE_VERIFIED|release-floor|selfcheck: PASSED|plugin set ENFORCE|AUKORA_RELAY|REFUSED|rror" | cut -c1-220 | tail -12 || true
echo "genesis $(systemctl is-active aukora-genesis)"; echo "gate $(systemctl is-active aukora-boundary-gate)"; echo "relay $(systemctl is-active aukora-relay)"
cat /etc/aukora-genesis/release.env; head -c 300 /etc/aukora-approvals/release-floor.json; echo
echo SWITCH_DONE $B
