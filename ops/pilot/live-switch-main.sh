#!/bin/bash
# LIVE PILOT. NOT RUN. Written by the Prime builder 2026-10-13 for Peter to start himself:  sudo bash ~/aukora-zip/live-switch-main.sh <full commit>
# Same order that ran in the staging container six times on 2026-10-12/13 (roll2.sh), with ONE difference: the approval
# is Peter's click in his own popup, not a stand-in key. Staging does not have this host's sandbox, OpenShell gateway or
# his real owner key, so the first live run can still stop; every stop restores the old gate package and the old release.
#
#  1 preflight   2 backup   3 stage gate package + manifest from STAGED copies   4 stop harness, swap gate package,
#  move launcher source, check-package (restore on failure)   5 start gate, RAISE ONE CARD   6 WAIT for Peter's click
#  (15 minutes, then restore)   7 install approval, point release.env at the new release, floor check, start harness
#  (restore on failure).
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
C=${1:?full commit}; S=${C:0:7}; REL=/opt/aukora-genesis/release-$S; SRC=/opt/aukora-genesis/src
L=/usr/local/lib/aukora-boundary; M=/etc/aukora-boundary-gate/gate-package-manifest.json; A=/etc/aukora-approvals/$C/state
CLEAN="env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C"; BOOT="$CLEAN /usr/bin/python3 -I -S $L/gate-bootstrap"
G="git -c safe.directory=* -C $SRC"; O="sudo -u aukora-gate /opt/aukora-node/bin/node --no-warnings /opt/aukora-boundary-gate/bin/owner-cli.mjs"
step() { echo; echo "== $*"; }
step "1 preflight"
[ -d "$REL" ] || { echo "release $REL is not built (run mat-live-main.sh first)"; exit 1; }
[ -z "$($G status --porcelain)" ] || { echo "launcher source checkout is not clean"; exit 1; }
PREV=$($G rev-parse HEAD); OLDREL=$(grep -o "release-[0-9a-f]*" /etc/aukora-genesis/release.env | head -1)
$G cat-file -t $C >/dev/null 2>&1 || $G fetch -q /home/ubuntu/aukora-zip/repro.bundle refs/remotes/origin/main 2>/dev/null
$G cat-file -t $C >/dev/null 2>&1 || { echo "commit $S is not in the launcher checkout and not in ~/aukora-zip/repro.bundle"; exit 1; }
echo "running $OLDREL, launcher at ${PREV:0:7}; going to release-$S"
for u in aukora-genesis aukora-boundary-gate; do [ "$(systemctl is-active $u)" = active ] || { echo "$u is not active; fix that first"; exit 1; }; done
step "2 backup"
TS=$(date -u +%Y%m%d-%H%M); B=/root/aukora-backup-pre-$S-$TS; install -d -m 0700 -o root -g root $B
tar -C / -czf $B/host.tgz opt/aukora-boundary-gate etc/aukora-boundary-gate usr/local/lib/aukora-boundary etc/aukora-genesis etc/aukora-approvals $( [ -d /opt/owner-key ] && echo opt/owner-key ) 2>/dev/null
cp -a /etc/aukora-genesis/release.env $B/release.env.old; cp -a /etc/aukora-approvals/release-floor.json $B/ 2>/dev/null; cp -a $M $B/manifest.old; cp -a $L/gate-bootstrap $B/gate-bootstrap.old; echo $PREV > $B/src.old
echo "backup in $B ($(du -h $B/host.tgz | cut -f1))"
step "3 stage"
ST=/root/gate-staging-$S; [ -e $ST ] && mv $ST $ST.old-$TS; mkdir -m 700 $ST; $G archive $C | (mkdir $ST/launcher && tar -x -C $ST/launcher)
cp -a $ST/launcher/packages/boundary-gate $ST/gate-package; cp -a $ST/launcher/packages/owner-key $ST/owner-key; cp /etc/aukora-boundary-gate/signer-epochs.json $ST/signer-epochs.json
out=$(cd $ST/launcher && /usr/bin/python3 -I -S packages/boundary-gate/host/install/generate-manifest.py --package $ST/gate-package --signer-epochs $ST/signer-epochs.json --owner-key $ST/owner-key --launcher-checkout $ST/launcher --output $ST/gate-package-manifest.json 2>&1) || { echo "generate-manifest REFUSED: $(echo "$out" | head -2 | cut -c1-200)"; echo "nothing was changed"; exit 1; }
echo "manifest generated from staged copies"
restore() {
  echo; echo "!! RESTORING the old gate package, manifest, bootstrap, launcher source and release"
  systemctl stop aukora-genesis 2>/dev/null || true; systemctl stop aukora-boundary-gate 2>/dev/null || true
  if [ -d $B/aukora-boundary-gate.old ]; then [ -d /opt/aukora-boundary-gate ] && mv /opt/aukora-boundary-gate /opt/aukora-boundary-gate.failed-$TS; mv $B/aukora-boundary-gate.old /opt/aukora-boundary-gate; fi
  if [ -d $B/owner-key.old ]; then [ -d /opt/owner-key ] && mv /opt/owner-key /opt/owner-key.failed-$TS; mv $B/owner-key.old /opt/owner-key; elif [ -e $B/owner-key.absent ] && [ -d /opt/owner-key ]; then mv /opt/owner-key /opt/owner-key.failed-$TS; fi
  cp -a $B/manifest.old $M; cp -a $B/gate-bootstrap.old $L/gate-bootstrap; cp -a $B/release.env.old /etc/aukora-genesis/release.env
  [ -f $B/release-floor.json ] && cp -a $B/release-floor.json /etc/aukora-approvals/release-floor.json
  $G -c advice.detachedHead=false checkout -q --detach $(cat $B/src.old)
  systemctl start aukora-boundary-gate; sleep 3; systemctl reset-failed aukora-genesis 2>/dev/null || true; systemctl start aukora-genesis || true; sleep 8
  echo "RESTORED: gate $(systemctl is-active aukora-boundary-gate), harness $(systemctl is-active aukora-genesis), on $(grep -o 'release-[0-9a-f]*' /etc/aukora-genesis/release.env | head -1). Backup kept in $B"; exit 1
}
step "4 swap the gate package (harness and gate stopped from here until step 7)"
systemctl stop aukora-selfcheck.timer 2>/dev/null || true; systemctl stop aukora-genesis; systemctl stop aukora-boundary-gate
for pair in "gate-package:/opt/aukora-boundary-gate" "owner-key:/opt/owner-key"; do name=${pair%%:*}; dest=${pair##*:}
  rm -rf $dest.new; cp -a $ST/$name $dest.new && chown -R root:root $dest.new && chmod -R u+rwX,go+rX,go-w $dest.new || restore
  if [ -d $dest ]; then mv $dest $B/$(basename $dest).old; else touch $B/$(basename $dest).absent; fi
  mv $dest.new $dest || restore; done
install -o root -g root -m 644 $ST/gate-package-manifest.json $M
install -o root -g root -m 755 $ST/launcher/packages/boundary-gate/host/install/gate-bootstrap.py $L/gate-bootstrap
$G -c advice.detachedHead=false checkout -q --detach $C && echo "launcher source at $($G rev-parse --short HEAD)" || restore
out=$($BOOT check-package 2>&1); echo "check-package: $(echo "$out" | head -2 | cut -c1-200)"; [ "$out" = PACKAGE_VERIFIED ] || restore
step "5 start the gate on the new package and raise ONE card"
systemctl start aukora-boundary-gate; for i in $(seq 1 20); do [ -S /run/aukora-gate/owner.sock ] && [ "$(systemctl is-active aukora-boundary-gate)" = active ] && break; sleep 1; done
[ "$(systemctl is-active aukora-boundary-gate)" = active ] || { journalctl -u aukora-boundary-gate -n 8 --no-pager -o cat | cut -c1-200; restore; }
cd /tmp; SHOW=$($BOOT approval show --release-dir $REL 2>&1 | grep -viE "experimental|trace-warn|base64"); echo "$SHOW" | head -8
OP=$(echo "$SHOW" | awk '/^OPERATION/{print $2}'); REC=$(echo "$SHOW" | awk '/^RECORD/{print $2}'); [ -n "$OP" ] && [ -n "$REC" ] || { echo NO_OPERATION; restore; }
RAISE=$($BOOT approval raise --release-dir $REL --operation $OP 2>&1 | grep -viE "base64|experimental|trace-warn" || true); echo "$RAISE" | head -4
ID=$(echo "$RAISE" | awk '/^PENDING/{print $2}'); [ -n "$ID" ] || { echo RAISE_FAILED; restore; }
step "6 WAITING for Peter to approve the plugin set in his popup (card ${ID:0:8}; 15 minutes)"
echo "   The card must show PLUGIN SET $(echo "$SHOW" | awk '/^PLUGIN SET/{print $3}') and RECORD $REC. Approve only if it does."
install -d -o root -g root -m 0755 /etc/aukora-approvals/$C $A $A/gate-state; OK=0
for i in $(seq 1 ${WAIT_TICKS:-180}); do
  if ! $O pending --socket /run/aukora-gate/owner.sock 2>/dev/null | grep -q "^${ID:0:8} "; then
    OUT=$($BOOT approval install --release-dir $REL --operation $OP --out $A/gate-state 2>&1); if echo "$OUT" | grep -q "^INSTALLED"; then OK=1; echo "$OUT" | grep -E "INSTALLED|FLOOR" | grep -v base64 | cut -c1-200; fi; break
  fi; sleep 5; done
[ $OK = 1 ] || { echo "no approval was installed (rejected, expired or timed out): $(echo "${OUT:-}" | grep -v base64 | head -2 | cut -c1-200)"; restore; }
step "7 point at the new release and start the harness"
printf 'AUKORA_RELEASE_DIR=%s\nAUKORA_APPROVAL_ROOT=%s\nAUKORA_RECORD_SHA=%s\n' $REL $A $REC > /etc/aukora-genesis/release.env.new && chmod 0644 /etc/aukora-genesis/release.env.new && mv /etc/aukora-genesis/release.env.new /etc/aukora-genesis/release.env
sudo -u aukora-host $CLEAN /usr/bin/python3 -I -S $L/gate-bootstrap floor check --release-dir $REL --approval-state-root $A 2>&1 | grep -viE "experimental|trace-warn" | cut -c1-200 || true
systemctl reset-failed aukora-genesis 2>/dev/null || true; T0=$(date -u +"%Y-%m-%d %H:%M:%S"); systemctl start aukora-genesis || true
for i in $(seq 1 40); do curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:18735/ | grep -qE "200|30[0-9]|401|403" && break; [ "$(systemctl is-failed aukora-genesis)" = failed ] && break; sleep 5; done
journalctl -u aukora-genesis --since "$T0" --no-pager -o cat | grep -E "REFUSED|release-floor|selfcheck|plugin set ENFORCE|AUKORA_BUZZ|AUKORA_RELAY|rror" | tail -10 | cut -c1-200
[ "$(systemctl is-active aukora-genesis)" = active ] || restore
systemctl start aukora-selfcheck.timer 2>/dev/null || true
echo; echo "SWITCH_DONE: harness $(systemctl is-active aukora-genesis) on release-$S, gate $(systemctl is-active aukora-boundary-gate), relay $(systemctl is-active aukora-relay 2>/dev/null). Backup in $B"
echo "Next, as the harness user: the door acceptance and the memory probe (commands in plan/MORNING-2026-10-13.md)."
