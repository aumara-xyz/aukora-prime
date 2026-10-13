#!/bin/bash
# Collects owner approval before stopping services and restores interrupted switches. History: ops/pilot/README.md.
set -Eeuo pipefail
umask 077
refuse() { echo "REFUSED: $*" >&2; exit 1; }
ROOT=${ROOT:-}
if [ -n "$ROOT" ]; then
  [ "${PILOT_SWITCH_TEST:-}" = 1 ] || refuse ROOT_TEST_ONLY
  [[ "$ROOT" = /* && "$ROOT" != / && "$ROOT" != */ && "$ROOT" != *'/../'* && "$ROOT" != *'/./'* ]] || refuse ROOT_INVALID
  [ -d "$ROOT" ] && [ ! -L "$ROOT" ] || refuse ROOT_INVALID
fi
[ "$(id -u)" = 0 ] || refuse ROOT_REQUIRED
PYTHON=$ROOT/usr/bin/python3
CLEAN=(env -i PATH=/usr/bin:/bin HOME="$ROOT/root" LANG=C LC_ALL=C)
if [ -n "$ROOT" ]; then CLEAN=(env -i PATH="$ROOT/usr/bin:$ROOT/bin:/usr/bin:/bin" HOME="$ROOT/root" LANG=C LC_ALL=C ROOT="$ROOT" PILOT_SWITCH_TEST=1); fi
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
SCRIPT=$SCRIPT_DIR/$(basename -- "$0")
detached() {
  "${CLEAN[@]}" "$PYTHON" -I -S -c 'import os,re,signal,sys
ignored=signal.getsignal(signal.SIGHUP)==signal.SIG_IGN
session=os.getsid(0)==int(sys.argv[1])
if session:
 try: fd=os.open("/dev/tty",os.O_RDONLY); os.close(fd); session=False
 except OSError: pass
stream=sys.argv[3]; service=False
if re.fullmatch("[0-9a-f]{32}",sys.argv[2]) and re.fullmatch("[0-9]+:[0-9]+",stream):
 st=os.fstat(1); service=stream==str(st.st_dev)+":"+str(st.st_ino)
sys.exit(0 if ignored or session or service else 1)' "$$" "${INVOCATION_ID:-}" "${JOURNAL_STREAM:-}"
}
# A detached child has no terminal input or SSH environment; its log is private even under umask 002.
if { [ -t 0 ] || [ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ]; } && ! detached; then
  LOG=$(mktemp "$ROOT/root/aukora-switch-log-XXXXXX") || refuse DETACH_LOG_FAILED
  nohup env -u SSH_CONNECTION -u SSH_CLIENT -u SSH_TTY "$BASH" "$SCRIPT" "$@" < /dev/null > "$LOG" 2>&1 &
  printf 'DETACHED: pid %s; tail -f %q\n' "$!" "$LOG"
  exit 0
fi
SRC=$ROOT/opt/aukora-genesis/src
L=$ROOT/usr/local/lib/aukora-boundary
M=$ROOT/etc/aukora-boundary-gate/gate-package-manifest.json
ENVFILE=$ROOT/etc/aukora-genesis/release.env
FLOOR=$ROOT/etc/aukora-approvals/release-floor.json
NODE=$ROOT/opt/aukora-node/bin/node
boot() { "${CLEAN[@]}" "$PYTHON" -I -S "$L/gate-bootstrap" "$@"; }
git_src() { (umask 022; git -c 'safe.directory=*' -C "$SRC" "$@"); }
owner_pending() { sudo -u aukora-gate "$NODE" --no-warnings "$ROOT/opt/aukora-boundary-gate/bin/owner-cli.mjs" pending --socket "$ROOT/run/aukora-gate/owner.sock"; }
active() { [ "$(systemctl is-active "$1" 2>/dev/null)" = active ]; }
phase() {
  printf 'phase=%s\n' "$1" > "$B/state.new"
  mv "$B/state.new" "$B/state"
  "${CLEAN[@]}" "$PYTHON" -I -S -c 'import os,sys
for p in (sys.argv[1], os.path.dirname(sys.argv[1])):
 f=os.open(p,os.O_RDONLY)
 try: os.fsync(f)
 finally: os.close(f)' "$B/state"
}
clean_prepared() {
  local name
  for name in aukora-boundary-gate owner-key; do rm -rf "$ROOT/opt/$name.switch-new-${B##*/}"; done
}
PORT=18735
drain() {
  local i connections
  for ((i=0; i<60; i++)); do
    connections=$(ss -tan) || { echo PORT_STATUS_FAILED; return 1; }
    if ! grep -q ":$PORT " <<< "$connections"; then echo "port $PORT drained"; return 0; fi
    sleep 2
  done
  echo PORT_NOT_DRAINED; return 1
}
wait_harness() {
  local i code
  for ((i=0; i<40; i++)); do
    code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/" || true)
    if active aukora-genesis && [[ "$code" =~ ^(200|30[0-9]|401|403)$ ]]; then return 0; fi
    [ "$(systemctl is-failed aukora-genesis 2>/dev/null)" != failed ] || break
    sleep 5
  done
  return 1
}
B=; ARMED=0; LOCKED=0; RESTORING=0; LOCK_PREP=
LOCK=$ROOT/root/aukora-switch.lock
release_lock() {
  if [ "$LOCKED" = 1 ]; then rm -f "$LOCK"; LOCKED=0; fi
  if [ -n "$LOCK_PREP" ]; then rm -f "$LOCK_PREP/pid"; rmdir "$LOCK_PREP"; LOCK_PREP=; fi
}
restore() {
  [ "$RESTORING" = 0 ] || return 1
  RESTORING=1; ARMED=0; set +e
  trap - INT TERM HUP
  echo "RESTORING: $B"
  local bad=0 name dest old attempt unit wanted candidate
  try() { "$@" || { echo RESTORE_STEP_FAILED; bad=1; }; }
  phase restoring || return 1
  try systemctl stop aukora-selfcheck.timer
  try systemctl stop aukora-genesis
  try systemctl stop aukora-boundary-gate
  for name in aukora-boundary-gate owner-key; do
    dest=$ROOT/opt/$name; old=$dest.switch-old-${B##*/}
    if [ -d "$B/$name.saved" ]; then
      # Immutable saved copies make recovery repeatable even if recovery itself is killed between renames.
      try rm -rf "$dest.switch-restore"
      try cp -a "$B/$name.saved" "$dest.switch-restore"
      try rm -rf "$dest"
      try mv "$dest.switch-restore" "$dest"
    elif [ -f "$B/$name.absent" ]; then try rm -rf "$dest"; else bad=1; fi
    try rm -rf "$dest.switch-new-${B##*/}" "$old"
  done
  try cp -a "$B/manifest.old" "$M"
  try cp -a "$B/gate-bootstrap.old" "$L/gate-bootstrap"
  try cp -a "$B/release.env.old" "$ENVFILE"
  candidate=$(cat "$B/commit")
  if [[ "$candidate" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; then
    dest=$ROOT/etc/aukora-approvals/$candidate
    try rm -rf "$dest"
    [ ! -d "$B/approval.saved" ] || try cp -a "$B/approval.saved" "$dest"
  else echo RECOVERY_COMMIT_INVALID; bad=1; fi
  if [ -f "$B/release-floor.json" ]; then try cp -a "$B/release-floor.json" "$FLOOR"; else try rm -f "$FLOOR"; fi
  [ ! -f "$B/floor-lock.absent" ] || try rm -f "$FLOOR.lock"
  try git_src -c advice.detachedHead=false checkout -q --detach "$(cat "$B/src.old")"
  try systemctl start aukora-boundary-gate
  for ((attempt=0; attempt<3; attempt++)); do
    if drain; then
      systemctl reset-failed aukora-genesis >/dev/null 2>&1
      systemctl start aukora-genesis
      wait_harness && break
    fi
  done
  while read -r unit wanted; do
    if [ "$wanted" = active ]; then
      if [ "$unit" != aukora-genesis ]; then try systemctl start "$unit"; fi
      active "$unit" || bad=1
    else try systemctl stop "$unit"; active "$unit" && bad=1; fi
  done < "$B/units.old"
  if ! active aukora-genesis; then echo 'HARNESS DOWN: recovery exhausted three drain-then-start attempts'; bad=1; fi
  if [ "$bad" = 0 ]; then phase done || return 1; echo 'RESTORED: original release and active units'; return 0; fi
  echo "RECOVERY_FAILED: run $SCRIPT --recover $B"; return 1
}
finish() {
  local rc=$?
  trap - EXIT
  if [ "$ARMED" = 1 ]; then restore || true; rc=1
  elif [ "$MODE" = switch ] && [ -n "$B" ] && [ "$RESTORING" = 0 ]; then clean_prepared || rc=1; phase done || rc=1; fi
  release_lock || rc=1
  exit "$rc"
}
MODE=switch
if [ "${1:-}" = --recover ]; then
  [ "$#" = 2 ] || refuse RECOVERY_ARGUMENTS
  MODE=recover; B=$2
  [ "${B%/*}" = "$ROOT/root" ] && [[ "${B##*/}" = aukora-backup-pre-* ]] || refuse RECOVERY_PATH
  [ "$(cd -- "$B" 2>/dev/null && pwd -P)" = "$B" ] && [ ! -L "$B" ] && [ -f "$B/state" ] || refuse RECOVERY_PATH
else
  [ "$#" = 1 ] && [[ "$1" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || refuse COMMIT_ARGUMENT
  C=$1; S=${C:0:7}; REL=$ROOT/opt/aukora-genesis/release-$S; A=$ROOT/etc/aukora-approvals/$C/state
  for prior in "$ROOT"/root/aukora-backup-pre-*/state; do
    [ -f "$prior" ] || continue
    grep -qx 'phase=done' "$prior" || refuse "UNFINISHED_SWITCH: $SCRIPT --recover ${prior%/state}"
  done
fi
if [ -e "$LOCK" ] || [ -L "$LOCK" ]; then
  PID=$(cat "$LOCK/pid" 2>/dev/null || true)
  [[ "$PID" =~ ^[0-9]+$ ]] || refuse SWITCH_LOCK_INCOMPLETE
  if [[ "$PID" =~ ^[0-9]+$ ]] && kill -0 "$PID" 2>/dev/null; then refuse SWITCH_RUNNING; fi
  # A dead lock without an unfinished state precedes every service stop and can be discarded.
  if [ -L "$LOCK" ]; then
    old_lock=$(readlink "$LOCK")
    [ "${old_lock%/*}" = "$ROOT/root" ] && [[ "${old_lock##*/}" = .aukora-switch-lock-* ]] || refuse SWITCH_LOCK_INVALID
    rm -f "$LOCK" "$old_lock/pid"; rmdir "$old_lock" || refuse SWITCH_LOCK_FAILED
  else rm -f "$LOCK/pid"; rmdir "$LOCK" || refuse SWITCH_LOCK_FAILED; fi
fi
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# Publish a complete pid directory atomically; another invocation never sees an uninitialized lock.
LOCK_PREP=$(mktemp -d "$ROOT/root/.aukora-switch-lock-XXXXXX")
printf '%s\n' "$$" > "$LOCK_PREP/pid"
"${CLEAN[@]}" "$PYTHON" -I -S -c 'import os,sys; os.symlink(sys.argv[1],sys.argv[2])' "$LOCK_PREP" "$LOCK" || refuse SWITCH_LOCK_FAILED
LOCKED=1
if [ "$MODE" = recover ]; then
  # Before the armed marker, only private backup/staging files and a pending owner card could have changed.
  if [ ! -f "$B/armed" ]; then clean_prepared; phase done; echo 'RECOVERED: no services were stopped'; exit 0; fi
  for f in manifest.old gate-bootstrap.old release.env.old src.old units.old commit; do [ -f "$B/$f" ] || refuse "RECOVERY_BACKUP_MISSING: $f"; done
  restore; exit $?
fi
[ -f "$SCRIPT_DIR/ui-probe.mjs" ] || refuse UI_PROBE_MISSING
[ ! -e "$FLOOR.lock" ] || refuse FLOOR_LOCK_REQUIRES_RECONCILIATION
[ -d "$REL" ] || refuse RELEASE_NOT_BUILT
[ -z "$(git_src status --porcelain)" ] || refuse LAUNCHER_DIRTY
PREV=$(git_src rev-parse HEAD)
git_src cat-file -t "$C" >/dev/null 2>&1 || git_src fetch -q "$ROOT/home/ubuntu/aukora-zip/repro.bundle" refs/remotes/origin/main
git_src cat-file -t "$C" >/dev/null 2>&1 || refuse COMMIT_MISSING
for unit in aukora-genesis aukora-boundary-gate; do active "$unit" || refuse "UNIT_NOT_ACTIVE: $unit"; done
B=$(mktemp -d "$ROOT/root/aukora-backup-pre-$S-XXXXXX")
phase backup
printf '%s\n' "$C" > "$B/commit"
for unit in aukora-genesis aukora-boundary-gate aukora-selfcheck.timer; do
  if active "$unit"; then printf '%s active\n' "$unit"; else printf '%s inactive\n' "$unit"; fi
done > "$B/units.old"
items=(opt/aukora-boundary-gate etc/aukora-boundary-gate usr/local/lib/aukora-boundary etc/aukora-genesis etc/aukora-approvals)
[ ! -d "$ROOT/opt/owner-key" ] || items+=(opt/owner-key)
tar -C "${ROOT:-/}" -czf "$B/host.tgz" "${items[@]}"
cp -a "$ENVFILE" "$B/release.env.old"
[ ! -f "$FLOOR" ] || cp -a "$FLOOR" "$B/release-floor.json"
touch "$B/floor-lock.absent"
[ ! -d "${A%/state}" ] || cp -a "${A%/state}" "$B/approval.saved"
cp -a "$M" "$B/manifest.old"; cp -a "$L/gate-bootstrap" "$B/gate-bootstrap.old"
printf '%s\n' "$PREV" > "$B/src.old"
for name in aukora-boundary-gate owner-key; do
  if [ -d "$ROOT/opt/$name" ]; then cp -a "$ROOT/opt/$name" "$B/$name.saved"; else touch "$B/$name.absent"; fi
done
cat > "$B/RECOVERY.txt" <<RECOVERY
As root, after an interrupted switch:
  bash '$SCRIPT' --recover '$B'
This restores the saved packages, launcher, manifest, bootstrap, floor and release.env,
then drains and starts the harness (at most three attempts). It also starts
aukora-selfcheck.timer when units.old records it active, and verifies the original unit set.
Do not begin another switch until recovery reports RESTORED. HARNESS DOWN is a failure.
The full host archive is '$B/host.tgz'; saved package directories remain reusable.
RECOVERY
ST=$B/staging
phase stage
mkdir "$ST" "$ST/launcher"
git_src archive "$C" | tar -x -C "$ST/launcher"
cp -a "$ST/launcher/packages/boundary-gate" "$ST/gate-package"
cp -a "$ST/launcher/packages/owner-key" "$ST/owner-key"
cp "$ROOT/etc/aukora-boundary-gate/signer-epochs.json" "$ST/signer-epochs.json"
(cd "$ST/launcher" && "${CLEAN[@]}" "$PYTHON" -I -S packages/boundary-gate/host/install/generate-manifest.py --package "$ST/gate-package" --signer-epochs "$ST/signer-epochs.json" --owner-key "$ST/owner-key" --launcher-checkout "$ST/launcher" --output "$ST/gate-package-manifest.json") > "$B/manifest.log" 2>&1 || refuse STAGE_MANIFEST_FAILED
phase approval
SHOW=$(boot approval show --release-dir "$REL" 2>/dev/null) || refuse 'INSTALLED_GATE_SHOW_FAILED: old release remains up; upgrade compatibility requires owner review'
OP=$(printf '%s\n' "$SHOW" | awk '/^OPERATION/{print $2}')
REC=$(printf '%s\n' "$SHOW" | awk '/^RECORD/{print $2}')
CONTENT=$(printf '%s\n' "$SHOW" | awk '/^CONTENT SHA/{print $3}')
SET=$(printf '%s\n' "$SHOW" | awk '/^PLUGIN SET/{print $3}')
[[ "$OP" =~ ^[0-9a-f]{64}$ && "$REC" =~ ^[0-9a-f]{64}$ && "$CONTENT" =~ ^[0-9a-f]{64}$ && "$SET" =~ ^[0-9a-f]{64}$ ]] || refuse INSTALLED_GATE_CARD_INVALID
approval_exists() {
  "${CLEAN[@]}" "$NODE" --input-type=commonjs -e 'const fs=require("node:fs"),crypto=require("node:crypto");try{process.exit(crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex")===process.argv[2]?0:1)}catch{process.exit(1)}' "$ROOT/var/lib/aukora-boundary/targets/plugins/aukora-plugin-set/approval.json" "$CONTENT"
}
if ! approval_exists; then
  RAISE=$(boot approval raise --release-dir "$REL" --operation "$OP" 2>/dev/null) || RAISE=
  ID=$(printf '%s\n' "$RAISE" | awk '/^PENDING/{print $2}')
  if [ -z "$ID" ] && ! approval_exists; then
    PENDING=$(owner_pending 2>/dev/null) || refuse INSTALLED_GATE_PENDING_FAILED
    FACTS="| release $C (release-$S) | plugin set $SET | operation $OP (rechecked at launch) | release record $REC"
    ID=$(printf '%s\n' "$PENDING" | awk -v sha="${CONTENT:0:12}" -v facts="$FACTS" '
      /^[^ ]/ {id=($3=="plugins/aukora-plugin-set/approval.json" && $6==sha) ? $1 : ""; first=1; next}
      first {if(id!="" && index($0,facts)) {print id; exit}; first=0}')
    [ -n "$ID" ] || refuse 'INSTALLED_GATE_RAISE_FAILED: old release remains up; no matching pending card'
  fi
  echo "WAITING: owner approval for operation $OP and record $REC; old release remains up (default 15 minutes)"
  [[ "${WAIT_TICKS:-180}" =~ ^[1-9][0-9]*$ ]] || refuse WAIT_INVALID
  for ((i=0; i<${WAIT_TICKS:-180}; i++)); do
    approval_exists && break
    owner_pending > /dev/null 2>&1 || refuse APPROVAL_POLL_FAILED
    sleep 5
  done
fi
approval_exists || refuse APPROVAL_NOT_RECEIVED
# Prepare copies on each destination filesystem before entering the two-rename swap window.
phase prepared
for pair in "gate-package:aukora-boundary-gate" "owner-key:owner-key"; do
  name=${pair%%:*}; dest=$ROOT/opt/${pair#*:}; new=$dest.switch-new-${B##*/}
  [ ! -e "$new" ] || refuse PACKAGE_STAGE_EXISTS
  cp -a "$ST/$name" "$new"; chown -R root:root "$new"; chmod -R u+rwX,go+rX,go-w "$new"
done
# This marker precedes the first stop and survives SIGKILL; --recover never sources state as shell code.
touch "$B/armed"; ARMED=1
phase stop
systemctl stop aukora-selfcheck.timer
systemctl stop aukora-genesis
systemctl stop aukora-boundary-gate
for pair in "gate-package:aukora-boundary-gate" "owner-key:owner-key"; do
  name=${pair%%:*}; dest=$ROOT/opt/${pair#*:}; new=$dest.switch-new-${B##*/}; old=$dest.switch-old-${B##*/}
  phase "$name-out"
  [ ! -e "$dest" ] || mv "$dest" "$old"
  phase "$name-in"
  mv "$new" "$dest"
done
phase manifest
install -o root -g root -m 644 "$ST/gate-package-manifest.json" "$M"
phase bootstrap
install -o root -g root -m 755 "$ST/launcher/packages/boundary-gate/host/install/gate-bootstrap.py" "$L/gate-bootstrap"
phase launcher
git_src -c advice.detachedHead=false checkout -q --detach "$C"
phase check-package
OUT=$(boot check-package 2>/dev/null) || refuse PACKAGE_CHECK_FAILED
[ "$OUT" = PACKAGE_VERIFIED ] || refuse PACKAGE_CHECK_FAILED
phase gate-start
systemctl start aukora-boundary-gate
for ((i=0; i<20; i++)); do active aukora-boundary-gate && break; sleep 1; done
active aukora-boundary-gate || refuse GATE_START_FAILED
# "active" is not "listening": on the live pilot the gate opened its sockets a moment after the unit reported active,
# and installing the approval at once failed with ENOENT (first live run of this version). Wait for both sockets.
for ((i=0; i<30; i++)); do [ -S "$ROOT/run/aukora-gate/gate.sock" ] && [ -S "$ROOT/run/aukora-gate/owner.sock" ] && break; sleep 1; done
[ -S "$ROOT/run/aukora-gate/gate.sock" ] && [ -S "$ROOT/run/aukora-gate/owner.sock" ] || refuse GATE_SOCKETS_MISSING
phase approval-install
# The harness user reads its own approval at the floor check and at every start. This script runs under a strict
# mask, so the approval folders and the records written into them are made readable explicitly (found in the first
# staging rehearsal of this version: the floor check refused with EACCES and the switch restored).
install -d -o root -g root -m 0755 "$ROOT/etc/aukora-approvals/$C" "$A" "$A/gate-state"
# The approval records and the release floor are public, signed facts the harness user must read: write them under
# the ordinary mask, not this script's private one (second rehearsal: the floor file itself came out unreadable).
(umask 022; boot approval recover-cache --release-dir "$REL" --operation "$OP" --out "$A/gate-state" > "$B/approval.log" 2>&1 || boot approval install --release-dir "$REL" --operation "$OP" --out "$A/gate-state" > "$B/approval.log" 2>&1) || refuse APPROVAL_INSTALL_FAILED
grep -q '^INSTALLED' "$B/approval.log" || refuse APPROVAL_INSTALL_FAILED
chmod -R u+rwX,go+rX,go-w "$ROOT/etc/aukora-approvals/$C"
[ ! -f "$FLOOR" ] || chmod 0644 "$FLOOR"
phase floor
sudo -u aukora-host "${CLEAN[@]}" "$PYTHON" -I -S "$L/gate-bootstrap" floor check --release-dir "$REL" --approval-state-root "$A" > "$B/floor.log" 2>&1 || refuse FLOOR_CHECK_FAILED
phase drain
drain || refuse PORT_NOT_DRAINED
systemctl reset-failed aukora-genesis
# Publish the new environment immediately before starting; any unverified start restores the old one.
printf 'AUKORA_RELEASE_DIR=%s\nAUKORA_APPROVAL_ROOT=%s\nAUKORA_RECORD_SHA=%s\n' "$REL" "$A" "$REC" > "$B/release.env.new"
chmod 0644 "$B/release.env.new"
phase release-env
phase harness-start
mv "$B/release.env.new" "$ENVFILE"
systemctl start aukora-genesis || refuse HARNESS_START_FAILED
wait_harness || refuse HARNESS_NOT_READY
phase ui-probe
"${CLEAN[@]}" "$NODE" "$SCRIPT_DIR/ui-probe.mjs" "$ROOT/home/aukora-host/genesis/state/launch-url.json" > "$B/ui-probe.log" 2>&1 || refuse UI_PROBE_FAILED
phase log-check
INVOCATION=$(systemctl show aukora-genesis -p InvocationID --value)
[[ "$INVOCATION" =~ ^[0-9a-f]{32}$ ]] || refuse HARNESS_LOG_ID_MISSING
journalctl "_SYSTEMD_INVOCATION_ID=$INVOCATION" --no-pager -o cat > "$B/harness.log" || refuse HARNESS_LOG_FAILED
if grep -qE '^aukora-[a-z-]+ \(file://.*\): Error' "$B/harness.log"; then refuse PLUGIN_LOAD_ERROR; fi
active aukora-genesis || refuse HARNESS_NOT_ACTIVE
phase units
while read -r unit wanted; do
  if [ "$wanted" = active ]; then systemctl start "$unit"; active "$unit" || refuse "UNIT_NOT_ACTIVE: $unit"
  else systemctl stop "$unit"; if active "$unit"; then refuse "UNIT_UNEXPECTED_ACTIVE: $unit"; fi; fi
done < "$B/units.old"
phase done; ARMED=0
echo "SWITCH_DONE: verified harness on release-$S, approval installed, UI probe and plugin log check passed; backup $B"
