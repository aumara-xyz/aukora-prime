#!/usr/bin/env bash
# Run as auma: make sure OpenShell sandbox "auma-ws" is Ready with network mode none AND runs the hard startup policy in
# sandbox-policy.yml (beside this script: Landlock hard_requirement, include_workdir false, writable /sandbox /tmp
# /dev/null, plus /dev/pts + /dev/ptmx so a PTY opens INSIDE the sandbox; nothing else); a running sandbox reporting any other effective policy is snapshotted, deleted and recreated. And that the agent's
# /sandbox workspace survives Podman restarts AND sandbox recreation:
#   * a host copy lives in ~auma/sandbox-persist (0700, outside every container)
#   * it is refreshed from the live volume on every run and right before any delete
#   * a recreated sandbox gets it restored into its new workspace volume before use
# Refuses (exit 3) when the container's network mode is anything but "none"; exit 4 when a restore cannot be
# done safely (the persist copy is then left untouched).
# Bootstrap is an explicit operator preparation path, never an admission result.
bootstrap=0
if [ "$#" -ne 0 ]; then
  [ "$#" -eq 1 ] && [ "$1" = --bootstrap-profile ] || { echo "REFUSING: unsupported preparation arguments" >&2; exit 2; }
  bootstrap=1
fi
export XDG_RUNTIME_DIR=/run/user/$(id -u) OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=$HOME/.local/state/openshell/tls
POLICY="$(cd "$(dirname "$0")" && pwd)/sandbox-policy.yml"; [ -r "$POLICY" ] || { echo "REFUSING: $POLICY missing" >&2; exit 5; }
INVENTORY=/usr/local/lib/aukora-boundary/openshell/sandbox-inventory.py
[ -r "$INVENTORY" ] || { echo "REFUSING: sandbox inventory helper missing" >&2; exit 5; }
# Ordinary startup refuses missing profile custody before any persistence/create.
# Explicit bootstrap instead requires protected public schema/pin/range inputs;
# it cannot install a profile or admit a workload. The operator holds traffic.
if [ "$bootstrap" = 1 ]; then
  /usr/bin/python3 -I -S "$INVENTORY" auma-ws bootstrap || { echo "REFUSING: reviewed generation inputs missing" >&2; exit 7; }
  exec 9>>"$XDG_RUNTIME_DIR/aukora-sbx-exec.lock" || exit 7
  /usr/bin/flock -w 30 9 || { echo "REFUSING: bootstrap admission lock unavailable" >&2; exit 7; }
else
  /usr/bin/python3 -I -S "$INVENTORY" auma-ws profile || { echo "REFUSING: reviewed deployment profile missing" >&2; exit 7; }
fi
# Guest image: localhost/aukora-guest:current (guest-image/build.sh) when present, else OpenShell's default image.
IMG=localhost/aukora-guest:current; FROM=(); podman image exists "$IMG" 2>/dev/null && FROM=(--from "$IMG")
cd "$HOME"; P="$HOME/sandbox-persist"; mkdir -p "$P"; chmod 700 "$P" 2>/dev/null
vol() { local id listed; listed=$(podman ps -a --sort created --format '{{.Names}}') || return 1
  id=$(printf '%s\n' "$listed" | sed -n 's/^openshell-default--auma-ws-//p')
  [[ "$id" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]] || return 1
  echo "$HOME/.local/share/containers/storage/volumes/openshell-sandbox-$id-workspace/_data"; }
snapshot() { local v; v=$(vol) || return 1; [ -n "$v" ] || return 1
  podman unshare bash -c 'v=$1; P=$2; test -d "$v" || exit 1; rm -rf "$P.new"; cp -a "$v/." "$P.new/" 2>/dev/null || { mkdir -p "$P.new" && cp -a "$v/." "$P.new/"; } || exit 1
    rm -rf "$P.prev"; mv "$P" "$P.prev" && mv "$P.new" "$P"' _ "$v" "$P" && echo "snapshot: live /sandbox -> $P"; }
# exact startup policy check: effective policy == sandbox-policy.yml (normalized; OpenShell omits empty network_policies)
policy_ok() { /usr/bin/python3 -I -S "$INVENTORY" auma-ws policy; }
phase() { local listed; listed=$(openshell sandbox list 2>/dev/null) || return 1
  printf '%s\n' "$listed" | awk '$1=="auma-ws"{print $NF}'; }
waitready() { for i in $(seq 1 90); do [ "$(phase)" = Ready ] && return 0; sleep 1; done; return 1; }
for i in $(seq 1 30); do openshell status >/dev/null 2>&1 && break; sleep 1; done
# Register by config file, not by grepping `gateway list`: with no gateway registered, its hint text
# ("Register a gateway with: openshell gateway add ...") contains "openshell", so the old grep skipped the add.
[ -f "$HOME/.config/openshell/gateways/openshell/metadata.json" ] || openshell gateway add https://127.0.0.1:17690 --local --name openshell
openshell gateway select openshell >/dev/null
ph=$(phase) || { echo "REFUSING: sandbox phase observation unavailable" >&2; exit 7; }; created=0
# Changing the gateway's userns default does not change a Ready container. The
# explicit operator bootstrap recreates this named sandbox after a good snapshot.
# A failed snapshot/delete/wait refuses; no workload is admitted from this path.
if [ "$bootstrap" = 1 ] && [ -n "$ph" ]; then
  snapshot || { echo "REFUSING: bootstrap workspace snapshot failed" >&2; exit 4; }
  openshell sandbox delete auma-ws </dev/null || { echo "REFUSING: bootstrap delete unavailable" >&2; exit 7; }
  for i in $(seq 1 60); do
    ph=$(phase) || { echo "REFUSING: bootstrap absence observation unavailable" >&2; exit 7; }
    [ -z "$ph" ] && break
    sleep 1
  done
  ph=$(phase) || { echo "REFUSING: bootstrap absence observation unavailable" >&2; exit 7; }
  [ -z "$ph" ] || { echo "REFUSING: bootstrap old sandbox still listed" >&2; exit 7; }
fi
case "$ph" in
  Ready) ;;
  "") openshell sandbox create --name auma-ws "${FROM[@]}" --no-auto-providers --no-tty --detach --policy "$POLICY" </dev/null; created=1 ;;
  *) # Stopped/Completed/Error/...: try to bring the SAME sandbox (same volume) back first
     openshell sandbox start auma-ws </dev/null >/dev/null 2>&1; waitready || {
       snapshot; openshell sandbox delete auma-ws </dev/null
       for i in $(seq 1 60); do [ -z "$(phase)" ] && break; sleep 1; done
       openshell sandbox create --name auma-ws "${FROM[@]}" --no-auto-providers --no-tty --detach --policy "$POLICY" </dev/null; created=1; } ;;
esac
# Running another image than :current (e.g. a rebuilt carrier): recreate the same way, keeping /sandbox.
image_ok() { [ "${#FROM[@]}" -eq 0 ] && return 0; local c; c=$(podman ps --format '{{.Names}}' | grep '^openshell-default--auma-ws-' | head -1)
  [ -n "$c" ] && [ "$(podman inspect "$c" --format '{{.Image}}')" = "$(podman image inspect "$IMG" --format '{{.Id}}')" ]; }
if [ "$created" = 0 ] && waitready && ! image_ok; then
  echo "auma-ws runs another image than $IMG: snapshot, recreate"
  snapshot; openshell sandbox delete auma-ws </dev/null
  for i in $(seq 1 60); do [ -z "$(phase)" ] && break; sleep 1; done
  openshell sandbox create --name auma-ws "${FROM[@]}" --no-auto-providers --no-tty --detach --policy "$POLICY" </dev/null; created=1
fi
# Ready but not on the hard startup policy (e.g. created before it existed): recreate, keeping /sandbox via the snapshot.
if [ "$created" = 0 ] && waitready && ! policy_ok; then
  echo "auma-ws runs another startup policy: snapshot, recreate with $POLICY"
  snapshot; openshell sandbox delete auma-ws </dev/null
  for i in $(seq 1 60); do [ -z "$(phase)" ] && break; sleep 1; done
  openshell sandbox create --name auma-ws "${FROM[@]}" --no-auto-providers --no-tty --detach --policy "$POLICY" </dev/null; created=1
fi
waitready || { echo "auma-ws not Ready" >&2; exit 1; }
v=$(vol)
# the persist copy is owned by the container uid: inspect/copy it inside the podman user namespace
if [ "$created" = 1 ]; then
  [ -n "$v" ] || { echo "REFUSING: new workspace volume not found; persist copy left untouched" >&2; exit 4; }
  if podman unshare bash -c '[ -n "$(ls -A "$1" 2>/dev/null)" ]' _ "$P"; then
    podman unshare cp -a "$P/." "$v/" || { echo "REFUSING: restore into new volume failed; persist copy left untouched" >&2; exit 4; }
    echo "restored $P -> new workspace volume"
  fi
else snapshot; fi
c=$(podman ps --format '{{.Names}}' | grep '^openshell-default--auma-ws-' | head -1)
net=$(podman inspect "$c" --format '{{.HostConfig.NetworkMode}}'); echo "sandbox network mode: $net"
[ "$net" = none ] || { echo "REFUSING: sandbox network mode is '$net', expected none" >&2; exit 3; }
policy_ok || { echo "REFUSING: auma-ws does not report the hard startup policy" >&2; exit 6; }
# New UUIDs are still unavailable. Generate/review/install the exact profile
# separately while admission traffic is held, then rerun ordinary startup.
if [ "$bootstrap" = 1 ]; then
  echo "REFUSING: bootstrap prepared; fresh reviewed inventory binding required" >&2
  exit 7
fi
# No automatic adoption of a changed container/map/mount baseline. The operator
# must install the reviewed protected profile before this exact readback can pass.
/usr/bin/python3 -I -S "$INVENTORY" auma-ws check || { echo "REFUSING: sandbox deployment inventory unavailable" >&2; exit 7; }
[ -n "$v" ] && ln -sfn "$v" "$HOME/workspace"
openshell sandbox list
