#!/usr/bin/env bash
# Run as auma: make sure OpenShell sandbox "auma-ws" is Ready with network mode none AND runs the hard startup policy in
# sandbox-policy.yml (beside this script: Landlock hard_requirement, include_workdir false, writable /sandbox /tmp
# /dev/null only); a running sandbox reporting any other effective policy is snapshotted, deleted and recreated. And that the agent's
# /sandbox workspace survives Podman restarts AND sandbox recreation:
#   * a host copy lives in ~auma/sandbox-persist (0700, outside every container)
#   * it is refreshed from the live volume on every run and right before any delete
#   * a recreated sandbox gets it restored into its new workspace volume before use
# Refuses (exit 3) when the container's network mode is anything but "none"; exit 4 when a restore cannot be
# done safely (the persist copy is then left untouched).
export XDG_RUNTIME_DIR=/run/user/$(id -u) OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=$HOME/.local/state/openshell/tls
POLICY="$(cd "$(dirname "$0")" && pwd)/sandbox-policy.yml"; [ -r "$POLICY" ] || { echo "REFUSING: $POLICY missing" >&2; exit 5; }
cd "$HOME"; P="$HOME/sandbox-persist"; mkdir -p "$P"; chmod 700 "$P" 2>/dev/null
vol() { local id; id=$(podman ps -a --sort created --format '{{.Names}}' | sed -n 's/^openshell-default--auma-ws-//p' | tail -1); [ -n "$id" ] && echo "$HOME/.local/share/containers/storage/volumes/openshell-sandbox-$id-workspace/_data"; }
snapshot() { local v; v=$(vol); [ -n "$v" ] || return 0
  podman unshare bash -c 'v=$1; P=$2; test -d "$v" || exit 0; rm -rf "$P.new"; cp -a "$v/." "$P.new/" 2>/dev/null || { mkdir -p "$P.new" && cp -a "$v/." "$P.new/"; } || exit 1
    rm -rf "$P.prev"; mv "$P" "$P.prev" && mv "$P.new" "$P"' _ "$v" "$P" && echo "snapshot: live /sandbox -> $P"; }
# exact startup policy check: effective policy == sandbox-policy.yml (normalized; OpenShell omits empty network_policies)
policy_ok() { openshell policy get auma-ws --full -o json 2>/dev/null | python3 -I -S -c 'import json,sys,re
want=sys.argv[1]; d=json.load(sys.stdin); p=dict(d.get("policy") or {}); p.setdefault("network_policies",{})
txt=open(want).read()
# the policy file is tiny, flat YAML written by us: compare the fields that matter exactly
ok=(d.get("status")=="effective" and p.get("version")==1 and p.get("landlock")=={"compatibility":"hard_requirement"}
 and p.get("network_policies")=={} and (p.get("filesystem_policy") or {}).get("include_workdir") is False
 and sorted((p.get("filesystem_policy") or {}).get("read_write") or [])==sorted(["/sandbox","/tmp","/dev/null"])
 and "hard_requirement" in txt)
sys.exit(0 if ok else 1)' "$POLICY"; }
phase() { openshell sandbox list 2>/dev/null | awk '$1=="auma-ws"{print $NF}'; }
waitready() { for i in $(seq 1 90); do [ "$(phase)" = Ready ] && return 0; sleep 1; done; return 1; }
for i in $(seq 1 30); do openshell status >/dev/null 2>&1 && break; sleep 1; done
# Register by config file, not by grepping `gateway list`: with no gateway registered, its hint text
# ("Register a gateway with: openshell gateway add ...") contains "openshell", so the old grep skipped the add.
[ -f "$HOME/.config/openshell/gateways/openshell/metadata.json" ] || openshell gateway add https://127.0.0.1:17690 --local --name openshell
openshell gateway select openshell >/dev/null
ph=$(phase); created=0
case "$ph" in
  Ready) ;;
  "") openshell sandbox create --name auma-ws --no-auto-providers --no-tty --detach --policy "$POLICY" </dev/null; created=1 ;;
  *) # Stopped/Completed/Error/...: try to bring the SAME sandbox (same volume) back first
     openshell sandbox start auma-ws </dev/null >/dev/null 2>&1; waitready || {
       snapshot; openshell sandbox delete auma-ws </dev/null
       for i in $(seq 1 60); do [ -z "$(phase)" ] && break; sleep 1; done
       openshell sandbox create --name auma-ws --no-auto-providers --no-tty --detach --policy "$POLICY" </dev/null; created=1; } ;;
esac
# Ready but not on the hard startup policy (e.g. created before it existed): recreate, keeping /sandbox via the snapshot.
if [ "$created" = 0 ] && waitready && ! policy_ok; then
  echo "auma-ws runs another startup policy: snapshot, recreate with $POLICY"
  snapshot; openshell sandbox delete auma-ws </dev/null
  for i in $(seq 1 60); do [ -z "$(phase)" ] && break; sleep 1; done
  openshell sandbox create --name auma-ws --no-auto-providers --no-tty --detach --policy "$POLICY" </dev/null; created=1
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
[ -n "$v" ] && ln -sfn "$v" "$HOME/workspace"
openshell sandbox list
