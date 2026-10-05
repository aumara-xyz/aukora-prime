#!/bin/bash
# STAGING ONLY: rescue old auma-ws workspace volume, then recreate auma-ws under the binding gateway
set -u
TS=$(date -u +%Y%m%dT%H%M%SZ)
V=/home/auma/.local/share/containers/storage/volumes/openshell-sandbox-ab571750-87df-4e8d-ae88-8de2ca2af4fa-workspace/_data
if [ -d "$V" ]; then tar czf /root/rescue-auma-ws-volume-$TS.tgz -C "$V" . && (cd "$V" && find . -printf '%M %u:%g %s %p\n') > /root/rescue-auma-ws-volume-$TS.list && echo "RESCUE /root/rescue-auma-ws-volume-$TS.tgz $(sha256sum /root/rescue-auma-ws-volume-$TS.tgz | cut -c1-16) files=$(wc -l < /root/rescue-auma-ws-volume-$TS.list)"; fi
A="sudo -u auma env XDG_RUNTIME_DIR=/run/user/1001 OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=/home/auma/.local/state/openshell/tls HOME=/home/auma"
cd /tmp
$A openshell sandbox list 2>/dev/null | grep -q "^auma-ws" && $A openshell sandbox delete auma-ws </dev/null 2>&1 | tail -2
for i in $(seq 1 60); do $A openshell sandbox list 2>/dev/null | grep -q '^auma-ws' || break; sleep 1; done
IMG=(); $A podman image exists localhost/aukora-guest:current && IMG=(--from localhost/aukora-guest:current)
$A openshell sandbox create --name auma-ws "${IMG[@]}" --no-auto-providers --no-tty --detach --policy /usr/local/lib/aukora-boundary/openshell/sandbox-policy.yml </dev/null 2>&1 | tail -5
for i in $(seq 1 90); do P=$($A openshell sandbox list 2>/dev/null | awk '$1=="auma-ws"{print $NF}'); [ "$P" = Ready ] && break; sleep 1; done
echo "PHASE $P"
$A openshell sandbox list 2>&1 | tail -2
C=$($A podman ps --format '{{.Names}}' | grep '^openshell-default--auma-ws-' | head -1)
echo "CONTAINER $C"
$A podman inspect "$C" --format '{{json .Mounts}}' | python3 -c 'import json,sys;[print("MNT",m["Type"],m.get("Source"),"->",m["Destination"],"RW" if m.get("RW") else "RO") for m in json.load(sys.stdin)]'
$A podman inspect "$C" --format 'ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} Tmpfs={{json .HostConfig.Tmpfs}} Net={{.HostConfig.NetworkMode}} UsernsMode={{.HostConfig.UsernsMode}}'
journalctl -u aukora-openshell-gateway --since "-3min" --no-pager | grep -E "WARN|ERROR" | tail -5 | cut -c1-250
