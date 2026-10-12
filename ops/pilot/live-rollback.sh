#!/bin/bash
# LIVE PILOT: put back the release that ran before the 2026-10-13 morning switch, from that switch's own backup.
set -uo pipefail
B=${1:?backup dir}; SRC=/opt/aukora-genesis/src; L=/usr/local/lib/aukora-boundary; M=/etc/aukora-boundary-gate/gate-package-manifest.json; TS=$(date -u +%H%M%S)
for f in aukora-boundary-gate.old manifest.old gate-bootstrap.old release.env.old src.old; do [ -e $B/$f ] || { echo "backup is missing $f; nothing changed"; exit 1; }; done
drain() { local n=1; for i in $(seq 1 60); do n=$(ss -tan 2>/dev/null | grep -c ":18735 " || true); [ "$n" = 0 ] && break; sleep 2; done; echo "port drained (remaining $n)"; }
systemctl stop aukora-selfcheck.timer 2>/dev/null || true; systemctl stop aukora-genesis; systemctl stop aukora-boundary-gate
mv /opt/aukora-boundary-gate /opt/aukora-boundary-gate.c8cf03c-$TS && cp -a $B/aukora-boundary-gate.old /opt/aukora-boundary-gate || { echo GATE_PACKAGE_STEP_FAILED; }
[ -e $B/owner-key.absent ] && [ -d /opt/owner-key ] && mv /opt/owner-key /opt/owner-key.c8cf03c-$TS
cp -a $B/manifest.old $M; cp -a $B/gate-bootstrap.old $L/gate-bootstrap; cp -a $B/release.env.old /etc/aukora-genesis/release.env
[ -f $B/release-floor.json ] && cp -a $B/release-floor.json /etc/aukora-approvals/release-floor.json
git -c safe.directory='*' -C $SRC -c advice.detachedHead=false checkout -q --detach $(cat $B/src.old)
out=$(env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C /usr/bin/python3 -I -S $L/gate-bootstrap check-package 2>&1); echo "check-package: $out" | head -2
systemctl start aukora-boundary-gate; sleep 3; drain; systemctl reset-failed aukora-genesis 2>/dev/null || true; systemctl start aukora-genesis || true
for i in $(seq 1 40); do c=$(curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:18735/); echo "$c" | grep -qE "200|30[0-9]|401|403" && break; [ "$(systemctl is-failed aukora-genesis)" = failed ] && { drain; systemctl reset-failed aukora-genesis; systemctl start aukora-genesis || true; }; sleep 4; done
systemctl start aukora-selfcheck.timer 2>/dev/null || true
echo "NOW: $(grep -o 'release-[0-9a-f]*' /etc/aukora-genesis/release.env | head -1) harness $(systemctl is-active aukora-genesis) gate $(systemctl is-active aukora-boundary-gate) ui $c src $(git -c safe.directory='*' -C $SRC rev-parse --short HEAD)"
journalctl -u aukora-genesis --since "-2 min" --no-pager -o cat | grep -E "selfcheck|release-floor|plugin set ENFORCE|REFUSED|port-unavailable" | tail -4 | cut -c1-160
