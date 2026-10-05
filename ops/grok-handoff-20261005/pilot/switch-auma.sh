#!/bin/bash
# Run INSIDE aukora-staging as root. Switch staging host stack from R3 5fc1fea to the Auma relay release (cdfb55f-based).
set -euo pipefail
C=3bc01bb7746226a646d7c2fa50e71675fd9022cd; S=${C:0:7}; TS=$(date -u +%Y%m%d-%H%M)
B=/root/r3-host-backup-$TS; mkdir -m 700 $B
systemctl stop aukora-genesis aukora-selfcheck.timer 2>/dev/null || true
systemctl stop aukora-boundary-gate
tar -C / -czf $B/host.tgz opt/aukora-boundary-gate etc/aukora-boundary-gate usr/local/lib/aukora-boundary etc/aukora-genesis etc/aukora-approvals home/aukora-gate $(cd / && ls -d etc/systemd/system/aukora-*)
echo BACKUP $B/host.tgz $(du -h $B/host.tgz | cut -f1)
cd /opt/aukora-genesis/src
git fetch -q /root/auma-relay.bundle release/auma-relay:refs/heads/release/auma-relay
git -c advice.detachedHead=false checkout -q --detach $C
[ -z "$(git status --porcelain)" ] && echo SRC_CLEAN $(git rev-parse HEAD)
# gate package: exact tree of packages/boundary-gate at C
rm -rf /root/pkg-$S && mkdir /root/pkg-$S && git archive $C packages/boundary-gate | tar -x -C /root/pkg-$S
rm -rf /opt/aukora-boundary-gate.new && cp -a /root/pkg-$S/packages/boundary-gate /opt/aukora-boundary-gate.new
chown -R root:root /opt/aukora-boundary-gate.new && chmod -R u+rwX,go+rX,go-w /opt/aukora-boundary-gate.new
mv /opt/aukora-boundary-gate /root/pkg-r3-old-$TS && mv /opt/aukora-boundary-gate.new /opt/aukora-boundary-gate
rm -f /root/manifest-$S.json
/usr/bin/python3 -I -S packages/boundary-gate/host/install/generate-manifest.py --package /opt/aukora-boundary-gate --signer-epochs /etc/aukora-boundary-gate/signer-epochs.json --output /root/manifest-$S.json
install -o root -g root -m 644 /root/manifest-$S.json /etc/aukora-boundary-gate/gate-package-manifest.json
install -o root -g root -m 755 packages/boundary-gate/host/install/gate-bootstrap.py /usr/local/lib/aukora-boundary/gate-bootstrap
install -o root -g root -m 755 packages/boundary-gate/host/openshell/ensure-sandbox.sh /usr/local/lib/aukora-boundary/openshell/ensure-sandbox.sh
install -o root -g root -m 755 packages/boundary-gate/host/openshell/gateway.sh /usr/local/lib/aukora-boundary/openshell/gateway.sh
for u in aukora-genesis.service aukora-selfcheck.service aukora-selfcheck.timer; do install -o root -g root -m 644 packages/boundary-gate/host/systemd/$u /etc/systemd/system/$u; done
sed 's/SKGATE_GID/1003/' packages/boundary-gate/host/systemd/aukora-boundary-gate.service > /etc/systemd/system/aukora-boundary-gate.service; chmod 644 /etc/systemd/system/aukora-boundary-gate.service
systemctl daemon-reload
env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C /usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-package
systemctl start aukora-boundary-gate; sleep 4; systemctl is-active aukora-boundary-gate; journalctl -u aukora-boundary-gate -n 5 --no-pager | cut -c1-200
