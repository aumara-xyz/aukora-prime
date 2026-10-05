#!/bin/bash
# STAGING ONLY: F c36 workspace binding (OpenShell 0.1.2 + binding patch) with a test-only workspace fixture.
set -euo pipefail
TS=$(date -u +%Y%m%dT%H%M%SZ)
L=/usr/local/lib/aukora-boundary/openshell
[ -f /root/openshell-gateway-0.1.2-stock.bak ] || cp -p /usr/bin/openshell-gateway /root/openshell-gateway-0.1.2-stock.bak
[ -d /root/oshost-pre-fgw ] || cp -a $L /root/oshost-pre-fgw
[ -f /root/openshell-inventory.json.pre-fgw ] || cp -p /etc/aukora-boundary-gate/openshell-inventory.json /root/openshell-inventory.json.pre-fgw
# 1 workspace per Peter 10:57: own folder owned by auma, group auma-ws (gid 166536 = host gid of guest gid 1000) incl. aukora-host
getent group auma-ws >/dev/null || groupadd -g 166536 auma-ws
id -nG aukora-host | grep -qw auma-ws || usermod -aG auma-ws aukora-host
install -d -m 0755 -o root -g root /srv/auma-ws
if [ ! -d /srv/auma-ws/aukora-prime/.git ]; then git clone -q -b labs/r3-int /root/r3int.bundle /srv/auma-ws/aukora-prime; fi
chown -R auma:auma-ws /srv/auma-ws/aukora-prime
MODE=${WS_MODE:-2750}   # 2750 = F's current guard (no group write); 2770 = Peter's layout, needs F's fence exception
find /srv/auma-ws/aukora-prime -type d -exec chmod $MODE {} + ; find /srv/auma-ws/aukora-prime -type f -exec chmod g+r,o-rwx {} +
ls -ld /srv/auma-ws /srv/auma-ws/aukora-prime /srv/auma-ws/aukora-prime/.git
# 2 registration (root:root 0644, protected parent)
REG=/etc/aukora-boundary-gate/openshell-workspace.json
if [ ! -f $REG ]; then
  printf '{"version":1,"workspace_id":"%s","workspace_source":"/srv/auma-ws/aukora-prime","git_source":"/srv/auma-ws/aukora-prime/.git"}' "$(cat /proc/sys/kernel/random/uuid)" > $REG.new
  chown root:root $REG.new && chmod 0644 $REG.new && mv $REG.new $REG
fi
cat $REG; echo
# 3 host scripts from r3-int (sandbox-inventory with 4-mount/2-tmpfs, gateway.sh userns auto:size=65536)
rm -rf /root/oshost-new && mkdir /root/oshost-new && tar xzf /root/oshost-r3int.tgz -C /root/oshost-new
for f in sandbox-inventory.py gateway.sh ensure-sandbox.sh inventory-generation-schema.json workload-pin.json sandbox-policy.yml; do install -m $( [ -x /root/oshost-new/$f ] && echo 0755 || echo 0644 ) -o root -g root /root/oshost-new/$f $L/$f; done
install -m 0755 -o root -g root /root/oshost-new/custody/sbx_exec_body.sh $L/custody/sbx_exec_body.sh
install -m 0644 -o root -g root /root/oshost-new/custody/exec_fds.py $L/custody/exec_fds.py
# 4 gateway binary
install -m 0755 -o root -g root /root/openshell-gateway-f /usr/bin/openshell-gateway
sha256sum /usr/bin/openshell-gateway | cut -c1-16
systemctl restart aukora-openshell-gateway; sleep 5; systemctl is-active aukora-openshell-gateway
echo "DEPLOYED $TS"
