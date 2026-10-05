set -eu
SRC=~/aukora-zip/c358ac7/packages/boundary-gate
N=~/aukora-prime-tools/node-v24.11.1-linux-x64
[ -x /opt/aukora-node/bin/node ] || { sudo -n mkdir -p /opt/aukora-node && sudo -n cp -a $N/bin $N/lib $N/include $N/share /opt/aukora-node/ 2>/dev/null || sudo -n cp -a $N/. /opt/aukora-node/; sudo -n chown -R root:root /opt/aukora-node; }
/opt/aukora-node/bin/node -v
sudo -n rm -rf /opt/aukora-boundary-gate && sudo -n cp -a $SRC /opt/aukora-boundary-gate && sudo -n chown -R root:root /opt/aukora-boundary-gate && sudo -n chmod -R go-w /opt/aukora-boundary-gate
G=$(getent group skgate | cut -d: -f3)
sudo -n install -d -o aukora-gate -g skgate -m 0750 /var/lib/aukora-boundary /var/lib/aukora-boundary/targets /var/lib/aukora-boundary/targets/plugins /var/lib/aukora-boundary/targets/plugins/auma-theme
[ -f /var/lib/aukora-boundary/targets/plugins/auma-theme/theme.json ] || { printf %s "{\"accent\": \"default\"}" | sudo -n -u aukora-gate tee /var/lib/aukora-boundary/targets/plugins/auma-theme/theme.json >/dev/null; sudo -n chmod 0640 /var/lib/aukora-boundary/targets/plugins/auma-theme/theme.json; sudo -n chgrp skgate /var/lib/aukora-boundary/targets/plugins/auma-theme/theme.json; }
sudo -n tee /etc/systemd/system/aukora-boundary-gate.service >/dev/null <<UNIT
[Unit]
Description=AUKORA lab: boundary gate (owner-only approvals, signed ledger and receipts)
After=network.target
[Service]
User=aukora-gate
Group=aukora-gate
SupplementaryGroups=skgate
UMask=0027
RuntimeDirectory=aukora-gate
RuntimeDirectoryMode=0750
ExecStartPre=+/bin/chgrp skgate /run/aukora-gate
ExecStart=/opt/aukora-node/bin/node /opt/aukora-boundary-gate/bin/gate.mjs serve --home /home/aukora-gate --run /run/aukora-gate --target-root /var/lib/aukora-boundary/targets --port 17792 --gid $G --time-zone Asia/Makassar
Restart=on-failure
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
UNIT
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now aukora-boundary-gate.service
sleep 4
systemctl is-active aukora-boundary-gate
sudo -n journalctl -u aukora-boundary-gate -n 6 --no-pager | cut -c1-260
sudo -n ls -la /run/aukora-gate
