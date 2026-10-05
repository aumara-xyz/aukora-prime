set -eu
R=~/aukora-zip/c358ac7/packages/boundary-gate
sudo -n install -m 0755 -o root -g root /tmp/os/openshell /tmp/os/openshell-gateway /usr/bin/
openshell --version; openshell-gateway --version
sudo -n install -d -m 0755 -o root -g root /usr/local/lib/aukora-boundary /usr/local/lib/aukora-boundary/openshell
sudo -n install -m 0755 -o root -g root $R/host/sbx-exec /usr/local/lib/aukora-boundary/sbx-exec
sudo -n install -m 0755 -o root -g root $R/host/openshell/*.sh /usr/local/lib/aukora-boundary/openshell/
sudo -n install -m 0644 -o root -g root $R/host/openshell/gateway-metadata.json /usr/local/lib/aukora-boundary/openshell/
sudo -n cp $R/host/sudoers.template /tmp/aukora-boundary.sudo
sudo -n visudo -cf /tmp/aukora-boundary.sudo
sudo -n install -m 0440 -o root -g root /tmp/aukora-boundary.sudo /etc/sudoers.d/aukora-boundary
sudo -n rm /tmp/aukora-boundary.sudo
sudo -n visudo -c | tail -2
sudo -n tee /etc/systemd/system/aukora-auma-podman.service >/dev/null <<UNIT
[Unit]
Description=AUKORA lab: rootless Podman API for auma
After=user@1001.service
Wants=user@1001.service
[Service]
User=auma
Group=auma
ExecStart=/usr/local/lib/aukora-boundary/openshell/podman-service.sh
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
sudo -n tee /etc/systemd/system/aukora-openshell-gateway.service >/dev/null <<UNIT
[Unit]
Description=AUKORA lab: NVIDIA OpenShell 0.1.2 gateway (podman driver, 127.0.0.1:17690, mTLS) for auma
After=aukora-auma-podman.service
Requires=aukora-auma-podman.service
[Service]
User=auma
Group=auma
ExecStart=/usr/local/lib/aukora-boundary/openshell/gateway.sh
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
sudo -n tee /etc/systemd/system/aukora-auma-sandbox.service >/dev/null <<UNIT
[Unit]
Description=AUKORA lab: ensure OpenShell sandbox auma-ws (network none)
After=aukora-openshell-gateway.service
Requires=aukora-openshell-gateway.service
[Service]
Type=oneshot
RemainAfterExit=yes
User=auma
Group=auma
TimeoutStartSec=900
ExecStart=/usr/local/lib/aukora-boundary/openshell/ensure-sandbox.sh
[Install]
WantedBy=multi-user.target
UNIT
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now aukora-auma-podman.service aukora-openshell-gateway.service
sleep 15
systemctl is-active aukora-auma-podman aukora-openshell-gateway
sudo -n journalctl -u aukora-openshell-gateway -n 15 --no-pager | cut -c1-250
