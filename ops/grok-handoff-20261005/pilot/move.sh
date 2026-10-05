set -eu
# stop the ubuntu-run Genesis backend and its launcher (only processes whose cmdline names release-7ae564b)
for p in $(pgrep -u ubuntu -f "aukora-zip/release-7ae564b"); do [ "$p" != "$$" ] && kill "$p" 2>/dev/null || true; done
sleep 3
sudo -n install -d -o root -g root -m 0755 /opt/aukora-genesis
[ -d /opt/aukora-genesis/release-7ae564b ] || sudo -n mv /home/ubuntu/aukora-zip/release-7ae564b /opt/aukora-genesis/release-7ae564b
sudo -n chown -R root:root /opt/aukora-genesis/release-7ae564b && sudo -n chmod -R go-w,a+rX /opt/aukora-genesis/release-7ae564b
[ -d /opt/aukora-genesis/src ] || sudo -n git clone -q https://github.com/aumara-xyz/aukora-prime.git /opt/aukora-genesis/src
sudo -n git -C /opt/aukora-genesis/src checkout -q 7ae564b432aa7fcbefb0fc8310776f713436a1c8
sudo -n -u aukora-host -H git config --global --add safe.directory /opt/aukora-genesis/src
sudo -n install -d -o aukora-host -g aukora-host -m 0700 /home/aukora-host/genesis
[ -d /home/aukora-host/genesis/state ] || sudo -n cp -a /home/ubuntu/aukora-zip/state /home/aukora-host/genesis/state
sudo -n install -d -o aukora-host -g aukora-host -m 0700 /home/aukora-host/genesis/support
sudo -n chown -R aukora-host:aukora-host /home/aukora-host/genesis
sudo -n rm -f /home/aukora-host/genesis/state/launch-url.json /home/aukora-host/genesis/state/launch.json
sudo -n chmod 0700 /home/aukora-host /home/aukora-host/genesis/state
# remove the old copy of state that held the key under ubuntu
rm -rf /home/ubuntu/aukora-zip/state
sudo -n tee /etc/systemd/system/aukora-genesis.service >/dev/null <<UNIT
[Unit]
Description=AUKORA Genesis runtime (Prime 7ae564b) as aukora-host, loopback 127.0.0.1:18735
After=network-online.target aukora-boundary-gate.service aukora-auma-sandbox.service
Wants=aukora-boundary-gate.service aukora-auma-sandbox.service
[Service]
User=aukora-host
Group=aukora-host
UMask=0077
WorkingDirectory=/opt/aukora-genesis/src
Environment=PATH=/opt/aukora-node/bin:/usr/local/bin:/usr/bin:/bin
Environment=AUKORA_SUPPORT_ROOT=/home/aukora-host/genesis/support
Environment=AUKORA_STATE=/home/aukora-host/genesis/state
ExecStart=/usr/bin/python3 scripts/launch-dsh.py --release /opt/aukora-genesis/release-7ae564b --state-root /home/aukora-host/genesis/state --port 18735 --allow-unapproved --patch /opt/aukora-genesis/release-7ae564b/aukora-composition.patch.yml
KillMode=control-group
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now aukora-genesis.service
sleep 50
systemctl is-active aukora-genesis
sudo -n journalctl -u aukora-genesis -n 12 --no-pager | sed -E "s/token=[A-Za-z0-9_-]+/token=R/g" | cut -c1-220
ss -ltnp 2>/dev/null | grep 18735; ps -o user,pid,args -C node | grep release-7ae564b | cut -c1-120
df -h / | tail -1
