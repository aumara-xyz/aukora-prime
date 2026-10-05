#!/bin/bash
# Staging stand-in for the pilot's aukora-relay.service (same release bytes, own empty DB, no real tokens), so the
# containment probe has a real relay process owned by a separate uid, as on the pilot. Port 18734 (18733 is the proxy).
set -euo pipefail
id aukora-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin aukora-relay
install -d -o root -g root -m 755 /opt/aukora-relay /opt/aukora-relay/releases /opt/aukora-relay/bin
rm -rf /opt/aukora-relay/releases/921b3c0-auma && cp -a /root/relay-auma/relay /opt/aukora-relay/releases/921b3c0-auma
chown -R root:root /opt/aukora-relay/releases/921b3c0-auma && chmod -R u+rwX,go+rX,go-w /opt/aukora-relay/releases/921b3c0-auma
ln -sf /opt/aukora-node/bin/node /opt/aukora-relay/bin/node
install -d -o aukora-relay -g aukora-relay -m 700 /var/lib/aukora-relay
D=$(head -c 48 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | sha256sum | cut -d' ' -f1)
sudo -u aukora-relay bash -c "umask 077; printf '{\"version\":1,\"tokenDigests\":{\"grok\":\"$D\"}}\n' > /var/lib/aukora-relay/auth.json"
sed -e 's/^Environment=RELAY_PORT=.*/Environment=RELAY_PORT=18734/' /opt/aukora-relay/releases/921b3c0-auma/aukora-relay.service > /etc/systemd/system/aukora-relay.service
grep -q RELAY_PORT=18734 /etc/systemd/system/aukora-relay.service
systemctl daemon-reload; systemctl restart aukora-relay; sleep 2; systemctl is-active aukora-relay; systemctl show -p MainPID aukora-relay
