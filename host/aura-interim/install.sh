#!/bin/bash
# INTERIM Aura collector install (Grok, 2026-10-04). Run with sudo on the pilot.
set -euo pipefail
B=$(cd "$(dirname "$0")" && pwd)
. /etc/aukora-genesis/release.env; export AUKORA_RELEASE_DIR
N=/opt/aukora-node/bin/node
id aukora-aura >/dev/null 2>&1 || useradd --system --home-dir /var/lib/aukora-aura --shell /usr/sbin/nologin --user-group aukora-aura
U=$(id -u aukora-aura); G=$(id -g aukora-aura)
install -d -o root -g aukora-aura -m 0750 /etc/aukora-aura
install -d -o root -g root -m 0755 /usr/local/lib/aukora-aura
install -d -o aukora-aura -g aukora-aura -m 0700 /var/lib/aukora-aura /var/lib/aukora-aura/store /var/lib/aukora-aura/snapshot
install -o root -g root -m 0644 "$B/snapshot.mjs" "$B/anchor.mjs" "$B/verify.mjs" "$B/keygen.mjs" /usr/local/lib/aukora-aura/
install -o root -g root -m 0644 "$B/context.mjs" /etc/aukora-aura/context.mjs
install -o root -g aukora-aura -m 0644 /run/aukora-gate/receipt-ed25519.pub /etc/aukora-aura/gate-receipt-ed25519.pub
$N -e 'const {createPublicKey,createHash}=require("node:crypto");const k=createPublicKey(require("fs").readFileSync("/etc/aukora-aura/gate-receipt-ed25519.pub"));process.stdout.write(createHash("sha256").update(k.export({type:"spki",format:"der"})).digest("hex")+"\n")' > /etc/aukora-aura/gate-key.sha256
chmod 0644 /etc/aukora-aura/gate-key.sha256
(cd /etc/aukora-aura && $N /usr/local/lib/aukora-aura/keygen.mjs)
chgrp aukora-aura /etc/aukora-aura/author-INTERIM.key
$N /usr/local/lib/aukora-aura/anchor.mjs /home/aukora-gate/gate.db
sed "s/AURA_UID/$U/; s/AURA_GID/$G/" "$B/aukora-aura-collector.service" > /etc/systemd/system/aukora-aura-collector.service
install -o root -g root -m 0644 "$B/aukora-aura-collector.timer" /etc/systemd/system/
systemctl daemon-reload
echo INSTALLED
