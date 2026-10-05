#!/bin/bash
set -e
C=${1:?commit}; S=${C:0:7}
git -C /opt/aukora-genesis/src fetch -q /root/hygiene.bundle release/hygiene:refs/heads/release/hygiene && git -C /opt/aukora-genesis/src -c advice.detachedHead=false checkout -q --detach $C
ls /mnt/dsh >/dev/null && ls /mnt/tools >/dev/null
rm -rf /root/mat-src-hyg && git clone -q /opt/aukora-genesis/src /root/mat-src-hyg && cd /root/mat-src-hyg && git -c advice.detachedHead=false checkout -q --detach $C
export PATH=/mnt/tools/node-v24.11.1-linux-x64/bin:/mnt/tools/pnpm/node_modules/.bin:/usr/bin:/bin AUKORA_STATE=/root/matstate-hyg HOME=/root
umask 022
python3 scripts/materialize-aukora-release.py --from /mnt/dsh --to /opt/aukora-genesis/release-$S
echo MAT_EXIT $?
chmod -R u+rwX,go+rX,go-w /opt/aukora-genesis/release-$S
