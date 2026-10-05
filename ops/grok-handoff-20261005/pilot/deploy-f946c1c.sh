set -eu
SHA=f946c1c0431c2bf7da0d1d1b4c0490e03cd1df25; S=f946c1c; REL=/opt/aukora-genesis/release-$S
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
cd ~/aukora-zip/c358ac7
git fetch -q origin main && git checkout -q $SHA && git log --oneline -1
if [ ! -d "$REL" ]; then sudo -n install -d -o ubuntu -g ubuntu -m 0755 "$REL" && sudo -n rmdir "$REL"; sudo -n install -d -o ubuntu -g ubuntu -m 0755 /opt/aukora-genesis/stage-$S; fi
# materializer needs to create the target dir itself; give ubuntu a writable parent via a staging symlink-free approach:
sudo -n chown ubuntu:ubuntu /opt/aukora-genesis
set +e
AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to "$REL" > ~/aukora-zip/materialize-$S.log 2>&1; MAT=$?
if [ $MAT -ne 0 ]; then echo "MAT_FIRST_EXIT $MAT; rebuilding DSH"; python3 scripts/build-dsh.py > ~/aukora-zip/build-$S.log 2>&1; echo "BUILD_DSH_EXIT $?"; rm -rf "$REL"; AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to "$REL" > ~/aukora-zip/materialize-$S.log 2>&1; MAT=$?; fi
set -e
sudo -n chown root:root /opt/aukora-genesis; sudo -n rmdir /opt/aukora-genesis/stage-$S 2>/dev/null || true
echo "MAT_EXIT $MAT"; [ $MAT -eq 0 ]
sudo -n chown -R root:root "$REL" && sudo -n chmod -R go-w,a+rX "$REL"
grep -c "confineReads" "$REL/plugins/aukora-action-gate/lib/index.mjs"
sudo -n git -C /opt/aukora-genesis/src fetch -q origin main && sudo -n git -C /opt/aukora-genesis/src checkout -q $SHA
sudo -n sed -i "s#release-7ae564b#release-$S#g; s#(Prime 7ae564b)#(Prime $S)#" /etc/systemd/system/aukora-genesis.service
sudo -n systemctl daemon-reload && sudo -n systemctl restart aukora-genesis.service
sleep 40
systemctl is-active aukora-genesis
sudo -n journalctl -u aukora-genesis -n 6 --no-pager | sed -E "s/token=[A-Za-z0-9_-]+/token=R/g" | cut -c1-200
sudo -n ls -l /home/aukora-host/genesis/state/launch-url.json
df -h / | tail -1
echo DEPLOY-DONE
