set -u
SHA=cdfb55ff2ed5d3f4ceb8d6734cc4997241a1f2ff; S=cdfb55f; REL=/opt/aukora-genesis/release-$S
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
cd ~/aukora-zip/c358ac7 && rm -rf vendor/dsh.bak-pre-f57c0ee && git fetch -q origin main && git checkout -q $SHA && git log --oneline -1
ls vendor/dsh/.dsh-build/
sudo -n rm -rf /opt/aukora-genesis/release-cdfb55f.tmpx $REL; sudo -n chown ubuntu:ubuntu /opt/aukora-genesis
AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to "$REL" > ~/aukora-zip/materialize-$S.log 2>&1; MAT=$?; echo "MAT_EXIT $MAT"
sudo -n chown root:root /opt/aukora-genesis
grep -E "materialize-release-failed" -A4 ~/aukora-zip/materialize-$S.log | cut -c1-300
if [ $MAT -eq 0 ]; then sudo -n chown -R root:root "$REL" && sudo -n chmod -R go-w,a+rX "$REL"; sudo -n git -C /opt/aukora-genesis/src fetch -q origin main && sudo -n git -C /opt/aukora-genesis/src checkout -q $SHA; echo READY $(sudo -n git -c safe.directory=* -C /opt/aukora-genesis/src rev-parse HEAD); fi
