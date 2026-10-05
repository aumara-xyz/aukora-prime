set -eu
SHA=$1; S=${SHA:0:7}; REL=/opt/aukora-genesis/release-$S; OLD=$(sudo -n grep -o "release-[0-9a-f]\{7\}" /etc/aukora-genesis/release.env | head -1)
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
cd ~/aukora-zip/c358ac7
git fetch -q origin main && git checkout -q $SHA && git log --oneline -1
sudo -n chown ubuntu:ubuntu /opt/aukora-genesis
set +e
AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to "$REL" > ~/aukora-zip/materialize-$S.log 2>&1; MAT=$?
if [ $MAT -ne 0 ]; then echo "MAT_FIRST_EXIT $MAT; rebuilding DSH"; python3 scripts/build-dsh.py > ~/aukora-zip/build-$S.log 2>&1; echo "BUILD_DSH_EXIT $?"; rm -rf "$REL"; AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to "$REL" > ~/aukora-zip/materialize-$S.log 2>&1; MAT=$?; fi
set -e
sudo -n chown root:root /opt/aukora-genesis
echo "MAT_EXIT $MAT"; [ $MAT -eq 0 ]
sudo -n chown -R root:root "$REL" && sudo -n chmod -R go-w,a+rX "$REL"
sudo -n git -C /opt/aukora-genesis/src fetch -q origin main && sudo -n git -C /opt/aukora-genesis/src checkout -q $SHA
echo READY-TO-RESTART $OLD '->' release-$S
