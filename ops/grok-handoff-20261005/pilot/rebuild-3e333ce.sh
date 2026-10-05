set -u
SHA=3e333cef39b399b3be4f5a7bb5707dc402e6c890; S=3e333ce; REL=/opt/aukora-genesis/release-$S
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
cd ~/aukora-zip/c358ac7 && git checkout -q $SHA && git status --short | head -3
rm -rf vendor/dsh; python3 scripts/build-dsh.py > ~/aukora-zip/build-$S.log 2>&1; echo "BUILD_EXIT $?"
ls vendor/dsh/.dsh-build/
sudo -n rm -rf $REL; sudo -n chown ubuntu:ubuntu /opt/aukora-genesis
AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to "$REL" > ~/aukora-zip/materialize-$S.log 2>&1; echo "MAT_EXIT $?"
sudo -n chown root:root /opt/aukora-genesis
grep -E "materialize-release-failed" -A4 ~/aukora-zip/materialize-$S.log | cut -c1-300
