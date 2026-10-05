set -u
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
cd ~/aukora-zip/c358ac7
python3 scripts/build-dsh.py > ~/aukora-zip/build2.log 2>&1; echo "BUILD_DSH_EXIT $?"
mkdir -p -m 700 ~/aukora-zip/matstate
AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to /opt/aukora-genesis/release-7ae564b > ~/aukora-zip/materialize2.log 2>&1; echo "MAT_EXIT $?"
echo REBUILD DONE
