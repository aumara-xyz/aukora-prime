set -u
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
cd ~/aukora-zip/c358ac7
echo "BUILD START $(date -Is)"
python3 scripts/build-dsh.py; echo "BUILD_DSH_EXIT $?"
echo "BUILD END $(date -Is)"
