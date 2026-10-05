export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:/usr/local/bin:/usr/bin:/bin
export AUKORA_SUPPORT_ROOT=$HOME/aukora-zip/support AUKORA_STATE=$HOME/aukora-zip/state
umask 077
cd ~/aukora-zip/c358ac7
echo "LAUNCH START $(date -Is)"
exec python3 scripts/launch-dsh.py --release $HOME/aukora-zip/release-7ae564b --state-root $HOME/aukora-zip/state --port 18735 --allow-unapproved --patch $HOME/aukora-zip/release-7ae564b/aukora-composition.patch.yml
