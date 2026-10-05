set -u
SHA=4c24fd06e8f07b399b714aed547ef7646390f53e; S=4c24fd0; REL=/opt/aukora-genesis/release-$S
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
cd ~/aukora-zip/c358ac7 && git diff --quiet cdfb55f $SHA -- vendor/dsh && echo DSH_UNCHANGED && git checkout -q $SHA && git log --oneline -1 && [ -z "$(git status --porcelain)" ] && echo CLEAN
[ -e "$REL" ] && { echo REL_EXISTS; exit 1; }
sudo -n chown ubuntu:ubuntu /opt/aukora-genesis
AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to "$REL" > ~/aukora-zip/materialize-$S.log 2>&1; MAT=$?; echo "MAT_EXIT $MAT"
sudo -n chown root:root /opt/aukora-genesis
grep -E "materialize-release-failed" -A4 ~/aukora-zip/materialize-$S.log | cut -c1-300
if [ $MAT -eq 0 ]; then sudo -n chown -R root:root "$REL" && sudo -n chmod -R go-w,a+rX "$REL"; fi
grep -E "^(RECORD|PLUGIN SET|RELEASE MATERIALIZED|record sha256)" ~/aukora-zip/materialize-$S.log
git checkout -q cdfb55f && echo REPO_BACK $(git log --oneline -1 | cut -c1-7)
ls -ld $REL; ls /opt/aukora-genesis
