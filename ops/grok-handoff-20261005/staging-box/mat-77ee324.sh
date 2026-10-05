set -u
# Peter YES 11:49 WITA: prepare live switch 4c24fd0 -> 77ee324 (release/plugin set only; gate package unchanged, as RAN on staging)
SHA=77ee324; REL=/opt/aukora-genesis/release-$SHA
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
cd ~/aukora-zip/c358ac7 || exit 1
PREV=$(git rev-parse HEAD)
git fetch -q ~/aukora-zip/hygiene-77ee324.bundle release/hygiene:refs/heads/release/hygiene || exit 1
FULL=$(git rev-parse $SHA); echo "FULL $FULL"
git diff --quiet 4c24fd0 $FULL -- vendor/dsh && echo DSH_UNCHANGED
git checkout -q $FULL && git log --oneline -1 && [ -z "$(git status --porcelain)" ] && echo CLEAN
[ -e "$REL" ] && { echo REL_EXISTS; exit 1; }
sudo -n chown ubuntu:ubuntu /opt/aukora-genesis
AUKORA_STATE=$HOME/aukora-zip/matstate python3 scripts/materialize-aukora-release.py --to "$REL" > ~/aukora-zip/materialize-$SHA.log 2>&1; MAT=$?; echo "MAT_EXIT $MAT"
sudo -n chown root:root /opt/aukora-genesis
grep -E "materialize-release-failed" -A4 ~/aukora-zip/materialize-$SHA.log | cut -c1-300
if [ $MAT -eq 0 ]; then sudo -n chown -R root:root "$REL" && sudo -n chmod -R go-w,a+rX "$REL"; fi
grep -E "^(RECORD|PLUGIN SET|RELEASE MATERIALIZED|record sha256)" ~/aukora-zip/materialize-$SHA.log
git checkout -q $PREV && echo REPO_BACK $(git log --oneline -1 | cut -c1-7)
ls -ld $REL; ls /opt/aukora-genesis; df -h / | tail -1
