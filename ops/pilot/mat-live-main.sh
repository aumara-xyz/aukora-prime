#!/bin/bash
# PILOT HOST (Prime builder, 2026-10-13). Build the release directory for a commit of main BESIDE the live release.
# Nothing is approved, installed or switched: the live service keeps running its own release. Same method as mat-77ee324.sh.
set -u
C=${1:?commit}; S=${C:0:7}; REL=/opt/aukora-genesis/release-$S; OV=/home/aukora-host/genesis/state/home/openviking
export PATH=$HOME/aukora-prime-tools/node-v24.11.1-linux-x64/bin:$HOME/aukora-prime-tools/pnpm/node_modules/.bin:$PATH
umask 022
cd ~/prime-ci-clean || exit 1
[ "$(git rev-parse HEAD)" = "$C" ] && [ -z "$(git status --porcelain)" ] && echo "CLEAN at $S" || { echo NOT_CLEAN_AT_COMMIT; exit 1; }
[ -e "$REL" ] && { echo REL_EXISTS; exit 1; }
BEFORE=$(grep -o "release-[0-9a-f]*" /etc/aukora-genesis/release.env | head -1)
# The pilot still runs the older relay service and its plugin, so its releases keep them (--with-legacy-relay); a
# default release no longer mounts them.
# The owner's existing notes are readable only with the project map (scripts/kira/build-project-map.mjs made it).
MAP=""; [ -f /etc/aukora/kira-projects.json ] && MAP="--kira-project-map /etc/aukora/kira-projects.json" && echo "with project map"
sudo -n chown ubuntu:ubuntu /opt/aukora-genesis
AUKORA_STATE=$HOME/aukora-zip/matstate-live python3 scripts/materialize-aukora-release.py --from $HOME/aukora-zip/main-build/vendor/dsh --to "$REL" --kira-openviking-home "$OV" $MAP --with-legacy-relay > ~/aukora-zip/materialize-live-$S.log 2>&1; MAT=$?; echo "MAT_EXIT $MAT"
sudo -n chown root:root /opt/aukora-genesis
grep -E "materialize-release-failed" -A3 ~/aukora-zip/materialize-live-$S.log | cut -c1-300
[ $MAT -eq 0 ] && sudo -n chown -R root:root "$REL" && sudo -n chmod -R go-w,a+rX "$REL"
grep -E "^(RECORD|PLUGIN SET|RELEASE MATERIALIZED|record sha256)" ~/aukora-zip/materialize-live-$S.log | cut -c1-170
echo "live still: $(grep -o "release-[0-9a-f]*" /etc/aukora-genesis/release.env | head -1) (was $BEFORE); genesis $(systemctl is-active aukora-genesis)"; ls -ld /opt/aukora-genesis | cut -c1-40; df -h / | tail -1 | awk '{print "disk free", $4}'
