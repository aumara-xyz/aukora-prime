#!/bin/bash
# Peter YES 11:49 WITA: remove live release-3ac3509, release-e337397 (and staging release-5fc1fea, run separately).
# Rescue first: full file list (mode owner size mtime path) + sha256 list (excl. node_modules) + small config tarball.
# Never touches 4c24fd0 (running), cdfb55f (rollback), /etc/aukora-approvals, keys, chains or state.
set -euo pipefail
B=/var/backups/aukora-release-rescue; install -d -m 0700 "$B"
TS=$(date -u +%Y%m%dT%H%M%SZ)
CUR=$(sed -n 's/^AUKORA_RELEASE_DIR=//p' /etc/aukora-genesis/release.env 2>/dev/null || true)
for r in "$@"; do
  case "$r" in 4c24fd0|cdfb55f|77ee324) echo "REFUSE protected release $r"; exit 1;; esac
  d=/opt/aukora-genesis/release-$r
  [ -d "$d" ] || { echo "SKIP $r (absent)"; continue; }
  [ "$CUR" != "$d" ] || { echo "REFUSE $r is the running release"; exit 1; }
  if (for q in /proc/[0-9]*; do readlink "$q/cwd" "$q/exe" 2>/dev/null; grep -hF "$d/" "$q/maps" 2>/dev/null; done; lsof +D "$d" 2>/dev/null | tail -n +2) | grep -qF "$d"; then echo "REFUSE $r is in use by a process"; exit 1; fi
  find "$d" -printf '%M %u:%g %s %TY-%Tm-%TdT%TH:%TM %P\n' | sort -k5 | gzip -9 > "$B/release-$r-$TS.files.gz"
  (cd "$d" && find . -path ./node_modules -prune -o -type f -print0 | sort -z | xargs -0 sha256sum) | gzip -9 > "$B/release-$r-$TS.sha256.gz"
  (cd "$d" && tar czf "$B/release-$r-$TS-config.tgz" --ignore-failed-read $(ls -d *.yml *.json strip-manifest.json 2>/dev/null | sort -u))
  echo "RESCUE $r: $(ls -l $B/release-$r-$TS.* $B/release-$r-$TS-config.tgz | awk '{print $NF" "$5}' | tr '\n' ' ')"
  rm -rf --one-file-system "$d"; echo "REMOVED $d"
done
df -h / | tail -1
