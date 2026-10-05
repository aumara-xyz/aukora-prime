#!/bin/bash
# AUKORA: read-only mirror of Prime main for Auma (Peter 11:22 item 1). Root-owned; Auma (guest gid -> auma-ws)
# and the harness (aukora-host in auma-ws) can read, nobody but root can write. Refresh = fetch + forced checkout.
# Lives inside the bound workspace so the guest sees it at /sandbox/prime-main; excluded from her git status.
set -euo pipefail
REMOTE=https://github.com/aumara-xyz/aukora-prime.git
BARE=/var/lib/aukora-prime-mirror/prime.git
WS=/srv/auma-ws/aukora-prime
DST=$WS/prime-main
umask 027
install -d -m 0700 -o root -g root /var/lib/aukora-prime-mirror
# Source: GitHub when reachable; otherwise an integrator-dropped bundle (hosts without egress, e.g. staging).
BUNDLE=/var/lib/aukora-prime-mirror/main.bundle
[ -d "$BARE" ] || git init -q --bare "$BARE"
if ! timeout 60 git -C "$BARE" fetch -q --prune "$REMOTE" '+refs/heads/main:refs/heads/main' 2>/dev/null; then
  [ -f "$BUNDLE" ] || { echo "prime-main: GitHub unreachable and no $BUNDLE" >&2; exit 1; }
  git bundle verify -q "$BUNDLE" >/dev/null 2>&1 || git -C "$BARE" bundle verify -q "$BUNDLE"
  REF=$(git -C "$BARE" bundle list-heads "$BUNDLE" | awk 'NR==1{print $2}'); git -C "$BARE" fetch -q "$BUNDLE" "+$REF:refs/heads/main"; echo "prime-main: from bundle"
fi
SHA=$(git -C "$BARE" rev-parse refs/heads/main)
TMP=$(mktemp -d "$WS/.prime-main.new.XXXXXX")
git -C "$BARE" archive "$SHA" | tar -x -C "$TMP"
printf '%s\n' "$SHA" > "$TMP/MAIN_SHA"
chown -R root:auma-ws "$TMP"; find "$TMP" -type d -exec chmod 2750 {} +; find "$TMP" -type f -exec chmod 0640 {} +
find "$TMP" -type f -perm /u+x -exec chmod 0750 {} + 2>/dev/null || true
OLD=""; [ -d "$DST" ] && OLD="$WS/.prime-main.old.$$" && mv "$DST" "$OLD"
mv "$TMP" "$DST"; [ -n "$OLD" ] && rm -rf --one-file-system "$OLD"
EX=$WS/.git/info/exclude; grep -qxF '/prime-main/' "$EX" 2>/dev/null || { printf '/prime-main/\n/.prime-main.*\n' >> "$EX"; }
echo "prime-main $SHA"
