#!/bin/sh
# Root, on the pilot: install and load the auma host-local deny rule (persistent across reboot).
set -eu
B="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
id -u auma >/dev/null
[ "$(id -u auma)" = 1001 ] || { echo "auma uid is not 1001; edit the rule first" >&2; exit 1; }
grep -qx 'auma:165536:65536' /etc/subuid || { echo "auma subuid range differs; edit the rule first" >&2; exit 1; }
/usr/sbin/nft -c -f "$B/auma-local-deny.nft"
install -d -o root -g root -m 0755 /etc/aukora-boundary
install -o root -g root -m 0644 "$B/auma-local-deny.nft" /etc/aukora-boundary/auma-local-deny.nft
install -o root -g root -m 0644 "$B/aukora-auma-local-deny.service" /etc/systemd/system/aukora-auma-local-deny.service
systemctl daemon-reload
systemctl enable --now aukora-auma-local-deny.service
systemctl reload aukora-auma-local-deny.service
/usr/sbin/nft list table inet aukora_auma_local
