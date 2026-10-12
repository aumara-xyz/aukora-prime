#!/usr/bin/env bash
# Build the relay image from a source tree already unpacked at /var/lib/aukora-buzz/src/<commit>.
# Run as aukora-buzz. Usage: build.sh <full commit of aumara-xyz/aukora-buzz>
# The build is niced and held to four compile jobs so the harness on the same machine keeps its share.
set -euo pipefail
# No login session exists for this user; point Podman at the lingering user manager, as the node's other
# rootless Podman service does.
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
SHA="${1:?usage: build.sh <commit>}"
ROOT=/var/lib/aukora-buzz
SRC="$ROOT/src/$SHA"
[ -f "$SRC/Dockerfile" ] || { echo "no source at $SRC" >&2; exit 1; }
cd "$ROOT"
nice -n 19 podman build --target runtime \
  --env CARGO_BUILD_JOBS="${AUKORA_BUZZ_BUILD_JOBS:-4}" \
  --build-arg BUZZ_SOURCE_SHA="$SHA" --build-arg BUZZ_BUILD_ID="aukora-node" \
  -t "localhost/aukora-buzz-relay:${SHA:0:12}" "$SRC"
umask 077
printf 'IMAGE=localhost/aukora-buzz-relay:%s\nSOURCE_SHA=%s\n' "${SHA:0:12}" "$SHA" > "$ROOT/image.env"
# The builder stages are several gigabytes; only the runtime image is kept.
podman image prune -f >/dev/null
echo "built localhost/aukora-buzz-relay:${SHA:0:12}"
