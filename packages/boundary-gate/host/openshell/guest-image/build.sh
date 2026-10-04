#!/usr/bin/env bash
# Run as auma: build localhost/aukora-guest:<inputs-digest> and retag :current.
#   build.sh <node-binary> <exec.py> <ptc process.js>
# Production inputs: /opt/aukora-node/bin/node, <release>/plugins/aukora-openshell-confinement/guest/exec.py,
# <release>/packages/ptc-runtime/ptc-runtime-node/lib/process.js. Then run ensure-sandbox.sh, which recreates auma-ws
# from :current (keeping /sandbox through its snapshot) when the running container uses another image.
set -euo pipefail
[ "$#" -eq 3 ] || { echo "usage: build.sh <node> <exec.py> <process.js>" >&2; exit 2; }
export XDG_RUNTIME_DIR=/run/user/$(id -u)
ctx=$(mktemp -d); trap 'rm -rf "$ctx"' EXIT
install -m 0755 "$1" "$ctx/node"; install -m 0644 "$2" "$ctx/exec.py"; install -m 0644 "$3" "$ctx/process.js"
cp "$(dirname "$0")/Containerfile" "$ctx/"
(cd "$ctx" && sha256sum node exec.py process.js Containerfile) > "$ctx/INPUTS"
tag=$(sha256sum "$ctx/INPUTS" | cut -c1-12)
podman build -q -t "localhost/aukora-guest:$tag" -t localhost/aukora-guest:current "$ctx" >/dev/null
echo "localhost/aukora-guest:$tag (current)"; cat "$ctx/INPUTS"
