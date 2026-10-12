#!/usr/bin/env bash
# Stop the relay pod. Data under /var/lib/aukora-buzz/data is kept. Run as aukora-buzz.
set -euo pipefail
# No login session exists for this user; point Podman at the lingering user manager, as the node's other
# rootless Podman service does.
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
if podman pod exists aukora-buzz; then
  podman pod stop -t 20 aukora-buzz >/dev/null
else
  status=$?
  # Only exit 1 establishes absence; inspection errors must fail the stop job.
  if [ "$status" -ne 1 ]; then exit "$status"; fi
fi
exit 0
