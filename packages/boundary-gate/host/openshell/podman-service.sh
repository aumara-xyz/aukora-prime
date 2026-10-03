#!/usr/bin/env bash
# Rootless Podman API socket for Linux user auma (start as: sudo -n -u auma -H <this script>).
set -e
export XDG_RUNTIME_DIR=/run/user/$(id -u); cd "$HOME"
mkdir -p "$XDG_RUNTIME_DIR/podman"
exec podman system service --time=0 "unix://$XDG_RUNTIME_DIR/podman/podman.sock"
