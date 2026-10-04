#!/usr/bin/env bash
# NVIDIA OpenShell 0.1.2 gateway for Linux user auma: podman compute driver, loopback port 17690, mTLS.
# Certificates are generated into auma's private state directory on first start; none are published.
set -e
export XDG_RUNTIME_DIR=/run/user/$(id -u); cd "$HOME"
export OPENSHELL_LOCAL_TLS_DIR="$HOME/.local/state/openshell/tls" OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_COMPUTE_DRIVER=podman OPENSHELL_SERVER_PORT=17690
# Exact v0.1.2 Podman-driver configuration knob. Workload root must be a
# subordinate identity; supervisor remains in its explicitly observed host scope.
export OPENSHELL_PODMAN_USERNS=auto:size=65536
for i in $(seq 1 30); do curl -sf --unix-socket "$XDG_RUNTIME_DIR/podman/podman.sock" http://d/_ping >/dev/null && break; sleep 1; done
[ -f "$OPENSHELL_LOCAL_TLS_DIR/server/tls.crt" ] || openshell-gateway generate-certs --output-dir "$OPENSHELL_LOCAL_TLS_DIR" --server-san host.openshell.internal
openshell-gateway config preflight
exec openshell-gateway
