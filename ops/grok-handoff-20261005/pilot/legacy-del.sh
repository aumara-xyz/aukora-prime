#!/bin/bash
# STAGING ONLY: delete the legacy (unbound) auma-ws with the stock 0.1.2 gateway, then reinstall the binding gateway
set -u
A="sudo -u auma env XDG_RUNTIME_DIR=/run/user/1001 OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=/home/auma/.local/state/openshell/tls HOME=/home/auma"
cd /tmp
install -m 0755 /root/openshell-gateway-0.1.2-stock.bak /usr/bin/openshell-gateway; systemctl restart aukora-openshell-gateway; sleep 6
$A openshell sandbox delete auma-ws </dev/null 2>&1 | tail -2
for i in $(seq 1 60); do $A openshell sandbox list 2>/dev/null | grep -q '^auma-ws' || break; sleep 1; done
$A openshell sandbox list 2>&1 | tail -2
$A podman ps -a --format '{{.Names}}' | grep auma-ws || echo "no auma-ws containers"
install -m 0755 /root/openshell-gateway-f /usr/bin/openshell-gateway; systemctl restart aukora-openshell-gateway; sleep 6
sha256sum /usr/bin/openshell-gateway | cut -c1-16; systemctl is-active aukora-openshell-gateway
