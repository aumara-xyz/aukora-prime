#!/bin/bash
# STAGING ONLY: temporary g+w mechanics test (top dir 2771), reverted to 2751 at end
A="sudo -u auma env XDG_RUNTIME_DIR=/run/user/1001 OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=/home/auma/.local/state/openshell/tls HOME=/home/auma"
cd /tmp
chmod 2771 /srv/auma-ws/aukora-prime
G='printf bindproof > /sandbox/auma-scratch-bind-proof.txt && echo "GUEST WRITE top (g+w): ALLOWED" || echo "GUEST WRITE top: DENIED"; ls -ln /sandbox/auma-scratch-bind-proof.txt 2>&1; printf x > /sandbox/docs/x 2>/dev/null && echo "WRITE subdir(2750): ALLOWED" || echo "WRITE subdir(2750): DENIED"; ls -lnd /sandbox /sandbox/.git'
$A openshell sandbox exec --name auma-ws --no-tty --timeout 30 -- /bin/bash -c "$G" </dev/null 2>&1
echo "== host side"; ls -ln /srv/auma-ws/aukora-prime/auma-scratch-bind-proof.txt 2>&1
sudo -u aukora-host cat /srv/auma-ws/aukora-prime/auma-scratch-bind-proof.txt 2>&1; echo
rm -f /srv/auma-ws/aukora-prime/auma-scratch-bind-proof.txt
chmod 2751 /srv/auma-ws/aukora-prime; ls -ld /srv/auma-ws/aukora-prime
