#!/bin/bash
# STAGING ONLY: verify Auma's read-only Prime main mirror (guest via direct openshell exec; host as aukora-host)
A="sudo -u auma env XDG_RUNTIME_DIR=/run/user/1001 OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=/home/auma/.local/state/openshell/tls HOME=/home/auma"
cd /tmp
$A openshell sandbox list 2>&1 | tail -1
G='echo "guest MAIN_SHA: $(cat /sandbox/prime-main/MAIN_SHA)"; head -c 60 /sandbox/prime-main/plan/ORGANISM.md; echo
printf x > /sandbox/prime-main/x 2>/dev/null && echo "guest WRITE prime-main: ALLOWED" || echo "guest WRITE prime-main: DENIED"
printf x >> /sandbox/prime-main/AGENTS.md 2>/dev/null && echo "guest APPEND file: ALLOWED" || echo "guest APPEND file: DENIED"
rm -f /sandbox/prime-main/AGENTS.md 2>/dev/null && echo "guest RM: ALLOWED" || echo "guest RM: DENIED"
mv /sandbox/prime-main /sandbox/pm2 2>/dev/null && echo "guest MV dir: ALLOWED" || echo "guest MV dir: DENIED"'
$A openshell sandbox exec --name auma-ws --no-tty --timeout 30 -- /bin/bash -c "$G" </dev/null 2>&1
echo "host aukora-host read: $(sudo -u aukora-host cat /srv/auma-ws/aukora-prime/prime-main/MAIN_SHA 2>&1)"
sudo -u aukora-host sh -c 'printf x > /srv/auma-ws/aukora-prime/prime-main/x' 2>/dev/null && echo "host aukora-host WRITE: ALLOWED" || echo "host aukora-host WRITE: DENIED"
sudo -u auma sh -c 'printf x > /srv/auma-ws/aukora-prime/prime-main/x' 2>/dev/null && echo "host auma WRITE: ALLOWED" || echo "host auma WRITE: DENIED"
sudo -u auma sh -c 'mv /srv/auma-ws/aukora-prime/prime-main /srv/auma-ws/aukora-prime/pm2' 2>/dev/null && echo "host auma MV (owner of parent): ALLOWED" || echo "host auma MV: DENIED"
ls -ld /srv/auma-ws/aukora-prime/prime-main /srv/auma-ws/aukora-prime/pm2 2>&1 | cut -c1-80
