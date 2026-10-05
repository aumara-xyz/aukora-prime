#!/bin/bash
# STAGING ONLY: ./prime verify inside auma-ws (direct openshell exec; sbx-exec admission pending F's schema fix)
cd /tmp
echo "host workspace HEAD: $(git -c safe.directory=/srv/auma-ws/aukora-prime -C /srv/auma-ws/aukora-prime rev-parse HEAD)"
sudo -u auma env XDG_RUNTIME_DIR=/run/user/1001 OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=/home/auma/.local/state/openshell/tls HOME=/home/auma \
  openshell sandbox exec --name auma-ws --no-tty --timeout 900 -- /bin/bash -c 'cd /sandbox && export PATH=/usr/lib/aukora/node/bin:$PATH && node --version && command -v git; T0=$(date +%s); ./prime verify; echo "prime verify rc=$? in $(( $(date +%s)-T0 ))s"' </dev/null 2>&1
