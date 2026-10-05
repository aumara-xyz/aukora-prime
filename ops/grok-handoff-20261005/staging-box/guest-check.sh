#!/bin/bash
# STAGING ONLY: guest checks via direct `openshell sandbox exec` as auma (sbx-exec admission not yet passable: profile pending F)
A="sudo -u auma env XDG_RUNTIME_DIR=/run/user/1001 OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_LOCAL_TLS_DIR=/home/auma/.local/state/openshell/tls HOME=/home/auma"
cd /tmp
G='set +e; echo "id: $(id)"; echo "pwd: $(cd /sandbox && pwd)"; ls /sandbox | head -5; echo "HEAD: $(cat /sandbox/.git/HEAD)"; R0=$(git -C /sandbox rev-parse HEAD 2>&1); echo "rev before: $R0"
printf x > /sandbox/auma-scratch-bind-proof.txt 2>&1 && echo "WRITE /sandbox: ALLOWED" || echo "WRITE /sandbox: DENIED"
printf x >> /sandbox/.git/HEAD 2>/dev/null && echo "WRITE .git/HEAD: ALLOWED" || echo "WRITE .git/HEAD: DENIED ($?)"
mv /sandbox/.git /sandbox/.git-moved 2>&1 | head -1; [ -d /sandbox/.git ] && echo "mv .git: DENIED (still there)"
GIT_OPTIONAL_LOCKS=0 git -C /sandbox status --short 2>&1 | head -2; git -C /sandbox -c user.email=a@b -c user.name=a commit --allow-empty -m x 2>&1 | tail -1
echo "rev after: $(git -C /sandbox rev-parse HEAD 2>&1)"
printf y > /tmp/t && echo "WRITE /tmp: OK (tmpfs)"; printf y > /etc/x 2>/dev/null && echo "WRITE /etc: ALLOWED" || echo "WRITE /etc: DENIED"
grep -E " /sandbox| /tmp | / " /proc/self/mountinfo | cut -d" " -f4-6,9-11
ls /home/aukora-host 2>&1 | head -1; ls /srv/aukora-boundary 2>&1 | head -1'
$A openshell sandbox exec --name auma-ws --no-tty --timeout 60 -- /bin/bash -c "$G" </dev/null 2>&1
echo "== host side"; ls -la /srv/auma-ws/aukora-prime/auma-scratch-bind-proof.txt 2>&1; git -C /srv/auma-ws/aukora-prime rev-parse HEAD
