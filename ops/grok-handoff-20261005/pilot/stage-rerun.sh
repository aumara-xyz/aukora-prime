#!/bin/bash
# Runs INSIDE aukora-staging as root. Staging-only relay on 127.0.0.1:18733 (container), fresh staging keys, paired driver rerun with raw output saved.
set -euo pipefail
TS=$(date -u +%Y%m%dT%H%M%SZ); EV=/root/evidence/auma-rerun-$TS; mkdir -p -m 700 $EV; OUT=$EV/raw.log
exec > >(tee -a $OUT) 2>&1
echo "RUN $TS host=$(hostname) (aukora-staging container; staging-only relay; live relay/key untouched)"
ss -ltn | grep -q '127.0.0.1:18733' && { echo "18733 still bound (proxy device?)"; exit 1; }
U=/etc/systemd/system/aukora-relay.service
sed -i 's/^Environment=RELAY_PORT=.*/Environment=RELAY_PORT=18733/' $U
# fresh staging keys: auma (aukora-host) + staging seeder (root only)
KA=/home/aukora-host/.config/aukora-relay/auma.key
[ -e $KA ] && mv $KA $KA.revoked-$TS
sudo -u aukora-host bash -c "umask 077; head -c 48 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > $KA"
install -d -m 700 /root/.staging-relay; KS=/root/.staging-relay/seeder.key
(umask 077; head -c 48 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > $KS)
DA=$(sha256sum < $KA | cut -d' ' -f1); DS=$(sha256sum < $KS | cut -d' ' -f1)
echo "STAGING auma key digest prefix ${DA:0:8} (live auma is 6d02f697); seeder (author grok, staging only) prefix ${DS:0:8}"
systemctl stop aukora-relay
sudo -u aukora-relay bash -c "umask 077; printf '{\"version\":1,\"tokenDigests\":{\"grok\":\"$DS\",\"auma\":\"$DA\"}}\n' > /var/lib/aukora-relay/auth.json.new && mv /var/lib/aukora-relay/auth.json.new /var/lib/aukora-relay/auth.json"
systemctl daemon-reload; systemctl start aukora-relay; sleep 2
echo "staging relay $(systemctl is-active aukora-relay) pid $(systemctl show -p MainPID --value aukora-relay) on $(ss -ltnp | grep 18733 | awk '{print $4}')"
# seed 20 synthetic project-test messages as staging 'grok'
for i in $(seq 1 20); do
  python3 - "$KS" "$i" <<'PY'
import json,sys,urllib.request,time
k=open(sys.argv[1]).read().strip(); i=sys.argv[2]
b=json.dumps({'clientRequestId':f'staging-seed-{i}-{time.time_ns()}','kind':'chat','refs':[],'body':f'STAGING SEED {i}: synthetic project-test message for the paired AUMA relay rerun.'}).encode()
r=urllib.request.Request('http://127.0.0.1:18733/v1/messages',data=b,method='POST',headers={'authorization':'Bearer '+k,'content-type':'application/json'})
urllib.request.urlopen(r).read()
PY
sleep 1; done; echo "seeded 20"
REL=/opt/aukora-genesis/release-4c24fd0; D=/tmp/auma-accept.mjs
cp /root/auma-accept.mjs $D && chmod 644 $D
echo "DRIVER $D sha256 $(sha256sum < $D | cut -d' ' -f1) (source /root/auma-accept.mjs $(sha256sum < /root/auma-accept.mjs | cut -d' ' -f1))"
echo "PLUGIN_BEFORE $(sha256sum < $REL/plugins/aukora-relay-auma/lib/index.mjs | cut -d' ' -f1)"
G=/home/aukora-gate/gate.db
q(){ /opt/aukora-node/bin/node --no-warnings -e 'const {DatabaseSync}=require("node:sqlite");const db=new DatabaseSync(process.argv[1],{readOnly:true});for(const r of db.prepare(process.argv[2]).all())console.log(process.argv[3],JSON.stringify(r))' "$@"; }
q $G "select max(seq) maxseq from ledger" LEDGER_BEFORE
echo "DRIVER_START $(date -u +%FT%T.%3NZ)"
cd /tmp && sudo -u aukora-host env -i PATH=/usr/bin:/bin HOME=/home/aukora-host /opt/aukora-node/bin/node --no-warnings $D $REL "AUMA STAGING PAIRED RERUN $TS: synthetic project-test post via the installed relay_post tool. Advisory only, not an order." || echo "DRIVER_EXIT $?"
echo "DRIVER_END $(date -u +%FT%T.%3NZ)"
echo "PLUGIN_AFTER $(sha256sum < $REL/plugins/aukora-relay-auma/lib/index.mjs | cut -d' ' -f1)"
q $G "select seq,at,event,detail,hash from ledger where seq > (select max(seq)-8 from ledger) and event like 'relay-%' order by seq" LEDGER_RELAY
q /var/lib/aukora-relay/relay.sqlite "select * from messages where author='auma' order by rowid" RELAY_AUMA_ROWS 2>/dev/null || q /var/lib/aukora-relay/relay.sqlite "select name from sqlite_master" RELAY_TABLES
echo "SAVED $OUT"
