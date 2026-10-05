#!/bin/bash
# Usage: sudo bash deploy-claude.sh <claude-sha256-digest>
set -euo pipefail
DIG="$1"; [[ "$DIG" =~ ^[a-f0-9]{64}$ ]]
TS=$(date -u +%Y%m%d-%H%M)
SRC=/home/ubuntu/aukora-zip/relay-auma/relay
OLD=/opt/aukora-relay/releases/921b3c0-claude
NEW=/opt/aukora-relay/releases/921b3c0-auma
V=/var/lib/aukora-relay
UNIT=/etc/systemd/system/aukora-relay.service
[ -e "$NEW" ] && { echo "NEW exists"; exit 1; }
# installed unit must equal repo's prior version modulo release name
diff <(sed 's#921b3c0-claude#921b3c0-auma#g' "$UNIT") "$SRC/aukora-relay.service" && echo UNIT_MATCH
install -d -o root -g root -m 755 "$NEW" "$NEW/test"
for f in .gitignore auth.mjs check.mjs client.mjs contract.mjs package.json server.mjs store.mjs; do install -o root -g root -m 644 "$SRC/$f" "$NEW/$f"; done
install -o root -g root -m 644 "$SRC/test/relay.test.mjs" "$NEW/test/relay.test.mjs"
systemctl stop aukora-relay.service
trap 'echo FAILED-restoring; cp -p "/root/aukora-relay.service.bak-pre-auma-$TS" "$UNIT" 2>/dev/null; cp -p "$V/auth.json.bak-pre-auma-$TS" "$V/auth.json" 2>/dev/null; systemctl daemon-reload; systemctl start aukora-relay.service; systemctl is-active aukora-relay.service' ERR
cp -p "$V/relay.sqlite" "$V/relay.sqlite.bak-pre-auma-schema-$TS"
cp -p "$V/auth.json" "$V/auth.json.bak-pre-auma-$TS"
cp -p "$UNIT" "/root/aukora-relay.service.bak-pre-auma-$TS"
sudo -u aukora-relay /opt/aukora-relay/bin/node --no-warnings -e '
const {DatabaseSync}=require("node:sqlite");
const db=new DatabaseSync(process.argv[1]);
const before={}; for(const t of ["messages","status","storage_usage"]) before[t]=db.prepare(`select count(*) c from ${t}`).get().c;
const maxSeq=db.prepare("select max(seq) m from messages").get().m;
db.exec("BEGIN IMMEDIATE");
for (const t of ["messages","status","storage_usage"]) {
  const sql=db.prepare("select sql from sqlite_master where type=? and name=?").get("table",t).sql;
  const n=sql.split("\x27dot\x27,\x27claude\x27)").join("\x27dot\x27,\x27claude\x27,\x27auma\x27)");
  if (n===sql) throw new Error("no change "+t);
  db.exec(`ALTER TABLE ${t} RENAME TO ${t}_preclaude`);
  db.exec(n);
  db.exec(`INSERT INTO ${t} SELECT * FROM ${t}_preclaude; DROP TABLE ${t}_preclaude;`);
}
db.exec("COMMIT");
for(const t of Object.keys(before)){const c=db.prepare(`select count(*) c from ${t}`).get().c; if(c!==before[t]) throw new Error("count "+t); console.log(t,c);}
console.log("maxSeq",db.prepare("select max(seq) m from messages").get().m, "was", maxSeq, "seqtbl", JSON.stringify(db.prepare("select * from sqlite_sequence").all()));
console.log("integrity", db.prepare("pragma integrity_check").get().integrity_check);
for(const r of db.prepare("select name,sql from sqlite_master where type=\x27table\x27").all()) console.log(r.name, /auma/.test(r.sql||""));
' "$V/relay.sqlite"
sudo -u aukora-relay python3 - "$V/auth.json" "$DIG" <<'PY'
import json,sys,os
p,d=sys.argv[1],sys.argv[2]
a=json.load(open(p)); assert 'auma' not in a['tokenDigests']; assert d not in a['tokenDigests'].values()
a['tokenDigests']['auma']=d
tmp=p+'.new'; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,json.dumps(a,indent=2).encode()+b'\n'); os.close(fd); os.replace(tmp,p)
print('principals', sorted(a['tokenDigests']))
PY
install -o root -g root -m 644 "$SRC/aukora-relay.service" "$UNIT"
systemctl daemon-reload
systemctl start aukora-relay.service
sleep 2; systemctl is-active aukora-relay.service; systemctl show -p ExecStart aukora-relay.service | grep -o '/opt/aukora-relay/releases/[^ ]*'
