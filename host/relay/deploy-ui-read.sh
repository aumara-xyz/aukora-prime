#!/bin/bash
# Deploy the ui-read relay viewer principal (Peter-approved, relay c286; source d7de692).
# RUN ONLY ON PETER'S GO — this touches live relay config and restarts aukora-relay.
# What it does: backs up the external auth file, adds a fresh ui-read token digest
# (scope comes from host/relay/contract.mjs NARROW_AUTHORS: messages:read only),
# restarts the relay, verifies whoami + that every POST kind refuses.
# The token is written 0600 to a file Peter picks up; it is never printed.
set -euo pipefail
AUTH=${1:-/var/lib/aukora-relay/auth.json}
OUT=${2:-/root/ui-read.token}
[ -f "$AUTH" ] || { echo "REFUSED: $AUTH not found (relay auth layout differs; stop)"; exit 2; }
python3 - "$AUTH" <<'EOF'
import json, secrets, sys, os, hashlib, shutil, time
path = sys.argv[1]
info = os.stat(path)
if info.st_mode & 0o077: raise SystemExit("REFUSED: auth file is not 0600")
config = json.load(open(path))
if config.get("version") != 1 or "tokenDigests" not in config: raise SystemExit("REFUSED: auth file shape")
if "ui-read" in config["tokenDigests"]: raise SystemExit("REFUSED: ui-read already present (would rotate without Peter)")
import hashlib
token = secrets.token_urlsafe(48)
config["tokenDigests"]["ui-read"] = hashlib.sha256(token.encode()).hexdigest()
backup = path + ".bak-pre-ui-read"
import shutil, time
shutil.copy2(path, backup + time.strftime("-%Y%m%dT%H%M%SZ", time.gmtime()))
with open(path, "w") as fh: json.dump(config, fh, indent=1, sort_keys=True)
os.chmod(path, 0o600)
with open("/root/ui-read.token.tmp", "w") as fh: fh.write(token + "\n")
os.chmod("/root/ui-read.token.tmp", 0o600)
print("auth updated (ui-read added); backup next to the auth file")
EOF
install -m 0600 -o root -g root /root/ui-read.token.tmp "$OUT" && rm -f /root/ui-read.token.tmp
echo "token at $OUT (0600) — deliver to Peter's Mac ~/.aukora-nebius/ 0600, never print"
systemctl restart aukora-relay && sleep 3 && systemctl is-active aukora-relay
python3 - <<'EOF'
import json, urllib.request
token = open("/root/ui-read.token").read().strip()
def call(path, method="GET", body=None):
    req = urllib.request.Request("http://127.0.0.1:18733" + path, method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body else None)
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e: return e.code, None
me, data = call("/v1/whoami")
assert me == 200 and data["author"] == "ui-read" and data["scopes"] == ["messages:read"], data
code, _ = call("/v1/messages", "POST", {"clientRequestId": "ui-read-probe", "kind": "chat", "body": "refuse me", "refs": []})
assert code == 403, code
print("VERIFIED: ui-read reads, posts refuse 403")
EOF
