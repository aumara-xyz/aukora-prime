#!/bin/bash
# Non-live voice staging on pilot. User ubuntu, no root, no service, nothing touches /opt or live.
set -euo pipefail
ST=$HOME/aukora-voice-staging
SRC=$HOME/aukora-zip/r3-5fc1fea/plugins/aukora-face/apps/vendor/auma-live/source/voice
mkdir -p $ST && cd $ST
[ -d src ] || cp -r $SRC src
PIPVER=24.2
if [ ! -x .venv/bin/python ]; then
  /usr/bin/python3 -m venv --copies --without-pip .venv
fi
if [ ! -x .venv/bin/pip ]; then
  WH=pip-$PIPVER-py3-none-any.whl
  EXP=$(curl -fsS https://pypi.org/pypi/pip/$PIPVER/json | /usr/bin/python3 -c "import json,sys;d=json.load(sys.stdin);print([u for u in d['urls'] if u['filename']=='$WH'][0]['digests']['sha256'])")
  URL=$(curl -fsS https://pypi.org/pypi/pip/$PIPVER/json | /usr/bin/python3 -c "import json,sys;d=json.load(sys.stdin);print([u for u in d['urls'] if u['filename']=='$WH'][0]['url'])")
  curl -fsSL -o $WH "$URL"
  echo "$EXP  $WH" | sha256sum -c -
  .venv/bin/python $WH/pip install --no-index --no-cache-dir $WH
  echo "pip bootstrap $WH sha256 $EXP"
fi
.venv/bin/python -I -m pip install --only-binary=:all: --require-hashes --no-cache-dir -r src/requirements-linux.lock
.venv/bin/python -I -m pip check
.venv/bin/python - <<'PY'
import json,hashlib,urllib.request,shutil,pathlib
root=pathlib.Path('.')
for it in json.load(open('src/models.lock.json'))['files']:
  p=root/'models'/it['path']; p.parent.mkdir(parents=True,exist_ok=True)
  if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest()==it['sha256']: print('ok',it['path']); continue
  t=p.with_suffix(p.suffix+'.download')
  with urllib.request.urlopen(it['url'],timeout=300) as r, open(t,'wb') as o: shutil.copyfileobj(r,o,1<<20)
  h=hashlib.sha256(t.read_bytes()).hexdigest()
  assert t.stat().st_size==it['size'] and h==it['sha256'], ('MISMATCH',it['path'],h)
  t.rename(p); print('fetched+verified',it['path'],h[:12])
PY
echo STAGE-READY
