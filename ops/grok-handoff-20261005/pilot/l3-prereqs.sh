set -eu
echo "== python3.11"
if ! command -v python3.11 >/dev/null; then
  sudo -n DEBIAN_FRONTEND=noninteractive add-apt-repository -y ppa:deadsnakes/ppa >/dev/null
  sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3.11 python3.11-venv >/dev/null
fi
python3.11 --version
echo "== llama-server b11381"
T=b11381; SHA=7e235592575e8df35f525195b6d7ac773c9d50a4ddb070ba4fb1ff3c073ef4da; D=/opt/llama.cpp/$T
if [ ! -x $D/llama-server ]; then
  tmp=$(mktemp -d); curl -fsSL -o $tmp/l.tgz https://github.com/ggml-org/llama.cpp/releases/download/$T/llama-$T-bin-ubuntu-x64.tar.gz
  echo "$SHA  $tmp/l.tgz" | sha256sum -c -
  sudo -n install -d -o root -g root -m 0755 $D; sudo -n tar -xzf $tmp/l.tgz -C $D --strip-components=1 --no-same-owner; rm -rf $tmp
  sudo -n chown -R root:root $D; sudo -n chmod -R go-w,a+rX $D
fi
ls $D | head -5; B=$(find $D -maxdepth 2 -name llama-server -type f | head -1); echo "bin=$B"
sudo -n ln -sfn "$B" /usr/local/bin/llama-server
/usr/local/bin/llama-server --version 2>&1 | head -2
sha256sum "$B"
echo "== openviking home + credentials (aukora-host, 0700/0600, never printed)"
H=/home/aukora-host/genesis/state/home/openviking
sudo -n install -d -o aukora-host -g aukora-host -m 0700 $H
sudo -n -u aukora-host python3 - <<'PY'
import os,secrets
for name in ("root.key","viking-door.key"):
    p="/home/aukora-host/genesis/state/home/openviking/"+name
    if os.path.exists(p): print(name,"exists"); continue
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,secrets.token_hex(32).encode()); os.close(fd); print(name,"created")
PY
sudo -n stat -c "%A %U:%G %s %n" $H $H/root.key $H/viking-door.key
echo PREREQS-DONE
