set -e
cd ~/aukora-zip
kill 189361 2>/dev/null || true
sleep 3
sudo -n cat /var/lib/aukora-prime-step1/home/.credentials.yaml | python3 -c "
import sys,os
src=sys.stdin.read().splitlines()
i=src.index(\"refs:\"); refs=[l for l in src[i:] if l.strip()]
p=os.path.expanduser(\"~/aukora-zip/state/home/.credentials.yaml\")
cur=open(p).read().rstrip(\"\n\").splitlines()
assert not any(l.startswith(\"refs:\") for l in cur)
fd=os.open(p+\".new\",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
os.write(fd,(\"\n\".join(cur+refs)+\"\n\").encode()); os.close(fd); os.replace(p+\".new\",p)
"
stat -c "%U %a %s" state/home/.credentials.yaml
sed -E "s/(:[[:space:]]*).+/\1<redacted>/" state/home/.credentials.yaml
nohup bash launch.sh > launch.log 2>&1 < /dev/null &
sleep 45
grep -o "Spawned Genesis PID [0-9]*" launch.log
ss -ltn | grep 18735
