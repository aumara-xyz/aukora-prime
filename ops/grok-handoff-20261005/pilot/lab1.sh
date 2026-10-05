set -eu
export DEBIAN_FRONTEND=noninteractive
sudo -n apt-get update -qq
sudo -n apt-get install -y -qq --no-install-recommends podman uidmap slirp4netns passt fuse-overlayfs crun catatonit >/tmp/lab-apt.log 2>&1 || { tail -20 /tmp/lab-apt.log; exit 1; }
sudo -n apt-get clean
podman --version
id auma >/dev/null 2>&1 || sudo -n useradd -m -s /bin/bash auma
id aukora-host >/dev/null 2>&1 || sudo -n useradd -m -s /bin/bash aukora-host
id aukora-gate >/dev/null 2>&1 || sudo -n useradd -r -m -s /usr/sbin/nologin aukora-gate
getent group skgate >/dev/null || sudo -n groupadd skgate
sudo -n usermod -aG skgate aukora-host; sudo -n usermod -aG skgate aukora-gate
grep -q "^auma:" /etc/subuid || sudo -n usermod --add-subuids 200000-265535 --add-subgids 200000-265535 auma
grep -E "^auma:" /etc/subuid /etc/subgid
sudo -n chmod 0750 /home/auma /home/aukora-host; sudo -n chmod 0700 /home/aukora-gate
sudo -n loginctl enable-linger auma
for u in auma aukora-host aukora-gate; do id $u; done
df -h / | tail -1
