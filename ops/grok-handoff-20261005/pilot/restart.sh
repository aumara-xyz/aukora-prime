set -u
sudo -n systemctl stop aukora-genesis
for i in $(seq 1 40); do n=$(sudo -n ss -tan | grep -c ":18735 "); [ "$n" = 0 ] && break; sleep 3; done; echo "tw=$n"
sudo -n systemctl reset-failed aukora-genesis; sudo -n systemctl start aukora-genesis; sleep 25
systemctl is-active aukora-genesis
sudo -n journalctl -u aukora-genesis -n 8 --no-pager | grep -E "Spawned|error|Started" | sed -E "s/token=[A-Za-z0-9_-]+/token=R/g" | cut -c1-200
sudo -n ls -l /home/aukora-host/genesis/state/launch-url.json
