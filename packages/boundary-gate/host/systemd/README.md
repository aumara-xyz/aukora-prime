# systemd units (as deployed on the Nebius pilot, 2026-10-04)

Replaces the lab's pm2 supervision (L4). Install as root into `/etc/systemd/system/`, then
`systemctl daemon-reload && systemctl enable --now aukora-auma-podman aukora-openshell-gateway aukora-auma-sandbox aukora-boundary-gate`.

`aukora-genesis.service` runs the Genesis runtime (`scripts/launch-dsh.py`) as `aukora-host` on loopback port 18735,
after the gate and sandbox. Its state root (`/home/aukora-host/genesis/state`, 0700) holds the provider credential;
the owner reaches it only through an SSH tunnel. Change the release path when a new release is materialized.

Assumed layout (see `../SETUP.md`): host scripts in `/usr/local/lib/aukora-boundary/` (root 0755), OpenShell 0.1.2
`openshell`/`openshell-gateway` in `/usr/bin`, Node 24.11.1 in `/opt/aukora-node`, this package (root-owned) in
`/opt/aukora-boundary-gate`, gate targets in `/var/lib/aukora-boundary/targets`, linger enabled for `auma`.
Differences from SETUP.md observed on Ubuntu 24.04: Podman is 4.9.3 (distribution package), not 5.4.2.
