# systemd units (as deployed on the Nebius pilot, 2026-10-04)

Replaces the lab's pm2 supervision (L4). Install as root into `/etc/systemd/system/`, then
`systemctl daemon-reload && systemctl enable --now aukora-auma-podman aukora-openshell-gateway aukora-auma-sandbox aukora-boundary-gate`.

`aukora-genesis.service` runs the Genesis runtime (`scripts/launch-dsh.py`) as `aukora-host` on loopback port 18735,
after the gate and sandbox. Its state root (`/home/aukora-host/genesis/state`, 0700) holds the provider credential;
the owner reaches it only through an SSH tunnel. The unit file is release-agnostic and byte-identical to the pilot's; the
only per-release file is the root-owned `/etc/aukora-genesis/release.env` (`aukora-genesis.release.env.example`).

## Release switch (signed enforcement, no waiver)

1. Materialize the release under `/opt/aukora-genesis/release-<7>`.
2. `plugin-set-approval.mjs raise --release-dir <dir>` puts a plugin-set card in front of the owner (one click; the card
   states as gate facts whether the plugin set is unchanged since the previous approval, and ROLLBACK when the release is
   below the floor). Root never imports anything from the candidate release: `src/plugin-set-canon.mjs` reads it as data.
3. After the owner approves: `plugin-set-approval.mjs install --release-dir <dir> --out /etc/aukora-approvals/<sha>/state/gate-state`
   writes the approval + pin and moves the monotonic release floor (`/etc/aukora-approvals/release-floor.json`) forward.
4. Write `release.env`, `systemctl restart aukora-genesis`. `ExecStartPre` runs the self-check, then
   `release-floor.mjs check`, which refuses an approval older than the floor (an old release with its own old approval).
   Rolling back means raising the old release again for a fresh owner approval.

Assumed layout (see `../SETUP.md`): host scripts in `/usr/local/lib/aukora-boundary/` (root 0755), OpenShell 0.1.2
`openshell`/`openshell-gateway` in `/usr/bin`, Node 24.11.1 in `/opt/aukora-node`, this package (root-owned) in
`/opt/aukora-boundary-gate`, gate targets in `/var/lib/aukora-boundary/targets`, linger enabled for `auma`.
Differences from SETUP.md observed on Ubuntu 24.04: Podman is 4.9.3 (distribution package), not 5.4.2.

## Boundary self-check (fail closed)

`aukora-genesis.service` runs `bin/selfcheck.mjs` as `ExecStartPre` (as aukora-host): every forbidden action must be
refused and the in-sandbox egress probe must pass, and the result must be recorded as a signed `selfcheck` ledger entry,
or the runtime does not start (three tries in five minutes, then it stays down). `aukora-selfcheck.timer` re-runs the
same check every 15 minutes; a failure starts `aukora-genesis-failclosed.service`, which stops the runtime.
Install `bin/selfcheck.mjs` with the gate runtime (`/opt/aukora-boundary-gate/bin/`), then
`systemctl enable --now aukora-selfcheck.timer`.
