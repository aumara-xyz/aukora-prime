# Host setup: UID separation and the OpenShell sandbox

This is the operator recipe for the boundary's foundation, distilled from the Genesis SKUNKWORKS
boundary lab (`aumara-xyz/aukora-genesis`, `labs/deepseek-harness-boundary`, lab tip `6fa70cd`).
Nothing in Prime runs it automatically. It creates no users, keys, tunnels or services by itself.

**Status.** Source in this directory: SOURCE-ONLY, with the checks in `../checks/` (see the package
README for what they exercise). The lab reports it ran this layout on its own Debian 13 box with
NVIDIA OpenShell 0.1.2 on rootless Podman 5.4.2; for Prime that is a CLAIMED lab observation, not a
Prime runtime qualification. It does not qualify Prime's separate Docker-driver execution lane in
`packages/execution` (G3 remains UNPERFORMED there).

## Principals

| Linux principal | Owns | May do |
| --- | --- | --- |
| `aukora-host` | the harness process, its state and the model credential | run `sbx-exec` as `auma` (one sudo rule); connect the gate's PROPOSE socket (group `skgate`) |
| `auma` | rootless Podman, the OpenShell gateway (podman driver, loopback port 17690, mTLS), sandbox `auma-ws` | nothing on the host beyond its own home |
| `aukora-gate` | proposals, the signed ledger, the receipt key, the owner secret, the allowlisted target files | serve the PROPOSE socket (0660, group `skgate`) and the OWNER socket (0600, gate only) |
| group `skgate` | — | members `aukora-host` and `aukora-gate` |

The only bridge from the harness to the agent's hands is `sudoers.template`:

```
aukora-host ALL=(auma) NOPASSWD: /usr/local/lib/aukora-boundary/sbx-exec
```

Install it as `/etc/sudoers.d/aukora-boundary` (0440 root) after `visudo -cf`. The harness user gets no
other sudo rule; the self-check (`src/selfcheck.mjs`) refuses every agent tool if `sudo -n` to root, to
`aukora-gate`, or to `auma` outside `sbx-exec` succeeds.

## Pinned components (as reported by the lab)

| component | version |
| --- | --- |
| NVIDIA OpenShell | `openshell` / `openshell-gateway` 0.1.2; images `ghcr.io/nvidia/openshell/{sandbox,supervisor}:0.1.2` |
| Podman | 5.4.2, rootless, user `auma` |
| Node.js | 24.11.1 or later (`node:sqlite` is needed by the gate) |
| OS | Debian 13; no systemd (the lab supervised processes with pm2) |

Version tags are not digests. Record the image digests you actually pull before any qualification claim.

## Steps (operator, as root; review each before running)

1. Users and group: `useradd -m -s /bin/bash auma`, `useradd -m -s /bin/bash aukora-host`,
   `useradd -r -m -s /usr/sbin/nologin aukora-gate`, `groupadd skgate`, `usermod -aG skgate aukora-host`,
   `usermod -aG skgate aukora-gate`. Give `auma` subordinate UID/GID ranges for rootless Podman.
2. Optional disk quota: put all of `auma`'s Podman storage on a size-limited loop image mounted
   `nodev,nosuid` before Podman starts (the lab used 2.5 GiB; a fill test hit ENOSPC inside the sandbox
   with the host disk unaffected).
3. Runtime dir: `install -d -o auma -g auma -m 0700 /run/user/$(id -u auma)`.
4. As `auma`: start `openshell/podman-service.sh`, then `openshell/gateway.sh` (generates mTLS material into
   `~auma/.local/state/openshell/tls` on first start; never publish it), then `openshell/ensure-sandbox.sh`.
   `ensure-sandbox.sh` creates `auma-ws` with `--no-auto-providers`, keeps a host copy of `/sandbox`, and
   **refuses (exit 3) unless the container network mode is `none`**.
5. Install `sbx-exec` as `/usr/local/lib/aukora-boundary/sbx-exec`, `root:root 0755`, and the sudo rule.
6. Gate (as `aukora-gate`, umask 027): `install -d -o aukora-gate -g skgate -m 0750` the run directory and the
   target root (`targets/plugins/auma-theme/`, theme file 0640 group `skgate`), keep the gate home 0700, then
   `node bin/gate.mjs serve --home <gate home> --run <run dir> --target-root <target root> --gid <skgate gid>`.
   The PROPOSE socket comes up 0660 group `skgate`, the OWNER socket 0600. Publish the loopback owner page
   only on a channel the harness cannot reach. Owner decisions: `bin/owner-cli.mjs --socket <run>/owner.sock`.
7. Run the self-check as `aukora-host` (forbidden probes plus `gateProbes` as `extraProbes`) before enabling
   any agent tool, and keep it running periodically.

`openshell/gateway-metadata.json` is the client-side gateway registration (mTLS, loopback). Certificates
and keys are not included and must stay in `auma`'s private state.

## What `sbx-exec` enforces

- timeout is digits only, clamped to 1..300 s; no TTY, stdin closed, fixed environment;
- per call: kill leftovers from earlier calls, run with `ulimit -t 330` and a 20 MB file-size cap, kill
  everything left behind (setsid/nohup/double-fork included), sparing PID 1, OpenShell's login shell and
  processes of calls still running;
- stdout/stderr each capped at 1 MiB (the harness side caps again at 64 KiB).

Known limits carried from the lab: the cleanup heuristic trusts OpenShell 0.1.2's login-shell layout;
"network none" was verified by the container's network mode and the in-sandbox probe, not by an
independent packet-level audit.
