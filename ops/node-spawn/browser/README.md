# Fresh browser test node

SOURCE-ONLY installer for Ubuntu 24.04, separate `aukora-host` / `aukora-gate`,
root-held packages, fresh gate keys, no relay/Buzz/invites. The browser release
disables shell/file/network/delegation providers and refuses **every model tool**,
including newly registered tools. It is a screens-only profile, not the normal
OpenShell containment profile. No model credential or identity state is copied.

Initial approval is a **bearer link plus typed two-step confirmation, not a device
key**. It is available only before owner enrollment has ever required device
proof. Enrollment or the durable enforcement latch prevents bearer approval;
losing owner-state never reopens it. The page uses the exact resulting SHA-256
for a release card; theme cards retain their colour confirmation. Its signed
receipt does not install approval or advance the floor until `start.sh` verifies
and installs it. Gate restart rotates the private bearer (12-hour lifetime).

The runtime composition verifier accepts the same exact page label as the
protected verifier and no other page label. Do not relabel a page receipt as a
socket approval. Browser enrollment/session/ceremony/TLS work is separate.

Pre-stage four inputs in a private root-owned directory, with no symlink/hardlink
inputs. Use a **clean committed** checkout containing this change; preserve its
full 40-character revision and operator-reviewed bundle SHA-256. On a connected
Ubuntu 24.04 preparation machine of the same CPU architecture:

1. `git bundle create checkout.bundle HEAD` from the clean reviewed clone.
2. Copy `vendor/dsh-source.tar.gz`; installer checks `upstream-dsh.json`'s digest.
3. Copy the official `node-v24.11.1-linux-{x64,arm64}.tar.xz` as `node.tar.xz`,
   including headers; verify its official signed checksums before selecting the
   operator SHA-256. The container also checks the binary reports `v24.11.1`.
4. Create `dependencies.tar.gz` with `debs/`, `pnpm/`, `store/`. In a fresh stock
   Ubuntu 24.04 preparation container run `apt-get update`, then
   `apt-get --download-only install git build-essential ca-certificates python3 iproute2`;
   copy **all** downloaded `.deb` files to `debs/`. Keep all dependency packages
   needed by that stock image; offline install uses `dpkg --install`, never apt
   or an internet fetch. Python3, Bash, tar, dpkg and coreutils must already be
   present in the stock image. Unpack the verified `pnpm@11.7.0` distribution
   into `pnpm/` (entry `pnpm/dist/pnpm.cjs` with its support tree). With pinned
   Node and that pnpm, extract the pinned harness into a preparation directory
   and run `pnpm fetch --frozen-lockfile --store-dir /absolute/path/to/store`
   there. Archive these three directories with hardlinks expanded, e.g.
   GNU `tar --hard-dereference -czf dependencies.tar.gz debs pnpm store`.
   Include platform-specific optional/native dependencies for the target CPU.
   Choose and retain the dependencies archive SHA-256 after review. This is a
   dependency store, never an installed harness or another node's private state.

Record `sha256sum checkout.bundle node.tar.xz dependencies.tar.gz` privately in
the operator's change record. These supplied digests identify selected bytes;
they do not independently prove upstream publisher provenance. The installer
verifies each, the harness archive pin, lockfile, pnpm version, successful harness
build receipt, installed package manifest, final release record and approval.
Build logs stay root-private under `/var/lib/aukora-browser`; never publish them.

On the **local LXD host**, import/identify a trusted stock Ubuntu 24.04 container
image first; retain its full fingerprint. `create.sh` refuses remote aliases,
existing node/profile names and a non-Ubuntu image. It uses only local LXD,
isolated unprivileged IDs, no NIC, no nesting/devlxd, 2 CPUs, 4 GiB RAM,
512 processes and a 20 GiB root disk on the default profile's storage pool:

Before creation, verify `lxc --force-local cluster list` reports clustering is
disabled. This runbook requires a standalone daemon on the intended host;
`--force-local` selects the local socket and does not qualify cluster placement.

```bash
bash ops/node-spawn/browser/create.sh --name C1 --image "$IMAGE_FINGERPRINT" \
  --inputs "$INPUTS" --checkout-sha256 "$CHECKOUT_SHA256" --revision "$REVISION" \
  --node-sha256 "$NODE_SHA256" --dependencies-sha256 "$DEPENDENCIES_SHA256" \
  --app-port "$HOST_APP_PORT" --owner-port "$HOST_OWNER_PORT"
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase before
```

LXD's non-NAT proxy enters the container's network namespace and forwards to its
loopback; the two host listeners bind **only 127.0.0.1**. Verify this on the real
host (`ss -ltnp`, `lxc --force-local config show C1 --expanded`), including that
raw app/owner ports are unreachable externally. A separate reviewed host HTTPS
proxy must use operator-provided app/owner hostnames and certificates, preserve
Host/Origin/WS/SSE, overwrite spoofed forwarding headers and omit access/query
logs on the owner route. No hostname, DNS, TLS configuration, login broker or
public claim is supplied here. Do not expose either origin publicly until the
other browser-node parts and their negative ingress tests are qualified.

Deliver the current owner bearer to Peter through the host's existing private
operator route, directly from `/home/aukora-gate/owner-secret.json` inside C1.
These scripts never print it. Peter opens the separate HTTPS owner page with
that bearer at the owner origin's `/?k=<private bearer>` himself, reviews the
initial exact release card, types its digest,
and confirms. Do not click for him or export the raw owner Unix socket.

```bash
lxc --force-local exec C1 -- bash /opt/aukora-genesis/src/ops/node-spawn/browser/start.sh
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase after
lxc --force-local exec C1 -- bash /opt/aukora-genesis/src/ops/node-spawn/browser/status.sh
```

`after` checks installed users/modes/pins, loopback listeners, exact approved
floor, the existing signed-in UI probe and current service invocation's plugin
load errors. It uses the private launch descriptor inside C1; no launch token is
delivered to a browser. Then Peter must open the actual HTTPS app and perform his
binding ceremony through the separately implemented owner flow. No script here
enrolls him, installs a synthetic subject, proves a model reply, memory, browser
streaming, device custody, human uniqueness, consent or complete containment.

To deactivate, run `remove.sh` inside C1; it stops/disables only these units and
retains keys, release bytes, approvals and floor. To destroy this test node,
operator runs `lxc --force-local delete --force C1` and
`lxc --force-local profile delete browser-C1`, then removes its host HTTPS route.
Do not wipe a floor or reuse an interrupted installation; inspect its private
failure record or discard that fresh test container and create another from inputs.

UNVERIFIED host assumptions: stock image provenance and prerequisites; standalone LXD
local CLI/proxy options, isolated UID allocation and kernel namespace support;
storage pool/quota capacity; build resource limits and complete offline store;
unused loopback ports; proxy UID 65534 reaching container loopback; systemd,
journald, socket permissions and Ubuntu inherited umask; DNS/certificates/private
bearer delivery, HTTPS origin/session integration, real authenticator and Peter's
approval/binding. Repeat acceptance after reboot; no real host was inspected here.
