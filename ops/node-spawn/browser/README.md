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
socket approval. The installer supplies the HTTPS-origin and one-use app claim
plumbing; owner enrollment/binding and host DNS/certificates still require their
separate protected flow and operator actions.

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
   into `pnpm/` (entry `pnpm/bin/pnpm.cjs` with its support tree). With pinned
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
  --app-host "$APP_HOST" --owner-host "$OWNER_HOST" \
  --app-port "$HOST_APP_PORT" --owner-port "$HOST_OWNER_PORT" --claim-port "$HOST_CLAIM_PORT"
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase before
```

LXD's non-NAT proxy enters the container's network namespace and forwards to its
loopback; the three distinct host listeners bind **only 127.0.0.1**. Hostnames
must be distinct lowercase DNS names without a scheme, wildcard, port or path;
numeric final labels are refused. The installer writes root-owned, readable
`/etc/aukora/public-origin` and `/etc/aukora/owner-public-origin`, pins both names
in its installation record, and refuses a rerun with different names. Verify this on the real
host (`ss -ltnp`, `lxc --force-local config show C1 --expanded`), including that
raw app/owner/claim ports are unreachable externally. The app proxy targets
the harness on container port 18735; the owner proxy targets the gate on 17792;
the claim proxy targets `aukora-browser-claim.service` on 18736. The broker is
root-owned and runs as root on container loopback to read the private launch
descriptor. It serves exact claim/sign-in/sign-out endpoints and does not
forward app WebSocket or SSE traffic. A separate reviewed host HTTPS
proxy must use operator-provided app/owner hostnames and certificates, preserve
Host/Origin/WS/SSE, overwrite spoofed forwarding headers and omit access/query
logs on the owner route. Render its exact three upstreams on the LXD host:

```bash
python3 ops/node-spawn/ingress/render.py \
  --app-host "$APP_HOST" --owner-host "$OWNER_HOST" \
  --harness-port "$HOST_APP_PORT" --owner-port "$HOST_OWNER_PORT" --claim-port "$HOST_CLAIM_PORT" \
  --output "$CADDY_CANDIDATE"
sudo caddy validate --config "$CADDY_CANDIDATE" --adapter caddyfile
sudo install -o root -g root -m 0644 "$CADDY_CANDIDATE" /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

`CADDY_CANDIDATE` is an operator-selected file; preserve any other existing host
routes before installing it. Caddy sends only the exact broker endpoints to
the claim port; app HTTP, WebSocket and SSE go directly to the harness. No DNS,
certificate or public-browser observation is supplied by these scripts. See
the [ingress runbook](../ingress/README.md) for the public negative checks.

Deliver the current owner bearer to Peter through the host's existing private
operator route, directly from `/home/aukora-gate/owner-secret.json` inside C1.
These scripts never print it. Peter opens the separate HTTPS owner page with
that bearer at the owner origin's `/?k=<private bearer>` himself, reviews the
initial exact release card, types its digest,
and confirms. Do not click for him or export the raw owner Unix socket.
To invalidate the current owner bearer, run inside C1 as root:

```bash
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py rotate-owner-link
```

This requests a gate restart, waits for its sockets, and prints no bearer. Deliver
the replacement through the same private operator route.
The harness requires the gate; systemd's restart propagation is unverified here.
After a rotation or passkey activation, inspect `status.sh`; if the approved
harness is inactive, run `start.sh`, then repeat after-approval acceptance.

```bash
lxc --force-local exec C1 -- bash /opt/aukora-genesis/src/ops/node-spawn/browser/start.sh
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase after
lxc --force-local exec C1 -- bash /opt/aukora-genesis/src/ops/node-spawn/browser/status.sh
```

`after` checks installed users/modes/pins, all three loopback proxies, exact approved
floor, the existing signed-in UI probe and current service invocation's plugin
load errors. It also requires the claim service, protected public origin files,
401 without a cookie at the public app authority, and a fresh claim that exchanges
once for an authority-bound cookie: the authenticated request succeeds and reuse
is refused. These requests stay inside C1 with a public Host header; they do not
test TLS, Caddy, a real browser or WebSocket/SSE streaming. The probe spends its
own claim and prints no link or cookie. Mint a separate five-minute link for Peter:

```bash
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py claim
```

This root command prints only the link. Give it directly through the private
operator route; do not log it. It carries a one-use fragment, never the harness
launch token. Then Peter must open the actual HTTPS app and perform his
binding ceremony through the separately implemented owner flow. Returning
sign-in at `https://APP_HOST/__aukora/signin` goes through the broker to the
owner origin's `/owner/signin`; it requires protected passkey gate configuration
and enrollment. The installer pins complete authority/contracts/Aumlok packages
in the gate manifest, initially selects the bearer owner page, and creates no
enrollment or synthetic identity. After the initial release approval, prepare
the actual protected passkey setup and browser binding configuration following
the [gate procedure](../../../packages/boundary-gate/README.md#returning-browser-sign-in-and-final-subject-binding).
Use the actual app's configured `local-control.json` path, never a copied
projection; arrange gate read/traverse access only to that public record without
exposing the machine seed. For this install the gate's primary group is `skgate`:

```bash
# Inside C1 as root, after mint-passkey-claim wrote the exclusive setup file:
chown root:skgate /etc/aukora-boundary-gate/passkey-setup.json
chmod 0640 /etc/aukora-boundary-gate/passkey-setup.json
# Root writes browser-join.json with the actual app origin and binding_record,
# root:skgate 0640, under the protected /etc/aukora-boundary-gate directory.
/usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py enable-owner-signin
```

`enable-owner-signin` verifies the installed package, checks both configurations
with the existing gate readers as the gate user, matches their app/owner origins
and gate signer, and writes a fixed root-owned service drop-in selecting both
passkey and browser-join modes. A conflicting drop-in is refused. It reloads
systemd, restarts the gate and waits for its sockets; it neither enrolls nor
approves. Peter opens `https://OWNER_HOST/owner/enroll`, enters the private
passkey enrollment claim and uses his authenticator. After the phrase ceremony
he signs the gate's exact final subject/node binding. Returning sign-in is
available after enrollment at `https://APP_HOST/__aukora/signin`; a retained
binding must remain valid. Missing setup, configuration, read permission or
enrollment refuses sign-in. Missing final binding refuses approvals/effects;
it cannot reopen bearer approval for an enrolled owner. No script here
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
three unused loopback ports; proxy UID 65534 reaching container loopback; systemd,
journald, socket permissions and Ubuntu inherited umask; DNS/certificates/private
bearer delivery, installed HTTPS origin/session integration, real authenticator and Peter's
approval/binding. Repeat acceptance after reboot; no real host was inspected here.
