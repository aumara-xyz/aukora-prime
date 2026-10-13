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

When this host carries siblings, create each with its own `--name`, app and owner
hostnames, and three loopback ports. Put all nodes in the ingress runbook's
root-owned JSON inventory, render it with `render.py --nodes`, validate the exact
candidate with `render.py --check` and Caddy, install, reload, then check the
installed Caddyfile. To add C2, run the `create.sh` and `acceptance.sh --phase
before` sequence above with C2's distinct values before adding its JSON row. To
remove C2, remove its JSON row, render, validate, install, reload and check first;
then deactivate or delete only C2 and remove its DNS. Do not reuse its ports until
the installed-file check passes and its hostnames no longer answer. See the
[ingress add/remove procedure](../ingress/README.md#add-a-second-node) for exact
commands. Each hostname can reach only its node's ports. The app's `__Host-`
cookie is host-only, so sibling hostnames cannot share it.

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
After a rotation or passkey activation, inspect the service directly with
`systemctl is-active aukora-browser.service`; if the approved harness is
inactive, run `start.sh`, then repeat after-approval acceptance.

```bash
lxc --force-local exec C1 -- bash /opt/aukora-genesis/src/ops/node-spawn/browser/start.sh
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase after
lxc --force-local exec C1 -- systemctl is-active aukora-browser.service
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
binding ceremony through the separately implemented owner flow.

To enable a model reply, set the one permitted DeepSeek credential inside C1
as root. The safest interactive route prompts on the container terminal with
echo disabled; without `--prompt`, the command accepts one credential only from
non-terminal standard input and refuses a terminal. Never put the key in an
argument, environment variable or shell assignment:

```bash
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py model-key --prompt
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py status
```

Success prints only `MODEL_KEY_SET provider=deepseek sha256=XXXXXXXXXXXX`;
compare that 12-hex SHA-256 prefix with a digest computed in the private source
of the credential. `status` prints only `MODEL_KEY provider=deepseek
present=yes|no`, never a digest or value. Remove the store with `node.py
model-key --remove`; removal prints only `MODEL_KEY_REMOVED provider=deepseek`.

The file is `/home/aukora-host/genesis/state/home/.credentials.yaml`, the
runtime's `$DSH_HOME/.credentials.yaml`. The pinned harness names that location
and layout at
`vendor/dsh/packages/credentials/credentials-local/src/index.ts:60-68,166-226`,
rejects group/other-readable stores at `:96-143`, and atomically writes mode
`0600` at `:753-785`. DeepSeek's default reference is
`DEEPSEEK_API_KEY` (`vendor/dsh/packages/llm/llm-deepseek/src/config.ts:28,80-86`)
and it resolves the reference for each request
(`vendor/dsh/packages/llm/llm-deepseek/src/index.ts:84-103`). This command writes
that exact version-1 `refs` document, owned by `aukora-host`, through a private
same-directory atomic replacement; it refuses symlinks, hard links, foreign
ownership, non-private ancestry, malformed existing content and non-printable,
empty, multiline or over-4096-byte input.

The pinned DeepSeek provider has a per-request output-token setting, not a
per-node spend or request-count ceiling. It is not wired as a cost cap. Set a
conservative account/project budget and request limit at the provider before
supplying C1's key. The browser composition leaves `llm-deepseek` and the plain
chat/session path mounted. None of `BROWSER_DISABLED_ROWS` is needed for a
plain text reply: those rows are shell, file, network-tool, workflow and
delegation effects (plus their UI/providers). `file-upload` intentionally stays
mounted for session startup. The pinned base composition mounts the LLM,
session, credentials, agent loop and DeepSeek rows at
`vendor/dsh/packages/bundle/base/cordis.patch.yml:27-34,87-98,488-505`; the web
composition mounts file upload, conversation and chat at
`vendor/dsh/packages/bundle/web-app/cordis.patch.yml:190-193,254-261`. None of
those IDs is disabled by the browser profile. Any model tool call is separately refused by
`aukora-browser-refusal`; this does not prove a provider reply works.

For an installed, release-approved node whose binding ceremony is already
finished, switch approvals with this exact sequence. Use a reviewed installation
containing these files and complete pinned passkey packages; this command does
not upgrade an older installation or reapprove its release.

```bash
# Local host: mint immediately before the owner is ready (five-minute expiry).
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py passkey-claim
# Give the one printed owner-hostname link through the private operator route.
# Owner: open it, touch to create the credential, touch again to prove possession.
# Wait for "Owner passkey enrolled. Enrollment is closed."
lxc --force-local exec C1 -- systemctl is-active aukora-browser.service
# If the approved harness is inactive after the gate restart:
lxc --force-local exec C1 -- bash /opt/aukora-genesis/src/ops/node-spawn/browser/start.sh
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase passkey
```

`passkey-claim` requires root, verifies package pins and the existing approved
release floor, and reads only the app's actual public binding record at
`/home/aukora-host/genesis/state/aumlok-binding/local-control.json`. It verifies
that the approved composition configures that path and the pinned app origin,
and selects the record's sole unrevoked machine approval key; unbound or
ambiguous records refuse. It derives a stable node ID from this node's fresh gate
public signer. No phrase, seed, private owner key or synthetic identity is read
or enrolled. The RP ID is **exactly `OWNER_HOST`**, never the app hostname or its
parent domain. The setup pins the existing subject, control digest and record
hash; it is a root-selected snapshot, not proof of the phrase ceremony's consent.

The command creates the setup and private saved claim exclusively, sets gate
read access to setup, verifies it as the gate user, and installs a protected
passkey-only service drop-in. It restarts the gate, waits for both sockets and
checks the service is active before printing **only**
`https://OWNER_HOST/owner/enroll#claim=…`. Keep that link
private; do not log it. The page removes the fragment before requests, retains
it in that origin's tab session storage until success, and automatically requests
creation followed by possession. It does not require pasting a claim or a third
subject-binding touch. Bearer approvals are disabled as soon as this mode starts,
including before enrollment completes; the retained gate latch prevents downgrade.

To recover an interrupted ceremony **before its original five-minute expiry**,
run the same `node.py passkey-claim` command above as root. It redelivers the
saved claim after restarting the gate; then reopen that link or reload the same
tab. A tab reload while the original gate process is still running does not
resume the reserved ceremony. The secret claim resumes
the same enrollment ID and registration/possession stage. Once registration is
retained, only possession resumes; another credential cannot replace it. The
root command can redeliver the same unexpired claim if activation was interrupted;
it never mints a replacement setup. Completed or cryptographically failed
ceremonies remain closed, including across restart. An expired unfinished claim
requires an explicit recovery policy; do not delete protected state, reset the
floor or downgrade to the bearer page.

`passkey` repeats `after` acceptance, then checks the installed gate's retained
setup/enrollment matches the actual current public app binding, enrollment is
closed over HTTP, and the old bearer page and a bearer-only approval both refuse.
It also runs a valid software-signed control and wrong RP/origin/node proofs
through the **installed verifier with ephemeral software state**. It cannot sign
as the real enrolled owner and does not count those fixture checks as live owner
approval. No software credential is installed, no card is approved, and no effect
is authorized by acceptance.

To review future cards, retrieve the rotated bearer through the existing private
operator route and open `https://OWNER_HOST/owner/cards?bearer=…`. The bearer opens
cards; only the enrolled passkey signs approvals. This already-bound activation
pins the existing subject at enrollment and does not enable the separate browser
join or returning sign-in. A pre-existing browser-join selection is refused; it
cannot be removed to avoid its final-binding requirement. The provisional join's
separate procedure remains in the
[gate runbook](../../../packages/boundary-gate/README.md#returning-browser-sign-in-and-final-subject-binding).

A real qualification must show the owner hostname and two real authenticator
prompts in an actual HTTPS browser; successful enrollment of this bound subject
and node; one harmless exact-card passkey approval and cold receipt verification;
bearer/proofless/second-enrollment refusal after restart; actual loopback/TLS
routing, installed package pins and service state. None ran here. Software
fixtures do not prove device custody, human uniqueness, informed consent,
public-browser behavior, model replies, memory, streaming or complete containment.
Synced versus device-only credentials and expired-claim/device-loss recovery
remain owner policy choices; none attestation permits backup-eligible passkeys.

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
