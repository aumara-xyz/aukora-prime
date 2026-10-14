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

Optional offline meaning-based recall (SOURCE-ONLY, no node qualified here):
on a connected **Linux x86_64** preparation machine with Python 3.11 and pip,
supply an existing complete llama.cpp **b11381** CPU release tree. The repository's
`host/pins/llama-server-b11381.json` pins every file and symlink; it does not
provide an archive URL, compiler recipe or interpreter pin. Recompiling a different
tree does not satisfy it. Build into a new file in the private input directory:

```bash
bash ops/node-spawn/browser/openviking-bundle.sh \
  --llama-tree "$PINNED_LLAMA_TREE" --output "$INPUTS/openviking.tar.gz"
# Add to the create.sh command above, using the printed BUNDLE sha256:
# --openviking-bundle "$INPUTS/openviking.tar.gz" --openviking-sha256 "$OPENVIKING_SHA256"
```

The builder downloads binary Linux Python 3.11 wheels for all 163 exact locked
distributions, verifies their hashes and metadata against the existing hash-locked
closure, checks the pinned Linux OpenViking wheel named by `openviking-setup.sh`,
the 639,150,592-byte Qwen embedding model and the complete llama tree. It prints
every artifact's byte count and SHA-256, then the archive's count and digest.
Wheel selection fixes the Ubuntu 24.04 glibc 2.39, x86_64 and CPython 3.11 tags.
Tar entry order, ownership, modes and timestamps and gzip timestamps are fixed;
identical pinned artifacts produce identical bundle bytes. The wheel selection
must succeed without source builds; absent Linux wheels or incompatible metadata
refuse. No version or hash is relaxed. Use the same Ubuntu 24.04/glibc target
environment for preparation. Python 3.11 **with venv/ensurepip** and the pinned
llama build's system libraries must already exist in the image or the reviewed
offline `.deb` inputs. These system bytes are operator-selected, not covered by
the OpenViking artifact pins; the optional installer refuses missing Python.

Creation snapshots the optional file before LXD actions and checks its supplied
digest; missing pairs, malformed digests, unsafe files and changed bytes refuse.
Installation rechecks it, bounds extraction to 6 GiB/512 entries, and checks the
internal pins rather than trusting the archive manifest. It installs from local
wheels with `--no-index --no-deps --require-hashes`, then runs `pip check`.
The venv/model live under root-owned read-only `/opt/aukora-openviking`; the exact
llama tree lives at `/opt/llama.cpp/b11381`. The harness-owned private store is
`/home/aukora-host/genesis/state/home/openviking`; its fresh `root.key` is 0600
and never printed. Only that store is writable in the OpenViking unit.
The release receives `--kira-openviking-home`; its deployment overlay is seeded
before binding and retains `openVikingHome` when the binding writes its subject.
Kira uses this home to opt into semantic recall while retaining its lexical fallback.
Without the optional input, there is no runtime, store or service added; installation
and after-acceptance say `KIRA_RECALL lexical; no OpenViking bundle`.

Memory uses the supervisor's existing knobs: two CPU threads, a 2,048-token
context, one slot, mmap, no 8 GiB prompt cache and a 1,536 MiB sampled embedder
RSS+swap limit. The pair's unit has `MemoryHigh=2048M`, `MemoryMax=2304M`,
`MemorySwapMax=0`, `TasksMax=64`, `CPUQuota=200%`. Its hard cap leaves 1,792 MiB
of the 4 GiB node for the harness, gate and OS; both services can contend for
the two CPUs. Suitability and latency are unmeasured. Every two seconds the
supervisor samples its owned embedder group; exceeding 1,536 MiB kills/restarts
that embedder, interrupts requests, and retains OpenViking through ordinary
recycling. Retries back off 2/4/8/16/30 seconds; a sixth failure stops the pair.
Systemd retries after 10 seconds, at most three starts in 300 seconds. The hard
cgroup cap can kill either server before a sample and restart the pair.

Disk includes the 609.5 MiB model, the full llama tree, an expanded Python venv
and growing store. Exact Linux cost is unmeasured: the builder reports artifact
totals and installation prints `OPENVIKING_RUNTIME_BYTES` for the installed
runtime/model/llama, excluding store, input archive and base OS. Installation
requires 8 GiB free before extraction (6 GiB payload ceiling plus 2 GiB runtime
headroom); runtime expansion, harness build and retained input/store bytes still
share the node's 20 GiB quota. The extracted wheel payload is removed after install.
Observe actual `du` and quota headroom before using a node for retained memories.

After the owner's existing release approval and start, run `acceptance.sh --phase
after`; after real browser binding, run `acceptance.sh --phase bound`. Both repeat
the normal browser checks and require the OpenViking unit active, both HTTP
`/health` endpoints on container `127.0.0.1:1933/1934`, no non-loopback TCP/UDP
listeners, a private single-link harness-owned key, read-only runtime custody,
the pinned llama tree and the retained overlay home. `bound` additionally requires
the public binding record. These checks share the existing loopback checkpoint
in the public evidence schema; that exporter does not record the optional bundle
digest or prove the probes occurred. OpenViking has no host proxy or public port.

An operator must observe on a real offline node: successful wheel installation
and `pip check`; loaded release and overlay home before/after binding; both health
responses and loopback-only TCP/UDP listeners; actual service cgroup limits and
private key ownership/mode; measured peak RAM, disk and latency under two-CPU load;
embedder over-limit restart and retained store; restart/reboot health; a saved
synthetic note found through a differently worded query and again after restart;
and a separate no-bundle node staying lexical. Retain a miss/failure as such.
Fixtures and health checks do not prove semantic relevance, real indexing, durable
recall, owner approval, whole-node containment, or acceptable resource use.

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

To retain public evidence from an installation containing this exporter, choose
a new local file and run:

```bash
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase after --evidence "$PUBLIC_EVIDENCE"
node scripts/audit/browser-node-evidence.mjs "$PUBLIC_EVIDENCE"
```

The export contains only release/input digests, the public signer, the original
approval receipt and signed apply entry, the floor, UTC observation time and
named PASS/FAIL check groups. It excludes names, addresses, origins, command
output, journals, links, cookies and private keys. The host adds its transport
PASS after real expanded LXD readback; the other groups run inside the container.
The file is created exclusively with mode 0600. A failed check leaves a prefix
ending in FAIL and a failing command status; subsequent groups did not run.
Unsafe or unavailable proof metadata refuses export altogether.

The gate has no operation for signing this caller record, so `record_signature`
is null. Its receipt and ledger entry retain their existing signatures. The v2
floor has **no standalone signature**: the verifier binds its release, record,
signer, sequence and hash to the signed apply entry. Floor history/epoch and
protected custody are not authenticated offline. Checks, time and installer
input declarations remain unsigned. The verifier does not establish a real
node's key ownership, actual execution, installed file bytes, latestness, full
ledger history, human presence, identity or device custody. Review before
committing an operator export under [browser-node evidence](../../../evidence/browser-node/README.md).

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

The browser Kira row waits quietly as `kira.memory:aumlok-not-linked`
before binding. Its ordinary configuration reads the deployment overlay only
when mounting, so rewriting that file alone cannot start an already-failed row.
The browser wrapper now checks the verified public binding and overlay every
250 ms, requires their subject and state directory to agree, and mounts one
owned Kira child in the same harness process. No manual restart is required.
The supported child API is in the pinned `vendor/dsh-source.tar.gz`,
`vendor/cordis/src/registry.ts:310-337`; child disposal belongs to the parent at
`vendor/cordis/src/fiber.ts:265-297`. `upstream-dsh.json` pins the archive digest.
These source changes and local fixtures do not verify an installed node.

For a **throwaway rehearsal node only**, after initial release approval and
start, mark it and drive the ceremony through its own routes:

```bash
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py mark-rehearsal
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/rehearse-bind.py
```

**Never mark or run this driver on a node an owner will bind.** It creates a
throwaway `rehearsal-only` identity and permanently spends the first-binding
ceremony. `mark-rehearsal` requires an installed node with no binding record and
creates `/var/lib/aukora-browser/rehearsal-only` exclusively, owned by root with
mode `0600`. The driver requires root and that exact protected marker before
minting a claim. It exchanges the claim on container loopback with the node's
public Host and Origin, checks unbound status, prepares seven words, verifies a
wrong phrase is refused, prepares a fresh draw because the wrong attempt spent
the first, binds the correct phrase, and checks another prepare is refused.
It prints one PASS/FAIL line per step and never prints words, claim code,
ceremony ID or cookie. It does not approve a release, prove owner consent,
qualify custody on a real node, or test public TLS or a browser.

After binding, require the separate bound acceptance phase and retain its public
evidence in a new local file:

```bash
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase bound --evidence "$PUBLIC_EVIDENCE"
node scripts/audit/browser-node-evidence.mjs "$PUBLIC_EVIDENCE"
```

`bound` requires the `0600` harness-owned binding record, machine seed, attempts
database and lock, the same subject in the Kira overlay, active memory in the
current service invocation, served apps and admitted session RPC, refusal of
another prepare, and zero `did not activate` log entries since that start. It
creates or adopts the fixed `browser-node-bound-acceptance` Session without a
prompt or turn. It
checks Aura's gate/code heads, writes one harmless note through Kira's own
`remember` method, then requires the Kira head. The note command runs as
`runuser -u aukora-host -- /opt/aukora-node/bin/node --input-type=module -e` with
the exact `bound_remember` script in `node.py`, the approved release, verified
public subject and `/home/aukora-host/genesis/state/home/kira-memory`. That script
calls `createTrackedMemory({stateDir,subject}).remember({text:'Browser node
acceptance memory probe.',from:'browser-node-acceptance'})`. The note is fixed
and contains no owner data. This does not exercise a native model tool, prove
owner approval or qualify containment.

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
# Stdout is the secret enrollment link: do not capture it in logs or transcripts.
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

The command creates the digest-only setup exclusively, sets gate
read access to setup, verifies it as the gate user, and installs a protected
passkey-only service drop-in. It restarts the gate, waits for both sockets and
checks the service is active before printing **only**
`https://OWNER_HOST/owner/enroll#claim=…`. Keep that link
private; do not log it. The raw code is returned only by this first mint and is
never written to disk by the command. The lower-level gate `mint-passkey-claim`
command also returns its code on stdout; that stdout is a secret. Both newly
generated browser-node passkey drop-ins run a root startup step that removes any
legacy `passkey-claim.txt` before enrollment is exposed, including after a crash;
it removes the file regardless of whether the old claim is used or expired.
Existing installed drop-ins require the owner's upgrade route to acquire this
step; direct generic gate starts do not install it.
The page removes the fragment before requests, retains
it in that origin's tab session storage until success, and automatically requests
creation followed by possession. It does not require pasting a claim or a third
subject-binding touch. Bearer approvals are disabled as soon as this mode starts,
including before enrollment completes; the retained gate latch prevents downgrade.

To recover an interrupted ceremony **before its original five-minute expiry**,
use the originally printed link or the same browser tab, after restarting the
gate through the private operator route. The mint command refuses to reprint
an existing claim; only its digest remains on the node. A tab reload while the
original gate process is still running does not resume the reserved ceremony.
The secret claim resumes
the same enrollment ID and registration/possession stage. Once registration is
retained, only possession resumes; another credential cannot replace it. The
command never mints a replacement setup. Losing the original link and tab,
including an interrupted activation before the first print, requires an explicit
recovery policy. Completed or cryptographically failed
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

### Software passkey rehearsal

Use a disposable, already release-approved and app-bound rehearsal node built
with these changes. Never use an owner's node, identity or credentials. Mark it
before minting its first passkey claim; this root-only command writes the
protected `/etc/aukora-boundary-gate/rehearsal.json` marker. The gate exposes
`<meta name="aukora-node-mode" content="rehearsal">` on enrollment only when that
marker is valid. The driver refuses before enrollment if the marker is absent.
Marking is a permanent operator designation: destroy this node afterwards;
never hand it to an owner or remove the marker to repurpose it.

```bash
lxc --force-local exec "$REHEARSAL_NODE" -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py mark-rehearsal
export PATH=$HOME/.local/node-v24.11.1/bin:$PATH
set +x
set -o pipefail
# Two private stdin lines: single-use enrollment link, then current cards link.
# The bearer is needed to read cards; it cannot approve them. No secret arguments.
{
  lxc --force-local exec "$REHEARSAL_NODE" -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py passkey-claim
  lxc --force-local exec "$REHEARSAL_NODE" -- /opt/aukora-node/bin/node --input-type=module -e '
    import fs from "node:fs";
    const origin = fs.readFileSync("/etc/aukora/owner-public-origin", "utf8").trim();
    const { bearer } = JSON.parse(fs.readFileSync("/home/aukora-gate/owner-secret.json", "utf8"));
    console.log(origin + "/owner/cards?bearer=" + encodeURIComponent(bearer));'
} | node ops/node-spawn/browser/rehearse-passkey.mjs --owner-origin "$OWNER_ORIGIN" --app-origin "$APP_ORIGIN"
```

Do not tee, log or save this pipeline's input. The driver keeps its software
private key only in memory, follows GET redirects only within those two exact
HTTPS origins, refuses POST redirects, and prints one secret-free PASS/FAIL line
per step. It refuses extra pending cards and approves only canonical theme
bytes. In a second host terminal, after `PASS bearer-refused`, raise exactly one
theme proposal (this command approves nothing):

```bash
lxc --force-local exec "$REHEARSAL_NODE" -- runuser -u aukora-host -- /opt/aukora-node/bin/node --input-type=module -e '
  import { call } from "/opt/aukora-boundary-gate/src/server.mjs";
  const socket = "/run/aukora-gate/gate.sock", target = "plugins/auma-theme/theme.json";
  const current = await call(socket, "read", { target });
  const content = current.content === '\''{"accent": "#112233"}'\'' ? '\''{"accent": "#223344"}'\'' : '\''{"accent": "#112233"}'\'';
  await call(socket, "propose", { target, content, claimed_base: current.sha256, why: "Software rehearsal theme", session: "rehearsal" });'
```

Wrong RP ID, origin and challenge assertions each use a fresh review **before**
the successful approval. After APPLIED they would only test the spent review.
The driver then requires an applied result, a receipt bound to the exact proof,
removal of the pending card, and refusal of the unchanged proof's replay. It does
not independently verify the receipt signature or ledger inclusion.

After `PASS replay-refused`, enable returning sign-in in that second terminal.
The already-bound activation deliberately starts without browser join. Select
its existing public binding record, then use the existing protected startup
command. First returning sign-in does not read that record until final subject
binding is selected; this rehearsal does not grant record or seed access:

```bash
lxc --force-local exec "$REHEARSAL_NODE" -- /usr/bin/python3 -I -S -c '
import json, os, sys
path = "/etc/aukora-boundary-gate/browser-join.json"
value = {"version": 1, "kind": "aukora-browser-join/v1", "app_origin": sys.argv[1], "binding_record": "/home/aukora-host/genesis/state/aumlok-binding/local-control.json"}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
os.fchmod(fd, 0o644)
with os.fdopen(fd, "w") as output: json.dump(value, output)
' "$APP_ORIGIN"
lxc --force-local exec "$REHEARSAL_NODE" -- /usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py enable-owner-signin
# If its gate restart stopped the harness:
lxc --force-local exec "$REHEARSAL_NODE" -- bash /opt/aukora-genesis/src/ops/node-spawn/browser/start.sh
```

The driver waits up to five minutes each for the card and sign-in page. It signs
the gate's sign-in statement, exchanges the one-use returned code at the app
origin, and requires a Secure, HttpOnly, SameSite=Strict, Path=/, `__Host-` cookie
without Domain. This does not perform the join's final subject-binding touch;
future card approvals with join selected require that separate step. Destroy
the rehearsal node rather than recovering or reusing its software credential.

`node --test ops/node-spawn/browser/rehearse-passkey.test.mjs` runs real gate
handlers in process with a software authenticator. The rehearsal marker,
operator proposal/startup, HTTPS transport and harness cookie exchange are
simulated there; sign-in code redemption uses the real gate handler. No installed
node was reachable for this change. Running this driver on an installed node
proves the exercised protocol with a **software authenticator**, not a real
device, a person, informed consent, rendered browser behavior or containment.

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
