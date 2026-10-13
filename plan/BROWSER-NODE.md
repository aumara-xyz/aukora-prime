# Browser node: C1, then C2

Owner direction for this investigation: a normal browser is the product window;
two fresh LXD test nodes on the existing cloud host, each bound by the owner,
first C1, then C2. No Electron, SSH tunnel, downloaded SSH key, relay or invites
in C1. This is a source investigation and proposed work order, not an installation.

Reviewed `5d69e2f69135494448a468cbc21781ebb8bb29cd`, Node `v24.11.1`.
No remote machine or real authenticator was inspected. References below name
source files and line numbers at that revision. `vendor/dsh/…` means the pinned
harness source read at `~/aukora-prime/vendor/dsh`; the serving/authentication
files were compared with this clone's `vendor/dsh-source.tar.gz` and the permitted
read-only copy at `~/aukora-genesis/vendor/dsh`. Archive SHA-256 matches
`upstream-dsh.json:3-6`. The vendor directory's enclosing Git HEAD is not a
harness revision.

## 1. Serving

The harness already serves a browser application; Electron is a carrier, not the
renderer implementation that must be replaced. Its web bundle mounts the built
frontend (`vendor/dsh/packages/bundle/web-app/src/index.ts:162-165,225-232`),
and its HTTP server dispatches routes and fallback through `node:http`
(`vendor/dsh/packages/host/webserver/src/index.ts:9,219-256,292-299`).
The launcher fixes the backend to `127.0.0.1`, currently the service's port 18735
(`scripts/launch-dsh.py:652-654`;
`packages/boundary-gate/host/systemd/aukora-genesis.service:47`).

| Existing mechanism | Public-browser consequence |
| --- | --- |
| Webserver schema permits `127.0.0.1` or `0.0.0.0`, port 0 through 65535; CLI has `--host`, `--port`, `--trusted-host`, but explicitly refuses CLI `--host 0.0.0.0` (`vendor/dsh/packages/host/webserver/src/index.ts:58-69,125-130`; `vendor/dsh/packages/bundle/web-app/src/startup.ts:51-54,74-85`). | Keep backend loopback. A host reverse proxy cannot directly dial another container's loopback namespace: provide a container-local forwarding/proxy service reachable only from the host proxy, with the actual LXD network path/firewall tested. This topology is proposed, not supplied by those server options. |
| A random 32-byte launch token authorizes one root GET with `?token=`, which sets a signed cookie and redirects 303 to `/`, with `no-store`/`no-referrer` (`vendor/dsh/packages/client/connection/src/browser-auth.ts:52-57,240-264`). | This is bearer login, not a user account. Do not send the reusable node launch token to the new browser login flow. |
| Cookie name is `dsh-auth-` + SHA-256/base64url of canonical request Host, including port; its signed audience must match the same authority (`vendor/dsh/packages/client/connection/src/browser-auth.ts:69-78,106-108,289-301`). | A cookie minted for `127.0.0.1:18735` cannot sign in at a public hostname. A browser login must mint/exchange a cookie for the public authority. |
| Cookie has `HttpOnly`, `SameSite=Strict`, `Path=/`, expiry/Max-Age, no Domain and **no Secure** (`vendor/dsh/packages/client/connection/src/browser-auth.ts:120-123`). Default lifetime is 30 days, with a persistent signing secret (`vendor/dsh/packages/client/connection/src/index.ts:84-94,107-118`; `vendor/dsh/packages/client/connection/src/browser-auth.ts:161-177`). No logout/revocation method exists in this class (`vendor/dsh/packages/client/connection/src/browser-auth.ts:210-302`). | Add Secure and bounded, revocable owner sessions. Restarting the harness is not logout. TLS alone does not change the emitted cookie flags. |
| `trustedHosts` is already configurable; a portless entry accepts that hostname at any port (`vendor/dsh/packages/client/connection/src/api-request-trust.ts:49-81`; `vendor/dsh/packages/client/connection/src/index.ts:75-95,107-112`). | Pass the exact public authority through a reviewed release overlay or a small launcher `--trusted-host` passthrough. Preserve Host at the proxy. |
| API trust rejects untrusted Host and `Sec-Fetch-Site: cross-site`; present Origin must have matching `.host`, but scheme is ignored and missing Origin is accepted (`vendor/dsh/packages/client/connection/src/api-request-trust.ts:91-117`). This precedes cookie authentication (`vendor/dsh/packages/client/connection/src/rpc-host.ts:96-105`; `vendor/dsh/packages/client/connection/src/index.ts:124-138`). | Preserved public Host without its allowlist makes API fail 403; rewriting Host to loopback while preserving public Origin also fails. Stripping Origin is not a repair. Add exact configured HTTPS-origin checks to the owner/session routes; review the weaker harness fence explicitly. |
| `/api/remote.mux` uses the same trust and cookie checks before upgrade; browser chooses page origin and `wss:` under HTTPS (`vendor/dsh/packages/api/gateway/src/index.ts:205-228`; `vendor/dsh/packages/api/gateway/src/client/stream-client.ts:304-309`). HMR SSE uses the same rejection helper (`patches/client-hmr-events-auth.patch.json:7-16,19-36`). | Proxy HTTP, WS upgrades and SSE without removing Host, Origin, Cookie or Fetch Metadata; prove all three on C1. |
| No trusted-proxy or public-origin option appears in the serving/auth config; request Host is read directly, internal Fetch URL uses `http://dsh.internal` (`vendor/dsh/packages/host/webserver/src/index.ts:58-70,125-131`; `vendor/dsh/packages/client/connection/src/index.ts:72-95`; `vendor/dsh/packages/client/connection/src/http-bridge.ts:39-45`). | `trustedHosts` does not authorize arbitrary forwarded headers. Restrict incoming hostname, overwrite client-supplied proxy headers, and configure external origin independently. |
| Frontend index requires authentication, static assets are public, traversal is refused and unsupported fallback methods return 405 (`vendor/dsh/packages/host/frontend-static/src/index.ts:76-105,124-141`). Default API bridge body ceiling is 300 MiB (`vendor/dsh/packages/client/connection/src/http-bridge.ts:10-14,47-71`). | Public assets are expected; private APIs must remain fenced. Add endpoint-specific body, time, connection and rate limits before internet exposure. |

The private launch descriptor must remain internal: validation requires an HTTP
loopback URL and one token, and writes the token/URL with private permissions
(`scripts/launch-dsh.py:705-736`). Logs are separately redacted
(`scripts/launch-dsh.py:688-698,767`). The nearby comment that no token reaches
disk is broader than the descriptor code; trust the latter. A safe proxy must
also keep URLs/tokens out of access logs and referrers.

## 2. Sign-in: what can be reused

| Component | Browser / Electron / unjoined status |
| --- | --- |
| `packages/owner-key` | Node public P-256/SPKI verification and identity pinning, not a login screen (`packages/owner-key/src/index.mjs:2-3,64-74`). Nostr binding explicitly grants no authority (`packages/owner-key/src/index.mjs:89-105`). `ownerAuthorizationEnrollment()` validates caller-supplied subject, key, epoch and registry/activation digests; it neither establishes them nor writes protected state (`packages/owner-key/src/authorization.mjs:35-54`). No production enrollment caller was found in the repository search; missing owner-state stops node-spawn (`ops/node-spawn/linux.sh:167`). |
| Prime WebAuthn | Browser assertion adapter calls `navigator.credentials.get`, requires exact secure origin/RP, recomputes request challenge, and returns authenticator/client data (`packages/ui/adapters/passkey.mjs:24-89`). NEXT authority verifies assertions and supplies one-use login challenges, sessions and per-operation approvals (`packages/authority/src/webauthn.mjs:44-69`; `packages/authority/src/service.mjs:295-377`). It is not the Genesis entry/gate login: default `/api/prime` returns 503, default composition marks passkey unavailable and host plugin `apply` is a no-op (`harness/host.mjs:71`; `scripts/compose.py:119`; `packages/ui/prime-authority/lib/index.js:2`). Tests use synthetic P-256 authenticator data (`packages/authority/check.mjs:95-103,238`); this investigation did not run a real authenticator. |
| Prime registration | Registration/possession backend exists: none-attestation ES256 registration parser, creation options, then possession assertion (`packages/authority/src/passkey-enrollment.mjs:94-169`). It requires an already selected public identity/provenance, has no route/store/config writer, and ends with `requires_protected_setup_commit:true`, `owner_enrollment:false` (`:2,47-63,137-169`). No browser `navigator.credentials.create` enrollment screen was found by repository search. `packages/authority/README.md:128` saying registration validation is absent is stale relative to this code. |
| Aumlok | Identity face renders in a browser, but first binding is exposed only through Electron `window.aukoraAumlok`; ordinary browser ceremony controls are absent (`plugins/aukora-face/aumlok/src/client/index.ts:48-53`; `plugins/aukora-face/aumlok/src/client/binding-bridge.ts:74-89`; `apps/aukora-desktop/aumlok-bridge-preload.cjs:4-29`). Public-host status/identity reads also stop on `isLoopback` (`plugins/aukora-face/aumlok/src/client/control-status-loader.ts:45`; `plugins/aukora-face/aumlok/src/client/index.ts:55-60`). Not a browser login. |
| Gate OWNER-HTTP | Real opt-in browser HTML/forms: `--owner-page`, default port 17792, loopback only (`packages/boundary-gate/bin/gate.mjs:23-24,53-54`; `packages/boundary-gate/src/server.mjs:38-50`). URL/hidden bearer plus typed two-step colour confirmation; no browser signer, CSP disallows scripts (`packages/boundary-gate/src/owner-page.mjs:25,53,61-75,85-89`). It submits no owner authorization proof, so cannot approve enrolled-owner mode (`packages/boundary-gate/src/gate.mjs:572-601`). Red-team “owner page” uses a synthetic gate without owner-state and checks rendering/warnings, not passkey login (`packages/boundary-gate/checks/redteam.mjs:37-49,105-109`; shared warning computation `packages/boundary-gate/src/card.mjs:65-80,148-154`). |
| Desktop approvals | Current popup adapter uses the existing Mac owner socket and sends legacy review/decide without P-256 proof (`apps/aukora-desktop/main.mjs:458-478`; `apps/aukora-desktop/aumlok-signer-airlock.mjs:279-295`). A separate owner-key caller seam exists, but native Swift refuses before signing/key/biometric operations (`apps/aukora-desktop/owner-key-bridge.mjs:69-96,112-132`; `apps/aukora-desktop/owner-key-touchid.swift:145-153,189-191`). Do not describe that seam as a working passkey route. |

The smallest browser login is a protected bootstrap registration followed by a
WebAuthn login challenge and a bounded server session, joined to the existing
harness cookie boundary. Keep the private launch token inside the node. This is
new integration work; neither phrase possession nor a cookie appoints the owner
(`packages/owner-key/src/authorization.mjs:35-54`;
`packages/authority/src/service.mjs:295-377`).

## 3. Browser approvals

The enrolled-owner gate already binds operation, proposal, target, before/after
hashes, gate identity, owner subject/root/epoch, fresh challenge and expiry
(`packages/owner-key/src/authorization.mjs:8-12,149-167`;
`packages/boundary-gate/src/gate.mjs:524-538`). It verifies current protected
owner-state, pending bytes, expiry, displayability, target validation and raw
P-256 authorization; a locked transaction retains proof, spends the challenge
and changes pending to applying before effect (`packages/boundary-gate/src/gate.mjs:572-648`). The
authorization requirement latches in durable history and cannot downgrade on
loss of owner-state (`packages/boundary-gate/src/gate.mjs:110-140`); state and all ancestors must be
root-owned, non-symlink and not group/other writable (`packages/boundary-gate/src/owner-state.mjs:7-29`).

WebAuthn does not sign arbitrary raw operation bytes: it signs authenticator
data plus SHA-256 of clientDataJSON, containing a challenge. Gate raw P-256
currently signs domain-prefixed authorization bytes instead
(`packages/authority/src/webauthn.mjs:57-68`;
`packages/owner-key/src/authorization.mjs:170-206`). Therefore add an explicit,
closed **WebAuthn proof version**, with challenge equal to the digest of the
gate-issued canonical authorization. Reuse the existing credential, exact
origin, RP hash, UP/UV, backup flags, counter and signature checks; keep durable
counter update in the gate's consumption transaction
(`packages/authority/src/webauthn.mjs:44-69`). Preserve the gate's existing
review and apply path, rather than introducing a second authority service.

Smallest proposed file scope: `packages/owner-key/src/authorization.mjs` plus a
WebAuthn verifier module; `packages/boundary-gate/src/{gate,owner-state,owner-page,
server,receipts}.mjs`, its ledger schema and `bin/gate.mjs`; a browser adapter
based on `packages/ui/adapters/passkey.mjs`; a protected setup writer. Proof
retention and cold verification must understand the new profile: generic gate
receipt reader currently accepts v2, while owner-key has a dedicated v3 reader
(`packages/boundary-gate/src/receipts.mjs:8-16`;
`packages/owner-key/src/authorization.mjs:111-145`). Existing pin reviews must
follow their mechanisms, especially `tests/kira-gate-capture-host.test.mjs`.

**Never** approve from a cookie/session alone, put an assertion's signature into
the raw-ECDSA proof, mint browser proof with a node-held key, expose the OWNER
Unix socket as general RPC, reset the release floor, or fall back to bearer
approval when enrollment is missing. Those would bypass the verified proof,
channel, one-use and state requirements above (`packages/boundary-gate/src/gate.mjs:110-140,572-648`;
`packages/boundary-gate/src/server.mjs:40-50`; `packages/owner-key/src/authorization.mjs:197-206`).

The verifier checks a valid assertion from the pinned credential carrying UP/UV
flags over a bound challenge, not that Peter understood the card. Actual user
verification enforcement needs qualification with the real authenticator. Current registration
uses `attestation:'none'`, permits backup-eligible keys and prefers rather than
requires resident credentials (`packages/authority/src/passkey-enrollment.mjs:110-122`;
`packages/authority/src/webauthn.mjs:63-69`). It does **not** prove a key physically never leaves a
device. If literal device-only custody is required, Peter must choose a
non-backup credential policy and qualify the target authenticator; none
attestation still does not attest hardware provenance.

## 4. Binding ceremony

Current generator draws seven independent uniform words from pinned 2,048-word
BIP-39 lists: 77 bits for that generator, not for chosen words. Legacy acrostic
phrases remain accepted for recovery (`plugins/aukora-aumlok/lib/ceremony-phrase.mjs:22-45,77-109`;
`plugins/aukora-aumlok/lib/bind-v3.mjs:169-172`). The 34-bit statement in `plan/NORTH-STAR.md:240-241`
describes the older generator, not today's uniform path.

`derive-v3` normalizes the public handle as salt and phrase as password, runs
scrypt N=2^17/r=8/p=5, then derives Ed25519 and ML-DSA-65 root halves
(`plugins/aukora-aumlok/lib/derive-v3.mjs:58-60,161-200,225-238`). `bindV3`
refuses an occupied directory, creates a random genesis nonce/subject and
machine index 0, and writes public `local-control.json` and private
`machine-seed-v3.json`; it persists neither phrase nor root seed and requires
file custody (`plugins/aukora-aumlok/lib/bind-v3.mjs:144-218`; `plugins/aukora-aumlok/lib/record-v3.mjs:64-73,207-218,284-323`).
The public record contains version 3, both public root halves/root ID, binding
time, genesis reference/nonce, epoch 0, null receipt, normalized handle, phrase
language/legacy metadata and machine 0's public key
(`plugins/aukora-aumlok/lib/record-v3.mjs:138-180`;
`plugins/aukora-aumlok/lib/bind-v3.mjs:183-195`). The desktop selects an overlay's
configured directory, otherwise `<state root>/aumlok`
(`apps/aukora-desktop/aumlok-bridge.mjs:181-200`); the two custody files are 0600
(`plugins/aukora-aumlok/lib/record-v3.mjs:64-73`). This record is not itself
P-256 owner enrollment. That Ed25519 machine identity is distinct from the P-256 gate owner key
(`plugins/aukora-aumlok/lib/bind-v3.mjs:182-195`; `packages/owner-key/src/index.mjs:64-74`).

Handle/language, draw, show/hide, type-back, acknowledgment and bind screens
exist, currently wired to desktop IPC (`plugins/aukora-face/aumlok/src/client/AumlokSurface.tsx:248-362`;
`apps/aukora-desktop/aumlok-draw.mjs:85-100`). Backend identity routes require
loopback **server binding**, which a container-local proxy can preserve; browser
`isLoopback` restrictions require a reviewed public-origin replacement, not
wholesale removal of authentication (`plugins/aukora-face/aumlok/src/index.ts:466-495`;
`plugins/aukora-face/aumlok/src/client/control-status-loader.ts:45`; `plugins/aukora-face/aumlok/src/client/index.ts:55-60`).

The standalone co-presence portal is browser code, with nonextractable WebCrypto
P-256 keys stored in IndexedDB (`packages/copresence/portal-v0/portal/index.html:212,1227,2449`).
Its receiver checks fresh signed evidence, optional exact text and roles, and
one-use consumption; `verifyDeviceBinding` checks an existing device/member
statement, not an enrollment producer (`packages/copresence/receiver.mjs:126-145,170-210`).
There is no production ceremony receiver join found by repository search.
A receipt adds evidence of the shared encounter, not gate authority, person
uniqueness, ownership or absence of relay (`packages/copresence/portal-v0/portal/index.html:394`;
`plan/NORTH-STAR.md:335-338`).

Proposed first run: open HTTPS address -> explicitly claim the prepared node ->
create/verify owner passkey -> optionally perform the existing two-device light
exercise if Peter retains that October 12 order -> choose handle/language and
draw/see/retype phrase -> bind subject and device-owner key to this exact node ->
review its initial release card with that passkey -> enter the app. The light
exercise requires a second device and a new receipt join; it cannot manufacture
owner enrollment (`plan/NORTH-STAR.md:228-230`; `packages/copresence/receiver.mjs:194-210`).

**Owner custody decision:** the shortest port calls existing `bindV3` on the node;
the node receives the recovery phrase and temporarily derives the root there.
TLS does not make derivation local (`plugins/aukora-aumlok/lib/bind-v3.mjs:173-218`). Preferred if those
secrets must remain on the device: port derivation to a browser worker and submit
only public binding material with possession proofs, separately enrolling the
node's machine authority. This needs a new closed envelope binding node identity,
genesis, handle, node public key, owner credential and fresh server nonce: root
dual-signatures, node possession and a passkey assertion must all verify. Current
record projection is not a binding-authorization verifier; a separately generated
node key also needs honest custody/purpose metadata rather than the current
HKDF-derived machine label (`plugins/aukora-aumlok/lib/record-v3.mjs:293-299,378-389,421-447`;
`plugins/aukora-aumlok/lib/root-class-v3.mjs:87-88`;
`plugins/aukora-aumlok/lib/machine-key-v3.mjs:76-100`). No new crypto dependency is necessary: existing
vendored Noble scrypt/HKDF and Aumlok Ed25519/ML-DSA code provide the primitives
(`vendor/authority/deps/@noble/hashes@2.2.0/scrypt.js:5-8,177,225`;
`vendor/authority/deps/@noble/hashes@2.2.0/hkdf.js:6-7`; `plugins/aukora-aumlok/lib/vendor/noble-curves/curves/ed25519.js:9-18`;
`plugins/aukora-aumlok/lib/vendor/noble-ml-dsa/index.mjs:23`). Browser bundling, protocol and real-device
memory/time qualification are still needed; the existing Node/fs binding is not
already that implementation (`plugins/aukora-aumlok/lib/derive-v3.mjs:188-192`; `plugins/aukora-aumlok/lib/bind-v3.mjs:212-213`).

For C2, rerunning first bind with the same phrase creates the same root but a
different subject because genesis nonce changes; it does not add another node
to C1's identity (`plugins/aukora-aumlok/lib/bind-v3.mjs:173-195`). Machine index derivation and
revocation-aware selection exist, but current bind always selects zero and no
production caller of `nextMachineIndex()` was found (`plugins/aukora-aumlok/lib/machine-key-v3.mjs:76-100`;
`plugins/aukora-aumlok/lib/record-v3.mjs:635-663,700-725`). Peter must choose independent test subjects
under his separately enrolled owner credentials, or a shared subject with a
new root-authorized add-machine ceremony. Do not copy C1's private state to C2.

## 5. Fresh node

`ops/node-spawn/spawn.sh` has two different paths. Default LXD path verifies an
invite and then refuses unimplemented image/profile/provisioning gaps; it is
not a fresh container installer (`:25-26,59-95,114-143`). Its header saying no
installer exists does not describe the later `--linux` path: that path stages
pinned Node, clean reviewed checkout, gate/owner packages and built harness,
creates service users, redeems **two** invites, configures the Buzz door,
preserves approval/floor and runs installed door readback
(`ops/node-spawn/linux.sh:37-46,50-144,160-176`;
`ops/node-spawn/stage.py:16-20,79-84,219-273`). It still refuses missing enrollment and relies
on already provisioned sandbox, local-deny, gate keys, ranges and state
(`ops/node-spawn/linux.sh:167-169`; `ops/node-spawn/configure-host.py:118-147`). Its acceptance requires a
closed relay and admitted Auma query; it does not prove browser or ceremony
(`ops/node-spawn/configure.mjs:55-64`). Neither path is the requested no-invite/no-relay C1.

Fresh-clone machinery is a usable build/boot recipe, not a protected installer:
it verifies inputs, materializes a release and explicitly uses temporary
same-user authority, no model key (`scripts/fresh-clone-check.sh:73-81,133-181`;
`plan/NORTH-STAR.md:487-489`). Its own default writes outside this clone and
therefore was not executed here (`scripts/fresh-clone-check.sh:99-112`). The plan's past
node/CI reports are retained reports, not fresh runtime evidence from this task.

| Fresh C1 input | Existing code / missing installation |
| --- | --- |
| Container and principals | Fresh unprivileged LXD container, reviewed image/resources/private proxy transport, separate harness/gate users and root-held packages; never clone the pilot/staging state. Default spawn explicitly lacks LXD profile; Linux path supplies user/stage routines (`ops/node-spawn/spawn.sh:65-79`; `ops/node-spawn/linux.sh:59-103`). For the minimum demo, disable shell/file/agent effect providers unless the existing normal sandbox route is actually provisioned and qualified; default service selfcheck depends on that route (`packages/boundary-gate/host/systemd/aukora-genesis.service:13-17,39-47`). A restricted browser-demo profile requires review, not a selfcheck waiver. |
| Gate | Fresh local bearer/receipt signing keys, public signer epochs, installed protected package/runtime manifests, targets, owner-state and approved release floor; an independent bootstrap surface must run **before** the harness, since harness startup requires approval (`ops/node-spawn/spawn.sh:92-103,124-139`; `ops/node-spawn/configure-host.py:133-137`; `packages/boundary-gate/host/systemd/aukora-genesis.service:41-47`). Browser enrollment must not depend on an already running approved harness. |
| Kira identity/state | Generated composition has placeholder `aumlok:subject:owner`, deployment template supplies subject/stateDir (`scripts/materialize-aukora-release.py:1626-1635,1790-1803`). Normal identity resolution reads `kira-deployment-overlay.patch.yml` in the support root and refuses an unresolved canonical subject; protected capture config can provide an explicit interim alias mapping (`plugins/aukora-kira/lib/memory-identity.mjs:103-145`; `plugins/aukora-kira/lib/gate-capture-host.mjs:119-160`). Write C1's overlay from its verified ceremony, not staging's synthetic subject. Launcher forwards support root but not arbitrary model env variables (`scripts/launch-dsh.py:625-651`). |
| Model | Owner supplies one permitted provider credential; local managed credentials live in `$DSH_HOME/.credentials.yaml`, are protected against group/other read, and DeepSeek resolves its credential reference per request (`vendor/dsh/packages/credentials/credentials-local/src/index.ts:60-68,135-143`; `vendor/dsh/packages/llm/llm-deepseek/src/config.ts:28,82`; `vendor/dsh/packages/llm/llm-deepseek/src/index.ts:103`). A node can serve screens without it, but a reply needs it. Set provider/spend limits for C1; never print the credential or copy a pilot store. |
| OpenViking | Separate private home/root.key must already be provisioned; pinned install/runtime and embedding model checks exist (`scripts/openviking-setup.sh:11-28,78-89,109-129`). Materialize with `--kira-openviking-home` and preserve that config in the owner overlay (`scripts/materialize-aukora-release.py:423-431,976-977,1794-1803`). Naming that home is semantic recall opt-in despite `retrieval: lexical` (`plugins/aukora-kira/lib/index.js:538-539`). Lexical memory can precede semantic recall, but must be labeled as such. |
| Relay/door | C1 needs neither HTTP relay nor Buzz key/channel/session/admission. Default release mounts both host tools; Buzz door returns unavailable when its private configuration is absent (`scripts/materialize-aukora-release.py:1610-1625`; `plugins/aukora-buzz-door/lib/index.mjs:33,543-547`). Add a reviewed no-network profile excluding them, rather than fabricating admission or copying settings. Preserve invitation requirements for the existing network installer. |

## 6. Internet review risks

| Risk | Existing mitigation / required addition |
| --- | --- |
| First visitor claims owner; enrollment race or repeated setup replaces a root | Public enrollment helper only checks structure (`packages/owner-key/src/authorization.mjs:35-54`). Need exclusive, expiring, owner-delivered node claim and protected setup commit; bind public key/subject/node/RP and close enrollment after success. No open first-visitor enrollment. |
| Host confusion, HTTP cookie leakage, CSRF or cross-site WS | Existing Host/Fetch Metadata/Origin-host and cookie fences described in §1. Need exact external HTTPS origin, Secure/revocable sessions, strict proxy routing, independent CSRF protection on owner mutations and WS handshake checks; refuse forwarded-header spoofing. |
| Proposing app replaces approval display or invokes signer with misleading card | Card sanitizes/fences model notes but does not isolate web origins (`packages/boundary-gate/src/card.mjs:65-80,148-154`). Serve immutable gate-owned approval/enrollment code on an independently controlled owner origin, or explicitly review the larger same-origin trust assumption. Keep owner cookies/RP isolated from model-controlled apps; no iframe approval. Existing page frame/CSP protection is a starting point (`packages/boundary-gate/src/owner-page.mjs:85`), not a signed display guarantee. |
| Cookie theft becomes authority; replay or C1 proof applies on C2 | Per-operation owner proof, gate identity, expiry, durable challenge consumption and stale-byte checks already exist (§3). Extend to WebAuthn/RP/counters without fallback; retain session revocation, rate limits and cross-node refusal evidence. |
| DoS, model cost or an exposed administration API | API bridge permits 300 MiB and cookie admits RPC (`vendor/dsh/packages/client/connection/src/http-bridge.ts:10-14`; `vendor/dsh/packages/client/connection/src/rpc-host.ts:96-105`). Need bounded bootstrap/login/approval requests, connection/challenge quotas, model request/cost caps and a reviewed public RPC surface. Do not expose LXD, raw OWNER/propose sockets, OpenViking or credential stores. |
| Phrase/root leaks, weak chosen words, mistaken passkey custody claim | Current Node bind sees root/phrase, uniform generation has conditional 77-bit estimate, none-attestation accepts backup keys (§§3-4). Decide local derivation and passkey policy; no phrase in prompts, URLs, logs or receipts. Do not market biometric/unique-human/device-only custody without its evidence. |
| Cloud operator, shared host or container escape owns node authority | Root-held state and separate sockets/users exist (§§3,5); host administrator/shared kernel still control code and node state. Qualify LXD isolation and backend reachability. Device signatures do not make cloud-hosted UI or root operator harmless; this does not prove complete containment. |
| Release substitution, rollback or restart revives spent approvals | Existing package checks, exact approval and monotonic floor precede launch (`packages/boundary-gate/host/systemd/aukora-genesis.service:41-47`), and gate consumption is durable (§3). Preserve these in new mode; inspect loaded release, reboot and replay on C1. Lost-key recovery/rotation must be owner governed; a wiped state/floor is not recovery. |
| Ceremony receipt is treated as admission or authority | Co-presence receiver verifies and consumes evidence, creates no owner binding (§4). C1 has no network membership; receipts cannot unlock a gate effect or silently admit a relay member. |

## Ordered implementation: stop first at C1 opened and bound

These are proposed files, not changes made by this investigation. Each row
depends on the previous row's real-node proof. Small = one bounded configuration
or adapter; medium = several joined components; large = a new protected protocol
or fresh deployment path. No date or successful live result is implied.

| Order / size | What and files touched | Proof on a real fresh node | Owner input |
| --- | --- | --- | --- |
| 1 · small | Fix C1 profile and trust choices: no relay/invites; per-node RP/origin, trusted owner display origin, exclusive initial claim; local phrase derivation versus explicitly accepted cloud custody; optional two-device exercise; C2 identity relation. Record agreed values in operator input for `ops/node-spawn`, not secrets in source. | Operator confirms image/profile and proxy-to-container private path on the existing host; Peter identifies the intended browser device/authenticator and hostname. Dependency: none. | **Decision + hostname(s)**; confirm co-presence requirement and key recovery/custody policy. |
| 2 · large | Add a C1 installer mode beside existing invitation flow: reuse `ops/node-spawn/{linux.sh,stage.py,configure-host.py}` and pinned fresh-clone build functions, separate gate/harness principals, fresh local gate keys and reviewed public epochs, final release bytes/manifests/targets, restricted no-relay profile, final OpenViking config paths and bootstrap serving without starting unapproved harness. Provision normal containment or refuse all model effect providers. | Fresh LXD C1 from image, no copied state; read installed users/modes/package pins, fresh signer fingerprint, loopback listeners and failed unauthorized effect attempts. Show missing owner-state blocks harness while bootstrap still answers. Dependency: 1. | **Decision** on restricted demo profile; operator supplies reviewed image/resources. |
| 3 · medium | TLS ingress/session plumbing: new proxy configuration under `ops/node-spawn`; container-local private forwarder; `scripts/launch-dsh.py` trusted-host passthrough or release overlay; narrow pinned harness cookie/origin patch through `upstream-dsh.json`/`patches`. Keep internal descriptor loopback. | Public HTTPS bootstrap at C1 hostname from clean device; correct certificate; bad Host/origin/cross-site WS refused; raw ports unreachable externally; Secure cookie policy observed on bootstrap. Harness WS/SSE acceptance follows its approved launch in row 7. No token printed. Dependency: 2. | **Hostname/DNS/TLS access** and approval-origin choice from 1. |
| 4 · large | Protected first-run browser owner enrollment and login: `packages/authority/src/{passkey-enrollment,webauthn}.mjs` reuse, `packages/owner-key/src/authorization.mjs`, gate owner-state/setup writer, browser create/get screen and session broker. Generate real registration/activation evidence, not invented digest fields. Add a provisional node-claim registration protocol; existing enrollment challenges already bind the final identity and cannot have their subject replaced later (`packages/authority/src/passkey-enrollment.mjs:47-63,137-158`). Row 5 must obtain a new passkey-signed exact subject/node binding and commit protected root/epoch activation. | Peter creates credential and proves possession on the clean device; operator sees only public credential/provenance. Concurrent claim, wrong node/RP/origin, replay, expired claim and second setup refuse. Bootstrap-session login/logout/expiry tested; no reusable launch token in browser history/traffic. Full owner/app login follows final binding and row 7. Dependency: 3. | **Peter's real enrollment action**; device-only versus sync policy from 1. |
| 5 · large (local derivation) / medium (accepted cloud derivation) | Port ceremony transport in `plugins/aukora-face/aumlok/src/client/{index,binding-bridge,control-status-loader,AumlokSurface}`; split browser-safe derivation from `plugins/aukora-aumlok/lib/{derive-v3,bind-v3,record-v3,genesis-v3,machine-key-v3}` using existing pinned crypto. New authenticated public-record/possession installation join, passkey-signed exact subject/node binding, protected owner-state activation and final bound Kira support overlay before release approval. If light exercise required, join `packages/copresence/receiver.mjs` and portal receipt screen as evidence only. | Peter draws/retypes words and binds C1; refresh and reboot preserve verified public subject/node/key association, private node machine state remains isolated; duplicate/conflicting bind refuses. For local option observe network/logs carry no phrase/root; measure KDF memory/time on target device and compare fixed public vectors. If co-presence retained, both real devices sign/scan and replay refuses. Dependency: 4. | **Peter's binding ceremony**, optional second device; custody choice from 1. |
| 6 · large | Gate browser approvals: `packages/owner-key/src/authorization.mjs` plus explicit WebAuthn module; `packages/boundary-gate/{bin/gate.mjs,src/{gate,owner-state,owner-page,server,ledger,receipts}.mjs}` and browser signer/card. Preserve existing transactional apply and reconcile proof/receipt readers and guarded pins. | Before harness boot, Peter reviews exact initial release card and uses authenticator; installed proof/floor verify. Cookie-only, wrong digest/key/node/RP/origin, stale/replayed/cancelled/expired release proof all produce no effect, including after gate restart. Rendered theme-card proof follows harness launch in row 7. Dependency: 5. | **Peter's real release and test-card approvals**. |
| 7 · medium | Launch exactly the finalized candidate from rows 2/5 approved in row 6: node-spawn startup units, permitted model credential and existing screen/memory probes. Materializer/profile/overlay writer changes belong before row 6; changing approved release bytes requires a fresh card, never a silent rebuild. Extend existing `ops/pilot/ui-probe.mjs` / `scripts/kira/release-recall-probe.mjs` acceptance for public hostname and actual browser ceremony. | Launch approved release; Peter opens C1 in ordinary browser on untouched device, sees icons/apps/identity, gets one model reply; HTTP/WS/SSE authenticated streaming works; one harmless theme card applies once after real passkey approval, appears on screen and has a verifiable receipt. Remember, semantic recall, forget and restart checks use C1's configured memory; stolen cookie alone cannot approve. Read back loaded revision/overlay, owner state, receipt and listening ports. API probes alone do not count as rendered-screen proof. Dependency: 6. | **Model key/provider/budget** and Peter's screen observation. Without key, report screens/binding only, no reply. |
| 8 · medium for separate subjects; large for shared identity | Repeat installer and ceremony for fresh C2, using row 1's identity policy; shared identity additionally needs root-authorized add-machine producer around `record-v3`/`machine-key-v3`. Do not copy C1 secrets, cookie keys, ledger/floor or machine index 0. | Both independent hostnames open from untouched browser context; Peter binds C2 himself; both show intended owner/subject association. C1 cookie/proof cannot authorize C2, memories/receipts isolated, independent restart preserves bindings. Dependency: C1 proof in 7. | **Second hostname**, enrollment/binding/approvals, identity choice from 1. |

For every new protection above, require its focused regression to fail when the
guard is removed, and retain the mutation result. Real-node proofs remain
additional: unit tests cannot establish enrollment, proxy policy, containment,
phrase secrecy, screen rendering or a model reply. Reconcile source/build pins
through reviewed diffs, never by accepting a new digest blindly
(`CONTRIBUTING.md:19-27,30`; `docs/AUKORA-GOLDEN-BOUNDARY.md:721-727`).

## Investigation checks and limits

RAN under Node 24.11.1 with scratch kept inside this clone:

- Pinned harness in-memory trust probe: `PASS pinned harness trust probe: 6 assertions; public Host needs trustedHosts; rewritten Host rejects browser Origin; Origin scheme ignored`.
- `./security-review`: `pass=19 fail=0 skipped=0 unperformed=11`, exit 2;
  child totals `tests=265 pass=262 fail=0 cancelled=0 skipped=3 todo=0`.
  `host-capture-retention: PASS` (`32/32`); protected bootstrap `61/61`.
  Three socket checks were unperformed because paths inside this long clone
  exceed Unix socket path limits, not because of an application failure.
  Nine declared runtime gaps remain; the two partially skipped profile rows
  account for the other two unperformed rows.
- Existing mutation checks ran, including
  `SOURCE-ONLY repository source-pin guard mutation: 1/1 killed; removing the comparison fails all six drift regressions`,
  `SOURCE-ONLY workspace input controls: 3/3 killed; real secret-name/hardlink/external-link inputs accepted only after their guard is removed`,
  and `18 source guard mutations detected`. This document adds no protection,
  so it has no new guard mutation to claim.
- `./prime verify`: exit 2,
  `UNPERFORMED ordinary source suite: PRIVATE_EXTERNAL_EVIDENCE_PARENT_REQUIRED`.
  Its configured runner requires evidence outside the source, which conflicts
  with this task's inside-clone-only rule. No source-profile job was performed;
  owner, database, UID, guest, paid-provider and composed-pixel qualification
  remain unperformed. No external evidence directory was created.
- Read-only synthetic crypto probe: `scrypt full-cost parity: PASS; elapsed 1972 ms`,
  `existing ESM Ed25519 proof: PASS`, `existing ESM ML-DSA proof: PASS`. Existing
  Noble async scrypt matches Node scrypt at full configured cost for one synthetic
  input; this does not measure a real browser or device.
- `node packages/boundary-gate/checks/redteam.mjs`: exit 0,
  `tests 4`, `pass 4`, `fail 0`, `cancelled 0`, `skipped 0`, `todo 0`.
  This exercises synthetic legacy owner-page/card behavior, not public ingress,
  enrolled-owner approval or a rendered real browser.
- Literal basename search of `tests/` and `packages/*/checks` found no test
  naming `BROWSER-NODE.md`. No guarded source/pin, check registration, runtime
  or existing tracked file was changed.
- Document whitespace and citation file/first-line checks passed (144 references).

NOT RUN: fresh installer/container provisioning, TLS/public browser route, real
WebAuthn registration/signing, owner binding, co-presence devices, model reply,
memory service or installed containment. No commit or push is attempted under
this task's explicit rules. This plan proves neither a working browser product
nor identity uniqueness, informed consent, hardware custody, cloud secrecy or
complete mediation of the agent's effects.
