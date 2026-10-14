# Browser-node correctness review

Original review revision: `1437a70833dc8dd3048d7cc9d91a100f488c4a34`.
Status updated from commit messages through `38004c5159500b23ffaefb5df8c98e3ee4150e9f`;
the update is not a new inspection of a deployed Caddy, browser, authenticator,
container, DNS, certificate, firewall, journal or relay. The original review's
loopback `listen()` probe was refused by the sandbox with `EPERM`.

## Repair status — 2026-10-13 evening

These labels use only the audited commit messages. **FIXED IN SOURCE** does not
mean the change ran on a node. No finding below has a later **RAN ON A NODE**
claim in those messages.

| Finding | Current status and scope |
| --- | --- |
| 1 · interrupted enrollment | **FIXED IN SOURCE.** Commit `c2c291c` retains the request and accepted registration across a gate restart while the original claim is live. Its recorded run used a software authenticator; no real authenticator, browser or installed node was run. Expired unfinished setup still requires an owner recovery policy. |
| 2 · unbound general RPC | **OPEN.** A change is described as parked and unrehearsed; the audited commit messages do not record it landing or running on a node. The committed archive-backed test still records authenticated unbound access through both general RPC dispatch paths, so documentation is not a protection. |
| 3 · cookie prefix | **FIXED IN SOURCE.** Commit `c45fcf0` makes the public HTTPS cookie `__Host-dsh-auth-*`; its message records ingress/session/source checks and explicitly says the cookie was not run in a real browser on a node. Existing public cookies require sign-in again after installation. Per-session server revocation remains open. |
| 4 · slow broker connections | **FIXED IN SOURCE.** Commit `c45fcf0` adds absolute header and body deadlines plus a connection cap. Its message records source checks, not installed proxy behavior. |
| 5 · transient invitation delivery | **FIXED IN SOURCE.** Commit `c45fcf0` keeps the same redemption pending through bounded retry after transient relay failure. Its message records source checks, not a real closed-relay retry. |

Commit `c45fcf0` says the harness and all nine face bundles were rebuilt and
their records and frozen copies refreshed after the cookie patch. That is a
source/build claim, not an installed-node observation.

These source changes do not prove safe Internet ingress, real passkey custody,
live cookie behavior, installed limits, relay idempotence or runtime containment.

## Original review evidence at `1437a70`

The details below preserve why the findings were opened. The evening status
table above supersedes their repair state.

### CONFIRMED

1. **A reserved passkey claim can permanently strand a fresh node.** The gate
   durably changes `fresh` to `reserved`, but keeps the ceremony only in a
   process-local map; after restart the registration route returns
   `passkey:ceremony-lost`, while another start returns
   `passkey:enrollment-closed` (`packages/boundary-gate/src/gate.mjs:176-203`;
   `packages/authority/src/passkey-enrollment.mjs:135-146`). The repository's
   real test script demonstrates the state: `tests/owner-passkey-gate.test.mjs:86-90`.
   Observed output:

   ```text
   ✔ claim is required, expires, cannot race, and an unfinished ceremony cannot resume after restart
   ```

   This fails closed, but there is no recovery path short of replacing protected
   setup/state. Smallest fix: durably retain enough ceremony state to resume, or
   add an owner/operator-authorized expiry reset from `reserved` to `fresh` that
   is impossible after `state_text` exists; test crash at each enrollment stage.

### PLAUSIBLE

1. **The four pieces are not one protected bootstrap.** A claim creates an
   ordinary harness session; the pinned host connection admits an authenticated
   request to every registered RPC channel (`vendor/dsh` archive,
   `packages/client/connection/src/rpc-host.ts:96-105,158-176`). Aumlok's browser
   routes accept that same cookie and exact app origin, then return the binding
   words and allow first bind (`plugins/aukora-face/aumlok/src/index.ts:74-123,589-617`).
   The Aumlok installation instructions expressly say they supply no passkey
   enrollment or owner-state activation (`plugins/aukora-aumlok/README.md:6-12`),
   and the browser-node installer says binding/enrollment are separate
   (`ops/node-spawn/browser/README.md:95-101`). Thus a signed-in but unbound
   browser is not constrained to bootstrap operations, and executable
   model-written content on the app origin would be indistinguishable from the
   trusted shell for the binding POST. Smallest fix: issue a bootstrap-scoped
   session whose central route allowlist permits only status/enrollment/binding;
   upgrade it only after one protected passkey-to-exact-subject/node commit, and
   serve untrusted active content on a non-sibling, non-app origin.

2. **The public session is neither revocable nor resistant to sibling cookie
   tossing.** The pinned cookie has a durable signing secret and absolute
   one-day lifetime (`scripts/compose-entries.mjs:19`; archived
   `browser-auth.ts:161-215,289-301`), with no session identifier, logout, or
   revocation store. The Secure patch keeps `dsh-auth-*`, `Path=/`, and no
   `Domain`, but not the `__Host-` prefix
   (`patches/public-browser-secure-cookie.patch.json:13-22`). Host-only means the
   app and owner hosts cannot read each other's cookie; however, a compromised
   sibling can set a parent-domain cookie with the predictable same name, and
   the parser accepts the first matching pair (archived `browser-auth.ts:106-122`),
   plausibly shadowing the valid cookie for denial of service. It cannot forge
   the HMAC or gain owner authority. Smallest fix: use a `__Host-` name and add a
   short-lived server-side session ID with logout/revocation and key rotation.

3. **The claim/owner broker has a slow-client exhaustion path.** Each connection
   gets an unbounded `ThreadingHTTPServer` thread, then blocks reading the
   declared body with no socket deadline (`ops/node-spawn/ingress/claim.py:391-424,490-492`).
   Caddy caps total body size but the template sets no header/body timeouts or
   connection quota (`ops/node-spawn/ingress/Caddyfile.template:4-10,19-75`). A
   throwaway real-handler listener probe could not run because loopback bind was
   `EPERM`; this is reasoned, not observed. Smallest fix: fixed/bounded workers
   plus per-connection header/body deadlines in the broker, and matching Caddy
   timeouts/rate ceilings.

4. **Three transient delivery failures permanently spend an invitation.** All
   member transport/refusal, Aura, malformed acknowledgement, and unknown errors
   share one three-attempt terminal path (`ops/buzz-relay/admit.mjs:150-186`);
   `resume` then records `undeliverable` and never retries
   (`ops/buzz-relay/admit.mjs:255-277`). A brief outage can therefore prevent an
   otherwise valid member and every descendant indefinitely. Smallest fix:
   terminalize only cryptographically or protocol-permanent rejection; keep
   transport/Aura/unknown states pending with capped exponential retry and an
   explicit owner-authorized abandon/reissue operation.

### NOT A DEFECT

- **Claim reuse/races and state files held.** Disposable script
  `tmp/review-browser-claim.py` (deleted) imported the real `claim.py`, used two
  simultaneous `ClaimStore.consume` calls, then substituted corrupt JSON and a
  symlink. Output was
  `concurrent-consume ['CLAIM_SPENT', 'OK']`,
  `corrupt-state CLAIM_STORE_INVALID`, and
  `symlink-state 62 Too many levels of symbolic links`. Locking, no-follow,
  atomic replace, and directory sync are at `claim.py:128-188,209-229`.
- **Proxy confusion and cross-site requests held in source tests.** Caddy closes
  unknown hosts and overwrites forwarding facts; owner and binding handlers
  require exact Host/Origin/fetch metadata and bounded JSON. The owner RP/origin
  is separate and ignores the app cookie. The ingress suite reported `5` passed,
  `0` failed and killed claim `12/12`, Caddy `10/10`, and Secure-cookie `2/2`
  mutations. This is not a live proxy/browser observation.
- **Second binding/enrollment and secret reflection held.** Aumlok spends the
  draw before work and uses `O_EXCL|O_NOFOLLOW` (`browser-binding.mjs:170-229`);
  route errors are fixed strings. Binding tests reported `26 passed, 0 failed`
  and `31 killed, 0 survived`; route mutations were `21/21 KILLED`.
- **Passkey proof replay/cross-node held; counters advance when reported, while WebAuthn permits 0-to-0 for non-counting authenticators such as synced passkeys.** Authorization binds the
  node, RP, exact origin, credential, challenge/card digest, expiry and durable
  review; the gate compare-and-sets the counter in the consumption transaction
  (`packages/owner-key/src/authorization.mjs:325-342`;
  `packages/boundary-gate/src/gate.mjs:698-745`). Passkey tests reported `131`
  passed, `0` failed, including counter, restart, wrong-node/origin/RP and guard
  mutations. This used software fixtures, not a real authenticator.
- **Admission concurrency, bounded HTTP parsing and redaction held.** The stores
  serialize spending; HTTP tests bound bodies, deadlines, peers and address
  tables, and logs expose only invite ID/outcome. Admission reported `25` passed,
  `0` failed, `1` live skip with `67/67` mutations killed; HTTP guards reported
  `15` passed, `0` failed and `36/36` killed. Listener qualification was
  unperformed because of sandbox `EPERM`.

Mandatory `./security-review` result was
`pass=18 fail=1 skipped=0 unperformed=11`, reported child totals
`tests=272 pass=269 fail=0 cancelled=0 skipped=3 todo=0`. Its pinned
`host-capture-retention` case passed `35/35`; no guarded pin was changed. The
single failure is pre-existing HEAD face-copy drift in nine `.build-inputs.json`
files, reproduced directly by `node scripts/audit/check-face-copies.mjs`; this
review changed none of those files. No test or package check names
`REVIEW-BROWSER-NODE.md`.

## Owner decisions

Choose the protected binding/global-RPC policy join, authority for expired
enrollment recovery or explicit invitation abandonment, session
lifetime/per-session revocation policy, and whether model-authored active content
may share the app registrable domain.
These source results do **not** prove a safe Internet node, containment, phrase
secrecy, real-device custody, live cookie behavior, rendered-screen integrity,
or that the four pieces have been installed and joined.


## Working-tree unbound bootstrap repair — 2026-10-14, SOURCE ONLY

Base `67e98443f0e83d4b909410308c7dc0290710d1ee`, plus this working tree.
This supersedes the parked empty-list design, not the historical node observations
above. The supplied real-node report shows that omitting the upload/session
service chain leaves 31 client entries pending and prevents every screen.
No build or installed browser run was performed for this repair.

The archive SHA-256 is
`ae0968314dcd5e3c9d7e8f1f5748bbd289afc4ef5668187e0ef6524a7c64c87e`,
DSH `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`. Cited harness source files
were compared with the archive and the supplied read-only extracted tree;
`tests/browser-bootstrap-boot.test.mjs` repeats comparison for each loaded source.
Paths/lines below refer to the pristine archive; first-party faces refer to this tree.

The dependency trace is `apps/web/src/main.ts:6` ->
`packages/client/web/src/boot.ts:81-87` -> `bootClient` -> `mountClient`.
`boot-client.ts:54-55` waits for the actual Loader and rejects non-active entries.
The renderer provides `slots` and `uiRenderer`; settings uses public-browser
memory persistence (`ui-settings/src/client/index.ts:58`), so its host describe
call is skipped. Locale and theme provide local services. File-upload's client
provides `fileUpload` without uploading; session-controller's client requires it
and provides `sessions` synchronously (`api/session-controller/src/client/index.ts:85-110`).
The ui-session client waits on sessions and slots; the shared layout requires slots/theme/locale/sessions; Aumlok requires
slots/locale/connection, then its projection/layout. Aumlok's status fetch runs
at apply and connection reset; the existing projection subscription opens its
surface. Removing fileUpload reproduces the genuine Loader pending failure in
the new test. UI atoms and transport are fixtures; this is not a browser render.

These are the eager Remote calls on that initial public, unbound path:

| Method/stream | Client need and source | Reads only? / unbound policy |
| --- | --- | --- |
| `$events` | Gateway generation calls `ready(host)`; `api/gateway/src/client/remote-events.ts:135-143` | Only the ready frame is exposed; emit/waterfall contents are withheld. Allowed. |
| `credentials/describe` | Web-search configuration badge; `client/ui-settings-plugins/src/client/web-search-card-controller.ts:98,128` | Yes: configured/writable metadata, values stripped by `api/settings-controller/src/credentials.ts:83-90`. Allowed. |
| `agentPresets/list` | Hero preset chips and reset refresh; `client/ui-agent-preset/src/client/settings-store.ts` | Yes: path-free roster, `preset/agent-presets/src/index.ts:285-303`. Allowed. |
| `session/modelCatalog` | Global model directory resolver; `client/ui-model-selection/src/client/index.ts:137`, `service.ts:52`, `catalog.ts:45` | Yes: provider/model names/default, no addressed session; `api/session-controller/src/catalog.ts:16-66`. Allowed. |
| `permissionPresets/catalog` | Permission catalog subscribes to connection generation; `client/ui-permission-presets/src/client/index.ts:134-135`, `ui-permission-presets/src/client/catalog.ts:44-53,115-134` | Yes: configured names/descriptions (`interaction/permission-presets/src/index.ts:292-305,388-394`), does not apply permissions. Allowed. |
| `dynamicCordisRunner/syncInspectManifest` | Scheduled inspection publication; `extensions/cordis-client-runner/src/client/inspect-registry.ts` | No: replaces host mirror, `extensions/cordis-host-runner/src/index.ts:497-500`. Refused; chain catches failure. |
| `session/control` | Session controller starts its control stream at apply | Reads queue/message/projection content (`api/session-controller/src/control.ts`). Refused; failure callback logs, service stays mounted. |
| `session/list` | SessionManager refresh on connection ready/reset | Reads summaries/projections. Refused; list remains pending with error, not a missing service. |
| `dynamicCordisRunner/inventory` | UI Cordis refreshes at apply/reset; `extensions/ui-cordis/src/client/index.ts:58-61,82-85,173` | Reads session-associated agent/package/run diagnostics (`extensions/cordis-host-runner/src/index.ts:525-542`). Refused; `ui-cordis/src/client/inventory.ts:78-100` catches failure. |
| `workspace/follow` | Workspace client starts snapshot stream at apply | Reads workspace paths/session IDs; unnecessary for binding. Refused; model stores failure. |

A retained session selection can additionally attempt `subagents/list`; it is
refused. Public `settings/describe` is skipped. The session-list readiness guard
in the replacement `plugins/aukora-face/settings/src/client/SettingsOnboarding.tsx:35` prevents the
initial DeepSeek onboarding reads `llm/listProviders` and
`llm/listConfigurableProviders`. `GET /open-in-app/apps` is also eager but optional: its controller catches refusal and hides the host-open button (`client/ui-open-in-app/src/client/controller.ts:71-85`). No session-content read is admitted for this screen; retained local selection does not widen the policy.
Static assets, theme, Aura snapshot, Aumlok control/identity reads and the four
first-binding POSTs retain the parked exceptions; binding POSTs intentionally
write identity state and are separate from the five-entry RPC list.

`browser-bootstrap-guard.patch.json` checks HTTP before route/fallback selection
and upgrades. Only GET `/api/remote.mux` can upgrade while unbound; the existing
cookie/Host/Origin checks still run. Gateway checks run before Remote
context/lookup resolution and again immediately before `Reflect.apply`; special
`$events` and `$events/result` dispatch paths are checked too. The private
`$events/content` sentinel is default-denied before binding, at broadcast,
waterfall delivery and dequeue. Already-open connections admit new events after
binding; prebinding pending waterfalls are replayed on normal reconnection.
Bound calls and ordinary profiles use the original dispatch.

HTTP refusal is 403 `{ok:false,reason:'browser-node:binding-required'}`.
The actual mux pump emits `type:'error'` with the same code/message and
`details:{status:403,reason:'browser-node:binding-required'}`. Missing/throwing/
invalid policy uses `browser-node:binding-guard-unavailable`. The real pinned
mux receive/pump is exercised in memory, without listen().

Integrator commands, **NOT RUN**, from a clean reviewed checkout with a fresh
archive extraction (retain any previous patched/built tree separately):

```sh
export PATH=$HOME/.local/node-v24.11.1/bin:$PATH
python3 scripts/build-dsh.py
scripts/build-face-bundles.sh
python3 scripts/materialize-aukora-release.py --browser-node --public-origin "$AUKORA_APP_ORIGIN" --from "$PWD/vendor/dsh" --to "$AUKORA_REVIEWED_RELEASE"
./security-review
```

Use the existing browser install/approval/start/acceptance route for an isolated
rehearsal; obtain a fresh owner approval for the exact rebuilt plugin set.
Do not reuse an earlier release's approval or hot-load these bytes into a node.
The patch set changes from eight to nine. Existing harness
`.dsh-build/pinned-harness-build.json`, `genesis-artifacts.json`, upstream client
build/host artifact inventories, all nine face `lib/.build-inputs.json` records,
and downstream release strip/artifact/plugin-set/materialization records need
regeneration. Face inputs include `upstream-dsh.json`; stale manifests must not
be relabelled. The installed bootstrap and root gate-package manifest also need
regeneration through the installer because the launcher-recipe pin changed.
Frozen NEXT face snapshots remain historical; no frozen pins were moved here.

Reviewed capture reconciliation changed only the materializer hash and its
review comment: browser webserver/gateway opt-ins, bootstrap mount and required
plugin name. Kira rows/configuration/proposal socket and the gate.mjs hash are
unchanged. The bootstrap's recipe pin and the default surface fingerprint were
refreshed. This does not join a browser session to an exact owner/passkey,
isolate active content, prove containment, or establish usable installed boot.

## Independent review of the pre-binding restriction (Grok, read-only, 2026-10-14)

A second model family reviewed `plugins/aukora-action-gate/lib/browser-bootstrap.mjs`, its harness patch, its
composition rows and `tests/browser-bootstrap-*.test.mjs` without write access. Its findings and what was done:

| Finding (reviewer's label) | Status |
| --- | --- |
| `GET /api/aukora/aumlok-identity` was readable before binding and can create a messaging identity (CONFIRMED) | FIXED IN SOURCE: removed from the pre-binding reads; a test asserts its refusal |
| `/plugins//events` and encoded-slash forms are not covered by the events denial (SUSPECT) | CONFIRMED by a new test at the guard, then FIXED IN SOURCE: any path with an empty segment, an encoded slash or a backslash is refused before binding |
| `bound()` means only that a control record can be read; a leftover or copied record lifts the whole guard (CONFIRMED) | OPEN, accepted for a fresh node: the installer names a binding directory that does not exist until the ceremony creates it. Not a defence against whoever can write that directory (the node's own harness user or root) |
| `prepare` returns the drawn words, so a signed-in client can prepare and bind without a person typing (CONFIRMED) | OPEN by design in this version: the words are drawn on the node and shown once. A binding proves the holder of the signed-in session completed the routes, not that a person read or typed anything |
| `/plugins/` is an open prefix for GET and HEAD apart from events (CONFIRMED; no other live handler found) | OPEN, accepted: bundles and maps live there; a new handler under `/plugins/` would need its own rule |
| RPC names are an exact set; no method-name trick found (CONFIRMED) | holds |
| The multiplexed socket is filtered before providers run; only the readiness frame passes (CONFIRMED) | holds |
| The guard is the first step of HTTP handling and of the upgrade; OPTIONS is refused (CONFIRMED) | holds |

The reviewer's verdict: ship to a test node whose binding directory is fresh and empty; do not describe it as
more than that. RAN ON A NODE (rehearsal `aukora-r1`, stand-in approval, real browser over HTTPS): the app
booted, the binding screen opened by itself, session creation, session listing and file upload answered 403
`browser-node:binding-required`, and the after-approval acceptance passed in its unbound mode.

## Independent review of the sign-in path (Grok, read-only, 2026-10-14)

Verified against `13ff8248cb35c72445249d20db4770c4dba6e508` and these working-tree
repairs, without relying on the review's line numbers. Read the named ingress,
browser installer and enrollment source, the pinned harness archive and its
read-only built `BrowserAuth`/request-trust implementation. This is SOURCE ONLY;
no remote machine, installed unit, Caddy listener or real browser was changed.

| Finding | Reviewer's label | Status |
| --- | --- | --- |
| 1. Sign-out leaves the harness session alive | CONFIRMED | OPEN: pinned `BrowserAuth` verifies an unexpired HMAC without a session registry or revoke API. Sign-out clears only this browser's cookie and does not close upgraded sockets. A copied cookie works until absolute expiry, at most one day, or until the fixed revocation command stops the serving unit, rotates its signing secret and restarts it. An ordinary restart preserves the key and cookie. Use HTTPS links on a dedicated parent domain and disclose this limit to the test user. |
| 2. Revocation helper targets the wrong service | CONFIRMED | FIXED IN SOURCE: inspect loaded/active browser and legacy genesis units, require exactly one verified serving unit, validate its launcher/state root and bind stop/rotation/restart checks to it. Real pinned cookie verification accepts the old cookie before rotation and refuses it after reactivation with the rotated key; systemctl itself is a fixture here. |
| 3. Raw passkey enrollment code remains on disk | CONFIRMED | FIXED IN SOURCE: mint persists only the verification digest and returns the secret once; an existing setup cannot reprint it. The mint command's stdout is secret. New codes are absent from files and retained gate state after use, expiry and restart. Browser-node passkey drop-ins run a root startup sweep that removes and directory-syncs the legacy cleartext file regardless of use/expiry, including after a crash. Old installed drop-ins and direct generic gate starts need the updated browser-node activation route; source changes do not upgrade them. Lost first output requires an owner recovery decision. |
| 4. HTTP redirect carries a token query onward | CONFIRMED | FIXED IN SOURCE: both HTTP hosts answer `token` queries with 404; all other redirects use only the path, dropping every query because unknown parameters can hold secrets. Claim codes remain in fragments, and the mint instructions identify stdout as secret. A token already sent over HTTP has already crossed the wire; use HTTPS links only. |
| 5. HSTS and SameSite do not isolate siblings under a shared parent | CONFIRMED policy; SUSPECT practical break | OPEN: `SameSite=Strict` still attaches the app cookie to same-site requests targeting the app; pinned request trust accepts missing Origin after its Host fence. No state-changing sibling GET was traced. `__Host-`/no Domain keeps cookies off sibling servers but does not block sibling-initiated requests. Use a dedicated registrable parent with no untrusted siblings or model-authored active content. HSTS `--hsts-include-subdomains` is an explicit render option, default off for shared zones; it covers descendants of each configured host, not their common parent or siblings. |
| 6. Restart during exchange strands an already-spent code | CONFIRMED | FIXED IN SOURCE: preserve spend-before-exchange, recognize the pinned harness's exact token-refusal response, reread the descriptor once and retry only a changed token within the already-spent claim. Never un-spend; transport/other refusals do not retry. A second restart or unavailable descriptor can still require a new claim. |
| 7. Atomic replace may lack directory fsync | CONFIRMED crash safety; SUSPECT power loss | NOT A DEFECT at this revision: `ClaimStore._write` already fsyncs the containing directory after `os.replace`, before exchange. The injected `os.fsync` regression checks file/replace/directory order and kills removal of the directory sync. It proves the call/order, not power-loss behavior of a deployed filesystem. |

The remaining observations hold in the inspected source: exact host/port routing
with a closed catch-all; fixed sign-in fallback and `/` harness redirect;
Transfer-Encoding refusal, one request per broker connection, and CR/LF cookie
refusal. These checks do not prove safe internet deployment, root containment,
hardware passkey custody, sibling-host isolation or installed revocation.

## Independent review of the binding ceremony (Grok, read-only, 2026-10-14)

Checked against base `d5998c07f99a1f6e9244b2baf9714bd7843c9676` and this
working tree. All six findings were checked in the current binding, custody,
strict-read, attempt-limit and face-route source rather than relying on the
reviewer's line numbers. **FIXED IN SOURCE** describes these local repairs;
no installed node, browser or real owner ceremony was inspected or changed.

| Finding | Reviewer's label | Status |
| --- | --- | --- |
| 1. Record remains after overlay failure; status reads only the record | CONFIRMED | FIXED IN SOURCE: startup and status validate the kept machine seed and public control, derive a missing or disagreeing overlay from the record and configured state path, durably write it and check agreement before reporting bound. An unreadable overlay returns a named refusal rather than bound. |
| 2. Exclusive record and seed writes lack fsync; an orphan overlay blocks retry | CONFIRMED | FIXED IN SOURCE: exclusive custody writes fsync their file and containing directory. Recovery removes an overlay with no record. A stale marker permits durable removal of missing or torn first-write custody, leaving UNBOUND; complete custody yields BOUND only after overlay agreement. Other validation, metadata or I/O failures preserve custody and refuse for inspection. |
| 3. A crash leaves an exclusive lock that no ceremony verb can free | CONFIRMED | FIXED IN SOURCE: startup and status reclaim a stale marker after recovery succeeds; failed repair retains it for retry. Successful bind removes and directory-syncs its owned marker before returning success. Status reports `unbound`, `binding-in-progress` only while this process holds the lock, or `bound` after agreement. Live lock ownership and inode-matched release preserve exclusivity. This assumes one harness process owns the binding directory. |
| 4. Draw expiry and the persisted limiter use wall-clock time | CONFIRMED | FIXED IN SOURCE for draw expiry: a process-local monotonic clock determines its lifetime; wall time remains for persisted dates/deadlines. OPEN for the persisted limiter: its last-seen floor prevents rollback from shortening a lock, but a forward jump can unlock it before the real elapsed interval. Acceptable only with an owner-accepted trusted-clock assumption for the test stage. |
| 5. Deletion refuses, but a same-uid matching empty attempt database resets failures | SUSPECT against a filesystem attacker; CONFIRMED deletion does not reopen guessing | OPEN: reopen still uses `initialize: false` and missing state refuses. A disposable source probe confirmed that replacing the closed database with a matching empty one resets failures. File ownership/mode checks do not stop its own user rewriting state; binding to a readable directory identity cannot close that threat. The record has the same custody class. |
| 6. Status is an authenticated same-origin POST and returns public binding fields only after authentication | CONFIRMED | NOT A DEFECT: the shared route handler applies the cookie fence before the action, requires exact POST URL/Host/Origin, and unauthenticated refusal contains no bound bit or subject fields. Authenticated status intentionally returns subject, handle, boundAt and rootId. Source route checks remove the fence, URL and exception-redaction guards and require their regressions to fail. |

RAN under Node v24.11.1: `node tests/aumlok-browser-binding.test.mjs --mutate`
reported `36 passed, 0 failed` and `51 killed, 0 survived`;
`node tests/aumlok-browser-record-durability.test.mjs` reported `12 PASS, 0 FAIL`
and killed all five mutations. `node tests/aumlok-browser-recovery.test.mjs`
reported `4 PASS, 0 FAIL` after abrupt process exits at LOCK, RECORD, SEED and
OVERLAY, including fresh binds after UNBOUND. `./security-review` reported
`pass=19 fail=0 skipped=0 unperformed=11` (exit 2, profile UNPERFORMED);
host-capture-retention passed `36/36`, and no guarded pins changed.
The four crash steps follow initial attempt-store provisioning. A crash during
that provisioning is not covered; missing attempt state deliberately refuses.

The additional observations also hold in the inspected source: exclusive lock
creation and record `wx` prevent two successful first binds; submitted words are
absent from URLs and bind/cancel/status/error responses; overlay reads use
`O_NOFOLLOW`; the public handle is NFKC-folded at prepare and bind reuses that
saved handle. These checks do not prove phrase secrecy on a compromised host,
power-loss behavior of installed storage, Kira activation, owner/passkey custody,
or that a kept identity was minted on a real node. The owner must decide whether
trusted clock and harness-user filesystem custody suffice for a disposable test;
they do not establish protection against that user or malicious storage rollback.

## Whole-repository red team of GitHub main d5998c0 (Grok, read-only, 2026-10-14)

Three read-only Grok reviews ran on fresh clones of GitHub main at `d5998c0`:
owner authority, claims against code and CI, and the installer. The installer
review returned no findings on two attempts. An Antigravity (Gemini) review was
NOT RUN: its local CLI needs a project already opened in that app for this
repository, and none exists. Each finding was checked against the current tree
before it is listed here.

| Finding | Verdict | State |
|---|---|---|
| A release approved on the gate's passkey page cannot install: the page writes approver `owner via gate passkey page`, and `verifyGateSetApproval` accepts only the socket and bearer-page strings; once passkey setup exists the bearer path is refused | CONFIRMED in source (`plugin-set-canon.mjs`, `owner-page.mjs`) | FIXED IN SOURCE: the passkey-page approver is accepted only with the retained v3 owner proof; an in-process software-passkey approval verifies as the installer verifies. NOT RUN with a real authenticator or on an installed node |
| The release floor is checked only by the unit's pre-start and by `node.py`, never by `scripts/launch-dsh.py`, so the harness user can run the launcher by hand against an older release tree still on disk | CONFIRMED in source | FIXED IN SOURCE and booted on the rehearsal node: the launcher runs the protected floor check before spawning. A by-hand old-release launch was NOT RUN |
| The composition hook skips plugin-set verification when `gate-config.json`, in a state root the harness user owns, says `waived` | CONFIRMED in source | FIXED IN SOURCE: a root-protected installed release refuses `waived`. The first build of this fix failed to boot on the rehearsal node (missing import its tests had injected); fixed, with a test that calls the real readers |
| Passkey counters: 0 then 0 is accepted | CONFIRMED; that is how WebAuthn treats authenticators that keep no counter (synced passkeys) | Wording corrected |
| `ui-probe --expect-unbound` refuses only the apps; session create/list and upload refusals were seen by hand, not checked by acceptance or recorded in evidence | CONFIRMED | FIXED and RAN on the rehearsal node: unbound acceptance proves the five boot reads answer and session create, list and upload are refused with `browser-node:binding-required`; bound acceptance proves the same calls pass, sent in the gateway's real `client-request` envelope (the first version used the wrong shape and was caught on the node) |
| Acceptance read "unbound" from the binding directory, which the binding service creates before any binding | CONFIRMED at `d5998c0` | FIXED on local main: acceptance reads `local-control.json` |
| CI: UNPERFORMED rows pass the checks job, so a green run does not include the harness-dependent browser tests; `docs/CI.md` says otherwise | CONFIRMED | FIXED: `docs/CI.md` describes the workflow as it is |
| STATUS, CLAIMS and THREAT-MODEL disagree on whether the rewritten pilot switch ran live; no signed switch export is in the tree | CONFIRMED (documents) | FIXED: all three now say operator-reported, no signed export retained |
| The memory row cites a readability fixture; the Aura log is rewritten by copy and rename under a lock that can be taken after 30 s | CONFIRMED | FIXED (documents): the row names which file is O_APPEND and which is rewritten, and that same-user replacement is not prevented |
| Three `assert-script` jobs count as PASS on exit 0 with no assertion count | CONFIRMED | OPEN |

Rehearsal at the integrated revision of this commit, RAN on the rehearsal node
with a stand-in approval and a throwaway identity: unbound acceptance passed
(first screen and boot reads served; apps, session create/list and upload
refused), the scripted binding passed all nine steps, and bound acceptance
passed without a restart: binding custody, the same memory subject, Kira
reported active by the Aura snapshot, session RPCs and apps answering, repeat
binding refused, and Aura heads matching the independent ledgers after a Kira
note. Before this, the bound check looked for a Kira log line that never
reaches any output: plugin `ctx.logger` lines are only buffered in memory
because no console exporter is mounted (`vendor/cordis/src/logger.ts`), so the
check could not pass on any node. Memory readiness is now read from the
snapshot instead. Not run: a real owner, a real authenticator, a model reply.
