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
- **Passkey proof replay/cross-node/counters held.** Authorization binds the
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
