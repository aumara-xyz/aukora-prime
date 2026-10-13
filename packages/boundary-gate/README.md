# Boundary gate: harness-to-agent boundary (from the Genesis SKUNKWORKS lab)

The agent ("Auma") gets its hands only inside an NVIDIA OpenShell sandbox owned by a separate Linux user,
and the harness that runs the model cannot change the system except by proposing to a gate run by a
third Linux user. This package distills that lab into Prime's layout. Prime's `./prime boot` and the 66-job source profile do not
start it; on the Linux pilot it runs as systemd services (`host/systemd/`) and is the boundary of the live organism
(see [ARCHITECTURE.md](../../ARCHITECTURE.md)).

Source: `aumara-xyz/aukora-genesis`, `labs/deepseek-harness-boundary` at lab tip `6fa70cd`
(`labs/gate-hardening-r3`). Upstream DeepSeek Harness is MIT and is not vendored here.

| Part | Where | Status in Prime |
| --- | --- | --- |
| UID separation, single sudo rule, OpenShell 0.1.2 on rootless Podman | `host/`, `host/SETUP.md` | SOURCE-ONLY; a scoped live probe RAN on the lab box (commit `ad76485`); long-running lab operation CLAIMED |
| Harness-side sandbox runner, egress probe, fail-closed self-check | `src/layout.mjs`, `src/sandbox.mjs`, `src/selfcheck.mjs`, `bin/selfcheck.mjs` | self-check DEPLOYED on the pilot as `ExecStartPre` + 15-min timer (`host/systemd/`), covered by `checks/` |
| Owner-only approval gate: split PROPOSE/OWNER sockets, signed hash-chained ledger, single-use approval, signed receipts with HMAC approval evidence, crash reconciliation | `src/gate.mjs`, `src/ledger.mjs`, `src/secrets.mjs`, `src/server.mjs`, `bin/` | RAN on the pilot (systemd `aukora-boundary-gate`), covered by `checks/` |
| Boundary: declarative allowlist (Auma's theme; the operator-only plugin-set approval), symlink-refusing atomic target store, revert as an owner-approved proposal, receipt verification against key and ledger, propose-only harness client and self-check gate probes | `src/targets.mjs`, `src/fs-store.mjs`, `src/receipts.mjs`, `src/gate-client.mjs`, `src/wiring.mjs` | SOURCE-ONLY, covered by `checks/`; one cross-UID scratch run RAN on the lab box (see commit) |
| Round-3 hardening: owner page with all warnings, swatch and AFTER APPLY line, two-step typed approve, 12 h rotating bearer, global rate limits, note sanitising and lookalike/spoof/pressure warnings | `src/card.mjs`, `src/owner-page.mjs` | SOURCE-ONLY, covered by `checks/`; lab headless-browser runs CLAIMED |
| Red-team regression corpus: round-3 attacks (815) and benign controls (61) replayed through the real allowlist, store, gate and owner page | `fixtures/redteam/`, `checks/redteam.mjs` | SOURCE-ONLY plus passing checks; the lab's live GLM red-team runs (830+ attacks, 0 approved) are CLAIMED, not re-run here |

## The gate

The gate runs as `aukora-gate` (`bin/gate.mjs serve --home DIR --run DIR`). The harness reaches only the
PROPOSE socket (0660, group `skgate`): it can read targets, propose exact new bytes against a required
base sha256, read the audit log and close (reject/cancel) a pending proposal. It has no approve operation;
an approving `close` is refused and recorded. Approval exists only on the OWNER socket (0600, gate user) and
only as ONE ceremony: `review` (a fresh single-use challenge over the exact base/new, 120 s) then `decide_review`
echoing it. There is no direct `approve` op (the gate refuses to start if one is added). The owner's popup runs
this ceremony through the Mac bridge; `bin/owner-cli.mjs approve` (pilot break-glass) runs the same two steps. The
gate-served owner page is OFF unless `--owner-page` is given (then loopback, 12 h rotating bearer, two-step typed
confirmation, and its approval also runs review -> decide_review). An approval is single use (pending to applying before any write), rechecks
the base hash, writes bytes from the gate's own version store, verifies the result and returns an
Ed25519-signed receipt whose HMAC evidence binds id, base, result and approver. Every event is appended to
a hash-chained, signed SQLite ledger with append-only triggers (`bin/gate.mjs verify`). Rate limits are
global and per target: 1 pending, 3 per 10 minutes, 60 s cooldown after a reject, 10 minute dedupe of a
rejected result.

## The boundary

The allowlist (`src/targets.mjs`) has two targets. The plugin-set approval `plugins/aukora-plugin-set/approval.json`
is operator-only: it is raised on the OWNER socket by `bin/plugin-set-approval.mjs`, never proposable by the agent,
and its approval is the gate-signed admission the runtime launch requires (see `host/systemd/README.md` for the
release switch and the monotonic release floor). The agent's one target is `plugins/auma-theme/theme.json`, accepted only as
the canonical bytes `{"accent": "#RRGGBB"}` (uppercase hex) or `{"accent": "default"}` (at most 256 bytes,
printable ASCII). Target names must be normalized relative paths under `plugins/`; code targets are refused
by construction (the lab's earlier `plugins/user/<name>/index.js` target was removed and is not carried).
The gate's store refuses any symlink component, opens with `O_NOFOLLOW`, writes via an exclusive temp file,
fsync and rename, fsyncs the directory and leaves the file 0640 with the shared group (harness reads, cannot
write). Revert proposes an earlier applied version's exact bytes and needs the same owner approval; it gets
its own `revert-applied` receipt. `src/receipts.mjs` (`bin/gate.mjs verify-receipt`) accepts a receipt only
if its signature and key fingerprint verify, the ledger is intact and the identical receipt is in an apply
entry. The harness side uses `src/gate-client.mjs`, which has no approve function; its `gateProbes` plug
into the self-check as `extraProbes` (owner socket connect, approve op, approving close: all must fail).
The harness reads the theme with `readThemeText`, which falls back to `default` on any non-canonical bytes.

## Red-team regression corpus

`fixtures/redteam/rt3-attacks.json` (815 rows: 808 misleading proposals in 10 attack categories such as lookalike
hex, fake AFTER APPLY or gate badges, owner impersonation and approve spam, plus 7 schema probes) and
`rt3-benign.json` (61 benign controls) come from the lab's round-3 corpus. Each row pins the lab's scratch-replay
result: refused (and why) or pending with the exact result sha256, AFTER APPLY line, warning count and a sha256
of the exact warning text. `checks/redteam.mjs` replays every row through an in-process gate with the real
theme allowlist and filesystem store (only the 3-per-10-minute window is lifted, as in the lab replay) and
asserts, per row, agreement with the lab, plus: 673 pending and 142 refused (89 schema, 53 identical no-op);
every misleading pending card carries at least one warning; the rendered owner page shows the same warnings as
the popup, the AFTER APPLY line and both swatch chips, with Reject first and Approve out of the tab order; an
approving `close` on every real pending id is refused and recorded; nothing is applied, the theme bytes are
unchanged and the ledger verifies. Benign controls all reach the owner, and 7 of 61 carry warnings the design
asks for (6 `#D4AF37` name collisions, 1 `default`).

These checks run in the package check below (`npm run check:boundary-gate` from the repository root). They
are not part of the frozen, sha-pinned 66-job source profile (`packages/ops/fast-verify/manifest.mjs`), whose
runner, CI helper and inventory count are a reviewed contract; adding a job there needs that review.

Known limits carried from the lab: the legacy owner bearer is a link secret (anyone holding it can approve until it
expires); the operator who can become the gate user is trusted by construction; the model's chat text
outside the gate card is not gate-verified. The opt-in passkey path below has source checks only.

## Passkey owner mode: C1 operator runbook

This mode is opt-in per node. It requires an enrolled passkey for effects; the rotating owner bearer permits
card access, never approval by itself. The optional browser join below supplies returning harness sign-in
and a final passkey-signed Aumlok subject binding; the existing app supplies the phrase ceremony.
No real authenticator, HTTPS ingress, LXD or installed service was exercised by these source checks.

For the installed browser-node profile with its app binding already finished,
use the [browser-node operator sequence](../../ops/node-spawn/browser/README.md):

```sh
# Root inside the node; prints only the private owner-hostname enrollment link.
/usr/bin/python3 -I -S -B /opt/aukora-genesis/src/ops/node-spawn/browser/node.py passkey-claim
# Owner opens that link: create credential, then prove possession (two touches).
# Local LXD host, after restarting the approved harness if status reports inactive:
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase passkey
```

This route selects the already-bound app's actual public record and exact owner
hostname as RP ID. Enrollment commits that subject directly, so it does not
select the provisional browser join or require a third final-binding assertion.
It refuses an existing browser join. Before expiry, the same secret claim can
resume the retained ceremony after restart; accepted registration cannot be
replaced and enrollment cannot reopen after success or a cryptographic failure.
Acceptance checks live enrollment/bearer refusal and the installed verifier's
software-key positive/negative controls separately; it never approves as the owner.

The lower-level procedure below is for separately provisioned gate installations.

The host integrator must install/pin the complete import closure before starting this mode. Do not bypass the
bootstrap with an unprotected direct `serve` invocation. Root-held code must include `/opt/aukora-boundary-gate`
and its new `src/owner-passkey-script.mjs`, `/opt/owner-key`, `/opt/authority` (including its preserved
`upstream/` imports), and `/opt/contracts`, from the same reviewed checkout; ancestors and files must be
root-owned and not group/other writable. Node must be exactly 24.11.1. This is a deployment prerequisite, not a
claim that these install paths have been provisioned. Stage the complete packages from one reviewed revision;
preserve upstream/vendor/license files. The passkey generator profile is opt-in:

```sh
/usr/bin/python3 -I -S packages/boundary-gate/host/install/generate-manifest.py \
  --package "$STAGED_GATE" --owner-key "$STAGED_OWNER_KEY" \
  --launcher-checkout "$STAGED_CHECKOUT" --signer-epochs "$STAGED_SIGNER_EPOCHS" \
  --passkey-authority "$STAGED_AUTHORITY" --passkey-contracts "$STAGED_CONTRACTS" \
  --output "$STAGED_MANIFEST"
```

Use the protected staging/install procedure in [host/install/README.md](host/install/README.md), adding complete
authority/contracts packages at the fixed roots above. Require the installed bootstrap's `check-package` to
print `PACKAGE_VERIFIED` before minting a claim or starting the gate. These commands describe the source opt-in;
the host installer and service unit still need the operator's reviewed materialization.

1. Provision fresh C1 gate signer, protected home, targets and release floor through the reviewed installer,
   with separate gate/harness principals and no copied state. Keep the harness stopped until its exact release
   is approved. Supply a fresh 64-hex node identity and a dedicated HTTPS owner origin as operator inputs.
   The RP is exactly that origin's DNS hostname. Keep the gate listener on container loopback; the reviewed
   private proxy must preserve Host/Origin/Fetch Metadata, reject other hosts and prevent external raw-port access.
   Disable query/body logging on owner routes. Never forward the harness launch token to this page.
2. Root reviews `FINAL_BINDING`, the closed public JSON accepted by
   `validatePasskeyEnrollmentBinding()` in `packages/authority/src/passkey-enrollment.mjs`: immutable identity
   (`owner_id`, canonical `subject`, `approval_key_did`, `control_digest`, `authorization_epoch >= 1`),
   `identity_provenance`, HTTPS `passkey_profile`, public `user`, and empty `existing_credential_ids`.
   Provenance fields alone do not verify an Aumlok projection. Without the browser join this subject stays
   fixed at enrollment. With the join it identifies the provisioning ceremony; no effects can be approved
   until a fresh passkey assertion binds the actual app record's subject and root digest to this node.
3. Set absolute protected paths `PINNED_NODE`, `GATE_PUB`, `FINAL_BINDING`, and `CLAIM_OUT`;
   `PASSKEY_SETUP` must be `/etc/aukora-boundary-gate/passkey-setup.json` for the installed bootstrap.
   Set public `NODE_ID` and `OWNER_ORIGIN`. Mint immediately before Peter is ready:

   ```sh
   sudo "$PINNED_NODE" /opt/aukora-boundary-gate/bin/gate.mjs mint-passkey-claim \
     --pub "$GATE_PUB" --binding "$FINAL_BINDING" --node "$NODE_ID" \
     --owner-origin "$OWNER_ORIGIN" --passkey-setup "$PASSKEY_SETUP" --claim-out "$CLAIM_OUT"
   sudo chown root:aukora-gate "$PASSKEY_SETUP"
   sudo chmod 0640 "$PASSKEY_SETUP"
   ```

   Both output files are exclusive creations. The claim is in root-private `CLAIM_OUT` (0600), never stdout;
   deliver it through the private operator route. The browser-node wrapper prints it only in the owner
   page's fragment link, which the page removes before requests; never record it in logs. The claim expires
   after five minutes. Starting enrollment reserves it durably. After gate restart, presenting the same
   secret claim before expiry resumes the same retained stage and ID, without a second registration once
   registration is accepted. Direct enrollment IDs cannot resume without that claim. Success or a
   cryptographic failure closes enrollment permanently. There is no expiry reset/recovery command here.
   Do not delete the database, replace setup, reset the floor or copy another node.
4. Configure the protected gate service with its existing `serve` arguments plus
   `--passkey-setup /etc/aukora-boundary-gate/passkey-setup.json`; omit `--owner-page`. Its entry is
   `/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap serve`, with the fixed home/run/target
   paths and reviewed GID in [host/install/README.md](host/install/README.md). Peter opens
   `OWNER_ORIGIN/owner/enroll`, enters the claim and performs credential creation and the possession assertion
   himself. Verify the enrolled ledger/state and refusal of a second claim/registration/finish attempt.
5. Deliver the fresh rotating gate bearer privately for `OWNER_ORIGIN/owner/cards?bearer=…`; redact it from
   ingress logs. The static hash-pinned script removes the query from the current history entry. Peter reviews
   the exact retained JSON card and node authorization, then clicks the passkey approval himself. The page has
   no inline script and is unframeable. A cookie alone must produce no effect.
6. On C1, record one harmless effect and its public receipt. Repeat wrong digest/key/node/RP/origin, missing UV,
   expired proof and replay attempts: effect count must stay one. Restart the gate with the same state and replay
   again; verify the ledger and retained receipt cold using installed `gate.mjs verify` and `verify-receipt`.
   Inspect actual loaded code/pins, owner state, private listener reachability and Peter's screen before calling
   the node delivered. These source tests cannot establish any of those observations.

Peter must choose synced versus device-only passkey policy and recovery expectations before qualification.
Current enrollment uses none attestation and permits backup-eligible credentials; a device-only policy still
needs enforcement and real-authenticator qualification, and none attestation does not prove hardware custody.
A passkey approval proves a key on one device signed these exact bytes after that device's local user check;
it does not prove a unique person; synced passkeys leave the device; no real authenticator ran here.

### Returning browser sign-in and final subject binding

Opt in with `--browser-join /etc/aukora-boundary-gate/browser-join.json` beside `--passkey-setup`.
Root writes that protected, non-writable configuration as:

```json
{"version":1,"kind":"aukora-browser-join/v1","app_origin":"https://app.example.invalid","binding_record":"/home/aukora-host/browser-controller/local-control.json"}
```

Use the actual `local-control.json` path configured for the app's browser binding, not a copied projection.
After its first creation, give the gate read access to that exact public file and traverse access to its
parents. Grant no directory listing or default read ACL: the same directory holds `machine-seed-v3.json`.
Preserve the seed's private permissions. The reader refuses aliases,
uses the existing bounded strict JSON reader, and derives the subject with the existing `recordProjection()`.
Stage the complete reviewed `plugins/aukora-aumlok` at `/opt/aukora-aumlok`; add
`--browser-aumlok "$STAGED_AUMLOK"` to `generate-manifest.py` beside the authority/contracts profiles.
The bootstrap verifies that complete root-held inventory before executing the join. Changing either
configuration after selection refuses; removing the join after selection cannot restore provisional approvals.

After enrollment, open `APP_ORIGIN/__aukora/signin` (or `OWNER_ORIGIN/owner/signin`). The gate displays a
60-second statement binding its signer identity, node, owner origin, RP, app audience and durable nonce.
The enrolled passkey assertion uses the same verifier and counter as card approval. Every attempt spends
the nonce, including refused assertions. Success hands the browser a 60-second one-use code in the fixed
app URL fragment; the page removes it from history and the broker exchanges it using its existing claim
store. No enrollment means refusal; the root-minted original claim remains the first-entry route.

Sign in to the app, complete its existing phrase binding, then open `OWNER_ORIGIN/owner/binding`.
Review the exact public subject, root digest and node before signing. The gate retains that statement and
assertion in its protected database and uses the signed subject for subsequent card authorization.
It re-verifies the retained signature and current record on binding-sensitive use, including returning
sign-in after binding and every card approval; changed subject/root, missing record or lost configuration
refuses. The initial bootstrap still requires an independently approved harness release capable of serving
the ceremony; this adapter is not a fresh-node installer or a substitute for initial release approval.

The ingress [runbook](../../ops/node-spawn/ingress/README.md) describes cookie clearing and node-wide
session revocation. Real enrollment, informed review, public TLS, ACL installation, browser rendering,
restarts and separate-user containment remain unperformed. These source checks prove neither identity
uniqueness nor device-only custody, phrase secrecy from the cloud operator, recovery or complete mediation.

Checks (no network, no sudo, no OpenShell needed):

```sh
node --test packages/boundary-gate/checks/*.mjs
```

The sandbox-wrapper check replaces `/usr/bin/openshell` with a local stub and runs the wrapper's real
cleanup script inside a private PID namespace (`unshare --user --map-current-user --pid --fork
--mount-proc`). Where unprivileged user namespaces are unavailable that case is reported as skipped,
not passed. A green check is source evidence only: it does not establish real OpenShell isolation,
network absence, Podman storage quotas or the deployed sudo rule.
