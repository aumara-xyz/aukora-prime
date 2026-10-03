# Boundary gate: harness-to-agent boundary (from the Genesis SKUNKWORKS lab)

The agent ("Auma") gets its hands only inside an NVIDIA OpenShell sandbox owned by a separate Linux user,
and the harness that runs the model cannot change the system except by proposing to a gate run by a
third Linux user. This package distills that lab into Prime's layout. It is unmounted: nothing in
`./prime boot` or the 66-job source profile starts it.

Source: `aumara-xyz/aukora-genesis`, `labs/deepseek-harness-boundary` at lab tip `6fa70cd`
(`labs/gate-hardening-r3`). Upstream DeepSeek Harness is MIT and is not vendored here.

| Part | Where | Status in Prime |
| --- | --- | --- |
| UID separation, single sudo rule, OpenShell 0.1.2 on rootless Podman | `host/`, `host/SETUP.md` | SOURCE-ONLY; a scoped live probe RAN on the lab box (commit `ad76485`); long-running lab operation CLAIMED |
| Harness-side sandbox runner, egress probe, fail-closed self-check | `src/layout.mjs`, `src/sandbox.mjs`, `src/selfcheck.mjs` | SOURCE-ONLY, covered by `checks/` |
| Owner-only approval gate: split PROPOSE/OWNER sockets, signed hash-chained ledger, single-use approval, signed receipts with HMAC approval evidence, crash reconciliation | `src/gate.mjs`, `src/ledger.mjs`, `src/secrets.mjs`, `src/server.mjs`, `bin/` | SOURCE-ONLY, covered by `checks/` |
| Boundary: theme-only declarative allowlist, symlink-refusing atomic target store, revert as an owner-approved proposal, receipt verification against key and ledger, propose-only harness client and self-check gate probes | `src/targets.mjs`, `src/fs-store.mjs`, `src/receipts.mjs`, `src/gate-client.mjs`, `src/wiring.mjs` | SOURCE-ONLY, covered by `checks/`; one cross-UID scratch run RAN on the lab box (see commit) |
| Round-3 hardening: owner page with all warnings, swatch and AFTER APPLY line, two-step typed approve, 12 h rotating bearer, global rate limits, note sanitising and lookalike/spoof/pressure warnings | `src/card.mjs`, `src/owner-page.mjs` | SOURCE-ONLY, covered by `checks/`; lab headless-browser runs CLAIMED |
| Red-team regression corpus: round-3 attacks (815) and benign controls (61) replayed through the real allowlist, store, gate and owner page | `fixtures/redteam/`, `checks/redteam.mjs` | SOURCE-ONLY plus passing checks; the lab's live GLM red-team runs (830+ attacks, 0 approved) are CLAIMED, not re-run here |

## The gate

The gate runs as `aukora-gate` (`bin/gate.mjs serve --home DIR --run DIR`). The harness reaches only the
PROPOSE socket (0660, group `skgate`): it can read targets, propose exact new bytes against a required
base sha256, read the audit log and close (reject/cancel) a pending proposal. It has no approve operation;
an approving `close` is refused and recorded. Approval exists only on the OWNER socket (0600, gate user)
and on the gate-served owner page (loopback, bearer link rotated on every start and expiring after 12 h,
two-step typed confirmation). An approval is single use (pending to applying before any write), rechecks
the base hash, writes bytes from the gate's own version store, verifies the result and returns an
Ed25519-signed receipt whose HMAC evidence binds id, base, result and approver. Every event is appended to
a hash-chained, signed SQLite ledger with append-only triggers (`bin/gate.mjs verify`). Rate limits are
global and per target: 1 pending, 3 per 10 minutes, 60 s cooldown after a reject, 10 minute dedupe of a
rejected result.

## The boundary

The allowlist (`src/targets.mjs`) has exactly one target: `plugins/auma-theme/theme.json`, accepted only as
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

Known limits carried from the lab: the owner bearer is a link secret (anyone holding it can approve until it
expires); the operator who can become the gate user is trusted by construction; the model's chat text
outside the gate card is not gate-verified; WebAuthn owner assertions are design only.

Checks (no network, no sudo, no OpenShell needed):

```sh
node --test packages/boundary-gate/checks/*.mjs
```

The sandbox-wrapper check replaces `/usr/bin/openshell` with a local stub and runs the wrapper's real
cleanup script inside a private PID namespace (`unshare --user --map-current-user --pid --fork
--mount-proc`). Where unprivileged user namespaces are unavailable that case is reported as skipped,
not passed. A green check is source evidence only: it does not establish real OpenShell isolation,
network absence, Podman storage quotas or the deployed sudo rule.
