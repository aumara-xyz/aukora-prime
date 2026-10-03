# Boundary gate: harness-to-agent boundary (from the Genesis SKUNKWORKS lab)

The agent ("Auma") gets its hands only inside an NVIDIA OpenShell sandbox owned by a separate Linux user,
and the harness that runs the model cannot change the system except by proposing to a gate run by a
third Linux user. This package distills that lab into Prime's layout. It is unmounted: nothing in
`./prime boot` or the 66-job source profile starts it.

Source: `aumara-xyz/aukora-genesis`, `labs/deepseek-harness-boundary` at lab tip `6fa70cd`
(`labs/gate-hardening-r3`). Upstream DeepSeek Harness is MIT and is not vendored here.

| Part | Where | Status in Prime |
| --- | --- | --- |
| UID separation, single sudo rule, OpenShell 0.1.2 on rootless Podman | `host/`, `host/SETUP.md` | SOURCE-ONLY; lab run CLAIMED |
| Harness-side sandbox runner, egress probe, fail-closed self-check | `src/layout.mjs`, `src/sandbox.mjs`, `src/selfcheck.mjs` | SOURCE-ONLY, covered by `checks/` |
| Owner-only approval gate: split PROPOSE/OWNER sockets, signed hash-chained ledger, single-use approval, signed receipts with HMAC approval evidence, crash reconciliation | `src/gate.mjs`, `src/ledger.mjs`, `src/secrets.mjs`, `src/server.mjs`, `bin/` | SOURCE-ONLY, covered by `checks/` |
| Round-3 hardening: owner page with all warnings, swatch and AFTER APPLY line, two-step typed approve, 12 h rotating bearer, global rate limits, note sanitising and lookalike/spoof/pressure warnings | `src/card.mjs`, `src/owner-page.mjs` | SOURCE-ONLY, covered by `checks/`; lab headless-browser runs CLAIMED |

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
rejected result. The production entry allowlists nothing until a reviewed declarative target registry is
wired in (`src/wiring.mjs`); until then every proposal is refused.

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
