# Ordinary keyless verification

G owns this source runner. H owns the root `./prime verify` hook and its separation
from D snapshot verification. Existing ops archive `verify` remains unchanged.
The reviewable standalone API is:

```sh
node packages/ops/verify-fast.mjs --root /physical/prime/source --evidence-dir /physical/private/parent/new-run
node packages/ops/verify-fast.mjs --root /physical/prime/source --evidence-dir /physical/private/parent/new-run --json true
```

Use the approved pinned Node 24.11.1. Children use this process's exact executable;
no Node is selected through inherited PATH. A recorded executable hash is an
observation, not independently retained byte approval. The outer trusted launcher
owns that approval. Python-dependent metadata checks use only existing system
`/usr/bin/python3` >=3.9 and its standard library. Nothing installs dependencies.

The source root is explicit and physical. The evidence directory must be a new
canonical absolute path outside that source, under an existing owned parent without
group or other write permission.
H can create a new mode0700 temporary parent and pass a new child path. No directory
discovery, state symlink, candidate callback, command, selector, environment override,
glob or package-manager script is accepted from CLI input.

The importable entry is `runFastVerify({root, evidenceDir, json?, signal?})` from
`runner.mjs`; `json` is a boolean and `signal` is an `AbortSignal`. H can preserve the
returned `exit_code` in its root dispatch. No root hook agreement is inferred from
this standalone implementation.

| Configured ordinary property | Compiled check | Dependency |
| --- | --- | --- |
| Frozen contracts | `packages/contracts/check.mjs`, without optional mutation copies | Node built-ins; separately pinned golden JSON |
| Original memory bytes/IDs | Only the named positive historical byte-forms test in `packages/memory/test/codecs-hardening.test.mjs` | Node; no PG/store/authority |
| Mock inference accounting | The one mock test in `packages/inference/check.mjs` | Node SQLite, synthetic fixture credentials/owned child; zero external requests |
| Static UI boundaries | `packages/ui/scripts/check-static.mjs` | Local copied native assets and pinned baseline manifest |
| Owner presentation | `packages/ui/scripts/check-transport.mjs` | Injected local transport/authenticator fixtures; no real passkey |
| Release metadata | `packages/ops/check-digest-controls.mjs` | Node and Python stdlib; owned disposable files |
| Authority review TTL renewal | UNPERFORMED until H relays the safe short C entrypoint | Full C/admission/guard suites excluded |
| Ordinary executor binding | UNPERFORMED until H relays the approved exact selector | No held OpenShell or guest fixture |

Literal check-source SHA256 pins were read from clean H checkpoint
`795f32337dd27848eaf85952b70ab86a27c54b24`; the ops metadata check pin comes from G
`4b2a1be915fc6e06ce01109216fdea22a85d003b`. Missing or changed check files report
UNPERFORMED and are never repinned from the candidate at launch. Golden contract
and UI baseline inputs have independent literal pins too. Component implementations
are tested by those fixed assertions; the profile never trusts candidate JSON PASS
fields. Completed assertion failures are FAIL. TAP checks require a nonzero completed
test count and their exact selected title; skipped-only or unknown selection cannot
pass. These reviewed source assertions establish no independent OS boundary.

| Exit | Meaning |
| --- | --- |
| 0 | Every configured ordinary check completed PASS |
| 1 | At least one completed assertion check failed, or invocation was invalid |
| 2 | No completed assertion failure, but a prerequisite/check/termination is UNPERFORMED |

Separate scope exclusions and historical records never count as current PASS and do
not by themselves change the ordinary suite's exit. The two missing configured C/F
checks currently cause exit2 even if all six available checks pass.

The target is approximately three minutes on an ordinary laptop. Per-case execution
is capped at15 seconds, with20 seconds for the one reviewed inference case; the suite
uses a cooperative150-second budget and stops subsequent cases after timeout,
cancellation, output overflow or uncertain completion. This is no hard whole-host
deadline or descendant-confinement claim. Signals target only the runner's own direct
spawn. Descendant cleanup remains UNPERFORMED; no unrelated PID or process group is
killed. Setup, hashing and cleanup also consume the budget.

Each case receives new private HOME/TMPDIR and an explicit scrubbed environment.
The direct Node child has a compiled512MiB heap limit; native memory and descendants
have no independently enforced resource boundary in this source profile.
Provider keys, PG variables, DSH-entry overrides, user Node options and shell startup
files are not inherited. Child output is bounded and retained only long enough for
the fixed result protocol; raw stdout/stderr, exception stacks and environment data
never enter displayed results or evidence. Known statuses/reasons, counts and code
identity are recorded instead.

The evidence parent and new directory identities are retained and rechecked around
scratch creation, execution and summary writes. A changed/aliased pathname refuses
as `EVIDENCE_CHANGED`; it is never repaired or followed into an alternate directory.
These Node pathname checks narrow rebinding mistakes but are not atomic dirfd
confinement against concurrent same-UID mutation. Protected separate ownership and
actual OS enforcement remain outside this ordinary source profile.

Historical PG/UID entries are OWNER_RELAY_ONLY records received from H. Receipt files
and hashes have not been supplied to G, so they remain null and independently verified
historical evidence is unavailable. PG storage was reported with a toy authority;
parent/UID creation was reported separately. Neither establishes the current C/D join,
current ACLs or whole-product acceptance. The runner opens no live database, worker,
service, preview or historical store, and never reruns those checks.

Owner ceremony, current PG/cross-UID/guest enforcement, paid inference and composed
pixels stay UNPERFORMED. G1 stays PENDING with its unchanged three probes and evaluator
rules. The long265-save authority fixture belongs to separately owned extended work;
this runner has no extended/audit/activation option.

`node packages/ops/fast-verify/engine-check.mjs` exercises orchestration using one
private disposable copy of the engine and a tiny closed fixture manifest. That copy
cannot configure the production runner and its outcomes never qualify Prime.
