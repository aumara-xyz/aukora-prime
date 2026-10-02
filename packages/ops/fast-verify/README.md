# Ordinary keyless verification

H owns the root `./prime verify` dispatch. This source profile retains the original
eight ordinary checks and adds 29 required full owner-memory files. Snapshot
verification remains the separate `./prime verify SNAPSHOT OWNER [HEADS]` interface.
The standalone entry is:

```sh
node packages/ops/verify-fast.mjs --root /physical/prime/source --evidence-dir /physical/private/parent/new-run
```

Use pinned Node 24.11.1. Children use this process's executable with a 512 MiB Node
heap cap and a new private HOME/TMPDIR. The runner scrubs inherited provider keys,
PG variables, Node options and external source overrides. It installs nothing and
requires no DSH checkout, user repository, credentials or live database for the
required source jobs. Literal entry and support SHA256 pins bind the reviewed
assertion files. They are never refreshed from a candidate at launch. The profile
records no Git checkout attestation (`source_review_commit: null`); record the
received revision separately. A changed required entry is UNPERFORMED until its
new bytes are explicitly reviewed and its literal pin updated in source.

The original eight jobs cover contracts, the selected historical-memory byte
vector, mock inference accounting, static UI routes, owner transport presentation,
release metadata, ordinary authority review renewal and ordinary Bash binding.
Their original selection boundaries remain explicit in `manifest.mjs`.

The additional required files run without name filters:

| Group | Required full files |
| --- | --- |
| Bridge | `pilot-capture`, `workflow-store`, `owner-memory-workflow`, `owner-memory-hook`, `owner-memory-host`, `owner-memory-facade`, `owner-recovery`, `owner-logout`, `owner-forget`, `owner-forget-workflow`, `expanded-review-join`, `invocation-forget-join`, `owner-capacity`, `owner-save-retry` and `pre-reservation-unknown` under `packages/runtime-bridge/test/*.test.mjs` |
| B source | `controller`, `approval-action`, `logout`, `forget-review`, `forget-result`, `forget-controller` under `packages/ui/prime-authority/checks/*.mjs`, plus `ordinary-recovery.test.mjs`, `ordinary-hook.test.mjs`, `capture-review.test.mjs` and `expanded-transport.test.mjs` |
| H assembly | `harness/check-owner-memory-client.mjs`, `check-owner-memory-context.mjs`, `check-owner-memory-transport.mjs`, and all six cases in `check-owner-memory-recovery.mjs` |

Required TAP jobs must complete a nonempty plan, the literal required title and
minimum top-level count, zero failures/cancellations/skips/TODOs, and matching
Node summary counters. SKIP or TODO at any nested assertion fails the job even if
another assertion passes. Required JSON assertion scripts must emit a final PASS
summary with a positive assertion/group/case count and no skipped, TODO, failed or
cancelled cases. The runner parses actual child output; caller-provided PASS
objects cannot replace a job. Required jobs cannot configure test-name selectors.
Raw stdout/stderr, stacks and secrets are not retained in evidence.
The pre-reservation-unknown file asserts the existing fail-closed unresolved
fence; its PASS would not establish a known-unsent recovery repair (W1 remains
BLOCKED). The required native hook and recovery checks use their current local
source controller and fixture; missing dependencies fail rather than skip.

| Exit | Meaning |
| --- | --- |
| 0 | Every configured job completed PASS |
| 1 | A completed assertion/protocol failed, including a required skip/TODO |
| 2 | No completed failure, but a prerequisite, source pin or termination is UNPERFORMED |

The mandatory 37-job profile has a cooperative 600-second suite budget. Only
the 20 required full TAP files have 120-second case limits; the other 17 jobs
retain their existing 15/20/30-second limits. At profile preparation, the source
declarations expand to 106 required TAP cases and nine required JSON assertion
files. This source count is not a completed run. Expected full-profile duration
is UNMEASURED and the wall target is null; evidence records actual duration.
These are execution budgets, not a ten-minute completion promise. A timeout,
cancellation, output overflow or uncertain child completion
stops later jobs. Only the runner's own direct child is signalled. This is neither
kernel resource enforcement nor a descendant-cleanup guarantee. Evidence must be
new, private and outside the physical source root; pathname rebinding refuses.
Same-UID source tests establish no independent OS boundary.

Real owner enrollment, actual PostgreSQL, present UID/ACL separation, OpenShell
runtime containment, paid inference and composed browser pixels are explicitly
UNPERFORMED. The separately pinned DSH/React compiled lifecycle/SSR checks and the
costly 265-save authority admission run are also outside this cold source profile.
Historical PG/UID reports remain historical records, never current PASS. G1 stays
PENDING and runtime qualification stays UNPERFORMED even after source PASS.

`node packages/ops/fast-verify/engine-check.mjs` verifies only orchestration using
a disposable engine copy and tiny closed synthetic manifests. Its fixtures test
mixed/nested SKIP/TODO refusal, incomplete counters, selector refusal and structured
summary handling. It does not run the product suites or qualify Prime.
