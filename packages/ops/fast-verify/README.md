# Ordinary keyless verification

H owns the root `./prime verify` dispatch. This source profile retains the original
eight ordinary checks and adds 21 required full owner-memory files. Snapshot
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
| Bridge | `pilot-capture`, `workflow-store`, `owner-memory-workflow`, `owner-memory-hook`, `owner-memory-host`, `owner-memory-facade`, `owner-recovery`, `owner-logout`, `owner-forget`, `owner-forget-workflow` under `packages/runtime-bridge/test/*.test.mjs` |
| B source | `controller`, `approval-action`, `logout`, `forget-review`, `forget-result`, `forget-controller` under `packages/ui/prime-authority/checks/*.mjs`, plus `ordinary-recovery.test.mjs` |
| H assembly | `harness/check-owner-memory-client.mjs`, `check-owner-memory-context.mjs`, `check-owner-memory-transport.mjs`, and all six cases in `check-owner-memory-recovery.mjs` |

Required TAP jobs must complete a nonempty plan, the literal required title and
minimum top-level count, zero failures/cancellations/skips/TODOs, and matching
Node summary counters. SKIP or TODO at any nested assertion fails the job even if
another assertion passes. Required JSON assertion scripts must emit a final PASS
summary with a positive assertion/group/case count and no skipped, TODO, failed or
cancelled cases. The runner parses actual child output; caller-provided PASS
objects cannot replace a job. Required jobs cannot configure test-name selectors.
Raw stdout/stderr, stacks and secrets are not retained in evidence.

| Exit | Meaning |
| --- | --- |
| 0 | Every configured job completed PASS |
| 1 | A completed assertion/protocol failed, including a required skip/TODO |
| 2 | No completed failure, but a prerequisite, source pin or termination is UNPERFORMED |

The cooperative suite budget remains 150 seconds, with a target below three
minutes. Original jobs retain 15/20-second limits; full joined files permit up to
30 seconds. A timeout, cancellation, output overflow or uncertain child completion
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
