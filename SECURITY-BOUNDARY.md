# Security boundary: start with 20 files

The software that proposes an act should not be the authority that permits it.

This is a review entry map for the selected pilot source, not a claim that the complete trusted computing base is 20 files. Imported modules, dependencies, Node/Python, the operating system, deployment permissions and the owner channel also matter. Prime NEXT has a [separate source architecture](docs/PRIME-NEXT-ARCHITECTURE.md); it is not the pilot runtime. [Current claims](docs/CLAIMS.md) distinguish source, operator reports, retained exports and unperformed checks.

| File | Invariant to inspect |
| --- | --- |
| [gate.mjs](packages/boundary-gate/src/gate.mjs) | Proposal is not approval; the reviewed bytes and challenge bind the one-use decision. |
| [server.mjs](packages/boundary-gate/src/server.mjs) | Propose and owner channels have different operations and custody. |
| [targets.mjs](packages/boundary-gate/src/targets.mjs) | Fixed target schema, exact base/change and operator-only release target. |
| [card.mjs](packages/boundary-gate/src/card.mjs) | Gate facts and model text have distinct presentation roles. |
| [ledger.mjs](packages/boundary-gate/src/ledger.mjs) | Signed sequence/hash chain retains decisions and effects. |
| [receipts.mjs](packages/boundary-gate/src/receipts.mjs) | Effect receipt binds the exact change and gate identity. |
| [secrets.mjs](packages/boundary-gate/src/secrets.mjs) | Gate key and owner/propose credential handling remain separate. |
| [plugin-set-canon.mjs](packages/boundary-gate/src/plugin-set-canon.mjs) | Trusted verifier reads candidate data; candidate code supplies no verifier authority. |
| [release-floor.mjs](packages/boundary-gate/src/release-floor.mjs) | Previously installed approval constrains launch; current wall-clock ordering remains a hardening gap. |
| [selfcheck.mjs](packages/boundary-gate/bin/selfcheck.mjs) | Failed or unrecorded checks refuse launch; fixture tests stub host observations. |
| [aukora-genesis.service](packages/boundary-gate/host/systemd/aukora-genesis.service) | Service requires self-check, approval and floor checks; a template is not installed-unit evidence. |
| [sbx-exec](packages/boundary-gate/host/sbx-exec) | Sandbox dispatch and cleanup are separate from a model's claims about completion. |
| [plugin-set.mjs](plugins/aukora-composition-gate/src/plugin-set.mjs) | Admission binds the recorded plugin set, release and approval pin. |
| [action-gate index.mjs](plugins/aukora-action-gate/lib/index.mjs) | Tool requests encounter the gate before an effect. |
| [action-gate policy.mjs](plugins/aukora-action-gate/lib/policy.mjs) | Model explanations do not widen policy. |
| [confinement index.mjs](plugins/aukora-openshell-confinement/lib/index.mjs) | Supported one-shot route is explicit; unsupported routes refuse. |
| [aumlok-bridge.mjs](apps/aukora-desktop/aumlok-bridge.mjs) | Desktop IPC does not manufacture a gate review or owner grant. |
| [aumlok-signer-airlock.mjs](apps/aukora-desktop/aumlok-signer-airlock.mjs) | Adapter carries the gate-bound review and exact decision. |
| [aumlok-approval.html](apps/aukora-desktop/aumlok-approval.html) | Gate facts first, model text fenced last, one-click approval without forced friction. |
| [launch-dsh.py](scripts/launch-dsh.py) | Foreground service launch refuses preview waiver flags. |

## Run the existing scoped checks

```sh
./security-review --list
./security-review --logs /tmp/aukora-review-private
```

Node 24.11.1 is the selected interpreter. The fixed `offline-critical-v1` profile runs existing trusted-release, gate-signer, owner-card and stubbed self-check tests, the retained L2 signature verifier, face-copy equality and generated-table consistency. It never calls the live self-check CLI, host/sandbox probes, providers, network anchors, a deployment or the complete NEXT profile. Disposable local IPC can be refused by a restricted environment; that child failure remains visible.

JSON stdout includes received SHA, dirty state, boundary-file SHA256s, commands, actual exit/signal/error, timings, output digests and available TAP totals. `--logs` retains unmodified private stdout/stderr/exit files; keep those outside tracked source. Mutation-selector environment variables are cleared and named; the command does not run mutants. Exit `1` means a scoped failure. Exit `2` retains declared UNPERFORMED live acceptance even when all scoped rows pass. `--list` executes no child and reports those rows UNPERFORMED. The full source profile remains `./prime verify` with its own historical failure and exclusions.

The L2 verifier checks a historical signed prefix against the published pilot key. It does not fetch the external anchor, prove the latest tail, attest the deployed host, identify the person or establish hardware custody. Current `evidence/current.json` is the claim source for generated tables, not an authority or a test receipt.

## Open obligations

Signed sequence/epoch release ordering, pre-import gate/collector bootstrap pinning, guest-external per-execution custody, full containment/cleanup, hardened owner roots, current NEXT joins and current full-profile execution remain distinct obligations. Concurrent workers' prepared fixes are not marked complete until selected source and actual evidence land. [Known gaps](README.md#known-gaps) and [private vulnerability reporting](SECURITY.md) remain the front door.
