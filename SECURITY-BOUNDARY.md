# Security boundary: start with 20 files

The software that proposes an act should not be the authority that permits it.

This is a review entry map for the selected pilot source, not a claim that the complete trusted computing base is 20 files. Imported modules, dependencies, Node/Python, the operating system, deployment permissions and the owner channel also matter. Prime NEXT has a [separate source architecture](docs/PRIME-NEXT-ARCHITECTURE.md); it is not the pilot runtime. [Current claims](docs/CLAIMS.md) distinguish source, operator reports, retained exports and unperformed checks.

| File | Invariant to inspect |
| --- | --- |
| [gate.mjs](packages/boundary-gate/src/gate.mjs) | Proposal is not approval; the reviewed bytes and challenge bind the one-use decision. |
| [server.mjs](packages/boundary-gate/src/server.mjs) | Propose and owner channels have different operations and custody. |
| [targets.mjs](packages/boundary-gate/src/targets.mjs) | Fixed target schema, exact base/change and operator-only release target. |
| [gate-bootstrap.py](packages/boundary-gate/host/install/gate-bootstrap.py) | Root bootstrap verifies the installed package, then runs approval raise/install and the floor check from checked buffers. |
| [ledger.mjs](packages/boundary-gate/src/ledger.mjs) | Signed sequence/hash chain retains decisions and effects. |
| [release-floor CLI](packages/boundary-gate/bin/release-floor.mjs) | Floor tool executes checked buffers from its fixed trusted installation. |
| [operator-data.mjs](packages/boundary-gate/src/vendor/operator-data.mjs) | Closed candidate data helpers supply no candidate code authority. |
| [plugin-set-canon.mjs](packages/boundary-gate/src/plugin-set-canon.mjs) | Trusted verifier reads candidate data; candidate code supplies no verifier authority. |
| [release-floor.mjs](packages/boundary-gate/src/release-floor.mjs) | Previously installed approval constrains launch; ordering uses the signer epoch and signed ledger sequence. |
| [selfcheck.mjs](packages/boundary-gate/bin/selfcheck.mjs) | Failed or unrecorded checks refuse launch; fixture tests stub host observations. |
| [aukora-genesis.service](packages/boundary-gate/host/systemd/aukora-genesis.service) | Service requires self-check, approval and floor checks; a template is not installed-unit evidence. |
| [sbx-exec](packages/boundary-gate/host/sbx-exec) | Sandbox dispatch and cleanup are separate from a model's claims about completion. |
| [plugin-set.mjs](plugins/aukora-composition-gate/src/plugin-set.mjs) | Admission binds the recorded plugin set, release and approval pin. |
| [action-gate index.mjs](plugins/aukora-action-gate/lib/index.mjs) | Tool requests encounter the gate before an effect. |
| [trusted-verifier-pins.json](packages/boundary-gate/src/vendor/trusted-verifier-pins.json) | Reviewed module hashes come from trusted install data, not a candidate. |
| [confinement index.mjs](plugins/aukora-openshell-confinement/lib/index.mjs) | Supported one-shot route is explicit; unsupported routes refuse. |
| [aumlok-bridge.mjs](apps/aukora-desktop/aumlok-bridge.mjs) | Desktop IPC does not manufacture a gate review or owner grant. |
| [aumlok-signer-airlock.mjs](apps/aukora-desktop/aumlok-signer-airlock.mjs) | Adapter carries the gate-bound review and exact decision. |
| [aumlok-approval.html](apps/aukora-desktop/aumlok-approval.html) | Gate facts first, model text fenced last, one-click approval without forced friction. |
| [launch-dsh.py](scripts/launch-dsh.py) | Foreground service launch refuses preview waiver flags. |

## Current recorded boundary state

Generated from [evidence/current.json](evidence/current.json). Timestamps identify supplied observations; SOURCE and INTERIM retain their limits. The live containment result remains FAIL.

<!-- BEGIN GENERATED current-boundary-status -->
| Current boundary claim | Status / evidence timestamp | Limit |
| --- | --- | --- |
| The installed pre-Node gate-bootstrap verifies package custody; the live v2 floor orders approvals by protected signer epoch and verified signed ledger sequence. | **REPORTED** · Installed-package/floor readback at 3ac3509: PACKAGE_VERIFIED; release floor signer epoch 1, signed sequence 207; evidence at 2026-10-04T13:41:10Z | Rollback needs fresh owner approval. Root updater, interpreter, manifest and protected public epoch registry remain trust anchors. Source fixtures do not attest those anchors; replacement Aura profile custody remains separate. |
| Landed card clarity shows gate-decided ROUTINE/CRITICAL, one plain action line and gate facts before fenced model text; approval stays one click without typing/reveal/scroll/dwell. | **REPORTED** · Supplied card/gate installation report; native app patched and relaunched with bridge polling; evidence at 2026-10-04T08:50:33Z | Recorded card installation plus source presence does not measure comprehension or attendance, prove native owner-root enrollment, or attest the current rendered window in this docs task. |
| The installed INTERIM Aura collector ran; cold verification passed through ledger position 153 with an anchor verified. | **REPORTED** · Supplied e337397 collector cold-verification result; evidence at 2026-10-04T10:44:52Z | INTERIM pilot-generated owner/controller keys are not enrolled native owner custody. Root-recorded anchors are not an independent witness. The replacement collector and actual per-note Kira/Aura association remain separate pending acceptance. |
| One-shot bash uses the pilot OpenShell route; the latest supplied containment baseline remains FAIL on guest inherited socket descriptors. | **REPORTED** · Live ./security-review-containment at 3ac3509 with the host-side inherited-descriptor closure (exec_fds.py) installed: guest 34 DENIED / 1 ALLOWED (inherited sockets from the in-guest OpenShell exec path), host-as-auma 35 DENIED / 0 ALLOWED, control 20/20 + 7/7 decoys, observer clean; VERDICT FAIL; evidence at 2026-10-04T13:42:00Z | Full containment remains unqualified until the actual route closes the inherited-descriptor finding and re-verification passes with outside observation/control. File tools still use the host fence; guest-external custody, resource enforcement and complete cleanup remain separate. No live check ran for this refresh. |
| The service runs a fail-closed self-check before start and on a 15-minute timer. | **REPORTED** · Production self-check/timer account plus disposable transient start-gate proof: forced failure blocked the unit main process; evidence at 2026-10-04T11:39:37Z | The transient proof establishes before-start failure handling, not a live sabotage or continuous gate-service loss dependency. The reported BindsTo/RemainAfterExit unit change is pending; source/RPC stubs do not establish current egress policy. |
<!-- END GENERATED current-boundary-status -->

## Run the existing scoped checks

```sh
./security-review --list
./security-review --logs /tmp/aukora-review-private
```

Node 24.11.1 is the selected interpreter. The fixed `offline-critical-v1` profile runs the existing trusted-bootstrap VM fixture (baseline only), trusted-release, gate-signer, owner-card and stubbed self-check tests, the retained L2 signature verifier, face-copy equality and generated-table consistency. It never calls the live self-check CLI, host/sandbox probes, providers, network anchors, a deployment or the complete NEXT profile. Disposable local IPC can be refused by a restricted environment; that child failure remains visible.

JSON stdout includes received SHA, dirty state, boundary-file SHA256s, commands, actual exit/signal/error, timings, output digests and available TAP totals. `--logs` retains unmodified private stdout/stderr/exit files; keep those outside tracked source. Mutation-selector environment variables are cleared and named; the command does not run mutants. Exit `1` means a scoped failure. Exit `2` retains declared UNPERFORMED live acceptance even when all scoped rows pass. `--list` executes no child and reports those rows UNPERFORMED. The full source profile remains `./prime verify` with its own historical failure and exclusions.

The L2 verifier checks a historical signed prefix against the published pilot key. It does not fetch the external anchor, prove the latest tail, attest the deployed host, identify the person or establish hardware custody. Current `evidence/current.json` is the claim source for generated tables, not an authority or a test receipt.

## Open obligations

Collector bootstrap pinning, guest-external per-execution custody, inherited guest descriptors (reported by `./security-review-containment`), full containment/cleanup, hardened owner roots, current NEXT joins and current full-profile execution remain distinct obligations. Concurrent workers' prepared fixes are not marked complete until selected source and actual evidence land. [Known gaps](README.md#known-gaps) and [private vulnerability reporting](SECURITY.md) remain the front door.

Next: [ARCHITECTURE.md](ARCHITECTURE.md) → [verification scope](README.md#check-it-yourself) → [paper](docs/AUKORA-GOLDEN-BOUNDARY.md) → [separate research](research/README.md). The [recorded live containment FAIL and host follow-up](README.md#containment-baseline) are separate from these offline checks.
