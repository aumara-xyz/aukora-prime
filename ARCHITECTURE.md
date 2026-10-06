# How AUKORA fits together

**Repository map:** `plugins/` + `apps/aukora-desktop/` — pilot runtime and owner client.
`packages/boundary-gate/` — separate authority; [20-file review map](SECURITY-BOUNDARY.md).
`packages/{authority,memory,execution,inference,runtime-bridge,ui,ops}/` + `harness/` — NEXT source.
`evidence/current.json` + `docs/` — current claims, public receipts and archived history.
`scripts/` — check/operator index; `plan/` — directions; `labs/` — NOT LIVE; [research/](research/README.md) — separate research reports.

*Start here if you are reading the repository rather than running it.* The component table describes the selected source account in [evidence/current.json](evidence/current.json). Current factual claim rows are generated in [CLAIMS](docs/CLAIMS.md). The component status rows below are generated from the same canonical data as the README and Security Boundary. **REPORTED** means a supplied operator observation with its timestamp; **SOURCE** means present code, and **NOT YET** means a missing qualification. A linked test is a review entry point, not a new result from this refresh.
[docs/CLAIMS.md](docs/CLAIMS.md) is the claim-by-claim account; the [README](README.md) carries current status; history is archived.

The repository holds two layers. Keep them apart while reading:

1. **The organism (operator-reported on one Linux pilot).** A Genesis agent runtime ("Auma") whose plugins are admitted only as an
   owner-approved set, whose one-shot bash route uses an NVIDIA OpenShell sandbox, and whose governed theme/plugin-set changes go
   through proposals to a boundary gate that only the owner can approve, from a desktop app on the owner's Mac.
2. **Prime NEXT packages (SOURCE).** `packages/authority`, `memory`, `execution`, `inference`, `runtime-bridge`,
   `contracts`, `ui`, `ops`: a stricter authority path under construction. `./prime verify` runs their 66-job source
   profile. They are not what runs on the pilot. See [docs/PRIME-NEXT-ARCHITECTURE.md](docs/PRIME-NEXT-ARCHITECTURE.md).

## Revision and observation identity

<!-- BEGIN GENERATED current-revisions -->
| Identity | Revision / observation | Meaning |
| --- | --- | --- |
| Source account | `9815c56e985bca2198342e78344e97a81e19597a` | Base reviewed for this documentation snapshot; the review command emits the received HEAD and dirty state. |
| Public main observed | `9815c56e985bca2198342e78344e97a81e19597a`, 2026-10-06T10:12:31Z (r4-candidate-3 labs tip after D/H/E/F/M integration; SOURCE, ahead of the frozen main and the deployment) | Read/fetch observation, not a deployment proof; main may advance. |
| Pilot deployment | `3673b98a3e090d122ed0853386ff60913287c3a8`, 2026-10-06T10:12:31Z · **REPORTED** | Live release 3673b98 is Peter-reported; the installed gate remains the old package 4c24fd0. No normal admitted shell or accepted bound workspace. Later source commits and observer success do not establish admission, containment closure or whole-product acceptance. |
| Tested revision | Per-check HEAD and file digests from `./security-review` | No current test result is inferred from a commit message or this table. Historical results stay in [evidence history](docs/EVIDENCE-HISTORY.md). |
<!-- END GENERATED current-revisions -->

## The organism on one page

```
 owner's Mac                                   Linux pilot (one host, separate Linux users)
 ───────────                                   ────────────────────────────────────────────────────────────────
 AUKORA desktop app  ── SSH tunnel ──►  Genesis runtime "Auma"  (user aukora-host, loopback :18735)
 (apps/aukora-desktop)                    │  plugins admitted by the composition gate (owner-approved plugin set)
   owner card:                            │  every tool call judged by the action gate
   gate facts first,                      │  bash ──► sbx-exec (root wrapper, one sudo rule) ──► OpenShell sandbox
   model text fenced,                     │                                                    (user auma, /sandbox)
   one-click Approve                      │  proposes changes (cannot approve)
        ▲                                 ▼
        └──── owner.sock ◄──── BOUNDARY GATE (user aukora-gate) ◄──── propose.sock
                               signed hash-chained ledger · owner-only targets · signed receipts
                               signs plugin-set approvals ─► /etc/aukora-approvals (root) ─► launcher
                                                                    release floor ─┘   (systemd ExecStartPre)
```

## Components

<!-- BEGIN GENERATED current-components -->
| Component | Role and code | Existing check / observation | Status / evidence timestamp | Limit |
| --- | --- | --- | --- | --- |
| Genesis runtime | Pinned DSH/Cordis host and compiled harness; recorded launcher binds 8389 artifacts to six exact patches; [launcher](scripts/launch-dsh.py); [materializer](scripts/materialize-aukora-release.py) | [existing release check](tests/aukora-plugin-set-trusted-verifier.test.mjs) | **REPORTED** · Peter reports live release 3673b98; old gate package 4c24fd0. No runtime readback ran in this docs task; OPERATOR_REPORT / LIVE; evidence at 2026-10-05T12:41:00Z | Live release 3673b98 is Peter-reported; the installed gate remains the old package 4c24fd0. No normal admitted shell or accepted bound workspace. Later source commits and observer success do not establish admission, containment closure or whole-product acceptance. |
| Composition gate | Records/adopts the owner-approved plugin set bound to the release and record; [set admission](plugins/aukora-composition-gate/src/plugin-set.mjs) | [existing signer check](tests/aukora-plugin-set-gate-signer.test.mjs) | **REPORTED** · Historical 3ac3509 PACKAGE_VERIFIED/floor readback is retained; Peter now reports live 3673b98 with old gate package 4c24fd0; OPERATOR_REPORT / LIVE; evidence at 2026-10-05T12:41:00Z | No current bootstrap, floor or package readback ran here. Historical signer epoch/ledger sequence is not a current installed claim; rollback still needs fresh owner approval. |
| Boundary gate | Separate proposal/owner channels, exact-byte review and signed event ledger; [gate](packages/boundary-gate/src/gate.mjs); [ledger](packages/boundary-gate/src/ledger.mjs) | [existing gate fixture](packages/boundary-gate/checks/gate.mjs) | **REPORTED** · Peter reports the installed gate remains the old package 4c24fd0; separate channel/exact-byte review mechanism exists in source; OPERATOR_REPORT / LIVE; evidence at 2026-10-05T12:41:00Z | Live runtime 3673b98 does not imply gate-package parity. This docs task did not verify installed bytes, human attendance, native owner-key enrollment or hardware custody. |
| Signed launch and v2 floor | Pre-Node custody check; signer epoch/ledger sequence floor; fresh approval for rollback; [bootstrap](packages/boundary-gate/host/install/gate-bootstrap.py); [signed floor](packages/boundary-gate/src/release-floor.mjs) | [source/runbook](packages/boundary-gate/host/install/README.md); [existing check](tests/aukora-plugin-set-trusted-verifier.test.mjs) | **REPORTED** · Historical 3ac3509 PACKAGE_VERIFIED/floor readback is retained; Peter now reports live 3673b98 with old gate package 4c24fd0; OPERATOR_REPORT / LIVE; evidence at 2026-10-05T12:41:00Z | No current bootstrap, floor or package readback ran here. Historical signer epoch/ledger sequence is not a current installed claim; rollback still needs fresh owner approval. |
| Boundary self-check | Before-start check and 15-minute timer; failure refuses/stops the configured runtime; [self-check](packages/boundary-gate/bin/selfcheck.mjs); [timer](packages/boundary-gate/host/systemd/aukora-selfcheck.timer) | [existing stubbed check](packages/boundary-gate/checks/selfcheck-bin.mjs) | **REPORTED** · Production self-check/timer account plus disposable transient start-gate proof: forced failure blocked the unit main process; OPERATOR_REPORT / HISTORICAL; evidence at 2026-10-04T11:39:37Z | The transient proof establishes before-start failure handling, not a live sabotage or continuous gate-service loss dependency. The reported BindsTo/RemainAfterExit unit change is pending; source/RPC stubs do not establish current egress policy. |
| Action gate | Routes tool requests through configured guard/policy before effects; [action entry](plugins/aukora-action-gate/lib/index.mjs); [policy](plugins/aukora-action-gate/lib/policy.mjs) | [existing source check](plugins/aukora-action-gate/check.mjs) | **REPORTED** · Peter reports live release 3673b98; old gate package 4c24fd0. No runtime readback ran in this docs task; OPERATOR_REPORT / LIVE; evidence at 2026-10-05T12:41:00Z | Mounted pilot route is recorded; host file fences and a source guard do not establish complete mediation or containment. |
| OpenShell confinement | Normal shell admission and bound workspace remain unaccepted; retained confinement source and historical host-local deny; [adapter](plugins/aukora-openshell-confinement/lib/index.mjs); [wrapper](packages/boundary-gate/host/sbx-exec); [host-local policy](host/auma-local-deny/README.md) | [separate live command scope](scripts/audit/containment/README.md) | **REPORTED** · Peter status report: live 3673b98, no normal admitted shell, no accepted bound workspace. Earlier bound guest 33 DENIED / 0 ALLOWED was ADMISSION-BYPASSED; host-as-auma 40 DENIED / 7 ALLOWED. Kimi later reports observer pass, with admission blockers remaining.; OPERATOR_REPORT / UNQUALIFIED; evidence at 2026-10-05T12:41:00Z | ADMISSION-BYPASSED guest results do not qualify the normal route. Observer pass does not clear admission or the host allowed routes. Historical inherited-descriptor finding remains retained; no live check ran in this docs task. |
| Desktop owner card | Gate-decided labels and plain action line, trusted facts first, model text fenced last, one-click approval; [card](apps/aukora-desktop/aumlok-approval.html); [adapter](apps/aukora-desktop/aumlok-signer-airlock.mjs) | [clarity check](tests/aukora-owner-card-clarity.test.mjs); [no-friction check](tests/aukora-owner-card-no-friction.test.mjs) | **REPORTED** · Supplied card/gate installation report; native app patched and relaunched with bridge polling; OPERATOR_REPORT / HISTORICAL; evidence at 2026-10-04T08:50:33Z | Recorded card installation plus source presence does not measure comprehension or attendance, prove native owner-root enrollment, or attest the current rendered window in this docs task. |
| Aumlok / native owner root | Identity/approval source; native owner-root custody and enrollment remain unqualified; [identity](plugins/aukora-aumlok/README.md); [owner-key source](packages/owner-key/README.md) | [historical source fixture](tests/aukora-airlock.test.mjs) | **NOT YET** · No selected public acceptance receipt; UNQUALIFIED / UNQUALIFIED | Owner enrollment is the owner’s action. A passkey with user verification proves a real authenticator, not hardware custody, who the human is or informed consent. |
| Kira | Mounted remembered/signed note and recall source; [memory source](plugins/aukora-kira/README.md) | [recall source check](tests/aukora-kira-ask-recall.test.mjs) | **REPORTED** · Peter reports live release 3673b98; old gate package 4c24fd0. No runtime readback ran in this docs task; OPERATOR_REPORT / LIVE; evidence at 2026-10-05T12:41:00Z | Pilot memory is recorded, not an owner-approved NEXT save. Replacement collector and genuine per-note Aura association remain pending. |
| Aura observation/court lane | Composition-log adapters and independent-process court interfaces; [Aura source](scripts/aura/README.md); [retained court](vendor/append-only/replicas/README.md) | [existing witness check](tests/aukora-witness-commits.test.mjs) | **SOURCE** · Retained composition-log/court source and separate historical witness checks; SOURCE_RECORD / SOURCE | SOURCE lane with separate historical runs; this is not the installed INTERIM gate collector or an independent current witness. |
| Aura gate collector / Nostr records | Installed INTERIM signed-ledger collection and cold verification through 153; [INTERIM install](host/aura-interim/README.md); [cold verification source](scripts/aura/verify-collected.mjs) | [installed verifier source](host/aura-interim/verify.mjs); [separate source check](scripts/aura/checks/collector.mjs) | **REPORTED** · Supplied e337397 collector cold-verification result; OPERATOR_REPORT / HISTORICAL; evidence at 2026-10-04T10:44:52Z | INTERIM pilot-generated owner/controller keys are not enrolled native owner custody. Root-recorded anchors are not an independent witness. The replacement collector and actual per-note Kira/Aura association remain separate pending acceptance. |
| PQ hybrid experiments | Pinned hybrid signature/KEM lab; grants no authority; [NOT LIVE lab](labs/pq-hybrid/README.md) | [existing lab check](labs/pq-hybrid/checks/hybrid.mjs) | **SOURCE** · Standalone lab on pinned Noble dependencies; SOURCE_RECORD / SOURCE | NOT LIVE; grants no authority and does not qualify a deployed identity/receipt migration. |
<!-- END GENERATED current-components -->

## Three flows, end to end

1. **Auma changes something she may only propose (her theme).** Auma calls `aukora_gate_propose` → the gate validates
   the exact bytes against the target schema and base hash and records `propose` → the owner's app receives the
   pending question over `owner.sock` → the card shows the gate-computed from→to, then the model's note fenced →
   one click → `review` + `decide_review` → the gate writes the bytes from its own version store, signs a receipt,
   appends `decide` and `apply`. Auma's own socket has no approve operation (`packages/boundary-gate/src/gate.mjs`).
2. **A new release goes live.** Materialize → root `gate-bootstrap approval raise` (owner channel only; agents cannot raise
   it) → the card states whether the plugin set is unchanged since the previous approval → one click → `gate-bootstrap approval install`
   writes the gate-signed approval into a root-owned approval root and moves the release floor → `release.env` →
   restart: `gate-bootstrap check-package`, self-check, `gate-bootstrap floor check`, launcher, composition gate
   admission. Bootstrap source/runbook: [host/install](packages/boundary-gate/host/install/README.md).
3. **Auma runs a command.** The action gate judges the call → the OpenShell adapter accepts only one-shot
   `workspace-write` bash in `/sandbox` → `sbx-exec` runs it in the sandbox as `auma` → output returns. Paths under
   the gate's and approvals' directories are refused before bash runs.

## Not mounted, fixtures, history

Present in the tree but not part of the live organism (see [lab index](labs/README.md)): `plugins/aukora-gate-demo` (a one-file fixture for the
composition gate's governed-grant lane), `plugins/aukora-box`, `plugins/aukora-organism`,
`plugins/aukora-subscription-hands`, `plugins/aukora-nostr` (a library, used by the collector),
`labs/deepseek-harness-boundary` (the lab the boundary gate was distilled from), `labs/laya-screen`.
Historical reports live in `docs/` with their dates; [ARCHIVE.md](ARCHIVE.md) lists retired material.

## What this does not claim

Not containment of a hostile agent on the Mac, not independent verification (all verifiers are this project's code),
not that only approved code runs (bare dependencies, the gate bootstrap and workers are outside the plugin set), and
not human attendance or comprehension at an approval. [docs/CLAIMS.md](docs/CLAIMS.md#not-claimed) names each.

For review, follow [README](README.md) → [SECURITY-BOUNDARY.md](SECURITY-BOUNDARY.md) → this architecture → [verification scope](README.md#check-it-yourself) → [paper](docs/AUKORA-GOLDEN-BOUNDARY.md) → [separate research](research/README.md). The [retained containment baseline and host follow-up](README.md#containment-baseline) remain distinct from the offline verifier; full containment is unqualified.
