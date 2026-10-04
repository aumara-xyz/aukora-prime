# AUKORA Prime

![AUKORA's intended human-first architecture](docs/assets/aukora-human-first.png)

*Human first. AI next.*

AUKORA aims to become an open personal AI workspace that helps people think, remember, build tools and improve the workspace itself. Models and applications could change while identity, memory, relationships and authority stay with the person. People and their agents could cooperate without handing control to one platform: **the person is the platform**.

**The software that proposes an act should not be the authority that permits it.**

**Reading the code? Start with [SECURITY-BOUNDARY.md](SECURITY-BOUNDARY.md), then [ARCHITECTURE.md](ARCHITECTURE.md):** how the pilot organism (Genesis runtime, boundary gate, OpenShell sandbox, desktop owner app, Aumlok, Kira, Aura) connects, with shared REPORTED / SOURCE / NOT YET status and links to the existing checks.

## Today

One Linux pilot runs the Genesis-derived runtime, the boundary gate and a separate-user OpenShell route; the owner reaches it through the desktop app. The latest deployment revision below is **operator-reported**, not an observation made by this checkout. The [L2 evidence](docs/evidence/l2-demo-2026-10-04/README.md) carries a signed theme-change receipt and ledger prefix that you can verify offline. One-shot bash was reported in the sandbox; full containment and per-execution cleanup remain unqualified, and the live containment test currently fails on inherited guest descriptors.

Prime NEXT is a separate source layer under construction. Its full source profile has a recorded failure; its protected owner/memory/execution/inference joins are not qualified by the pilot. Current source, main, deployment and tested revisions have separate identities.

```sh
./security-review                 # scoped offline checks; JSON, with exclusions
./prime verify                    # complete NEXT source profile; retain failures
sudo ./security-review-containment # live containment check (root, on the pilot only)
```

**Recursion research:** [Ornith / Nebius Lab report and sanitized digest](research/README.md) — separate research evidence, not a deployed AUKORA model or product qualification.

Read [the security boundary](SECURITY-BOUNDARY.md), [component map](ARCHITECTURE.md), [current claims](docs/CLAIMS.md) and [historical evidence](docs/EVIDENCE-HISTORY.md). [Contribute](CONTRIBUTING.md) or [report a vulnerability privately](SECURITY.md).

<!-- BEGIN GENERATED current-revisions -->
| Identity | Revision / observation | Meaning |
| --- | --- | --- |
| Source account | `3ac3509a25fbfd03fd50a670f1fcdfef2aa5470e` | Base reviewed for this documentation snapshot; the review command emits the received HEAD and dirty state. |
| Public main observed | `3ac3509a25fbfd03fd50a670f1fcdfef2aa5470e`, 2026-10-04T13:45:00Z (origin/main fetch; equals the release commit) | Read/fetch observation, not a deployment proof; main may advance. |
| Pilot deployment | `3ac3509a25fbfd03fd50a670f1fcdfef2aa5470e`, 2026-10-04T13:41:12Z · **REPORTED** | Operator observations of one Linux pilot. Later docs-only commits on main do not change the runtime/gate identity. No full-containment or whole-product qualification follows. |
| Tested revision | Per-check HEAD and file digests from `./security-review` | No current test result is inferred from a commit message or this table. Historical results stay in [evidence history](docs/EVIDENCE-HISTORY.md). |
<!-- END GENERATED current-revisions -->

## Check it yourself

Use Node 24.11.1, an existing Python 3.9 or later at `/usr/bin/python3`, and an environment that permits disposable private Unix-domain sockets. Use `umask 0022` in the disposable source-check shell; private fixture state still specifies restrictive modes explicitly. A wrapper that silently changes the child umask can change filesystem-refusal fixtures and must be recorded as a different test environment. Restricted sandboxes can reject the IPC fixtures with `EPERM`; retain that failed/blocked result rather than treating it as PASS. Run the command above from the repository root.

The latest reported full-profile run remains **61 PASS / 1 FAIL / 4 UNPERFORMED** at its historical revisions; see the current table and [original account](docs/archive/README-before-audit-surface.md). This cleanup does not rerun or repair that profile. Required success is exit `2`, zero failed jobs and the declared external PostgreSQL arm still UNPERFORMED. That outcome would be source evidence, not whole-product acceptance.

The shorter `./security-review` runs the fixed offline profile described in [SECURITY-BOUNDARY.md](SECURITY-BOUNDARY.md). It prints received HEAD, dirty state, boundary-file digests, every check's actual exit/result and declared unperformed arms as JSON. Use `./security-review --list` to see its commands without executing them; use `--logs /tmp/aukora-review-private` to retain private raw output. Exit `1` means a check failed; exit `2` preserves open live acceptance even if all scoped checks pass. No check is run merely by reading this README.

If repository access is available, a fresh review starts with:

```sh
git clone --branch main https://github.com/aumara-xyz/aukora-prime.git
cd aukora-prime
```

For a standalone sanitized source bundle, use `git clone --branch main aukora-prime-sanitized.bundle aukora-prime`, then run the verification command above. A bundle’s default branch can otherwise differ from its contained `main` ref.

The historical receipt does not attest the received revision. [CI source checks](docs/CI.md) require a separately observed Actions run; adding a workflow is not an execution result. Preserve the revision and complete result you receive, including failures and unavailable checks. The [evidence history](docs/EVIDENCE-HISTORY.md) retains earlier runs and the immutable release receipt. The [profile description](packages/ops/fast-verify/README.md) states scope and exclusions; owner enrollment, provider credentials, a database and an OpenShell guest are not prerequisites for the public source profile.

## Status

### Status glossary

**REPORTED** is an operator account, not independently observed here. **RECORDED** is dated retained evidence. **SOURCE** means code is present, without a current-head test or installed-system claim. **NOT YET / UNPERFORMED** names a missing implementation or check; **PROPOSED** names a direction; **RESEARCH** names a separate retained research report. A review command's **PASS / FAIL** applies only to its exact row and revision. No percentage describes trust.

<!-- BEGIN GENERATED current-claims -->
| Claim | Status / basis | Code or check | Limit |
| --- | --- | --- | --- |
| Separate-user Linux pilot runs the Genesis-derived runtime, action gate and desktop owner route. | **REPORTED** · Operator switch readback: runtime release-3ac3509 (main = runtime = gate = 3ac3509); evidence at 2026-10-04T13:41:12Z | [component map](ARCHITECTURE.md) | One pilot host at the recorded observation; this task did not repeat runtime readback. Later source/main and the docs successor are not automatically the deployed runtime. |
| A theme proposal reached owner review, was approved once and applied with a signed receipt. | **RECORDED** · L2 signed export, 2026-10-04; ledger #1–#24 | [export and verifier](docs/evidence/l2-demo-2026-10-04/README.md) | Signatures and matching bytes are checkable offline. Hot reload is operator-recorded; this export does not establish current ledger completeness, human identity or comprehension. |
| Agent proposal and owner approval use separate gate channels; review binds exact change bytes. | **REPORTED** · Installed gate package verified against the 3ac3509 manifest (PACKAGE_VERIFIED, 77 files); channel/review mechanism is present in that source; evidence at 2026-10-04T13:41:10Z | [gate](packages/boundary-gate/src/gate.mjs); [existing signer check](tests/aukora-plugin-set-gate-signer.test.mjs) | Installed-byte/readback evidence does not prove human attendance, native owner-key enrollment or hardware custody. Synthetic protocol checks retain their limits. |
| The installed pre-Node gate-bootstrap verifies package custody; the live v2 floor orders approvals by protected signer epoch and verified signed ledger sequence. | **REPORTED** · Installed-package/floor readback at 3ac3509: PACKAGE_VERIFIED; release floor signer epoch 1, signed sequence 207; evidence at 2026-10-04T13:41:10Z | [root bootstrap](packages/boundary-gate/host/install/gate-bootstrap.py); [bootstrap trust/limits](packages/boundary-gate/src/vendor/TRUSTED-VERIFIER.md); [existing VM fixture check](packages/boundary-gate/src/vendor/check-trusted-verifier.mjs) | Rollback needs fresh owner approval. Root updater, interpreter, manifest and protected public epoch registry remain trust anchors. Source fixtures do not attest those anchors; replacement Aura profile custody remains separate. |
| Landed card clarity shows gate-decided ROUTINE/CRITICAL, one plain action line and gate facts before fenced model text; approval stays one click without typing/reveal/scroll/dwell. | **REPORTED** · Supplied card/gate installation report; native app patched and relaunched with bridge polling; evidence at 2026-10-04T08:50:33Z | [one-click check](tests/aukora-owner-card-no-friction.test.mjs); [model-fence check](tests/aukora-owner-card-model-fence.test.mjs) | Recorded card installation plus source presence does not measure comprehension or attendance, prove native owner-root enrollment, or attest the current rendered window in this docs task. |
| One-shot bash uses the pilot OpenShell route; the latest supplied containment baseline remains FAIL on guest inherited socket descriptors. | **REPORTED** · Live ./security-review-containment at 3ac3509 with the host-side inherited-descriptor closure (exec_fds.py) installed: guest 34 DENIED / 1 ALLOWED (inherited sockets from the in-guest OpenShell exec path), host-as-auma 35 DENIED / 0 ALLOWED, control 20/20 + 7/7 decoys, observer clean; VERDICT FAIL; evidence at 2026-10-04T13:42:00Z | [scope](plugins/aukora-openshell-confinement/README.md); [wrapper](packages/boundary-gate/host/sbx-exec); [live containment test](security-review-containment); [auma local-service deny](host/auma-local-deny/README.md); [dated findings and disposition](evidence/containment/2026-10-04.md) | Full containment remains unqualified until the actual route closes the inherited-descriptor finding and re-verification passes with outside observation/control. File tools still use the host fence; guest-external custody, resource enforcement and complete cleanup remain separate. No live check ran for this refresh. |
| The service runs a fail-closed self-check before start and on a 15-minute timer. | **REPORTED** · Production self-check/timer account plus disposable transient start-gate proof: forced failure blocked the unit main process; evidence at 2026-10-04T11:39:37Z | [existing stubbed check](packages/boundary-gate/checks/selfcheck-bin.mjs); [units](packages/boundary-gate/host/systemd/README.md) | The transient proof establishes before-start failure handling, not a live sabotage or continuous gate-service loss dependency. The reported BindsTo/RemainAfterExit unit change is pending; source/RPC stubs do not establish current egress policy. |
| The installed INTERIM Aura collector ran; cold verification passed through ledger position 153 with an anchor verified. | **REPORTED** · Supplied e337397 collector cold-verification result; evidence at 2026-10-04T10:44:52Z | [collector scope](scripts/aura/README.md); [interim install](host/aura-interim/README.md) | INTERIM pilot-generated owner/controller keys are not enrolled native owner custody. Root-recorded anchors are not an independent witness. The replacement collector and actual per-note Kira/Aura association remain separate pending acceptance. |
| Prime NEXT contains stricter authority, retained-memory, inference, bridge and guardian components. | **SOURCE** · Retained NEXT source and dated connected mock/build records | [NEXT map](docs/PRIME-NEXT-ARCHITECTURE.md); [checkpoint](docs/development/INTEGRATION-CHECKPOINT-2026-10-02.md) | These packages are not the pilot runtime. Native request production, protected joins, genuine provider reply and complete runtime acceptance remain unfinished. |
| The latest reported full NEXT source-profile run had 61 PASS / 1 FAIL / 4 UNPERFORMED. | **RECORDED** · Local 4381ca3 / zipper account retained in historical README | [original account](docs/archive/README-before-audit-surface.md); [immutable history](docs/EVIDENCE-HISTORY.md) | full-owner-recovery failed; PostgreSQL and three unreviewed memory support jobs did not run. This is not current-head execution or GitHub CI evidence. |
| One synthetic-P256-approved save ran through PG 16 with authority UID 995 and memory UID 994; independent authority, memory and DB restarts preserved bytes, citation and receipt. | **RECORDED** · Dated bounded synthetic experiment | [sanitized summary](docs/evidence/bounded-memory-experiment.json) | One older synthetic save, cleaned up; not real owner enrollment, indexing/search or current product qualification. |
| Real owner passkey enrollment, hardened root recovery and hardware custody. | **NOT YET** · No selected public acceptance receipt | [known gaps](README.md#known-gaps) | Owner enrollment is the owner’s action. A passkey with user verification proves a real authenticator, not hardware custody, who the human is or informed consent. |
| Hybrid ML-DSA-65 + Ed25519 signature and hybrid KEM experiments exist. | **SOURCE** · Standalone lab on pinned Noble dependencies | [lab scope](labs/pq-hybrid/README.md) | NOT LIVE; grants no authority and does not qualify a deployed identity/receipt migration. |
| Registered agents, human networking, replaceable providers/apps and broader capability cells. | **PROPOSED** · North Star and field design | [plan](plan/NORTH-STAR.md); [field patterns](plan/FIELD-DISTILL.md) | Research directions; source fixtures and one pilot do not establish a working global platform. |
| Ornith / recursion experiments have a dated public report and sanitized evidence digest. | **RESEARCH** · PR #10 merge 6f9e6f433924800e365c7e400a6c4bdb30bcdc79; report snapshot 2026-10-04 07:45 UTC | [research index](research/README.md); [sanitized digest](research/evidence/NEBIUS-LAB-2026-10-04.json) | Retained report/digest inspection, not complete independent reproduction. No training/GPU evaluation ran in this cleanup; no deployed AUKORA provider or product acceptance follows. |
<!-- END GENERATED current-claims -->

## Containment baseline

<!-- BEGIN GENERATED current-containment -->
**ANY ALLOWED = FAIL; missing enumeration or a detecting control cannot establish PASS.** The supplied operator result at 2026-10-04T13:42:00Z for runtime `3ac3509a25fbfd03fd50a670f1fcdfef2aa5470e` remains **FAIL**: guest **34 DENIED / 1 ALLOWED** (socket descriptors inherited inside the guest from the OpenShell exec path; the host launcher closure 7cfe8d7 is installed; protected-target reach not established); host-as-auma **35 DENIED / 0 ALLOWED** after the host firewall.

The original baseline at 2026-10-04T10:43:00Z had guest **34 DENIED / 1 ALLOWED** and host-as-auma **33 DENIED / 2 ALLOWED**. The observer was unchanged; signed ledger prefix through 153 intact. The disposable control had 20/20 allowed routes, 7/7 decoy changes detected; PROVES DETECTION; that is detection evidence, not containment PASS. Workspace operations were reported working.

See the [three findings and their disposition](evidence/containment/2026-10-04.md), [command scope](scripts/audit/containment/README.md) and [host-firewall scope](host/auma-local-deny/README.md). The inherited-descriptor finding stays OPEN. Required evidence: actual route closes finding plus new outside-observer/control result; no PASS inferred from source landing. This docs task reran no live check; full containment remains unqualified.
<!-- END GENERATED current-containment -->

Review in order: [security boundary](SECURITY-BOUNDARY.md) → [architecture](ARCHITECTURE.md) → [verification scope](#check-it-yourself) → [Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md) → [separate recursion research](research/README.md). Runtime records, offline checks, NEXT source and research have separate scopes.

## Known gaps

- The pinned harness recipe includes the captured-ID Cordis logger disposal fix and the per-read gateway cancellation fix, with exact patch digests and MIT notices. The six-patch recipe is built into the deployed release (operator-reported: the launcher binds 8389 compiled artifacts to 6 exact patches); the earlier four-patch build receipts remain historical.

- The current complete source profile (local run, see above) fails one job, `full-owner-recovery`, with four jobs not run; the earlier six-failure [CI result at `8fda787`](docs/evidence/source-profile-ci-8fda787.json) remains retained. The required checks and counters stay in place.
- An attempted pre-reservation refusal remains unknown until authoritative C/D non-consumption, absence of an intent/effect and writer closure can be established together. No UI callback or missing-effect exception clears that fence. The affected owner-effect runtime stays unavailable.
- The retained-memory source protocol now includes authority preparation, request-bound dispatch and factual settlement. Its authenticated separated-worker phase adapter is not implemented or qualified here. Retained-profile restore refuses until its lineage is established; no stale checkpoint or success flag can replace that evidence.
- Logout, logical forget and verified-receipt recovery have source joins. Current served behavior and the protected owner path still need acceptance. An unknown outcome retains its consumption and replay fence; reconciliation is not permission to repeat an effect. Logical purge does not promise erasure of physical media, WAL or external copies.
- The retained NEXT owner build binds 87 source inputs and 46 generated outputs; the compiled native Cordis/H fixture passed 11 groups. Synthetic owner and read-only reply views were observed separately, as recorded in the [checkpoint](docs/development/INTEGRATION-CHECKPOINT-2026-10-02.md). The prepared `baef862` release predates later E/F increments and is unbooted. Each changed source revision needs its own build/composition/served-byte evidence before an installed-product claim. Models display does not enable credentials or inference.
- The native owner/task/conversation request producer remains missing. Memory projection requires a fresh exact-binding acknowledgement; a stale binding or uncertain outcome cannot create a new approval or effect. The default protected composition remains unmounted.
- Same-UID witness rollback remains a declared limit. Candidate-writable state and its reference cannot establish independent authority. A separate UID also needs authenticated IPC, protected configuration, owner proof and actual target enforcement.
- The owner's real passkey enrollment requires the owner's action and remains unperformed. A real passkey with user verification does not prove hardware custody, human identity, comprehension or freely given attendance. Lost-device revocation, key rotation, owner recovery and challenge-abuse recovery remain hardening work. Source challenge quotas are bounded; they do not complete that account.
- OpenShell execution RAN on the pilot as one-shot commands in the `auma` sandbox (see the status table); the `packages/execution` path below is not that path. Full effective-configuration readback, a durable final-verification fence, conservative timeout/null-exit handling and the mounted factory’s tracked Cordis effect are integrated source. The atomic expected-policy execution fence, external cleanup supervisor, resources and actual remote absence remain unqualified. Cordis disposal and logical service isolation do not establish those runtime properties.
- The protected NEXT inference path has no qualified live reply. Source now contains immutable total-budget descriptors, cross-task reservations, original pre-reserve attempts, held dispatch continuation and durable evidence/outbox. The [connected mock pilot](docs/evidence/next-dsh-pilot-e994789.json) checks their join; it does not qualify independent spend-store custody, rollback, secure credential entry, protected host binding or a real paid reply. The USD 10 total / USD 0.01 first-request example is inert data. Real dispatch requires separately approved caps, data scope and qualified route/rate/terms/version inputs. Plaintext request/receipt/reply retention remains disclosed in the [inference handoff](packages/inference/next-development-handoff.md).
- Guardian registrations, original wall deadlines and cleanup intent are retained in source, but the pinned backend refuses unsupported reclamation. Workload images are unbuilt definitions with null output digests. Actual execution, resource enforcement, atomic configuration and complete external cleanup remain unqualified.
- Threads needs an available read-only workspace host or an explicit unavailable state. New capture review binds the complete statement, attribution, fixed metadata and selected evidence quote. New text must already be NFC and satisfy the declared control-character policy; historical bytes are preserved. The Apps donor build receipt remains historical; a new Apps source build is unperformed.
- Voice and vision remain unavailable: their donor hosts and authority doors are unmounted, and the Prime static route refuses the AumaLive and Lingwa pages and their voice entry modules. Source presence does not establish local processing or measured egress. A Mac preview can send entered content to its Linux host; see the [data residence account](docs/PRIME-NEXT-ARCHITECTURE.md#data-residence-in-the-preview).
- A second-machine reproducible release digest remains unconfirmed. [GitHub private vulnerability reporting is enabled](SECURITY.md); no separate private email contact or response-time commitment is established.

The live agent is not yet fully contained. Root and identity design still need hardening. Each repaired defect needs a focused regression, and each runtime claim needs evidence from the configured path that actually ran.

## Genesis lineage

Prime carries the full public [AUKORA Genesis](https://github.com/aumara-xyz/aukora-genesis) runtime from Genesis main `9572138ef140311867bcf140e07f0e58d023c61f`, squashed into Prime as one commit (`c358ac7`, 2026-10-04): apps/aukora-desktop, plugins, presets, overlays, vendor, scripts, labs and Genesis tests, with Prime's packages, docs and tests kept beside it. Earlier selected donor material (identity/approval, memory/evidence and UI foundations, originally pinned at `645d3213b8aede3b544269b4224ae09df06b0a42`) remains recorded below. The [donor record](provenance/donors.json), [component ledger](provenance/core-ledger.json) and [notices](licenses/README.md) identify what was retained. Prime keeps that selected material locally; no sibling Genesis checkout is required. Genesis observations do not automatically qualify Prime. Some other historical donor locations remain unavailable; see the [specific source-availability account](licenses/DONOR-SOURCE-AVAILABILITY.md).

## Read and contribute

- [Short overview and reading map](docs/READING-GUIDE.md), [complete Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md) and [review guide](SHARE.md)
- [NEXT source checkpoint](docs/development/INTEGRATION-CHECKPOINT-2026-10-02.md), [join decision](docs/development/INFERENCE-JOIN-DECISION.md) and [changelog](CHANGELOG.md)
- [Contribute a question, correction or patch](CONTRIBUTING.md) · [Architecture and build instructions](docs/PRIME-NEXT-ARCHITECTURE.md) · [CI source checks and limits](docs/CI.md)
- [License inventory](licenses/README.md), [AGPL v3 text](LICENSE), [donor provenance](provenance/donors.json) and [component ledger](provenance/core-ledger.json)
- [Report a vulnerability privately](SECURITY.md)
- [Contributor rules](AGENTS.md), [Claude instructions](CLAUDE.md) and [optional deep-review questions](docs/VISION-QUESTIONS.md)
- [Recursion / Nebius Lab research](research/README.md) — dated report and sanitized digest, separate from product evidence.

First-party software declares **AGPL-3.0-or-later**. Third-party code retains its own licenses: DSH is MIT, OpenShell is Apache-2.0, and vendored dependencies keep their notices. The byte-identical AUMA canon and readers carry **CC-BY-SA-4.0** in their pinned public language publication; the [Auma source and attribution notice](licenses/AUMA-LINGWA-NOTICES.md) preserves that grant and the older donor’s AGPL declarations. See the inventory for the selected closure and its gaps. Prime’s software license is unchanged.
