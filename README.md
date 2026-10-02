# AUKORA Prime

*Human first. AI next.*

AUKORA aims to become an open personal AI workspace that helps people think, remember, build tools and improve the workspace itself. Models and applications could change while identity, memory, relationships and authority stay with the person. People and their agents could cooperate without handing control to one platform: **the person is the platform**.

**The software that proposes an act should not be the authority that permits it.**

**Today:** a stranger can read the full design, inspect the selected source and provenance, and run the source checks. Prime is a research release with a pinned UI preview. Real owner effects, product memory, paid inference and live execution remain disabled; the live agent is not yet fully contained.

From a checkout with [the prerequisites below](#check-it-yourself):

```sh
./prime verify
```

**Released evidence:** at `58a95f4`, two 66-job runs each recorded **65 PASS / 0 FAIL / 1 PostgreSQL UNPERFORMED**, exit `2` ([paired receipt](https://github.com/aumara-xyz/aukora-prime/releases/download/prime-v1.2.1-research-review/prime-v1.2.1-research-review.paired-receipt.json)). This is scoped source evidence, not current runtime qualification; [history and exclusions](docs/EVIDENCE-HISTORY.md) remain visible.

**Read:** [short overview](docs/READING-GUIDE.md) → [complete paper](docs/AUKORA-GOLDEN-BOUNDARY.md) → [evidence/source review](SHARE.md). **Participate:** [contributor front door](CONTRIBUTING.md).

![AUKORA's intended human-first architecture](docs/assets/aukora-human-first.png)

## Check it yourself

Use Node 24.11.1, an existing Python 3.9 or later at `/usr/bin/python3`, and an environment that permits disposable private Unix-domain sockets. Use `umask 0022` in the disposable source-check shell; private fixture state still specifies restrictive modes explicitly. A wrapper that silently changes the child umask can change filesystem-refusal fixtures and must be recorded as a different test environment. Restricted sandboxes can reject the IPC fixtures with `EPERM`; retain that failed/blocked result rather than treating it as PASS. Run the command above from the repository root.

**Expected source-profile outcome:** exit `2` with zero job failures and the declared external PostgreSQL acceptance arm still UNPERFORMED. Report the complete result and exclusions; this is not a PostgreSQL, runtime or whole-product PASS.

If repository access is available, a fresh review starts with:

```sh
git clone --branch main https://github.com/aumara-xyz/aukora-prime.git
cd aukora-prime
```

For a standalone sanitized source bundle, use `git clone --branch main aukora-prime-sanitized.bundle aukora-prime`, then run the verification command above. A bundle’s default branch can otherwise differ from its contained `main` ref.

The historical receipt does not attest the received revision. [CI source checks](docs/CI.md) require a separately observed Actions run; adding a workflow is not an execution result. Preserve the revision and complete result you receive, including failures and unavailable checks. The [evidence history](docs/EVIDENCE-HISTORY.md) retains earlier runs and the immutable release receipt. The [profile description](packages/ops/fast-verify/README.md) states scope and exclusions; owner enrollment, provider credentials, a database and an OpenShell guest are not prerequisites for the public source profile.

## Status

### Status glossary

| Label | Plain meaning |
| --- | --- |
| RAN | The named check or experiment ran at the stated revision; read its result and limits. |
| PASS / FAIL | That check passed or failed. PASS is not a certificate for the whole product. |
| SOURCE-ONLY / Built | Code for a mechanism is present. “Built” does not mean the feature is available or its real operating path is qualified. |
| RECORDED EXPERIMENT | A retained account of an earlier run, with its original assumptions; not a new reproduction. |
| UNPERFORMED | The named check or qualification was not established. It does not erase narrower experiments that ran. |
| Disabled | The product route is intentionally unavailable. Source or preview UI may still exist. |
| PROPOSED | A design or research direction, not a delivered capability. |
| PENDING | An obligation is still open; no result is implied. |

### Current account

| Status | What exists | Review entry point | Limit |
| --- | --- | --- | --- |
| RAN at historical source revision `58a95f4` | The matching released 66-job runs each recorded 65 PASS, 0 FAIL and 1 external PostgreSQL UNPERFORMED, exit 2. Earlier failed and successful receipts remain in the [evidence history](docs/EVIDENCE-HISTORY.md). | `./prime verify`; [immutable paired receipt](https://github.com/aumara-xyz/aukora-prime/releases/download/prime-v1.2.1-research-review/prime-v1.2.1-research-review.paired-receipt.json), [scope](packages/ops/fast-verify/README.md). | Exact tested revision and both full results are in the receipt. This publication update does not change the product profile; the historical receipt does not attest the received revision. Real owner, live database, current UID, guest, paid provider and browser qualification remain UNPERFORMED; G1 PENDING. |
| RAN at historical documentation baseline `9d6c2205` | Frozen Node/browser contracts: 421 assertions; owner controller: 11 cases; static script CSP: 39 assertions across six routes. | `node packages/contracts/check.mjs`; `node packages/ui/prime-authority/checks/controller.mjs packages/contracts/src/browser.mjs`; `node harness/check-static-csp.mjs`. | Synthetic review and source routing checks do not establish owner enrollment, rendered parity or effect mediation. |
| SOURCE-ONLY | Durable owner logout, session-bound approvals, exact save/forget review and receipt-bound recovery are integrated source. | [Authority](packages/authority/README.md), [owner UI](packages/ui/prime-authority/README.md), [host seam](harness/OWNER-MEMORY-HANDOFF.md). | The protected public owner/effect path remains unavailable. Recovery may present verified existing evidence; it cannot authorize or retry an uncertain effect. |
| SOURCE-ONLY | Atomic retained-memory participant and authority phases preserve marker, intent, dispatch and final receipt ordering. | [Atomic retention](packages/memory/ATOMIC_RETENTION.md), [authority source](packages/authority/README.md), [bridge](packages/runtime-bridge/README.md). | The separated private phase adapter and current PostgreSQL/UID acceptance are unfinished. Retained-profile restore is disabled. |
| RECORDED EXPERIMENT | One synthetic-P256-approved save through PostgreSQL 16 and distinct authority/memory users; bytes, citation and receipt survived independent restarts. | [Dated sanitized summary](docs/evidence/bounded-memory-experiment.json). | Older source, one synthetic save, no real owner; saved, not indexed or searchable. Reading the summary does not repeat or independently authenticate the original run. |
| RAN build checkpoint | The frozen `1b7bd3d` baseline built the pinned Linux harness and owner plugin and composed a release. | [Build instructions](docs/ARCHITECTURE.md), [owner build receipt](packages/ui/docs/owner-build-receipt.md). | Linux-generated output has its own identity. The earlier generated build was observed at both 1440×900 and 480×800 with disabled credential controls. That renderer result does not qualify later source, owner enrollment or inference. |
| Disabled | Actual OpenShell execution and live model inference. | [Execution](packages/execution/README.md), [inference](packages/inference/README.md). | Real gateway containment, remote cleanup, protected credential admission and a budget-capped real reply remain unqualified. Public effects stay fail-closed. |
| Proposed | Cordis/OpenShell execution composition, registered agents and human networking, agentic browser, handset, 27-cell receipt wiring, seven-word ceremony and NDI integration. | [Paper's Built / Proposed table](docs/AUKORA-GOLDEN-BOUNDARY.md#built--proposed-commands-and-limits). | These designs are not functioning product claims. |

Real PostgreSQL and separate Linux users are not wholly unperformed: the bounded experiment above ran. Qualification of the current complete product under those conditions remains UNPERFORMED. Synthetic signers and mock SDK responses retain their limits.

## Known gaps

- An attempted pre-reservation refusal remains unknown until authoritative C/D non-consumption, absence of an intent/effect and writer closure can be established together. No UI callback or missing-effect exception clears that fence. The affected owner-effect runtime stays unavailable.
- The retained-memory source protocol now includes authority preparation, request-bound dispatch and factual settlement. Its authenticated separated-worker phase adapter is not implemented or qualified here. Retained-profile restore refuses until its lineage is established; no stale checkpoint or success flag can replace that evidence.
- Logout, logical forget and verified-receipt recovery have source joins. Current served behavior and the protected owner path still need acceptance. An unknown outcome retains its consumption and replay fence; reconciliation is not permission to repeat an effect. Logical purge does not promise erasure of physical media, WAL or external copies.
- The current owner plugin was compiled against the verified pinned harness: its genuine receipt binds 85 source inputs and 38 generated outputs. Source/output checks and the compiled component’s eight SSR/protocol groups passed; current browser observation remains separate. The genuine owner build receipt binds current source and generated outputs. Composition verifies that receipt rather than accepting the old receipt. Each changed source revision still needs its own build, composition, served-byte checks and renderer observation. The Models companion is read-only; catalog display does not enable credential entry or inference.
- Same-UID witness rollback remains a declared limit. Candidate-writable state and its reference cannot establish independent authority. A separate UID also needs authenticated IPC, protected configuration, owner proof and actual target enforcement.
- The owner's real passkey enrollment requires the owner's action and remains unperformed. A real passkey with user verification does not prove hardware custody, human identity, comprehension or freely given attendance. Lost-device revocation, key rotation, owner recovery and challenge-abuse recovery remain hardening work. Source challenge quotas are bounded; they do not complete that account.
- OpenShell execution is disabled. Full effective-configuration readback, a durable final-verification fence, conservative timeout/null-exit handling and the mounted factory’s tracked Cordis effect are integrated source. The atomic expected-policy execution fence, external cleanup supervisor, resources and actual remote absence remain unqualified. Cordis disposal and logical service isolation do not establish those runtime properties.
- Live inference has no qualified reply. A real provider route needs protected key custody, exact approved numeric caps, data scope and provider terms/version qualification. No generic credential backend or paid fallback is enabled. The newer global total-budget delivery is deferred; existing mock per-task accounting does not enforce an approved all-in global cap.
- Threads needs an available read-only workspace host or an explicit unavailable state. New capture review binds the complete statement, attribution, fixed metadata and selected evidence quote. New text must already be NFC and satisfy the declared control-character policy; historical bytes are preserved. The Apps donor build receipt remains historical; a new Apps source build is unperformed.
- Voice and vision remain unavailable: their donor hosts and authority doors are unmounted, and the Prime static route refuses the AumaLive and Lingwa pages and their voice entry modules. Source presence does not establish local processing or measured egress. A Mac preview can send entered content to its Linux host; see the [data residence account](docs/ARCHITECTURE.md#data-residence-in-the-preview).
- A second-machine reproducible release digest remains unconfirmed. [GitHub private vulnerability reporting is enabled](SECURITY.md); no separate private email contact or response-time commitment is established.

The live agent is not yet fully contained. Root and identity design still need hardening. Each repaired defect needs a focused regression, and each runtime claim needs evidence from the configured path that actually ran.

## Genesis lineage

Prime carries selected source from the public [AUKORA Genesis](https://github.com/aumara-xyz/aukora-genesis) prototype, pinned at `645d3213b8aede3b544269b4224ae09df06b0a42`, including identity/approval, memory/evidence and UI foundations. The [donor record](provenance/donors.json), [component ledger](provenance/core-ledger.json) and [notices](licenses/README.md) identify what was retained. Prime keeps that selected material locally; no sibling Genesis checkout is required. Genesis observations do not automatically qualify Prime. Some other historical donor locations remain unavailable; see the [specific source-availability account](licenses/DONOR-SOURCE-AVAILABILITY.md).

## Read and contribute

- [Short overview and reading map](docs/READING-GUIDE.md), [complete Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md) and [review guide](SHARE.md)
- [Contribute a question, correction or patch](CONTRIBUTING.md) · [Architecture and build instructions](docs/ARCHITECTURE.md) · [CI source checks and limits](docs/CI.md)
- [License inventory](licenses/README.md), [AGPL v3 text](LICENSE), [donor provenance](provenance/donors.json) and [component ledger](provenance/core-ledger.json)
- [Report a vulnerability privately](SECURITY.md)
- [Contributor rules](AGENTS.md), [Claude instructions](CLAUDE.md) and [optional deep-review questions](docs/VISION-QUESTIONS.md)
- [Published Nebius Lab research reference](https://github.com/aumara-xyz/aukora-prime/blob/review/nebius-lab/research/NEBIUS-LAB.md) — a separate sanitized research snapshot with its own evidence and limits, not a product release.

First-party software declares **AGPL-3.0-or-later**. Third-party code retains its own licenses: DSH is MIT, OpenShell is Apache-2.0, and vendored dependencies keep their notices. The byte-identical AUMA canon and readers carry **CC-BY-SA-4.0** in their pinned public language publication; the [Auma source and attribution notice](licenses/AUMA-LINGWA-NOTICES.md) preserves that grant and the older donor’s AGPL declarations. See the inventory for the selected closure and its gaps. Prime’s software license is unchanged.
