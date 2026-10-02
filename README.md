![AUKORA's intended human-first architecture](docs/assets/aukora-human-first.png)

*Human first. AI next.*

The software that proposes an act should not be the authority that permits it.

AUKORA Prime is a research release of an open, AGPL governed personal-AI core. It has measured source mechanisms and a pinned UI preview; real owner effects, product memory, paid inference and live execution remain disabled. The intended architecture puts identity, memory and authority with the human while models and apps remain replaceable. The image describes that intended architecture; measured results and gaps follow below.

**Reviewing the project? Start with [the verification-first review guide](SHARE.md).** It leads through the checks, setup requirements and scoped source questions before the optional architectural discussion. [The Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md) separates that vision from the implementation ledger in [§17](docs/AUKORA-GOLDEN-BOUNDARY.md#17-what-exists-today).

## Check it yourself

Use Node 24.11.1, an existing Python 3.9 or later at `/usr/bin/python3`, and an environment that permits disposable private Unix-domain sockets. Restricted sandboxes can reject the IPC fixtures with `EPERM`; retain that failed/blocked result rather than treating it as PASS. In a checkout of this repository, run:

```sh
./prime verify
```

If repository access is available, a fresh review starts with:

```sh
git clone --branch main https://github.com/aumara-xyz/aukora-prime.git
cd aukora-prime
./prime verify
```

For a standalone sanitized source bundle, use `git clone --branch main aukora-prime-sanitized.bundle aukora-prime`, then run the same command. A bundle’s default branch can otherwise differ from its contained `main` ref.

**PENDING — final paired 66-job source verification:** the corrected profile still requires two complete runs at the same frozen revision. Publication acceptance remains on hold; no final PASS is claimed. Final source identity and both full results must be recorded through the planned named review reference `prime-v1.2-research-review` and an external immutable receipt identifying the exact tested revision. Record the exact revision received and both full results; an older receipt does not qualify a different checkout. [The profile description](packages/ops/fast-verify/README.md) records the configured scope and its exclusions. The separate snapshot interface remains `./prime verify SNAPSHOT OWNER [RETAINED_HEADS_JSON]`.

**HISTORICAL RAN · FAIL at `54c4a306b1e46c9e2db4e9f2a164e7cd2b7ce671`:** the later 66-job run returned 63 PASS, 2 FAIL and 1 UNPERFORMED. Its [retained result](docs/evidence/source-profile-54c4a306.json) does not qualify the subsequently corrected profile.

**HISTORICAL RAN · FAIL at source checkpoint `9c8f5c1b78c18c0b5251e42a7313aa5fd718ef31`:** the earlier 66-job source profile completed with 58 PASS, 2 FAIL and 6 UNPERFORMED in a fresh source-only clone, exit 1, in 209.966 seconds. The [sanitized result](docs/evidence/source-profile-9c8f5c1.json) lists every job. Two bridge fixture jobs failed; authority-core timed out and four later jobs did not run. The exact external PostgreSQL arm remained unperformed. These failures remain retained.

**HISTORICAL RAN at `e9908aa39a24fc57970662e94882fdc63f5087a0`:** the earlier 37-job profile passed, exit 0, in 106.158 seconds; its [result](docs/evidence/source-profile-e9908aa.json) remains retained. That narrower PASS does not close the current 66-job failures or runtime qualification.

An independent cold run at `b336753` returned 36 PASS / 1 FAIL in 154.599 seconds. Its host-check diagnostic found `listen EPERM` before the Unix-socket protocol assertions, so independent cold acceptance remains environment-blocked. The recorded root runs do not replace that result or justify weakening the required assertion.

**HISTORICAL RAN at source checkpoint `0d3d8f3c27e86b08798d032b75b7f32d05e0424d`:** all eight ordinary checks completed PASS with exit 0. This predates the widened full profile and later P0 repairs; it does not close all current requirements. The earlier frozen review checkpoint `1b7bd3d7909996c8d515a5c588059e5b2257e39a` also passed, including cold source-archive verification without a harness build or dependency installation. Run the command at the revision you actually received and report that revision and output. The [earlier recorded source output](docs/evidence/publication-source-verification.json) identifies its own checkpoint and is historical evidence.

The source profile does not establish real owner enrollment, live PostgreSQL, current UID separation, guest containment, paid inference or rendered browser behavior. A PASS applies to the checks that actually ran, not a whole-product certificate.

## Status

**RAN** means executed at the stated checkpoint and scope. **SOURCE-ONLY** identifies integrated code without current deployment qualification. **RECORDED EXPERIMENT** identifies retained evidence from its original run. **UNPERFORMED** names a qualification not established by those narrower results. **PROPOSED** identifies the research direction.

| Status | What exists | Review entry point | Limit |
| --- | --- | --- | --- |
| Final paired source verification pending | The corrected 66-job profile awaits two complete runs at one frozen revision. Failed history remains retained: `54c4a306` returned 63/2/1 and `9c8f5c1` returned 58/2/6, in PASS/FAIL/UNPERFORMED order. | `./prime verify`; [later failed result](docs/evidence/source-profile-54c4a306.json), [earlier failed result](docs/evidence/source-profile-9c8f5c1.json), [scope](packages/ops/fast-verify/README.md). | Publication acceptance remains on hold. The named review reference and external immutable receipt must identify the exact tested revision and both full results. No final PASS or deployment qualification follows. |
| RAN at historical documentation baseline `9d6c2205` | Frozen Node/browser contracts: 421 assertions; owner controller: 11 cases; static script CSP: 39 assertions across six routes. | `node packages/contracts/check.mjs`; `node packages/ui/prime-authority/checks/controller.mjs packages/contracts/src/browser.mjs`; `node harness/check-static-csp.mjs`. | Synthetic review and source routing checks do not establish owner enrollment, rendered parity or effect mediation. |
| SOURCE-ONLY | Durable owner logout, session-bound approvals, exact save/forget review and receipt-bound recovery are integrated source. | [Authority](packages/authority/README.md), [owner UI](packages/ui/prime-authority/README.md), [host seam](harness/OWNER-MEMORY-HANDOFF.md). | The protected public owner/effect path remains unavailable. Recovery may present verified existing evidence; it cannot authorize or retry an uncertain effect. |
| SOURCE-ONLY | Atomic retained-memory participant and authority phases preserve marker, intent, dispatch and final receipt ordering. | [Atomic retention](packages/memory/ATOMIC_RETENTION.md), [authority source](packages/authority/README.md), [bridge](packages/runtime-bridge/README.md). | The separated private phase adapter and current PostgreSQL/UID acceptance are unfinished. Retained-profile restore is disabled. |
| RECORDED EXPERIMENT | One synthetic-P256-approved save through PostgreSQL 16 and distinct authority/memory users; bytes, citation and receipt survived independent restarts. | [Dated sanitized summary](docs/evidence/bounded-memory-experiment.json). | Older source, one synthetic save, no real owner; saved, not indexed or searchable. Reading the summary does not repeat or independently authenticate the original run. |
| RAN build checkpoint | The frozen `1b7bd3d` baseline built the pinned Linux harness and owner plugin and composed a release. | [Build instructions](docs/ARCHITECTURE.md), [owner build receipt](packages/ui/docs/owner-build-receipt.md). | Linux-generated output has its own identity. The earlier generated build was observed at both 1440×900 and 480×800 with disabled credential controls. That renderer result does not qualify later source, owner enrollment or inference. |
| Disabled | Actual OpenShell execution and live model inference. | [Execution](packages/execution/README.md), [inference](packages/inference/README.md). | Real gateway containment, remote cleanup, protected credential admission and a budget-capped real reply remain unqualified. Public effects stay fail-closed. |
| Proposed | Cordis/OpenShell execution composition, registered agents and human networking, agentic browser, handset, 27-cell receipt wiring, seven-word ceremony and NDI integration. | [Paper and Built / Proposed table](docs/AUKORA-GOLDEN-BOUNDARY.md). | These designs are not functioning product claims. |

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
- A second-machine reproducible release digest and a private security reporting contact remain unconfirmed.

The live agent is not yet fully contained. Root and identity design still need hardening. Each repaired defect needs a focused regression, and each runtime claim needs evidence from the configured path that actually ran.

## Read and contribute

- [Review prompt](SHARE.md) and [Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md)
- [Architecture and build instructions](docs/ARCHITECTURE.md)
- [License inventory](licenses/README.md), [AGPL v3 text](LICENSE), [donor provenance](provenance/donors.json) and [component ledger](provenance/core-ledger.json)
- [Vulnerability reporting — private contact pending](SECURITY.md)
- [Contributor rules](AGENTS.md), [Claude instructions](CLAUDE.md) and [verification-first review](SHARE.md)

First-party source declares **AGPL-3.0-or-later**. Third-party code retains its own licenses: DSH is MIT, OpenShell is Apache-2.0, and vendored dependencies keep their notices. See the inventory for the selected closure and its gaps.
