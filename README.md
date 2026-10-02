# AUKORA Prime

*Human first. AI next.*

The software that proposes an act should not be the authority that permits it.

AUKORA's Golden Boundary vision is a personal AI workspace that can help build tools and propose improvements to itself, while the human retains identity, memory, relationships and authority. Models and applications could change; people and their agents could cooperate without handing control to one platform. **“The person is the platform”** is the proposed destination.

**Start here: [the short overview and reading map](docs/READING-GUIDE.md).** It covers the whole system, then points into [the complete Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md), including its network, philosophy and continuation. For assessment, follow [the review guide](SHARE.md) to evidence and source, or choose its optional deep-review track.

Prime is an open, AGPL governed research release with measured source mechanisms and a pinned UI preview. Real owner effects, product memory, paid inference and live execution remain disabled. The vision and image describe intended architecture; the [status](#status), [known gaps](#known-gaps) and paper's [implementation ledger](docs/AUKORA-GOLDEN-BOUNDARY.md#17-what-exists-today) delimit present claims.

![AUKORA's intended human-first architecture](docs/assets/aukora-human-first.png)

## Check it yourself

Use Node 24.11.1, an existing Python 3.9 or later at `/usr/bin/python3`, and an environment that permits disposable private Unix-domain sockets. Use `umask 0022` in the disposable source-check shell; private fixture state still specifies restrictive modes explicitly. A wrapper that silently changes the child umask can change filesystem-refusal fixtures and must be recorded as a different test environment. Restricted sandboxes can reject the IPC fixtures with `EPERM`; retain that failed/blocked result rather than treating it as PASS. In a checkout of this repository, run:

```sh
./prime verify
```

**Expected source-profile outcome:** exit `2` with zero job failures and the declared external PostgreSQL acceptance arm still UNPERFORMED. Report the complete result and exclusions; this is not a PostgreSQL, runtime or whole-product PASS.

If repository access is available, a fresh review starts with:

```sh
git clone --branch main https://github.com/aumara-xyz/aukora-prime.git
cd aukora-prime
./prime verify
```

For a standalone sanitized source bundle, use `git clone --branch main aukora-prime-sanitized.bundle aukora-prime`, then run the same command. A bundle’s default branch can otherwise differ from its contained `main` ref.

**HISTORICAL RAN at `36f1171bb1e82469eac7fca0190fc9e52f7045c4`:** matching integrator and independent 66-job runs each recorded 65 PASS, 0 FAIL and 1 declared external UNPERFORMED, exit `2`, in 238.697 and 256.323 seconds respectively. The [paired receipt](docs/evidence/source-profile-36f1171-paired.json) records that tested revision and both full results. Functional status was PASS; overall and runtime qualification remained UNPERFORMED, with G1 PENDING. This pair does not qualify a changed candidate.

**HISTORICAL RAN at `58a95f47b417b0b0b0f5235cdcf78fd29a7a1c26`:** the released matching integrator and independent 66-job runs each recorded **65 PASS, 0 FAIL and 1 external PostgreSQL UNPERFORMED**, exit `2`, in 305.282 and 245.450 seconds respectively. The [immutable v1.2.1 release](https://github.com/aumara-xyz/aukora-prime/releases/tag/prime-v1.2.1-research-review) preserves the [paired receipt](https://github.com/aumara-xyz/aukora-prime/releases/download/prime-v1.2.1-research-review/prime-v1.2.1-research-review.paired-receipt.json) (SHA256 `549188b892c55bf01335aa748c61d2c85746516c5070ec6b48c43aeefff4d6bd`), its exact tested revision and both full results. Functional source-profile status was PASS; overall and runtime qualification remained UNPERFORMED, with G1 PENDING.

This reading-path update changes Markdown only; product and verifier bytes are unchanged from the tested revision. No new execution is claimed for this documentation revision. Run the command on the revision you receive and retain its result. Future product or verifier changes need their own evidence; preserve existing immutable tags and receipts. [The profile description](packages/ops/fast-verify/README.md) records the configured scope and exclusions. The separate snapshot interface remains `./prime verify SNAPSHOT OWNER [RETAINED_HEADS_JSON]`.

**HISTORICAL RAN · FAIL at `8bd7dbbcbe78f5a059a991dc0a3903232c3a5100`:** the most recent failed 66-job run returned 63 PASS, 2 FAIL and 1 external UNPERFORMED, exit 1, in 341.689 seconds. Its [retained result](docs/evidence/source-profile-8bd7dbb.json) records worker and authority-core source jobs passing. The two rejected source-check children exited 0 with 12 cases and 35 checks; the result decoder treated their `live_auth` and `public_qualification` UNPERFORMED annotations as required incomplete tests. The aggregate FAIL remains retained; these diagnostics establish no product or runtime PASS.

**HISTORICAL RAN · FAIL at `54c4a306b1e46c9e2db4e9f2a164e7cd2b7ce671`:** the later 66-job run returned 63 PASS, 2 FAIL and 1 UNPERFORMED. Its [retained result](docs/evidence/source-profile-54c4a306.json) does not qualify the subsequently corrected profile.

**HISTORICAL RAN · FAIL at source checkpoint `9c8f5c1b78c18c0b5251e42a7313aa5fd718ef31`:** the earlier 66-job source profile completed with 58 PASS, 2 FAIL and 6 UNPERFORMED in a fresh source-only clone, exit 1, in 209.966 seconds. The [sanitized result](docs/evidence/source-profile-9c8f5c1.json) lists every job. Two bridge fixture jobs failed; authority-core timed out and four later jobs did not run. The exact external PostgreSQL arm remained unperformed. These failures remain retained.

**HISTORICAL RAN at `e9908aa39a24fc57970662e94882fdc63f5087a0`:** the earlier 37-job profile passed, exit 0, in 106.158 seconds; its [result](docs/evidence/source-profile-e9908aa.json) remains retained. That narrower PASS does not qualify the later 66-job profile or runtime.

The first independent `8bd7dbbc` run returned 62 PASS / 4 FAIL in 322.163 seconds. Its wrapper accidentally changed childumask to `077`; D reproduced the resulting permission-guard refusal and all13 retention cases passed with ordinary `022`, without a memory code change. The two shared JSON accounting failures and the original independent outcome remain retained. Its exact PostgreSQL arm stayed UNPERFORMED inside a failed job; a zero aggregate UNPERFORMED-job count does not mean PostgreSQL ran.

An independent cold run at `b336753` returned 36 PASS / 1 FAIL in 154.599 seconds. Its host-check diagnostic found `listen EPERM` before the Unix-socket protocol assertions, so independent cold acceptance remains environment-blocked. The recorded root runs do not replace that result or justify weakening the required assertion.

**HISTORICAL RAN at source checkpoint `0d3d8f3c27e86b08798d032b75b7f32d05e0424d`:** all eight ordinary checks completed PASS with exit 0. This predates the widened full profile and later P0 repairs; it does not close all current requirements. The earlier frozen review checkpoint `1b7bd3d7909996c8d515a5c588059e5b2257e39a` also passed, including cold source-archive verification without a harness build or dependency installation. Run the command at the revision you actually received and report that revision and output. The [earlier recorded source output](docs/evidence/publication-source-verification.json) identifies its own checkpoint and is historical evidence.

The source profile does not establish real owner enrollment, live PostgreSQL, current UID separation, guest containment, paid inference or rendered browser behavior. A PASS applies to the checks that actually ran, not a whole-product certificate.

## Status

**RAN** means executed at the stated checkpoint and scope. **SOURCE-ONLY** identifies integrated code without current deployment qualification. **RECORDED EXPERIMENT** identifies retained evidence from its original run. **UNPERFORMED** names a qualification not established by those narrower results. **PROPOSED** identifies the research direction.

| Status | What exists | Review entry point | Limit |
| --- | --- | --- | --- |
| RAN at historical source revision `58a95f4` | The matching released 66-job runs each recorded 65 PASS, 0 FAIL and 1 external PostgreSQL UNPERFORMED, exit 2. Earlier failed and successful receipts remain retained below. | `./prime verify`; [immutable paired receipt](https://github.com/aumara-xyz/aukora-prime/releases/download/prime-v1.2.1-research-review/prime-v1.2.1-research-review.paired-receipt.json), [scope](packages/ops/fast-verify/README.md). | Exact tested revision and both full results are in the receipt. This Markdown-only update has no new execution claim. Real owner, live database, current UID, guest, paid provider and browser qualification remain UNPERFORMED; G1 PENDING. |
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

- [Short overview and reading map](docs/READING-GUIDE.md), [complete Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md) and [review guide](SHARE.md)
- [Architecture and build instructions](docs/ARCHITECTURE.md)
- [License inventory](licenses/README.md), [AGPL v3 text](LICENSE), [donor provenance](provenance/donors.json) and [component ledger](provenance/core-ledger.json)
- [Vulnerability reporting — private contact pending](SECURITY.md)
- [Contributor rules](AGENTS.md), [Claude instructions](CLAUDE.md) and [optional deep-review questions](docs/VISION-QUESTIONS.md)

First-party source declares **AGPL-3.0-or-later**. Third-party code retains its own licenses: DSH is MIT, OpenShell is Apache-2.0, and vendored dependencies keep their notices. See the inventory for the selected closure and its gaps.
