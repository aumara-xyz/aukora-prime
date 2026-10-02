# Source verification evidence history

This history preserves the reported runs, failures and limitations previously narrated in the README and paper. Receipts and original evidence files are unchanged. These are records of named revisions, not a fresh run or a claim about an installed system. Use the [status glossary](../README.md#status-glossary) and [source-review guide](../SHARE.md#evidence-and-source-review) to interpret them.

## NEXT publication source profile

**RAN · FAIL at `8fda787563357c188a63b5fd3ec062f8ef044e0c`:** the [actual normal CI run](https://github.com/aumara-xyz/aukora-prime/actions/runs/37010345479) completed all 66 jobs with **59 PASS, 6 FAIL and 1 external PostgreSQL UNPERFORMED**, exit `1`, in 72.259 seconds. The [sanitized receipt](evidence/source-profile-ci-8fda787.json) retains all job statuses and failed titles. The six failures affect `full-workflow-store`, `full-owner-memory-workflow`, `full-owner-memory-hook`, `full-owner-recovery`, `full-owner-forget-workflow` and `bridge-ui-adapter-lifecycle`. No required assertion or counter was removed to accept them. Runtime qualification remains UNPERFORMED; G1 PENDING.

The downloaded seven-file artifact matched server SHA256 `94a6c6a12365221ce11041d8da7c97f4348bc10bf45db91e126eb42c6c033f09`. Its unmodified stdout JSON, machine summary and engine summary agree, and the published CI validator independently rejects the failed result. The artifact expires on 2026-10-09; its actual bytes are retained privately. The evaluator withholds child raw output, so this receipt does not claim to preserve that output.

The [focused publication checks](evidence/next-publication-checks-b867c72.json) passed 29 inference cases, 25 Cordis-provider cases and owner build input/output verification. The earlier local full-profile attempt ended without an execution-transport result and remains UNPERFORMED. These scoped checks and prior release receipts do not supersede the failed complete CI run or qualify an installed system.

## Released source profile

The released `58a95f4` pair below supersedes the preparation-era pending status. It does not close runtime qualification or rerun the checks for a later documentation revision. The [runner README](../packages/ops/fast-verify/README.md) describes the profile; the receipt identifies what actually ran.

**HISTORICAL RAN at `58a95f47b417b0b0b0f5235cdcf78fd29a7a1c26`:** the released matching integrator and independent 66-job runs each recorded **65 PASS, 0 FAIL and 1 external PostgreSQL UNPERFORMED**, exit `2`, in 305.282 and 245.450 seconds respectively. The [immutable v1.2.1 release](https://github.com/aumara-xyz/aukora-prime/releases/tag/prime-v1.2.1-research-review) preserves the [paired receipt](https://github.com/aumara-xyz/aukora-prime/releases/download/prime-v1.2.1-research-review/prime-v1.2.1-research-review.paired-receipt.json) (SHA256 `549188b892c55bf01335aa748c61d2c85746516c5070ec6b48c43aeefff4d6bd`), its exact tested revision and both full results. Functional source-profile status was PASS; overall and runtime qualification remained UNPERFORMED, with G1 PENDING.

The public-entry, notice and CI update at `3017db7` preserved product/profile bytes from the released source. Its [actual CI run](https://github.com/aumara-xyz/aukora-prime/actions/runs/37004013526) recorded 65 PASS, 0 FAIL and 1 PostgreSQL UNPERFORMED, exit 2; it remains historical for later revisions. NEXT now changes product source and selected reviewed source pins. Local CI-validator checks are separate synthetic checks; a workflow file or older result does not establish execution of the received revision. Run the command on the revision you receive and retain its result. Future product or verifier changes need their own evidence; preserve existing immutable tags and receipts. [The profile description](../packages/ops/fast-verify/README.md) records the configured scope and exclusions. The separate snapshot interface remains `./prime verify SNAPSHOT OWNER [RETAINED_HEADS_JSON]`.

## Earlier runs and failures

**HISTORICAL RAN at `36f1171bb1e82469eac7fca0190fc9e52f7045c4`:** matching integrator and independent 66-job runs each recorded 65 PASS, 0 FAIL and 1 declared external UNPERFORMED, exit `2`, in 238.697 and 256.323 seconds respectively. The [paired receipt](evidence/source-profile-36f1171-paired.json) records that tested revision and both full results. Functional status was PASS; overall and runtime qualification remained UNPERFORMED, with G1 PENDING. This pair does not qualify a changed candidate.

**HISTORICAL RAN · FAIL at `8bd7dbbcbe78f5a059a991dc0a3903232c3a5100`:** the failed 66-job run returned 63 PASS, 2 FAIL and 1 external UNPERFORMED, exit 1, in 341.689 seconds. Its [retained result](evidence/source-profile-8bd7dbb.json) records worker and authority-core source jobs passing. The two rejected source-check children exited 0 with 12 cases and 35 checks; the result decoder treated their `live_auth` and `public_qualification` UNPERFORMED annotations as required incomplete tests. The aggregate FAIL remains retained; these diagnostics establish no product or runtime PASS.

**HISTORICAL RAN · FAIL at `54c4a306b1e46c9e2db4e9f2a164e7cd2b7ce671`:** the later 66-job run returned 63 PASS, 2 FAIL and 1 UNPERFORMED. Its [retained result](evidence/source-profile-54c4a306.json) does not qualify the subsequently corrected profile.

**HISTORICAL RAN · FAIL at source checkpoint `9c8f5c1b78c18c0b5251e42a7313aa5fd718ef31`:** the earlier 66-job source profile completed with 58 PASS, 2 FAIL and 6 UNPERFORMED in a fresh source-only clone, exit 1, in 209.966 seconds. The [sanitized result](evidence/source-profile-9c8f5c1.json) lists every job. Two bridge fixture jobs failed; authority-core hit its then-configured 60-second limit and four later jobs did not run. The exact external PostgreSQL arm remained unperformed. These failures remain retained.

**HISTORICAL RAN at `e9908aa39a24fc57970662e94882fdc63f5087a0`:** the earlier 37-job profile passed, exit 0, in 106.158 seconds; its [result](evidence/source-profile-e9908aa.json) remains retained. That narrower PASS does not qualify the later 66-job profile or runtime.

The first independent `8bd7dbbc` run returned 62 PASS / 4 FAIL in 322.163 seconds. Its wrapper accidentally changed the child umask to `077`; the memory-lane follow-up reproduced the resulting permission-guard refusal and all 13 retention cases passed with ordinary `022`, without a memory code change. The two shared JSON accounting failures and the original independent outcome remain retained. Its exact PostgreSQL arm stayed UNPERFORMED inside a failed job; a zero aggregate UNPERFORMED-job count does not mean PostgreSQL ran.

An independent cold run at `b336753` returned 36 PASS / 1 FAIL in 154.599 seconds. Its host-check diagnostic found `listen EPERM` before the Unix-socket protocol assertions, so independent cold acceptance remains environment-blocked. The recorded root runs do not replace that result or justify weakening the required assertion.

**HISTORICAL RAN at source checkpoint `0d3d8f3c27e86b08798d032b75b7f32d05e0424d`:** all eight ordinary checks completed PASS with exit 0. This predates the widened full profile and later P0 repairs; it does not close all current requirements. The earlier frozen review checkpoint `1b7bd3d7909996c8d515a5c588059e5b2257e39a` also passed, including cold source-archive verification without a harness build or dependency installation. Run the command at the revision you actually received and report that revision and output. The [earlier recorded source output](evidence/publication-source-verification.json) identifies its own checkpoint and is historical evidence.

The source profile does not establish real owner enrollment, live PostgreSQL, current UID separation, guest containment, paid inference or rendered browser behavior. A PASS applies to the checks that actually ran, not a whole-product certificate.

## Additional source-suite history and limits

The source runner preserves the separate snapshot interface; the original preparation baseline refused the source command through that CLI. The earlier runs above do not qualify the later 66-job profile or runtime.

Run `./prime verify` on the received revision and retain both complete results for final paired review. The corrected full source profile has a cooperative 600-second suite budget: required full TAP files have 120-second limits, the exact `authority-core-only` job has a 180-second limit, and other ordinary jobs have limits of at most 60 seconds. Its summary records actual duration and separate PASS, FAIL and UNPERFORMED results. These are execution budgets, not a completion promise or a kernel deadline. Current owner, database, UID, guest, paid-provider and browser qualification remain excluded. The released pair is historical evidence at `58a95f4`; this documentation update adds no execution claim, and a scoped source PASS is not a whole-product certificate.

Source IPC checks need permission to create disposable private Unix-domain sockets. The environment-blocked `b336753` result above must not be bypassed or silently skipped.

The earlier full authority suite could outlive the five-minute session during its 265-save admission fixture. Ordinary signed session-renewal source is integrated, preserving the production session lifetime; the long admission run remains outside this keyless profile. A repaired package check is not an excuse to omit the cold review entry point or silently suppress a failure.

## Other evidence and provenance

The [paper's implementation ledger](AUKORA-GOLDEN-BOUNDARY.md#17-what-exists-today) retains scoped contract, controller, static-route and build observations. The [bounded PostgreSQL experiment](evidence/bounded-memory-experiment.json) records one synthetic-approved save at its own historical revision; [the paper explains its limits](AUKORA-GOLDEN-BOUNDARY.md#what-the-postgresql-experiment-earned). The [engine result](evidence/json-all-producers-final-engine.json), [source provenance](../provenance/donors.json), [component ledger](../provenance/core-ledger.json) and [licenses](../licenses/README.md) remain available for inspection. Historical donor paths may differ from today's layout; see [donor source availability](../licenses/DONOR-SOURCE-AVAILABILITY.md).
