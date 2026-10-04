# Nebius Lab: research record

> **Update 2026-10-04 (rev 3).** The H200 work described below as HELD has since run (Oct 3–4) under per-run preregistrations. Results are summarised in the next section; the original offline snapshot follows unchanged below it. Full code, preregistrations and receipts: `aumara-xyz/aukora-genesis` branch `labs/sokoban-recursion-r1` (sealed test sets, weights and raw transcripts withheld).

## GPU-run results (Oct 3–4, 2026)

Labels: **RAN** = executed, receipt named; **SOURCE-ONLY** = code/plan, not executed; **CLAIMED** = asserted, not demonstrated. Categories kept distinct: historical (pre-Oct values) / recalculated / synthetic control / qualified GPU run / demonstrated improvement.

Domain: 8x8 two-box Sokoban with an exact simulator/BFS verifier; model Ornith-1.5-35B-A3B (Qwen3.5-MoE, ~3B active); one H200. Every test below used a sealed puzzle set never used for training, with a pass rule locked before the run.

| Claim | Category | Label / receipt |
| --- | --- | --- |
| One generation of verified-trace LoRA training (v7) improves format-independent solving over the untrained model on a 2nd sealed set: 22.2% → 26.6% of 1152 attempts, 53 boards up / 32 down, p=0.0147 | demonstrated improvement (single generation) | RAN — prereg/REP1-RESULT.json |
| Same effect first seen on another sealed set, p=0.019 (secondary test) | qualified GPU run | RAN — prereg/V7-RESULT.json |
| Earlier 11→22/128 "doubling" was mostly answer-format learning | recalculated | RAN — prereg/CONFIRM-1/2-RESULT.json |
| Interactive play (simulator feedback each turn) vs single-shot: 69 → 116 of 288 (p=3e-6); not better at equal token budget (50 vs 69) | qualified GPU run | RAN — prereg/WMC-RESULT.json |
| Forcing an answer on truncated thinking rescued 0; prompt-pasted value hints hurt (89→73/512) | qualified GPU run (negative) | RAN — prereg/FORCED-1-RESULT.json, S1b-RESULT.json |
| Second generation (gen-2 with coach hints) did not beat gen-1; hint text leaked into targets | qualified GPU run (negative) | RAN — AMENDMENTS.md |
| 1.9M-param policy/value CNN trained on solver labels: 98.3% best-move accuracy; with search 200/200 fresh puzzles | supervised, not self-improvement | RAN (CPU/MPS) — lab/p1_REPORT.md |
| Sob-Zero self-play on DeepMind Boxoban (10x10, 4 boxes), no solver labels: sealed 800-level solve rate 68.9% → 86.0% (champion), best 88.9%, p≈6e-34 | demonstrated multi-generation self-improvement (one seed; started from the supervised net) | RAN — prereg/SOBZERO-RESULT.json |
| v9: Ornith LoRA-trained on winning interactive turns (incl. System-1-guided games, guidance removed + leak-gated); sealed holdout_v9 interactive: v9 88/288 vs v7 136/288 (12 boards up / 53 down), 17-32 band 45 → 15; verdict NO_PROMOTE | qualified GPU run (negative) | RAN — prereg/V9-RESULT.json |
| Dream-RSI-style replay ("dreaming"): search configs tuned offline on recorded Sob-Zero search trees, confirmed live on held-out gate levels (transfer ratio 0.89), then one preregistered sealed run: 688 → 718 of 800 (86.0% → 89.75%), 36 up / 6 down, p=1.4e-6, 3.4x fewer expansions per solve | demonstrated improvement (planner, not network; one seed) | RAN — prereg/DREAM-RESULT.json |
| v7 interactive baseline on new sealed set holdout_v9: 136/288; turn-by-turn System-1 guidance during collection: 741/1280 wins vs 206/640 unguided (different pools — exploratory) | qualified GPU run / exploratory | RAN — v9 receipts (in progress) |
| Compounding multi-generation gains in the LLM itself; transfer to a second game | not shown | CLAIMED-NOT-YET |

Costs (approximate, public $5.40/GPU-h): Oct 3 ≈ $51 GPU + $11.48 API (API use stopped); Oct 4 in progress. Provider STOPPED was confirmed at the end of Oct 3.

Governance invariants (held throughout): sealed evaluation sets and the verifier sit outside the trained model's reach; fast intuition/coach signals can veto or route but never approve; a better model never gains authority to install itself, change its evaluator or widen its own permissions — promotion is a human (owner) decision per generation; every deviation is logged append-only.

---

## Original snapshot (Oct 1–2, unchanged)

This branch collects completed offline research artifacts copied from pinned source revisions through `3e0f870f9fa4e008f4410d160b2b9e77bda539ae`. It is **not a product release, a completed GPU experiment or permission to start one**. Product source is the sanitized `a15966fd4cda16186757adf84c954b44f4ccf5c8` baseline. Only selected research file bytes were copied; the donor branch's Git history was not imported.

## Read the evidence in order

| Reference artifact | What ran or was recovered | Evidence limit |
| --- | --- | --- |
| [Initial offline inventory](evidence/2026-10-01-recursion-phase0/RESULTS.md) | Synthetic arithmetic, missing-input refusal and a fail-closed corpus inventory. | Made-up fixture values are not model results. Earlier missing-input statements describe that round and are superseded below. |
| [Input recovery](evidence/2026-10-02-input-recovery/RESULTS.md) | Five authored scenarios, twelve cached calibration rows and sixteen source-bound loop metadata records recovered; historical values recalculated. | Original calibration request texts, complete responses and independent labels remain missing. No judge/model rerun or verified authority-chain corpus. |
| [Retrospective calibration](evidence/2026-10-02-posthoc-calibration/RESULTS.md) | Historical exact verdict remains 5/12 (41.7%); explicitly optional KEEP/SAFE grouping gives 8/12 (66.7%). | Seen-data, author-labeled arithmetic. Same-table AUC/threshold separation is not generalization or prospective accuracy. |
| [Prospective readiness](evidence/2026-10-02-prospective-readiness/RESULTS.md) | Offline runtime/file inventories and prerequisite checks. | NOT READY FOR H200. No inference, training, provider action or real manifest qualification. |
| [Refresh trial design](evidence/2026-10-02-refresh-run-design/RESULTS.md) | Archived trainer statically inspected; a new schedule and separate candidate-fit note drafted. | DRAFT / UNREGISTERED / UNEXECUTED / HELD. Archived code was not run. Subsequent runner source below advances the earlier missing-runner gap. |
| [New isolated runner](evidence/2026-10-02-refresh-runner/RESULTS.md) | Latest recorded CPU attempt passed 19 injected synthetic control checks, with source hashes, receipts and prior failed attempts retained. | No model libraries, provider, CUDA backend, training or model-performance result. Cooperative checks and a supervisor interface do not prove actual shutdown or GPU containment. |
| [H200 baseline preparation](evidence/2026-10-02-h200-readiness/RESULTS.md) | One recorded suite passed 18 synthetic CPU control checks; one measured preparation produced seven existing-row hashes. Exact source, receipts and a partial new draft commitment are retained. | UNREGISTERED / PARTIAL_DRAFT_ONLY; data eligibility PENDING; no original base/tokenizer qualification, model/GPU run, corpus ingestion or actual stop/export qualification. No training or new recursion result. |

The exact historical verdict result is preserved alongside the optional mapping. Twelve curated historical rows, posthoc thresholds and hash locks over already seen data cannot establish independent ground truth, a prospective prediction or product safety. The strict verified governance corpus remains **0 verified examples**.

## Current baseline preparation

The [current source/evidence inventory](evidence/2026-10-02-h200-readiness/current-source-evidence-manifest.json) binds 20 source/evidence files and the already included runner dependency. The aggregate [publication manifest](publication-manifest.json) also hashes that inventory itself, for 21 new payload files. The [source-status history](evidence/2026-10-02-h200-readiness/source-status-history.json) separates earlier untested source snapshots from the later recorded CPU checks. The original historical receipts are preserved; copied evidence is not a new publication-time run.

The seven-row preparation was a private, measured parsing-and-hashing operation on an existing known file. Only its sanitized metadata is included: no row text, private paths, private draft directory or actual provider/account identifiers. A content hash does not establish permitted use, independent truth, suitability or model performance. The [eligibility procedure](evidence/2026-10-02-h200-readiness/ELIGIBILITY-REGISTRATION.md) remains pending, and the [new preregistration draft](evidence/2026-10-02-h200-readiness/baseline-preregistration-DRAFT.json) has no executable freeze or go. It neither reconstructs nor grades the missing historical prediction lock.

The [GO/NO-GO account](evidence/2026-10-02-h200-readiness/GO-NO-GO.md) retains the exact missing model/tokenizer, environment, disk, current capacity/cost and independently qualified stop/export/received-copy prerequisites. Its tonight target is a planning deadline, not execution authority. The baseline would be inference-only; a measured deficit would not authorize training. Later training has separate data, registration and runtime obligations.

## What is still missing

A real run needs pinned base/tokenizer inventories, eligible private pair-file hashes, a frozen schedule, measured baseline, runtime/memory/throughput and save/reload qualification, actual free space, private verified all-in pricing and budget receipts, an independently qualified stop/export controller, and satisfaction of the existing conditional authorization. Historical judge outputs, full calibration request/response provenance, independent labels and the original locked historical prediction remain unrecovered. A new prospective experiment needs its own preregistration; it cannot recreate the historical lock.

GPU work remains **HELD**. No start, retry, paid model call, training, disk creation/deletion or provider action is authorized by this branch. Private operator manifests and raw provider/account records are absent.

## Costs and limits

The new local research ledgers record **$0 incremental paid experimental spend**, zero cloud-compute seconds, zero model/API calls and zero newly created cloud storage resources. Standing storage, host electricity and agent/subscription usage are unverified or excluded; $0 is not an account invoice or a claim of no ongoing costs.

The proposed USD30 total ceiling and four-hour maximum are **conditional**. Peter already authorized a run when those conditions are satisfied; a second generic go is not required. Readiness conditions remain unmet, so the run stays HELD. The latest runner report relays an operator-reported USD5.40/hour compute quote and a four-hour compute-plus-existing-storage projection of $21.731510768. That projection is not measured spend, a verified private pricing receipt or a complete all-in ceiling check. Older design documents preserve the earlier currency uncertainty and missing-go wording; the latest runner report supersedes that authorization wording. Current provider state, actual shutdown, received-copy export and billing reconciliation remain unproven by this packet.

## Review and provenance

Read each RESULTS file with its local run ledger, input/source hashes, failed attempts and missing-input manifest. First-line MEASURED/SYNTHETIC labels describe the retained evidence; they do not grant independent witness status. Commands printed in archived reports document their original executions, not a request to launch a GPU run.

[`publication-manifest.json`](publication-manifest.json) identifies selected source blobs and the exact published payload hashes. The first 84 files were copied from `43810da533c044cbd6f3c8c375fba47e9f983bb5`; the 35 completed runner files were copied from `1cea929b784c6deba13bb5ce11e90e1e5ffa6ab3`. The 21 baseline-preparation files were applied from the three hash-pinned reference patches ending at `3e0f870f9fa4e008f4410d160b2b9e77bda539ae`, without importing that private Git history. The original 119 payloads remain byte-identical; the aggregate now inventories 140 selected payloads. Active untracked work and private raw provider records are excluded. Publication privacy review is bounded to reachable Git history and these payload bytes; encoded/semantic information, provider caches and image pixels remain outside pattern-scan proof.

First-party source retains AGPL-3.0-or-later. Upstream notices and dependency licenses remain intact in [licenses](../licenses/README.md).
