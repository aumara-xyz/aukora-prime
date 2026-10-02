Evidence class: SYNTHETIC proposed run and schedule; MEASURED static source/receipt inspection is separately labeled.
Reference only. New design is DRAFT, UNREGISTERED, UNEXECUTED and HELD. No product authorization.

A real trainer was recovered: `aukora-lab/train_burn18-hybrid.py`, SHA-256 `5db86fcf16433ef6fef6568be7fe83e555570c37b98b615b05de21664dabc5ee`. Its AdamW/backward loop supplies a concrete basis for a **new prospective Gen16 continuation case study**. This supersedes the earlier bounded search's missing-trainer observation; it does not prove which script historically executed a burn. The original gen-19 locked prediction is still missing. No replacement prediction was made, and the draft's hypothesis is human-authored.

## New design

Use only the operator's pinned Gen16 continuation: **1,107,347,624 bytes**, adapter SHA-256 `ed8b316728368f73f670485eaf2bac09126585e68f17e50dd48cb4c9b9ee1dac`, config SHA-256 `38e08fda482a14a20d1f294b0da71ce1d0b930323fa2db9ba761e84cca18c1be`. `operator-input-summary.json` derives sanitized metadata from the operator receipt, whose own file hash is retained. This lab did not repeat checkpoint hashing or load tensor values. Valid header extent and local hashes are not successful model-load evidence. Adapter configuration records PEFT writer version 0.20.0; the intended remote environment must be qualified independently.

`preregistration-DRAFT.json` proposes a single seeded targeted-refresh trial. Preserve a budget of 140 engraving exposures per epoch (`7 × REPEAT=20`), and allocate **[50,50,8,8,8,8,8]** to rows 0–6. Target rows 0/1 receive 100/140 = **5/7**, versus source uniform 40/140 = **2/7**. The exact vector is a new design choice, not an old locked parameter. The acceptance note's rows-0/1 direction supports exploring the knob, without proving this vector best. The deterministic index schedule is saved and hashed in `row-schedule-DRAFT.json`; actual row contents/hashes are not yet bound.

There are 146 corpus + 140 engraving updates per complete epoch: **286**, with **858** minimum at three epochs and **1,716** maximum at six. Overall engraving **step share is 48.95%, not 22%**; no token-share or equal-compute claim follows. The proposed order retains actual corpus-first source ordering, then a specified balanced engraving schedule. Source comments saying engraving-first do not describe the inspected implementation.

The new gate deliberately differs from the old gate: evaluate assistant-target loss separately on **all seven** rows after a full epoch, require finite maximum raw loss <=0.001, and require all seven strict character-prefix recalls after at least three epochs. Each recall uses a nonempty target `chosen.strip()[:240]`, greedy generation capped at 120 tokens, and `generated.strip().startswith(target)`. This is **character-prefix recall of repeated training answers**, not byte equality, complete-answer equality or heldout generalization. Before registration, qualify target reachability within the generation cap and bind decoding/tokenizer policy. Preserve legacy substring recall as a secondary diagnostic only.

Record the seven-row Gen16 baseline first. If both target rows already pass the new metric, this restoration question does not justify training; revise/register a different question. Previously passing protected-row regressions fail the trial. First fully passing completed gate at epoch >=3 is selected; wall/budget interruption is INCOMPLETE, never success. Without a separately preregistered matched comparator, targeted-refresh causality remains UNPROVEN. No independent labels, verified governance corpus or machine forecast is supplied by this plan.

## Why the recovered trainer must not be launched unchanged

- Default output overwrites `gen-17`; the fixed burn-18 receipt is overwritten even when checkpoint OUT is changed.
- The gate uses the last 100 online engraving losses, not post-epoch evaluation of all seven examples; substring occurrence is weaker than exact start recall.
- The 80-minute clock starts after model load/encoding, is checked between steps, and does not bound generation, saves, export or lifecycle reconciliation.
- Gate receipts are retained in memory until the final write. A cut-short epoch has no gate checkpoint. There is no qualified exception-safe partial export or independent provider stop.
- Saved adapters omit optimizer/scheduler/RNG state and do not qualify a resumable training checkpoint.

A **new isolated runner remains to be implemented and hashed**. It must reject existing output roots before loading; route every receipt, checkpoint and log to a unique new run directory; persist gates incrementally; enforce local-only, hash-bound loading; reject empty/truncated targets; and obey an outer paid-window deadline with export/stop reserve. No runnable training command is offered while that runner and its input/control bindings are missing. The original script was never imported or executed here.

## Resource, budget and access holds

Parent relayed Peter's conditional **$30 maximum TOTAL / four-hour maximum**. Explicit start go is still absent. The draft proposes a shorter controller ceiling of two hours: up to 20 minutes setup/smoke, 80 minutes training including gates/saves, and 20 minutes export/stop reconciliation. These are proposed maximum allowances, **not measured duration estimates**. Actual deadline must be reduced to fit verified all-in pricing and reserve, and measured from provider billing start. Stop earlier when the question is answered or a gate fails.

Base model identity/revision/shard hashes, tokenizer/template hashes, both pair-file hashes, stable row mapping, remote runtime/CUDA lock, peak GPU memory and throughput remain missing. Generic `base-weights` is not model identity; no replacement model is silently permitted. The operator initially reported denied SSH before connect; this lab made no retry or alternative access attempt. After Peter completed manual login, the operator reported a fresh **STOPPED** read for the existing `1gpu-16vcpu-200gb`, `gpu-h200-sxm` instance, with an existing 200 GiB NETWORK_SSD boot disk and secondary disk. This baseline state is not end-of-run shutdown confirmation. Current pricing, free space, scheduling capacity and independent stop control remain unqualified. `NotEnoughResources` means stand down without retries.

At the parent adapter's size, seven adapter-only saves would occupy **7,751,433,368 bytes**, plus **1,107,347,624 bytes** for an atomic-write temporary copy. This is planning arithmetic, not measured future output size; it excludes optimizer/RNG, base/tokenizer, metadata/logs and export duplication. The interrupted trial is not authorized to resume. Verify adequate free space on an existing permitted volume against actual smoke-save size and margins. No K3, new disk/volume, pruning or deletion is proposed.

The operator's latest calculator relay gives hourly quote units 5.4 compute + 0.0194444 boot + 0.013433292 secondary storage, or **21.731510768 units over four hours before transfer/API/other charges**. Currency is absent in the supplied JSON; USD and invoiced cost are NOT established. Do not report this as $21.73 all-in or as spend. The operator inventories an existing 200 GiB boot and 186 GiB secondary disk; capacity is not available free space. CPU Prime remains RUNNING under its existing work, and historical jobs/object storage are not touched. Define and log ongoing cost scope alongside experimental charges before an all-in dollar deadline is qualified.

Raw model outputs would first export privately to the operator's Mac with hashes; public reference integration requires H's privacy review. Partial receipts/logs must export on every path, with missing checkpoints recorded honestly. Final shutdown requires fresh provider output confirming **STOPPED**, plus an all-in cost ledger. Neither exists for this proposed run.

## What actually ran and cost

From this directory:

| Command | Measured wall time | Input/output type | New paid experimental spend |
| --- | --- | --- | --- |
| `python3 inspect_trainer.py > trainer-inspection.stdout.txt` — initial retained run | 0.016386958 s | Static source metadata, MEASURED | $0 |
| Same command after helper privacy correction | 0.009122167 s | Static source metadata, MEASURED | $0 |
| `python3 build_schedule.py > schedule.stdout.txt` | 0.002627875 s | Proposed schedule SYNTHETIC; local telemetry MEASURED | $0 |

Initial static stdout and ledger are retained as `prior-static-*`. `review-corrections.json` records helper-path sanitization, target reachability/baseline requirements, and checkpoint-estimate clarification. Total retained command time: **0.028137 seconds**; discovery, receipt reading and review time are outside that sum. The operator's separate checkpoint hash took 2.554817125 seconds per its receipt; it is not this lab's run.

Each local command: 0 cloud seconds × $0/s = $0; 0 model/API calls = $0; 0 new cloud storage resources = $0. **Total new paid experimental spend: $0.** Standing storage remains UNVERIFIED; host energy and subscription/agent usage are excluded, not silently zeroed.

Passed: real training loop identified; source hazards and actual metrics recorded; new schedule arithmetic independently checked; verified-parent metadata consumed without repeating heavy work; draft clearly separated from historical grading. Failed/held: safe runner, exact model/data locks, target reachability and baseline, resource estimates, current provider access/state/rate and independent stop qualification. No H200 start, checkpoint overwrite, source execution, model load, disk action, training, provider call, product edit or Library upload occurred. The earlier packet remains frozen. Candidate-model fit is a separate source-only note; different models cannot silently replace this continuation's base.
