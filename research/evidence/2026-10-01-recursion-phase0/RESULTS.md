MEASURED: reference-only source inventory and offline tool executions. Numeric scorer inputs are SYNTHETIC. No model evaluation, training, cloud window, or product change occurred.

# Recursion side lab — 2026-10-01 UTC

Phase 0 ran source inventory and three bounded local commands. It did **not** reproduce Jev performance, recover the original dream pool, or create a usable governance corpus. Phase 1 did not run: Peter's new spending ceiling is blank and the window has no explicit go.

All changes are confined to this directory in a separate Prime clone/branch. The canonical checkout remained clean at `9d6c2205af5a05651b9fff7525505fb2ce0e076d` during the work. Nothing was activated, pushed, or published. The code here is newly authored reference tooling, not the missing archived method.

## What ran

Run from this directory: `python3 run_phase0.py`. `run-ledger.json` records exact commands, UTC starts, measured wall times, exits, input classes, hashes and costs. Its named input-lock file hashes the inputs before execution and rechecks them afterward. This local record is not an independent timestamp or public preregistration. Run-number prefixes preserve subsequent raw outputs. Earlier overwritten raw outputs are disclosed in `prior-run-notes.json`; they are a retention defect, not concealed evidence.

| Command | Input | Result | Wall time | Incremental experimental spend |
|---|---|---|---|---|
| `python3 evaluate_offline.py metric-fixture.json` | Synthetic made-up numeric records | Arithmetic validated; one incorrect verdict and one worsening choice retained | 0.034231125 s | $0 |
| `python3 evaluate_offline.py dream-pool-registry.json` | Synthetic missing-input registry; documented refusal names only | Exit 2, `NOT_RUN_MISSING_GROUND_TRUTH`; both real metrics null | 0.030216583 s | $0 |
| `python3 generate_governance_corpus.py --inventory source-inventory.json --output run5.corpus-manifest.json` | Historical reports and source metadata | Exit 2, `NO_VERIFIED_RECEIPTS`; 0 examples, 0 accepted revisions | 0.032537709 s | $0 |

Final run5 wall time totals **0.096985417 s** for the three child commands. Prior execution timings and their retention limitations are recorded separately; all recorded incremental experimental costs are $0. The synthetic arithmetic check yielded risk separation **3.5×**, exact-verdict accuracy **75% (3/4)**, suboptimal choices improved **1/2**, and worsening choices **1/4**. These numbers describe the made-up fixture only. **They are not Jev, Laya, Bonsai or Prime results.** The fixture contains no activation, forgery, authority, memory or cloud operation.

Raw stdout and stderr are retained even for exit-2 outcomes. The generator currently has no receipt acceptance adapter. It is a fail-closed inventory tool, not a completed verified-receipt generator. Flags such as `corpus_eligible` cannot make it accept a source. No training file was produced or used.

## Phase 0 requested lanes

| Lane | Ran / not ran | What blocks the requested measurement |
|---|---|---|
| Dream pool, five original decisions plus new history | **Model run NOT RUN**; missing-input registry prepared | Original five inputs, frozen independent ground truth, original Jev outputs and cost receipts not recovered. Four new case names retained as user-supplied metadata only. No refused case reconstructed. Jev route is paid and has no approval/ceiling. |
| Jev recalibration, twelve old decisions plus refusals | **NOT RUN** | Old twelve examples, exact model ID, frozen labels, prompt and complete outputs absent. **New risk separation: UNMEASURED. New exact-verdict accuracy: UNMEASURED.** |
| Verified governance corpus | Inventory command **RAN**, corpus creation **BLOCKED** | No verified sanitized settle/decline/replay/B1/M9 receipt set supplied. 0 examples; 0 accepted source revisions; 2 inventoried revisions. Historical narratives are not receipts. |
| Riemann / CPU | **NOT RUN** | Existing Riemann method not located in approved source scope. No replacement mathematical demo was substituted. |
| Bonsai local | **NOT RUN** | CLI binaries present, but compatible pack/runtime and memory headroom not qualified. No weights downloaded, packages installed or model loaded. |
| Laya local | **NOT RUN** | Existing cache/venv presence observed; completeness, checkpoint pin and resource headroom not qualified. No inference or tuning. |

The requested `experiments/governed-learning/generate_governance_corpus.py` is missing (404) at the current Genesis pin. Genesis `ARCHIVE.md` records the Sep-27 removal of the experimental tree into a private archive. That archive, private conversations and journals were not ingested. The documented `glm/ingestion` branch was absent from a bounded public branch lookup. New tooling remains here, under `research/evidence/`, in accordance with the lab's path restriction.

## Historical claims and corrections

Pinned source: Genesis `645d3213b8aede3b544269b4224ae09df06b0a42`; exact report blob hashes and links are in `source-inventory.json`. Metadata was read, but underlying run artifacts were not recovered.

- The recursion report corrects the headline to **2/3 baseline-suboptimal points, 4/5 overall, zero worse**. Peter's task names the older 3/5 headline. Neither is a new lab result; no old cost was re-measured.
- The source reports **5.2× risk separation** over twelve recorded decisions. The **41.7% exact-verdict accuracy** supplied in the task is not present in that report and remains unverified here. Both requested new metrics remain unmeasured; neither is omitted or replaced by synthetic arithmetic.
- The Nebius report records about **467 compute seconds and $0.59**, a disk-headroom refusal, no training/inference/model loads and historical provider-confirmed STOPPED. No raw invoice or provider output was recovered. Existing storage burn and **current instance state are UNVERIFIED**; this lab made no provider calls and does not claim a fresh STOPPED confirmation.
- Nine generations, certified laws, backup completeness and the gen-19 prediction lock are **historical assertions not reverified by this lab**. No investor uniqueness or shipped-behavior claim follows from them.

## Laya / Jev and Bonsai source findings

`model-source-audit.json` records exact primary-source revisions, licence facts and file sizes. Laya source is pinned at `4aa6761be8173de4ce6d92c31b3e40b6eaf59a7c`. Laya is an encoder package; Jev is a separate TypeSafe API. Laya's third-party Jev comparisons use differing prompts and sample counts. They do not establish better governance quality for Prime. Source package v0.3.23 requires Python ≥3.10 and the recorded torch/transformers dependencies. Checkpoint cards declare Apache-2.0. Local performance and tuning benefit remain UNPROVEN.

Requested Bonsai repository is pinned at `f10afb355f104535e3e3e98cf7ab7795c72bd292`. Its `Bonsai-27B-Q1_0.gguf` is listed at **3,803,452,480 bytes**, Q1_0_g128, with PrismML's custom llama.cpp kernels required by the card. Generic HF defaults point to the 53,808,280,640-byte F16 file. Neither validates the installed CLI for the compressed pack. The Sep-21 report names a **different ternary Q2/PQ2 pack**, so its 7.59 GB and 9.2 tok/s cannot be transferred to this file. No local weights were hashed or loaded. Nebius hosting, frozen A/B/DIAG results and dojo learning remain UNPROVEN.

## Phase 1 — held

**NOT RUN.** No H200 start, capacity retry, SSH, disk prune, checkpoint deletion, K3, new disk or volume, training burn, Bonsai comparison or shutdown action occurred. The old reported $50 ceiling does not authorize this new window.

Before a future window: Peter supplies a new dollar ceiling and explicit go; the operator supplies exact instance/rate/storage accounting and fresh provider state; verified Mac backup manifests precede any proposed deletion; the original gen-19 preregistration and locked prediction must be recovered. `NotEnoughResources` means stand down. Partial outputs and provider STOPPED reconfirmation remain required on every future execution path. This evidence grants no authority for those actions.

## Costs and remaining limits

Each new offline run recorded 0 cloud compute seconds × $0/s = **$0**, 0 model API calls = **$0**, and no newly created cloud storage = **$0**. Small public metadata/source text was fetched; no model weights were downloaded. Those source reads incurred no experimental provider/model charge. Total **incremental external experimental spend: $0**. Existing storage, host energy and Codex subscription/agent usage are outside that total; existing storage burn is unverified, never silently zeroed.

Exact offline wall times and the total are in `run-ledger.json`; source inventory wall time is UNRECORDED. Source URLs and Genesis blob hashes are recorded, but complete raw source-audit responses, response digests and retrieval wall times were not retained. The metadata audit remains reproducible from its primary-source links, not independently attested by this bundle. Timeout/invalid-output retention handling was added after review but its fault paths are UNPERFORMED. The evidence includes failures, missing artifacts and refusals. Integration into Prime remains pending the single integrator's privacy review. No independent publication or push occurred.
