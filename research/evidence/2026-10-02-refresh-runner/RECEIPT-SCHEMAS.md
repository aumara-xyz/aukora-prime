Evidence class: SYNTHETIC — documentation of required private receipt structure, not qualification evidence.
Reference only. No actual receipt, approval, model result or provider guarantee is supplied here.

# Required input receipts for schema version 1

The fixed private manifest hash binds each receipt's exact bytes through its `inputs` entry. These are the fields checked by `runner_core.validate_manifest` and the supervisor guard. Null or invented measurements do not qualify a trial. The operator must preserve commands, raw measurements and provenance supporting each receipt. Machine-readable booleans can report an authorized decision; they cannot independently prove it.

All real source files and receipts are private operator inputs. Add `evidence_class` and `reference_only` in their first lines. Use `measured` only for records backed by actual executions or actual operator observations; synthetic fixtures cannot satisfy real prerequisites by relabeling them. Baseline receipts may summarize both measurements and authorized decisions, with their respective provenance stated. The code permits extra provenance fields, but required binding objects below must match exactly.

## Baseline: `inputs.baseline`

Required `binding` is the exact object below, with real values substituted:

```json
{
  "parent_sha256": "PINNED_GEN16_ADAPTER_SHA256",
  "parent_config_sha256": "PINNED_GEN16_CONFIG_SHA256",
  "base_file_sha256s": ["SORTED_ALL_BOUND_BASE_FILE_SHA256_VALUES"],
  "tokenizer_file_sha256s": ["SORTED_ALL_BOUND_TOKENIZER_FILE_SHA256_VALUES"],
  "engraving_sha256": "EXACT_7_ROW_FILE_SHA256"
}
```

The parent hashes must equal the pinned hashes in the manifest template. The arrays are sorted lists of SHA values from the manifest's `base_files` and `tokenizer_files`, not filenames or only selected weight shards. Duplicate SHA values for distinct files remain present in those lists. `metrics` must equal the manifest's full fixed metrics object.

The baseline receipt requires `evidence_class: "measured"`; synthetic control fixtures are refused as real readiness. `strict_recall` is exactly seven JSON booleans in engraving source-row order. Rows 0 and 1 cannot both be true for this restoration question. `target_prefix_tokens` is exactly seven measured positive integers, each <=120, under the bound tokenizer and decoding policy. `loss` is exactly seven measured finite, nonnegative numeric parent losses in the same row order. Preserve their actual raw measurements as supporting evidence.

During execution the runner checks the exact generation-prompt/full-supervised token prefix alignment before applying prompt masks. It refuses full sequences exceeding `min(16384, runtime.qualified_context_tokens)`, missing assistant-target loss tokens, engraving generation prompts plus 120 new tokens exceeding the qualified context, target prefixes outside 1–120 tokens, or target encode/decode round-trip differences under the fixed decoding policy. It also checks actual prefix-token counts against the receipt. These checks do not demonstrate model recall.

The fresh baseline evaluation must contain exactly ordered rows 0–6 with matching canonical engraving row-content hashes, boolean recalls and finite nonnegative losses. The runner refuses training if that fresh recall differs from the frozen `strict_recall` receipt or both target rows already pass. Fresh baseline losses are measured and validated; exact numeric equality to the older baseline `loss` list is not required.

## Schedule: `inputs.schedule`

Required fields:

- `status`: `REGISTERED`.
- `quota`: exactly `[50,50,8,8,8,8,8]`.
- `row_indices`: exactly 140 integers from 0 through 6, with occurrence counts equal to `quota`. This full ordered list fixes training order; the quota alone does not.
- `row_content_sha256`: exactly seven row digests in the engraving file's source order.

Each row digest hashes the UTF-8 bytes of `json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":"))`. Hash the complete parsed JSON row, including any extra source fields. This is not the raw line's byte hash. The schedule remains unregistered until the actual row content and entire ordered list are frozen; the template allocation alone does not register it.

## Runtime: `inputs.runtime_receipt`

Required `qualified` must be true. Required `runtime` must equal the manifest's runtime object: exact Python version, exact package versions for `torch`, `transformers`, `peft` and `safetensors`, CUDA version, device `cuda:0` and `qualified_context_tokens`. This qualified context capacity must be an integer >120. The validator compares Python and installed package metadata; the model backend separately checks CUDA and requires the qualified context not to exceed the loaded model's supported `max_position_embeddings`, including nested text configuration if applicable. Qualification evidence must additionally establish the actual model/adapter load, dtypes, GPU memory, bounded step duration, checkpoint save/reload, context sufficiency for the bound rows and available storage under this runtime. Those facts cannot be replaced with the mere existence of packages or a model card's maximum context claim.

## Pricing: `inputs.pricing_receipt`

Required `currency` is `USD`. Required `verified_hourly_rate_usd` and `unavoidable_costs_upper_usd` must exactly match the manifest's approval fields. The operator/parent report official-source confirmation of USD 5.40/hour H200 compute, effective October 1, from [Nebius prices](https://nebius.com/prices); the prior reported currency-source ambiguity is resolved. Their four-hour compute plus two existing H200 storage base charges projects USD 21.731510768 before other charges and reserve. This projection is not measured spend, an invoice or an all-in confirmation. This lab made no external pricing request in updating these documents.

The actual private priced receipt is still required and must bind the applicable intended resource/window rate, source date and charge scope. Supply a conservative upper bound for unavoidable storage, transfer, API and other costs and state which standing costs the window includes. The validator uses these bounds to constrain the provider deadline under USD 30; it cannot establish the correctness of a rate or reconcile an invoice.

## Independent supervision: `inputs.supervisor_receipt`

Required fields:

- `armed`: true.
- `provider_stop_responsibility_acknowledged`: true.
- `session_id`, `controller_identity`, `run_id` and `provider_deadline_utc`: exactly match the corresponding manifest values.

Both `session_id` and `controller_identity` must be nonempty strings. Provide the independently running supervisor's actual identity and operational proof separately. It owns provider stop outside the training process and must handle a blocked worker or machine/network failure. These fields acknowledge responsibility; they do not guarantee shutdown. The provider deadline must fit both the affordability bound and the approved window; a >=1,200-second teardown reserve is retained by the runner.

### Dynamic heartbeat: `supervision.heartbeat_file`

This liveness file is deliberately updated, so its changing bytes are not a static input SHA binding. Its path must be a regular nonsymlink file of at most 1,048,576 bytes; path ancestors also cannot be symlinks. The supervisor writes actual `session_id`, `controller_identity`, `run_id` and `provider_deadline_utc`, all matching the manifest, plus `armed: true` and `updated_at_utc` with a timezone. `stop_requested: true` requests interruption. The guard rejects a mismatched/unarmed heartbeat, an update more than five seconds in the future, or an age exceeding the registered positive `heartbeat_max_age_seconds` (at most 60). Use atomic supervisor updates and retain an independent event log. Failure to read or parse the file is not permission to continue.

The runner performs cooperative checks between operations. It cannot interrupt a hung GPU call, blocked model load or unavailable host solely through this file. Qualify an independent controller capable of terminating the worker and stopping the existing provider instance; do not infer those capabilities from a heartbeat JSON alone.

## Data eligibility: `inputs.data_eligibility_receipt`

Required `approved_for_this_research_training` and `no_private_conversation_ingest` must be true. Required `corpus_sha256` and `engraving_sha256` must exactly match the manifest's two pair-file hashes. Supply the actual authorized data review and provenance; no verified training-corpus promotion follows from this receipt. The pair files must respectively parse as 146 and 7 JSON objects, each with a nonempty string `prompt` and nonempty string `chosen` (or `completion`). Private text remains outside the public reference packet.

## File inventory and freeze

`inputs.runner_files` binds the actual `runner_core.py` and `refresh_runner.py`, exactly two source paths. The real base/tokenizer roots must have every file hash-bound: bound inventories must equal the directory contents, with no extra files or symlinks. Files ending in `.py`, `.bin`, `.pt`, `.pth` or `.pkl` are prohibited; model weights use safetensors. The base inventory requires `config.json` and safetensors weights. The parent-adapter directory must contain only `adapter_config.json` and `adapter_model.safetensors`; even an extra README causes refusal. Complete model/tokenizer inventory and load qualification remain operator responsibilities; hashes alone do not certify identity or compatibility.

Freeze the final manifest and receipts before the new trial begins. `trial_training_not_yet_run_ack: true` refers to the trial, allowing earlier authorized baseline/smoke qualification to produce required receipts. Neither a newly typed receipt nor hashing an already observed outcome makes the old analysis prospective. `--validate-only` still requires a REGISTERED manifest, verified USD budget inputs, an active bound supervisor and all required hashes; it does not import PyTorch or load a model. The UNREGISTERED template is expected to refuse. Only `--execute` additionally requires `approval.explicit_go: true`. That flag records satisfied readiness under Peter's existing conditional run-when-ready authorization, within USD30 all-in/max4h; it is not a request for another generic go. Keep it false until every specified condition is met. New permissions, resources, data or model scope remain subject to the applicable approval. No runner file calls a provider API.

## Produced evidence and completeness

Each completed evaluation row produces a private partial receipt with `row`, `row_content_sha256`, `loss`, `strict_recall`, the legacy substring diagnostic and raw generated text. It is marked `partial_evaluation_group: true` and `checkpoint_binding: "UNBOUND_UNTIL_GATE_CHECKPOINT_SAVED"`. A row receipt proves neither whole-seven-row gate completion nor a saved checkpoint. Both fresh baseline and gate validation require exactly ordered IDs 0–6, canonical row-content hashes, strict boolean recall and finite nonnegative numeric losses. A completed gate's interim evaluation likewise remains unbound until the save succeeds; the finalized `gate-epoch-N.json` supplies checkpoint file hashes. Required saved adapter weights and configuration must be nonempty regular nonsymlink files. Preserve all partial receipts when interrupted or failed. Native `adapter_model.safetensors` and `adapter_config.json` retain their model formats; `artifact-label.json` supplies the evidence label as a sidecar.

Terminal writes to `outcome.json`, `stop-request.json` and `run-state.json` are independently attempted, followed by separate best-effort writes of `finalization-status.json`, per-run `RESULTS.md` and the local export manifest. `finalization-status.json` records model-protocol status and terminal-write errors known before those later attempts; it cannot anticipate later failures. The export manifest also includes `local_finalization_errors` known before its own write. Returned `model_protocol_status` preserves the model gate result. Returned overall `status` becomes INCOMPLETE if finalization errors occur or local export hashes are incomplete, including after a model-protocol PASS. Earlier saved model outcomes and `export-manifest.json.worker_status` use model-protocol scope; retain returned stdout to preserve the later completeness decision.

The generated `RESULTS.md` is best effort and records exact `command_argv`, wall time at terminal model-protocol state, completed updates/gates, protocol status and errors already observed. An injected synthetic control fixture has no real CLI vector and must use its outer capture receipt instead. Cost, provider shutdown and transfer completion remain explicitly pending the operator's ledger and receipts. Record final window/export/shutdown timing independently rather than treating the pre-export protocol timing as all-in elapsed time. A `RESULTS.md` write failure contributes to local finalization errors; no public evidence integration is complete without a reviewed results file.

The local export manifest reports existing file names/hashes, hash errors and `complete_hash_manifest`. `local_export_manifest_confirmed` reports only that a local manifest was written; `local_export_hashes_complete` and `local_finalization_errors` determine local completeness. Transfer, Mac copy verification, provider STOPPED and actual all-in cost remain separate operator obligations. Finalization is best effort: expired deadlines can leave hashes unfinished, and process/host/network failure can prevent local receipts entirely. A local stop request is not a provider stop action or guarantee.
