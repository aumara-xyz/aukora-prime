Evidence class: SYNTHETIC — new source and injected CPU controls; no model-training or provider result.
Reference only. Native model files produced by a future authorized run must retain their format and use the checkpoint's classification sidecar.

# Research runner source checkpoint

Implemented a new, isolated Gen16 continuation runner. The source never imports or executes the archived trainer. The actual CUDA backend is lazy and was not instantiated. No PyTorch, Transformers, PEFT or safetensors module was imported during these checks. No model download, model API call, training, provider action, disk/volume creation, pruning or product edit occurred.

The manifest template remains **UNREGISTERED**, with missing real inputs and `explicit_go: false`. Its proposed allocation `[50,50,8,8,8,8,8]` is a draft, not a frozen experiment. No machine prediction is graded. The original locked historical prediction remains unavailable.

## What the source implements

- Exclusive new output directory; existing output refuses before backend construction. No original generation or receipt path is reused.
- Fixed manifest SHA, actual runner-source hashes, pinned Gen16 adapter/config, all-file base/tokenizer inventories, approved pair-file hashes, frozen schedule and private qualification receipts.
- Timer beginning before parsing/validation/load/encoding. Cooperative budget, wall and heartbeat checks; separate external controller interface for actual provider stop.
- Local-only safetensors loading without trusted remote code. Runtime and qualified context-capacity checks; exact prompt-token alignment and target-prefix round-trip checks.
- Fresh seven-row parent evaluation before updates, strict finite nonnegative losses, boolean recalls and row-content hashes; post-epoch gate under the same policy.
- Partial row receipts, per-update events, per-gate adapter checkpoints, expected nonempty adapter weights/config and checkpoint hashes. Adapter-only saves do not authorize resume.
- Independent best-effort terminal writes, per-run RESULTS.md, durable finalization errors, local export hashes and explicit interrupted/incomplete states. Model-protocol PASS is separate from export, cost and shutdown completion.

The strict recall policy is a Unicode character prefix: generated text, after strip, starts with the first 240 stripped target characters, under a 120-token generation budget. It is not byte equality, full-completion accuracy or generalization. The archived substring diagnostic is secondary only. The criterion requires all seven post-epoch losses <=0.001 and seven strict-prefix recalls after at least epoch 3; this is a new criterion, not an assertion that the old run met it.

## Commands and retained outputs

All commands ran from this directory on the Mac CPU, without model libraries. Capture receipts preserve the actual interpreter argv and hashes of the source at each successful attempt.

| Attempt | Exact command | Captured wall seconds | Result |
| --- | --- | ---: | --- |
| 1 | `python3 synthetic_control_checks.py > synthetic-checks.stdout.txt` | UNRECORDED | Fixture failed before backend creation: a symlinked temporary-path ancestor was refused. Sanitized failure transcription retained; complete original stderr/source bytes were not retained. |
| 2 | `python3 capture_synthetic_checks.py` | 0.208786458 | 14 injected checks passed. |
| 3 | `python3 capture_synthetic_checks.py` | 0.28310175000000004 | 19 injected checks passed after static-review fixes. |
| 4 | `python3 capture_synthetic_checks.py` | 0.27161966699999995 | 19 injected checks passed with per-attempt result capture. |
| 5 | `python3 capture_synthetic_checks.py` | 0.201801625 | 19 injected checks passed with bounded capture and source/template hashes. |
| 6 | `python3 capture_synthetic_checks.py` | 0.876984417 | 19 injected checks passed after the authorization wording correction; execution behavior unchanged. |

Each `synthetic-checks-runN.receipt.json` records source hashes, exit code, wall time, stdout/stderr sizes and cost scope. Label headers were added to captured stdout/stderr; runner-directory paths would be sanitized in stderr. Empty stderr files are retained and labeled. Attempts 4–6 also retain complete per-attempt result tables; `synthetic-check-results.json` is the latest table. Attempts 2 and 3 retain their counts/stdout and source hashes, but their earlier full tables were not separately archived. The failure in attempt 1 is not hidden by later passes.

The 19 latest checks cover unregistered and wrong-hash manifests, existing-output preservation, synthetic checkpoint binding, loader failure, timer including load, partial-update interruption, save failure, invalid baseline, independent first/terminal write failure handling, durable failure metadata and RESULTS.md, three malformed gates, missing checkpoint weights, input hash mismatch, stale heartbeat and absent supervisor identity. All model behavior is injected. Fake clocks simulate deadlines; no GPU timing, resource qualification, real manifest acceptance or trained-model recall was tested.

`python3 verify_source_packet.py` performs standard-library AST/JSON parsing, first-lines classifications, file hashes and a limited private-path/key-marker scan of immediate packet files. Its exact wall time and inventory are in `source-packet-checks.json`. This is a limited source check, not exhaustive privacy review or installed-app validation. `git diff --cached --check` validates the staged patch format before commit.

The first packet scan failed on its own generic path-marker literal, a scanner false positive (0.012872542 seconds). The original failed scan is retained as `source-packet-checks-run1.json`. The pattern was narrowed to actual user-directory syntax and actual private-key headers; no actual private path was found in that failed scan. Subsequent scans are numbered rather than replacing failed evidence.

## Cost ledger

For attempts 1–6: new experiment cloud compute seconds **0** × cloud rate = **$0**; model/API calls **0**, therefore model/API pennies **$0**; new disks/volumes **0**, therefore incremental resource-creation charges **$0**. No paid model/provider operation occurred. The first failed attempt has unknown wall time; that uncertainty is retained.

Standing storage charges, local electricity and agent/subscription usage were not queried or priced and are **UNVERIFIED/excluded** from this experiment-spend statement. It is not an account invoice or a claim of zero standing burn.

**Total new paid experiment spend: $0.** Actual future all-in spend requires the operator's ledger; the runner does not reconcile billing.

## Held work and what remains UNPROVEN

No real training, baseline, CUDA qualification, Bonsai load or Jev API evaluation ran here. The strict verified training corpus from the earlier reference lane remains empty; these fixtures are not corpus promotion. Phase 1 remains **HELD** because readiness conditions are unmet. Peter already directly authorized a run when ready under USD30 all-in/max4h; no additional generic go is needed after every specified condition is satisfied.

Real base/tokenizer identity and full inventory, eligible private pair files, measured baseline, runtime compatibility/dtypes/memory/throughput, checkpoint save/reload, actual free space, all-in cost bound, independently qualified controller/stop/export mechanism and billing start remain operator prerequisites. The unchanged `explicit_go` field records that the existing conditional authorization is ready to apply; it stays false while conditions remain unmet. A filled JSON acknowledgment does not independently prove these facts. Materially new permissions, resources, data or model scope still need the applicable approval. No operator-private manifest was imported into this packet.

This authorization wording corrects the initial cb57b01 handoff's statement that another generic start go was missing. The hold remains correct. No feature scope or execution was added by this correction.

The operator reported official USD5.40/hour pricing confirmation and a four-hour compute-plus-existing-storage projection of $21.731510768 before other charges and reserve. The draft still requires a verified private pricing receipt; that projection is not measured spend or a complete all-in ceiling check.

Provider **STOPPED at the end**, network export, received-copy verification and host/network-failure recovery remain **UNPROVEN**. This runner performs no provider action. A heartbeat and stop-request file acknowledge a separate controller; they do not prove it can stop the instance. Cooperative Python checks cannot terminate a blocked GPU call. Local finalization/export is best effort and may fail if the process, machine or network fails. Failures must be retained by the independent operator, including when the worker cannot write a receipt.

No improvement, matched-comparator advantage, historical prediction hit, investor valuation, product behavior or automatic authorization follows from this source checkpoint. H must privacy-review the reference-only source patch before integration/publication; no push or Library replacement occurred.
