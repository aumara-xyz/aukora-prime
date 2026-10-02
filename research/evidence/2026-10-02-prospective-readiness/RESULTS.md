Evidence class: MEASURED local inventory/checksums; SYNTHETIC proposed experiment and controls are separately labeled.
Reference only. No inference, training, provider action, deletion or product change.

**Decision: NOT READY FOR H200.** A new prospective experiment is allowed to have a new preregistration; the missing historical gen-19 prediction is not its prerequisite. The smallest near-ready option found is a fixed-weight Laya compatibility smoke test on a fresh synthetic fixture. It would test the runtime and output contract, not historical prediction accuracy, recursion, independently verified governance quality or training improvement. It does not justify an H200 allocation by itself.

## What ran

Exact reproducible command, from this directory: `python3 preflight.py > preflight.stdout.txt`.
UTC start: 2026-10-02T01:45:02.965310+00:00. Measured wall time: **1.374905333 seconds**. Standard-library code inspected named cache files, parsed a bounded safetensors header, read installed package metadata/source as text, and calculated streaming SHA-256 hashes. Archived/model source was not imported or executed; weights were not loaded. Hashing used a 1 MiB buffer, an initial 900,000,000-byte per-file size check and a cooperative 15-second per-file loop check. This is not a hard timeout for blocking I/O or the whole script. The requested priority reduction failed; the process continued at unchanged priority, as recorded. No OS-access workaround was attempted for previously unavailable RAM headroom.

The existing `convaiinnovations/laya` snapshot is `1c5edc17a7acd8701df6fc341c0d179f1c62c982`, not the audited current public checkpoint. Its five expected local files were found and hashed, including the nested encoder and tokenizer metadata. Absence of root-level tokenizer/config files was not treated as incompleteness.

| File | Bytes | SHA-256 |
| --- | --- | --- |
| model.safetensors | 842,609,210 | `891102d372688fc2a094dac56a384bc537b87c63f21f9f3dac0be2b7cbc8d86c` |
| rl_agent_config.json | 745 | `ae287b56bbcf5f8c4f4541ae9dfd00c914c4c48b940b8398c3058af37ba92bbd` |
| encoder/config.json | 2,083 | `bf3ab80598fdccf414855a2ce80f22859e4492d06ca8a62ddd1cfb63972f8979` |
| tokenizer/tokenizer.json | 3,583,228 | `6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30` |
| tokenizer/tokenizer_config.json | 308 | `50044de60daaa73df97d262e15a40d4faf0160e7d742df64b377877a1320dd12` |

The header lists 206 tensors, 421,293,830 parameters and mixed F16/F32 storage; its declared extent matches the file size. This establishes local byte identity and structural extent, not numerical/model compatibility or quality. Named standard cache directories for `convaiinnovations/laya-typed-decisions` and `Qwen/Qwen2.5-1.5B-Instruct` are absent in the bounded check; this is not an assertion about every location on the Mac.

The actual inspected environment is Python 3.9.6, Laya 0.3.4, torch 2.8.0, transformers 4.53.0, safetensors 0.7.0, huggingface-hub 0.36.2, peft 0.17.1 and accelerate 1.10.1. The installed Laya metadata allows Python >=3.8. This differs from the previously audited newer public source, which required Python >=3.10. Package metadata presence is not a successful import/load test. Loader source hashes and relevant calls are in `local-preflight.json`. The loader can mutate tokenizer configuration and has download fallbacks: any future runner must stage mutable metadata inside the lab, use local paths and enforce offline behavior before loading.

A second free command, `python3 verify_sources.py > source-verification.stdout.txt`, ran with `GENESIS_SOURCE_ROOT` bound to the permitted Genesis checkout. That private absolute path is intentionally omitted from the public evidence; the exact source revision and per-file `git show` commands are retained in `source-verification.json`. This check took **0.314907625 seconds**, verified all eight expected source hashes, exported no raw source and executed none of it. Each subprocess command, exit, byte count and wall time is recorded. The two retained preflight commands total **1.689812958 measured seconds**; this excludes earlier read-only discovery and review time.

## Exact readiness gaps and estimates

No qualified H200 training command is supplied because no ready small trainer plus frozen fresh data, environment and scoring contract was established in the bounded source scope. `source-inventory.json` binds eight relevant source/data/planning files to revision `500bb4ba2748c8dc2b816560e6bbd052d300b67e` and exact byte hashes; raw data is not exported. The inspected adapter scripts materialize/validate data and the gen-19 code is a grader, with no inspected optimizer/backward loop. This is a bounded observation, not an assertion that no trainer exists anywhere. Existing archived model experiments do not qualify a new burn. The original locked prediction remains missing, so historical grading stays HELD. No replacement prediction was fabricated.

The Laya weight file is 0.843 GB on disk. A hypothetical FP32 copy of all 421,293,830 parameters requires `421293830 × 4 = 1,685,175,320` bytes, before activations, framework buffers and temporary copies. This is a parameter-storage calculation, **not a measured GPU requirement**. Peak inference/training memory and model duration are UNMEASURED because no load or step ran; training also lacks frozen optimizer, sequence length, batch size and trainer. Available disk measured 33.406 GiB; RAM/GPU headroom and CUDA support remain unqualified. There is no defensible throughput-based duration estimate yet. The measured 1.37-second metadata preflight must not be used as a model runtime estimate.

For the smallest new compatibility experiment: freeze a fresh synthetic fixture and exact local checkpoint/environment; implement a local-only runner that preserves the original cache; qualify permitted memory headroom; measure one bounded load/inference; export raw outputs and errors. Do not label the author-created fixture independently grounded or promote it into training. A concrete new training question would need its own fresh registration and measured smoke step. Neither is registered or run in this directory.

## Window control and cost

Peter's proposed **four-hour maximum (14,400 seconds)** is a planning window, not explicit go or a numeric TOTAL dollar ceiling. There is no obligation to use four hours; stop when the evidence question is answered or a gate fails. The user-quoted $5/hour and historical rates/allocated shapes remain unverified. The older launch sheet contradicts later historical reporting on allocation and rates; a fresh operator quote and provider configuration are required. `$5/hour × 4 hours = $20` is compute arithmetic only, not an all-in quote.

`window-controls.md` records an unexecuted checklist for source/input locks, all-in accounting, capacity stand-down, teardown reserve, partial export on every path, independent stop control and final provider **STOPPED** output. None is qualified by a planning file. No provider action, capacity retry, SSH, pruning, disk/volume creation or deletion occurred. Current provider state, invoices, backups and standing storage remain UNVERIFIED.

Model/API calls: 0. Cloud compute: 0 seconds × $0/s = $0. Downloads/installs: 0. New cloud storage resources: 0, incremental charge: $0. Total **new paid experimental spend: $0**. Existing standing storage, host energy and subscription/agent usage are outside that total, not silently zeroed. See `run-ledger.json`.

Passed: bounded offline file/header/checksum inventory and accurate resource distinctions. Failed/held: priority reduction, unqualified model compatibility and headroom, no runnable qualified GPU trainer/data, no measured model memory/time, no current provider allocation/rate/stop qualification, and no numeric ceiling/go. Verified training corpus remains **0 examples**. Product paths, morning checkout/runtime and the prior Library packet are untouched. The independent-labeling plan remains separate and held; current agents are not blind.
