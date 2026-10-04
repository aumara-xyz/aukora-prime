# Nebius Lab: Ornith, ARC-AGI-3 and learning from consequences

Research update, **4 October 2026, 07:45 UTC / 15:45 UTC+8**. This is a dated evidence snapshot; ongoing experiments may have advanced since publication.

**The clearest result so far is a modest, replicated Sokoban improvement in Ornith, plus two replay-verified clears of one public ARC3 level in separate agent runs.** A separate 1.9-million-parameter policy/value network also improved substantially through self-play. These are three different findings, with different models, evaluators and limits.

Ornith is **Ornith-1.5-35B-A3B: approximately 35 billion total parameters and 3 billion active parameters**, a mixture-of-experts model. Calling it a dense 3B model would misstate both its capacity and its memory requirements. The ARC3 run configuration identifies model revision `10fbf86fed7ecee4a061f8b499a618f46001cac1`, BF16 vision inference and vLLM 0.30 on one H200.

## Evidence and scope

The [sanitized evidence digest](evidence/NEBIUS-LAB-2026-10-04.json) contains selected numeric fields from the local receipts and SHA-256 hashes of the inspected source records. It excludes credentials, infrastructure identifiers, private paths, held-out puzzle contents, game-specific solution traces and human baseline counts. These summaries support inspection of the reported results; they are not a complete independent reproduction package. Hashes identify bytes and do not independently establish correctness.

**RAN** means an execution is recorded in the retained evidence. For the original GPU experiments and replays, this publication inspected existing receipts; it did not rerun those experiments. **SOURCE-ONLY** means implementation exists without the corresponding live result. **UNPERFORMED** means the claimed experiment or qualification has not been established. **CLAIMED** denotes an assertion without supporting evidence in this review. Statistical values below are reported from the receipts, not newly recomputed from raw per-board data.

This lab report concerns model and harness research. It does not change the [AUKORA product status](../README.md#status), establish runtime containment or qualify an installed application. The earlier [research report and historical evidence archive](https://github.com/aumara-xyz/aukora-prime/blob/review/nebius-lab/research/NEBIUS-LAB.md) remain available. Statements there that GPU work was held describe the October 1–2 snapshot, not current operations.

## Ornith: what improved, and what did not

The principal Ornith training experiments used 8×8, two-box Sokoban, with environment/simulator verification. Evaluation puzzles were held out from training. Multiple samples per board are correlated, so attempts are not independent boards; the reported paired tests compare boards.

| Experiment | Recorded result | Interpretation and limit |
| --- | --- | --- |
| **REP1: v7 versus base, second held-out set** | **256/1,152 → 306/1,152 solved attempts; 22.22% → 26.56%; +4.34 percentage points.** 144 boards × 8 samples; 53 boards improved, 32 worsened; one-sided p=0.0147. Primary PASS. | The strongest replicated Ornith learning result. One training generation, one game family. The v7 recipe included verified trajectories and consequence-prediction practice; this does not isolate prediction practice as the sole cause. |
| V7 original evaluation | Base 132, gen1 159, v7 164 solved attempts out of 576. **Primary v7 > gen1 failed**: 43 boards up, 38 down, p=0.328. | The secondary v7 > base result, p≈0.019, was encouraging but involved multiple comparisons. REP1 subsequently tested v7 > base as its primary hypothesis. No demonstrated compounding improvement over gen1. |
| WMC: interactive feedback | Single-shot 69/288 versus interactive 116/288; p=0.000003. At a matched 16k token budget, interactive achieved **50/288 versus 69/288**, failing the improvement test. | Feedback helped with a larger reasoning budget; the unmatched run used roughly 3–4× the tokens. No demonstrated token-efficiency advantage. |
| V9: imitate winning interactive turns after removing guidance | **136/288 for v7 → 88/288 for v9**; 12 boards up, 53 down. Tokens per solve 53,214 versus 53,227; both primary goals and the band guard failed. **NO_PROMOTE.** | A substantial negative result. Removing guidance from teacher-influenced examples did not create a better learner. Matched-16k counts were 90 versus 77. This motivates learner-observable training targets; it does not prove all imitation training fails. |
| Earlier format improvement | Strict scoring rose from 11/128 to 22/128 in an early comparison. Later format-independent counts were base 96, gen1 77, gen2 102 out of 512; the registered improvement tests failed. | Much of the apparent early gain was output-format learning. The later generation also had documented hint leakage into training targets. These results do not establish robust planning improvement. |
| Forced answers and prompt hints | Forcing answers rescued **0** additional solves: 89/512 before and after, with 229 truncated outputs. A separate hint prompt reduced solves from 89 to 73/512. | Negative exploratory evidence. A forced valid-action fallback remains useful for harness reliability; that is a separate claim from better solving. |

The earlier report also records System-1-guided collection wins of 741/1,280 versus 206/640 unguided. Those used different puzzle pools and are exploratory, not a matched causal comparison or a held-out improvement claim.

## Separate small network: self-play and search

**Sob-Zero is a separate 1.9-million-parameter policy/value CNN, not Ornith.** The 1.9M figure counts parameters, not training examples. It operates on 10×10, four-box Boxoban/Sokoban with search. It started from a supervised checkpoint; the subsequent self-play phase used environment outcomes without solver labels.

| Experiment | Recorded result | Interpretation and limit |
| --- | --- | --- |
| Sob-Zero on Mac | Starting checkpoint 551/800 (68.9%) to selected champion 688/800 (86.0%). | Multi-generation improvement within this game family. Use the selected champion, not the best intermediate evaluation, as the principal result. |
| **Sob-Zero on H200** | **551/800 → 752/800: 68.9% → 94.0%**, final champion generation 23, search budget B=200. 207 newly solved, 6 lost; reported one-sided p≈9.45×10⁻⁵⁴. | A strong within-family result for this small network plus search. It reused the Mac seed and evaluation sets, with a larger training budget; it is not an independent-seed replication. Mean solution length rose 34.9→38.3 and mean seconds 3.85→4.3, so solve-rate improvement did not imply improvement on every metric. |
| Dream-style search tuning with frozen network | **688/800 → 718/800: 86.0% → 89.75%**; 36 newly solved, 6 lost; p≈1.41×10⁻⁶. Expansions per solve 9,096.5→2,644.0, about 3.44× fewer. | A planner/configuration gain, not a weight-training gain. Configurations were selected using recorded searches and a gate, then evaluated. One seed and the same game family. |

The Sob-Zero registration separates training and gate data from the 800 evaluation levels, but also reports evaluation rates across generations. The same evaluation set was reused across research stages. Treat this as training-disjoint, within-family evidence; repeated feedback makes it unsuitable for a claim of untouched, one-time generalization across the entire research programme. The very small p-values do not remove this selection and reuse limitation.

A predecessor supervised CNN was reported as reaching 98.3% best-move accuracy and solving 200/200 fresh puzzles with search. That figure is retained here as **historical, reported evidence from the earlier report**; its underlying receipt was not independently re-audited for this update. It is not self-play evidence.

## ARC-AGI-3: verified progress on public development games

The custom curious-observer harness uses observations, available actions, level counters and state, with its own play notes, hypotheses and optional learned simulator. It is not automatically an official benchmark Standard or ProviderAdapter configuration. These runs are public-game development work, not an official ARC3 score or a private benchmark submission.

The first input-format comparison, ARC3-1b, tried five recent images, one recent image and a text grid on LS20 and TU93. All six 150-action runs recorded zero levels cleared.

### Completed ARC3-2 comparison

| Public game | Arm | Recorded levels | First-clear action | Stored-sequence replay |
| --- | --- | ---: | ---: | --- |
| LS20 | CUR, curious observer | **1** | **38** | **38/38 frame hashes matched; zero mismatches; level trace matched** |
| LS20 | CURSIM, simulator enabled | 0 | — | No clear to verify |
| TU93 | CUR | 0 | — | No clear to verify |
| TU93 | CURSIM | 0 | — | No clear to verify |

Each job used a 150-action cap. The LS20 CUR run continued after its first clear but did not clear level 2. The later board transition exposed stale object IDs and routes. Across both games, CUR used 247 LLM calls and no simulator calls; CURSIM used 255 LLM calls and 48 simulator calls. Mean seconds per action were approximately 32.67 and 43.04 respectively. There were no accepted simulator plans in this comparison. This is no evidence of a simulator advantage.

### ARC3-3 partial snapshot

The ongoing design covers eight public games in two chains, a library per arm, two primary arms, and a separate no-library control: **24 planned jobs**. The local watcher recorded **five completed summaries at 07:44:53 UTC**. The batch was still running; missing results must not be counted as failures or successes.

| Public game | Arm | Actions used | Recorded levels | Replay evidence |
| --- | --- | ---: | ---: | --- |
| LS20 | CUR3 | 150 | 0 | — |
| LS20 | **CURSIM3** | 150 | **1, at action 44** | **44/44 frame hashes matched; zero mismatches; level trace matched** |
| TU93 | CUR3 | 150 | 0 | — |
| LS20 | CUR3, no library | 150 | 0 | — |
| TU93 | CUR3, no library | 150 | 0 | — |

Six other jobs had begun in the last inspected progress snapshot; the rest remained queued. No complete eight-game comparison is available yet. ARC3-3 adds explicit level-clear notification, refreshed board IDs and inherited mechanics presented as low-confidence hypotheses. The shared-library and no-library results are incomplete and do not establish a transfer benefit.

The new clear occurred in a simulator-enabled arm, but **that does not establish that a simulator caused it**. Its recorded clear action came from the model's commit path; the summary's best simulator failed its acceptance gate, and no executed simulator-plan counters were recorded. The job logged 116 LLM calls and 20 simulator calls.

These are **two successful closed-loop agent runs, under different harness versions, on the same public level**, followed by stored-action replays. The replays start fresh environments and check the recorded outcomes; they do not ask the model to solve again. They establish reproducibility of those action sequences. They do not establish reliability across seeds, fresh closed-loop replication under one frozen configuration, generalization to unseen games, a complete game clear, or a benchmark percentage. The historical replay receipts check post-action frames and level traces; initial-frame checking is added in the new replay implementation.

## Next experiment: predict before acting

The working hypothesis is that predicting an action's consequences can improve state tracking and provide environment-labelled learning targets. It is motivated by the Sokoban results, especially the v7 recipe and the failed guidance-removal experiment. A causal demonstration that prediction training is the decisive ingredient remains **UNPERFORMED**.

ARC3-4 separates three arms using the same model and fixed per-call budgets:

1. **CONTROL4:** control harness.
2. **PREDICT4:** predict consequences before acting and record the actual transition.
3. **FEEDBACK4:** the prediction mechanism plus feedback about prediction errors.

The bounded development pilot is six sequential jobs across LS20 and TU93, capped at 40 actions and three resets per job. It has a three-hour extension budget, with work stopped before the end to allow cleanup. No weights are updated and no simulator or shared learned library is used in this pilot. It is a diagnostic pilot on known development games, not the unseen-game evaluation.

**RAN, offline only:** 18 synthetic correctness checks and seven synthetic launch/queue checks passed using mock transports/services. These cover action-bound predictions, board-epoch invalidation, transition recording, replay checking and bounded launch behavior. They include no Ornith inference and demonstrate no model-performance gain. **SOURCE-ONLY for the live experimental path:** the pilot was queued behind the current runs at this snapshot and had no live result yet. Source and preregistration hashes are retained in the digest. The proposed 4,000-token input capsule is not implemented; it must not be confused with a reasoning-token budget. Macro continuations are explicitly unscored, and the training export is canonical transition data rather than a finished tokenized training corpus.

After the harness is reliable, the intended training target is the actual next observation or object change from the learner's own action, not a frontier model's hidden explanation. A future learning experiment must lock game-family splits, training budget, weights, harness and evaluation criteria before opening the test results. Include a no-transfer control, freeze the learned library before testing, and record all attempts, failed calls, fallback usage, tokens, elapsed time and idle GPU cost. Compare better weights with a frozen harness separately from a better harness with frozen weights. A faster-adaptation claim requires learning curves on previously untouched families; replaying a known sequence cannot establish it.

## Fair play, costs and remaining evidence

The research protocol permits frames, available actions, level counter/state, public general documentation and the agent's own play-derived notes, hypotheses and simulators. It excludes game source, outside game-specific hints or copied solutions, and human baseline counts in the agent context. This is the operating rule, not a claim that publication independently audited every historical prompt. Public games used repeatedly for development are not held-out games.

The earlier operator report estimated October 3 spending at approximately $51 GPU plus $11.48 external API, and recorded provider STOPPED at that day's end. The working compute estimate is $5.40 per GPU-hour; the approved three-hour pilot extension therefore estimates $16.20 of compute. These are reported estimates, not a reconciled current invoice or complete all-in cost. Current experiments were still active at the snapshot. The completion controller must confirm the provider's **STOPPED** state; guest shutdown alone does not establish that billing ended. Authentication or control-plane failures can prevent a nominal wall-time cap from being a guaranteed billing cap.

The October 1–2 archive also retains earlier governance/calibration research: 5/12 strict historical verdicts, an optional 8/12 grouping on the same seen examples, zero verified governance training examples, and mocked runner/readiness checks. Those are separate from these learning experiments and establish neither generalization nor deployed governance effectiveness.

What makes this work worth pursuing is the combination of a replicated, limited Ornith training gain, substantial self-play gains in a much smaller specialized network, and now actual public ARC3 level progress. What remains missing is equally concrete: a successful matched ARC3 prediction experiment, causal component ablations, independent seeds, untouched game-family transfer, replicated closed-loop success and complete cost accounting. **Promising research progress is supported; a general ARC3 breakthrough or a general self-improving LLM is not yet established.**

First-party source retains AGPL-3.0-or-later; existing repository and upstream notices remain applicable.
