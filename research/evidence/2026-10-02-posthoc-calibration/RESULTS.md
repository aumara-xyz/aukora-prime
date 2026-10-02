Evidence class: SYNTHETIC benchmark arithmetic; MEASURED local calculation telemetry is identified separately.
Reference only. No model evaluation, training, product authorization or production claim.

The original exact-verdict result remains **5/12 (41.7%)**. An explicitly optional, retrospective mapping that groups only KEEP and SAFE gives **8/12 (66.7%)**. REJECT, TOMBSTONE and HOSTILE retain distinct labels. The mapping is frozen in `posthoc-analysis-plan.json`; it does not establish operational equivalence or replace the exact result.

| Statistic | Recorded result | Nominal 95% Wilson interval |
| --- | --- | --- |
| Original exact verdict | 5/12 = 41.7% | 19.3–68.0% |
| Optional KEEP/SAFE-only mapping | 8/12 = 66.7% | 39.1–86.2% |

These are nominal binomial intervals, calculated by the [Wilson score method described by NIST](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm). Random, independent sampling is not established for these twelve curated author-labeled cases. The intervals are conditional descriptions, not population or production guarantees.

Retrospective risk discrimination uses author-labeled HOSTILE (4 cases) versus every other label (8 cases, including REJECT and TOMBSTONE). All 32 positive/negative score comparisons rank the HOSTILE case higher: ROC AUC = **1.0**. The maximum other-label score is 0.96 and minimum HOSTILE score is 1.66. A midpoint threshold selected from these same rows, `risk >= 1.31`, gives TP=4, TN=8, FP=0, FN=0. AUC summarizes ranking, as distinguished from verdict accuracy in the [official ROC AUC documentation](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.roc_auc_score.html). The 32 pairs are correlated, not 32 independent observations; no AUC confidence interval is claimed. The threshold was selected and evaluated on the same twelve rows and has no heldout validation. Other labels are not certified safe. Rounded risk scalars are not calibrated probabilities.

The nominal Wilson intervals for this same-table sensitivity (4/4), specificity (8/8) and accuracy (12/12) are 51.0–100%, 67.6–100% and 75.8–100%, respectively, subject to the same unmet sampling assumptions and additional posthoc selection. Perfect separation here does not establish generalization.

## What ran and cost

Exact command, from this directory: `python3 analyze_posthoc.py > analysis.stdout.txt`.
UTC start: 2026-10-02T01:35:38.719392+00:00. Measured calculation wall time: **0.002095625 seconds**. The script read the already exported sanitized twelve-row historical table and the explicit analysis plan, wrote a local hash record before recalculation, and computed arithmetic using Python's standard library. `local-analysis-lock.json` binds input, plan and script hashes. This is a lock before a new recalculation of already seen data; it does **not** make the historical analysis prospective or independently timestamped.

Model calls: 0. Provider actions: 0. Cloud compute: 0 seconds × $0/s = $0. API charges: $0. New cloud storage resources: 0, incremental storage charge: $0. Total **new paid experimental spend: $0**. Existing standing storage remains UNVERIFIED; host energy and subscription/agent usage are outside that total. `run-ledger.json` is measured local telemetry. `posthoc-metrics.json` and raw calculation stdout are labeled SYNTHETIC because historical input/prompt provenance is unverified, despite the arithmetic being reproducible.

## Passes, failures and unresolved work

Passed: strict 5/12 preserved; optional mapping restricted to KEEP/SAFE; confusion counts and rank arithmetic recomputed; no original source or result rewritten. The prior accepted limited-reference Library packet at checkpoint `cae5cbe2a1166f279a82554e586579ce75184de3` stays frozen; this correction is a separate source-only patch.

Held: no twelve-situation labeling packet was created. The bounded original calibration JSON and threshold source contain **0/12 original situation/request texts**. Verdicts and author labels cannot reconstruct those texts honestly. `independent-labeling-readiness.json` records the gap. Parent and current agents have seen the labels and cannot claim blindness. A future labeling step requires approved original sanitized situations, a neutral packet with opaque identifiers and option definitions, an operator-held answer key, and an independent human who discloses prior exposure. That step has not occurred.

UNPROVEN: author labels are not independently established; original requests, full raw responses, usage receipts and the original locked prediction remain absent. No new Jev/Laya/Bonsai evaluation ran. A future prospective experiment requires genuinely unseen heldout cases and frozen independent labeling, split, metric, model binding and failure rules before execution. Hashing this seen-data analysis does not supply them. No rows are promoted to a verified training corpus; that corpus remains **0 verified examples**. H200 spending and provider actions remain held. Product code and the morning checkout/runtime are untouched.
