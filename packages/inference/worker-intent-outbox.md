# Private inference intent and settlement outbox

The later [private continuation increment](private-continuation.md) supersedes the claim-only callback described below: Bridge now holds observation through HTTP/evidence, and a durable attempt precedes C reserve. The original accounting/evidence invariants remain.

Implementation against NEXT's `INFERENCE-JOIN-DECISION.md` at `6becb72`. Parser correction is already integrated by NEXT `0004510`; this increment does not change either HTTP decoder. After explicit test approval, focused keyless admission, worker ledger/evidence/outbox and total-budget checks ran against implementation `6eedca6`, using copied NEXT `0004510` contracts in a disposable tree. All 15 test groups passed; strict consumer typing also passed with the pinned TypeScript compiler and actual DSH declarations. The complete C/Bridge/runtime join remains unmounted and unqualified. No builds, service starts, credential handling or provider calls ran.

NEXT subsequently identified expiry crossing asynchronous observation or key custody. The corrected source rechecks bound operation expiry after post-claim observation and inside the credential callback immediately before transport. Two focused asynchronous expiry regressions passed, preserving the original grant and worst-case hold with zero transport calls. The affected existing app/wire mock group also passed with zero external API calls; it uses only inert synthetic vault bytes and credential placeholders. No real credential was read or created. Parser/BOM behavior remains unchanged.

## Admission and immutable intent

`verifyPrivateDispatch(request,route,task,observation)` accepts exactly the existing eighteen-field private request and its fifteen-field admission: the twelve E binding fields plus sibling `operation`, `consumed_grant`, `request_digest`. It independently reconstructs body/citation/binding hashes and reservation, validates frozen operation/grant structure, and matches the exact target, parameters, six effective limits, three-field total-budget view, owner/task/conversation, provider/region and data scope. Request digest uses the agreed `aukora-prime.inference-request.v1\0` domain and frozen canonical JSON. Signed maximum cost is compared exactly in eight-decimal USD units; sub-microusd excess cannot round into an allowed ceiling.

`observation` contains the registered C `{owner_id,subject}`, protected stored seven-field `total_budget`, and independently observed vault `credential_generation`. It uses the existing E budget/state helper. The trusted route resolver must qualify the original approved config/rates; C independently verifies the registered Task's `agent_id`, actual consumed grant, owner authority and fresh target state. Structural validation alone is not grant authentication.

The service clones the caller's entire request before its first await and sends the same private body snapshot to HTTP. Callback copies cannot mutate it. The worker intent persists only operation/grant, the twelve-field binding, request ID/digest, original effective LocalTask and route/rates, exact stored budget, conservative input/output bounds and citations. It adds no prompt or reply-text copy to the worker ledger. The existing app JSONL/ledger retention is unchanged.

## One store and interruption ordering

The existing `SpendLedger` owns two additional SQLite tables, `worker_intents` and `worker_evidence`; there is no second database or orchestration loop. `reserveWorkerIntent` registers immutable task/route, checks all task/total allowances, inserts the worst-case request charge/slot and inserts the immutable intent in ONE `BEGIN IMMEDIATE` transaction. Insufficient allowance or a reused UUID prevents claim and HTTP. A previously consumed C PREPARED grant is not refunded by this refusal.

| Durable worker phase | Permitted continuation in the original invocation | Interruption behavior |
| --- | --- | --- |
| `intent_committed` | Commit `claim_started` before calling C | Retain intent and all allowance; restart does not resume claim |
| `claim_started` | Accept only C's exact DISPATCHED/grant/UUID/digest reply | Lost, rejected, malformed or timed-out reply records uncertainty; no repeat claim or HTTP |
| `claimed` | Reobserve policy/generation, then commit `http_started` | Changed policy, cancellation or crash retains allowance; no resumed HTTP |
| `http_started` | Invoke native provider once and record factual outcome | Lost response or process interruption retains worst case; no new UUID or retry |
| `outcome_recorded` | Deliver the committed factual outbox payload | Lost C delivery leaves the same evidence pending; no provider replay |

The phase transitions use conditional updates, and HTTP eligibility requires the exact validated C claim reply. The private callback is now `verifyDispatchAdmission(request): Promise<WorkerClaimReply>`, not a boolean. Its exact reply is `{ok:true,status:'DISPATCHED',consumed_grant,request_id,request_digest}`. It is called only after reservation and the durable claim-start fence. A claim wait is bounded by the original route's `max_request_ms`; a late reply is discarded and cannot enable HTTP.

Duplicate dispatch always meets the existing durable request fence before claim. Phase methods are internal trusted-worker continuations, not restart instructions or IPC endpoints. Explicit recovery never calls them. The single protected authoritative worker/store remains a deployment requirement; in-process active/credential-entry fences are not cross-process custody or anti-rollback. Starting another worker database cannot mint new allowance.

## Evidence, delivery and recovery

`recordWorkerEvidence` validates completed usage and cost against the persisted original rates and reservation. In one transaction it updates actual accounting, retains the request slot, stores the immutable receipt and exact six-field C payload, and adds the pending delivery entry. Result and receipt hashes use the agreed domains. `observed_at` is generated once for committed evidence and is resent unchanged. Worker evidence contains a result digest, not reply text. Unknown evidence has null result/usage, retains worst-case cost/tokens, and cannot be interpreted as cancellation or zero charge.

Claim uncertainty may leave C PREPARED. An unknown outbox in that state can be refused by ordinary C settlement; it remains pending for trusted C reconciliation. The worker never fabricates a successful DISPATCHED acknowledgement to make settlement pass.

C delivery is outside the provider outcome catch. A timeout, refusal or malformed settlement acknowledgement does not change completed worker evidence or restore allowance. Delivery waits at most `min(1000, originalRoute.max_request_ms)` milliseconds, then returns with pending status; it can later resend only the exact persisted metadata. Delayed acknowledgements are checked and applied by receipt digest, so an old acknowledgement cannot erase newer reconciliation evidence. No timer starts another claim or provider call.

The four-field private provider reply remains unchanged. A reply establishes the worker's factual result, not C settlement. The trusted host must read `settlementStatus(owner,task,uuid)` to display pending settlement separately; no public status route or UI control is mounted here.

Private service methods:

- `pendingRequests(owner,{after_request_id,limit})` lists at most 100 unresolved intent/outbox identities in UUID order, including acknowledged unknown outcomes that still need factual reconciliation. Resume listing after the last returned UUID. It performs no delivery or recovery.
- `settlementStatus(owner,task,uuid)` reports phase, local outcome, whether an exact claim reply was recorded, current receipt digest and `settlement_pending`.
- `retrySettlement(owner,task,uuid)` sends only the earliest pending committed payload using `settleInference` or `reconcileInferenceSettlement`. It requires no fresh owner session for factual redelivery and returns pending status on failure.
- `recoverUnknown(context,scope)` requires the authenticated owner and a quiescent worker. It records unknown evidence for an interrupted intent without claim/HTTP, then attempts factual delivery. An existing outcome is not rewritten.
- `reconcileEvidence(context,{owner_id,task_id,request_id,evidence_id})` requires the authenticated owner and a trusted `getReconciliationEvidence` resolver. The resolver supplies existing local factual evidence under the original intent; it must not issue inference or accept app-supplied usage/result as fact. Earlier unknown evidence must already be acknowledged before changed completed evidence can be committed and sent through explicit reconciliation. No request slot is restored.

The generic ledger `settle`, `reconcile` and `transition` routes refuse worker-intent rows. They cannot release a worker charge using arbitrary token/cost numbers or an evidence label. Original unknown evidence remains retained after a later completion. A database failure that prevents durable evidence recording returns `WORKER_EVIDENCE_COMMIT_REQUIRED` and leaves the durable intent/reservation for recovery.

## Required private adapters and remaining limits

In addition to the existing callbacks, the service requires `getOwnerIdentity`, `settleInference` and `reconcileInferenceSettlement`. The first supplies the actual registered C owner pair. The latter two accept only the agreed six-field evidence payload and return the closed seven-field C acknowledgement. C/Bridge own their implementation under the scoped `inference_effect` role. No memory/executor role, generic method dispatcher or public route is added here.

The worker reobserves route/task/owner/vault state after claim and compares the full immutable intent before HTTP. `verifyWorkerContinuation` checks expiry after that awaited observation. `DeepSeekHttpProvider` checks the same operation expiry after asynchronous custody, immediately before invoking transport; missing, invalid or reached expiry refuses with `DISPATCH_APPROVAL_EXPIRED`. The service records uncertainty with consumed identity and worst-case allowance retained. Credential entry and dispatch have two-way in-process owner fences, and credential generation is reread inside key custody before use. External policy changes and multiple processes still require the qualified host's immutable-policy/single-writer boundary. Policy observation callbacks must be bounded trusted reads; source callbacks do not establish that runtime boundary.

Focused checks now RAN: `node --test packages/inference/check-dispatch.mjs` (3 groups), `node --test packages/inference/check-total-budget.mjs` (5 groups), and `node --test packages/inference/check-worker-outbox.mjs` (7 groups), all PASS. The updated synthetic fixture uses the agreed observation, admission and claim shapes. Coverage includes nested admission/operation mismatches, exact money bounds, forced transaction rollback, insufficient allowance, two-process contention, persistent phases/restart, malformed claim refusal, immutable original-rate evidence, pending outbox retention, stale acknowledgement fencing and generic-settlement refusal. The strict no-emit `check-worker-types.mts` consumer covers frozen JSON compatibility and required callback/admission/receipt shapes. These synthetic grants establish no real owner authority.

The subsequent expiry correction RAN `node --test packages/inference/check-dispatch-expiry.mjs` (2 groups PASS) and the affected `node --test --test-name-pattern='^Lane E disposable mock acceptance:' packages/inference/check.mjs` (1 group PASS). The former exercises the actual shared post-claim continuation and native-provider custody callback; the latter checks that the unexpired mocked wire path still works. Mock clocks are local to each test, and no network transport or real credential is used.

UNPERFORMED integration questions remain: full service-level callback timeout/late-reply orchestration, live credential-entry interleavings, current separate-UID/vault custody, trusted reconciliation provenance, and the connected C/Bridge/DSH path. Ledger phase and focused expiry tests do not establish those runtime boundaries. The next functional milestone is NEXT's single keyless end-to-end conversation through the agreed private adapters, using mocked factual provider output and real local reservation/evidence/outbox state. No paid-call or key-entry permission follows from these checks.
