This is the E interface record for C/bridge/NEXT coordination. C review `01aec8a` accepts the target, parameters, twelve-field binding and request/result domains below. E confirms C's exact admission nesting and factual settlement semantics in the source increment appended below. The E budget/state helper is implemented as SOURCE-ONLY; the complete authority join is not mounted or implemented in the existing memory-only authority worker. E must not send inference through `memory_effect` or fabricate D/F receipts. The provider, key and model body stay in E's separated credential service; C receives only verified owner/session, nonsecret operation/grant and request/evidence digests.

The existing frozen OperationProposal fields remain unchanged. C-accepted inference values and semantics:

- `audience: 'aukora-prime.inference'`, `action_type: 'inference.generate'`; exactly the registered Task's `task_id`, `owner_id`, `agent_id`, and `data_scope:['conversation']` for the first candidate.
- Closed `target_identity`: `{version:1,kind:'prime-inference-route/v1',owner_subject,route_id,provider,endpoint,model,region,config_digest,credential_generation,total_budget_id}`. The trusted route/credential host derives every field from immutable qualified configuration and C's actual owner subject; the app's assertion is insufficient. `expected_state_version` names the independently observed route/config/generation/budget-policy version using the shared E derivation below; C/NEXT must integrate the trusted observer rather than accept an app-supplied string.
- Closed `canonical_parameters`: `{version:1,kind:'prime-inference-request/v1',binding,request_digest,limits,total_budget}`. `limits` is exactly `{max_requests,max_input_tokens,max_output_tokens,max_total_tokens,max_request_ms,task_spend_ceiling}`; `total_budget` is exactly `{budget_id,ceiling,policy_digest}` with approved USD decimal ceiling and independently observed policy digest. These review-visible numeric fields must match the worker's approved Task/route and immutable total descriptor, not app assertions. `binding` is the exact existing E flat tuple below; it contains hashes/IDs and conservative bounds, never raw prompt, API key, entry ticket, authorization header or provider reply.
- `provider_and_region` equals the qualified route; `maximum_cost` covers this request's conservative reservation and is no larger than the approved Task/route ceiling. Expiry, nonce, policy version and authorization epoch remain C-owned verification facts. Owner proof binds the full exact operation digest using the existing verifier. Prompt review must use an independently bound display of the exact request and its hash; a bare hash alone does not explain a request to an owner.

Exact existing E binding fields:

```text
owner_id, task_id, conversation_id, request_uuid,
body_sha256, binding_hash, citations_sha256, config_digest,
reserved_tokens, reserved_cost_microusd,
credential_generation, total_budget_id
```

All IDs/config/generation/body and citation hashes must match the independently recomputed worker request. Bare body/binding/citation hashes are lowercase SHA256 hex; config digest uses `sha256:<hex>`. Token/cost/generation fields are safe integers, generation positive. This tuple has no secret values. C/E agree the inference request digest: `sha256:` plus SHA256 of UTF-8 `aukora-prime.inference-request.v1\0` followed by the existing frozen `canonicalJson(binding)`. Do not use F's executor request digest or silently substitute another domain. The worker must derive the tuple from its verified exact body, route and task before computing the digest. Its runtime join remains pending.

Minimal admission join:

1. C reserves exactly `{operation,approval_proof}` through the existing verifier/kernel, consuming approval and returning durable PREPARED `ConsumedGrant`. App `authorize_dispatch(binding)` returns one closed flat object with exactly the twelve binding fields above plus `operation`, `consumed_grant` and `request_digest`. These three are siblings, with no extra opaque wrapper or nested `binding` inside the admission. The operation's `canonical_parameters.binding` still contains the exact twelve-field tuple. Operation and grant use unchanged frozen types; this is not a frontend readiness boolean.
2. The separated worker validates frozen operation/grant structure, the exact operation/target/request tuple, current approved config/generation, conservative cost and immutable budget ID. It atomically persists intent, original policy and worst-case allowance in its existing private ledger BEFORE claim. After a durable claim-start fence, its `verifyDispatchAdmission(envelope)` callback reobserves and calls C `claimDispatch({operation,consumed_grant,request_id:request_uuid,request_digest})` over the reviewed inference-specific private channel. Only the exact DISPATCHED/grant/UUID/digest reply makes HTTP eligible. A missing/lost/conflicting claim is fenced; no second claim or new UUID retry.
3. C claim durably binds the already consumed PREPARED grant to the request; it performs no second kernel consumption and does not replace spend admission or prove an HTTP request/reply. The worker reobserves policy, commits the HTTP-attempt fence and invokes the provider once. Factual evidence/outbox and accounting then commit together. This source implementation closes E's former claim-before-reservation gap; the actual C/Bridge/runtime join remains unqualified. No new public generic authority role or secret transport is requested.

Budget fields stay outside B's closed provider read row. Required host-only immutable descriptor is `{version:1,budget_id,owner_id,provider:'deepseek',route_id:'externalDeepSeek',ceiling:{currency:'USD',amount},approval_reference}`. Current candidate values are USD `10.000000` TOTAL testing and USD `0.010000` first-task/route ceiling, one attempt, conversation-only, at most 4,096 input/256 output/4,352 aggregate tokens and 15 seconds. Generic product code requires explicit approved values and supplies no personal default. Both boundary ledgers use the same budget ID and one authoritative protected worker store; new tasks/restarts/unknown outcomes do not release held allowance.

Requested model-result evidence for C review, separate from frozen ExecutionReceipt/MemoryEffectReceipt:

```text
version: 1
kind: 'prime-inference-effect/v1'
operation_id, operation_digest, grant_id, request_id, request_digest
owner_subject, task_id, conversation_id, route_id
config_digest, credential_generation, total_budget_id, body_sha256
outcome: 'completed' | 'outcome_unknown'
result_digest: prefixed SHA256 | null
usage: {input_tokens,output_tokens,cost_microusd} | null
reservation_retained: boolean
observed_at: explicit UTC time
```

For completed evidence, the credential worker verifies the qualified wire model, bounded strict UTF-8/JSON response, allowed note schema/source IDs and usage bounds, commits local usage and metadata evidence, then sends the same evidence for C settlement. The proposed result digest domain is `aukora-prime.inference-result.v1\0` over frozen canonical `{text,source_ids,input_tokens,output_tokens}`; the C receipt carries its digest, not content. A response digest is worker evidence, not attestation of remote weights or computation.

For an unknown outcome, `result_digest:null`, `usage:null`, `reservation_retained:true`; consumed authority, request slot and worst reservation stay held. No success/cancellation/no-charge claim is inferred from a timeout, closed socket or owner acknowledgment. Later factual reconciliation must bind the same request and conflicting evidence must refuse. E confirms C's factual settlement method and digest domain below; C's receipt validator and the private runtime join remain unimplemented in this increment. Only local accounting settlement exists, and C final settlement remains pending.

Key-entry/configuration approval is a separate exact owner action, not permission for inference. Secrets never enter any operation, binding, proof, broker state or evidence receipt. Existing owner session authentication is a read, not approval. B's secure-entry UI and NEXT's actual owner/private credential transport must be independently qualified before a real key or paid call.

This proposal changes no retention: the current E app retains plaintext request JSONL/raw receipts and reply results. The first prompt must be non-sensitive with that disclosure. C evidence is metadata/digest only; no promise is made about local, provider, backup or physical erasure.

After explicit approval, focused keyless admission, total-budget and worker-outbox checks RAN with all 15 groups passing, plus a passing strict declaration consumer check. [Worker acceptance scope](worker-intent-outbox.md) records the tested implementation and limits. Full contract vectors, strict-parser fixtures, private service integration and live qualification remain UNPERFORMED; source tests do not authorize effects.

## E budget/state source increment for C and NEXT

`src/budget-binding.mjs`, importable through `@aukora-prime/inference/budget-binding`, is the shared E implementation. It uses the existing frozen `canonicalJson` and E SHA256 helper. There is no new operation, receipt or serialization family. This defines E's exact budget/state bytes for C to consume; C/NEXT integration and verification remain pending. Existing configuration, body, citation, request-binding and operation digest bytes are unchanged.

Let `CJ(x)` be the frozen compact sorted `canonicalJson(x)` and `H(s)` be lowercase SHA256 of UTF-8 `s`, prefixed with `sha256:`. In the following preimages, `\0` denotes exactly one NUL byte; there is no newline, BOM or trailing delimiter.

```text
policy_digest = H("aukora-prime.inference-budget-policy.v1\0" + CJ(descriptor))
state_version = H("aukora-prime.inference-state.v1\0" + CJ({target_identity,policy_digest}))
```

`descriptor` is EXACTLY the immutable stored seven-field object, including `approval_reference`. The canonical key order is:

```text
{"approval_reference":REFERENCE,"budget_id":BUDGET_ID,"ceiling":{"amount":SIX_DECIMAL_STRING,"currency":"USD"},"owner_id":OWNER_ID,"provider":"deepseek","route_id":"externalDeepSeek","version":1}
```

Uppercase symbols above mean JSON-encoded string values, not literal tokens or fixtures. The existing constructor normalization remains: positive USD amount, at most eight input decimal places, truncate fractional microusd downward, reject values outside the positive safe-integer microusd range, and store exactly six decimals without leading whole-part zeros. `normalizeTotalBudget` is for construction BEFORE owner review. The digest and state helpers reject an unnormalized descriptor; they never normalize signed operation bytes into acceptance. Thus the exact normalized ceiling (for example `"10.000000"`, not `"10"`) must be displayed and reviewed before signing. No USD amount is a generic default.

`totalBudgetPolicyDigest(descriptor)` rejects extra fields, including the derived eighth field `ceiling_microusd`. `totalBudgetBinding(descriptor)` returns exactly `{budget_id,ceiling,policy_digest}`. `ledger.totalBudgetBinding(owner_id,budget_id)` reads the protected stored descriptor, checks its owner/ID, and returns that same three-field view. Do not pass `ledger.requireTotalBudget(...)` to the digest helper: its accounting return contains the extra derived field. No usage counters or remaining allowance enter either digest.

`inferenceBudgetState({owner,route,total_budget,credential_generation})` reconstructs the accepted eleven-field `target_identity` and returns `{target_identity,state_version,total_budget}`. Inputs have these sources:

- `owner` is the exact `{owner_id,subject}` projection of C's authenticated/registered owner mapping. `owner_id` must equal the stored descriptor owner; `subject` supplies target `owner_subject`. The two strings are distinct identities and are never substituted for each other.
- `route` is the independently qualified production LocalRoute for the original approved configuration. Its provider, route ID and budget ID must match the descriptor. The trusted resolver must verify its config digest against the original approved `{route,pricing}`, with the existing configuration domain and bytes. A valid-looking digest is not that verification.
- `total_budget` is the exact seven-field descriptor from the authoritative protected worker ledger, never the app's proposed `canonical_parameters.total_budget` or another database.
- `credential_generation` is a positive safe integer independently observed from current private vault status. It must equal the qualified route's generation. This parameter contains no credential value. The helper itself performs no vault read or owner/configuration verification; the trusted private observer must supply fresh facts, revalidate them before claim, and fence changes through dispatch. Merely passing the same app generation twice proves nothing.

The state canonical object contains exactly `policy_digest` then `target_identity`; target canonical key order is `config_digest,credential_generation,endpoint,kind,model,owner_subject,provider,region,route_id,total_budget_id,version`. Put the returned `state_version` unchanged into OperationProposal `expected_state_version`, and have the trusted observer independently reconstruct it with the same helper. Do not accept an app-supplied version or target as observation.

Descriptor `version:1`, target `version:1`, accepted target kind and both `v1` hash domains are fixed for this source increment. Changes to owner/approval reference/budget ID/normalized ceiling alter the policy digest; changes to that digest or any target field alter state version. Configuration or credential-generation changes therefore invalidate an earlier observation. Usage changes, new reservations, restarts and passage of time do not change policy state or create allowance. The original ledger descriptor remains immutable; a changed policy requires an explicitly approved future transition, not replacement of the row or a fresh database. Future preimage/schema changes require an explicit coordinated version/domain change, never silent reinterpretation of `v1`.

Available request/token/cost allowance remains checked atomically by E's existing `BEGIN IMMEDIATE` reservation. The state version is not a spend reservation. The worker must retain the original approved route/rates and effective LocalTask with immutable intent so later factual usage validation never uses current replacement rates. Effective operation limits remain LocalTask request/aggregate-token caps, task/route input/output intersections, qualified route time bound and LocalTask spend ceiling; every nested owner/task/conversation must match the registered Task.

## E confirmation of C factual settlement proposal

E accepts C's closed flat fifteen-field admission above and these private factual interfaces for the coordinated join:

```text
settleInference({operation,consumed_grant,request_id,request_digest,receipt,receipt_digest})
reconcileInferenceSettlement(same closed input)
reply: {ok:true,status,request_id,request_digest,receipt_digest,idempotent,reconciliation_required}
status: COMPLETED | OUTCOME_UNKNOWN
receipt_digest = H("aukora-prime.inference-receipt.v1\0" + CJ(full_receipt))
```

The receipt has exactly the fields listed earlier in this document. Completed evidence has the agreed result digest, bounded actual usage/cost under the original approved rates, and `reservation_retained:false`; the request slot remains spent. Unknown evidence has null result/usage and `reservation_retained:true`, retaining worst-case cost/tokens and the slot. `observed_at` is the durably recorded canonical UTC ISO timestamp and is resent unchanged. Exact repeated evidence is idempotent. Changed evidence requires explicit reconciliation of an unknown row; operation, grant, request, owner/task/conversation, config/generation, budget and body identity cannot change. Settlement needs factual trusted worker evidence rather than a live owner session, and cannot authorize another HTTP request.

The later [worker intent/outbox source increment](worker-intent-outbox.md) tightens admission to these exact fifteen fields and implements E's durable intent/reservation before claim, evidence/outbox transaction, claim/HTTP fencing and factual redelivery. It adds no C method implementation or private bridge role. A lost reserve reply cannot be assumed unconsumed. No released slot, uncertain-cost refund, repeated HTTP or fresh UUID may resolve missing evidence. C owns its factual validator and terminal retention changes; NEXT owns the one integrated private bridge/observer and lifecycle wiring. All changes remain source-only with verification pending.
