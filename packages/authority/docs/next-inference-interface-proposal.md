# One-request inference authority join

HISTORICAL PROPOSAL / SOURCE-ONLY. This records coordination against NEXT
`714e9ab9367b07ca4169f63b468354903be01be1`, whose development base is
`fbbb1ae43026cb1567afd3f02a28b8bec69f2351`. It changes no runtime API, policy,
role, export, frozen contract, key or service configuration at that checkpoint.
Present-tense source descriptions below refer to those historical checkpoints.
NEXT later settled the interfaces in `docs/development/INFERENCE-JOIN-DECISION.md`;
the current owned source increment is described in
[inference-authority-source.md](inference-authority-source.md). Approved focused keyless check results
are now recorded there; installed effects remain unqualified.

The later guarded source increment adds only the private
`src/inference-admission.mjs` parser/factory: accepted structural fields and
request digest are parsed, while every effect method remains `UNAVAILABLE`.
It has no enabling configuration branch, root export or worker mount. Parsing
matching fields does not verify owner authority, a durable grant or budget.

## Existing E inputs and bytes

E's current `DispatchBinding` has exactly these eleven fields:

```text
owner_id, task_id, conversation_id, request_uuid, body_sha256,
binding_hash, citations_sha256, config_digest, reserved_tokens,
reserved_cost_microusd, credential_generation
```

`authorize_dispatch(binding)` returns these same fields plus currently opaque
admission material. `verifyDispatchAdmission(request)` receives the private
worker request with these exact seventeen fields, excluding `AbortSignal`:

```text
admission, binding_hash, body, body_sha256, citations, citations_sha256,
config_digest, conversation_id, credential_generation, endpoint, headers,
owner_id, request_uuid, reserved_cost_microusd, reserved_tokens, route_id, task_id
```

The worker independently validates the approved route/task, fixed endpoint,
body, citations, credential generation and worst-case token/cost reservation.
Its existing callback may return `true` only after the private C join has
verified owner authority and durably claimed the exact dispatch; matching
fields or channel authentication alone are insufficient.

Preserve existing E digest bytes:

| Field | Existing preimage |
| --- | --- |
| `config_digest` | Prefixed SHA256 of UTF-8 `aukora-prime.inference-config.v1\0` plus E canonical `{route,pricing}` |
| `body_sha256` | Bare lowercase SHA256 of exact `JSON.stringify(body)` |
| `citations_sha256` | Bare SHA256 of E canonical citations |
| `binding_hash` | Bare SHA256 of E canonical `{owner_id,task_id,conversation_id,request_uuid,route,body_hash,citations}` |

Current NEXT has per-task accounting and no `total_budget_id`. E's independent
total-budget increment must be selected and its final request fields agreed
before dependent source wiring. The pilot USD 10 ceiling is an upper bound,
not approval for a call. One request additionally needs an explicit smaller
approved cap, data scope, qualified rates/terms/served version and request slot.

## Reuse C's existing authority path

Use the unchanged frozen `OperationProposal`, `ApprovalProof` and
`ConsumedGrant`, and the existing kernel/stores. Do not invent another decision
engine or represent model inference as a memory or OpenShell effect.

1. The trusted host selects owner/task/conversation, registered agent,
   route/provider/region, data classes, policy, current credential/config state
   and numeric budget. The proposing model supplies no authority identity or
   budget. Freeze the full E request and the exact host-prepared operation.
2. Obtain a valid session for the agreed inference profile, then call the
   existing `propose({session_token,operation})`,
   `approvalChallenge({session_token,operation})` and
   `approvalComplete({session_token,proof})`. Review must display the exact
   request/data scope, destination and worst-case cost from the same operation.
3. A private adapter verifies the agreed operation-to-E binding and independently
   recomputes scope/budget against immutable trusted route/task configuration.
   It calls `reserve({operation,approval_proof})`. The original kernel consumes
   the exact approval and durably records PREPARED before returning its grant.
4. The credential worker verifies that same admission and performs the existing
   `claimDispatch({operation,consumed_grant,request_id,request_digest})` once
   before HTTP. `request_id` must be the original E request UUID. The exact
   inference request-digest preimage is an outstanding agreement; do not alias
   it to an unrelated receipt domain or change E's existing hashes.
5. Persist the E request fence, worst-case reservation and actual result in its
   existing ledger. C factual settlement must receive a genuine, closed,
   operation/grant/request-bound inference receipt from the trusted credential
   worker after durable recording. A persisted settlement outbox can resend
   identical evidence after restart; it cannot repeat HTTP or mint a new UUID.

Any lost reservation/claim/HTTP/settlement reply preserves recorded consumption,
request fences and uncertainty. A lost reserve reply does not establish whether
consumption occurred; only trusted reconciliation can resolve that fact.
Claim-before-E-reservation is a real
interruption gap in current source: E and C must agree where the immutable
worker intent is persisted and how a reservation refusal is accounted for.
Never release a grant, refund an uncertain call or retry from a missing reply.
Budget recovery remains inside E's trusted service boundary with evidence;
reconciliation never restores a used request slot.

## Private transport and owner boundary

The current private worker accepts only `memory_effect`, audience
`aukora-prime.memory`, actions `memory.save|memory.forget`, and exact
`{kind:'prime-memory',owner_subject}`. Leave that profile and all public roles
unchanged. Bridge owns a separately source-fixed inference profile/handler
after the exact methods and schemas are agreed; it must not accept an arbitrary
union of C methods or app-supplied target observation.

C binds sessions and policy to one immutable audience. A separate inference
audience cannot reuse a memory session. The conservative proposed choice is a
separate trusted inference profile with its own valid owner login; no profile
name, new state/witness namespace or permission is installed by this proposal.
The final audience/session choice requires explicit C/E/bridge agreement.

Provider configuration approval and credential-entry approval are separate
owner actions. Existing C session authentication can verify their actor, but
login alone cannot approve them. Secrets never enter operation parameters,
approval proofs, C state, app RPC, model input or receipts.

Free diagnostic conversation remains a proposal surface without effect
authority. E's current keyless provider is explicitly mock, not a live free
route. A paid HTTP request is a separately approved spend/data-disclosure
effect; its reply keeps `grantsAuthority:false`, cannot invoke tools and cannot
approve a memory save or another call.

## Required agreement before implementation

- Exact inference action, audience, target, canonical parameters and their
  closed mapping to the final E request/budget fields. Shared v1 operation
  fields and digests remain frozen.
- Exact owner-reviewed material in the existing `admission` slot and its
  relationship to C's existing proof/grant. It remains opaque and unmounted
  until agreed; no new nested fields are assigned here.
- Inference request-digest bytes, trusted target observation/config-generation
  binding, private method allowlist and role.
- Genuine inference receipt schema/domain, settlement/reconciliation reply,
  durable worker outbox and the claim/reservation interruption accounting.
  Neither `ExecutionReceipt` nor a fabricated memory receipt is a substitute.
- E's final total-budget profile and proof-bearing configuration/credential
  actions. Source approval alone does not enable a provider or key entry.

Existing source references: `packages/inference/src/index.d.mts`,
`dispatch-policy.mjs`, `gateway.mjs`, `credential-service.mjs`, `ledger.mjs`;
`packages/runtime-bridge/src/ipc.mjs`, `worker.mjs`, `registry.mjs`;
`packages/authority/src/service.mjs`. Runtime containment, owner enrollment,
credential custody, actual provider calls and installed pilot acceptance remain
UNPERFORMED. The frozen release is untouched.

## C response to E's concrete proposal

E proposal received at `3caf9e282981919293f43af6d3846af8f3ce088c`,
`packages/inference/inference-contract-request.md`. The following C review
supersedes the earlier unspecified-field list for NEXT coordination. It freezes
no transport or implementation until E/NEXT/bridge confirm the complete join.

Accepted by C for that coordination:

- Audience `aukora-prime.inference`, action `inference.generate`, first-candidate
  conversation-only data scope, E's exact eleven-field target, six-field
  canonical parameters, six-field limits and three-field total-budget object.
  Their fields remain exactly those in E's proposal, with no C-added public
  operation field. The separate inference profile requires its own valid C
  session; existing memory sessions and `memory_effect` stay unchanged.
- E's final twelve-field binding adds `total_budget_id`. The admitted material
  should be a closed flat object containing those twelve fields plus exactly
  `operation`, `consumed_grant`, `request_digest`; no additional guessed opaque
  field or separate claim mapper is accepted. E/NEXT must confirm this exact
  nesting because the proposal's "plus opaque" wording was ambiguous.
- Request digest is prefixed SHA256 of UTF-8
  `aukora-prime.inference-request.v1\0` plus frozen `canonicalJson(binding)`.
  E must independently reconstruct that exact twelve-field tuple from the
  verified request and immutable policy before claim. Existing E body,
  citation, binding and configuration digest bytes remain unchanged.
- E's exact proposed inference receipt fields and two outcomes, separate from
  D/F receipts. Result digest is prefixed SHA256 of UTF-8
  `aukora-prime.inference-result.v1\0` plus frozen canonical
  `{text,source_ids,input_tokens,output_tokens}`. C receives its digest and
  trusted worker metadata, never reply text; this is not remote attestation.
- The USD 10 total and USD 0.010000 first-request candidate remain explicit
  profile data and do not authorize a call. Generic code supplies no personal
  default. The first Task/route admits one attempt with E's proposed
  4096/256/4352 token caps and 15000 ms bound only after exact owner approval.

C proposes these private factual methods for E/NEXT confirmation:

```text
settleInference({operation,consumed_grant,request_id,request_digest,
                 receipt,receipt_digest})
reconcileInferenceSettlement(same closed input)

reply: {ok:true,status,request_id,request_digest,receipt_digest,
        idempotent,reconciliation_required}
status: COMPLETED | OUTCOME_UNKNOWN
```

Receipt digest is prefixed SHA256 of UTF-8
`aukora-prime.inference-receipt.v1\0` plus frozen canonical full receipt.
Identical receipt bytes are idempotent. Changed evidence requires the explicit
reconcile method from an unknown row; the original identity, operation, grant,
request, configuration, credential generation, budget and body binding cannot
change. Factual settlement does not require a still-live owner session and
cannot permit another HTTP request. No method is implemented or exposed here.

Completed evidence requires non-null result/usage, independently verified
bounded usage and exact cost under the original approved rates, and
`reservation_retained:false`: the worst-case charge has been replaced by actual
charge, while the request slot remains spent. Unknown requires null result and
usage and `reservation_retained:true`, retaining worst-case cost/tokens and the
request slot. `observed_at` must be a canonical UTC ISO timestamp from the
durably recorded evidence; retries resend it unchanged. E/NEXT must confirm
these semantics before implementation. C's local terminal validator/compactor
also needs genuine inference evidence support; unknown rows remain full, with
all original kernel consumption, preparations and witness duties intact.

Required corrections and unresolved derivations:

1. `reserve` consumes owner approval and commits kernel PREPARED. Existing
   `claimDispatch` binds that prepared grant to one request and commits
   DISPATCHED; it does not perform a second kernel consumption. Their existing
   replies remain unchanged.
2. The private binder must compare nested binding owner/task/conversation to
   the authenticated registered Task, not merely the operation's owner/task.
   C's generic policy does not yet validate nested conversation or E budgets.
   Bounds/cost must independently match E's effective LocalTask and route, and
   reserved cost must fit the operation maximum and approved money ceilings.
   Effective limits are approved LocalTask request/aggregate-token caps,
   intersected route/task input/output caps, the qualified route time bound
   and the effective LocalTask USD ceiling. Original approved input/output
   rates must remain durably bound for factual usage validation after a later
   configuration change; current rates cannot reinterpret an old receipt.
3. Define `total_budget.policy_digest` over the exact immutable stored
   seven-field descriptor, including `approval_reference`, with an agreed
   domain. Do not hash the extra derived `ceiling_microusd` helper field.
   Stored normalized six-decimal ceiling bytes must be explicitly reviewed;
   never silently normalize an already signed operation.
4. Define `expected_state_version` and its trusted observer from the qualified
   route/config/generation and immutable budget policy. A caller-supplied
   version is insufficient. Mutable remaining allowance must still be checked
   atomically by the authoritative protected E ledger at reservation; the
   policy version cannot substitute for available budget.
5. Persist immutable worker operation/grant/request intent before a claim can
   be sent, then persist actual evidence and settlement outbox before C
   settlement. E currently has no such outbox. Lost replies preserve any
   recorded consumption and uncertainty, with no repeat claim/HTTP, released
   slot, refunded uncertain reservation or new UUID retry.
6. Bridge must choose a separate source-fixed inference role/method allowlist
   and independent observation seam. This document adds no role, state/witness
   namespace, public route, configuration or credential-entry approval mapper.

Source-only independent reviews confirmed E's tuple/domain compatibility and
the current C lifecycle/retention limitations. No package check, syntax check,
test, build, UI probe, key, service or provider action ran. Implementation
remains pending the specific agreements above.

## Minimal NEXT decisions for the guarded mapper

The C source skeleton accepts only the flat fifteen-field admission described
above. No wrapper material field is added: twelve binding fields plus exactly
`operation`, `consumed_grant`, `request_digest`. C's parser is structural only;
the existing kernel/store remains the sole durable grant authority.

The trusted credential worker owns immutable request/operation/grant intent
before sending a claim, and actual receipt/digest/settlement input in an outbox
before sending settlement. A lost claim never triggers another claim or HTTP
request. A lost settlement reply permits identical evidence resend only, with
the original `observed_at`; changed factual evidence uses explicit unknown
reconciliation. Unknown holds its worst reservation and request slot.

The private factual input and result use the proposed six-field settlement and
existing C reply fields above. Only authenticated credential-worker transport
may submit this evidence; no app/public receipt path is added. Completed
evidence must use original approved rates and durable actual accounting;
unknown cannot infer cancellation, free spend or permission to retry.

Those three decisions need E/NEXT confirmation together with E's exact budget
policy digest and independently observed state-version helper. This skeleton
offers no callback, configuration flag or trusted-looking JSON that can enable
effects before that source join is agreed. Every effect method remains
`UNAVAILABLE`; it is neither root-exported nor worker-mounted.
