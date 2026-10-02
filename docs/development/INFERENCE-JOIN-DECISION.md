# NEXT inference join decision

SOURCE-ONLY coordination decision. NEXT accepts C's reviewed `01aec8a`
response to E `3caf9e2` and E's `2029418` budget/state derivations for the
specific interfaces below. This decision adds
no runtime API, role, policy, contract field, credential, service or permission.
The accepted field layouts are recorded in
[C's proposal](../../packages/authority/docs/next-inference-interface-proposal.md)
and [E's request](../../packages/inference/inference-contract-request.md).
Their earlier unspecified eleven-field-binding language is superseded by the
twelve-field binding and fifteen-field admission below. This was the original source agreement; the C/E/Bridge implementation is now
imported. Protected deployment remains pending.

## Admission and existing authority lifecycle

Use the existing `ExternalDeepSeekGateway.authorize_dispatch(binding)` and
E's shared private continuation. Imported `3ca1cdf` replaces the earlier
`SeparatedCredentialService.verifyDispatchAdmission` callback with the held
`withDispatch` continuation and durable pre-reserve attempt. Admission
is exactly the twelve existing E binding fields plus the three named siblings:

```text
owner_id, task_id, conversation_id, request_uuid, body_sha256,
binding_hash, citations_sha256, config_digest, reserved_tokens,
reserved_cost_microusd, credential_generation, total_budget_id,
operation, consumed_grant, request_digest
```

No opaque nested wrapper or additional blanket grant is accepted. The existing
frozen operation and consumed-grant formats are unchanged. The operation uses
`aukora-prime.inference` / `inference.generate`, E's exact eleven-field target,
six-field parameters, six-field limits and three-field total-budget view.
Every nested owner/task/conversation must match the independently registered
Task and worker LocalTask; operation scope alone is insufficient.

`reserve({operation,approval_proof})` consumes the exact owner approval and
commits PREPARED. App-side `authorize_dispatch` returns its exact grant and
binding; it does not claim dispatch. A lost reserve reply remains uncertain,
with no assumed refund, fresh approval nonce or new UUID retry to escape it.

The separated credential worker independently reconstructs the binding from
its verified body/citations, qualified route, current vault generation and
protected stored budget. Before any claim it must atomically commit immutable
operation/grant/request intent, the original effective LocalTask, route and
pricing, and the worst-case request/token/cost reservation. Insufficient
allowance prevents both claim and HTTP. An already consumed C preparation is
not refunded or reset by that refusal. The atomic allowance check cannot be
replaced by a state hash.
Use the existing worker ledger for this intent/reservation and its settlement
outbox, rather than a second orchestration store or a host-side evidence copy.
E owns the exact ledger transaction implementation and its interruption cases.

Only that separated worker calls the existing
`claimDispatch({operation,consumed_grant,request_id,request_digest})`.
`request_id` is the original request UUID. Claim must return exact DISPATCHED,
grant, UUID and digest before HTTP is eligible. Claim fences a previously
consumed grant; it is not a second approval consumption. A lost claim reply
keeps the recorded intent and held allowance; no repeat claim or HTTP follows.

Request digest is `sha256:` plus SHA256 of UTF-8
`aukora-prime.inference-request.v1\0` followed by frozen
`canonicalJson(twelveFieldBinding)`. The written `\0` denotes one NUL byte.
Existing bare body/binding/citation hashes and configuration bytes stay intact.

## Private transport and observations

Bridge owns the source implementation. NEXT selects a separate source-fixed
`inference_effect` private role using the existing authenticated authority IPC
and its exact `{input,operation,operation_digest,observation}` envelope. Its
method allowlist is limited to:

```text
authority.propose, authority.loginChallenge, authority.loginComplete,
authority.authenticateSession, authority.logoutSession,
authority.approvalChallenge, authority.approvalComplete,
authority.declineApproval, authority.status, authority.reserve,
authority.claimDispatch, authority.settleInference,
authority.reconcileInferenceSettlement
```

The new role cannot invoke memory settlement or executor settlement. Existing
`memory_effect`, public roles and the sixteen-method owner-memory HTTP surface
remain unchanged. This decision originally requested that implementation from the Bridge owner.
The closed inference-role allowlist is now imported; no public role is widened. C's inference
profile requires its own audience-bound authenticated owner session; memory
sessions are not portable. No state/witness reinitialization is authorized.

The private observer comes from E's qualified route/configuration, C's actual
owner mapping, the authoritative worker's stored seven-field budget descriptor
and independently read vault generation. E's reviewed `2029418` shared source
helper is imported at `@aukora-prime/inference/budget-binding`. NEXT accepts
`sha256:` plus SHA256 of `aukora-prime.inference-budget-policy.v1\0` followed by
frozen canonical JSON of the exact normalized seven-field stored descriptor,
including `approval_reference`. State version uses
`aukora-prime.inference-state.v1\0` followed by canonical
`{target_identity,policy_digest}`. Neither includes derived microusd helpers or
mutable allowance. Signed/observed inputs must already contain the exact stored
six-decimal amount; construction normalization happens before review, never
during proof verification. Descriptor/target versions and domains stay fixed;
future shape or preimage changes require coordinated versioning. Do not
duplicate its normalization in H or C. Observation remains
exactly `{target_identity,state_version}`; a host cannot echo operation values
as independent observation. Preserve the existing per-call scope and refuse
reentrant/mismatched calls. Reobserve at approval/reserve/claim and fence changes
through dispatch; this derivation is not containment or available allowance.

## Factual evidence and settlement

NEXT accepts C's exact six-field factual input and reply:

```text
settleInference({operation,consumed_grant,request_id,request_digest,
                 receipt,receipt_digest})
reconcileInferenceSettlement(same closed input)
reply: {ok:true,status,request_id,request_digest,receipt_digest,
        idempotent,reconciliation_required}
status: COMPLETED | OUTCOME_UNKNOWN
```

The credential worker is the evidence writer. Commit validated usage, the
immutable receipt and pending settlement outbox before attempting C delivery.
C receives the agreed receipt metadata and result digest; the app does not
manufacture evidence from a rendered reply. Use exactly E's listed receipt
fields, `aukora-prime.inference-result.v1\0` over canonical
`{text,source_ids,input_tokens,output_tokens}`, and
`aukora-prime.inference-receipt.v1\0` over the canonical full receipt, each with
prefixed SHA256. Persist the original canonical UTC ISO `observed_at`; retries
resend identical bytes and do not generate another timestamp.

Completed replaces the worst-case charge with bounded actual tokens/cost under
the original approved rates and sets `reservation_retained:false`. The request
slot remains spent. Unknown has null result/usage and
`reservation_retained:true`, retaining worst-case tokens/cost and the slot.
Lost C settlement delivery does not undo a factual worker result: retain its
outbox and report settlement pending. Redelivery is only of that committed
receipt, never a claim or provider request. Identical evidence is idempotent;
changed evidence uses explicit reconciliation of an unknown row with every
original operation/grant/request/configuration/budget identity preserved.

C owns the genuine receipt validator, terminal record/compactor support and
existing kernel/witness invariants. Unknown rows remain fully retained. Factual
settlement does not require a current owner session and cannot authorize any
new effect. A timeout cannot establish cancellation or zero charge.

## Integrated source and next narrow increments

1. E's shared budget/state helper is integrated and consumed by C/Bridge.
   The integrated C/E mapper check passed 20 cases and 127 assertions.
   E's combined `23b0723` parser correction
   supersedes held `8a94ea6`: both decoders use `fatal:true,ignoreBOM:true`,
   preserving the BOM for strict rejection. Request and response parser checks
   remain UNPERFORMED.
2. E's corrected `377da04d` implements durable worker intent/evidence/outbox
   around the existing ledger and exact fifteen-field admission. The subsequent `3ca1cdf`
   adds the private continuation inside Bridge's held observation and the durable
   attempt guard before C reserve, with 15 focused lane groups and strict types.
3. C's accepted lifecycle/receipt validation and Bridge's private role/trusted
   observer are integrated. The connected `e994789` smoke passed pinned DSH,
   genuine synthetic C approval, E shared continuation and one mock reply.
   It covers retained attempt/replay refusal and idempotent factual settlement
   after graceful same-process reopen. [Evidence](../evidence/next-dsh-pilot-e994789.json).
   The actual separated credential service and protected custody are unexercised.
4. NEXT connects the existing host/native UI seams after those private gaps
   close. The unchanged mock result was observed in B's compiled read-only view;
   the native interactive producer remains missing and send is disabled.

Peter approved focused keyless local checks. C/E/B/F/Bridge source and scoped
evidence are imported; the owner UI has a fresh verified build. E's imported shared
continuation now preserves Bridge observation through dispatch without duplicate
reserve or claim, and its ledger retains a durable pre-C-reserve attempt.
Connected keyless evidence remains distinct from protected credential custody.
Protected product UI acceptance and installed runtime qualification remain UNPERFORMED.
Protected custody, first-request rates and
terms qualification, the separate configuration/key-entry approval and runtime
activation remain unresolved prerequisites; a source agreement grants none.
