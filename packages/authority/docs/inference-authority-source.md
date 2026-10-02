# Settled inference authority source

SOURCE-ONLY implementation against NEXT's `INFERENCE-JOIN-DECISION.md`, first
read at `6becb72f309355d76f803e68c02173aafbd9fb40`. Later NEXT integration of
the guarded mapper does not qualify a running service. Approved keyless local checks now cover the changed interfaces and
factual settlement path; their scope is recorded below. Builds, authentic owner
admission/private-worker/provider integration and live effects remain unperformed.

## Trusted profile and unchanged authority path

The trusted `createAuthorityService` constructor accepts this optional data:

```text
inferenceProfile: {contexts:[{route,local_task,total_budget,original_config}]}
```

This is an immutable protected host registry, not guest JSON, a public settings
route or a readiness flag. Each context uses E's closed production `LocalRoute`,
effective `LocalTask`, exact normalized seven-field stored budget descriptor,
and original existing `ProviderConfiguration` `{route,pricing}`. Keep the
original configuration bytes with E's `route.status:'unavailable'` before any
qualified-status promotion. C checks
the existing configuration digest and qualified route's rates, caps, timeout,
evidence IDs, served version, endpoint/model/region against those bytes.
Authentic configuration approval and actual pricing/terms qualification remain
protected provisioner duties. No configuration or key-entry approval hook is
enabled by constructing this data.

C obtains the actual owner/subject from its durable pinned owner mapping and
the independently registered frozen Task from existing `authorizeTask`. It
compares nested owner/task/conversation, route and all effective limits. The
first profile remains conversation-only. C invokes E's accepted
`@aukora-prime/inference/budget-binding` helper for the exact budget policy and
state version, with no copy of normalization or change to signed bytes. Its
optional peer is loaded only when configuring this profile; absence refuses
configuration without loading credentials, starting a service or opening a
store. Default no-profile core does not load that peer. Node/package resolution
for the configured source remains untested.

The existing synchronous `observeTarget` remains mandatory at approval,
reservation and claim. Its inference response is exactly
`{target_identity,state_version}` from the scoped authenticated private worker,
independently qualified route, protected stored descriptor, actual C owner
mapping and live vault generation. It cannot echo a guest operation or share
scope between reentrant/mismatched requests. Bridge owns that authenticated
private role/scope. C's immutable profile derivation verifies policy identity;
it cannot prove mutable remaining allowance or runtime containment.

The original exact owner session/review/proof and kernel/store checks still
consume approval and durably commit PREPARED. That same commit preserves the
original LocalTask, route, budget, configuration and rates. Claim reobserves the
target, verifies that unchanged snapshot and binds the original request UUID
and digest before committing DISPATCHED. It cannot reset a consumed grant.

## Mapper seams

`createInferenceAuthorityJoin()` has no dependencies and returns UNAVAILABLE.
Trusted composition may supply `{authority,resolveReviewedOperation?}` where
authority is the real protected C service or its authenticated private proxy.
It must never be a guest-controlled callback. The source mapper offers:

- `reserve({operation,approval_proof})`: exactly one original reserve call and
  the original validated PREPARED result; ambiguous/malformed replies refuse.
- `authorizeDispatch(binding)`: matches E's twelve-field `authorize_dispatch`
  callback. A read-only trusted resolver returns the existing exact reviewed
  `{operation,approval_proof}`. The full binding must match before reserve;
  the result is the closed flat fifteen-field admission. No resolver refuses.
- `claimDispatch(admission)`: maps that exact fifteen-field admission to the
  existing four-field claim and validates exact DISPATCHED/grant/UUID/digest.
- `settleInference(input)` / `reconcileInferenceSettlement(input)`: forward
  only the agreed six-field factual envelope and require its structured reply.

No method returns primitive success, retries an ambiguous call, manufactures a
proof/UUID/nonce, spends allowance or calls a provider. Before invoking claim,
E must independently reconstruct the body/citations and route/task/vault/budget
binding, then atomically commit original intent and worst allowance in its
existing worker ledger. C's state hash and matching admission do not replace
that transaction. Reserve without an eventual claim remains consumed PREPARED.
Do not connect the earlier E worker that claims before its ledger reservation.

## Genuine factual evidence

The service adds only the settled private methods:

```text
settleInference({operation,consumed_grant,request_id,request_digest,receipt,receipt_digest})
reconcileInferenceSettlement(same six fields)
reply: {ok:true,status,request_id,request_digest,receipt_digest,idempotent,reconciliation_required}
```

The exact twenty-field `prime-inference-effect/v1` receipt uses E's agreed
configuration/budget/body identity, original canonical UTC `observed_at`,
outcome, result digest and usage. Receipt digest uses
`aukora-prime.inference-receipt.v1` + NUL + frozen canonical full receipt.
No prompt, reply text, secret, fabricated memory receipt or ExecutionReceipt
enters C's factual path. The result digest uses the agreed inference-result
domain at E; C sees the digest and metadata rather than recomputing text.

Completed requires non-null result/usage, bounded actual tokens and exact
BigInt cost under the original durable rates, within original approved caps
and worst reservation; `reservation_retained:false`. Unknown requires null
result/usage and `reservation_retained:true`. Request slots remain spent. Exact
body-derived input/output bounds and raw result validation are E's narrower
independent duties; C cannot reconstruct them from hashes. E commits validated
usage/receipt and its outbox before C delivery. Authenticated `inference_effect`
transport is mandatory; no public receipt route exists here.

Identical committed evidence is idempotent, including after completed-row
compaction. The reply acknowledges the submitted receipt's factual outcome and
digest. An old accepted unknown receipt still replies OUTCOME_UNKNOWN after
later completion; it does not roll the current row back or prove completion.
Current operation state remains available through owner-authenticated `status`.
Changed evidence requires explicit reconciliation of an unknown row, exact
original identity/configuration/budget bindings and non-regressing observation
time. It cannot reinterpret an earlier typed completion or authorize an effect.
Factual settlement uses the original snapshot after owner/session/epoch expiry,
without reusing a current profile or live rates.

Completed inference terminal rows retain bounded digest/status/grant/request/
result metadata and all accepted settlement digests; their copied operation,
proof, original profile and usage payloads are removed within the same validated
durable commit. Unknown remains fully retained. Original kernel consumed IDs,
prepared descriptors, receipt head and witness histories are unchanged.
Executor/memory receipts cannot settle or compact an inference operation.

## Unperformed prerequisites

This patch does not install Bridge's `inference_effect` allowlist, its observer,
the E atomic intent/allowance/outbox transaction, configuration/key-entry owner
approval, credential custody, actual rates/terms qualification, runtime mounts
or UI delivery. Frozen public contracts and digest bytes stay unchanged. Builds and authenticated owner/private-worker/provider integration remain
UNPERFORMED. Focused check results below establish their named local scope,
not runtime qualification.

## Approved focused keyless checks

Ran on Node 24.11.1, with exact owned copies of E's pure helper closure and
Prime contracts; no runtime dependency on another checkout. No private key/signing,
credential, provider, network, live service or host-setting action ran.

| Command | Concrete question | Result |
| --- | --- | --- |
| `node packages/authority/check-inference-mapper.mjs` | Do the flat binding, original configuration and structured C replies bind exactly, while ambiguous calls stay un-retried? | PASS, 20 cases / 127 assertions |
| `node packages/authority/check-inference-evidence.mjs` | Are receipt outcomes/rates/cost/identities closed, and does compaction preserve unknown/history while refusing other evidence kinds? | PASS, 10 cases / 143 checks |
| `node packages/authority/check-inference-service.mjs` | Does actual C persist and reopen factual receipts with kernel/witness history intact, including explicit unknown reconciliation and historical acknowledgement? | PASS, 5 cases / 59 assertions |

Changed production modules passed `node --check`. A disposable source-copy
child loaded default C without the E peer, and configured inference refused
with `INFERENCE_BUDGET_HELPER_UNAVAILABLE` before any store open. Configured
helper resolution and exact E derivations ran with the selected owned peer.

The mapper authority replies and evidence-only history are modeled. The
service check models prior authenticated review/dispatch metadata, while the
unchanged kernel actually prepares/consumes public fixture IDs and its local
journal/witness and C factual settlement are real. It exercises no authentic
owner login/reserve/claim, private IPC, E allowance/outbox or physical power
loss. Temporary state/source copies are removed in `finally`.

Mapper and evidence checks passed once. Only the service check was rerun after
its cross-kind executor fixture failed the frozen receipt's cleanup and
sandbox-identity validation; that fixture was corrected to reach the intended
C guard. The syntax command was corrected after using zsh's reserved `path`
variable. These were check-command/fixture corrections; production source
required no repair. Existing unchanged full suites were not run.

The next functional milestone is E's atomic original intent/allowance and
immutable receipt/outbox plus Bridge's scoped authenticated inference role and
independent observer, joined through these C methods with a keyless mock
transport. Actual owner admission, configuration/credential qualification and
any paid request remain separately scoped integration work.
