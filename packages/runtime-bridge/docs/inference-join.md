# Private inference connection

Source implementation against NEXT `6becb72f309355d76f803e68c02173aafbd9fb40` and its
[accepted decision](../../../docs/development/INFERENCE-JOIN-DECISION.md).
After explicit owner approval, focused local keyless checks ran on isolated
snapshots, including current C source at `c66634a`. Their limits are recorded
below. This change installs no production state, credential, listener, service
or public/native UI join.

The Node-only `@aukora-prime/runtime-bridge/inference` subpath exports
`createTrustedInferenceObserver`, `createInferenceAuthorityConnection` and
`startInferenceAuthorityWorker`. Existing root/browser/memory closures do not
import it. Status remains `state:'unavailable',qualification:'unqualified'`;
callback presence supplies no host acceptance or permission for a paid call.

## C dependency and transport

Bridge lazily consumes C's fixed owned path `authority/src/inference-admission.mjs`
and its `parseInferenceBinding`, `parseInferenceOperation`,
`parseInferenceAdmission`, `inferenceRequestDigest` functions. The pinned base
lacks this file. NEXT's later source supplies the parser and factual C lifecycle;
neither supplies E's durable adapters or host acceptance. No fallback parser,
digest profile or kernel exists here.

Worker config is closed `{kind:'inference-authority',ipc,registryEntries,
authorityConfig}`. Actual C configuration requires audience
`aukora-prime.inference`, independent owner public pins and frozen registered
Tasks and C's explicit immutable `inferenceProfile.contexts`. Each context is
exactly `{route,local_task,total_budget,original_config}`; C validates the
original configuration and registered owner policy. The factory requires all
thirteen accepted methods from the actual `createAuthorityService` result and
the explicit profile before listening. Missing lifecycle/profile refuses
`INFERENCE_C_LIFECYCLE_UNMOUNTED` or `INFERENCE_C_PROFILE_UNMOUNTED`. The
unavailable skeleton factory is never used. No setup/reset/provisioning method
is exposed. NEXT supplies separately qualified, already provisioned state and
witness custody; inference uses its own ordinary audience-bound C session.

`createInferenceAuthorityIpcServer/Client` in the existing `ipc` subpath use only
the distinct fixed `inference_effect` role and decision's thirteen methods:
propose, loginChallenge, loginComplete, authenticateSession, logoutSession,
approvalChallenge, approvalComplete, declineApproval, status, reserve,
claimDispatch, settleInference and reconcileInferenceSettlement, each prefixed
`authority.`. There is no privilege union with memory/executor settlement or
public roles. The existing sixteen-method owner-memory surface stays unchanged.
Framing, strict textual JSON, MAC/sequence binding, bounds and Unix ACL checks
reuse the existing IPC. Those checks do not establish connected-peer OS UID or
installed isolation. The private credential/connection must remain outside app
access; NEXT owns its bounded app-to-E host interface.

The shared IPC decoder now preserves a UTF-8 BOM for strict parser rejection
(`fatal:true,ignoreBOM:true`) rather than silently removing ingress bytes. This
does not change a canonical frame, role, method or digest. Four focused IPC cases
passed, including strict ingress across inference, memory and public profiles.

Wire wrapper remains exactly `{input,operation,operation_digest,observation}`.
Only approval challenge/completion, reserve and claim carry observation. C's
request-local operation/digest/observation scope encloses the whole awaited C
call, refuses reentry and clears in `finally`; disconnect/timeout never releases
a still-running C call. Completion input remains `{session_token,proof}`. A
sixteen-slot ephemeral review cache retains the full challenged operation by
session/owner/operation/digest and removes it before proof submission. It is not
durable evidence or authority.

## Observer's internal host adapter

Config is `{registryEntries,ownerMappings,withQualifiedState?}`. Owner mappings
are exact `{owner_id,subject}` projections of actual C pins, never guest identity.
The optional adapter is unavailable when absent:

```text
withQualifiedState({owner_id,task_id}, consume)
consume({route,configuration,local_task,total_budget,credential_generation})
configuration = {digest,payload:{route,pricing},operation_id}
```

These trusted in-process data are not new wire fields or another evidence store.
NEXT/E must independently read the qualified production LocalRoute and approved
configuration row, effective stored LocalTask, authoritative worker ledger's
exact seven-field budget descriptor and live private vault generation. The
adapter verifies approval/qualification, then awaits consume while holding the
route/configuration/generation change fence. It cannot derive facts from the
operation. A valid-looking hash, mode string or callback result is not approval.

Bridge checks E's original configuration preimage, expected qualified route and
effective Task via E's helpers, matches all nested owner/task/conversation/route
bindings and all six effective limits, and bounds maximum cost. It imports the
exact Prime-local source exported by `@aukora-prime/inference/budget-binding` for
the stored budget/state derivations; it never copies their preimage or normalizes
signed descriptors. E rejects the eighth accounting field and unnormalized
stored amounts. The observation is exactly `{target_identity,state_version}`,
derived independently of the app target/version. Policy state supplies no
available allowance, containment or key access.

## Connection's internal E adapters

Config is closed `{authorityChannel,observer,getReviewedApproval?,
withCommittedIntent?,dispatchCommitted?,withCommittedSettlement?}`. Channel config
uses `{socketPath,credential,limits?,socketAccess?}`; its detached secret uses the
existing 32–64-byte hexadecimal string form. Nothing is discovered/generated.
These are pending NEXT/E host adapters around the existing E ledger, not new E
exports or persistence. Missing adapters refuse their effect path; booleans
cannot substitute for closed stored material.

`connection.authority` exposes ordinary C login/proposal/review/status for NEXT's
bounded host composition. `connection.authorizeDispatch(binding)` implements
the existing app gateway hook with:

```text
getReviewedApproval(exactTwelveFieldBinding) -> {operation,approval_proof}
```

That trusted adapter must select immutable owner-reviewed material, durably fence
the reserve attempt in the existing E lifecycle and refuse reuse after
uncertainty. Bridge matches the exact request/proof, calls C reserve once and
returns flat fifteen-field admission: twelve siblings plus
`operation,consumed_grant,request_digest`. It never claims or sends HTTP. Lost or
malformed PREPARED replies preserve uncertainty; no retry/refund/new nonce/UUID
or fresh approval is inferred.

The connection also retains content-free local reserve/dispatch latches keyed
by owner and original UUID, each bounded at 128 without eviction or logout reset.
Repeated calls refuse before another reserve/claim. Exhaustion makes that
connection unavailable; it does not erase duties. These latches survive neither
restart nor reconstruction, confer no authority and do not replace E's durable
one-shot attempt fences. A host must never reconstruct a connection to retry an
uncertain request.

The separated worker calls `connection.withDispatch(claimInput)` only after E
atomically commits original operation/grant/request, effective Task/route/rates
and worst-case allowance. Internal adapter grammar:

```text
withCommittedIntent({owner_id,task_id,operation_digest,request_uuid,request_digest}, consume)
consume(actualStoredFlatFifteenFieldAdmission)
dispatchCommitted(actualStoredAdmission, exactDispatchedReply)
```

E must durably admit that callback once and mark claim attempted before C
delivery. It reads the original already committed intent/reservation, never
caller-selected binding strings. Bridge requires exact equality, reobserves
qualified state, claims once with original UUID/digest and requires the exact
DISPATCHED grant before calling E's fixed dispatch adapter inside the same state
fence. That fence encloses actual dispatch, not merely the C reply. E owns verified
body/citations, credential/native HTTPS, unknown marking and durable evidence/
outbox. The old claim-before-reservation path must not be joined to this source.
No generic signing/HTTP oracle, prompt cache or second ledger exists here.

Factual input remains the accepted six fields. Its internal adapter is:

```text
withCommittedSettlement(method,
  {owner_id,task_id,operation_digest,request_uuid,request_digest,receipt_digest}, consume)
consume(actualStoredSixFieldSettlementInput)
method = settleInference | reconcileInferenceSettlement
```

It reads the original immutable receipt/outbox and original policy. Bridge
requires identical canonical bytes, including original observed_at, then sends
with null observation. C owns genuine receipt/domain/usage/retention validation
and kernel preparation/dispatch lookup. The exact seven-field reply binds
request/receipt digests, status, idempotence and reconciliation flag. Factual
settlement needs no current session, active Task or replacement route/vault
generation. Only E outbox delivery can repeat; claim/HTTP cannot. Changed evidence
uses explicit unknown reconciliation with original identities. No release,
unconsume, refund or cancellation endpoint is added.

## Pending qualification and focused checks

C's explicit policy profile, E's atomic intent/evidence/outbox adapters and
NEXT's protected host/native/UI joins remain prerequisites. Rates/terms/served
version, configuration/key-entry approval, custody, actual enrollment and runtime
activation remain unresolved. Public capabilities remain unavailable. Existing
memory workflows, including unresolved W1 closure, are unchanged.

Focused RAN evidence includes two missing-adapter/profile cases, four IPC cases
and eight boundary cases for altered flat/nested bindings, independent
configuration/budget/vault facts, attempt fences, lost reserve/claim without
retry, the state fence through dispatch and exact original outbox delivery.
The boundary cases use actual C parser and E helpers with explicitly TEST_ONLY
C replies and E adapters; they establish no durable E implementation.

One genuine C worker case passed against `c66634a`: ordinary synthetic P-256
login/review/proof, actual persisted kernel preparation and one dispatch claim,
altered configuration/task/grant/receipt refusals, logged-out unknown settlement
and a C-only cold restart. The restarted worker had no active Task registry and
a changed valid current profile; explicit completed reconciliation still used
the original retained context. Consumption and kernel history remained single,
and original evidence redelivery remained idempotent. E intent/dispatch/outbox
and the result are explicitly TEST_ONLY in this check. It proves no provider
effect, E durability or separate UID boundary.

The owner-memory fixture now retains the exact witness returned by
`controller.connect(client.binding)`. Four focused cases passed on an isolated
`c66634a` snapshot with held H/B source dependencies: distinct bindings with the
same owner, a new connection on the same binding, genuine C/D save/forget and
completed-save continuation. The fixture does not accept owner-ID-only
acknowledgement. Native cleanup remains a B dependency, and this is not a full
owner-memory suite result. W1 stays off.

The scoped commands are:

```sh
node --test packages/runtime-bridge/test/inference-ipc.test.mjs
node --test packages/runtime-bridge/checks/inference-boundary.test.mjs
node --test packages/runtime-bridge/checks/inference-real-authority.test.mjs \
  packages/runtime-bridge/test/inference-unmounted.test.mjs
PRIME_OWNER_MEMORY_SOURCE_PIN=c66634acdef7220fc0274ab56587d563d99b28b3 \
  node --test \
  --test-name-pattern='H stale native witness|H client generic hooks|H same-controller recovered receipt' \
  packages/runtime-bridge/test/owner-memory-facade.test.mjs
```

All ran with Node v24.11.1. The genuine C and owner-memory checks require the
corresponding owned source closure described in the handoff; the base `6becb72`
alone intentionally cannot run the genuine inference lifecycle.

A focused TypeScript 7.0.2 consumer check passed with `--skipLibCheck true` after
repairing the profile declaration's compatibility with E's owned interfaces.
Full declaration traversal is dependency-blocked by absent
`@deepseek-ai/dsh-llm` declarations in E's root re-export. No dependency install
or broad build ran; the consumer result establishes type compatibility only.

All source checks use disposable synthetic material. No paid provider request,
installed worker activation, real owner ceremony or host qualification ran.
Complete C/E runtime integration and public/native composition remain
UNPERFORMED.
