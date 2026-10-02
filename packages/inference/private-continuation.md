# Private continuation and pre-reserve attempt

This increment closes E's two source joins from NEXT `3f71aab`: a durable original-request guard before C reserve, and a continuation that lets Bridge hold qualified state through E's existing HTTP/evidence lifecycle. The production separated service still refuses on macOS and still constructs only its real private vault and native HTTP provider. The shared internal lifecycle is tested with synthetic claims and a mock provider; it is not a production custody bypass or a second inference loop.

## Private wiring

`verifyDispatchAdmission` is removed. A claim-only callback cannot keep Bridge's observation held through dispatch. `SeparatedServiceOptions` now requires `getReviewedApproval(binding)` and `withDispatch(claimInput)`. The latter returns the actual four-field provider reply after the committed continuation, not a claim or a boolean.

The existing Bridge connection and E service connect through these private callbacks:

| Bridge configuration | E service callback |
| --- | --- |
| `getReviewedApproval(binding)` | `service.getReviewedApproval(binding)` |
| `withCommittedIntent(lookup, consume)` | `service.withCommittedIntent(lookup, consume)` |
| `dispatchCommitted(admission, claim)` | `service.dispatchCommitted(admission, claim)` |
| `withCommittedSettlement(method, lookup, consume)` | `service.withCommittedSettlement(method, lookup, consume)` |

The service's `withDispatch` option calls that same connection's `withDispatch`. Its existing `settleInference` and `reconcileInferenceSettlement` options call the same connection's factual settlement methods. The service's `getReviewedApproval` option reads the exact already-reviewed pair from trusted host state; it must not point back to the service method. Lazy callbacks permit the two objects to refer to each other without executing a dispatch during construction. No new public route, renderer method, general dispatcher or model orchestration is introduced.

Bridge validates the exact narrower inference operation/admission/settlement schema at its existing runtime boundary. E's declarations continue to describe its broader supported data classes and frozen operation type. The E strict consumer passes; direct TypeScript assignment to Bridge's narrower types is not claimed. A typed host must use an actual validating boundary with correct declarations, not a cast or fabricated declaration. No C/Bridge files are changed by this E package patch.

## Before C reserve

`service.getReviewedApproval` observes the trusted owner, registered task/route and live vault generation, then registers the immutable task policy in the existing ledger. The shared reviewed-pair helper snapshots inputs, validates the exact proof/operation binding and expiry, and calls synchronous `ledger.beginReserveAttempt(binding, operation)` before returning either value to Bridge. The helper does not verify cryptography; C remains the owner authority.

The existing SQLite database gains `reserve_attempts`. It stores only the twelve-field binding, operation ID/digest and request digest. It stores no approval proof, operation plaintext, request/reply text or credential. The original UUID (case-insensitive) and operation ID are globally unique. It also refuses legacy held/completed worker requests. `reserveAttempt(owner, task, uuid)` is an inspection method, not a permission to repeat a reserve.

No attempt is deleted or reset after refusal, timeout, lost reply or restart. Changing the UUID cannot reuse the original operation; changing the operation cannot reuse the original UUID. New independent owner-approved operations are still subject to all existing request/spend caps. Failed SQLite commit rolls back and cannot return the reviewed pair to C. This guard does not charge allowance; E's original worker reservation remains the single accounting step.

## Claim through evidence

`service.dispatch` snapshots the original private request and requires the matching durable reserve attempt. It independently verifies the admission and atomically commits the existing worker intent and worst-case allowance, then calls Bridge `withDispatch` once. Bridge calls E `withCommittedIntent`, which verifies the original lookup and persists `claim_started` before awaiting `consume` once.

Inside that held consume scope, Bridge independently observes state and makes its sole C claim. It calls E `dispatchCommitted` with the exact admission and claim. E accepts the exact reply, reobserves policy, rechecks expiry, commits `http_started`, and invokes its existing native provider. Native custody rechecks expiry and the abort signal immediately before transport. E commits completed or unknown evidence before the callback returns or throws, so Bridge's qualified-state fence encloses HTTP and durable evidence.

Intent/HTTP callbacks require the active original invocation and are one-use. They cannot reconstruct a continuation from persisted phases. The original route's `max_request_ms` bounds the entire Bridge continuation. Timeout revokes the scope, aborts transport and retains worst-case uncertainty; a late claim/custody/reply cannot start HTTP or overwrite the recorded outcome. The revoked active request/owner fence remains until the underlying Bridge callback settles: timeout is not callback quiescence, so close, credential entry and recovery stay blocked during that interval.

After Bridge returns, the service delivers the exact original outbox as before. Settlement failure cannot change completed evidence or restore allowance. `withCommittedSettlement` reads and matches the persisted method, immutable intent lookup and receipt digest; it also works after restart/logout without an active dispatch or live observation. It never claims or runs inference.

## Focused verification

In the owned disposable `acceptance-worker-continuation-377da04` tree with NEXT `3f71aab` contracts, Node 24.11.1 passed:

- `check-reserve-attempt.mjs`: 6 groups covering reopen/lost result, UUID/operation mutation, strict binding/policy, forced COMMIT failure, two SQLite handles and legacy holds.
- `check-worker-continuation.mjs`: 6 groups covering the held lifecycle, original attempt requirement/caller snapshot, malformed or repeated callback refusal, timeout/late claim, timeout during native custody, and reserve-before-return/restart. The six groups were rerun once after adding the concrete callback-quiescence fix; all passed.
- `check-dispatch-expiry.mjs`: both existing asynchronous expiry groups passed.
- The affected `Lane E disposable mock acceptance:` group passed, including unexpired mock DSH/proxy/native-wire behavior; external API calls were zero.
- The strict no-emit consumer passed on its first run with pinned TypeScript 6.0.3, 215 resolved inputs and zero external non-toolchain dependencies.

Fifteen distinct runtime groups passed. Checks used only inert synthetic credential fixtures. No actual key, signature authority, provider call, socket, service activation, installation, host setting or shared-checkout edit occurred. Full suites/builds and production separate-UID custody were not run. NEXT still owns connected C/Bridge/DSH integration and usable pilot/browser qualification; these focused tests do not claim that runtime qualification.
