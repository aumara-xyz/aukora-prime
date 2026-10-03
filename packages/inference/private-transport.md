# Application-to-E dispatch binding

`@aukora-prime/inference/private-transport` supplies the existing callback consumed by `RemoteDeepSeekProvider` and a receiver binding for `SeparatedCredentialService.dispatch`. It constructs no provider, service, channel, listener, credential, IAM rule or socket. It does not implement a second inference loop. H/Bridge own the protected connection and authenticated per-invocation cancellation; E supplies request validation, detached copies, the bounded application wait and the receiver's connection to the existing worker lifecycle.

```ts
type PrivateInferenceDispatch = (
  envelope: Omit<ProviderRequest, 'signal'>,
  options: {signal: AbortSignal}
) => Promise<ProviderReply>;

createPrivateInferenceDispatch({
  send: protectedHostDispatch, // the same signature, one authenticated submission
  max_request_ms,             // explicit bound from the approved route policy, <= 60000
  max_request_bytes,          // explicit framing bound, <= 2 MiB
}): PrivateInferenceDispatch;

createPrivateInferenceReceiver({
  service,                   // existing separated service, not created here
  max_request_bytes,
}): PrivateInferenceDispatch;
```

The application passes the returned dispatch function to `new RemoteDeepSeekProvider({dispatch})`, then uses its existing `ExternalDeepSeekGateway` and pinned DSH registration. The application ledger and request receipt store remain distinct from the worker's protected ledger/vault. Root owns the owner/task request binding and native presentation glue; no `owner-inference-*` or root harness paths are changed here.

Missing `send` or receiver service refuses with `PRIVATE_CREDENTIAL_TRANSPORT_REQUIRED` before a usable callback is returned. A callback's presence does not authenticate a peer or qualify custody; H must provide the actual protected runtime. The Linux separate non-root UID requirement and service constructor remain unchanged. Nothing is activated by importing this module.

## Existing fields and lifecycle

The envelope has the same eighteen E fields; the admission keeps its twelve binding fields plus frozen operation, consumed grant and request digest. The adapter uses the existing frozen validators and domains. It checks closed structure, original owner/task/conversation/UUID, exact body/citation hashes, operation/grant correlation and the four-field bounded reply. It does not independently authorize a grant, approve route prices or derive allowed spend. E's existing private policy observer, durable attempt, worker intent, exact C claim and evidence/outbox remain the authority/accounting path.

Both sides snapshot inputs before asynchronous callbacks. The application submits once. A missing reply, malformed reply, service error or timeout returns fixed `PROVIDER_OUTCOME_UNKNOWN`; no raw channel error, header or credential metadata crosses the planner boundary. No automatic retry, reconnect, replacement UUID, new proof, fallback provider or refund is added. An application timeout/cancellation is not proof of an unsent request or worker quiescence. Existing worker unknown-outcome and retained active fences remain responsible for that distinction.

Before submission, an aborted caller signal refuses `CANCELLED_BEFORE_DISPATCH`. After submission, abort propagates through a fresh application-side signal and returns `CANCELLED_AFTER_DISPATCH`. Timeout also aborts that signal and returns unknown. Late completion is discarded. The adapter neither closes the service nor drains or resets its ledger.

## H/Bridge coordination seam

H's protected sender must propagate cancellation for the exact authenticated connection invocation. The receiver supplies its own local `AbortSignal` to `createPrivateInferenceReceiver`; it must not decode an `AbortSignal` from JSON or expose cancellation using only an untrusted UUID. Cancellation requests stopping work and never supplies settlement, release or an unsent certificate.

Current NEXT `c04c46a` Bridge authority IPC exposes `request(method,input)` and does not propagate cancellation to its handler. It is not a substitute for this host binding. This E increment does not change that method profile, reuse its private credentials in the application, or change memory transport behavior. No cross-thread messaging capability for the supplied H/Bridge thread IDs is callable in this execution context; these signatures are the coordination handoff, with parent relay requested.

The independent budget-observation interface is a separate [design pending approval](budget-observation-proposal.md). It is not implemented or adopted here. Missing protected transport, independent observation, enrolled owner, approved configuration, Linux custody and HTTPS deployment remain explicit runtime dependencies. Completion awaits Peter-relayed GLM verdict.

## Attached source checks

In the owned disposable `acceptance-private-transport-3ca1cdf` tree, Node 24.11.1 ran `node --test packages/inference/check-private-transport.mjs`: 4/4 groups passed, exit 0. Raw output is retained as `private-transport.tap`. These fixtures exercise detached frozen request bindings, unavailable/pre-abort behavior, cancellation to a distinct receiver-owned signal, fixed errors, timeout and late completion. They use callback fixtures only: no IPC socket, protected peer authentication, separated-service construction, credentials, provider traffic or service-blocked verification was exercised or rerouted.

The attached compile-only `check-private-transport-types.mts` passed once with pinned TypeScript 6.0.3, strict NodeNext/noEmit/skipLibCheck=false, 216 resolved inputs and zero external non-toolchain inputs. It verifies the private package export, adapter-to-provider assignment, existing service receiver compatibility and rejection of booleans or missing signals. Raw resolved-file output is retained as `private-transport-types.log`; this check does not qualify a protected peer.
