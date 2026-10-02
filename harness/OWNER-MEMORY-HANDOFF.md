# Unmounted owner-memory source seam

Owner hooks: `controller.setApprovalAction(handler|null)`, `controller.setForgetAction(handler|null)` and `controller.submitApproval()`. A memory action requires its explicit handler. The client forwards the controller’s private invocation options to `workflow.approveAndSave(options)` or `forgetWorkflow.approveAndForget(options)`. Each workflow uses the invocation’s owned `options.approve` callback for the exact retained review; it does not call raw `controller.approve()` while a hook is installed. The exposed `client.approveAndForget()` checks that the retained operation is `memory.forget`, then enters through `controller.submitApproval()`. The current controller dispatches by operation action and validates save and forget results separately; the owner surface renders the separate logical-forget result. This source join does not qualify the protected runtime or browser path. Save retains the exact draft, operation and independently paired `memory_capture`, coalesces repeated clicks, consumes the returned exact `approval_proof` for one save, then presents actual receipt/citation and independent storage/index/settlement states. Forget retains the exact record summary and presents a logical tombstone result, never a save result or a physical-erasure claim. Unknown outcomes fence repeat effects. The owner UI owns its separate plugin and genuine source/output receipt; bridge owns both workflow factories. No frozen face is changed by this source seam.

H factories are implemented but not imported/mounted by `host.mjs`:

- `owner-memory-browser.mjs`: `createOwnerMemoryHttpCall({contracts,fetcher?})` → `call(method,input,{signal?})`. Exactly one same-origin POST to `/api/prime/bridge/<method>`, closed 16-method allowlist matching the bridge public grammar, redirect refusal, strict bounded JSON/UTF-8 reply, no mutation retry. The added methods are `owner.logout`, `memory.proposeForget`, `memory.forget` and `memory.recover`; private reserve, dispatch, settlement and administration methods remain absent.
- `owner-memory-transport.mjs`: `createOwnerMemoryHttpRoutes({connection,publicBoundary,guardRequest,contracts})` → exact route descriptors. The existing DSH connection guard and trusted C/B origin profile precede any body read; they confer no owner authority. JSON is byte/depth bounded and strict before dispatch. The injected boundary must apply the existing bridge public qualification gate.
- `owner-memory-ipc.mjs`: `createOwnerMemoryIpcBoundary({channel,deployment,connect?})` → `publicBoundary.handlePublic(method,input)`. `channel` is a protected fixed authenticated public-worker channel; `deployment` is exact `{source_commit,release_digest}` from H's protected manifest (`release_digest` has `sha256:` prefix). A fresh channel checks authenticated `capability.status` and then sends one request; it does not retry after send. Missing config, unqualified/internal listener, mismatched release/source, or bare true refuses. HTTP association/role is never forwarded as IPC source context.
- `owner-memory-context.mjs`: `createOwnerMemoryContext({taskRegistry,bindings})` → the worker's existing `resolveHostContext`. Exact root-config binding `{credential_id,owner_id,task_id,memory_host}` pins captured source/event bytes. Actual server-generated `{transport:'ipc',credential_id}` selects the binding. C's verified session must match owner/subject and the active immutable Task. No browser body/header supplies owner/task/source; empty bindings refuse. Imports use fixed own source/composed paths only.
- `owner-memory-host.mjs`: `createOwnerMemoryHost({connection,guardRequest,contracts,channel,deployment})` assembles the guarded routes with the fixed authenticated IPC boundary. A missing channel/deployment remains unavailable. This creates no listener and is not mounted in `host.mjs`.
- NEXT SOURCE-ONLY: `mountOwnerMemoryHost({webServer,connection,guardRequest,contracts,channel,deployment})` registers those same exact routes and returns their disposer for the trusted composition's Cordis effect. Missing trusted inputs refuse. Partial registration rolls back prior routes; disposal fences requests still collecting a body or awaiting an IPC connection/capability reply. Already submitted effects retain their actual result/unknown handling. All unregisters are attempted; failed unregisters remain inert and can be retried by calling the disposer again. The default preview does not invoke this function. Its focused transport lifecycle check ran with 61 assertions using in-memory streams and a fake dispatcher.
  If both registration and rollback fail, `OWNER_MEMORY_HOST_REGISTRATION_FAILED` exposes a non-enumerable `dispose()` method for retrying residual cleanup; the residual handlers already refuse. The trusted lifecycle owner must retain this error until cleanup succeeds.
- `owner-memory-client.mjs`: `createOwnerMemoryClient({controller,contracts,ownerBinding,isCurrentConnection,fetcher?,passkeySigner?})` retains one adapter instance and exposes its frozen native `binding`. `ownerBinding` is exactly `{owner_id,passkeyProfile}`. No connection, login, assertion, save, forget or recovery occurs during construction/attachment. Provide the binding through native Cordis `primeAuthority`, wait for the native controller's `connect`, then call `attach()` to create both workflows and install separate explicit save and forget approval hooks. The factory requires capabilities separately. `logout()` removes local access immediately and returns the actual durable C reply; only `status:'LOGGED_OUT'` confirms revocation. Lost replies remain `OUTCOME_UNKNOWN`. Native sign-out, the new binding authority logout method and teardown share one revocation result per login attempt. Teardown first fences/disposes both workflows, then removes both hooks and disconnects the controller so a reentrant notification cannot send a previously unsent effect. A signer injection is a trusted composition/test primitive, never guest input or proof of human presence.

The imported bridge `startPublicMemoryWorker` (`kind:'public-memory'`) delegates every call to existing `bridge.handlePublic` and reports `public_dispatch:'qualified-owner-memory/v1'` in `capability.status`. That gate already requires the trusted structured `prime-separated-runtime-host/v1` acceptance record on each actual request. The internal/synthetic `startMemoryWorker` (`kind:'memory'`) retains its private `handleTrusted` seam and omits the marker. A prior capability read never grants authority. No acceptance record, credentials, identity, state or listener is created by the H factories or this source import.

Browser composition (source interface; not activation):

NEXT SOURCE-ONLY: `owner-memory-native.mjs` supplies the optional two-stage
`createOwnerMemoryNativeBinding(scope,options)` lifecycle owner. It requires the
existing `scope.primeOwnerUi` and its matching `primeOwnerNativeConnection`,
refuses an existing `primeAuthority` service,
constructs one client and provides its exact binding through native Cordis.
It neither calls `controller.connect` nor guesses when B has connected. After
the trusted native composition confirms B connected that exact binding, call
`attachAfterNativeConnection()` to install both hooks and the optional panel.
The helper captures the acknowledgement service identity and requires a fresh
`isConnected(client.binding)` result before attachment, between hook setters,
after panel provision and before subsequent use or each cleanup mutation.
Owner-ID equality and capability rows cannot replace that acknowledgement.
The lower-level client requires the same trusted current-connection observer.
A connection witness becomes false on replacement, including same-object
reconnect. Recovery also rechecks the captured owner and connection after
awaiting controller reconciliation.

Keep the helper inside its owning Cordis effect and dispose it before replacing
the binding. `setCapabilities(value)` and `capabilitiesUnavailable()` are explicit
post-attachment operations using independently observed status; no status read,
login, recovery, save or other request is scheduled. Late wrapper calls refuse.
Teardown attempts client/panel removal before authority removal, retains failed
removers and exposes retryable `error.dispose()` if setup/attachment rollback
itself fails. Reentrant attachment refuses; disposal during a hook notification
cannot reinstall the next hook. The focused candidate check ran with 95 assertions using an actual B
controller and fake registry; the six actual C/D recovery cases also passed
using synthetic credentials and disposable SQLite. They establish no
browser or real owner acceptance. B
`2c505856` now supplies witness-owned cleanup, including replacement during
connection setup. The exact compiled B/H join passed 11 groups with pinned
Cordis, zero HTTP requests and zero credential assertions. Compose already
copies this sibling module and
retains the existing three exact client-import rewrites; its new composed-module
import assertion is included in that 95-assertion check.

```js
let native
scope.effect(() => {
  native = createOwnerMemoryNativeBinding(scope, {contracts, ownerBinding})
  return () => native.dispose()
}, 'prime owner memory binding')
// Only after trusted composition confirms B connected native's exact service:
const client = native.attachAfterNativeConnection()
// Supply an independently observed capability result, never synthetic approval:
native.setCapabilities(observedCapabilities)
// Login and recovery remain explicit owner-flow actions.
```

This is a trusted composition API, not a shipped browser entry or an activation
switch. The default host, public routes and native plugin descriptors remain
unchanged. The lower-level client API below remains available to that same
trusted composition; it must follow the same connection/lifetime ordering.

NEXT SOURCE-ONLY: the client now forwards Bridge's `recall({query,limit})`
and `getRecallSnapshot()` and can provide B's optional native memory panel with
`client.providePilotMemory(scope)`. The exact frozen projection is
`{ownerController:controller,client}`. The scope must expose that same
`primeOwnerUi` controller; attachment and native `primeAuthority` connection
must already have happened. Register this helper within the trusted browser
composition's own Cordis effect and retain its returned disposer. It creates
no connection, login, capability observation, recovery or request. Independently
observed capability status must still be supplied through `setCapabilities`.

Client disposal removes the panel projection before disposing the stores and
binding. Failed native removal remains owned and retryable through `dispose()`,
including disposal during registration or during removal itself. After binding
replacement, construct and attach a fresh client and explicitly recover under
the fresh authenticated session. The default browser composition does not call
this helper. The private NEXT owner output has been rebuilt from the corrected source;
its verified receipt binds 87 source inputs and 46 generated outputs. Actual
served bytes and browser events remain unverified. Focused candidate lifecycle
regressions ran as recorded above; installed native injection remains unverified.

```js
const acknowledgement = scope.primeOwnerNativeConnection
const client = createOwnerMemoryClient({controller,contracts,ownerBinding,
  isCurrentConnection: binding =>
    scope.primeOwnerUi === controller && acknowledgement.controller === controller &&
    scope.primeOwnerNativeConnection === acknowledgement &&
    scope.primeAuthority === binding && acknowledgement.isConnected(binding) === true
})
// Native H composition provides client.binding as Cordis primeAuthority.
// After B's native injection has synchronously called controller.connect:
client.attach()
// Within the trusted native composition effect, using that same controller:
scope.effect(() => client.providePilotMemory(scope), 'prime-pilot-memory')
// After a fresh host-confirmed login, recover explicitly before new work.
await client.recover({operation_id:null})
await client.proposeSave({extraction_json,idempotency_key})
// B displays the exact paired draft; the human requests a review and approval.
// Its submitApproval() invokes the installed workflow once.
```

`recover()` and `recoverForget()` require the current authenticated owner. They read the server's durable workflow reference and actual C/D facts and may resend only an already committed settlement receipt. They do not construct proofs, reserve new authority, dispatch or repeat an effect. A `known_unsent` recovery reply is refused with `RECONCILIATION_REQUIRED`; it does not prove durable unsent closure or clear an uncertain operation. An unknown or mismatched reference remains fenced. For a separate logical-forget surface, use `proposeForget({record_id})`, prepare the exact controller review, then explicitly call `approveAndForget()` and render `forgetWorkflow.getSnapshot()`; use `recoverForget({operation_id:null})` after rebinding. No automatic recovery or mutation is scheduled on login.

Authority and memory come from the same adapter instance. The workflow passes `response.operation` and `response.memory_capture` together to `setOperation`; it never reconstructs the review draft from proposed parameters. Installing a hook before native `primeAuthority` injection is incorrect: B's asynchronous default binding may otherwise reconnect and clear it. Worker context is prepared from actual server-captured events in protected configuration, with explicit Task/attribution/privacy/scope. Dynamic guest registration and unsigned capture are absent. `createOwnerMemoryContext` does not authenticate arbitrary objects itself; it is only the callback downstream of authenticated IPC and C session verification.

Scoped source checks: `node harness/check-owner-memory-client.mjs` checks actual B controller + both bridge workflows + H HTTP/client assembly against synthetic replies, including one exact save, duplicate clicks, unknown fencing, confirmed/uncertain logout without duplicate requests, pending login isolation, recovery on a fresh binding without another save/proof, explicit forget callback and recovery, save callback reselection after a known-unsent forget, unmounted host refusal and an independent composed module import. It starts no listener. `node harness/check-owner-memory-transport.mjs` checks all four new methods under the closed allowlist and unmounted refusal, alongside the existing bounded transport/origin guards. Compose includes the owned `runtime-bridge` runtime closure, excludes its test trees, and rewrites exactly three browser imports to that release's own `prime-packages`. These checks are not the completed genuine C/D→PostgreSQL fixture, browser user presence or full gate qualification.

Current public routes/capabilities remain unavailable. Real owner pins, enrolled ES256 credential and the exact selected RP/origin remain held human/configuration inputs; the localhost profile is exactly `http://localhost:18731`, RP `localhost`, and cannot be substituted with preview `127.0.0.1:18732`. No key enrollment, new security/access action, root migration, API key, paid call, worker restart, publication or browser action is part of this source checkpoint.
