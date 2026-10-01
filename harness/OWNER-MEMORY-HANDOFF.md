# Unmounted owner-memory source seam

Agreed B hook: `controller.setApprovalAction(handler|null)` and `controller.submitApproval()`. A `memory.save` action requires an explicit handler. H supplies `() => workflow.approveAndSave()`; the bridge workflow calls `controller.approve()` directly, avoiding recursion. It retains the exact draft, operation and independently paired `memory_capture`, coalesces repeated clicks, consumes the returned exact `approval_proof` for one save, then presents actual receipt/citation and independent storage/index/settlement states. Unknown outcomes fence repeat save. B owns the separate plugin and its genuine source/output receipt; bridge owns `createOwnerMemoryWorkflow`. H edits no frozen face or sibling package.

H factories are implemented but not imported/mounted by `host.mjs`:

- `owner-memory-browser.mjs`: `createOwnerMemoryHttpCall({contracts,fetcher?})` → `call(method,input,{signal?})`. Exactly one same-origin POST to `/api/prime/bridge/<method>`, closed method allowlist, redirect refusal, strict bounded JSON/UTF-8 reply, no mutation retry.
- `owner-memory-transport.mjs`: `createOwnerMemoryHttpRoutes({connection,publicBoundary,guardRequest,contracts})` → exact route descriptors. The existing DSH connection guard and trusted C/B origin profile precede any body read; they confer no owner authority. JSON is byte/depth bounded and strict before dispatch. The injected boundary must apply the existing bridge public qualification gate.
- `owner-memory-ipc.mjs`: `createOwnerMemoryIpcBoundary({channel,deployment,connect?})` → `publicBoundary.handlePublic(method,input)`. `channel` is a protected fixed authenticated public-worker channel; `deployment` is exact `{source_commit,release_digest}` from H's protected manifest (`release_digest` has `sha256:` prefix). A fresh channel checks authenticated `capability.status` and then sends one request; it does not retry after send. Missing config, unqualified/internal listener, mismatched release/source, or bare true refuses. HTTP association/role is never forwarded as IPC source context.
- `owner-memory-context.mjs`: `createOwnerMemoryContext({taskRegistry,bindings})` → the worker's existing `resolveHostContext`. Exact root-config binding `{credential_id,owner_id,task_id,memory_host}` pins captured source/event bytes. Actual server-generated `{transport:'ipc',credential_id}` selects the binding. C's verified session must match owner/subject and the active immutable Task. No browser body/header supplies owner/task/source; empty bindings refuse. Imports use fixed own source/composed paths only.

The IPC public worker must report `public_dispatch:'qualified-owner-memory/v1'` in `capability.status` **only when its handler delegates every call to existing `bridge.handlePublic`**. That gate already requires the trusted structured `prime-separated-runtime-host/v1` acceptance record. An internal/synthetic listener using `handleTrusted` must omit that marker or report another profile. The public-worker composition is bridge-owned; H will not turn the existing internal worker into a qualified proxy by trusting a capability read alone. The worker must recheck `handlePublic` on the subsequent call. No acceptance record, credentials, identity, state or listener is created by these H factories.

Browser composition (source interface; not activation):

```js
const call = createOwnerMemoryHttpCall({contracts})
const adapters = createUiAdapters({call})
controller.connect({...trustedOwnerBinding,authority:adapters.authority,contracts})
const workflow = createOwnerMemoryWorkflow({controller,memory:adapters.memory,contracts})
controller.setApprovalAction(() => workflow.approveAndSave())
```

Authority and memory MUST come from the same adapter instance. The coordinator passes `response.operation` and `response.memory_capture` together to `setOperation`; it never reconstructs the review draft from proposed parameters. Worker context is prepared from actual server-captured events in protected configuration, with explicit Task/attribution/privacy/scope. Dynamic guest registration and unsigned capture are absent. `createOwnerMemoryContext` does not authenticate arbitrary objects itself; it is only the callback downstream of authenticated IPC and C session verification.

Scoped source checks: `node harness/check-owner-memory-transport.mjs` uses fake streams/dispatcher/IPC only, starts no listener and establishes no production acceptance. `node harness/check-owner-memory-context.mjs` verifies context/pin/byte isolation and an exact disposable composed-layout import. Compose includes the owned `runtime-bridge` runtime source closure, excluding its test trees. These checks are not the already completed genuine C/D→PostgreSQL fixture, browser user presence or full gate qualification.

Current public routes/capabilities remain unavailable. Real owner pins, enrolled ES256 credential and the exact selected RP/origin remain held human/configuration inputs; the localhost profile is exactly `http://localhost:18731`, RP `localhost`, and cannot be substituted with preview `127.0.0.1:18732`. No key enrollment, new security/access action, root migration, API key, paid call, worker restart, publication or browser action is part of this source checkpoint.
