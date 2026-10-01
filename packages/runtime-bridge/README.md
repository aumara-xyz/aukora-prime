# Prime runtime bridge

This package joins the existing authority, memory and UI packages. It owns no
kernel, executor, enrollment, credentials, PostgreSQL client or HTTP listener.
H owns the app mount and route qualification. C owns proof/session verification,
reservation, dispatch and settlement. D owns transactional memory effects and
the live target observation under its owner database lock.

```js
const taskRegistry = createTrustedTaskRegistry(trustedRegistryEntries)
let memory
const authority = createAuthorityService({
  ...trustedAuthorityConfig,
  authorizeTask: taskRegistry.authorizeTask,
  observeTarget: operation => memory.authorityTargetObservation(operation),
})
memory = createPostgresMemory({pool: pgPool, authority, contracts})
const bridge = createRuntimeBridge({
  authority, memory, taskRegistry, resolveHostContext, verifyHostQualification,
})
```

The host supplies an already configured `pgPool`. No credential discovery or
automatic migration/provisioning occurs. Every authority dependency must be the
corrected service, including `authenticateSession` and the D memory settlement
join. Required missing methods report `unmounted`; a mounted graph without host
acceptance reports `unqualified`. Public service calls remain unavailable.

`resolveHostContext({request,session})` is a trusted host callback that selects
the request's authenticated task and captured source event. Before login it
returns exactly `{login_owner_id}` from trusted owner selection. After C verifies
the opaque token it returns exactly `{task_id,memory_host}`. The bridge sets
`memory_host.owner_id`, `owner_subject` and `task_id` from C/registry and refuses
conflicting host values. It never accepts a caller's registry, source events,
owner, task, provider, region, policy or expected state as trusted context.
The `request` argument is a bounded host-owned JSON association record (for
example transport/request ID and exact Host/Origin), rather than a raw Node
request/stream object. Both input and this association/role are detached before
the first wait, including host qualification. Omitted roles default to read-only.

Registry entries are closed `{task,provider_and_region,audience,policy_version,
data_scope}`; `task` is the frozen Task v1. Construct a new registry for a new
trusted lifecycle snapshot. There is no public registration/update method.
The memory audience is `aukora-prime.memory`.

`handleTrusted(method,input,{request,role})` is the closed service seam for the
host-owned boundary and disposable qualification checks. It still verifies C's
current session and all exact operation/target binding. It does not establish
UID isolation or qualify HTTP routes. `handlePublic` additionally requires H's
host verifier to return an accepted structured production
`prime-separated-runtime-host/v1` record: separate numeric app/broker UIDs,
authenticated IPC, qualified owner enrollment and PostgreSQL runtime, and exact
source/release pins. A boolean or synthetic profile refuses. The verifier is
trusted deployment configuration, never a guest field. No current pilot profile
is independently accepted by this package.

Public method allowlist:

- `capability.status`: `{}`.
- `owner.loginChallenge`: `{owner_id,kind:'passkey'}`; owner selection is checked
  against the trusted host. `owner.loginComplete`: `{challenge,material}`.
- `owner.approvalChallenge`: `{session_token,operation}`.
- `owner.approvalComplete`: `{session_token,operation,proof}`.
- `owner.declineApproval` / `owner.status`: `{session_token,operation_id}`.
- `memory.proposeSave`: `{session_token,extraction_json,idempotency_key}`.
- `memory.save`: `{session_token,operation,approval_proof,extraction_json,idempotency_key}`.
- `memory.status`: `{session_token,record_id,revision:null|string}`.
- `memory.cite`: `{session_token,record_id,revision:null|string,retained_head:null|string}`.
- `memory.recall`: `{session_token,query,limit}`.

No public reserve, claim, settlement, cancellation, epoch, import, erasure or
administrative route exists. The proposer channel can propose and read; only the
owner-control channel can mutate approval or save. Channel credentials never
prove owner identity. `extraction_json` is a bounded original UTF-8 JSON string so
historical confidence decimals survive inside the frozen integer-only envelope.
D's duplicate/depth/finite-number parser reads it; the OperationProposal contains
capture/key hashes, exact live heads and literal statement/attribution. The frozen
v1 digest profile is unchanged.

`memory.proposeSave` obtains D's exact capture binding and builds the operation
from C's verified owner plus host-owned task/route/policy. C proposal admission
receives the closed authenticated `{session_token,operation}` envelope. A transport
role alone cannot admit a proposal or consume owner pending capacity. Approval methods scope
C's target checks through D's current locked observation. `memory.save` delegates
to `captureAuthorizedRemembered`; it never claims dispatch itself. D reserves,
commits an intent, rechecks live state under the owner lock, claims once, saves
record/events/chain/outbox/effect ledger, commits, then settles C using the genuine
memory receipt. Save parameters contain exactly `capture_sha256`,
`idempotency_key_sha256`, `heads`, `statement` and `attributed_to`. Literal statement
and attribution come from the captured extraction and trusted host. They accompany
the proposed operation as the independent `memory_capture` draft; expected review
text is never reconstructed from operation parameters or their hash. D verifies
all parameters again under its database lock before reserve and dispatch. A save
can be `saved/pending` or `saved/failed` before indexing.
Only D's later ACK makes the record searchable. Citation verifies original bytes,
source evidence, chain/member and retained head and grants no authority.

Unknown outcomes remain consumed. D's host-only `reconcileEffect` resends only a
committed local receipt; an unresolved intent forbids automatic retry. The bridge
has no public reconciliation receipt intake. Neither transport reconnect nor
client timeout resubmits a mutation.

## Owner memory action

`@aukora-prime/runtime-bridge/owner-memory-workflow` exports the browser-safe
`createOwnerMemoryWorkflow({controller,memory,contracts})`. B owns its existing
controller and review surface. H supplies `memory` from the same
`createUiAdapters({call})` instance whose `authority` is bound to that controller;
`call` remains H's authenticated transport and qualified app mount. This helper
does not create a route, session, source context, signer or qualification.

```js
const adapters = createUiAdapters({call: authenticatedWorkerCall})
controller.connect({...ownerBinding, authority: adapters.authority, contracts})
const workflow = createOwnerMemoryWorkflow({
  controller, memory: adapters.memory, contracts,
})
controller.setApprovalAction(() => workflow.approveAndSave())
// B's button calls submitApproval(); the helper calls approve() directly.
await workflow.proposeSave({extraction_json, idempotency_key})
// B's existing prepare() obtains the fresh exact review for owner display.
```

The proposal retains the detached exact extraction string and key, then passes
the response's independent `memory_capture` directly to `controller.setOperation`.
The owner/source/Task context remains derived by the worker, never supplied in
the browser draft. After explicit owner approval, `approveAndSave()` checks the
returned proof against the retained full operation and current owner session,
then invokes `memory.save` once with those exact fields. Concurrent and
notification-triggered clicks share the pending action. An attempted capture
cannot be submitted again through this helper; uncertainty blocks new captures
until host reconciliation. Ending a session before dispatch sends no save.

`getSnapshot()` and `subscribe()` expose approval, save, receipt, citation, index
and C settlement independently. Methods resolve a frozen snapshot. A validated
save result can remain `saved:true` with C settlement `pending`; this requires
reconciliation. A lost or invalid save response is `save:'unknown'`, `saved:null`
and cannot be retried. The helper checks receipt operation/owner/grant/result
bindings; commitment hashes are authenticated D/C claims. D and C retain the
authoritative preimage/digest, proof, effect and settlement verification. No
additional memory canonicalizer or authority verifier is introduced here.

After a confirmed save, the helper reads the exact record's status and citation.
Failure of either read preserves the genuine save receipt and sets
`read_error_code`. `refresh()` performs only those reads, using the retained
citation head; it never saves, settles or drains the index. Index booleans remain
`null` until D confirms them. A `VERIFIED` citation grants no authority. Ending
the session clears prior owner content while preserving content-free confirmed
save/settlement facts. `dispose()` affects this helper alone and does not cancel
or replay a mutation. H removes the action hook/subscription during teardown.

The scoped source checks use actual B/C/D objects and synthetic P-256 assertions
with a SQLite dialect fixture, including browser WebCrypto operation digests.
They establish source behavior, not a real owner ceremony, PostgreSQL/runtime
qualification or an activated public route. H/B composition and qualified owner
activation remain separate.

## Existing UI injection

Browser-safe `createUiAdapters({call})` from `src/ui-adapter.mjs` returns
`{authority,memory,logout}`. Inject `authority` into the unchanged
`createPrimeTransport` interface. The adapter retains the exact reviewed operation
and digest per session, checks completion binding, and attaches it to completion
for D's target observation. Its 16-review cache is discarded before submission;
an uncertain result requires a new explicit reconciliation path. Memory methods
use the successful C login token held in this adapter and reject caller overrides.
The adapter retains the successful sibling `memory_capture` and verifies exact
literal equality before review and save. H passes the sibling to B as
`controller.setOperation(operation,{memoryCapture:response.memory_capture})`;
direct transport users pass it to `prepareApproval(operation,{memoryCapture})`.
Missing or changed statement/attribution refuses before signing. This browser
comparison makes no claim to reproduce D's private full capture hash.
Logout and new login invalidate pending replies before they can restore a token
or repopulate captures/reviews. The 16-slot quotas reserve pending calls before
dispatch, so parallel responses cannot exceed the retained state bounds.
This package changes no face source or projection registration. Aura's durable
projection still needs H's host join; one save does not qualify all app features.

## Authenticated process transport

`createIpcServer({socketPath,credentials,handlePublic,limits})` and
`createIpcClient({socketPath,credential,limits})` use Node Unix sockets. The server
accepts host-provisioned `{id,role,secret}` entries; the client gets `{id,secret}`.
Secrets are 32–64 bytes, distinct channel roles are `proposer`, `read_only` and
`owner_control`. The server selects roles from its pins, not the request. A fresh
server/client nonce handshake authenticates both peers with HMAC-SHA256 and derives
a connection key. Domain-separated authenticated requests/responses carry strictly
increasing sequence numbers. Canonical framed JSON rejects duplicate keys and
unsafe integer spellings before dispatch. Output, frames, connections, inflight
calls, requests and timers have fixed bounded defaults. Timed-out handlers remain
charged against inflight capacity until settled. Lost mutation replies are unknown.

The absolute socket directory must already be canonical, private (0700) and owned
by the configuring host UID. An occupied socket path refuses. The package does not
create a directory, UID, system service, firewall rule or secret. Separate processes
with the same UID can rewrite state, witness and configuration: the child-process
test establishes transport behavior only. Linux peer-credential enforcement,
separate UID/socket ownership, retained-witness custody and app-to-broker method
confinement need the separately approved deployment and acceptance.

## Scoped proof

```sh
node --test packages/runtime-bridge/test/*.test.mjs
```

The C/D check uses genuine ES256 passkey assertions, C's real durable stores/kernel,
D's actual SQL/effect code, existing B transport, and a clearly test-only SQLite
dialect shim with real file transactions and cold reopen. It verifies altered
operation/extraction/source refusals, saved/indexed distinction, cited read/restart,
lost COMMIT reply, post-dispatch write failure and receipt-only reconciliation.
SQLite does not establish PostgreSQL WAL/fsync/advisory locks/FTS semantics.
The C/F check uses actual C proofs/claims/settlement, F's real owned ledger/lifecycle
and F's explicit test-only SDK mock. It does not run OpenShell or establish runtime
confinement. The IPC check uses a distinct child process and disposable socket.
No real owner enrollment, credentials, private memory, paid inference, live app
activation, new UID/security setup or deployment is performed here.
The adapted review checks additionally cover 129 unauthenticated proposals before
valid admission, hidden raw mutation routes, independently paired review text,
exact saved whitespace/Unicode/markup bytes, stale UI replies and parallel quotas.

## Worker followup for H's approved isolated setup

Run `node packages/runtime-bridge/src/worker.mjs --config /absolute/worker-config.mjs`.
The immutable host module's default export is one of these closed records:

- Authority: `{kind:'authority',ipc,registryEntries,authorityConfig}`.
- Memory: `{kind:'memory',ipc,registryEntries,authorityChannel,createPgPool,
  resolveHostContext,initializeSchema?,indexTarget?,indexGeneration?}`.
- Public memory: the same memory fields with `kind:'public-memory'` and mandatory
  `verifyHostQualification` from protected host configuration.

`@aukora-prime/runtime-bridge/worker` exports `startPublicMemoryWorker` for H's
explicit public-worker composition. Every RPC, including a call after capability
preflight, delegates to existing `bridge.handlePublic`. Its capability response
adds `public_dispatch:'qualified-owner-memory/v1'`; this marker identifies the
dispatch gate, not host acceptance. The structured host record still must pass
on each request. A missing verifier refuses configuration; null, boolean or
synthetic qualification results keep all effects unavailable. Startup status
reports `qualification:'per-request'`. The internal `startMemoryWorker` retains
its exact closed config, uses `handleTrusted` and omits this marker. H's public
IPC proxy must refuse that internal listener. No factory supplies acceptance,
owner credentials, source bindings or a deployed listener by default.

Production worker CLI config modules must be canonical root-owned regular files
with exact mode 0440 and the running worker's primary group. The direct parent
must be root-owned 0750 with that group; ancestors must be root-owned and forbid
group/other writes. The entry runs as a non-root worker. G/H must verify that the
dedicated primary group contains only its worker, has no extra app ACL, and that
imported secret material and all source/config/state ancestors remain protected.
This check alone does not qualify imported module permissions or deployment ACLs.
The synthetic client uses its private 0600 config. `test/worker-fixture.mjs`
permits same-UID 0600 disposable worker configs only for checks; it is not a
production export or installed entry point.

`ipc` is `{socketPath,credentials,limits?,socketAccess?}`. Authority credentials
accept only the fixed `memory_effect` role/private authority method list.
`authorityChannel` is `{socketPath,credential,limits?,socketAccess?}`. Memory
credentials accept the public role matrix. `createPgPool()` supplies the explicit
host pg 8.16.3 closure and config; it is not discovered. `initializeSchema:true`
is only for H's freshly authorized disposable schema. Internal workers report
unqualified. The explicit public worker rechecks host qualification per RPC;
its configuration or startup marker alone does not enable app HTTP routes.
Before starting a fresh synthetic authority worker, H's setup-only local path
must explicitly call C's `provisionNewAuthorityStore(trustedOptions)` once with
approved public configuration and a pristine dedicated witness namespace. Normal
services never provision missing state, even with a sticky provision flag. The
bridge and both worker method lists expose no provisioning or recovery reset.

Separate-UID `socketAccess` is exactly `{server_uid,client_uid,group_gid}`.
H/G must provision a canonical server-owned directory with exact mode 0710 and
the configured group, plus memberships. The server verifies its UID, binds its
new socket, sets its group and mode 0660; the client verifies its own UID and
server directory/socket ownership and modes. Clients cannot write the parent.
No worker creates a UID, group, parent directory or system unit. App ownership
must not reach broker source/config/state/witness or database writer credentials.

The private wrapper is exactly `{input,operation,operation_digest,observation}`.
Only review/reserve/claim carries D's closed live observation. It comes from D's
active owner database lock; memory's proxy retains the full canonical reviewed
operation keyed by owner, operation and digest. C installs a request-local scope,
calls its synchronous real method and clears in `finally`. There is no await or
cache inside that C scope. C independently verifies registered task/owner/route,
operation digest and normal proof. Dispatch IDs/digests come from D's committed
intent. Settlement carries no observation and no caller-produced receipt.
The memory proxy opens a fresh authenticated authority channel for each unsent
call and closes it afterward. C-only restart, idle closure and request-count
limits therefore do not permanently disable D. Every call sends once; timeout
or disconnect still leaves the caller's outcome unknown and is never retried.

H can run `node packages/runtime-bridge/src/verify-deployed.mjs --config
/absolute/synthetic-client.mjs --phase save`, restart the approved services, then
run the same command with `--phase read`. The trusted synthetic-only config
exports `{profile:'synthetic-prime-cd-check/v1',client,owner_id,passkeySigner,
extraction_json,idempotency_key,witness_path}`. H supplies the disposable signer
matched to C's explicitly configured synthetic public credential. The client
creates no keys/enrollment and prints only content-free evidence; an exclusive
witness records original-byte digest and retained citation head. The read phase
verifies exact bytes and C settlement across service restart. H must separately
observe actual PostgreSQL/version/fsync and distinct UID/ACL properties. This
source and its same-UID SQLite worker fixture do not supply those observations.
# Synthetic private C/D PostgreSQL fixture

The fixture entry points, closed configuration/signing grammar, H/operator
ownership and source/deployment evidence limits are in
[test/deployed-fixture.md](test/deployed-fixture.md). These files are outside the
package exports and preserve public runtime unavailability. The signer stays
inside the Mac owner's trust boundary, outside Linux workloads; fixed strict
SSH reaches only the approved protected app actor.

## Pinned owner hook and host source check

`test/verify-owner-memory-source-join.mjs` builds a fresh private source snapshot
from this repository's committed HEAD, B's verified complete bundle/evidence, and
H's four committed owner-memory helper modules at `4a2cd94`. It checks B's exact
artifact bytes and the controller's sibling browser adapter closure before
running the real C/D workflow through B's `submitApproval` hook. It writes the
input hashes, full check output and result beside the isolated snapshot. It
does not edit B/H source, their indexes, or this repository's dependency packages.

```sh
node packages/runtime-bridge/test/verify-owner-memory-source-join.mjs \
  --ui-bundle /absolute/ui-approval-hook.bundle \
  --ui-evidence /absolute/ui-approval-hook-evidence.json \
  --host-repository /absolute/isolated-h-repository \
  --output /absolute/fresh-private-check-directory
```

Hook tests explicitly skip when `PRIME_OWNER_HOOK_CONTROLLER` is absent; the
pinned runner supplies the exact copied B controller and treats any failed
joined guard as a failed checkpoint. Host tests likewise require the exact
copied H helpers via `PRIME_OWNER_MEMORY_HOST_ROOT`. C uses disposable synthetic
P256 credentials and its real verification/kernel/stores. D uses its actual
effect code with the test-only SQLite dialect fixture. Public IPC/HTTP checks
must refuse absent qualification; they never fabricate accepted host evidence.
No PostgreSQL, browser presence, enrollment or deployed UID acceptance is claimed
by this source check.

H must install the hook after `controller.connect`, which clears the previous
hook. During teardown, fence the workflow before disposing the controller:
`workflow.dispose(); controller.setApprovalAction(null); controller.dispose()`.
No stale UI action may dispatch merely because a disposed controller retained
an owner snapshot. Cancellation before the handler starts must release its
flight; cancellation after dispatch must retain an unknown outcome, while a
confirmed save remains a saved fact when only citation/index reads are pending.
These states are checked through the real hook, in addition to the direct
workflow lifecycle checks.
