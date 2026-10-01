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
only hashes and exact live heads. The frozen v1 digest profile is unchanged.

`memory.proposeSave` obtains D's exact capture binding and builds the operation
from C's verified owner plus host-owned task/route/policy. Approval methods scope
C's target checks through D's current locked observation. `memory.save` delegates
to `captureAuthorizedRemembered`; it never claims dispatch itself. D reserves,
commits an intent, rechecks live state under the owner lock, claims once, saves
record/events/chain/outbox/effect ledger, commits, then settles C using the genuine
memory receipt. A save can be `saved/pending` or `saved/failed` before indexing.
Only D's later ACK makes the record searchable. Citation verifies original bytes,
source evidence, chain/member and retained head and grants no authority.

Unknown outcomes remain consumed. D's host-only `reconcileEffect` resends only a
committed local receipt; an unresolved intent forbids automatic retry. The bridge
has no public reconciliation receipt intake. Neither transport reconnect nor
client timeout resubmits a mutation.

## Existing UI injection

Browser-safe `createUiAdapters({call})` from `src/ui-adapter.mjs` returns
`{authority,memory,logout}`. Inject `authority` into the unchanged
`createPrimeTransport` interface. The adapter retains the exact reviewed operation
and digest per session, checks completion binding, and attaches it to completion
for D's target observation. Its 16-review cache is discarded before submission;
an uncertain result requires a new explicit reconciliation path. Memory methods
use the successful C login token held in this adapter and reject caller overrides.
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

## Worker followup for H's approved isolated setup

Run `node packages/runtime-bridge/src/worker.mjs --config /absolute/worker-config.mjs`.
The immutable host module's default export is one of these closed records:

- Authority: `{kind:'authority',ipc,registryEntries,authorityConfig}`.
- Memory: `{kind:'memory',ipc,registryEntries,authorityChannel,createPgPool,
  resolveHostContext,initializeSchema?,indexTarget?,indexGeneration?}`.

Worker and synthetic client CLI config modules must be canonical regular files
with exact mode 0600, owned by root or their running UID. G/H must also keep
imported secret material private, and source/config/state ancestors protected
from app modification. The entry-file check alone does not qualify all imported
module permissions or deployment ACLs.

`ipc` is `{socketPath,credentials,limits?,socketAccess?}`. Authority credentials
accept only the fixed `memory_effect` role/private authority method list.
`authorityChannel` is `{socketPath,credential,limits?,socketAccess?}`. Memory
credentials accept the public role matrix. `createPgPool()` supplies the explicit
host pg 8.16.3 closure and config; it is not discovered. `initializeSchema:true`
is only for H's freshly authorized disposable schema. Both workers report
unqualified, and do not enable the app's HTTP routes.

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
