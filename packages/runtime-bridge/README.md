# Prime runtime bridge

This package joins the existing authority, memory and UI packages. It owns no
kernel, executor, enrollment, credentials, PostgreSQL client or HTTP listener.
H owns the app mount and route qualification. C owns proof/session verification,
reservation, dispatch and settlement. D owns transactional memory effects and
the live target observation under its owner database lock.

The explicit private v2 source adapter follows frozen decision v004 (SHA256
`95fcc9d4fb4420e2dbc13ba28b8332968b4b36e71f069a233847c23932a1c3b9`).
`createRetainedRuntimeBridge({authority,memory,closureProfile,taskRegistry,
resolveHostContext})` uses the actual D service's `readRetainedWorkflowJournal`,
`withRetainedWorkflowMutation` and `withRetainedJournalTransition`. Its profile
is exactly `{version:2,kind:'prime-private-unsent-closure/v2',
expected_authority_store_id,expected_memory_store_id,
retention_profile:'required-retained/v2'}`. The two IDs come from protected
pre-work configuration, never returned evidence. Missing methods, baseline,
current epoch, guards or retained continuity refuse; there is no legacy fallback.

This adapter preserves the original thirteen workflow columns and adds only the
selected six-column `prime_runtime_workflow_closure_progress_v2`. D must install
the exported fixed `RETAINED_JOURNAL_DESCRIPTORS` array on its branded live
owner query facade. Each closed descriptor has `name`, unchanged SQL `text`, and
ordered `parameters` selectors. Bridge mutators use only that facade and return `undefined`;
D retains pending, prepares the full candidate before SQL commit, rereads actual
SQL, publishes/readbacks it, and clears/verifies exact pending absence. Exported
`RETAINED_JOURNAL_SCHEMA` is setup-only source; no factory runs those statements.
The existing private v1 store, wire profiles and public input schemas are intact.
The SQL `progress_bytes` column is `BYTEA`, and Bridge supplies and compares
detached native `Buffer` bytes containing exact contracts `canonicalJson`.
Retained v3 ancestry uses D's closed `{bytes_base64,sha256}` encoding of those
same bytes. Text columns, alternate binary encodings, malformed UTF-8 and
noncanonical byte sequences refuse; no schema installation or conversion runs
inside a Bridge factory.

D source `4219694` accepts these exact nine descriptors and derives prior-row
CAS values, prior native progress bytes, and the target progress digest from
its verified actual transaction prestate. Bridge's frozen eight/nine-field
transition bodies remain unchanged. A private failure retains its original
transition ID/digest; the existing wire refusal shape remains unchanged.

Explicit owner recovery captures D's genuine participant, coordinator and
protected pending reader before narrowing the service facade. It independently
checks the current registered Task, owner/subject/epoch, configured profile,
original transition UUID/digest and prepared candidate. It permits only normal
workflow or closure journal publication cleanup, through D's existing exact
recovery methods, then obtains a new factual census. Factual reads and admission
never perform that cleanup. Another Task's pending marker, unsupported purpose,
unprepared candidate, changed identity or missing genuine source remains unknown.
This source join adds no marker fields, resolver or recovery endpoint to the wire;
it replays neither SQL nor an original effect. Genuine composed pending recovery
and PostgreSQL execution remain unperformed.

All v2 journal reads use D's authoritative owner census, including every registered
task and a verified empty history. C's authenticated proposal is confirmed before
retained registration and owner delivery. The ordinary attempted transition is
retained before D's actual reserve/dispatch/effect path. Saved/forgotten metadata
requires the exact genuine receipt and factual C settlement. Explicit recovery
retains started, then C2, then D's first published completion(A), then B, and
atomically complete plus known_unsent at C. Each boundary finishes exact pending
cleanup first. Fresh C and D factual reads revalidate every admission exemption;
no cache or metadata label proves non-execution. Recovery never promotes a live
proposed row into an attempted one or repeats an original effect.

For D's separately authorized full restore, the fixed local
`restoreRetainedJournal(tx, ancestry, closureProfile)` participant accepts only
the ordered full v3 projections authenticated by D from the actual local ancestor
to its current protected anchor. It checks each forward journal transition and
uses the same fixed CAS templates, returning `undefined`. It does not choose or
authenticate an anchor, touch other D tables, open a transaction, or publish a
checkpoint. D must validate and retain the complete restore on its owner session.
The selected C/D source at assembly `251fdb5` provides that authorized effect and
multi-step journal scope. H must inject the source-owned `restoreRetainedJournal`
as D's `journalRestore` when constructing `createPrivateV2Memory`; no caller may
supply this callback.

The retained Bridge exposes a separate local `bridge.restore` facade:

```js
const context = {request: authenticatedChannelAssociation, role: 'owner_control'}
await bridge.restore.propose({session_token}, coldBundle, context)
await bridge.restore.approvalChallenge({session_token, operation}, context)
await bridge.restore.approvalComplete({session_token, operation, proof}, context)
await bridge.restore.apply({session_token, operation, approval_proof}, coldBundle, context)
await bridge.restore.reconcile({session_token, operation}, context)
```

`request` and `role` belong to H's authenticated local channel context; they do
not come from the bundle or browser body. Every call reuses C's current durable
owner session and the existing trusted Task/context registry. D derives the full
restore proposal under its protected ancestor/anchor checks. Both approval calls
hold D's exact target-observation scope; C receives its original input shapes.
The unchanged full bundle is detached through D's historical-data helper, which
preserves donor decimal data rather than applying the strict operation codec.

Restore never enters the thirteen-column save/forget journal, ordinary admission
census, or negative retirement flow. D alone reserves, claims once, restores SQL
and journal state, retains the original pending identity, and settles its genuine
receipt. Bridge checks the unchanged C/D result and receipt bindings, and reads
C's factual completed status before reporting completed settlement. A pending
result or uncertainty permits only explicit `reconcile`, which forwards D's
original committed-receipt recovery; it never resubmits `apply`, claims again,
chooses a new request ID or labels a restore known-unsent.

H must own/drain these calls under the same lifetime as C, D and the Pool. This
facade adds no public or IPC method and supplies no runtime qualification. The
actual composed restore, PostgreSQL and cold-runtime checks remain unperformed.

The v2 adapter remains source-only and public routes report unqualified. The
legacy host acceptance record cannot qualify retained custody, PostgreSQL guards
or the new lineage path. C/D owned successor implementation and actual composed
PostgreSQL/retention/cold-runtime checks are separate evidence. The preserved
original-six result remains 55 PASS / 2 FAIL: two unchanged fixtures ask recovery
to close a merely proposed operation and provide SQLite rather than the required
native PostgreSQL/retained boundary. These fixtures and their assertions remain
unchanged; no passing source guard replaces their failures.

The isolated next-development pilot adds workflow recall, refreshable completed
save recovery and opt-in private outbox projection. Known-unsent recovery now
has a source join for permanent C closure and actual D writer fencing; its
PostgreSQL guard and separated-runtime acceptance remain unperformed. A status
read plus an absent effect still cannot close an operation. Focused inference and exact controller-
witness checks ran after owner approval on isolated source snapshots; their
commands and limits are in the handoff. Installed activation remains unperformed.
See [the diagnostic pilot interfaces
and acceptance steps](DIAGNOSTIC-PILOT.md) for B/E/H integration dependencies.

```js
const taskRegistry = createTrustedTaskRegistry(trustedRegistryEntries)
let memory
const authority = createAuthorityService({
  ...trustedAuthorityConfig,
  authorizeTask: taskRegistry.authorizeTask,
  observeTarget: operation => memory.authorityTargetObservation(operation),
})
memory = createPostgresMemory({pool: pgPool, authority, contracts})
const workflowStore = createPostgresWorkflowStore({pool: pgPool})
const bridge = createRuntimeBridge({
  authority, memory, workflowStore, taskRegistry, resolveHostContext, verifyHostQualification,
})
```

The host supplies an already configured `pgPool`. No credential discovery or
automatic migration/provisioning occurs. Every authority dependency must be the
corrected service, including `authenticateSession`, `logoutSession` and the D memory settlement
join. The approved schema initializer explicitly runs `memory.migrate()` and
`workflowStore.migrate()` on the same pool. Ordinary starts reopen those tables.
Required missing methods or an absent branded store report `unmounted`; a mounted graph without host
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
- `owner.logout`: `{session_token}`, authenticated owner-control only.
- `memory.proposeSave`: `{session_token,extraction_json,idempotency_key}`.
- `memory.save`: `{session_token,operation,approval_proof,extraction_json,idempotency_key}`.
- `memory.proposeForget`: `{session_token,record_id}`.
- `memory.forget`: `{session_token,operation,approval_proof}`, owner-control only.
- `memory.recover`: `{session_token,operation_id:null|string}`, owner-control only.
- `memory.status`: `{session_token,record_id,revision:null|string}`.
- `memory.cite`: `{session_token,record_id,revision:null|string,retained_head:null|string}`.
- `memory.recall`: `{session_token,query,limit}`.

No public reserve, claim, receipt intake, cancellation, epoch, import, purge or
administrative route exists. The proposer channel can propose and read; only the
owner-control channel can approve, save, forget, reconcile a retained receipt or log out. Channel credentials never
prove owner identity. `extraction_json` is a bounded original UTF-8 JSON string so
historical confidence decimals survive inside the frozen integer-only envelope.
D's duplicate/depth/finite-number parser reads it; the OperationProposal contains
capture/key hashes, exact live heads and literal statement/attribution. The frozen
v1 digest profile is unchanged.

New pilot capture input is statement-only. Older callers may supply category,
validFrom, observedAt, confidence and sensitivity only at the fixed values:
fact, trusted source date/time, 0.7 and none. Links and metadata overrides refuse.
The proposal retains the six fixed metadata fields inside the independently
prepared capture draft and also returns an identical `capture_metadata` sibling
for H/B display. This changes no capture hash profile or historical bytes.
The current joined source targets H `48638b9013f67d41abf5c9627f4ab89bb0c5893e`,
D `6326a4c928a7d14ab7e9ef7a7da626a6a6322d22`, and B
`a20812e72eed05b2981c8a799d4c7d6155f0de49`; the handoff records exact patch
and assembled file hashes.

`memory.proposeSave` obtains D's exact capture binding and builds the operation
from C's verified owner plus host-owned task/route/policy. C proposal admission
receives the closed authenticated `{session_token,operation}` envelope. A transport
role alone cannot admit a proposal or consume owner pending capacity. Approval methods scope
C's target checks through D's current locked observation. `memory.save` delegates
to `captureAuthorizedRemembered`; it never claims dispatch itself. D reserves,
commits an intent, rechecks live state under the owner lock, claims once, saves
record/events/chain/outbox/effect ledger, commits, then settles C using the genuine
memory receipt. Save parameters contain exactly `capture_sha256`,
`idempotency_key_sha256`, `heads`, `statement`, `attributed_to`,
`capture_metadata` and `evidence_quote`. The independent `memory_capture` draft
contains the last four fields. Statement and attribution come from the captured
extraction and trusted host; metadata comes from the fixed pilot profile and
trusted source timestamp. The quote is the full parsed text of the trusted
event whose original bytes match the selected source digest. Expected review
content is never reconstructed from operation parameters or their hash. D verifies
all parameters again under its database lock before reserve and dispatch. A save
can be `saved/pending` or `saved/failed` before indexing.
Only D's later ACK makes the record searchable. Citation verifies original bytes,
source evidence, chain/member and retained head and grants no authority.

Unknown outcomes remain consumed. D's host-only `reconcileEffect` resends only a
committed local receipt; an unresolved intent forbids automatic retry. The bridge
has no public reconciliation receipt intake. Neither transport reconnect nor
client timeout resubmits a mutation.

## Durable recovery and logout

`createPostgresWorkflowStore({pool})` is a small reference journal in the host's
configured PostgreSQL schema. It stores owner/task/operation IDs, existing
digests, phase and receipt/request references; it stores no statement, capture,
source events, operation payload, proof, grant or receipt bytes. The bridge writes
a proposal reference before C admission and atomically marks an attempt before
calling D. Owner-scoped attempt admission refuses another unresolved attempt.
The table grants no authority and never performs a memory effect. C and D remain
the owners of consumption, durable intent, effect and settlement evidence.

`memory.recover` discovers unresolved references and reads actual C status and D
`reconcileEffect`. D may resend only its retained committed receipt. An unresolved
intent, uncertain attempted call, unavailable binding or missing effect stays
unknown; fresh proposal/dispatch remains blocked until permanent closure facts
or a genuine completed effect are established. Ordinary admission preserves
delivered live proposals, including their review and decline path.

Explicit recovery may initiate closure only for an already durable interrupted
`attempted` reference. A requested `proposed` reference remains unchanged and
returns unknown; recovery does not manufacture an effect attempt or close a
delivered live proposal. C then authenticates the existing session and
resolves the complete original operation through the private six-field reference
contract. Its permanent never-consumed closure precedes D's owner-locked writer
closure. D must establish absent intent/effect/replay evidence, actual storage
guards and any configured retained-control completion. The bridge checks both
closed results, their distinct epoch meanings, exact operation correlation and
NUL-delimited digests before atomically marking that journal attempt
`known_unsent`. It never retries the original operation. An uncertain C or D
response leaves the attempt blocking.

Legacy `mark()` and `list()` remain reference-metadata methods. A legacy
`known_unsent` label supplies no C/D proof: Bridge admission includes it in a
separate candidate query. Cold labels require explicit recovery through both
original services. This Bridge instance keeps only the validated immutable proof
pair from its successful recovery, bound to the authenticated host epoch, and
reads C's permanent proof before later admission. It never invokes D closure from
ordinary proposal admission. Uncertain closure replies remain blocked for an
explicit recovery call. Under the owner lock, strict proposal/effect admission
rechecks attempted and legacy rows against the exact validated closure set.
Newly concurrent unresolved rows are not exempt. Bounded candidate overflow
refuses without dropping history.

`knownUnsentProfile:{version:1,environment:'source-only',retention:'non-retained'}`
is an explicit host-constructor option for the existing non-retained source
profile. It permits D's null retention result only; it does not substitute for
PostgreSQL guards and always prevents production-route qualification. Without
that option, a retained-control result is required. The frozen SQLite fixtures
do not supply the source profile or real PostgreSQL catalog/trigger enforcement;
they cannot establish this closure path. No fixture bypass or guard simulation
is provided.

This private-v1 join is a partial source checkpoint. The journal does not yet
persist a separate `CLOSING` protocol or the C/D closure digests, and the frozen
proofs do not bind independently expected C/D store identities. Those need an
explicit private-contract and journal-schema decision before implementation.
Warm admission relies on D's permanent writer-fence/restore guarantee; a cold
Bridge must explicitly recover its closed references again. More than 256
retained closed candidates in one Task conservatively refuses admission.
Actual PostgreSQL second-writer enforcement, crash/restore acceptance and
separated-role custody remain unperformed. This checkpoint does not establish
the full source or publication gate.

The closed response is `{ok,owner_id,owner_subject,task_id,operation_id,
operation_digest,action_type,state,reconciliation_required,result,receipt,
receipt_digest,authority_settlement,citation,index}`. `state` is `idle`,
`known_unsent`, `saved`, `forgotten` or `unknown`; null operation ID selects
interrupted blockers first, then the most recent reference, and does not close
ordinary delivered drafts. C/D completed receipt facts bind
the result. Citation/index reads may be unavailable without undoing a confirmed
save. Recovery never reconstructs an operation/proof from that result, retries an
effect, unconsumes an approval or accepts a browser receipt. Keep references
through worker restarts; a record snapshot alone cannot replace this journal.

After ordinary owner login on remount, H calls `workflow.recover()` on its fresh
controller/workflow binding. The helper validates owner/reference/digest and
receipt bindings, exposes recovered saved facts, and retains unknown fences.
The helper accepts a no-effect closure only from the same authenticated Bridge
recovery path; legacy journal labels remain insufficient. `refresh()` remains
read-only, including after validated completed-save recovery; `recover()` can
resend a factual settlement receipt through D. Recall is exposed separately by
`getRecallSnapshot()` so B's closed approval/save result remains unchanged.

`workflow.logout()` removes local controller access immediately, then calls the
same adapter's authenticated `owner.logout` route, forwarding exactly to C's
durable `logoutSession({session_token})`. Only `{ok:true,status:'LOGGED_OUT'}`
confirms revocation. Lost replies stay unknown and local generations remain
invalidated. One pending logout is coalesced; a new login waits for its outcome.
This join does not change epochs, revoke unrelated credentials or cancel an
already dispatched effect. B's local controller logout alone is insufficient;
H must invoke this joined method for its logout action.

## Approved logical forget

`createOwnerForgetWorkflow({controller,memory,contracts})` is a separate
browser-safe export. `proposeForget({record_id})` retains D's independent record
summary and exact operation. H/B obtain and render the existing fresh review,
including escaped literal statement/attribution, record/revision, canonical SHA,
time and heads. `approveAndForget()` obtains the exact owner proof and calls D's
approved forget once; concurrent calls coalesce. It receives the genuine
`forgetRecord(...,{include_receipt:true})` result/receipt, and `recover()` reads
that retained receipt without repeating the effect.

Logical forget hides the record and removes its search projection. Its result
truthfully preserves canonical payloads and reports physical erasure, authority
history erasure, backup erasure and WAL erasure as false. There is no raw delete
or purge route. This is a separate forget result, never a fake saved MemoryRecord.
H/B must explicitly mount the forget action; B's save-shaped approval hook alone
does not invoke it. No face source or host composition is edited in this lane.

The reproducible scoped runner is
`test/verify-owner-recovery-source-join.mjs --authority-repository ABS
--memory-repository ABS --ui-repository ABS --output ABSfresh`. It archives exact
committed source pins in an isolated own-root snapshot, runs only ordinary new
recovery/logout/forget/journal/pilot checks, and freezes hashes and logs. Tests
use actual C P-256 proof verification, C durable files and D effect code, with a
clearly synthetic SQLite SQL fixture. Cold service objects reopen existing
state without provisioning/migration. They establish neither PostgreSQL nor
deployed process/UID acceptance. The stopped adversarial review is not resumed.

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
controller.setApprovalAction((_view, options) => workflow.approveAndSave(options))
// B's button calls submitApproval(); the helper uses this invocation's approve().
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

The worker uses the fixed `prime-authority-unconsumed-closure/v1` private profile
for C's `closeUnconsumedOperation` and `readUnconsumedClosure`. Only the existing
`memory_effect` role accepts their MAC-covered versioned six-field wrappers.
They carry `{session_token,reference}` with no caller operation or target
observation. C resolves the original operation; the worker checks the exact
proof and independently configured owner/Task before returning it. Legacy
private, public and inference constructors keep their original allowlists.
This source change provisions no transport, credential, schema, process or host
qualification. The worker's current closed config does not select the optional
non-retained constructor profile; its closure path therefore requires retained
control evidence by default.

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
## Source-only inference connection

The separate private `inference_effect` transport, trusted observer and C/E
connection are documented in [docs/inference-join.md](docs/inference-join.md).
The earlier E intent/outbox and C profile dependencies are now imported source; E’s shared continuation joins them in the [recorded connected mock pilot](../../docs/evidence/next-dsh-pilot-e994789.json). See the [current join decision](../../docs/development/INFERENCE-JOIN-DECISION.md) and [shared continuation](../inference/private-continuation.md). Focused keyless source checks retain their own scope. A qualified protected host connection, native interactive producer, installed activation and real provider requests remain UNPERFORMED. The source adds no public route.

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

Hook tests run against the assembled local B controller by default and require
its real hook; `PRIME_OWNER_HOOK_CONTROLLER` may select an exact copied controller
from a pinned source snapshot. No required hook test skips. Host tests require the exact
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
flight. A confirmed approval followed by cancellation before the memory method
is invoked sends no effect and permits a fresh proposal. An unresolved approval
or attempted effect retains an unknown outcome, while a
confirmed save remains a saved fact when only citation/index reads are pending.
These states are checked through the real hook, in addition to the direct
workflow lifecycle checks.

Owned hooks forward B's per-invocation options:
`controller.setApprovalAction((_view,options)=>workflow.approveAndSave(options))`
and `controller.setForgetAction((_view,options)=>forgetWorkflow.approveAndForget(options))`.
The exact `{signal,approve}` callback belongs only to that live flight and is
released at cancellation and lifecycle boundaries; an owned hook never falls
back to raw approval. Explicit direct workflow calls may omit these options.
After factual recovery H must await `controller.reconcileApprovalAction(snapshot)`
before returning the unchanged workflow snapshot.

New capture review retains D's full independent draft: exact statement,
attribution, six fixed metadata fields, and the full selected source-event quote.
The bridge derives it from trusted original event bytes before waiting on D,
then compares D's returned draft and seven operation parameters. It never
normalizes new text or rewrites historical bytes. D's new helper and B's matching
committed helper/types/rendering must be composed together. B's cumulative
`a20812e7` patch includes the invocation change and the expanded helper; it
supersedes the earlier invocation-only patch. H must forward the exact invocation
options and rebuild its genuine owner assets before its full release gate.

An exact completed-save retry checks its durable owner/task/operation reference,
immutable capture and key, genuine D receipt, and C completed settlement before
returning the original saved result. It does not compare the already advanced
heads to the old approval or call reserve/dispatch again. The adapter releases
verified completed captures from its 16 pending slots and retains at most 16
completed review contexts for factual retries; C/D and the workflow journal
keep their durable replay evidence. Unknown attempts retain their pending context.

An attempted save that D refuses before reservation still requires reconciliation.
The current C status and D missing-effect exception do not prove durable kernel
non-consumption, absence of every D intent/effect/replay fence, or that an old
writer cannot later proceed. W1 remains unresolved until private C/D evidence
and cross-process closure guarantees are provided. Exception flags cannot turn
an attempted operation into `known_unsent`. The focused
`pre-reservation-unknown.test.mjs` shows this limitation with a genuine approved
proof whose changed expiry C refuses before consumption, leaving the attempted
journal blocked through cold service reopen. The adapter's existing 16 retained
forget contexts also remain a separate session-capacity limitation; this save
quota repair does not remove them.
