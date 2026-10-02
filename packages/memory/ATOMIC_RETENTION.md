# Atomic control retention source join

D owns this source join, based on preserved `10fcd1b6b3d4ae7a66f0a4890591d5341bf74c87`. It supplies the executable participant, owner serialization and ordered retention path. It preserves original canonical bytes, IDs, capture-review fields and digest domains. Prime now also carries C’s asynchronous retained methods in source. The authenticated separated-worker phase adapter, actual PostgreSQL retention, distinct-UID storage and private-worker transport acceptance remain unperformed.

## Required C methods

The configured retained profile requires these new asynchronous C entry points:

```js
reserveRetained({operation, approval_proof})
claimDispatchRetained({operation, consumed_grant, request_id, request_digest})
settleMemoryRetained({operation, consumed_grant, request_id, request_digest, receipt})
```

D refuses `memory:retained-authority-unavailable` when they are absent. It never falls back to ordinary `reserve`, `claimDispatch` or `settleMemory` in this profile. `markOutcomeUnknown` remains factual uncertainty reporting for an actual bound dispatch; it cannot unconsume or retry authority.

The earlier read-only C checkpoint `80f3e92ab7fe4d282b4a906b487d5d5022647631`, based on `eb90fc7e890ba950917bceeff009f55179e7769c`, was a documentation-only proposal. It is superseded by the retained methods now present in [Prime authority source](../authority/README.md). The C handoff reported 19 joined source cases and 650 assertions using genuine P-256 verification and disposable SQLite/file artifacts, with PostgreSQL session and UID metadata modeled. Those results do not establish an actual separated C/D/PostgreSQL retention path.

The current C source implements the asynchronous extension under its original state and witness writer locks: it validates approval/session/epoch/policy/target without grant mutation, awaits D’s private `prepare`, validates its permit and reasserts held locks, then rechecks with a fresh clock before the unchanged kernel PREPARED commit. It gates legacy memory methods in the retained profile and defers terminal memory compaction across broker writes until the exact retained effect has been verified, while retaining functional logout. H’s worker observation scope must span the awaited call; the authenticated phase adapter still needs implementation and actual acceptance. A Promise or a settlement-only guard cannot supply that transport and storage boundary.

## Durable order and owner serialization

One dedicated Prime-owned `pg` PoolClient holds a session-level owner advisory lock across all transactions, file retention calls, C calls and final settlement. `owner-serialization.mjs` acquires `pg_advisory_lock(hashtextextended(owner_subject,0))`; every participant phase inspects that same backend PID and its actual granted ExclusiveLock in `pg_locks`. A closed or uncertain scope refuses. Unlock uncertainty destroys only this owned client. These SQL observations do not attest an OS identity.

The retained path has this order:

1. D validates exact operation/proof structure, trusted owner/task/action/parameters, live control state and data preflight while its owner session is held.
2. C performs its pure approval checks under its original locks, then calls D `prepare({operation})`. D fsyncs and reads back the exact v2 pending marker before C creates its kernel PREPARED grant.
3. C rechecks and commits PREPARED. D commits the exact operation/grant/request intent.
4. D writes and reads back an immutable complete PREPARED generation. It then fsyncs the updated marker referencing that generation. The current pointer remains at the predecessor and the marker remains held.
5. C calls D `dispatch` to verify the updated marker, retained intent, exact grant/request and still-held owner SQL session, then commits its single DISPATCHED transition. D commits the actual record/control effect and its original receipt.
6. D publishes the complete final control checkpoint, checked against both predecessor and PREPARED generation. The current pointer is fsynced before the marker is removed and its directory fsynced.
7. C calls D `settle` to verify the actual retained effect/receipt/result and owner SQL session, then durably settles and may compact that exact terminal row. Only then is the owner session released.

The staged PREPARED generation and final generation share predecessor and sequence predecessor+1; the prepared generation is immutable evidence, not a current-pointer advance. The updated marker is the durable dispatch fence. C’s current retained source uses this staged-generation interface. The earlier two-cycle documentation proposal does not define the current protocol. Actual private-worker/PostgreSQL acceptance remains required.

The database and retained files are separate durable stores. This is an ordered fail-closed protocol, not a cross-store ACID commit or physical power-loss proof.

## Private participant interface

`createPostgresMemory({pool,authority,contracts,controlRetentionCoordinator})` constructs its owner serializer and process-local branded participant. In a direct trusted source join, C accepts that exact owned participant. Its brand cannot be serialized as authority over IPC. A separated deployment requires the source-owned authenticated phase adapter; that adapter remains unfinished. The participant’s only methods are:

```js
prepare({operation})
dispatch({operation, consumed_grant, request_id, request_digest})
settle({operation, consumed_grant, request_id, request_digest, receipt})
```

They operate only on a registered exact immutable D effect request under a live D-owned owner session. Guest requests cannot create that registration. The participant is privately branded. The controller's `runOperation`, `context` and `bindRecovered` remain D-owned and must not become public or wire routes. H must keep the participant out of its guest/public memory allowlist; a generic callback, Boolean or self-reported trace cannot substitute for this source.

Every phase returns exactly this detached frozen permit:

```js
{
  version: 1, kind: 'prime-retained-memory-permit/v1',
  phase: 'prepare' | 'dispatch' | 'settle',
  owner_id, owner_subject, authorization_epoch,
  operation_id, operation_digest, request_id, request_digest,
  owner_session: {
    kind: 'postgres-owner-session/v1',
    owner_id, owner_subject, authorization_epoch,
    session_id, backend_pid, lock_key_sha256
  },
  predecessor_checkpoint_sha256, checkpoint_sha256, control_sha256,
  marker_sha256, grant_digest, receipt_digest, result_digest
}
```

`prepare` binds the current predecessor and marker; grant/receipt/result digests are null. `dispatch` binds the exact PREPARED generation and updated marker, with a nonnull grant digest and null receipt/result digests. `settle` binds the final current generation and actual receipt/result, with a null marker digest. Checkpoint/control/marker/lock hashes are bare hex; operation/request/grant/receipt/result digests use their declared `sha256:` profile. The session ID is a UUID and backend PID a positive safe integer.

The marker digest covers UTF-8 `aukora-prime.memory-retention-marker.v2` + NUL + donor canonical marker JSON. The grant digest uses `aukora-prime.consumed-grant.v1` + NUL + frozen canonical grant JSON. Existing result/receipt domains stay `aukora-prime.memory-result.v1` and `aukora-prime.memory-receipt.v1`. No digest migration is introduced.

## Protected publisher interface

The constructors and protected storage requirements remain in [CONTROL_RETENTION.md](CONTROL_RETENTION.md). D selects no path, identities or permissions. H supplies the existing protected root and an authenticated private publisher transport:

```js
const coordinator = createControlRetentionCoordinator({reader, publisher: privatePublisher, contracts})
const memory = createPostgresMemory({pool, authority, contracts, controlRetentionCoordinator: coordinator})
```

`reader` must be the branded file reader; any additional `controlRetention` option must be that exact object. The publisher has own function properties `beginMutation`, `retainPrepared`, `publishMutation`. Publisher replies are not retention evidence: D independently validates protected files after every call.

The closed shared tuple is `{host:{owner_id,owner_subject,authorization_epoch},expected_checkpoint_sha256,operation_id,operation_digest,request_id,request_digest}`. `beginMutation(tuple)` creates the marker; `retainPrepared({...tuple,control_state})` writes the prepared generation and updates its marker; `publishMutation({...tuple,control_state})` publishes final current and clears the marker last. The exact immutable D request UUID/digest are reused throughout. Requests contain no proof or secret.

The v2 marker adds `prepared_checkpoint_sha256` and `prepared_generation_file`, initially null and later exact prepared references, to the shared identity/operation/request tuple; its schema is `aukora-prime-memory-retention-pending/v2`. Reader methods `inspectPending(host)`, `readPending(tuple)` and `observePredecessor(tuple)` validate exact scope and lineage. Normal `readCurrent` refuses any pending marker. Old v1 marker APIs cannot satisfy this profile.

Coordinator recovery derives an owned context from the actual persistent marker. It does not reserve, dispatch, recover a grant, publish or retry an effect. A file reader without the owned coordinator refuses mutations and reconciliation with `memory:control-retention-coordinator-required`. Default/unavailable and explicit legacy fixture paths retain their compatibility behavior without atomic-retention qualification.

## Restore and uncertain outcomes

Configured retained-profile restore is disabled: `prepareRestoreBinding`, `restoreSnapshot`, and `prime-restore` import refuse `memory:retained-restore-lineage-unqualified`. The missing C/D restore self-lineage is not replaced by a stale checkpoint, guest scope or synthetic successful trace. Ordinary approved save can proceed through the required retained methods independently. Legacy restore source behavior and its old fixtures do not qualify this profile.

Lost reserve reply, missing intent, failed PREPARED commit/publication and dispatch uncertainty retain the pending obligation. There is no automatic reserve, unconsume, grant recovery, cancellation or no-effect marker clearing. An intent without an applied receipt remains unresolved and is never dispatched by reconciliation.

After an actual effect commit, cold `reconcileEffect` uses only the existing operation/grant/request/effect. Under a fresh held owner session it completes the identical checkpoint, then sends the identical receipt for factual settlement, with no save/reserve/dispatch. A fresh publisher can finish marker removal after a genuinely committed pointer only when final candidate bytes, predecessor, prepared continuity and tuple match. If pointer/marker completion already succeeded but its reply or C settlement reply was lost, D verifies the exact current live control state and retained effect before resending that receipt. Unknown effect errors carry `reconciliation_required:true` and `automatic_retry:false`. Epoch mismatches refuse; no epoch-migration authority is added.

## Evidence and limits

The complete source suite has **112 nodes: 111 passed, 0 failed, 1 explicit PostgreSQL skip**, including six participant, seven owner-serializer and twelve atomic-path nodes. All 32 owned `.mjs` modules pass syntax checks and all 36 copied donor hashes remain unchanged; the exact capture-review helper stays `89cf53048efa6d12baff858f388b078ea64917ffb874d62d75f26d64648a96c0`. The final handoff receipt records the checks. Tests use durable SQLite fixtures, a private exact toy authority, protected-file readback and injected ordinary phase failures; they exercise exact participant registration, SQL-session observations, marker/intent/effect ordering and receipt-only recovery. Filesystem identities/groups and the Mac-stripped setgid bit are explicitly modeled under one actual UID. These results do not prove production C verification, real PostgreSQL, Unix separation, protected worker IPC, physical crashes or runtime activation. H/C own combined acceptance and existing protected-root/transport assignment. The stopped adversarial review was not resumed. Retained generations remain sensitive control backups and are not erased by local purge.
