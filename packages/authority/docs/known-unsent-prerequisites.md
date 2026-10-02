The exact Desktop `AUKORA_Sovereign_Composable_Runtime_Technical_Spec_v0.3.md`
was read with SHA-256
`0b1a334ff4854553c7bec4eab3b499dd556ef144f619273c5e931b70bd323d31`.
It is a design specification. Its demo evidence does not qualify Prime.

The current C successor implements only the C assignment in A's frozen
`closure-interface-decision-v004-private-v2.json`, SHA256
`95fcc9d4fb4420e2dbc13ba28b8332968b4b36e71f069a233847c23932a1c3b9`.
The historical v1 checkpoints below retain their original provenance. Current
private closure methods keep request2/reference6/reply6/C13 marker bytes. The
adopted v1 worker behavior remains selected when closureProfile is absent. This
trusted immutable profile explicitly selects the v2 successor:

```text
{version:2,kind:'prime-authority-closure-retention/v2',expected_store_id:<lowercase64hex>}
```

Supplied malformed v2 configuration, including a missing expected ID, refuses
before opening state. Selected v2 calls never fall back to the legacy
opener/loader after any failure; the existing v1 path uses its original txAsync
behavior, including adopted v1 housekeeping. Unconfigured ordinary core
methods retain their existing source behavior. A configured v2 store binds the
expected public history ID before reading or promoting any witness, uses a
dedicated single-history witness namespace outside the selected restore root,
and requires original kernel/broker keys even at count zero. Normal v2 open pins
both existing owner-only directories before the unchanged donor lock algorithm;
it cannot mkdir/chmod. Raw legacy records, missing state, altered IDs and unknown,
extra or missing witness keys refuse rather than migrate or rebaseline.

The profile key is unprefixed SHA256 of UTF8
`'aukora-prime.authority-closure-profile.v2\0'+canonicalJson(profile)`, retained
as count1. Each exact full closed row has `sha256:` row digest under
`aukora-prime.authority-closure-row.v2\0`; its inclusion key is unprefixed SHA256
under `aukora-prime.authority-closure-inclusion.v2\0` over
`{store_id:expected_store_id,row_digest}`, also count1. The exact sorted
`{store_id,entries:[{operation_key,row_digest,inclusion_key}]}` projection uses
`aukora-prime.authority-closure-set.v2\0`. Every domain contains one actual NUL.
The original witness remains `{schema:1,heads:{...}}` with unchanged kernel and
broker count meanings; cold load requires exactly those two history keys,
profile key and one inclusion key per validated closed row.

Explicit close freezes the complete prospective row and writes protected
`prime-authority-closure-retirement-pending-v2.json` in existing witness custody.
Its exact eight fields are version2, kind
`prime-authority-closure-retirement-pending/v2`, store_id,
previous_inclusion_digest, operation_key, closure_row, row_digest and
pending_digest. The last digest binds all other fields under
`aukora-prime.authority-closure-retirement-pending.v2\0`. Pending is atomically
written and fsynced before the original broker journal commit. The command then
retains the exact inclusion key through the original donor witness writer and
removes pending with directory fsync and readback before success. All ordinary
load/admission/preparation paths refuse pending. Resume authenticates a current
owner/session/Task and accepts only the identical frozen candidate, unchanged
kernel history and exact prior inclusion at the prescribed previous-revision or
already-committed boundary. It never refreshes a timestamp, creates another
revision for an already committed candidate, reconstructs an operation, grants
authority, consumes an approval or retries an effect.

An explicit close retry may find the exact committed/included row and no pending
file after a previous unlink whose following directory fsync failed. That branch
still validates the row, exact witness set and absence, fsyncs the held witness
parent directory and revalidates absence/inclusion before success. It fabricates
no pending candidate and changes no row/revision/timestamp. Factual read never
invokes this mutating durability-completion boundary.

Factual read uses original `TrustedStateStore.load` validation without the donor
approval-store witness promotion or Prime broker housekeeping. It validates
exact converged counts and inclusion, refuses any pending/partial evidence and
only acquires/releases ephemeral original locks. It never initializes, repairs,
promotes, completes or removes metadata. A lost reply with pending requires the
explicit negative command; the query cannot finish it. Corrupt protected history
returns reconciliation-required, while malformed caller references retain the
existing input refusal shape. The v1 marker and operation are returned only from
fully committed, fully included original state.

Setup remains the existing local `provisionNewAuthorityStore` export, not a
route: protected setup preselects the expected public ID for a genuinely empty
v2 history/witness. No setup is performed by this source change. The same UID
can replace state and witness together; this local continuity does not supply
independent custody. Complete unqualified restore remains unavailable. Actual
service/interruption/lifecycle/custody checks remain unperformed for this
increment, and the previously blocked checks remain stopped.

The initial increment `5081cf1` implements a C prerequisite, not known-unsent closure.
`preparation-history.mjs` validates the retained original kernel PREPARED history
before a load can advance its local witness and before a new journal commit.
Explicit Prime provisioning starts with an empty history; the unchanged adapters
append exactly one consumption and PREPARED entry per durably allowed transition.
The validator requires complete cardinality, contiguous receipt counts, unique
effect/approval IDs, closed entry fields and consumed-ID membership. Unknown or
incomplete histories refuse without reconstruction, migration or reset. The
original donor kernel, adapters and journal implementation are unchanged.

`assertOperationUnconsumed` is an internal refusal-only predicate. It compares the
full frozen operation and digest against validated original history and broker
bindings. It returns no evidence or permission. It is not exported by the package
entry point or called by any public or private worker route.

The subsequent source checkpoint follows A's frozen private contract v1,
snapshot revision 2, `closure-interface-decision-v002.json`, SHA-256
`95d7cd95e1e88b97f9ab937653e183e23278ec41724e87b8f9c5c2f2d5fa1faa`.
These methods are not mounted on any worker or HTTP route, and no
caller automatically invokes them during ordinary proposal admission:

```text
reference = {owner_id, owner_subject, task_id, operation_id, operation_digest, action_type}

closeUnconsumedOperation({session_token, reference})
readUnconsumedClosure({session_token, reference})
  -> {ok:true, status:'CLOSED_UNCONSUMED', operation:<stored original OperationProposal>,
      closure:<below>, closure_digest, idempotent}
```

All authenticate the existing C owner session and independently trusted Task
registry; the operation owner, Task and agent must match. This narrow source
supports only `memory.save`/`memory.forget`, audience `aukora-prime.memory`, and
exact target `{kind:'prime-memory',owner_subject:<authenticated owner subject>}`.
Close/read resolve original stored bytes and authenticate all six reference fields against those bytes;
neither accepts a caller's reconstructed operation. Missing, pruned or compact-only
records refuse; no cold metadata reference invents a replacement operation. The
reference-based frozen decision supersedes the earlier uncommitted full-operation
draft at the parent's explicit relay. C returns the original full operation;
its `action_type` must correlate with the six-field reference and D's marker.

`closeUnconsumedOperation` holds both original state/witness locks, validates the
complete original history and exact broker bindings, then commits a permanent
full-operation `CLOSED_UNCONSUMED` row before returning evidence. Its exact C-only
marker is:

```text
{version:1, kind:'prime-authority-never-consumed/v1', store_id:<64hex>,
 owner_id, owner_subject, task_id, operation_id, operation_digest:<sha256:64hex>,
 authorization_epoch:<original operation epoch>, closed_at:<ISO UTC millis>,
 broker_revision:<positive committed revision>, kernel_receipt_count:<uint>,
 kernel_receipt_head:<64hex|null at zero>}
```

`closure_digest` is SHA-256 of UTF8
`'aukora-prime.authority-never-consumed.v1\0' + canonicalJson(closure)`, prefixed
`sha256:`. The trusted private caller must obtain it from C or re-read C's durable
marker; a caller-supplied digest or unsigned JSON object is not independent proof.
Old operation expiry, target state or Task status cannot authorize an effect or
invalidate this factual denial. A fresh current owner session remains required.

The marker preserves the exact operation, never deletes original kernel history,
and survives pruning, terminal compaction and reopen. Store commits refuse removal
or changes to retained closure rows, and refuse any kernel PREPARED entry for the
closed digest. Every later proposal/review/reservation/dispatch rejects the row;
the unchanged before-kernel recheck also fences a previously copied approval.
Lost commit replies require re-reading the identical marker, not fresh reserve or
effect retry. A quota or persistence failure returns no successful closure proof.
The C marker establishes neither D absence nor actual D old-writer inability.
General C `status` therefore retains `reconciliation_required:true` for this
C-only closure. Only A's joint private evidence validation can conclude otherwise.

Known-unsent closure still requires one coordinated C/D/Bridge protocol:

1. D holds its actual owner writer lock and establishes exact operation-bound
   absence of durable intent, request, effect and replay/retained preparation.
2. C holds both original writer locks, verifies complete retained history and the
   exact unconsumed operation, then durably records a permanent operation closure
   fence. Every delayed reservation must recheck that fence in its before-kernel
   path, including a retained asynchronous reload.
3. D durably records matching closure and makes every old writer unable to commit
   that operation, including delayed/resumed workers. A local absence query,
   workflow phase or in-memory flag is insufficient.
4. Recovery verifies both retained markers and actual writer closure against the
   same owner, Task, operation ID and full digest. Partial commit, lost reply or
   crash stays unresolved until those facts agree. Only then may a distinct fresh
   proposal proceed; the original attempt is never retried.

Only the C side of the frozen joint private grammar is implemented here. No
worker/public route is adopted by C. The current Bridge
keeps legacy `known_unsent` rows unknown. `declineApproval` is temporary denial and
can be pruned; it is not durable closure. PREPARED, consumed, DISPATCHED and unknown
duties remain retained. No clear, unconsume, replay, abandonment or compensation
endpoint is added.

Delivered live proposals are a separate case. Ordinary admission must retain all
16 concurrent live C PROPOSED operations as reviewable, with no memory effects;
their actual later decline releases capacity for the seventeenth. Later admission
cannot automatically close an earlier live proposal. Interrupted unresolved
attempts require actual old-writer termination before any joint closure. The
internal predicate establishes neither interruption nor writer termination.

The custodians are concrete. C's `prime-broker-state-v1` metadata and original
kernel `consumedIds`, `prepared` and `receiptHead` are journaled through the
unchanged donor store. Its local `kernel-high-water.json` witness retains history
counts keyed by `store_id`. The same UID can rewrite both; these are not an
independent cosigner or off-box anchor. D owns SQL intents/effects/replay fences
and retained pending/generation records. Bridge's workflow journal is reference
metadata, not authority evidence. D source mapping was read at
`8f71be8c01e873cff1c761fe72b2e71f9de3d419`; this is not deployment evidence.

| v0.3 requirement | Required record and boundary | Current posture |
| --- | --- | --- |
| CP-4 intent → cosign → anchor before effect | Durable exact intent; separate witness's signed sequence/previous hash/entry hash/time; matching full-entry anchor on pinned different host/account, including owner-approved genesis | Design; independent witness, keys, time roots and anchor deployment unavailable |
| CP-6 receipt and CP-7 recovery | Genuine effect-specific outcome and cosigned receipt under insert-only custody; matching cosign and anchor evidence without replaying uncertain effects | Existing factual C receipt retention only; no anchored-recovery permission |
| TR-2 revoke before drain | Durable bridge activation/admission generation revoked before awaited cleanup, rechecked at dispatch and effect iterations | Owner authorization epoch is distinct; mutation API remains unavailable |
| One serialization point | Independent witness chain assigns one cosign per strictly increasing sequence | Original writer locks serialize local state only |
| TR-5 withdraw/install | Old Cordis bridge fiber/service withdraws; fresh fiber UID/generation installs; no in-place provider overwrite | Coordinated Bridge/Cordis source still required; registration order does not prove revoke-before-drain |
| CP-2/CP-5 final definition | Activated immutable effect definition, policy fingerprint, protected target and current preimage revalidated at actual D/F/E effect boundary | C checks policy, Task and target at reserve/dispatch; final adapter schema requires coordination |

PREPARED alone does not qualify for revocation inertia: C rechecks owner policy,
epoch, Task, approval session and target at DISPATCHED. The supplied Cordis paper's
`execute(callback, guard)` must not be attributed to the pinned implementation's
`effect(execute, label)` without an actual adapter enforcing those predicates.
No local counter, same-process participant or lifecycle cleanup is labelled
independent, revocation or proof of no effect.

Operator prerequisites remain separately approved and unavailable here: protected
separate witness process/UID/key; authenticated peers; independent second-language
validator; two independently signed time sources with retained HWM/drift policy;
pinned second host/account with enforced insert-only anchor and receipt roles;
owner-approved genesis/key-era ceremony; protected target and bridge/workload
lifecycle; independent verifier and alert channel. Code cannot create those trust
boundaries or qualify an installed path.

No test or fixture files change. The six LANE-0 test files must remain byte-identical
to `89d0cf5626045f1d9d38d78f873c92d2d5115d32`; their required 65-pass gate and
exact-head CI are not claimed by this isolated C source handoff. Both blocked
service verification actions stay stopped. No push, deployment, security
configuration, credential/enrollment, real effect or spending occurs. Publication
remains blocked pending the parent-relayed verdict, required evidence and explicit
sequencing approval.

Parent explicitly resolved the mutable-manifest mismatch with immutable
`manifest-v001-89d0cf5.json`, expected SHA-256
`6f43d5eda60baa58c80bbbaaea7d835eadeeeb0ed7042ffc4881ca7f686bf66d`.
The original mismatch evidence remains retained. Its historical `db09d17` snapshot
and this new explicit pin must be verified separately; the mutable latest file is
not silently accepted.
