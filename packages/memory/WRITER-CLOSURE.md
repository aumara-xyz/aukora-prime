# Exact memory writer closure — frozen private v1 source candidate

This is a D-owned candidate based on the memory bytes also present in integration
`89d0cf5626045f1d9d38d78f873c92d2d5115d32`. It changes no shared contracts or
Bridge/C routes. It implements D's part of A's frozen private contract v1,
decision snapshot v002 SHA-256
`95d7cd95e1e88b97f9ab937653e183e23278ec41724e87b8f9c5c2f2d5fa1faa`.
Owner implementation handoffs and integration remain separate. This is source
implementation, not a known-unsent runtime acceptance result.

## Frozen D interface

`memory.migrateWriterClosureGuards()` explicitly installs the memory-schema
PostgreSQL guards on the already supplied pool. It discovers no server, schema,
credentials, role or path. Installation requires the existing exact-schema DDL
authority; it grants nothing and cannot change PostgreSQL/process lifecycle.

`memory.closeUnsentOperation(trustedHost, reference)` requires the trusted
`owner_id`, `owner_subject`, `task_id` and current closing `authorization_epoch`.
`reference` is exactly the six scalar fields `{owner_id, owner_subject, task_id,
operation_id, operation_digest, action_type}` from the original operation. The
identity fields must match the trusted host and the original digest stays opaque;
D neither reconstructs missing proposal bytes nor substitutes a new digest. The
private closure scope is `memory.save` and `memory.forget`; other actions refuse.
The original operation's epoch is not inferred from its digest. The retained closure
records the current closing host epoch. It is a private worker recovery call, never
a guest receipt route. It must be used only for an interrupted unresolved attempt;
ordinary proposal admission must preserve delivered live reviewable proposals,
including all sixteen capacity slots and a genuine later decline.

The result is exactly:

```text
{
  status: 'closed-unsent',
  closure: {
    version: 1, kind: 'prime-memory-writer-closure/v1',
    owner_id, owner_subject, task_id, operation_id, operation_digest,
    action_type, authorization_epoch, closure_id,
    writer_closed: true, intent_absent: true, effect_absent: true,
    grants_authority: false
  },
  closure_digest,
  retention: null | { checkpoint_sha256, control_sha256, authorization_epoch },
  idempotent,
  grants_authority: false
}
```

`closure_digest` is `sha256:` plus SHA-256 of the UTF-8 bytes of
`aukora-prime.memory-writer-closure.v1\0` followed by donor canonical JSON of
the exact closure body. `closure_id` is a fresh UUID identifying closure, not an
effect dispatch/request, grant or fabricated result. A closing retention marker
uses that UUID and closure digest for its separate private purpose.

## Required C/D/Bridge join

C first permanently closes the authenticated exact original operation. D then
acquires the existing owner advisory session lock and checks exact operation
intent, effect and purged-effect fence together. Any such durable row refuses
absence. A previously committed identical closure may be read and factually
completed; a conflicting closure or unrelated pending marker refuses.

The immutable closure is committed with `synchronous_commit=on`. PostgreSQL
triggers take the same owner lock and prevent old or queued clients from inserting
or updating an intent, effect or replay fence for the closed operation. Closure
update/deletion/truncation is forbidden. Guard metadata is checked on the supplied
transaction's PostgreSQL catalog. The host must supply the actual owned PG pool;
synthetic query replies do not establish runtime evidence or attest host custody.
The exact implementation and installed path still require genuine acceptance.
This fence covers the existing approved writer path whose record/source/chain
mutations commit in the same transaction as a guarded intent or effect ledger
write. It does not fence standalone raw table writes. H must establish the actual
old writer's source and transaction path or its termination; these source changes
alone do not prove that a deployed old process cannot write through another path.

Configured independent retention records the closing marker before the durable
closure and confirms the prepared/final closure checkpoint from its owned reader.
No existing unresolved marker is erased to manufacture absence. The historical
eight-table v1 format and bytes remain exact; a nonempty closure table uses the
explicit v2 control-state profile/domain. Closures cannot be removed or changed
by later retained control state or restored data. Original records, chains and
source event bytes are not rebuilt or normalized.

A lost begin reply with an exact unprepared closing marker and no SQL closure row
can resume under the owner lock using that marker's original closure UUID/digest,
after the absence and installed-guard checks. A prepared marker with its SQL row
missing remains unresolved: this call cannot replace a qualified database restore.

**D's result alone is insufficient.** C must durably close the exact original
operation as never consumed, preventing any later reserve/prepare/dispatch and
retaining that fact beyond pending-row pruning. `DENIED`, `DECLINED`, a missing
row, a local flag and `PREPARED` are not that evidence. Bridge must verify identical
owner, subject, Task, operation ID and digest across both durable closures before
closing the old attempt and admitting a distinct fresh proposal. It never retries
the original attempt or refunds/unconsumes any authority. If C cannot prove never
consumed, the operation remains unknown and blocking even when D has fenced it.

The original six-field reference and full closure body are separately retained
as exact donor-canonical UTF-8 bytes. This restrictive fence needs no replacement
proposal, grant or effect request. C must check the original opaque digest against
its own durable state. A's frozen private C signatures are:

```text
C.closeUnconsumedOperation({session_token, reference})
C.readUnconsumedClosure({session_token, reference})
```

C authenticates the owner and Task, resolves the complete original operation from
its retained trusted source, and atomically checks that no prepared, consumed,
reserved or dispatched authority exists for the original operation. It must
permanently retain a terminal never-consumed record and check it at every later
propose/review/complete/reserve/prepare/dispatch entry point, including after
ordinary pending-row pruning. Ever-consumed or ambiguous operations refuse.
C success fields are exactly `{ok, status, operation, closure, closure_digest,
idempotent}` with `status: 'CLOSED_UNCONSUMED'`, the complete original operation,
and a permanent `prime-authority-never-consumed/v1` closure. Its closure records
the original operation epoch; D's closure records the authenticated current host
epoch. Bridge validates each against its documented source. The C digest prefix
is `aukora-prime.authority-never-consumed.v1` plus one NUL byte. This D package
does not implement or attest C's returned history.

D performs no C call while holding its owner session lock. Bridge calls C first,
then D, and admits no fresh proposal between. If a racing writer produced a durable
intent/effect before D obtained the lock, D refuses and the original attempt stays
unknown. Only after both facts and enforced writer fencing may Bridge close the
old attempt and admit a distinct fresh key. Ordinary admission never invokes this recovery path:
sixteen delivered live proposals remain reviewable, and genuine decline frees
capacity without closing unrelated proposals. A committed closure at a different
closing epoch is conservatively refused by this candidate rather than rewritten.

## Checks and limits

All source-profile tests and fixtures are unchanged. Retained TAP/hashes are in
the separate local handoff. Existing source regressions exercise the original
protocol; the new PostgreSQL trigger/closure path has not run on a live database.
No separated IPC/UID/custodian runtime, personal-data import, production migration,
credentials, security configuration, publication or paid inference was performed.
The exact Desktop v0.3 reference was read at the parent-relayed local path and
verified as SHA-256 `0b1a334ff4854553c7bec4eab3b499dd556ef144f619273c5e931b70bd323d31`.
Its CP-4 requires independent validation/time/custody and an acknowledged full
entry anchor before effect. The present local checkpoint mechanism does not
establish those dependencies. No whole-spec conformity claim follows.
Service-refused checks remain stopped.
