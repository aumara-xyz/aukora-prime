# Diagnostic owner-memory pilot

This is development source based on reviewed H `fbbb1ae43026cb1567afd3f02a28b8bec69f2351`.
The frozen publication tree is untouched. No tests, builds, keys, workers,
provider calls, indexing or host changes were performed for this increment.
Focused check approval is pending. Source review is not runtime acceptance.

## Integration interfaces

Use one `createUiAdapters({call})` instance for B's authority controller and
the memory workflow. Its opaque session is established by real C login. The
host selects the Task, source event, owner scope, privacy and routing; caller
payloads supply none of those facts.

The existing H native client must expose these additional read interfaces:

```js
recall: input => attached().recall(input),
getRecallSnapshot: () => attached().getRecallSnapshot(),
```

`workflow.recall({query,limit})` accepts an exact nonempty UTF-8 query of at most
4096 bytes and an integer limit from 1 through 100. Results are at
`workflow.getRecallSnapshot()`, separate from B's closed approval/save/recovery
snapshot and the approved save's record and receipt. `ready/found` with an empty record list means no lexical match.
`unavailable/undetermined` with null records means store availability is unknown.
Neither result clears a save or an unresolved effect. Every recalled record is
bound to C's authenticated owner subject and its corresponding citation. The
invoking Task ID is returned separately; older records need not share that Task.
D's recall ceilings remain visible, and remembered records grant no authority.

The existing `memory.recall` request grammar is unchanged. Its response now adds
`owner_id`, `owner_subject` and `task_id`, derived from C and the trusted registry.
The UI adapter discards status, citation, recall and recovery replies if its
session changes while the request is pending.

After genuine completed save recovery, `workflow.refresh()` can refresh the
recovered record's status and retained-head citation. The restored context is
read-only: it contains no reconstructed operation, draft or proof. Approval/save
cannot run from it. A fresh proposal still goes through the normal exact review.

For lexical recall, the trusted memory worker may opt into:

```js
indexProjection: {
  profile: 'prime-memory-outbox-projector/v1',
  batch_limit: 20,
}
```

The batch limit must be an integer from 1 through 100. This private wrapper queues
at most 32 coalesced owner contexts after a genuine committed save or receipt
reconciliation reports completed C settlement. It starts D's existing owner-locked
`drainOutbox` after the IPC handler completes, outside the receipt return path. It creates no public
index route, reservation or effect retry. The configured D target/generation
still governs projection. The committed receipt retains its original pending
index status; a later status read reports actual indexing separately. Projection
failure cannot undo the save. Without this option or another qualified private
projector, saved records may remain pending and lexical recall may return empty.

## Pilot acceptance after separately approved checks and setup

1. The integrator mounts H's guarded owner-memory HTTP host and native client.
   Use the existing genuine `/api/prime/capabilities` capsule for B, rather than
   substituting the bridge's diagnostic `capability.status` object. Unmounted or
   unqualified services keep owner actions unavailable. No qualification gate,
   enrollment requirement or protected worker configuration is relaxed here.
2. Provide `client.binding`, await B's `controller.connect`, then `client.attach`.
   Use a fresh client/controller composition after a browser remount; reconnect
   clears B's hooks and must not silently retain an old attachment.
3. Complete real configured owner login. Propose a statement-only extraction
   with a new idempotency key. Inspect the immutable statement, attribution,
   metadata, source quote, full operation and digest in B's owner surface.
   `controller.prepare()` and `controller.submitApproval()` use B's private
   owned invocation to approve and save that exact capture.
4. Retain the actual operation ID, completed receipt, record ID and verified
   citation head from the result. Confirm saved storage independently of
   pending/failed/searchable index state. After the configured private projector
   ACK, query literal words from the statement through `client.recall`.
5. After an explicitly scoped C/D/PG restart, retain the same state, witness,
   database, journal, registry/source binding and index target/generation.
   Recompose the browser client, log in freshly, recover that exact operation
   reference, then refresh status/citation and recall. Recovery may resend only
   D's locally committed receipt; it never repeats a save or dispatch.
6. A refused, timed-out or uncertain approval/save stays unavailable or requires
   reconciliation. Stop that mutation path. Do not reset state, mint replacement
   proofs, reuse an effect key, clear a fence or resubmit to make the demo proceed.

Needed focused checks, when approved: session change during each read; recalled
owner/citation mismatch; found-empty versus undetermined; recovered-save refresh
without save authority; private projection completed/pending/failure cases;
W1 proposed/legacy-known-unsent rows remaining blocked. Existing exact-operation,
receipt and replay checks remain relevant. No result is claimed before execution.

## W1 closure remains off

This development branch removes read-time promotion of absent D effects to
`known_unsent`. Legacy rows with that label remain active reconciliation duties.
The save and forget clients refuse that label as closure evidence. Normal
attempted rows with completed genuine C/D receipts can still restore factual
saved reads; legacy unsent labels and uncertainty cannot clear themselves.

A future closure join needs a matching durable C/D marker keyed to the exact
owner, Task, operation ID and full operation digest. D must hold its owner writer
lock and establish no intent, request, effect or retained replay marker; C must
independently check durable kernel prepared/consumed evidence and witness state.
Both writer paths must reject any later reserve/dispatch/effect against the
closed operation. Partial commit, lost reply or crash stays unknown until both
retained markers agree. That contract needs C/D ownership and separate review;
no closure API, marker writer, reset or unconsumption endpoint is added here.

Dependencies remain real C configured verifier/session store and witness, D's
actual host-supplied pgPool and schema, trusted active Task/source context,
authenticated private IPC, B owner controls and H host qualification. E's app
must consume these same injected interfaces and show unavailable/reconciliation
states. Lab code is reference-only and is not imported by this package.
