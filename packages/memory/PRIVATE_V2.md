# Private successor source

This is D's source implementation against frozen decision v004 (private contract
2, control state 3), SHA256
`95fcc9d4fb4420e2dbc13ba28b8332968b4b36e71f069a233847c23932a1c3b9`.
The v1 service and original fixed verification inputs remain unchanged. No
constructor provisions identity, baseline, schema, guards, credentials or runtime.

`createPrivateV2Memory` composes the actual closure, journal, save/forget and
cold-read adapters from exact `{pool,coordinator,profile,contracts,statements,authority}`
trusted-worker inputs. The restore-effect continuation additionally admits one
optional seventh local `journalRestore` function from the reviewed Bridge `9b434`
adapter. The six-field composition keeps its ordinary/cold surface and refuses
restore without that fixed adapter. The older five-field input still refuses
`memory:private-v2-host-qualification-unavailable`. Construction supplies no
qualification or provisioning. H's configured path must remain unmounted until
protected custody, full-entry anchors and native old/second-writer exclusion are
independently qualified. Every actual call still checks native guards and the
independent protected full v3 state; a boolean or profile is no replacement.

The owned modules implement:

- `private-v2-control/advance`: exact logical metadata/global profile, eleven-table
  projection, original thirteen-column workflows, progress, typed transitions,
  D15 markers and completion. Original v1/v2 bytes keep their unchanged parsers.
  Actual reads verify every stored chain against its head on the same client.
- `private-v2-guards.mjs/.sql`: real writable PostgreSQL catalog/owner-lock checks,
  unchanged closure guards, immutable metadata/history and deferred atomic
  workflow/progress correlation. Installation is an explicit caller-owned
  transaction on existing tables; no migration runs here.
- `private-v2-retention/coordinator`: original protected file/UID/inode/fsync
  algorithms, separate typed purposes, committed predecessor ancestry to an empty
  original baseline, exact prepared publication and independent readback, matching
  cleanup/fsync/absence verification. Distinct reader/publisher UIDs use H's closed
  publisher transport; transport replies establish no evidence. Unreachable
  prepared generations prove no publication. A permanent exact cleanup guard
  survives uncertain pending unlink/fsync. Completion is created only after
  durable absence verification; fresh readers require matching completion.
  Already-visible publication also resyncs and rereads the identical candidate.
- `private-v2-participant`: actual same-owner session and PoolClient; full candidate
  preparation before SQL commit, actual committed reread, identical publication
  and cleanup. Its whole awaited session, including unlock/release, is inside the
  uncertainty boundary. Prepared recovery never reapplies SQL or an effect.
- `private-v2-restore-journal`: derives an ordered, bounded query scope from the
  verified published interval between actual local state and CURRENT. It admits
  only the installed nine fixed descriptors, and only the exact sequence of
  owner reads and per-row CAS writes needed by Bridge's restoration helper.
  Each intermediate original13/progress readback is checked independently.
  Archived task IDs, closing epochs and established proofs remain unchanged.
- `private-v2-memory`: unmounted negative closure, immutable first-A completion,
  factual closure query and exact owner-wide/reference census. Pending reads never
  publish or clean up; predecessor-only recovery stays unknown.
- `private-v2-effect-participant`: genuine save/forget controller and explicit
  restore-effect controller with owned full-cold-bundle preflight, using the existing
  C `prepare/dispatch/settle` and eighteen-field v1 permit. Actual intent and applied
  candidates are prepared before their SQL commits, reread and independently
  published with exact cleanup before dispatch or settlement. It shares the same
  owner serializer with the journal composition. The existing D brand module
  registers only this internally created phase object and exposes its immutable
  bound profile; it accepts no caller brand registrar or qualification flag.
  The service's outer owner-session wrapper awaits final inspection, unlock and
  release inside that controller's uncertainty boundary. It retains internally
  captured operation/request and exact pending identity after the nested effect
  context ends; owner-only failures never manufacture an operation or request.
- `private-v2-records/restore`: genuine D-owned physical snapshot export/preflight/
  restore building blocks preserve original bytes, IDs, salts, events, evidence,
  citations, chains, controls, tombstones and purges. Cold verification checks every
  published predecessor edge and original completion. Caller artifacts cannot
  select the restore anchor. The standalone cold adapter restore method still refuses
  `memory:private-v2-restore-authority-join-unavailable`; in the explicit seven-field
  product composition, the actual effect service method overrides that method.
  Its D-owned physical helper preserves the new restore operation's own intent
  while installing the full archived physical/control state.

Private transition requests are exactly
`{transition_id,transition,transition_digest}`. Local Bridge callbacks return only
`undefined` and use reviewed fixed descriptors `{name,text,parameters}`. Parameters
are D-bound selectors from host, immutable transition and independently guarded
SQL baseline. Only the exact nine copied Bridge descriptors are admitted,
including legitimate `UPDATE SET` and its one fixed completion CTE. Prior CAS
bytes/scalars and the target progress digest are independently derived. Named query or exact
registered SQL/values use the same live transaction; no pool, release, DDL,
transaction command or guest SQL endpoint exists. Factual callbacks receive a
separate branded read facade; physical restore requires a write scope.
`recoverJournal` takes exactly `{host,transition_id,transition_digest}`.

The internal D-owned `runRetainedRestorePurpose(host,request,mutate)` uses the
existing exact request and control-restore purpose. Its callback receives
`(client,transition,localControl,restoreJournal,currentAnchor)`. Only D's physical
record helper receives that actual client. Calling
`await restoreJournal(restoreRetainedJournal)` gives the reviewed Bridge helper
the branded query facade, immutable local-to-current control interval and frozen
profile. The helper receives no PoolClient or caller-selected ancestry. Every
required query must finish, return matching actual rows and exhaust the bound
sequence; an invalid query or caught failure permanently refuses the scope.
The scope becomes inactive before final full-control reprojection. Success still
requires the exact full current anchor, candidate retention before SQL COMMIT,
committed reread, protected publication and matching durable pending cleanup.
A partial journal-only restore cannot pass that final equality. Original
transition identity and digest remain the recovery identity.

The explicit private source composition uses actual v3 control for ordinary
approved save/forget; the legacy service retains its existing v1 path. The earlier
provisional internal control-restore purpose uses a closure reference and never
authorizes a genuine restore operation or represents its own intent/effect ledger.
The new effect join described below uses a separate restore effect reference and
actual intent/effect rows, without changing the original13 workflow profile.
C `98dd` still refuses `memory.restore` or `mode: 'prime-restore'` with
`UNAVAILABLE / RETAINED_RESTORE_LINEAGE_UNQUALIFIED`; its narrow actual update is
pending. No alternate action, legacy reserve fallback or future-state SQL
projection bypasses that remaining gate.

Full cold export refuses forgotten/redacted payload. Restore also refuses a
redacted snapshot that would need a new control row outside the exact retained
anchor. A successful current export describes no pending; unresolved pending
lifecycle export/recovery still needs qualification.

RAN checks cover syntax/module loading, minimal pure synthetic grammar/refusals and
the unchanged scoped memory inputs recorded in each handoff. New composition
construction performed zero SQL/C/publisher calls. PostgreSQL SQL execution, old/second
writers, UID isolation, custody/hardware/cosign/full-entry anchor, live first save,
restore and activation remain UNPERFORMED. New cleanup fault-injection checks were
not run. SQL/filesystem commits are an ordered
fail-closed protocol, not one ACID transaction.


## Restore effect continuation from 5275

The explicit seven-field product composition exposes
`effects.restoreSnapshot(host,fullColdBundle,{operation,approval_proof})` through
the genuine controller's `runRestoreOperation`. Its owned preflight verifies the
full cold-bundle manifest, protected published ancestry and actual local physical
records before C consumption. C's unchanged three phase methods receive the
unchanged eighteen-field v1 permit and seven-field genuine owner session. Restore
keeps exactly seven canonical parameters:
`{manifest_sha256,mode:'prime-restore',heads,retained_heads,control_anchor_sha256,retention_checkpoint_sha256,retention_epoch}`.
The immutable five-field profile is unchanged. X's restore effect reference is
separate from the original thirteen-column workflow schema; no runtime workflow
is invented for X.

P is the complete independently protected published current state. A is the
actual SQL state verified as a published ancestor of P. The new retained intent
I is exactly A plus the sole X intent, as a typed restoration-event baseline;
it does not regress SQL or project uncommitted future SQL. The applied E is the
full archived P plus the unchanged X intent and X's actual effect/receipt. The
retainer checks that removing X from E gives P exactly. Archived P retains its
whole established first-A completion proofs, task IDs and closing epochs.
Ordinary reads and writes refuse unresolved I. Only a genuine registered phase
or factual effect reconciliation can observe it; neither retries the physical
effect or recreates a grant.

After C dispatch, D opens the fixed Bridge journal scope and runs the physical
record restore on the actual held owner transaction. The scope derives the
verified A-to-P interval, admits only the reviewed fixed query sequence, and
independently checks the actual archived original13/progress CAS bytes and
readbacks. The reviewed Bridge `9b434` helper supports ordinary monotone per-step
CAS only. If the selected published A-to-P interval crosses an earlier exceptional
restore edge that temporarily regressed control, the controller's pure preflight
refuses BEFORE C consumption; it does not flatten or skip that history. Complete
cold/protected-lineage validators still verify prior restore events. Physical
journal support for those intervals remains pending adaptation, so unrestricted
restore across every ancestry is not claimed. The physical helper preserves X's
own intent; full actual E equality,
prepared-candidate-before-COMMIT, committed reread, protected publication and
durable cleanup remain required before real-receipt settlement. The standalone
cold adapter remains a verification/building-block interface with no authority
service path; product composition deliberately selects the actual effect method
instead of that unavailable restore stub.

The `772e9cc`, `421` and `5275` packets and their original inputs/evidence remain
preserved historical source checkpoints. Evidence for this restore-effect
increment is ONLY `node --check` and independent source audit. Imports, new tests,
I/O, fault injection, actual PostgreSQL/IPC and host/effect qualification are
UNPERFORMED. C `98dd`'s restore gate remains unavailable pending its actual narrow
update. H's default/unqualified runtime remains unmounted. No public schema,
permissions, provisioning, activation, guest route or authority fallback is added.
