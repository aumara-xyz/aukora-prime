# New reduced-guarantee pilot setup source

This D-owned source is for a genuinely NEW pilot lineage and a first real-owner
approved memory save. It does not initialize an existing pilot, recover an old
lineage, or rebaseline old control state. Its scope is explicitly
**REDUCED-GUARANTEE: same host, owner passkey required, PostgreSQL required, no
authority independence or hardware-display claim**. Requirements in metadata are
not evidence that enrollment, storage or display qualification has occurred.
Public service guards remain closed. Optional restore follows a proven first save.

This packet is source-only. No PostgreSQL, filesystem bootstrap, guard migration,
operator setup, credentials, keys, enrollment, owner approval, activation,
publication, worker IPC or host-custody qualification was performed. Attached
checks use synthetic inert data and do not invoke setup or SQL. Existing source
packets and state are preserved.

## Explicit setup boundaries

H/A and the exclusive operator must obtain action-time approval before installing
anything or provisioning credentials, schemas, protected custody or persistent
guards. D supplies no provisioning commands, key generation or automatic setup.
The operator retains all schema/role/process lifecycle. D needs CREATE only within
the exact newly approved schema for its logical-store table and guards; it does
not request database CREATE/TEMP, superuser, schema ownership, new grants or
broader scope. Actual callers must have the approved table privileges and protected
publisher/reader identities before using these source methods.

1. C/H must provision a genuinely NEW authority store through C's explicit setup
   path, verify its actual new `store_id`, and supply that observed ID. D neither
   provisions C nor treats a supplied scalar ID as C identity proof. Existing
   real-pilot IDs are unverified and cannot be adopted by this source. C must
   verify the actual store/profile match again on its first retained reservation.
2. H/A and the exclusive operator select the new memory-store ID, one new schema
   named `prime_pilot_` plus a lowercase raw UUIDv4, and an already protected,
   canonical, empty publisher directory. IDs are externally supplied; D does not
   create identities, credentials, IDs or custody. Exact schema-table setup and
   original writer-closure guards precede D preparation. Keep old schemas,
   directories and state untouched.
3. In an already open writable READ COMMITTED transaction with synchronous commit
   and the genuine owner advisory lock held, invoke D preparation below. The caller
   owns COMMIT. A lost COMMIT reply is uncertainty and never authorizes retry or
   adoption. Preparation refuses any existing logical-store relation, including an
   empty one, and any old rows across every owner in the fixed census.
4. After the caller has separately acknowledged that setup COMMIT, use the NEW
   lineage adapter on its later, dedicated owner transaction. It re-verifies native
   PG state, sends the exact full snapshot to the protected bootstrap publisher,
   and independently verifies the distinct protected reader's genesis and lineage.
   A publisher acknowledgement alone is insufficient. No setup API is a guest route.
5. B/H adopt the exact new browser helper and trusted registry origin described
   below, rebuild the owner review surface, and preserve actual review evidence.
   A real-owner passkey approval must bind and display the exact first-save proposal,
   statement, attribution, evidence quote and reduced-guarantee profile. No fixture
   signer, configured boolean or setup receipt substitutes for that approval.

The immutable private profile is unchanged:

```js
{version:2,kind:'prime-private-unsent-closure/v2',
 expected_authority_store_id:observedNewCStoreId,
 expected_memory_store_id:newMemoryStoreId,
 retention_profile:'required-retained/v2'}
```

Each store ID is a lowercase raw SHA-256 string. The host is exactly
`{owner_id,owner_subject,task_id,authorization_epoch}`. Owner ID and subject are
distinct identifiers; later task IDs and epochs do not rewrite historical proofs.

## PG preparation and verification

Import directly from the owned `src/new-pilot-memory-store.mjs` source:

```js
prepareNewPilotMemoryStore(client,{host,profile,contracts,expected_schema})
verifyNewPilotMemoryStore(client,{host,profile,contracts,expected_schema})
```

The caller supplies the live client, already open transaction and held owner lock.
Neither method connects, opens/commits a transaction, creates a schema, grants a
role, provisions Bridge tables, changes a public service or starts a process.
`prepare` creates only `prime_memory_logical_store`, seeds exact immutable
metadata bytes/digest, and explicitly invokes D's existing private-v2 guard
migration. There is no IF EXISTS, adoption, retry or old-state fallback.

`NEW_PILOT_MEMORY_TABLE_NAMES` exports the exact 21-table registry. All 20 existing
relations must already be persistent ordinary tables in the approved schema, with
no partition, inheritance or RLS. Both methods hold SHARE ROW EXCLUSIVE locks and
recheck relation/namespace OIDs, backend, transaction ID, origin replication role,
writable READ COMMITTED isolation, actual owner lock and native durable guards.
Global emptiness checks cover all owners in the existing census. The exact full v3
control contains empty heads and all eleven empty control/journal table projections
plus genuine logical metadata/profile. SQL source observations do not prove OS UID.

The closed receipt is:

```js
{version:1,kind:'prime-new-pilot-memory-store/v1',phase:'prepared' /* or 'verified' */,
 owner_id,owner_subject,authorization_epoch,
 expected_authority_store_id,expected_memory_store_id,
 physical_scope:{schema,namespace_oid,backend_pid,transaction_id,table_oids},
 control,transaction_pending:true,grants_authority:false}
```

`transaction_pending:true` is deliberate. Verification observes the caller's
current transaction; it is not a COMMIT acknowledgement. A later committed setup
transaction is an orchestration requirement, not a boolean accepted by D. The NEW
handshake below opens its own later verification transaction. Unknown setup
outcomes require factual operator review; rerunning preparation is not recovery.

## Protected new-lineage publication

`src/private-v2-retention.mjs` exports the separate
`createPrivateV2NewLineageBootstrapPublisher` and pure
`makePrivateV2GenesisEnvelope`. Its ordinary publisher remains separate.
The bootstrap publisher accepts the unchanged exact configuration
`{directory,publisher_uid,retention_gid,reader_uid,contracts,profile}`. Custody is
pre-provisioned; publisher and reader are distinct configured UIDs. It makes no
directory, ownership, permission or identity changes.

The exact bootstrap request is `{host,control_state,expected_checkpoint_sha256}`.
The snapshot must be the complete empty v3 control state for the exact supplied
host/profile. Genesis preserves the ordinary eight-field v2 retention envelope,
sequence 1, null predecessor, normal canonical hashes and the supplied store IDs.
The pure helper establishes content only; it establishes neither SQL nor custody.

The directory must be completely empty. Every artifact is exclusive-created;
unknown files, previous owner state, orphan generations, current/pending/cleanup
markers, locks or prior bootstrap state refuse. A permanent original intent and
removable primary bootstrap pending precede publication. A permanent cleanup guard retains the exact pending bytes/digest and
candidate binding. Fresh readers and ordinary publishers refuse primary pending,
missing guard, remaining stage, or guard without matching completion, including
after restart.
Completion v2 bytes are fsynced, closed and read back under a deterministic private
stage name while pending still exists. Matching primary pending removal, directory
fsync and absence/current/genesis/guard verification must succeed; then the own lock
is retired, directory-synced and verified absent. Only after those durable
prerequisites may the exact staged certificate be exclusively linked to its final
name and its captured stage inode retired. Existing final certificates cannot be
replaced. Readback and exact artifact census precede the receipt.

For an uncompleted candidate, failure of pending-removal or lock-removal durability
leaves final completion absent, so fresh factories stay closed. After those prerequisites have succeeded,
final certificate-directory-sync or reply uncertainty may leave an eligible exact
factual certificate, matching the existing cleanup contract: after a crash it can
reduce availability, but it does not certify a failed prerequisite removal. A
factual reader never claims to have observed the publisher fsync. Original v1
bootstrap certificates are refused when a bootstrap intent is present; ordinary
legacy v2 lineages without bootstrap artifacts retain compatibility. No adoption,
rebaseline, replacement checkpoint or automatic retry API is supplied.

The receipt is exactly
`{version:1,kind:'prime-memory-new-lineage-bootstrap/v1',host,profile,control_sha256,checkpoint_sha256,new_lineage_only:true}`.
It is not a runtime qualification. Existing valid ordinary v2 lineages without
bootstrap markers retain compatibility; any present incomplete new bootstrap
marker refuses. Future checkpoints preserve the original genesis proof.

`src/new-pilot-lineage.mjs` composes the local setup handshake:

```js
const setup=createNewPilotLineageSetup({pool,reader,publisher,profile,contracts,expected_schema})
await setup.bootstrap(host)
```

Constructing `setup` performs no IO. The reader must be the genuine owned retention
reader; `publisher` is a closed trusted transport exposing only `bootstrap` and
optional status, bound to the same profile. Select those two members explicitly
when wrapping the bootstrap factory; its separate cleanup command is not admitted
by this initial-setup transport. H supplies protected IPC, authentication
and peer custody. No JavaScript transport object itself proves those properties.
The adapter is one-use from the first valid invocation, including pre-publication
failure. It holds the dedicated owner session through native PG verification,
publication, independent reader readback, repeated PG/current checks and verification
COMMIT, then awaits final owner-lock inspection/unlock/release. Once the publisher
may have observed a request, any failure becomes
`memory:new-pilot-lineage-outcome-unknown` with `automatic_retry:false` and
`reconciliation_required:true`. No actual reader/bootstrap was invoked in source checks.

The setup result binds full host/profile, native physical scope, control/checkpoint
digests, `new_lineage_only:true` and the reduced scope below. It explicitly reports
`authority_identity_verified:false` and `grants_authority:false`. Public save remains
closed until C/H independently establish identity/enrollment, the retained join and
actual owner review; a failed or uncertain setup does not open that service.

## Exact bootstrap retirement only

The separate protected publisher exposes:

```js
retireMatchingBootstrap({host,checkpoint_sha256,bootstrap_sha256})
```

This is a deliberate local operator/private authenticated command, never an
automatic retry or factual read. `bootstrap_sha256` is the original retained intent
digest; checkpoint is the exact original prepared genesis. The command requires
that same original intent, permanent cleanup guard, pending identity, unchanged
generation and CURRENT, plus the exact staged certificate or an already completed
matching certificate. It cannot create/rewrite a generation
or CURRENT, supply different control bytes, seed metadata, or execute SQL. Incomplete
attempts lacking these exact retained artifacts refuse rather than recreate them.
A changed candidate, foreign epoch/task/profile or different pending refuses.

H must invoke it only while the genuine owner PG session is held and actual native
`verifyNewPilotMemoryStore` control remains byte-identical to the original candidate;
C/H identity and the same protected transport/custody requirements still apply.
The command re-syncs and independently verifies the retained prerequisite artifacts,
removes only the exact matching primary pending, durably confirms pending and own
lock absence, then finishes only the identical staged certificate. A deliberate
repeat revalidates the same final certificate and candidate; it does not initialize
another lineage. Independent factual reader and native PG readback follow before
any admission decision. An uncertain continuation never authorizes a new checkpoint.
The initial `createNewPilotLineageSetup` instance remains one-use and supplies no
automatic continuation. No retirement command was invoked by attached pure checks.

`assertPrivateV2BootstrapCleanupContent` checks only the exact inert content tuple
`{host,profile,intent,guard,pending,completion}`. It proves no storage eligibility,
custody, PG state, durability, permission or runtime qualification.

## Reduced scope bound into new record bytes

`src/reduced-pilot-scope.mjs` exports the immutable scope and trusted origin:

```js
REDUCED_PILOT_SCOPE = {
 version:1,kind:'prime-reduced-guarantee-pilot/v1',guarantee:'REDUCED-GUARANTEE',
 deployment:'same-host',owner_approval:'passkey-required',storage:'postgresql-required',
 authority_independence:false,hardware_display:false
}
REDUCED_PILOT_CAPTURE_ORIGIN = {by:'prime.capture/v1',pilot_scope:REDUCED_PILOT_SCOPE}
```

H resolves the authenticated owner/task and supplies this origin from its immutable
trusted registry. Guest extraction cannot choose scope, profile or origin. The exact
eight scope fields permit no additions, aliases, normalization or elevated claims.
The unchanged record `origin` already participates in donor `rem:<sha256>` IDs and
canonical bytes. D's private capture digest includes that exact origin. Candidate
and final stored bytes recheck origin/profile parity under the owner lock.
The actual result/receipt therefore binds the scoped canonical bytes without adding
any public MemoryRecord, OperationProposal or effect-receipt field.

Human review keeps the existing exact six-field `capture_metadata` shape and sets
its `profile` to `REDUCED-GUARANTEE/prime-pilot-memory-capture/v1`. The unchanged
seven save parameters and four-field independent draft bind that literal into the
canonical operation digest. B must render the profile alongside exact escaped
statement/attribution/metadata/quote and validate the independently retained draft
before challenge/signing and save. The browser helper accepts only this literal
and the normal `prime-pilot-memory-capture/v1` profile; pairing mismatch refuses.
It does not reconstruct hidden source/capture preimages in the browser.

Normal origin-only captures retain their original profile and hashes. Historical
imports, notes, citations, tombstones, canonical formats, salts and original source
bytes are not rewritten or passed through a new builder. The changed browser helper
pin, B rebuild and H registry/join qualification remain explicit prerequisites for
a real reduced-pilot save. This source packet supplies no hardware-display or full
independence claim and does not change enrollment or public routes.
