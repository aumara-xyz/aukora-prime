# Independent memory control retention

This source checkpoint extends D `4e6d0336a286aa84e53479f0200d20d480ada5f8`. It provides a concrete file reader and publisher; it does not configure a production path, establish Unix identities, activate workers, connect to PostgreSQL or qualify the full write/retention protocol. Ordinary synthetic tests are the only new evidence.

## Exact host interface

Import these from `@aukora-prime/memory/control-retention`, or the owned `packages/memory/src/control-retention.mjs`:

```js
createUnavailableControlRetention()
createFileControlRetentionReader(config)
createFileControlRetentionPublisher(config)
isControlRetentionReader(adapter)
MEMORY_RETENTION_SCHEMA
```

`config` is closed and requires exactly:

```js
{
  directory: '<explicit absolute, real, canonical independent directory>',
  publisher_uid: '<nonnegative integer, actual publisher UID>',
  retention_gid: '<nonnegative integer, existing read group>',
  reader_uid: '<nonnegative integer, distinct actual reader UID>',
  contracts: '<owned frozen Prime contracts runtime>'
}
```

The placeholders describe types, not values. No production defaults are selected. The contracts runtime must expose `validateContract` and `operationDigest`. Constructors and every filesystem method require the actual and effective UID for the selected role and existing retention-group membership. The adapter creates no accounts or group membership.

Reader methods are `readCurrent(host)` and `restoreAnchorProvider(host)`; both return the same complete retained envelope. `status` is an immutable object with `{configured,kind,schema}`, not an authority result. The reader is internally branded. A publisher or arbitrary callback object cannot be supplied as `controlRetention`.

Publisher methods are:

```js
readCurrent(host)
beginUpdate({host, expected_checkpoint_sha256, operation_id, operation_digest})
publish({host, control_state, expected_checkpoint_sha256})
completePending({host, checkpoint_sha256})
```

All methods are asynchronous. Host is closed and contains precisely `{owner_id,owner_subject,authorization_epoch}`. H derives the distinct identity fields and current safe-integer epoch from verified C context; neither guest input nor the incoming snapshot supplies them. Reader requires the current epoch exactly. Publisher can observe an older epoch to advance it, and cannot publish an epoch regression.

Wire only the reader into `createPostgresMemory({pool,authority,contracts,controlRetention:reader})` and the same option into `runMemoryCommand`. The default is a branded unavailable reader: `controlRetentionStatus()` reports `configured:false`, and restore refuses `memory:trusted-restore-anchor-unavailable` before SQL or C. Explicit legacy `restoreAnchorProvider(host)` remains supported for a host's complete independently trusted bundle, but it supplies no file protection, pending-marker, epoch or checkpoint qualification. Boolean callbacks refuse. Supplying both interfaces refuses ambiguity.

## Storage preconditions

H must independently protect retention storage from recoverable memory data and record snapshots. The pre-existing canonical directory must belong to `publisher_uid:retention_gid`, with exact mode `02750`; its real ancestors must be protected, with only root-owned sticky temporary ancestors excepted. No symlink directory is accepted. Reader has group read/search only. The module never creates its directory, changes ownership or permissions, or chooses a path.

Files are canonical donor JSON followed by one LF, regular, single-link, publisher-owned, retention-group-owned, exact mode `0640`, and bounded in size. Opens refuse symlinks; file and directory identity is checked around access. Generation writes are exclusive. Owner lock files use `0600`, and cleanup only removes this call's exact owned inode. Stale locks remain fail closed; there is no force-unlock API. Current replacement and marker publication/removal use file and directory fsync. An uncertain write or close refuses `memory:control-retention-commit-uncertain`; that publisher instance does not retry.

The owner key is SHA-256 of UTF-8 `aukora-prime.memory-retention-owner.v1\0` plus donor canonical JSON of `{owner_id,owner_subject}`. Per-owner names are:

```text
<owner-key>.<checkpoint-sha256>.json
<owner-key>.current.json
<owner-key>.pending.json
<owner-key>.lock
```

Immutable envelope shape:

```js
{
  schema: 'aukora-prime-memory-retention/v1',
  owner_id, owner_subject, authorization_epoch,
  sequence, previous_checkpoint_sha256,
  control_state, checkpoint_sha256
}
```

`control_state` is the existing complete eight-table `aukora-prime-memory-control-state/v1` bundle. Checkpoint SHA-256 covers UTF-8 `aukora-prime.memory-retention.v1\0` plus canonical JSON of the envelope excluding its checksum. Sequence starts at 1, with a null predecessor only for that first checkpoint. The closed current pointer binds identity, epoch, sequence, digest and exact generation filename. Readers check it twice and refuse replacement races. A self-consistent generation does not establish independent current authority.

`publish` requires exact predecessor CAS. Bootstrap with a null predecessor permits only genuinely empty heads and eight empty tables. Nonempty snapshot/database bootstrap refuses; no migration override or import trust flag exists. Subsequent publication requires a matching pending marker. Continuity preserves old purges, requests, tombstones, redactions, fences and unresolved intents; completed result payloads may disappear only with an exact matching replay fence. Head domains and control scopes cannot disappear. Changed heads are accepted only from the trusted live publisher; the pure continuity check does not prove a chain prefix from opaque hashes.

## Required H write coordination

Pending marker shape is exactly:

```js
{
  schema: 'aukora-prime-memory-retention-pending/v1',
  owner_id, owner_subject, authorization_epoch,
  expected_checkpoint_sha256, operation_id, operation_digest
}
```

`beginUpdate` checks the current checkpoint CAS and durably creates this marker exclusively. Any pending marker makes readers refuse `memory:control-retention-update-pending`, including after a publisher restart. A failed candidate publication leaves the marker. `publish` requires the next complete live D bundle to retain the exact marker operation/digest in a validated intent, actual effect or content-free replay fence, then publishes and fsyncs the new current pointer before removing and fsyncing the marker. It never fabricates an applied result.

If the pointer committed but marker removal did not, a fresh publisher can inspect `readCurrent`. `completePending` removes the marker only when the actual current envelope has the exact requested checkpoint, marker predecessor, current owner/epoch and retained matching operation. It cannot clear an unchanged checkpoint, assert "no effect", cancel a pending intent, or replay a memory operation.

H owns the private authenticated publisher gate, trusted live export acquisition, per-owner serialization and C/worker join. It must coordinate every durable control write, including PREPARED intents, uncertain outcomes, restore/import and purge, with current-pointer publication. Creating a marker only after a DB commit leaves a crash gap before the marker. The ordinary fixture marks after PREPARED and before dispatch to exercise source semantics; it does **not** establish lossless retention of all PREPARED writes or production freshness. Conversely, marking before calling restore causes its normal reader preflight to refuse. H must resolve that atomic ordering and any narrowly scoped restore observation with D/C before enabling this path. There is no hidden generic-true hook that resolves this requirement.

Restore now binds `retention_checkpoint_sha256` and `retention_epoch` alongside `control_anchor_sha256`, exact incoming/retained heads and manifest digest. D rechecks the checkpoint and epoch under its owner transactions and requires the operation's authorization epoch to match. Changes refuse before reserve. These checks protect the supplied current observation; they do not substitute for the mandatory write-coordination gate.

H integration values remain unassigned in this lane: independent storage directory, existing publisher UID/GID and reader UID, trusted current epoch source, and the atomic ordering above. No permission or resource changes are implied by this constructor grammar.

## Evidence and limits

Ordinary source tests cover unavailable defaults, constructor shape, disk CAS/epoch/marker behavior, factual marker recovery, retained-row continuity and file-reader-bound cold restore. The restore fixture persists real bytes through SQLite and reopen, preserves exact intent bytes and citations, and refuses changed checkpoint/epoch before consumption. Its authority is a private toy, not production C. All file tests run under one actual OS UID; process identities/groups and the setgid bit stripped by this Mac filesystem are explicitly modeled. No Unix boundary or real PostgreSQL claim follows.

`test/operator-postgres.mjs` now explicitly selects all new replay-fence columns before preparation and binds its separate synthetic anchor to owner ID and epoch. Its report labels the provider `explicit-toy-host-provider/not-production-file-reader`. Operator instructions remain source only, exact-schema table migration only, with schema/admin lifecycle owned exclusively by the PG operator. The earlier 7+6 storage receipt predates this checkpoint and does not qualify its retention behavior.

Retained operations and receipts can contain statement text and original canonical record bytes. This directory and older immutable generations are sensitive control backups, separate from record snapshots. Local forget/purge does not erase them, C history, external copies, WAL or physical media.
