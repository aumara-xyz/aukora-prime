// SPDX-License-Identifier: AGPL-3.0-or-later
// Owned physical snapshot access for the explicit private-v2 source composition.
// The algorithms retain the original index.mjs serialization and record identities.
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { types } from 'node:util'
import { requireMemory, parseOriginal, sha256, verifyChain, validateOriginal, MAX_BYTES } from './codecs.mjs'
import { makeSnapshot, inspectSnapshot, recordCommitment } from './snapshot.mjs'
import { MEMORY_CONTROL_TABLES, MEMORY_WRITER_CLOSURE_TABLE } from './control-state.mjs'
import { isPrivateV2OwnerClient } from './private-v2-participant.mjs'
import { PRIVATE_CONTROL_TABLES, detachPrivateData } from './private-v2-control.mjs'
import { isPrivateV2EffectController } from './private-v2-effect-participant.mjs'
import { memoryEffectDigest } from './authorization.mjs'

const accesses = new WeakSet()
const queryFacades = new WeakMap()
const rows = async (db, sql, values = []) => (await db.query(sql, values)).rows
const bytes = value => Buffer.from(value)
const chainBytes = entries => Buffer.concat(entries.map(entry => bytes(entry.bytes)))
const definitions = Object.freeze({...MEMORY_CONTROL_TABLES, unsent_closures: MEMORY_WRITER_CLOSURE_TABLE})
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)
const rowKey = (row, definition) => canonicalJSON(definition.key.map(field => row[field]))
const sameRow = (a, b, definition) => b !== undefined && definition.columns.every(field =>
  definition.byteColumns.includes(field) ? bytes(a[field]).equals(bytes(b[field])) : a[field] === b[field])
function ownConfiguration(input, keys, code) {
  requireMemory(input && typeof input === 'object' && !Array.isArray(input) && !types.isProxy(input)
    && [Object.prototype, null].includes(Object.getPrototypeOf(input)), code)
  const descriptors = Object.getOwnPropertyDescriptors(input)
  requireMemory(Reflect.ownKeys(descriptors).every(key => typeof key === 'string' && keys.includes(key)
    && Object.hasOwn(descriptors[key], 'value') && descriptors[key].enumerable), code)
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]))
}

export const isPrivateV2RecordAccess = value => Boolean(value && accesses.has(value))

/**
 * This local factory owns literal SQL and never accepts a record-writing callback.
 * Its client must come from D's active owner participant; it cannot open transactions,
 * allocate connections, provision identities, or grant permission to restore.
 */
export function createPrivateV2RecordAccess(input = {}) {
  const {indexTarget = 'postgres:fts:simple:v1', indexGeneration = '1'} = ownConfiguration(input,
    ['indexTarget', 'indexGeneration'], 'memory:private-v2-record-configuration-invalid')
  requireMemory(typeof indexTarget === 'string' && indexTarget && typeof indexGeneration === 'string'
    && indexGeneration, 'memory:private-v2-record-index-profile-invalid')
  function owner(host) {
    requireMemory(typeof host?.owner_subject === 'string' && host.owner_subject.length > 0,
      'memory:private-v2-record-owner-required')
    return host.owner_subject
  }
  function client(db, host, access = 'read') {
    const actual = queryFacades.get(db) ?? db
    requireMemory(isPrivateV2OwnerClient(actual, host, access), 'memory:private-v2-owner-client-required')
    const facade = Object.freeze({query: async (sql, parameters) => {
      requireMemory(isPrivateV2OwnerClient(actual, host, access), 'memory:private-v2-owner-client-required')
      return actual.query(sql, parameters)
    }})
    queryFacades.set(facade, actual)
    return facade
  }

  async function exportSnapshot(db, host, rawOptions = {}) {
    db = client(db, host)
    const {full = false} = ownConfiguration(rawOptions, ['full'], 'memory:private-v2-record-export-options-invalid')
    requireMemory(typeof full === 'boolean', 'memory:private-v2-record-export-options-invalid')
    const subject = owner(host), files = [], heads = {}
    const tombstones = await rows(db, 'SELECT * FROM prime_memory_tombstones WHERE owner_subject=$1', [subject])
    const hidden = new Set(tombstones.map(row => row.record_id)), redactions = []
    const removedEvents = new Set(), liveEvents = new Set()
    requireMemory(!full || hidden.size === 0, 'memory:full-backup-forgotten-payload-forbidden')
    for (const row of await rows(db, 'SELECT * FROM prime_memory_records WHERE owner_subject=$1 ORDER BY record_id,revision', [subject])) {
      const meta = validateOriginal(row.canonical_bytes, subject)
      requireMemory(meta.id === row.record_id && meta.digest === row.original_sha256 && meta.format === row.record_format
        && meta.canon === row.canonicalizer && meta.scope === row.scope && meta.privacy === row.privacy
        && meta.tier === row.tier && meta.statement === row.statement && typeof row.task_id === 'string' && row.task_id,
      'memory:restore-stored-record-metadata-changed')
      const commitment = recordCommitment(row, bytes(row.canonical_bytes))
      if (!full && hidden.has(row.record_id)) redactions.push(commitment)
      else {
        for (const digest of commitment.source_digests) liveEvents.add(digest)
        files.push({path: `records/${row.record_id}/${row.revision}.json`, role: 'record', record_id: row.record_id,
          task_id: row.task_id, revision: row.revision, chain_domain: row.chain_domain,
          chain_sequence: row.chain_sequence, bytes: bytes(row.canonical_bytes)})
      }
    }
    const retained = await rows(db, 'SELECT bytes FROM prime_memory_redactions WHERE owner_subject=$1', [subject])
    requireMemory(!full || retained.length === 0, 'memory:full-backup-payload-unavailable')
    for (const row of retained) {
      const value = parseOriginal(row.bytes)
      if (!redactions.some(item => item.record_id === value.record_id && item.revision === value.revision)) redactions.push(value)
    }
    for (const value of redactions) {
      for (const digest of value.source_digests) removedEvents.add(digest)
      files.push({path: `redactions/${value.record_id}/${value.revision}.json`, role: 'redaction',
        bytes: Buffer.from(canonicalJSON(value) + '\n')})
    }
    for (const head of await rows(db, 'SELECT * FROM prime_memory_heads WHERE owner_subject=$1 ORDER BY chain_domain', [subject])) {
      const entries = await rows(db, 'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence',
        [subject, head.chain_domain])
      const verified = verifyChain(chainBytes(entries), head.hash)
      requireMemory(verified.sequence === head.sequence, 'memory:chain-head-sequence-changed')
      heads[head.chain_domain] = head.hash
      files.push({path: `chains/${head.chain_domain}.jsonl`, role: 'chain', chain_domain: head.chain_domain, bytes: chainBytes(entries)})
    }
    for (const event of await rows(db, 'SELECT sha256,bytes FROM prime_memory_events WHERE owner_subject=$1', [subject])) {
      requireMemory(sha256(bytes(event.bytes)) === event.sha256, 'memory:event-changed')
      if (!removedEvents.has(event.sha256) && (full || liveEvents.has(event.sha256))) files.push({
        path: `events/${event.sha256}.json`, role: 'event', bytes: bytes(event.bytes)})
    }
    for (const tombstone of tombstones) {
      const original = parseOriginal(tombstone.bytes), bare = original.tombstone ?? original
      files.push({path: `tombstones/${tombstone.record_id}.json`, role: 'tombstone', bytes: full ? bytes(tombstone.bytes)
        : Buffer.from(canonicalJSON({kind: 'tombstone', recordId: tombstone.record_id, at: bare.at}) + '\n')})
    }
    for (const control of await rows(db, 'SELECT * FROM prime_memory_controls WHERE owner_subject=$1', [subject])) files.push({
      path: `controls/${sha256(Buffer.from(control.scope))}.json`, role: 'control', scope: control.scope, bytes: bytes(control.bytes)})
    const opaque = new Set()
    for (const original of await rows(db, 'SELECT * FROM prime_memory_originals WHERE owner_subject=$1', [subject])) {
      const metadata = parseOriginal(original.metadata_bytes)
      requireMemory(sha256(bytes(original.bytes)) === original.sha256, 'memory:original-changed')
      if (full) files.push({path: `originals/${original.snapshot_digest}/${original.logical_path}`,
        role: metadata.role === 'approved-evidence' ? 'approved-evidence' : 'original', original_metadata: metadata,
        bytes: bytes(original.bytes)})
      else opaque.add(metadata.role === 'opaque-original' ? parseOriginal(original.bytes).sha256 : original.sha256)
    }
    for (const source of await rows(db, 'SELECT * FROM prime_memory_snapshots WHERE owner_subject=$1', [subject])) {
      if (full) files.push({path: `original-manifests/${source.digest}.json`, role: 'original', bytes: bytes(source.manifest_bytes)})
      else opaque.add(sha256(source.manifest_bytes))
    }
    for (const digest of opaque) files.push({path: `opaque-originals/${digest}.json`, role: 'opaque-original',
      bytes: Buffer.from(canonicalJSON({kind: 'opaque-original/v1', sha256: digest}) + '\n')})
    const snapshot = makeSnapshot(subject, files, heads, {redacted: !full})
    inspectSnapshot(snapshot, subject)
    return snapshot
  }

  async function preflight(db, host, snapshot, retained) {
    db = client(db, host)
    const subject = owner(host), checked = inspectSnapshot(snapshot, subject, {expectedHeads: retained.heads})
    requireMemory(same(snapshot.heads, retained.heads), 'memory:restore-anchor-heads-mismatch')
    requireMemory(checked.quarantine.length === 0, 'memory:restore-quarantine-forbidden')
    requireMemory(checked.records.every(item => typeof item.file.task_id === 'string' && item.file.task_id.length > 0
      && item.file.task_id.length <= 4096), 'memory:restore-record-task-required')
    requireMemory(!checked.records.some(item => checked.tombstones.some(tombstone => tombstone.id === item.meta.id)),
      'memory:restore-forgotten-payload-forbidden')
    const tables = retained.tables
    const purgedIds = new Set(tables.purges.flatMap(row => parseOriginal(row.bytes).record_ids))
    const purgedSources = new Set(tables.purges.flatMap(row => parseOriginal(row.bytes).source_digests ?? []))
    requireMemory(!checked.files.some(file => file.role === 'record' && purgedIds.has(file.record_id)), 'memory:purged-payload-reimport')
    requireMemory(![...checked.events.keys()].some(digest => purgedSources.has(digest)), 'memory:purged-source-reimport')
    for (const item of checked.records) {
      const digests = [item.meta.record.source?.sha256, ...(item.meta.record.evidence ?? []).map(evidence => evidence?.turnDigest)]
      requireMemory(!digests.some(digest => purgedSources.has(digest)), 'memory:purged-source-reference-reimport')
    }
    requireMemory(!tables.purges.length || (snapshot.schema === 'aukora-prime-memory-snapshot/v2'
      && !checked.files.some(file => ['original', 'approved-evidence'].includes(file.role))), 'memory:purged-source-forest-reimport')
    for (const head of await rows(db, 'SELECT * FROM prime_memory_heads WHERE owner_subject=$1 ORDER BY chain_domain', [subject])) {
      const incoming = checked.chains.get(head.chain_domain)
      requireMemory(incoming, 'memory:import-local-chain-omitted')
      const entries = await rows(db, 'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence',
        [subject, head.chain_domain])
      const old = verifyChain(chainBytes(entries), head.hash)
      requireMemory(old.sequence === head.sequence && incoming.sequence >= old.sequence
        && (old.sequence === 0 || incoming.entries[old.sequence - 1].hash === old.head), 'memory:import-chain-fork')
    }
    // A retained ancestor permits additions, never disappearance of an unpurged local revision.
    for (const prior of await rows(db, 'SELECT * FROM prime_memory_records WHERE owner_subject=$1 ORDER BY record_id,revision', [subject])) {
      const incoming = checked.records.find(item => item.meta.id === prior.record_id && item.file.revision === prior.revision)
      const redaction = checked.redactions.find(item => item.value.record_id === prior.record_id && item.value.revision === prior.revision)
      requireMemory(incoming ? incoming.meta.digest === prior.original_sha256 && bytes(prior.canonical_bytes).equals(incoming.file.bytes)
        && incoming.file.task_id === prior.task_id
        : redaction !== undefined && same(recordCommitment(prior, bytes(prior.canonical_bytes)), redaction.value),
      'memory:restore-local-record-omitted-or-changed')
    }
    requireMemory(checked.tombstones.length === tables.tombstones.length,
      'memory:restore-control-tombstone-set-mismatch')
    for (const row of tables.tombstones) {
      const value = parseOriginal(row.bytes), bare = value.tombstone ?? value
      requireMemory(checked.tombstones.some(tombstone => tombstone.id === row.record_id && tombstone.at === bare.at),
        'memory:restore-control-tombstone-omitted')
    }
    requireMemory(checked.redactions.length === tables.redactions.length, 'memory:restore-control-redaction-set-mismatch')
    for (const row of tables.redactions) requireMemory(checked.redactions.some(item => item.value.record_id === row.record_id
      && item.value.revision === row.revision && same(item.value, parseOriginal(row.bytes))), 'memory:restore-control-redaction-omitted')
    requireMemory(checked.controls.length === tables.controls.length && tables.controls.every(row => checked.controls.some(control =>
      control.scope === row.scope && control.file.bytes.equals(bytes(row.bytes)))), 'memory:restore-control-policy-mismatch')
    return checked
  }

  async function restoreHistoricalControl(db, host, retained) {
    db = client(db, host, 'write')
    const subject = owner(host)
    // Only the fixed D-owned historical tables are written here. Bridge owns its two journal tables.
    for (const [name, definition] of Object.entries(definitions)) {
      const target = retained.tables[name], local = await rows(db, 'SELECT ' + definition.columns.join(',') + ' FROM '
        + definition.table + ' WHERE owner_subject=$1', [subject])
      const wanted = new Map(target.map(row => [rowKey(row, definition), row]))
      for (const prior of local) {
        const next = wanted.get(rowKey(prior, definition))
        if (next !== undefined) requireMemory(name === 'controls' || sameRow(prior, next, definition), 'memory:restore-control-conflict')
        else {
          requireMemory(['intents', 'effects'].includes(name), 'memory:restore-retained-control-omitted')
          const fence = retained.tables.replay_fences.find(row => row.operation_id === prior.operation_id)
          const grant = prior.grant_id ?? parseOriginal(prior.grant_bytes).grant_id
          requireMemory(fence && fence.operation_digest === prior.operation_digest && fence.grant_id === grant
            && fence.request_id === prior.request_id && fence.request_digest === prior.request_digest,
          'memory:restore-control-replay-conflict')
          await db.query('DELETE FROM ' + definition.table + ' WHERE owner_subject=$1 AND operation_id=$2', [subject, prior.operation_id])
        }
      }
      for (const row of target) {
        requireMemory(row.owner_subject === subject, 'memory:restore-control-owner-mismatch')
        const columns = definition.columns
        await db.query('INSERT INTO ' + definition.table + '(' + columns.join(',') + ') VALUES('
          + columns.map((_, index) => '$' + (index + 1)).join(',') + ')' + (name === 'controls'
            ? ' ON CONFLICT(owner_subject,scope) DO UPDATE SET bytes=EXCLUDED.bytes' : ' ON CONFLICT DO NOTHING'),
        columns.map(field => row[field]))
        const keyColumns = ['owner_subject', ...definition.key]
        const [stored] = await rows(db, 'SELECT ' + columns.join(',') + ' FROM ' + definition.table + ' WHERE '
          + keyColumns.map((field, index) => field + '=$' + (index + 1)).join(' AND '), keyColumns.map(field => row[field]))
        requireMemory(sameRow(row, stored, definition), 'memory:restore-control-conflict')
      }
    }
  }

  // Preserve X only from the genuine active dispatched controller's factual I
  // row, independently compared with actual SQL. This creates a physical write
  // plan, never a new retained checkpoint or caller-selected control projection.
  async function liveRestoreTarget(db, host, snapshot, retained, controller) {
    requireMemory(isPrivateV2EffectController(controller), 'memory:private-v2-restore-controller-required')
    const actual = queryFacades.get(db) ?? db
    const evidence = detachPrivateData(await controller.restoreEvidence(actual))
    requireMemory(evidence && Object.keys(evidence).length === 5
      && ['anchor', 'localControl', 'ancestry', 'snapshot', 'operation'].every(key => Object.hasOwn(evidence, key)),
    'memory:private-v2-restore-evidence-fields-invalid')
    const operation = evidence.operation, control = evidence.anchor.control_state
    requireMemory(same(snapshot, evidence.snapshot) && operation.action_type === 'memory.restore'
      && operation.owner_id === host.owner_id && operation.target_identity.owner_subject === owner(host)
      && operation.task_id === host.task_id && operation.authorization_epoch === host.authorization_epoch
      && operation.canonical_parameters.manifest_sha256 === snapshot.manifest_sha256
      && retained.digest === control.control_sha256 && same(retained.heads, control.heads),
    'memory:private-v2-restore-original-target-mismatch')
    let decodedBytes = 0
    function decodeRow(row, specification) {
      requireMemory(row && Object.keys(row).length === specification.columns.length
        && specification.columns.every(field => Object.hasOwn(row, field)), 'memory:private-v2-restore-row-fields-invalid')
      const decoded = {...row}
      for (const field of specification.byteColumns) {
        const envelope = row[field]
        requireMemory(envelope && Object.keys(envelope).length === 2 && Object.hasOwn(envelope, 'bytes_base64')
          && Object.hasOwn(envelope, 'sha256') && typeof envelope.bytes_base64 === 'string'
          && typeof envelope.sha256 === 'string' && /^[0-9a-f]{64}$/.test(envelope.sha256),
        'memory:private-v2-restore-row-bytes-invalid')
        const original = Buffer.from(envelope.bytes_base64, 'base64')
        decodedBytes += original.length
        requireMemory(decodedBytes <= MAX_BYTES && original.toString('base64') === envelope.bytes_base64
          && sha256(original) === envelope.sha256, 'memory:private-v2-restore-row-bytes-changed')
        parseOriginal(original); decoded[field] = original
      }
      return decoded
    }
    const tables = {}
    for (const [name, specification] of Object.entries(PRIVATE_CONTROL_TABLES)) {
      const target = control.tables[name].map(row => decodeRow(row, specification))
      const supplied = retained.tables[name]
      requireMemory(Array.isArray(supplied) && supplied.length === target.length
        && target.every((row, index) => sameRow(row, supplied[index], specification)),
      'memory:private-v2-restore-original-target-mismatch')
      tables[name] = target
    }
    const live = decodeRow(detachPrivateData(await controller.restoreIntent(actual)), definitions.intents)
    const grant = parseOriginal(live.grant_bytes), request = parseOriginal(live.request_bytes)
    requireMemory(live.owner_subject === owner(host) && live.operation_id === operation.operation_id
      && live.operation_bytes.equals(Buffer.from(canonicalJSON(operation)))
      && grant.operation_id === operation.operation_id && grant.operation_digest === live.operation_digest
      && grant.owner_id === host.owner_id && grant.authorization_epoch === host.authorization_epoch
      && grant.audience === operation.audience && request.version === 1
      && request.operation_id === live.operation_id && request.operation_digest === live.operation_digest
      && request.owner_subject === owner(host) && request.action_type === 'memory.restore'
      && same(request.parameters, operation.canonical_parameters) && memoryEffectDigest(request) === live.request_digest,
    'memory:private-v2-restore-live-intent-binding-mismatch')
    requireMemory(!tables.intents.some(row => row.operation_id === live.operation_id || row.request_id === live.request_id)
      && !tables.effects.some(row => row.operation_id === live.operation_id || row.request_id === live.request_id)
      && !tables.replay_fences.some(row => row.operation_id === live.operation_id || row.request_id === live.request_id)
      && !tables.unsent_closures.some(row => row.operation_id === live.operation_id),
    'memory:private-v2-restore-anchor-live-intent-present')
    const stored = await rows(db, 'SELECT ' + definitions.intents.columns.join(',')
      + ' FROM prime_memory_intents WHERE owner_subject=$1 AND operation_id=$2', [owner(host), live.operation_id])
    requireMemory(stored.length === 1 && sameRow(live, stored[0], definitions.intents),
      'memory:private-v2-restore-live-intent-changed')
    tables.intents = [...tables.intents, live]
    return {...retained, heads: control.heads, tables}
  }

  async function restoreSnapshot(db, host, snapshot, retained, controller) {
    db = client(db, host, 'write')
    const historical = controller === undefined ? retained : await liveRestoreTarget(db, host, snapshot, retained, controller)
    const subject = owner(host), checked = await preflight(db, host, snapshot, retained)
    const priorPurges = new Set((await rows(db, 'SELECT operation_id FROM prime_memory_purges WHERE owner_subject=$1', [subject]))
      .map(row => row.operation_id))
    // A verified forward purge carries the original explicit source-forest discard.
    // Never leave an ancestor's plaintext forest after restoring that committed state.
    if (retained.tables.purges.some(row => !priorPurges.has(row.operation_id))) {
      for (const table of ['originals', 'snapshots', 'quarantine']) await db.query('DELETE FROM prime_memory_' + table
        + ' WHERE owner_subject=$1', [subject])
    }
    const [priorSnapshot] = await rows(db, 'SELECT manifest_bytes FROM prime_memory_snapshots WHERE owner_subject=$1 AND digest=$2',
      [subject, checked.digest])
    requireMemory(!priorSnapshot || bytes(priorSnapshot.manifest_bytes).equals(checked.manifestBytes), 'memory:restore-manifest-conflict')
    await db.query('INSERT INTO prime_memory_snapshots(owner_subject,digest,manifest_bytes) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
      [subject, checked.digest, checked.manifestBytes])
    for (const file of checked.files) {
      const {bytes: originalBytes, bytes_base64: ignored, ...metadata} = file
      await db.query('INSERT INTO prime_memory_originals(owner_subject,snapshot_digest,logical_path,bytes,sha256,metadata_bytes) '
        + 'VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',
      [subject, checked.digest, file.path, originalBytes, file.sha256, Buffer.from(canonicalJSON(metadata))])
      const [stored] = await rows(db, 'SELECT bytes,sha256,metadata_bytes FROM prime_memory_originals WHERE owner_subject=$1 '
        + 'AND snapshot_digest=$2 AND logical_path=$3', [subject, checked.digest, file.path])
      requireMemory(stored && stored.sha256 === file.sha256 && bytes(stored.bytes).equals(originalBytes)
        && bytes(stored.metadata_bytes).equals(Buffer.from(canonicalJSON(metadata))), 'memory:restore-original-conflict')
    }
    for (const [digest, originalBytes] of checked.events) {
      await db.query('INSERT INTO prime_memory_events(owner_subject,sha256,bytes) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
        [subject, digest, originalBytes])
      const [stored] = await rows(db, 'SELECT bytes FROM prime_memory_events WHERE owner_subject=$1 AND sha256=$2', [subject, digest])
      requireMemory(stored && bytes(stored.bytes).equals(originalBytes), 'memory:event-conflict')
    }
    for (const [domain, chain] of checked.chains) {
      const [existing] = await rows(db, 'SELECT sequence,hash FROM prime_memory_heads WHERE owner_subject=$1 AND chain_domain=$2', [subject, domain])
      const start = existing?.sequence ?? 0, lines = chain.file.bytes.toString('utf8').slice(0, -1).split('\n')
      for (const entry of chain.entries.slice(start)) await db.query('INSERT INTO prime_memory_chain(owner_subject,chain_domain,sequence,bytes,hash,prev) '
        + 'VALUES($1,$2,$3,$4,$5,$6)', [subject, domain, entry.sequence, Buffer.from(lines[entry.sequence - 1] + '\n'), entry.hash, entry.prev])
      await db.query('INSERT INTO prime_memory_heads(owner_subject,chain_domain,sequence,hash) VALUES($1,$2,$3,$4) '
        + 'ON CONFLICT(owner_subject,chain_domain) DO UPDATE SET sequence=EXCLUDED.sequence,hash=EXCLUDED.hash',
      [subject, domain, chain.sequence, chain.head])
    }
    for (const item of checked.records) {
      const meta = item.meta, file = item.file
      const [prior] = await rows(db, 'SELECT canonical_bytes,original_sha256 FROM prime_memory_records WHERE owner_subject=$1 '
        + 'AND record_id=$2 AND revision=$3', [subject, meta.id, file.revision])
      if (prior) requireMemory(prior.original_sha256 === meta.digest && bytes(prior.canonical_bytes).equals(file.bytes), 'memory:revision-conflict')
      else await db.query('INSERT INTO prime_memory_records(owner_subject,record_id,revision,canonical_bytes,original_sha256,'
        + 'record_format,canonicalizer,task_id,scope,privacy,tier,statement,chain_domain,chain_sequence,source_digest) '
        + 'VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)',
      [subject, meta.id, file.revision, file.bytes, meta.digest, meta.format, meta.canon, file.task_id,
        meta.scope, meta.privacy, meta.tier, meta.statement, file.chain_domain, file.chain_sequence, meta.record.source?.sha256 ?? null])
      const restored = await rows(db, 'SELECT canonical_bytes,original_sha256,record_format,canonicalizer,task_id,scope,privacy,tier,'
        + 'statement,chain_domain,chain_sequence,source_digest FROM prime_memory_records WHERE owner_subject=$1 '
        + 'AND record_id=$2 AND revision=$3', [subject, meta.id, file.revision])
      const stored = restored[0]
      requireMemory(restored.length === 1 && stored.original_sha256 === meta.digest && bytes(stored.canonical_bytes).equals(file.bytes)
        && stored.record_format === meta.format && stored.canonicalizer === meta.canon && stored.task_id === file.task_id
        && stored.scope === meta.scope && stored.privacy === meta.privacy && stored.tier === meta.tier && stored.statement === meta.statement
        && stored.chain_domain === file.chain_domain && stored.chain_sequence === file.chain_sequence
        && stored.source_digest === (meta.record.source?.sha256 ?? null), 'memory:restore-record-readback-conflict')
      await db.query('INSERT INTO prime_memory_outbox(owner_subject,record_id,revision,target,generation,operation) '
        + "VALUES($1,$2,$3,$4,$5,'index') ON CONFLICT DO NOTHING", [subject, meta.id, file.revision, indexTarget, indexGeneration])
    }
    await restoreHistoricalControl(db, host, historical)
    for (const tombstone of retained.tables.tombstones) await db.query('DELETE FROM prime_memory_fts WHERE owner_subject=$1 AND record_id=$2',
      [subject, tombstone.record_id])
    for (const redaction of retained.tables.redactions) {
      await db.query('DELETE FROM prime_memory_records WHERE owner_subject=$1 AND record_id=$2 AND revision=$3',
        [subject, redaction.record_id, redaction.revision])
      await db.query('DELETE FROM prime_memory_fts WHERE owner_subject=$1 AND record_id=$2 AND revision=$3',
        [subject, redaction.record_id, redaction.revision])
      await db.query('DELETE FROM prime_memory_outbox WHERE owner_subject=$1 AND record_id=$2 AND revision=$3',
        [subject, redaction.record_id, redaction.revision])
    }
    const removedSources = new Set(retained.tables.purges.flatMap(row => parseOriginal(row.bytes).source_digests ?? []))
    for (const digest of removedSources) await db.query('DELETE FROM prime_memory_events WHERE owner_subject=$1 AND sha256=$2', [subject, digest])
    // These original records were independently read back; the participant still
    // verifies the complete actual control after journal replay before preparing E.
    return Object.freeze({restored_records: checked.records.length})
  }
  const access = Object.freeze({exportSnapshot, preflight, restoreSnapshot})
  accesses.add(access)
  return access
}
