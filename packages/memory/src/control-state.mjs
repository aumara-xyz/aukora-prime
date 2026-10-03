// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { types } from 'node:util'
import { AURA_RECORD_DOMAIN, CHAIN_DOMAINS, MAX_BYTES, parseOriginal, requireMemory, sha256 } from './codecs.mjs'
import { MEMORY_AUDIENCE, memoryEffectDigest, memoryResultDigest, memoryTarget } from './authorization.mjs'

export const MEMORY_CONTROL_SCHEMA = 'aukora-prime-memory-control-state/v1'
export const MEMORY_CONTROL_SCHEMA_V2 = 'aukora-prime-memory-control-state/v2'
const spec = (name, key, columns, byteColumns = []) => Object.freeze({
  table: `prime_memory_${name}`, key: Object.freeze(key),
  columns: Object.freeze(['owner_subject', ...columns]), byteColumns: Object.freeze(byteColumns),
})
// Complete versioned table set. Rebuildable indexes and data snapshots are not control backups.
export const MEMORY_CONTROL_TABLES = Object.freeze({
  purges: spec('purges', ['operation_id'], ['operation_id', 'bytes'], ['bytes']),
  requests: spec('requests', ['idempotency_key'], ['idempotency_key', 'request_digest', 'record_id', 'revision']),
  intents: spec('intents', ['operation_id'], ['operation_id', 'operation_digest', 'grant_bytes', 'operation_bytes',
    'request_id', 'request_digest', 'request_bytes'], ['grant_bytes', 'operation_bytes', 'request_bytes']),
  effects: spec('effects', ['operation_id'], ['operation_id', 'operation_digest', 'grant_id', 'action', 'result_bytes',
    'request_id', 'request_digest', 'request_bytes', 'receipt_bytes', 'operation_bytes', 'grant_bytes'],
  ['result_bytes', 'request_bytes', 'receipt_bytes', 'operation_bytes', 'grant_bytes']),
  tombstones: spec('tombstones', ['record_id'], ['record_id', 'bytes', 'sha256'], ['bytes']),
  controls: spec('controls', ['scope'], ['scope', 'bytes'], ['bytes']),
  redactions: spec('redactions', ['record_id', 'revision'], ['record_id', 'revision', 'bytes'], ['bytes']),
  replay_fences: spec('replay_fences', ['operation_id'], ['operation_id', 'operation_digest', 'grant_id', 'action',
    'request_id', 'request_digest', 'status']),
})
// The historical eight-table profile remains exact. Writer closure adds a new profile
// only when there is an actual durable closure; stored original JSON is never rewritten.
export const MEMORY_WRITER_CLOSURE_TABLE = spec('unsent_closures', ['operation_id'], ['owner_id', 'task_id',
  'operation_id', 'operation_digest', 'action_type', 'authorization_epoch', 'reference_bytes', 'closure_bytes',
  'closure_digest'], ['reference_bytes', 'closure_bytes'])
const TABLES_V2 = Object.freeze({...MEMORY_CONTROL_TABLES, unsent_closures: MEMORY_WRITER_CLOSURE_TABLE})
const TABLE_NAMES = Object.keys(MEMORY_CONTROL_TABLES)
const TABLE_NAMES_V2 = Object.keys(TABLES_V2)
const ACTIONS = ['memory.save', 'memory.import', 'memory.restore', 'memory.backup', 'memory.forget', 'memory.purge', 'memory.erase-owner']
const HEX = /^[0-9a-f]{64}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const nonempty = value => typeof value === 'string' && value.length > 0 && value.length <= 4096
const recordId = value => typeof value === 'string' && /^(?:rem:|kira:)?[0-9a-f]{64}$/.test(value)
const instant = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
  && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value.slice(0, -1) + '.000Z'
const same = (left, right) => canonicalJSON(left) === canonicalJSON(right)
const exact = (value, keys, code) => requireMemory(value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), code)
const keyOf = (row, table) => canonicalJSON(TABLES_V2[table].key.map(key => row[key]))
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0
const commitment = value => sha256(Buffer.from((value.schema === MEMORY_CONTROL_SCHEMA_V2
  ? 'aukora-prime.memory-control-state.v2\0' : 'aukora-prime.memory-control-state.v1\0') + canonicalJSON(value)))
function ownData(object, key) {
  requireMemory(object && typeof object === 'object' && !types.isProxy(object), 'memory:control-state-inert-json-required')
  const descriptor = Object.getOwnPropertyDescriptor(object, key)
  requireMemory(descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable, 'memory:control-state-inert-json-required')
  return descriptor.value
}

// Reject accessor-bearing objects before reading any field. A bundle is inert JSON, not executable input.
function inertCopy(value) {
  const seen = new WeakSet()
  let textSize = 0
  function copy(node, depth) {
    requireMemory(depth <= 64, 'memory:control-state-depth')
    if (typeof node === 'string') {
      textSize += Buffer.byteLength(node)
      requireMemory(textSize <= MAX_BYTES, 'memory:control-state-bytes-limit')
      return node
    }
    if (node === null || typeof node === 'boolean') return node
    if (typeof node === 'number') {
      requireMemory(Number.isFinite(node) && (!Number.isInteger(node) || Number.isSafeInteger(node)), 'memory:control-state-number-invalid')
      return node
    }
    requireMemory(node && typeof node === 'object' && !types.isProxy(node) && !seen.has(node), 'memory:control-state-inert-json-required')
    seen.add(node)
    const array = Array.isArray(node), proto = Object.getPrototypeOf(node)
    requireMemory(proto === (array ? Array.prototype : Object.prototype) || (!array && proto === null),
      'memory:control-state-inert-json-required')
    const descriptors = Object.getOwnPropertyDescriptors(node), result = array ? [] : Object.create(null)
    requireMemory(Reflect.ownKeys(descriptors).every(key => typeof key === 'string'), 'memory:control-state-inert-json-required')
    if (array) requireMemory(node.length <= 10000, 'memory:control-state-row-limit')
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (array && key === 'length') continue
      requireMemory(Object.hasOwn(descriptor, 'value') && descriptor.enumerable
        && (!array || /^(?:0|[1-9][0-9]*)$/.test(key)), 'memory:control-state-inert-json-required')
      textSize += Buffer.byteLength(key)
      requireMemory(textSize <= MAX_BYTES, 'memory:control-state-bytes-limit')
      Object.defineProperty(result, key, {value: copy(descriptor.value, depth + 1), enumerable: true, writable: true, configurable: true})
    }
    if (array) requireMemory(result.length === node.length && Object.keys(result).length === node.length,
      'memory:control-state-inert-json-required')
    seen.delete(node)
    return result
  }
  const copied = copy(value, 0), bytes = Buffer.from(canonicalJSON(copied))
  requireMemory(bytes.length <= MAX_BYTES, 'memory:control-state-bytes-limit')
  return parseOriginal(bytes)
}

function binding(host) {
  requireMemory(host && typeof host === 'object' && !types.isProxy(host), 'memory:control-state-owner-required')
  const descriptors = Object.getOwnPropertyDescriptors(host)
  requireMemory(['owner_subject', 'owner_id'].every(key => descriptors[key] && Object.hasOwn(descriptors[key], 'value')),
    'memory:control-state-owner-required')
  const checked = inertCopy({owner_subject: descriptors.owner_subject.value, owner_id: descriptors.owner_id.value})
  requireMemory(nonempty(checked.owner_subject) && nonempty(checked.owner_id), 'memory:control-state-owner-required')
  return checked
}
function validateHeads(heads) {
  requireMemory(heads && typeof heads === 'object' && !Array.isArray(heads)
    && Object.entries(heads).every(([domain, head]) => CHAIN_DOMAINS.includes(domain)
      && typeof head === 'string' && (head === AURA_RECORD_DOMAIN || HEX.test(head))), 'memory:control-state-head-invalid')
}
function hashList(values, check, code) {
  requireMemory(Array.isArray(values) && values.every(check) && new Set(values).size === values.length, code)
}

function validateIntent(row, host, contracts) {
  requireMemory(nonempty(row.operation_id) && typeof row.operation_digest === 'string' && DIGEST.test(row.operation_digest)
    && typeof row.request_id === 'string' && UUID.test(row.request_id)
    && typeof row.request_digest === 'string' && DIGEST.test(row.request_digest), 'memory:control-state-intent-invalid')
  requireMemory(typeof contracts?.validateContract === 'function' && typeof contracts?.operationDigest === 'function',
    'memory:control-state-contracts-unavailable')
  const operation = parseOriginal(row.operation_bytes), grant = parseOriginal(row.grant_bytes), request = parseOriginal(row.request_bytes)
  try { contracts.validateContract('OperationProposal', operation); contracts.validateContract('ConsumedGrant', grant) }
  catch { requireMemory(false, 'memory:control-state-contract-invalid') }
  requireMemory(operation.operation_id === row.operation_id && contracts.operationDigest(operation) === row.operation_digest
    && operation.owner_id === host.owner_id && nonempty(operation.task_id) && ACTIONS.includes(operation.action_type)
    && operation.audience === MEMORY_AUDIENCE && same(operation.target_identity, memoryTarget(host.owner_subject)),
  'memory:control-state-operation-binding')
  requireMemory(nonempty(grant.grant_id) && grant.operation_id === row.operation_id && grant.operation_digest === row.operation_digest
    && grant.owner_id === host.owner_id && grant.audience === operation.audience
    && grant.authorization_epoch === operation.authorization_epoch, 'memory:control-state-grant-binding')
  exact(request, ['version', 'action_type', 'owner_subject', 'operation_id', 'operation_digest', 'parameters'],
    'memory:control-state-request-fields')
  requireMemory(request.version === 1 && request.action_type === operation.action_type && request.owner_subject === host.owner_subject
    && request.operation_id === row.operation_id && request.operation_digest === row.operation_digest
    && same(request.parameters, operation.canonical_parameters) && memoryEffectDigest(request) === row.request_digest,
  'memory:control-state-request-binding')
  return {operation, grant}
}

function validateWriterClosure(row, host) {
  requireMemory(row.owner_id === host.owner_id && nonempty(row.task_id) && nonempty(row.operation_id)
    && typeof row.operation_digest === 'string' && DIGEST.test(row.operation_digest)
    && ['memory.save', 'memory.forget'].includes(row.action_type)
    && Number.isSafeInteger(row.authorization_epoch) && row.authorization_epoch >= 0
    && typeof row.closure_digest === 'string' && DIGEST.test(row.closure_digest), 'memory:control-state-writer-closure-invalid')
  // The cold workflow retains this exact six-field reference, not original proposal bytes.
  // Its opaque operation digest joins C's authoritative never-consumed observation;
  // this private control-state parser cannot manufacture that authority or a proposal.
  const reference = parseOriginal(row.reference_bytes), closure = parseOriginal(row.closure_bytes)
  const referenceFields = ['owner_id', 'owner_subject', 'task_id', 'operation_id', 'operation_digest', 'action_type']
  exact(reference, referenceFields, 'memory:control-state-writer-closure-reference-fields')
  requireMemory(referenceFields.every(key => typeof reference[key] === 'string' && reference[key] === row[key])
    && row.reference_bytes.equals(Buffer.from(canonicalJSON(reference))), 'memory:control-state-writer-closure-reference-binding')
  const bindingFields = ['owner_id', 'task_id', 'operation_id', 'action_type', 'authorization_epoch']
  exact(closure, ['version', 'kind', 'owner_id', 'owner_subject', 'task_id', 'operation_id', 'operation_digest',
    'action_type', 'authorization_epoch', 'closure_id', 'writer_closed', 'intent_absent', 'effect_absent', 'grants_authority'],
  'memory:control-state-writer-closure-fields')
  requireMemory(closure.version === 1 && closure.kind === 'prime-memory-writer-closure/v1'
    && [...bindingFields, 'owner_subject', 'operation_digest'].every(key => closure[key] === row[key])
    && typeof closure.closure_id === 'string' && UUID.test(closure.closure_id)
    && closure.writer_closed === true && closure.intent_absent === true && closure.effect_absent === true
    && closure.grants_authority === false, 'memory:control-state-writer-closure-binding')
  requireMemory(row.closure_bytes.equals(Buffer.from(canonicalJSON(closure)))
    && row.closure_digest === 'sha256:' + sha256(Buffer.from('aukora-prime.memory-writer-closure.v1\0'
    + canonicalJSON(closure))), 'memory:control-state-writer-closure-digest')
  return closure
}

/** Encode native durable rows without rewriting any stored JSON bytes. No authority is created. */
export function makeMemoryControlState(host, state, {contracts} = {}) {
  const checkedHost = binding(host)
  const heads = ownData(state, 'heads'), tables = ownData(state, 'tables')
  requireMemory(tables && typeof tables === 'object' && !Array.isArray(tables) && !types.isProxy(tables),
    'memory:control-state-inert-json-required')
  const suppliedClosures = Object.hasOwn(tables, 'unsent_closures') ? ownData(tables, 'unsent_closures') : []
  requireMemory(Array.isArray(suppliedClosures) && !types.isProxy(suppliedClosures), 'memory:control-state-row-limit')
  exact(tables, Object.hasOwn(tables, 'unsent_closures') ? TABLE_NAMES_V2 : TABLE_NAMES, 'memory:control-state-tables-invalid')
  const tableNames = suppliedClosures.length ? TABLE_NAMES_V2 : TABLE_NAMES
  const encoded = {}
  for (const table of tableNames) {
    const source = ownData(tables, table)
    requireMemory(Array.isArray(source) && !types.isProxy(source) && source.length <= 10000, 'memory:control-state-row-limit')
    const {columns, byteColumns} = TABLES_V2[table]
    encoded[table] = Array.from({length: source.length}, (_, index) => {
      const row = ownData(source, String(index))
      requireMemory(!types.isProxy(row), 'memory:control-state-inert-json-required')
      exact(row, columns, 'memory:control-state-row-fields')
      const descriptors = Object.getOwnPropertyDescriptors(row)
      requireMemory(columns.every(key => Object.hasOwn(descriptors[key], 'value')), 'memory:control-state-inert-json-required')
      return Object.fromEntries(columns.map(key => {
        const value = descriptors[key].value
        if (!byteColumns.includes(key)) return [key, value]
        requireMemory(value && typeof value === 'object' && !types.isProxy(value)
          && (Object.getPrototypeOf(value) === Buffer.prototype || Object.getPrototypeOf(value) === Uint8Array.prototype),
        'memory:control-state-bytes-invalid')
        const bytes = Buffer.from(value)
        return [key, {bytes_base64: bytes.toString('base64'), sha256: sha256(bytes)}]
      }))
    }).sort((a, b) => compare(keyOf(a, table), keyOf(b, table)))
  }
  const body = {schema: suppliedClosures.length ? MEMORY_CONTROL_SCHEMA_V2 : MEMORY_CONTROL_SCHEMA,
    owner_subject: checkedHost.owner_subject, owner_id: checkedHost.owner_id,
    heads, tables: encoded}
  // Inspect the same portable representation that the independent retention provider will return.
  const inert = inertCopy(body), bundle = {...inert, control_sha256: commitment(inert)}
  inspectMemoryControlState(bundle, checkedHost, {contracts})
  return bundle
}

/** Digest integrity is self-consistency only. The caller must obtain this from independent retained control state. */
export function inspectMemoryControlState(bundle, host, {contracts} = {}) {
  const checked = inertCopy(bundle), checkedHost = binding(host)
  exact(checked, ['schema', 'owner_subject', 'owner_id', 'heads', 'tables', 'control_sha256'], 'memory:control-state-fields-invalid')
  requireMemory([MEMORY_CONTROL_SCHEMA, MEMORY_CONTROL_SCHEMA_V2].includes(checked.schema)
    && checked.owner_subject === checkedHost.owner_subject
    && checked.owner_id === checkedHost.owner_id, 'memory:control-state-owner-schema')
  validateHeads(checked.heads)
  const {control_sha256: digest, ...body} = checked
  requireMemory(typeof digest === 'string' && HEX.test(digest) && commitment(body) === digest, 'memory:control-state-changed')
  const tableNames = checked.schema === MEMORY_CONTROL_SCHEMA_V2 ? TABLE_NAMES_V2 : TABLE_NAMES
  exact(checked.tables, tableNames, 'memory:control-state-tables-invalid')
  if (checked.schema === MEMORY_CONTROL_SCHEMA_V2)
    requireMemory(Array.isArray(checked.tables.unsent_closures) && checked.tables.unsent_closures.length > 0,
      'memory:control-state-writer-closure-required')
  const tables = {}
  let total = 0, count = 0
  for (const table of tableNames) {
    const source = checked.tables[table], {columns, byteColumns} = TABLES_V2[table], keys = new Set()
    requireMemory(Array.isArray(source) && (count += source.length) <= 10000, 'memory:control-state-row-limit')
    tables[table] = source.map(row => {
      exact(row, columns, 'memory:control-state-row-fields')
      requireMemory(row.owner_subject === checkedHost.owner_subject, 'memory:control-state-row-owner')
      const key = keyOf(row, table)
      requireMemory(!keys.has(key), 'memory:control-state-row-duplicate'); keys.add(key)
      const decoded = {...row}
      for (const column of byteColumns) {
        const envelope = row[column]
        exact(envelope, ['bytes_base64', 'sha256'], 'memory:control-state-bytes-fields')
        requireMemory(typeof envelope.bytes_base64 === 'string' && typeof envelope.sha256 === 'string' && HEX.test(envelope.sha256),
          'memory:control-state-bytes-invalid')
        const bytes = Buffer.from(envelope.bytes_base64, 'base64'); total += bytes.length
        requireMemory(total <= MAX_BYTES && bytes.toString('base64') === envelope.bytes_base64
          && sha256(bytes) === envelope.sha256, 'memory:control-state-bytes-changed')
        parseOriginal(bytes)
        decoded[column] = bytes
      }
      return decoded
    })
  }
  const tombstones = new Set()
  for (const row of tables.tombstones) {
    // v1 snapshots historically admitted a wrapper. Keep its original bytes and hash unchanged.
    const original = parseOriginal(row.bytes), value = original.tombstone ?? original
    exact(value, ['kind', 'recordId', 'at'], 'memory:control-state-tombstone-invalid')
    requireMemory(recordId(row.record_id) && value.kind === 'tombstone' && value.recordId === row.record_id && instant(value.at)
      && sha256(row.bytes) === row.sha256, 'memory:control-state-tombstone-invalid')
    tombstones.add(row.record_id)
  }
  for (const row of tables.purges) {
    const value = parseOriginal(row.bytes)
    exact(value, ['kind', 'record_ids', 'source_digests', 'at'], 'memory:control-state-purge-invalid')
    requireMemory(nonempty(row.operation_id) && ['prime-active-record-purge/v1', 'prime-active-owner-purge/v1'].includes(value.kind)
      && instant(value.at), 'memory:control-state-purge-invalid')
    hashList(value.record_ids, recordId, 'memory:control-state-purge-invalid')
    hashList(value.source_digests, hash => typeof hash === 'string' && HEX.test(hash), 'memory:control-state-purge-invalid')
    requireMemory(value.record_ids.every(id => tombstones.has(id)) && (value.kind !== 'prime-active-record-purge/v1'
      || value.record_ids.length === 1), 'memory:control-state-purge-tombstone-missing')
  }
  for (const row of tables.requests) requireMemory(nonempty(row.idempotency_key) && row.idempotency_key.length <= 1024
    && typeof row.request_digest === 'string' && HEX.test(row.request_digest) && recordId(row.record_id)
    && Number.isSafeInteger(row.revision) && row.revision > 0, 'memory:control-state-idempotency-invalid')
  for (const row of tables.controls) {
    const value = parseOriginal(row.bytes)
    requireMemory(nonempty(row.scope) && Object.keys(value).every(key => ['controls', 'paused', 'offTheRecord', 'grantsAuthority'].includes(key))
      && (value.grantsAuthority === undefined || value.grantsAuthority === false)
      && ['paused', 'offTheRecord'].every(key => value[key] === undefined || typeof value[key] === 'boolean'),
    'memory:control-state-control-invalid')
    if (value.controls !== undefined) requireMemory(value.controls && typeof value.controls === 'object' && !Array.isArray(value.controls)
      && Object.entries(value.controls).every(([key, active]) => ['pause', 'off-the-record', 'someone-is-here', 'hide'].includes(key)
        && typeof active === 'boolean'), 'memory:control-state-control-invalid')
  }
  for (const row of tables.redactions) {
    const value = parseOriginal(row.bytes)
    exact(value, ['kind', 'record_id', 'revision', 'canonical_sha256', 'chain_domain', 'chain_sequence', 'source_digests'],
      'memory:control-state-redaction-invalid')
    requireMemory(recordId(row.record_id) && Number.isSafeInteger(row.revision) && row.revision > 0
      && value.kind === 'redacted-record/v1' && value.record_id === row.record_id && value.revision === row.revision
      && typeof value.canonical_sha256 === 'string' && HEX.test(value.canonical_sha256)
      && CHAIN_DOMAINS.includes(value.chain_domain) && Object.hasOwn(checked.heads, value.chain_domain)
      && Number.isSafeInteger(value.chain_sequence) && value.chain_sequence > 0 && tombstones.has(row.record_id),
    'memory:control-state-redaction-invalid')
    hashList(value.source_digests, hash => typeof hash === 'string' && HEX.test(hash), 'memory:control-state-redaction-invalid')
  }
  const intents = new Map(), requestIds = new Map(), grantIds = new Map()
  for (const row of tables.intents) {
    const validated = validateIntent(row, checkedHost, contracts)
    requireMemory(!requestIds.has(row.request_id) && !grantIds.has(validated.grant.grant_id), 'memory:control-state-replay-binding-conflict')
    intents.set(row.operation_id, {row, ...validated}); requestIds.set(row.request_id, row.operation_id); grantIds.set(validated.grant.grant_id, row.operation_id)
  }
  for (const row of tables.effects) {
    const intent = intents.get(row.operation_id)
    requireMemory(intent && ['owner_subject', 'operation_id', 'operation_digest', 'request_id', 'request_digest'].every(key => row[key] === intent.row[key])
      && ['grant_bytes', 'operation_bytes', 'request_bytes'].every(key => row[key].equals(intent.row[key])), 'memory:control-state-effect-intent-conflict')
    requireMemory(row.grant_id === intent.grant.grant_id && row.action === intent.operation.action_type, 'memory:control-state-effect-binding')
    const result = parseOriginal(row.result_bytes), receipt = parseOriginal(row.receipt_bytes)
    exact(receipt, ['version', 'kind', 'operation_id', 'operation_digest', 'grant_id', 'request_id', 'request_digest', 'owner_subject',
      'action_type', 'status', 'result_digest', 'result'], 'memory:control-state-receipt-fields')
    requireMemory(receipt.version === 1 && receipt.kind === 'prime-memory-effect/v1' && receipt.status === 'applied'
      && ['owner_subject', 'operation_id', 'operation_digest', 'grant_id', 'request_id', 'request_digest'].every(key => receipt[key] === row[key])
      && receipt.action_type === row.action && receipt.result_digest === memoryResultDigest(result) && same(receipt.result, result)
      && (result.owner_subject === undefined || result.owner_subject === checkedHost.owner_subject)
      && (result.task_id === undefined || result.task_id === intent.operation.task_id), 'memory:control-state-receipt-binding')
  }
  for (const row of tables.replay_fences) {
    requireMemory(nonempty(row.operation_id) && typeof row.operation_digest === 'string' && DIGEST.test(row.operation_digest)
      && nonempty(row.grant_id) && ACTIONS.includes(row.action) && typeof row.request_id === 'string' && UUID.test(row.request_id)
      && typeof row.request_digest === 'string' && DIGEST.test(row.request_digest) && row.status === 'payload-purged',
    'memory:control-state-replay-fence-invalid')
    requireMemory(!intents.has(row.operation_id) && !requestIds.has(row.request_id) && !grantIds.has(row.grant_id),
      'memory:control-state-replay-binding-conflict')
    requestIds.set(row.request_id, row.operation_id); grantIds.set(row.grant_id, row.operation_id)
  }
  tables.unsent_closures ??= []
  const effectOperations = new Set(['intents', 'effects', 'replay_fences'].flatMap(table =>
    tables[table].map(row => row.operation_id)))
  for (const row of tables.unsent_closures) {
    validateWriterClosure(row, checkedHost)
    requireMemory(!effectOperations.has(row.operation_id), 'memory:control-state-writer-closure-effect-conflict')
  }
  return {digest, heads: checked.heads, tables}
}
