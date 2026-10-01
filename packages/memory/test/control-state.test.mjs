// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { sha256 } from '../src/codecs.mjs'
import { MEMORY_AUDIENCE, memoryEffectDigest, memoryResultDigest, memoryTarget } from '../src/authorization.mjs'
import { MEMORY_CONTROL_SCHEMA, MEMORY_CONTROL_TABLES, makeMemoryControlState, inspectMemoryControlState } from '../src/control-state.mjs'

// Inert synthetic serialization checks only. There is no authority implementation, dispatch, I/O or database.
const host = {owner_subject: 'synthetic-control-subject', owner_id: 'synthetic-control-owner-id'}
const at = '2026-10-01T11:03:00Z', id = 'rem:' + 'a'.repeat(64), heads = {remembered: 'b'.repeat(64)}
const encode = value => Buffer.from(canonicalJSON(value))
const digestOperation = operation => 'sha256:' + sha256(Buffer.from('aukora-prime.operation.v1\0' + canonicalJSON(operation)))
// This injected fixture parser checks syntactic records only; it never establishes grant legitimacy.
const fixtureContracts = {
  validateContract(kind, value) {
    assert.ok(['OperationProposal', 'ConsumedGrant'].includes(kind)); assert.equal(value.version, 1)
    return value
  }, operationDigest: digestOperation,
}
const emptyTables = () => Object.fromEntries(Object.keys(MEMORY_CONTROL_TABLES).map(name => [name, []]))
const make = (tables = emptyTables(), override = {}) => makeMemoryControlState(host, {heads, tables, ...override}, {contracts: fixtureContracts})
const inspect = bundle => inspectMemoryControlState(bundle, host, {contracts: fixtureContracts})
function recommit(bundle) {
  const {control_sha256: ignored, ...body} = bundle
  return {...body, control_sha256: sha256(Buffer.from('aukora-prime.memory-control-state.v1\0' + canonicalJSON(body)))}
}
function rewriteBytes(bundle, table, column, update) {
  const value = JSON.parse(Buffer.from(bundle.tables[table][0][column].bytes_base64, 'base64'))
  update(value)
  const bytes = encode(value)
  bundle.tables[table][0][column] = {bytes_base64: bytes.toString('base64'), sha256: sha256(bytes)}
  return recommit(bundle)
}
function durableFixture() {
  const tables = emptyTables()
  tables.tombstones.push({owner_subject: host.owner_subject, record_id: id,
    bytes: Buffer.from(JSON.stringify({kind: 'tombstone', recordId: id, at}, null, 2) + '\n'), sha256: ''})
  tables.tombstones[0].sha256 = sha256(tables.tombstones[0].bytes)
  tables.purges.push({owner_subject: host.owner_subject, operation_id: 'synthetic-purge',
    bytes: encode({kind: 'prime-active-record-purge/v1', record_ids: [id], source_digests: ['c'.repeat(64)], at})})
  tables.requests.push({owner_subject: host.owner_subject, idempotency_key: 'synthetic-retained-capture-key',
    request_digest: 'd'.repeat(64), record_id: id, revision: 1})
  tables.controls.push({owner_subject: host.owner_subject, scope: 'owner', bytes: encode({paused: true, grantsAuthority: false})})
  tables.redactions.push({owner_subject: host.owner_subject, record_id: id, revision: 1,
    bytes: encode({kind: 'redacted-record/v1', record_id: id, revision: 1, canonical_sha256: 'e'.repeat(64),
      chain_domain: 'remembered', chain_sequence: 1, source_digests: ['c'.repeat(64)]})})
  return tables
}
function effectFixture({completed = true} = {}) {
  const tables = emptyTables()
  const operation = {version: 1, operation_id: 'synthetic-operation', owner_id: host.owner_id, task_id: 'historical-task',
    action_type: 'memory.forget', audience: MEMORY_AUDIENCE, authorization_epoch: 2,
    target_identity: memoryTarget(host.owner_subject), canonical_parameters: {record_id: id, at}}
  const operation_digest = digestOperation(operation)
  const grant = {version: 1, grant_id: 'synthetic-grant', operation_id: operation.operation_id, operation_digest,
    owner_id: host.owner_id, audience: MEMORY_AUDIENCE, authorization_epoch: 2}
  const request = {version: 1, action_type: operation.action_type, owner_subject: host.owner_subject,
    operation_id: operation.operation_id, operation_digest, parameters: operation.canonical_parameters}
  const request_id = '00000000-0000-4000-8000-000000000001', request_digest = memoryEffectDigest(request)
  const intent = {owner_subject: host.owner_subject, operation_id: operation.operation_id, operation_digest,
    grant_bytes: encode(grant), operation_bytes: Buffer.from(JSON.stringify(operation, null, 2) + '\n'),
    request_id, request_digest, request_bytes: encode(request)}
  tables.intents.push(intent)
  if (completed) {
    const result = {record_id: id, state: 'tombstoned', grants_authority: false}
    const receipt = {version: 1, kind: 'prime-memory-effect/v1', operation_id: operation.operation_id, operation_digest,
      grant_id: grant.grant_id, request_id, request_digest, owner_subject: host.owner_subject, action_type: operation.action_type,
      status: 'applied', result_digest: memoryResultDigest(result), result}
    tables.effects.push({...intent, action: operation.action_type, grant_id: grant.grant_id,
      result_bytes: encode(result), receipt_bytes: encode(receipt)})
  }
  return tables
}

test('versioned complete empty control state is explicit; heads-only and snapshot objects refuse', () => {
  const bundle = make(emptyTables(), {heads: {}})
  assert.equal(bundle.schema, MEMORY_CONTROL_SCHEMA); assert.deepEqual(inspect(bundle).heads, {})
  for (const value of [{owner_subject: host.owner_subject, heads}, {schema: 'aukora-prime-memory-snapshot/v2', owner_subject: host.owner_subject, heads}])
    assert.throws(() => inspect(value), {code: 'memory:control-state-fields-invalid'})
  const incomplete = {...bundle.tables}; delete incomplete.replay_fences
  assert.throws(() => make(incomplete), {code: 'memory:control-state-tables-invalid'})
})

test('control anchor preserves exact original bytes and retained requests for purged records', () => {
  const tables = durableFixture(), bundle = make(tables), checked = inspect(bundle)
  assert.equal(bundle.owner_id, host.owner_id); assert.notEqual(bundle.owner_id, bundle.owner_subject)
  assert.ok(checked.tables.tombstones[0].bytes.equals(tables.tombstones[0].bytes))
  assert.equal(checked.tables.requests[0].record_id, id)
  assert.equal(checked.tables.purges[0].operation_id, 'synthetic-purge')
  assert.equal(checked.tables.controls[0].scope, 'owner')
  assert.deepEqual(checked.heads, heads)
  const wrapped = durableFixture()
  wrapped.tombstones[0].bytes = Buffer.from(JSON.stringify({tombstone: {kind: 'tombstone', recordId: id, at},
    grantsAuthority: false, historical_format: 'synthetic-wrapper'}, null, 2) + '\n')
  wrapped.tombstones[0].sha256 = sha256(wrapped.tombstones[0].bytes)
  assert.ok(inspect(make(wrapped)).tables.tombstones[0].bytes.equals(wrapped.tombstones[0].bytes))
})

test('maker deterministically orders table primary keys without normalizing stored bytes', () => {
  const tables = durableFixture(), other = {...tables.requests[0], idempotency_key: 'aaa'}
  tables.requests.push(other)
  const ordered = make(tables)
  tables.requests.reverse()
  assert.deepEqual(make(tables), ordered)
  assert.notEqual(make({...tables, controls: []}).control_sha256, ordered.control_sha256)
})

test('owner subject, owner identity, row binding and bundle digests fail closed independently', () => {
  const bundle = make(durableFixture())
  assert.throws(() => inspectMemoryControlState(bundle, {...host, owner_id: 'wrong-owner'}), {code: 'memory:control-state-owner-schema'})
  assert.throws(() => inspectMemoryControlState(bundle, {...host, owner_subject: 'wrong-subject'}), {code: 'memory:control-state-owner-schema'})
  const changed = structuredClone(bundle); changed.tables.requests[0].owner_subject = 'wrong-subject'
  assert.throws(() => inspect(changed), {code: 'memory:control-state-changed'})
  assert.throws(() => inspect(recommit(changed)), {code: 'memory:control-state-row-owner'})
})

test('byte digests, canonical base64 and duplicate primary keys are checked even under a recomputed bundle digest', () => {
  const bundle = make(durableFixture())
  const changed = structuredClone(bundle); changed.tables.purges[0].bytes.sha256 = '0'.repeat(64)
  assert.throws(() => inspect(recommit(changed)), {code: 'memory:control-state-bytes-changed'})
  const noncanonical = structuredClone(bundle); noncanonical.tables.purges[0].bytes.bytes_base64 += '\n'
  assert.throws(() => inspect(recommit(noncanonical)), {code: 'memory:control-state-bytes-changed'})
  const duplicate = structuredClone(bundle); duplicate.tables.requests.push(duplicate.tables.requests[0])
  assert.throws(() => inspect(recommit(duplicate)), {code: 'memory:control-state-row-duplicate'})
})

test('purge, redaction, tombstone and control vocabularies are closed and referentially bound', () => {
  const bundle = make(durableFixture())
  assert.throws(() => inspect(rewriteBytes(structuredClone(bundle), 'purges', 'bytes', value => {value.kind = 'automatic-delete'})),
    {code: 'memory:control-state-purge-invalid'})
  assert.throws(() => inspect(rewriteBytes(structuredClone(bundle), 'purges', 'bytes', value => {value.at = '2026-02-30T11:03:00Z'})),
    {code: 'memory:control-state-purge-invalid'})
  assert.throws(() => inspect(rewriteBytes(structuredClone(bundle), 'controls', 'bytes', value => {value.grantsAuthority = true})),
    {code: 'memory:control-state-control-invalid'})
  assert.throws(() => inspect(rewriteBytes(structuredClone(bundle), 'redactions', 'bytes', value => {value.record_id = 'rem:' + 'f'.repeat(64)})),
    {code: 'memory:control-state-redaction-invalid'})
  const absent = structuredClone(bundle); absent.tables.tombstones = []
  assert.throws(() => inspect(recommit(absent)), {code: 'memory:control-state-purge-tombstone-missing'})
})

test('unresolved intents and completed effects preserve exact request, operation and grant bytes', () => {
  for (const completed of [false, true]) {
    const tables = effectFixture({completed}), bundle = make(tables), checked = inspect(bundle)
    assert.equal(checked.tables.intents.length, 1); assert.equal(checked.tables.effects.length, completed ? 1 : 0)
    for (const column of ['operation_bytes', 'grant_bytes', 'request_bytes'])
      assert.ok(checked.tables.intents[0][column].equals(tables.intents[0][column]))
  }
  assert.throws(() => inspectMemoryControlState(make(effectFixture()), host), {code: 'memory:control-state-contracts-unavailable'})
})

test('historical operation owner binding survives a recomputed operation and outer digest', () => {
  const tables = effectFixture({completed: false})
  const operation = JSON.parse(tables.intents[0].operation_bytes); operation.owner_id = 'wrong-owner'
  const operation_digest = digestOperation(operation)
  tables.intents[0].operation_bytes = encode(operation); tables.intents[0].operation_digest = operation_digest
  assert.throws(() => make(tables), {code: 'memory:control-state-operation-binding'})
})

test('request parameters and grant identity must join the durable operation', () => {
  const bundle = make(effectFixture({completed: false}))
  assert.throws(() => inspect(rewriteBytes(structuredClone(bundle), 'intents', 'grant_bytes', value => {value.owner_id = 'wrong-owner'})),
    {code: 'memory:control-state-grant-binding'})
  assert.throws(() => inspect(rewriteBytes(structuredClone(bundle), 'intents', 'request_bytes', value => {value.parameters.at = '2026-10-02T11:03:00Z'})),
    {code: 'memory:control-state-request-binding'})
  for (const field of ['operation_digest', 'request_id', 'request_digest']) {
    const coerced = structuredClone(bundle); coerced.tables.intents[0][field] = [coerced.tables.intents[0][field]]
    assert.throws(() => inspect(recommit(coerced)), {code: 'memory:control-state-intent-invalid'})
  }
})

test('effects require exact intent bytes and a closed matching result receipt', () => {
  const bundle = make(effectFixture())
  const noIntent = structuredClone(bundle); noIntent.tables.intents = []
  assert.throws(() => inspect(recommit(noIntent)), {code: 'memory:control-state-effect-intent-conflict'})
  assert.throws(() => inspect(rewriteBytes(structuredClone(bundle), 'effects', 'operation_bytes', value => {value.task_id = 'other-task'})),
    {code: 'memory:control-state-effect-intent-conflict'})
  assert.throws(() => inspect(rewriteBytes(structuredClone(bundle), 'effects', 'receipt_bytes', value => {value.result_digest = 'sha256:' + 'f'.repeat(64)})),
    {code: 'memory:control-state-receipt-binding'})
})

test('content-free fences remain portable while blocking collisions with retained intents or grants', () => {
  const tables = effectFixture({completed: false}), intent = tables.intents[0], grant = JSON.parse(intent.grant_bytes)
  const fence = {owner_subject: host.owner_subject, operation_id: intent.operation_id, operation_digest: intent.operation_digest,
    grant_id: grant.grant_id, action: 'memory.forget', request_id: intent.request_id, request_digest: intent.request_digest, status: 'payload-purged'}
  const fenced = emptyTables(); fenced.replay_fences.push(fence)
  assert.deepEqual(inspect(make(fenced)).tables.replay_fences, [fence])
  for (const field of ['operation_digest', 'request_id', 'request_digest']) {
    const invalid = emptyTables(); invalid.replay_fences.push({...fence, [field]: [fence[field]]})
    assert.throws(() => make(invalid), {code: 'memory:control-state-replay-fence-invalid'})
  }
  tables.replay_fences.push(fence)
  assert.throws(() => make(tables), {code: 'memory:control-state-replay-binding-conflict'})
  const invalid = emptyTables(); invalid.replay_fences.push({...fence, payload: 'forbidden'})
  assert.throws(() => make(invalid), {code: 'memory:control-state-row-fields'})
})

test('untrusted accessors, proxies, extra fields and cycles refuse without running getters', () => {
  const bundle = make(), accessor = structuredClone(bundle)
  let reads = 0
  Object.defineProperty(accessor, 'tables', {enumerable: true, get() {reads++; return bundle.tables}})
  assert.throws(() => inspect(accessor), {code: 'memory:control-state-inert-json-required'}); assert.equal(reads, 0)
  assert.throws(() => inspect(new Proxy(bundle, {get() {reads++; throw new Error('must not run')}})),
    {code: 'memory:control-state-inert-json-required'}); assert.equal(reads, 0)
  assert.throws(() => inspect({...bundle, silent_extension: true}), {code: 'memory:control-state-fields-invalid'})
  const state = {heads, tables: emptyTables()}
  Object.defineProperty(state, 'tables', {enumerable: true, get() {reads++; return bundle.tables}})
  assert.throws(() => makeMemoryControlState(host, state), {code: 'memory:control-state-inert-json-required'}); assert.equal(reads, 0)
  const cycle = {...bundle}; cycle.tables = cycle
  assert.throws(() => inspect(cycle), {code: 'memory:control-state-inert-json-required'})
})
