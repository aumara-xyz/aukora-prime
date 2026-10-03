// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MemoryRefusal, sha256 } from '../src/codecs.mjs'
import { PRIVATE_CONTROL_TABLES, createControlV3, controlV3Digest,
  logicalMetadataDigest } from '../src/private-v2-control.mjs'
import { PRIVATE_V2_RETENTION_SCHEMA, makePrivateV2GenesisEnvelope,
  assertPrivateV2BootstrapCleanupContent,
  createPrivateV2NewLineageBootstrapPublisher,
  isPrivateV2NewLineageBootstrapPublisher } from '../src/private-v2-retention.mjs'

// Dedicated synthetic parser/source fixtures, not C integration. Only projections
// without operation or grant rows use these inert test-local contracts. These tests
// never invoke bootstrap, create a directory, use PostgreSQL, mock storage or
// process identity, or change security/runtime configuration.
const contracts = Object.freeze({canonicalJson: canonicalJSON,
  validateContract() { throw new Error('source-only fixture cannot validate contracts') },
  operationDigest() { throw new Error('source-only fixture cannot digest operations') }})

const host = Object.freeze({owner_id: 'source-bootstrap-owner', owner_subject: 'source-bootstrap-subject',
  task_id: 'source-bootstrap-task', authorization_epoch: 3})
const profile = Object.freeze({version: 2, kind: 'prime-private-unsent-closure/v2',
  expected_authority_store_id: 'a'.repeat(64), expected_memory_store_id: 'b'.repeat(64),
  retention_profile: 'required-retained/v2'})
const metadata = Object.freeze({version: 1, kind: 'prime-memory-logical-store/v1',
  store_id: profile.expected_memory_store_id})
const emptyTables = () => Object.fromEntries(Object.keys(PRIVATE_CONTROL_TABLES).map(name => [name, []]))
const makeControl = ({owner = host, pair = profile, heads = {}, tables = emptyTables(), store = metadata} = {}) =>
  createControlV3(owner, {heads, tables,
    logical_store: {metadata: store, metadata_digest: logicalMetadataDigest(store)}}, {contracts, profile: pair})
const makeGenesis = (control = makeControl(), owner = host, pair = profile) =>
  makePrivateV2GenesisEnvelope(owner, control, {contracts, profile: pair})
const clone = value => structuredClone(value)
const recommit = value => ({...value, control_sha256: controlV3Digest(value)})
const refusal = (action, code) => assert.throws(action, error => error instanceof MemoryRefusal
  && (code === undefined || error.code === code))

test('new-lineage bootstrap source: an empty full v3 projection yields the existing exact genesis envelope', () => {
  const control = makeControl(), before = clone(control), envelope = makeGenesis(control)
  assert.deepEqual(Object.keys(envelope).sort(), ['schema', 'owner_id', 'owner_subject', 'authorization_epoch',
    'sequence', 'previous_checkpoint_sha256', 'control_state', 'checkpoint_sha256'].sort())
  assert.equal(envelope.schema, PRIVATE_V2_RETENTION_SCHEMA)
  assert.equal(envelope.owner_id, host.owner_id)
  assert.equal(envelope.owner_subject, host.owner_subject)
  assert.equal(envelope.authorization_epoch, host.authorization_epoch)
  assert.equal(envelope.sequence, 1)
  assert.equal(envelope.previous_checkpoint_sha256, null)
  assert.deepEqual(envelope.control_state, control)
  assert.deepEqual(envelope.control_state.logical_store, {metadata, metadata_digest: logicalMetadataDigest(metadata)})
  assert.deepEqual(envelope.control_state.closure_profile, profile)
  assert.deepEqual(Object.keys(envelope.control_state.tables).sort(), Object.keys(PRIVATE_CONTROL_TABLES).sort())
  assert.ok(Object.values(envelope.control_state.tables).every(rows => rows.length === 0))
  assert.deepEqual(envelope.control_state.heads, {})
  const {checkpoint_sha256, ...body} = envelope
  assert.match(checkpoint_sha256, /^[0-9a-f]{64}$/)
  assert.equal(checkpoint_sha256, sha256(Buffer.from('aukora-prime.memory-retention.v2\0' + canonicalJSON(body))))
  assert.deepEqual(makeGenesis(control), envelope)
  assert.deepEqual(control, before)
  assert.notEqual(envelope.control_state, control)
  assert.notEqual(envelope.control_state.tables, control.tables)
})

test('new-lineage bootstrap source: host owner and exact profile bind the donor control', () => {
  const control = makeControl()
  for (const key of ['owner_id', 'owner_subject']) {
    const otherHost = {...host, [key]: 'other-source-bootstrap-owner'}
    refusal(() => makeGenesis(makeControl({owner: otherHost}), host))
    refusal(() => makeGenesis(control, otherHost))
  }
  for (const key of ['expected_authority_store_id', 'expected_memory_store_id']) {
    refusal(() => makeGenesis(control, host, {...profile, [key]: 'c'.repeat(64)}))
  }
  for (const pair of [{...profile, version: 1}, {...profile, kind: 'prime-private-unsent-closure/v1'},
    {...profile, retention_profile: 'optional'}, {...profile, extra: true}]) {
    refusal(() => makeGenesis(control, host, pair))
  }
  const incompleteProfile = {...profile}; delete incompleteProfile.expected_authority_store_id
  refusal(() => makeGenesis(control, host, incompleteProfile))
})

test('new-lineage bootstrap source: logical store identity and digest are required before genesis', () => {
  const control = makeControl()
  const otherMetadata = {...metadata, store_id: 'c'.repeat(64)}
  const changedStore = clone(control)
  changedStore.logical_store = {metadata: otherMetadata, metadata_digest: logicalMetadataDigest(otherMetadata)}
  refusal(() => makeGenesis(recommit(changedStore)), 'memory:private-v2-control-logical-store-mismatch')
  const changedDigest = clone(control); changedDigest.logical_store.metadata_digest = 'sha256:' + 'd'.repeat(64)
  refusal(() => makeGenesis(recommit(changedDigest)), 'memory:private-v2-control-logical-store-mismatch')
  for (const storeId of ['', 'sha256:' + 'b'.repeat(64), 'B'.repeat(64), 'b'.repeat(63)]) {
    const malformed = clone(control); malformed.logical_store.metadata.store_id = storeId
    refusal(() => makeGenesis(recommit(malformed)))
    refusal(() => makeGenesis(control, host, {...profile, expected_memory_store_id: storeId}))
    refusal(() => makeGenesis(control, host, {...profile, expected_authority_store_id: storeId}))
  }
})

test('new-lineage bootstrap source: valid heads, historical rows, and new runtime rows cannot seed genesis', () => {
  const variants = [makeControl({heads: {remembered: 'd'.repeat(64)}})]
  const controls = emptyTables()
  controls.controls.push({owner_subject: host.owner_subject, scope: 'owner', bytes: Buffer.from(canonicalJSON({paused: true}))})
  variants.push(makeControl({tables: controls}))
  const requests = emptyTables()
  requests.requests.push({owner_subject: host.owner_subject, idempotency_key: 'source-bootstrap-key',
    request_digest: 'e'.repeat(64), record_id: 'rem:' + 'f'.repeat(64), revision: 1})
  variants.push(makeControl({tables: requests}))
  const workflows = emptyTables()
  workflows.runtime_workflows.push({owner_subject: host.owner_subject, owner_id: host.owner_id, task_id: host.task_id,
    operation_id: 'source-bootstrap-operation', operation_digest: 'sha256:' + 'e'.repeat(64), action_type: 'memory.save',
    idempotency_key_sha256: null, record_id: null, phase: 'proposed', request_id: null, request_digest: null,
    receipt_digest: null, created_at: '2026-10-01T12:00:00.000Z'})
  variants.push(makeControl({tables: workflows}))
  for (const control of variants) refusal(() => makeGenesis(control), 'memory:private-v2-retention-genesis-not-empty')
})

test('new-lineage bootstrap source: malformed control grammar and changed commitments fail closed', () => {
  const control = makeControl(), absentTable = clone(control), absentStore = clone(control), legacy = clone(control)
  delete absentTable.tables.workflow_closure_progress
  delete absentStore.logical_store
  legacy.schema = 'aukora-prime-memory-control-state/v1'
  for (const malformed of [null, [], {...control, extra: true}, {...control, control_sha256: 'd'.repeat(64)},
    recommit(absentTable), recommit(absentStore), recommit(legacy)]) refusal(() => makeGenesis(malformed))
  for (const owner of [null, [], {...host, extra: true}, {...host, task_id: ''}, {...host, owner_id: ''},
    {...host, owner_subject: ''}, {...host, authorization_epoch: -1}, {...host, authorization_epoch: 1.5}]) {
    refusal(() => makeGenesis(control, owner))
  }
  const missingTask = {...host}; delete missingTask.task_id
  refusal(() => makeGenesis(control, missingTask))
})

test('new-lineage bootstrap source: helper options are exact inert contracts and profile fields', () => {
  const control = makeControl(), missing = {contracts}, hidden = {contracts, profile}, symbolic = {contracts, profile}
  Object.defineProperty(hidden, 'unexpected', {value: true, enumerable: false})
  symbolic[Symbol('unexpected')] = true
  for (const options of [undefined, null, [], missing, {contracts, profile, extra: true}, hidden, symbolic]) {
    refusal(() => makePrivateV2GenesisEnvelope(host, control, options), 'memory:private-v2-retention-genesis-options-required')
  }
  let callbacks = 0
  const accessor = Object.defineProperty({contracts, profile}, 'profile',
    {enumerable: true, get() { callbacks++; throw new Error('source-only options accessor executed') }})
  refusal(() => makePrivateV2GenesisEnvelope(host, control, accessor), 'memory:private-v2-retention-genesis-options-required')
  const proxy = new Proxy({contracts, profile}, {ownKeys() { callbacks++; throw new Error('source-only options proxy executed') },
    getPrototypeOf() { callbacks++; throw new Error('source-only options proxy executed') }})
  refusal(() => makePrivateV2GenesisEnvelope(host, control, proxy), 'memory:private-v2-retention-genesis-options-required')
  assert.equal(callbacks, 0)
})

test('new-lineage bootstrap source: host, profile, control and contract accessors never execute', () => {
  let reads = 0
  const withGetter = (value, key) => Object.defineProperty({...value}, key, {enumerable: true,
    get() { reads++; throw new Error('source-only accessor executed') }})
  const control = makeControl()
  refusal(() => makeGenesis(control, withGetter(host, 'owner_id')))
  refusal(() => makeGenesis(control, host, withGetter(profile, 'expected_memory_store_id')))
  refusal(() => makeGenesis(withGetter(control, 'owner_id')))
  const nestedControl = clone(control)
  nestedControl.logical_store = withGetter(nestedControl.logical_store, 'metadata')
  refusal(() => makeGenesis(nestedControl))
  const accessorContracts = withGetter({...contracts}, 'canonicalJson')
  refusal(() => makePrivateV2GenesisEnvelope(host, control, {contracts: accessorContracts, profile}))
  assert.equal(reads, 0)
})

test('new-lineage bootstrap source: proxies fail without executing their traps', () => {
  let traps = 0
  const proxy = value => new Proxy(value, {get() { traps++; throw new Error('source-only proxy executed') },
    ownKeys() { traps++; throw new Error('source-only proxy executed') },
    getOwnPropertyDescriptor() { traps++; throw new Error('source-only proxy executed') },
    getPrototypeOf() { traps++; throw new Error('source-only proxy executed') }})
  const control = makeControl()
  refusal(() => makeGenesis(control, proxy({...host})))
  refusal(() => makeGenesis(control, host, proxy({...profile})))
  refusal(() => makeGenesis(proxy(control)))
  const nestedControl = clone(control); nestedControl.tables = proxy(nestedControl.tables)
  refusal(() => makeGenesis(nestedControl))
  refusal(() => makePrivateV2GenesisEnvelope(host, control, {contracts: proxy({...contracts}), profile}))
  assert.equal(traps, 0)
})

const constructorConfig = () => ({directory: '/source-only-new-lineage-bootstrap-no-storage',
  publisher_uid: 1000, reader_uid: 1001, retention_gid: 1000, contracts, profile})

test('new-lineage bootstrap source: constructor rejects only invalid configuration grammar before storage', () => {
  const config = constructorConfig(), missing = {...config}, hidden = {...config}, symbolic = {...config}
  delete missing.profile
  Object.defineProperty(hidden, 'unexpected', {value: true, enumerable: false})
  symbolic[Symbol('unexpected')] = true
  for (const value of [undefined, null, [], missing, {...config, extra: true}, hidden, symbolic]) {
    refusal(() => createPrivateV2NewLineageBootstrapPublisher(value), 'memory:private-v2-retention-configuration-required')
  }
  for (const directory of ['relative', '/', '/source-only/../new-lineage', '/source-only/new-lineage/']) {
    refusal(() => createPrivateV2NewLineageBootstrapPublisher({...config, directory}), 'memory:private-v2-retention-directory-required')
  }
  for (const change of [{publisher_uid: -1}, {reader_uid: 1.5}, {retention_gid: -1}, {reader_uid: config.publisher_uid}]) {
    refusal(() => createPrivateV2NewLineageBootstrapPublisher({...config, ...change}), 'memory:private-v2-retention-distinct-uids-required')
  }
  for (const invalidContracts of [null, {}, {...contracts, canonicalJson: null}]) {
    refusal(() => createPrivateV2NewLineageBootstrapPublisher({...config, contracts: invalidContracts}), 'memory:private-v2-retention-contracts-required')
  }
  for (const pair of [null, {...profile, extra: true}, {...profile, version: 1},
    {...profile, retention_profile: 'optional'}, {...profile, expected_authority_store_id: 'sha256:' + 'a'.repeat(64)},
    {...profile, expected_memory_store_id: 'B'.repeat(64)}]) {
    refusal(() => createPrivateV2NewLineageBootstrapPublisher({...config, profile: pair}), 'memory:private-v2-retention-profile-required')
  }
})

test('new-lineage bootstrap source: constructor rejects getters and proxies without executing them', () => {
  let callbacks = 0
  const config = constructorConfig(), accessor = Object.defineProperty({...config}, 'directory',
    {enumerable: true, get() { callbacks++; throw new Error('source-only constructor accessor executed') }})
  refusal(() => createPrivateV2NewLineageBootstrapPublisher(accessor), 'memory:private-v2-retention-configuration-required')
  const accessorProfile = Object.defineProperty({...profile}, 'version',
    {enumerable: true, get() { callbacks++; throw new Error('source-only profile accessor executed') }})
  refusal(() => createPrivateV2NewLineageBootstrapPublisher({...config, profile: accessorProfile}), 'memory:private-v2-retention-profile-required')
  const accessorContracts = Object.defineProperty({...contracts}, 'canonicalJson',
    {enumerable: true, get() { callbacks++; throw new Error('source-only contract accessor executed') }})
  refusal(() => createPrivateV2NewLineageBootstrapPublisher({...config, contracts: accessorContracts}), 'memory:private-v2-retention-contracts-required')
  const proxy = value => new Proxy(value, {ownKeys() { callbacks++; throw new Error('source-only constructor proxy executed') },
    getOwnPropertyDescriptor() { callbacks++; throw new Error('source-only constructor proxy executed') },
    getPrototypeOf() { callbacks++; throw new Error('source-only constructor proxy executed') }})
  refusal(() => createPrivateV2NewLineageBootstrapPublisher(proxy(config)), 'memory:private-v2-retention-configuration-required')
  refusal(() => createPrivateV2NewLineageBootstrapPublisher({...config, profile: proxy({...profile})}), 'memory:private-v2-retention-profile-required')
  refusal(() => createPrivateV2NewLineageBootstrapPublisher({...config, contracts: proxy({...contracts})}), 'memory:private-v2-retention-contracts-required')
  assert.equal(callbacks, 0)
})

test('new-lineage bootstrap source: arbitrary callback objects have no publisher brand', () => {
  for (const value of [undefined, null, {}, {bootstrap: async () => true},
    {bootstrap: async () => true, status: {kind: 'private-v2-new-lineage-bootstrap-publisher'}}]) {
    assert.equal(isPrivateV2NewLineageBootstrapPublisher(value), false)
  }
})

// Content validation alone supplies no file custody, durable cleanup, or admission.
const bootstrapIntentHash = value => sha256(Buffer.from('aukora-prime.memory-retention-bootstrap-intent.v1\0' + canonicalJSON(value)))
const bootstrapPendingHash = value => sha256(Buffer.from('aukora-prime.memory-retention-bootstrap-pending.v1\0' + canonicalJSON(value)))
function cleanupContentFixture() {
  const envelope = makeGenesis()
  const intent = {schema: 'aukora-prime-memory-retention-bootstrap-intent/v1', host, profile,
    control_sha256: envelope.control_state.control_sha256, checkpoint_sha256: envelope.checkpoint_sha256}
  const pending = {schema: 'aukora-prime-memory-retention-bootstrap-pending/v1',
    bootstrap_sha256: bootstrapIntentHash(intent), checkpoint_sha256: intent.checkpoint_sha256}
  const guard = {schema: 'aukora-prime-memory-retention-bootstrap-cleanup-guard/v1',
    pending: {...pending}, pending_sha256: bootstrapPendingHash(pending)}
  const completion = {schema: 'aukora-prime-memory-retention-bootstrap-completion/v2',
    bootstrap_sha256: pending.bootstrap_sha256, pending_sha256: guard.pending_sha256,
    checkpoint_sha256: pending.checkpoint_sha256}
  return {host, profile, intent, guard, pending, completion}
}

test('new-lineage bootstrap source: cleanup helper checks unresolved and completed content without admission', () => {
  const fixture = cleanupContentFixture()
  for (const input of [{...fixture, completion: null}, {...fixture, pending: null, completion: null},
    {...fixture, pending: null}, fixture]) {
    const before = clone(input), checked = assertPrivateV2BootstrapCleanupContent(input)
    assert.deepEqual(Object.keys(checked).sort(), ['host', 'profile', 'intent', 'guard', 'pending', 'completion'].sort())
    for (const key of Object.keys(input)) assert.deepEqual(checked[key], input[key])
    assert.equal(Object.hasOwn(checked, 'eligible'), false)
    assert.equal(Object.hasOwn(checked, 'admitted'), false)
    assert.deepEqual(input, before)
    assert.notEqual(checked.intent, input.intent)
    assert.notEqual(checked.guard, input.guard)
  }
  const reordered = {...fixture, completion: null,
    pending: {checkpoint_sha256: fixture.pending.checkpoint_sha256,
      bootstrap_sha256: fixture.pending.bootstrap_sha256, schema: fixture.pending.schema}}
  assert.deepEqual(assertPrivateV2BootstrapCleanupContent(reordered).pending, fixture.pending)
})

test('new-lineage bootstrap source: cleanup input is exact and its guard is mandatory even while unresolved', () => {
  const fixture = {...cleanupContentFixture(), pending: null, completion: null}
  for (const value of [undefined, null, [], {...fixture, eligible: true}, {...fixture, guard: null}]) {
    refusal(() => assertPrivateV2BootstrapCleanupContent(value))
  }
  for (const key of Object.keys(fixture)) {
    const missing = {...fixture}; delete missing[key]
    refusal(() => assertPrivateV2BootstrapCleanupContent(missing))
  }
  for (const guard of [{}, {...fixture.guard, extra: true}, {...fixture.guard, pending: null},
    {...fixture.guard, schema: 'aukora-prime-memory-retention-cleanup-guard/v3'},
    {...fixture.guard, pending_sha256: 'd'.repeat(64)}]) {
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, guard}))
  }
  const missingGuardDigest = {...fixture.guard}; delete missingGuardDigest.pending_sha256
  refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, guard: missingGuardDigest}))
})

test('new-lineage bootstrap source: cleanup intent, pending, guard and completion keep their exact digest bindings', () => {
  const fixture = cleanupContentFixture()
  for (const key of ['owner_id', 'owner_subject']) {
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, host: {...host, [key]: 'other-source-owner'}}))
  }
  refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture,
    profile: {...profile, expected_memory_store_id: 'c'.repeat(64)}}))
  for (const key of ['control_sha256', 'checkpoint_sha256']) {
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, intent: {...fixture.intent, [key]: 'c'.repeat(64)}}))
  }
  for (const key of ['bootstrap_sha256', 'checkpoint_sha256']) {
    const candidate = {...fixture.pending, [key]: 'd'.repeat(64)}
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, pending: candidate}))
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture,
      guard: {...fixture.guard, pending: candidate, pending_sha256: bootstrapPendingHash(candidate)}}))
  }
  for (const digest of ['sha256:' + fixture.guard.pending_sha256,
    sha256(Buffer.from(canonicalJSON(fixture.pending))),
    sha256(Buffer.from('aukora-prime.memory-retention-bootstrap-pending.v1\0' + canonicalJSON(fixture.pending) + '\n'))]) {
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, guard: {...fixture.guard, pending_sha256: digest}}))
  }
  for (const key of ['bootstrap_sha256', 'pending_sha256', 'checkpoint_sha256']) {
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, completion: {...fixture.completion, [key]: 'e'.repeat(64)}}))
  }
})

test('new-lineage bootstrap source: cleanup rejects legacy and malformed pending or completion candidates', () => {
  const fixture = cleanupContentFixture()
  const legacy = {schema: 'aukora-prime-memory-retention-bootstrap-completion/v1',
    bootstrap_sha256: fixture.completion.bootstrap_sha256, checkpoint_sha256: fixture.completion.checkpoint_sha256}
  const missingCompletionDigest = {...fixture.completion}; delete missingCompletionDigest.pending_sha256
  for (const completion of [legacy, missingCompletionDigest, {...fixture.completion, extra: true},
    {...fixture.completion, schema: legacy.schema}]) {
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, completion}))
  }
  for (const pending of [{...fixture.pending, extra: true},
    {...fixture.pending, schema: 'aukora-prime-memory-retention-pending/v2'}]) {
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, pending}))
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture,
      guard: {...fixture.guard, pending, pending_sha256: bootstrapPendingHash(pending)}}))
  }
})

test('new-lineage bootstrap source: cleanup rejects getters and proxies before executing callbacks', () => {
  const fixture = cleanupContentFixture()
  let callbacks = 0
  const getter = (value, key) => Object.defineProperty({...value}, key,
    {enumerable: true, get() { callbacks++; throw new Error('source-only cleanup getter executed') }})
  const proxy = value => new Proxy(value, {get() { callbacks++; throw new Error('source-only cleanup proxy executed') },
    ownKeys() { callbacks++; throw new Error('source-only cleanup proxy executed') },
    getOwnPropertyDescriptor() { callbacks++; throw new Error('source-only cleanup proxy executed') },
    getPrototypeOf() { callbacks++; throw new Error('source-only cleanup proxy executed') }})
  refusal(() => assertPrivateV2BootstrapCleanupContent(proxy(fixture)))
  for (const key of Object.keys(fixture)) {
    refusal(() => assertPrivateV2BootstrapCleanupContent(getter(fixture, key)))
    const value = fixture[key], field = Object.keys(value)[0]
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, [key]: getter(value, field)}))
    refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, [key]: proxy(value)}))
  }
  refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture,
    guard: {...fixture.guard, pending: getter(fixture.guard.pending, 'bootstrap_sha256')}}))
  refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture,
    guard: {...fixture.guard, pending: proxy(fixture.guard.pending)}}))
  for (const key of ['bootstrap_sha256', 'checkpoint_sha256']) {
    const digestGetter = Object.defineProperty({}, 'toJSON',
      {enumerable: true, get() { callbacks++; throw new Error('nested digest getter executed') }})
    for (const value of [proxy({}), digestGetter, [fixture.pending[key]]]) {
      refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture, pending: {...fixture.pending, [key]: value}}))
      refusal(() => assertPrivateV2BootstrapCleanupContent({...fixture,
        guard: {...fixture.guard, pending: {...fixture.pending, [key]: value}}}))
    }
  }
  assert.equal(callbacks, 0)
})
