// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { sha256 } from '../src/codecs.mjs'
import { MEMORY_AUDIENCE, memoryEffectDigest, memoryResultDigest, memoryTarget } from '../src/authorization.mjs'
import { MEMORY_CONTROL_TABLES, makeMemoryControlState } from '../src/control-state.mjs'
import { assertMemoryControlAdvance } from '../src/control-retention-advance.mjs'

// Inert synthetic continuity regressions only: no dispatch, authority implementation or I/O.
const host = {owner_subject: 'synthetic-retention-subject', owner_id: 'synthetic-retention-owner', authorization_epoch: 7}
const at = '2026-10-01T11:03:00Z', id = 'rem:' + 'a'.repeat(64), heads = {remembered: 'b'.repeat(64)}
const encode = value => Buffer.from(canonicalJSON(value))
const operationDigest = operation => 'sha256:' + sha256(Buffer.from('aukora-prime.operation.v1\0' + canonicalJSON(operation)))
const contracts = {validateContract(kind, value) { assert.ok(['OperationProposal', 'ConsumedGrant'].includes(kind)); assert.equal(value.version, 1) }, operationDigest}
const empty = () => Object.fromEntries(Object.keys(MEMORY_CONTROL_TABLES).map(name => [name, []]))
const make = (tables, value = heads) => makeMemoryControlState(host, {heads: value, tables}, {contracts})
const advance = (previous, next) => assertMemoryControlAdvance(previous, next, host, {contracts})
const cloneTables = tables => Object.fromEntries(Object.entries(tables).map(([name, rows]) => [name, rows.map(row => ({...row}))]))
function retainedFixture() {
  const tables = empty(), bytes = Buffer.from(JSON.stringify({kind: 'tombstone', recordId: id, at}, null, 2) + '\n')
  tables.tombstones.push({owner_subject: host.owner_subject, record_id: id, bytes, sha256: sha256(bytes)})
  tables.purges.push({owner_subject: host.owner_subject, operation_id: 'synthetic-purge',
    bytes: encode({kind: 'prime-active-record-purge/v1', record_ids: [id], source_digests: ['c'.repeat(64)], at})})
  tables.requests.push({owner_subject: host.owner_subject, idempotency_key: 'retained-key', request_digest: 'd'.repeat(64), record_id: id, revision: 1})
  tables.redactions.push({owner_subject: host.owner_subject, record_id: id, revision: 1,
    bytes: encode({kind: 'redacted-record/v1', record_id: id, revision: 1, canonical_sha256: 'e'.repeat(64),
      chain_domain: 'remembered', chain_sequence: 1, source_digests: ['c'.repeat(64)]})})
  tables.controls.push({owner_subject: host.owner_subject, scope: 'owner', bytes: encode({paused: true, grantsAuthority: false})})
  return tables
}
function intentFixture({completed = true, suffix = '1'} = {}) {
  const tables = empty()
  const operation = {version: 1, operation_id: 'synthetic-operation-' + suffix, owner_id: host.owner_id, task_id: 'historical-task',
    action_type: 'memory.forget', audience: MEMORY_AUDIENCE, authorization_epoch: 2,
    target_identity: memoryTarget(host.owner_subject), canonical_parameters: {record_id: id, at}}
  const operation_digest = operationDigest(operation)
  const grant = {version: 1, grant_id: 'synthetic-grant-' + suffix, operation_id: operation.operation_id, operation_digest,
    owner_id: host.owner_id, audience: MEMORY_AUDIENCE, authorization_epoch: 2}
  const request = {version: 1, action_type: operation.action_type, owner_subject: host.owner_subject,
    operation_id: operation.operation_id, operation_digest, parameters: operation.canonical_parameters}
  const request_id = '00000000-0000-4000-8000-' + suffix.padStart(12, '0'), request_digest = memoryEffectDigest(request)
  const intent = {owner_subject: host.owner_subject, operation_id: operation.operation_id, operation_digest,
    grant_bytes: encode(grant), operation_bytes: Buffer.from(JSON.stringify(operation, null, 2) + '\n'),
    request_id, request_digest, request_bytes: encode(request)}
  tables.intents.push(intent)
  if (completed) {
    const result = {record_id: id, state: 'tombstoned', grants_authority: false}
    const receipt = {version: 1, kind: 'prime-memory-effect/v1', operation_id: operation.operation_id, operation_digest,
      grant_id: grant.grant_id, request_id, request_digest, owner_subject: host.owner_subject, action_type: operation.action_type,
      status: 'applied', result_digest: memoryResultDigest(result), result}
    tables.effects.push({...intent, grant_id: grant.grant_id, action: operation.action_type, result_bytes: encode(result), receipt_bytes: encode(receipt)})
  }
  return tables
}
function fenceFor(tables) {
  const intent = tables.intents[0], operation = JSON.parse(intent.operation_bytes), grant = JSON.parse(intent.grant_bytes)
  return {owner_subject: host.owner_subject, operation_id: intent.operation_id, operation_digest: intent.operation_digest,
    grant_id: grant.grant_id, action: operation.action_type, request_id: intent.request_id, request_digest: intent.request_digest, status: 'payload-purged'}
}

test('exact state and valid supersets retain all old control rows and return no authority', () => {
  const tables = retainedFixture(), previous = make(tables), next = cloneTables(tables)
  assert.equal(advance(previous, previous), undefined)
  next.requests.push({...next.requests[0], idempotency_key: 'new-key'})
  next.controls.push({owner_subject: host.owner_subject, scope: 'task:synthetic', bytes: encode({offTheRecord: true})})
  assert.equal(advance(previous, make(next)), undefined)
})

test('retained purge, idempotency, tombstone, redaction and fence rows cannot disappear or change', () => {
  const tables = retainedFixture(), fenced = intentFixture()
  tables.replay_fences.push(fenceFor(fenced))
  for (const name of ['purges', 'requests', 'tombstones', 'redactions', 'replay_fences']) {
    const previous = empty()
    previous[name] = tables[name]
    if (['purges', 'redactions'].includes(name)) previous.tombstones = tables.tombstones
    const next = cloneTables(previous); next[name] = []
    assert.throws(() => advance(make(previous), make(next)), {code: 'memory:control-advance-retained-row-changed'})
  }
  const changed = cloneTables(tables); changed.requests[0].revision = 2
  assert.throws(() => advance(make(tables), make(changed)), {code: 'memory:control-advance-retained-row-changed'})
  const normalized = cloneTables(tables)
  normalized.tombstones[0].bytes = encode(JSON.parse(normalized.tombstones[0].bytes))
  normalized.tombstones[0].sha256 = sha256(normalized.tombstones[0].bytes)
  assert.throws(() => advance(make(tables), make(normalized)), {code: 'memory:control-advance-retained-row-changed'})
})

test('head domains and control scopes remain; valid control changes require changed heads', () => {
  const tables = retainedFixture(), previous = make(tables), next = cloneTables(tables)
  next.controls[0].bytes = encode({paused: false, grantsAuthority: false})
  assert.throws(() => advance(previous, make(next)), {code: 'memory:control-advance-control-without-head-change'})
  assert.equal(advance(previous, make(next, {remembered: 'f'.repeat(64)})), undefined)
  const noScope = cloneTables(tables); noScope.controls = []
  assert.throws(() => advance(previous, make(noScope, {remembered: 'f'.repeat(64)})), {code: 'memory:control-advance-control-scope-missing'})
  const emptyHeads = empty(), retainedHeads = make(emptyHeads)
  assert.throws(() => advance(retainedHeads, make(emptyHeads, {})), {code: 'memory:control-advance-head-missing'})
  assert.equal(advance(retainedHeads, make(emptyHeads, {...heads, approved: 'f'.repeat(64)})), undefined)
})

test('unresolved historical intents stay exact when completed or retained alongside new operations', () => {
  const tables = intentFixture({completed: false}), previous = make(tables)
  assert.equal(advance(previous, make(intentFixture())), undefined)
  const next = cloneTables(tables), other = intentFixture({completed: false, suffix: '2'})
  next.intents.push(other.intents[0])
  assert.equal(advance(previous, make(next)), undefined)
  assert.throws(() => advance(previous, make(empty())), {code: 'memory:control-advance-unresolved-intent-missing'})
  const fenced = empty(); fenced.replay_fences.push(fenceFor(tables))
  assert.throws(() => advance(previous, make(fenced)), {code: 'memory:control-advance-unresolved-intent-missing'})
  const changed = cloneTables(tables)
  changed.intents[0].operation_bytes = encode(JSON.parse(changed.intents[0].operation_bytes))
  assert.throws(() => advance(previous, make(changed)), {code: 'memory:control-advance-intent-changed'})
})

test('completed payload rows clear only to a fence with the exact old replay bindings', () => {
  const tables = intentFixture(), previous = make(tables), next = empty(), fence = fenceFor(tables)
  next.replay_fences.push(fence)
  assert.equal(advance(previous, make(next)), undefined)
  const noEffect = cloneTables(tables); noEffect.effects = []
  assert.throws(() => advance(previous, make(noEffect)), {code: 'memory:control-advance-effect-changed'})
  for (const [column, value] of Object.entries({operation_digest: 'sha256:' + 'f'.repeat(64), grant_id: 'other-grant',
    action: 'memory.purge', request_id: '00000000-0000-4000-8000-000000000009', request_digest: 'sha256:' + 'e'.repeat(64)})) {
    const mismatched = empty(); mismatched.replay_fences.push({...fence, [column]: value})
    assert.throws(() => advance(previous, make(mismatched)), {code: 'memory:control-advance-intent-fence-missing'})
  }
})

test('previous completed effects and existing content-free fences remain exact in later supersets', () => {
  const tables = intentFixture(), previous = make(tables), next = cloneTables(tables)
  const other = intentFixture({suffix: '2'}); next.intents.push(other.intents[0]); next.effects.push(other.effects[0])
  assert.equal(advance(previous, make(next)), undefined)
  const changed = cloneTables(tables), result = {record_id: id, state: 'other-synthetic-state', grants_authority: false}
  const receipt = JSON.parse(changed.effects[0].receipt_bytes)
  changed.effects[0].result_bytes = encode(result); changed.effects[0].receipt_bytes = encode({...receipt, result, result_digest: memoryResultDigest(result)})
  assert.throws(() => advance(previous, make(changed)), {code: 'memory:control-advance-effect-changed'})
  const fenced = empty(); fenced.replay_fences.push(fenceFor(tables))
  const fencedNext = cloneTables(fenced); fencedNext.replay_fences.push(fenceFor(other))
  assert.equal(advance(make(fenced), make(fencedNext)), undefined)
})
