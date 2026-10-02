// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { sha256 } from '../src/codecs.mjs'
import { createMemoryOwnerSerializer } from '../src/owner-serialization.mjs'
import { createFileControlRetentionReader } from '../src/control-retention.mjs'
import { createControlRetentionCoordinator } from '../src/control-retention-coordinator.mjs'
import { createRetainedMemoryParticipant, isRetainedMemoryParticipant } from '../src/retained-memory-participant.mjs'

// Ordinary constructor/scope source fixtures only. SQL responses are explicit models;
// no PostgreSQL, separate UID, runtime configuration, marker or authority effect is exercised.
const contracts = Object.freeze({validateContract: (_kind, value) => value,
  operationDigest: value => 'sha256:' + sha256(Buffer.from(canonicalJSON(value)))})
const host = Object.freeze({owner_id: 'participant-owner-id', owner_subject: 'participant-owner-subject', authorization_epoch: 4})
const operation = Object.freeze({operation_id: 'participant-operation', owner_id: host.owner_id,
  authorization_epoch: host.authorization_epoch, audience: 'aukora-prime.memory', action_type: 'memory.save',
  target_identity: {kind: 'prime-memory', owner_subject: host.owner_subject}})
const request = () => ({host, operation, request_id: '00000000-0000-4000-8000-000000000001', request_digest: 'sha256:' + 'd'.repeat(64)})
function fixture({unlockFailure = false} = {}) {
  const sql = [], released = [], publisherCalls = []
  const client = {async query(statement) {
    sql.push(statement)
    if (statement.startsWith('SELECT pg_advisory_lock(')) return {rows: [{backend_pid: 423}]}
    if (statement.startsWith('SELECT pg_backend_pid()')) return {rows: [{backend_pid: 423, held: true}]}
    if (statement.startsWith('SELECT pg_advisory_unlock(')) {
      if (unlockFailure) throw new Error('modeled unlock reply lost')
      return {rows: [{unlocked: true}]}
    }
    throw new Error('unexpected modeled SQL')
  }, release(value) {released.push(value)}}
  const serializer = createMemoryOwnerSerializer({pool: {async connect() {return client}}})
  const reader = createFileControlRetentionReader({directory: '/tmp/prime-participant-unmaterialized-fixture',
    reader_uid: process.getuid(), publisher_uid: process.getuid() + 100000,
    retention_gid: process.getgid(), contracts})
  const publisher = Object.fromEntries(['beginMutation', 'retainPrepared', 'publishMutation'].map(name =>
    [name, async value => {publisherCalls.push([name, value]); return true}]))
  const coordinator = createControlRetentionCoordinator({reader, publisher, contracts})
  return {serializer, coordinator, sql, released, publisherCalls}
}
const create = (f, overrides = {}) => createRetainedMemoryParticipant({coordinator: f.coordinator, serializer: f.serializer, contracts, ...overrides})

test('private participant and controller are source-branded and closed; fabricated capability callbacks fail', () => {
  const f = fixture(), controller = create(f)
  assert.equal(isRetainedMemoryParticipant(controller.participant), true)
  assert.equal(isRetainedMemoryParticipant({...controller.participant}), false)
  assert.equal(isRetainedMemoryParticipant({prepare: async () => true}), false)
  assert.deepEqual(Object.keys(controller).sort(), ['participant', 'runOperation', 'context', 'bindRecovered'].sort())
  assert.deepEqual(Object.keys(controller.participant).sort(), ['prepare', 'dispatch', 'settle'].sort())
  assert.equal(Object.isFrozen(controller), true)
  assert.equal(Object.isFrozen(controller.participant), true)
  assert.equal(controller.context(), null)
  assert.throws(() => create(f, {coordinator: {...f.coordinator}}), {code: 'memory:retained-participant-owned-coordinator-required'})
  assert.throws(() => create(f, {serializer: {...f.serializer}}), {code: 'memory:retained-participant-owned-serializer-required'})
  assert.throws(() => createRetainedMemoryParticipant({coordinator: f.coordinator, serializer: f.serializer, contracts, permitted: true}),
    {code: 'memory:retained-participant-configuration-required'})
  assert.deepEqual(f.sql, [])
})

test('operation registration lives only within the actual owned SQL scope; completion invalidates it', async () => {
  const f = fixture(), controller = create(f)
  let captured
  const result = await controller.runOperation(request(), async scope => {
    captured = scope
    assert.equal(scope, f.serializer.current())
    assert.equal(controller.context(), null)
    await assert.rejects(controller.bindRecovered({tuple: {}, predecessor: {}}), {code: 'memory:retained-participant-owned-context-required'})
    await assert.rejects(controller.runOperation(request(), async () => {}), {code: 'memory:retained-participant-operation-already-active'})
    return 'ordinary-work'
  })
  assert.equal(result, 'ordinary-work')
  assert.equal(controller.context(), null)
  await assert.rejects(f.serializer.inspect(captured), {code: 'memory:owner-session-scope-inactive'})
  await assert.rejects(controller.participant.prepare({operation}), {code: 'memory:retained-participant-operation-not-active'})
  assert.deepEqual(f.publisherCalls, [])
  assert.deepEqual(f.released, [undefined])
})

test('closed source input rejects owner/epoch/request mismatches before a SQL scope exists', async () => {
  const f = fixture(), controller = create(f)
  for (const changed of [{host: {...host, authorization_epoch: 5}}, {host: {...host, owner_id: host.owner_subject}},
    {operation: {...operation, target_identity: {kind: 'prime-memory', owner_subject: 'other-owner'}}}]) {
    await assert.rejects(controller.runOperation({...request(), ...changed}, () => {}),
      {code: 'memory:retained-participant-operation-binding-invalid'})
  }
  for (const changed of [{request_id: [request().request_id]}, {request_digest: [request().request_digest]}]) {
    await assert.rejects(controller.runOperation({...request(), ...changed}, () => {}),
      {code: 'memory:retained-participant-request-binding-invalid'})
  }
  await assert.rejects(controller.runOperation({...request(), host: {...host, permitted: true}}, () => {}),
    {code: 'memory:retained-participant-host-required'})
  assert.deepEqual(f.sql, [])
  assert.deepEqual(f.publisherCalls, [])
})

test('guest accessors and proxies never execute while registering an immutable operation', async () => {
  const f = fixture(), controller = create(f)
  let calls = 0
  const accessor = {...operation}
  Object.defineProperty(accessor, 'owner_id', {enumerable: true, get() {calls++; return host.owner_id}})
  await assert.rejects(controller.runOperation({...request(), operation: accessor}, () => {}),
    {code: 'memory:retained-participant-inert-json-required'})
  const proxy = new Proxy(operation, {ownKeys() {calls++; return []}})
  await assert.rejects(controller.runOperation({...request(), operation: proxy}, () => {}),
    {code: 'memory:retained-participant-inert-json-required'})
  assert.equal(calls, 0)
  assert.deepEqual(f.sql, [])
})

test('phase methods reject unknown/changed operation and closed-shape bypass without publication', async () => {
  const f = fixture(), controller = create(f)
  await controller.runOperation(request(), async () => {
    await assert.rejects(controller.participant.prepare({operation, permitted: true}), {code: 'memory:retained-participant-prepare-fields-invalid'})
    await assert.rejects(controller.participant.prepare({operation: {...operation, action_type: 'memory.forget'}}),
      {code: 'memory:retained-participant-operation-not-active'})
    await assert.rejects(controller.participant.dispatch({operation, consumed_grant: true,
      request_id: request().request_id, request_digest: request().request_digest}),
      {code: 'memory:original-not-object'})
    await assert.rejects(controller.participant.settle({operation, consumed_grant: {}, request_id: request().request_id,
      request_digest: request().request_digest, receipt: {}, permits: true}), {code: 'memory:retained-participant-effect-fields-invalid'})
  })
  assert.deepEqual(f.publisherCalls, [])
})

test('lost owner-session cleanup retains exact operation/request bindings and forbids automatic retry', async () => {
  const f = fixture({unlockFailure: true}), controller = create(f)
  let executions = 0
  await assert.rejects(controller.runOperation(request(), async () => {
    executions++
    return 'modeled-completed-work'
  }), error => {
    assert.equal(error.code, 'memory:owner-session-unlock-uncertain')
    assert.equal(error.cause.message, 'modeled unlock reply lost')
    assert.equal(error.reconciliation_required, true)
    assert.equal(error.automatic_retry, false)
    assert.equal(error.operation_id, operation.operation_id)
    assert.equal(error.request_id, request().request_id)
    assert.equal(error.request_digest, request().request_digest)
    return true
  })
  assert.equal(executions, 1)
  assert.equal(controller.context(), null)
  assert.deepEqual(f.released, [true])
  assert.deepEqual(f.publisherCalls, [])
})
