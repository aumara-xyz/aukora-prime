// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { sha256 } from '../src/codecs.mjs'
import { createFileControlRetentionReader, createUnavailableControlRetention, MEMORY_RETENTION_SCHEMA } from '../src/control-retention.mjs'
import { createControlRetentionCoordinator, isControlRetentionCoordinator } from '../src/control-retention-coordinator.mjs'

// Pure validation only: factory creation does not touch the named nonexistent directory.
// This does not model separate processes, grant authority, use PG or create OS resources.
const contracts = Object.freeze({validateContract: (_kind, value) => value,
  operationDigest: value => 'sha256:' + sha256(Buffer.from(canonicalJSON(value)))})
const host = Object.freeze({owner_id: 'synthetic-coordinator-owner', owner_subject: 'synthetic-coordinator-subject', authorization_epoch: 4})
const operation = Object.freeze({operation_id: 'synthetic-coordinator-operation', owner_id: host.owner_id,
  authorization_epoch: host.authorization_epoch, audience: 'aukora-prime.memory', action_type: 'memory.save',
  target_identity: {kind: 'prime-memory', owner_subject: host.owner_subject}})
const request = () => ({host, operation, request_id: '00000000-0000-4000-8000-000000000001', request_digest: 'sha256:' + 'b'.repeat(64)})
function fileReader() {
  return createFileControlRetentionReader({directory: '/tmp/aukora-coordinator-unmaterialized-validation-fixture',
    reader_uid: process.getuid(), publisher_uid: process.getuid() + 100000, retention_gid: process.getgid(), contracts})
}
function publisher() {
  const calls = []
  return {calls, beginMutation: async value => { calls.push(['begin', value]); return true },
    retainPrepared: async value => { calls.push(['prepared', value]); return true },
    publishMutation: async value => { calls.push(['complete', value]); return true }}
}
const create = (overrides = {}) => createControlRetentionCoordinator({reader: fileReader(), publisher: publisher(), contracts, ...overrides})

test('only an actual branded file reader can qualify a retention coordinator', () => {
  let callbackCalls = 0
  const guestReader = {readCurrent: async () => { callbackCalls++; return true },
    readPending: async () => true, inspectPending: async () => true, observePredecessor: async () => true,
    status: {configured: true, kind: 'file-reader', schema: MEMORY_RETENTION_SCHEMA}}
  assert.throws(() => create({reader: guestReader}), {code: 'memory:control-retention-coordinator-owned-reader-required'})
  assert.throws(() => create({reader: createUnavailableControlRetention()}),
    {code: 'memory:control-retention-coordinator-file-reader-required'})
  assert.equal(callbackCalls, 0)
})

test('factory rejects Boolean publisher methods and missing structured publication methods', () => {
  for (const unqualified of [true, () => true, {beginMutation: true, retainPrepared: true, publishMutation: true},
    {beginMutation: async () => true}, {beginUpdate: async () => true, publish: async () => true}]) {
    assert.throws(() => create({publisher: unqualified}),
      {code: 'memory:control-retention-coordinator-publisher-methods-required'})
  }
})

test('coordinator is branded and frozen with the exact supplied reader and closed immutable status', () => {
  const reader = fileReader(), transport = publisher(), coordinator = create({reader, publisher: transport})
  assert.equal(isControlRetentionCoordinator(coordinator), true)
  assert.equal(isControlRetentionCoordinator({...coordinator}), false)
  assert.equal(coordinator.reader, reader)
  assert.equal(Object.isFrozen(coordinator), true)
  assert.equal(Object.isFrozen(coordinator.status), true)
  assert.deepEqual(coordinator.status, {configured: true, kind: 'control-retention-coordinator', schema: MEMORY_RETENTION_SCHEMA})
  assert.deepEqual(transport.calls, [])
})

test('factory rejects configuration and method accessors without executing them', () => {
  let getterCalls = 0
  const config = {reader: fileReader(), publisher: publisher(), contracts}
  Object.defineProperty(config, 'publisher', {get: () => { getterCalls++; return publisher() }, enumerable: true})
  assert.throws(() => createControlRetentionCoordinator(config), {code: 'memory:control-retention-coordinator-configuration-required'})
  const transport = publisher()
  Object.defineProperty(transport, 'beginMutation', {get: () => { getterCalls++; return async () => true }, enumerable: true})
  assert.throws(() => create({publisher: transport}), {code: 'memory:control-retention-coordinator-publisher-methods-required'})
  assert.throws(() => createControlRetentionCoordinator({reader: fileReader(), publisher: publisher(), contracts, restore_trusted: true}),
    {code: 'memory:control-retention-coordinator-configuration-required'})
  assert.equal(getterCalls, 0)
})

test('fabricated contexts cannot observe, stage or publish retained state', async () => {
  const transport = publisher(), coordinator = create({publisher: transport})
  const context = Object.freeze({tuple: {}, predecessor: {}})
  for (const method of ['observe', 'prepared', 'complete']) {
    await assert.rejects(coordinator[method](context, {}), {code: 'memory:control-retention-coordinator-owned-context-required'})
  }
  assert.deepEqual(transport.calls, [])
})

test('operation and request binding errors refuse before the genuine reader or publisher is reached', async () => {
  const transport = publisher(), coordinator = create({publisher: transport})
  for (const changed of [
    {operation: {...operation, owner_id: host.owner_subject}},
    {operation: {...operation, authorization_epoch: host.authorization_epoch - 1}},
    {operation: {...operation, audience: 'different-audience'}},
    {operation: {...operation, action_type: 'unowned.action'}},
    {operation: {...operation, target_identity: {kind: 'prime-memory', owner_subject: 'other-owner'}}},
  ]) await assert.rejects(coordinator.begin({...request(), ...changed}),
    {code: 'memory:control-retention-coordinator-operation-binding-invalid'})
  for (const changed of [{request_id: ['00000000-0000-4000-8000-000000000001']},
    {request_digest: ['sha256:' + 'b'.repeat(64)]}, {request_id: 'not-a-uuid'}]) {
    await assert.rejects(coordinator.begin({...request(), ...changed}),
      {code: 'memory:control-retention-coordinator-request-binding-invalid'})
  }
  await assert.rejects(coordinator.recover({...request(), operation: {...operation, owner_id: 'other-owner'}}),
    {code: 'memory:control-retention-coordinator-operation-binding-invalid'})
  assert.deepEqual(transport.calls, [])
})

test('guest accessors, proxies, extra host keys and Boolean digests never become retained authority', async () => {
  const transport = publisher(), coordinator = create({publisher: transport})
  let guestCalls = 0
  const accessorOperation = {...operation}
  Object.defineProperty(accessorOperation, 'owner_id', {get: () => { guestCalls++; return host.owner_id }, enumerable: true})
  await assert.rejects(coordinator.begin({...request(), operation: accessorOperation}),
    {code: 'memory:control-retention-coordinator-inert-json-required'})
  const proxyOperation = new Proxy(operation, {ownKeys: () => { guestCalls++; return [] }})
  await assert.rejects(coordinator.begin({...request(), operation: proxyOperation}),
    {code: 'memory:control-retention-coordinator-inert-json-required'})
  await assert.rejects(coordinator.begin({...request(), host: {...host, authenticated: true}}),
    {code: 'memory:control-retention-coordinator-host-required'})
  const badContracts = {...contracts, operationDigest: () => true}
  await assert.rejects(create({contracts: badContracts}).begin(request()),
    {code: 'memory:control-retention-coordinator-operation-digest-invalid'})
  assert.equal(guestCalls, 0)
  assert.deepEqual(transport.calls, [])
})
