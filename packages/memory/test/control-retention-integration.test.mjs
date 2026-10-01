// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createPostgresMemory } from '../src/index.mjs'
import { createUnavailableControlRetention, MEMORY_RETENTION_SCHEMA } from '../src/control-retention.mjs'
import { makeSnapshot } from '../src/snapshot.mjs'

// Constructor/default-only regressions. These dummy functions never access storage or a network.
function dummyPool() {
  let calls = 0
  const unavailable = async () => { calls++; throw new Error('unexpected dummy pool call') }
  return {pool: {connect: unavailable, query: unavailable}, calls: () => calls}
}
const host = {owner_id: 'synthetic-current-owner', owner_subject: 'synthetic-current-subject', authorization_epoch: 7}

test('constructor defaults to explicitly unavailable retained control state', () => {
  const fixture = dummyPool(), memory = createPostgresMemory({pool: fixture.pool})
  assert.deepEqual(memory.controlRetentionStatus(), {configured: false, kind: 'unavailable', schema: MEMORY_RETENTION_SCHEMA})
  assert.equal(fixture.calls(), 0)
})

test('default restore preparation fails closed before storage for the exact current host', async () => {
  const fixture = dummyPool(), memory = createPostgresMemory({pool: fixture.pool})
  const snapshot = makeSnapshot(host.owner_subject, [], {})
  await assert.rejects(memory.prepareRestoreBinding(host, snapshot), {code: 'memory:trusted-restore-anchor-unavailable'})
  assert.equal(fixture.calls(), 0)
})

test('arbitrary control retention object is rejected before its callback can run', () => {
  const fixture = dummyPool()
  let callbackCalls = 0
  const controlRetention = {restoreAnchorProvider: async () => { callbackCalls++; return true }}
  assert.throws(() => createPostgresMemory({pool: fixture.pool, controlRetention}), {code: 'memory:owned-control-retention-reader-required'})
  assert.equal(callbackCalls, 0); assert.equal(fixture.calls(), 0)
})

test('legacy restore provider must be a function rather than a boolean', () => {
  const fixture = dummyPool()
  assert.throws(() => createPostgresMemory({pool: fixture.pool, restoreAnchorProvider: true}), {code: 'memory:restore-anchor-provider-invalid'})
  assert.equal(fixture.calls(), 0)
})

test('legacy function and branded retained control reader cannot be configured together', () => {
  const fixture = dummyPool()
  let callbackCalls = 0
  const restoreAnchorProvider = async () => { callbackCalls++; return true }
  assert.throws(() => createPostgresMemory({pool: fixture.pool, restoreAnchorProvider, controlRetention: createUnavailableControlRetention()}),
    {code: 'memory:restore-provider-ambiguous'})
  assert.equal(callbackCalls, 0); assert.equal(fixture.calls(), 0)
})
