// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { AsyncResource } from 'node:async_hooks'
import { createMemoryOwnerSerializer, isMemoryOwnerSerializer } from '../src/owner-serialization.mjs'
import { MemoryRefusal, sha256 } from '../src/codecs.mjs'

// Ordinary source fixtures only: this client models exact SQL observations and cleanup.
// No PostgreSQL connection, database locking or process identity boundary is exercised.
const ACQUIRE = 'SELECT pg_advisory_lock(hashtextextended($1, 0)), pg_backend_pid() AS backend_pid'
const INSPECT = `SELECT pg_backend_pid() AS backend_pid, EXISTS (
  SELECT 1 FROM pg_locks
  WHERE locktype = 'advisory' AND mode = 'ExclusiveLock' AND granted = true
    AND pid = pg_backend_pid()
    AND classid = ((hashtextextended($1, 0) >> 32) & 4294967295)::oid
    AND objid = (hashtextextended($1, 0) & 4294967295)::oid
    AND objsubid = 1
) AS held`
const UNLOCK = 'SELECT pg_advisory_unlock(hashtextextended($1, 0)) AS unlocked'
const host = {owner_id: 'fixture-owner-id', owner_subject: 'fixture-owner-subject', authorization_epoch: 4}

function fixture({inspection = {held: true, backend_pid: 321}, unlock = {unlocked: true}, acquire = {backend_pid: 321}} = {}) {
  const calls = [], releases = [], client = {
    async query(sql, parameters) {
      calls.push({sql, parameters})
      if (sql === ACQUIRE) return {rows: [acquire]}
      if (sql === INSPECT) {
        if (inspection instanceof Error) throw inspection
        return {rows: [inspection]}
      }
      if (sql === UNLOCK) {
        if (unlock instanceof Error) throw unlock
        return {rows: [unlock]}
      }
      if (['BEGIN', 'COMMIT'].includes(sql)) return {rows: []}
      throw new Error('fixture received unexpected SQL')
    },
    release(destroy) { releases.push(destroy) }
  }
  let connects = 0
  const pool = {async connect() { connects++; return client }}
  return {serializer: createMemoryOwnerSerializer({pool}), client, calls, releases, connects: () => connects}
}

test('dedicated owner client spans asynchronous work and both transactions, then becomes inactive', async () => {
  const f = fixture(), serializer = f.serializer
  assert.equal(isMemoryOwnerSerializer(serializer), true)
  assert.equal(isMemoryOwnerSerializer({...serializer}), false)
  assert.equal(isMemoryOwnerSerializer({inspect: async () => true}), false)
  assert.equal(serializer.current(), null)
  let captured
  const result = await serializer.run(host, async scope => {
    captured = scope
    assert.equal(scope, serializer.current())
    assert.equal(scope.client, f.client)
    assert.equal(Object.isFrozen(scope), true)
    assert.equal(Object.isFrozen(scope.host), true)
    await scope.client.query('BEGIN')
    await scope.client.query('COMMIT')
    await Promise.resolve()
    const observation = await serializer.inspect()
    assert.deepEqual(Object.keys(observation).sort(), ['kind', ...Object.keys(host), 'session_id', 'backend_pid', 'lock_key_sha256'].sort())
    assert.equal(observation.kind, 'postgres-owner-session/v1')
    assert.equal(observation.backend_pid, 321)
    assert.match(observation.session_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    assert.equal(observation.lock_key_sha256, sha256(Buffer.from('aukora-prime.memory-owner-lock.v1\0' + host.owner_subject)))
    await scope.client.query('BEGIN')
    await scope.client.query('COMMIT')
    return 'effect-and-publication-complete'
  })
  assert.equal(result, 'effect-and-publication-complete')
  assert.equal(f.connects(), 1)
  assert.equal(f.calls.filter(call => call.sql === ACQUIRE).length, 1)
  assert.equal(f.calls.at(-1).sql, UNLOCK)
  for (const call of f.calls.filter(call => [ACQUIRE, INSPECT, UNLOCK].includes(call.sql))) {
    assert.deepEqual(call.parameters, [host.owner_subject])
  }
  assert.deepEqual(f.releases, [undefined])
  assert.equal(serializer.current(), null)
  await assert.rejects(serializer.inspect(captured), {code: 'memory:owner-session-scope-inactive'})
})

test('same-owner nested work reuses the held client and foreign or wrong-epoch scopes refuse', async () => {
  const f = fixture(), other = fixture()
  await f.serializer.run(host, async scope => {
    await f.serializer.run({...host}, async nested => assert.equal(nested, scope))
    await assert.rejects(f.serializer.run({...host, owner_subject: 'other-owner'}, async () => {}),
      {code: 'memory:owner-session-nested-owner-mismatch'})
    await assert.rejects(f.serializer.run({...host, authorization_epoch: 5}, async () => {}),
      {code: 'memory:owner-session-nested-owner-mismatch'})
    await assert.rejects(other.serializer.inspect(scope), {code: 'memory:owner-session-scope-inactive'})
    await assert.rejects(f.serializer.inspect({client: scope.client, host: scope.host}),
      {code: 'memory:owner-session-scope-inactive'})
  })
  assert.equal(f.connects(), 1)
  assert.equal(other.connects(), 0)
  assert.deepEqual(f.releases, [undefined])
})

test('private participant explicitly inspects the genuine active scope outside its ALS context only', async () => {
  const f = fixture(), outside = new AsyncResource('synthetic-private-memory-participant')
  let captured
  try {
    await f.serializer.run(host, async scope => {
      captured = scope
      const observation = await outside.runInAsyncScope(async () => {
        assert.equal(f.serializer.current(), null)
        await assert.rejects(f.serializer.inspect(), {code: 'memory:owner-session-scope-inactive'})
        await assert.rejects(f.serializer.inspect({...scope}), {code: 'memory:owner-session-scope-inactive'})
        return f.serializer.inspect(scope)
      })
      assert.equal(observation.owner_subject, host.owner_subject)
      assert.equal(observation.backend_pid, 321)
      assert.equal(f.serializer.current(), scope)
    })
    await outside.runInAsyncScope(async () => {
      assert.equal(f.serializer.current(), null)
      await assert.rejects(f.serializer.inspect(captured), {code: 'memory:owner-session-scope-inactive'})
    })
  } finally { outside.emitDestroy() }
  assert.deepEqual(f.releases, [undefined])
})

test('truthy or lost lock and changed backend observations refuse and destroy only the owned client', async () => {
  for (const [inspection, code] of [
    [{held: 'true', backend_pid: 321}, 'memory:owner-session-lock-not-held'],
    [{held: false, backend_pid: 321}, 'memory:owner-session-lock-not-held'],
    [{held: true, backend_pid: 322}, 'memory:owner-session-backend-mismatch'],
    [{held: true, backend_pid: '321'}, 'memory:owner-session-backend-mismatch'],
    [new Error('synthetic inspection connection uncertainty'), 'memory:owner-session-inspection-uncertain']
  ]) {
    const f = fixture({inspection})
    let ran = false
    await assert.rejects(f.serializer.run(host, async () => { ran = true }), {code})
    assert.equal(ran, false)
    assert.equal(f.serializer.current(), null)
    assert.deepEqual(f.releases, [true])
    assert.equal(f.calls.some(call => call.sql === UNLOCK), false)
  }
})

test('failed work keeps its exact refusal when confirmed cleanup succeeds', async () => {
  const f = fixture(), refusal = new MemoryRefusal('memory:fixture-action-refused')
  await assert.rejects(f.serializer.run(host, async () => { throw refusal }), error => error === refusal)
  assert.equal(f.calls.at(-1).sql, UNLOCK)
  assert.deepEqual(f.releases, [undefined])
})

test('unconfirmed unlock or invalid acquisition destroys the dedicated client without retry', async () => {
  for (const [unlock, code] of [
    [{unlocked: false}, 'memory:owner-session-unlock-not-confirmed'],
    [{unlocked: 'true'}, 'memory:owner-session-unlock-not-confirmed'],
    [new Error('synthetic unlock connection uncertainty'), 'memory:owner-session-unlock-uncertain']
  ]) {
    const f = fixture({unlock})
    await assert.rejects(f.serializer.run(host, async () => 'applied'), {code})
    assert.deepEqual(f.releases, [true])
    assert.equal(f.calls.filter(call => call.sql === UNLOCK).length, 1)
    assert.equal(f.connects(), 1)
  }
  const badPid = fixture({acquire: {backend_pid: '321'}})
  await assert.rejects(badPid.serializer.run(host, async () => {}), {code: 'memory:owner-session-backend-invalid'})
  assert.deepEqual(badPid.releases, [true])
  assert.equal(badPid.calls.some(call => call.sql === UNLOCK), false)
})

test('host and constructor accept only exact inert required fields before acquiring a client', async () => {
  const f = fixture()
  for (const bad of [{...host, extra: true}, {...host, authorization_epoch: -1}, {...host, owner_subject: []},
    {...host, get owner_id() { throw new Error('getter must not run') }}]) {
    await assert.rejects(f.serializer.run(bad, async () => {}), {code: 'memory:owner-session-host-required'})
  }
  assert.equal(f.connects(), 0)
  assert.throws(() => createMemoryOwnerSerializer({pool: {async connect() {}}, extra: true}),
    {code: 'memory:owner-session-configuration-required'})
})
