// SPDX-License-Identifier: AGPL-3.0-or-later
import { AsyncLocalStorage } from 'node:async_hooks'
import { randomUUID } from 'node:crypto'
import { types } from 'node:util'
import { MemoryRefusal, requireMemory, sha256 } from './codecs.mjs'

const serializers = new WeakSet()
const HOST_FIELDS = ['owner_id', 'owner_subject', 'authorization_epoch']
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
const check = (condition, code) => requireMemory(condition, `memory:owner-session-${code}`)
const safePid = value => Number.isSafeInteger(value) && value > 0

function fields(input, names, code) {
  check(input && typeof input === 'object' && !Array.isArray(input) && !types.isProxy(input)
    && [Object.prototype, null].includes(Object.getPrototypeOf(input)), code)
  const descriptors = Object.getOwnPropertyDescriptors(input)
  check(Reflect.ownKeys(descriptors).length === names.length && names.every(name => descriptors[name]
    && Object.hasOwn(descriptors[name], 'value') && descriptors[name].enumerable), code)
  return Object.fromEntries(names.map(name => [name, descriptors[name].value]))
}

function checkedHost(input) {
  const host = fields(input, HOST_FIELDS, 'host-required')
  check(['owner_id', 'owner_subject'].every(key => typeof host[key] === 'string'
    && host[key].length > 0 && host[key].length <= 4096)
    && Number.isSafeInteger(host.authorization_epoch) && host.authorization_epoch >= 0, 'host-required')
  return Object.freeze(host)
}

function method(object, name, code) {
  check(object && typeof object === 'object' && !types.isProxy(object), code)
  let cursor = object
  while (cursor) {
    const descriptor = Object.getOwnPropertyDescriptor(cursor, name)
    if (descriptor) {
      check(Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function', code)
      return descriptor.value.bind(object)
    }
    cursor = Object.getPrototypeOf(cursor)
    check(!cursor || !types.isProxy(cursor), code)
  }
  check(false, code)
}

function oneRow(result, code) {
  check(result && Array.isArray(result.rows) && result.rows.length === 1, code)
  return result.rows[0]
}

function uncertain(code, cause) {
  const error = new MemoryRefusal(`memory:owner-session-${code}`)
  if (cause !== undefined) error.cause = cause
  return error
}

export const isMemoryOwnerSerializer = value => serializers.has(value)

// A session-level lock survives transaction boundaries. Only this factory's live ALS scope
// exposes its dedicated client; closing the pipeline invalidates all captured scopes.
// The pool is supplied by the trusted host. These SQL observations cannot attest its OS UID.
export function createMemoryOwnerSerializer(input) {
  const {pool} = fields(input, ['pool'], 'configuration-required')
  const connect = method(pool, 'connect', 'pool-required')
  const storage = new AsyncLocalStorage(), owned = new WeakMap()

  function current() {
    const scope = storage.getStore(), state = scope && owned.get(scope)
    return state?.active && !state.uncertain ? scope : null
  }

  async function inspect(scope = current()) {
    const state = scope && owned.get(scope)
    // The trusted private IPC participant may retain this genuine scope while run awaits C.
    // Explicit inspection is read-only and uses its branded active client, even outside ALS.
    // Implicit inspection still resolves only through current() in the originating context.
    check(state?.active && !state.uncertain, 'scope-inactive')
    let result
    try { result = await state.query(INSPECT, [scope.host.owner_subject]) }
    catch (cause) {
      state.uncertain = true
      throw uncertain('inspection-uncertain', cause)
    }
    try {
      const row = oneRow(result, 'inspection-invalid')
      check(row.held === true, 'lock-not-held')
      check(safePid(row.backend_pid) && row.backend_pid === state.backendPid, 'backend-mismatch')
      check(state.active && !state.uncertain, 'scope-inactive')
    } catch (error) { state.uncertain = true; throw error }
    return Object.freeze({kind: 'postgres-owner-session/v1', ...scope.host,
      session_id: state.sessionId, backend_pid: state.backendPid,
      lock_key_sha256: sha256(Buffer.from('aukora-prime.memory-owner-lock.v1\0' + scope.host.owner_subject))})
  }

  async function run(inputHost, work) {
    const host = checkedHost(inputHost)
    check(typeof work === 'function', 'work-required')
    const prior = storage.getStore()
    if (prior) {
      check(current() === prior, 'scope-inactive')
      check(HOST_FIELDS.every(key => prior.host[key] === host[key]), 'nested-owner-mismatch')
      await inspect(prior)
      return work(prior)
    }
    let client
    try { client = await connect() }
    catch (cause) { throw uncertain('connect-uncertain', cause) }
    let query, release
    try {
      query = method(client, 'query', 'client-required')
      release = method(client, 'release', 'client-required')
    } catch (error) {
      // A PoolClient must have a callable release before it can be considered owned safely.
      try { method(client, 'release', 'client-required')(true) } catch {}
      throw error
    }
    const state = {active: false, uncertain: false, query, backendPid: null, sessionId: randomUUID()}
    let scope, value, failure, cleanupFailure
    try {
      let result
      try { result = await query(ACQUIRE, [host.owner_subject]) }
      catch (cause) { state.uncertain = true; throw uncertain('lock-uncertain', cause) }
      try {
        const row = oneRow(result, 'lock-result-invalid')
        check(safePid(row.backend_pid), 'backend-invalid')
        state.backendPid = row.backend_pid
      } catch (error) { state.uncertain = true; throw error }
      scope = Object.freeze({client, host})
      owned.set(scope, state)
      state.active = true
      value = await storage.run(scope, async () => {
        await inspect(scope)
        const result = await work(scope)
        await inspect(scope)
        return result
      })
    } catch (error) { failure = error }
    finally {
      state.active = false
      if (!state.uncertain) {
        try {
          const row = oneRow(await query(UNLOCK, [host.owner_subject]), 'unlock-result-invalid')
          check(row.unlocked === true, 'unlock-not-confirmed')
        } catch (cause) {
          state.uncertain = true
          cleanupFailure = cause instanceof MemoryRefusal ? cause : uncertain('unlock-uncertain', cause)
        }
      }
      try { release(state.uncertain ? true : undefined) }
      catch (cause) { cleanupFailure ??= uncertain('release-uncertain', cause) }
    }
    if (cleanupFailure) {
      if (failure) cleanupFailure.cause = failure
      throw cleanupFailure
    }
    if (failure) throw failure
    return value
  }

  const serializer = Object.freeze({run, current, inspect})
  serializers.add(serializer)
  return serializer
}
