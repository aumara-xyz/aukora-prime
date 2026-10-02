import nodeAssert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { createPrimeTransport } from '../../adapters/transport.mjs'
import { createPrimeOwnerController, createHttpAuthority } from '../src/client/controller.mjs'
import { createOwnerUiFixture } from './fixture.mjs'

// SOURCE checks only: every authority reply, session token and assertion is synthetic.
// Invoke with the exact supplied browser.mjs or runtime.mjs contract helper path.
const contracts = await import(process.argv[2] ? pathToFileURL(process.argv[2]).href
  : new URL('../../../contracts/src/runtime.mjs', import.meta.url).href)
let cases = 0, assertions = 0
const assert = new Proxy(nodeAssert, {
  apply(target, receiver, args) { assertions++; return Reflect.apply(target, receiver, args) },
  get(target, key) {
    const value = Reflect.get(target, key)
    return typeof value === 'function' ? (...args) => { assertions++; return Reflect.apply(value, target, args) } : value
  },
})
const clock = Date.parse('2030-01-01T00:00:00Z')
const token = 'synthetic-in-memory-only'
const confirmed = { ok: true, status: 'LOGGED_OUT' }
const deferred = () => {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
async function bounded(promise) {
  let timer
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('logout-check:fixture-timeout')), 5000)
  })]) } finally { clearTimeout(timer) }
}
async function test(name, work) {
  try { await work(); cases++ }
  catch (error) { error.message = `logout-check:${name}: ${error.message}`; throw error }
}
function fixture({ answer = confirmed, logout, missing = false, challengeGate, signerGate, loginGate } = {}) {
  const base = createOwnerUiFixture(contracts, { now: () => clock, loginGate: loginGate?.promise })
  const calls = { challenge: 0, signer: 0, complete: 0, logout: [] }
  const entered = { challenge: deferred(), signer: deferred(), complete: deferred() }
  let sharedAuthenticated = false, sharedRevision = 0
  const authority = {
    ...base.authority,
    async loginChallenge(input, options) {
      calls.challenge++; entered.challenge.resolve()
      await challengeGate?.promise
      return base.authority.loginChallenge(input, options)
    },
    async loginComplete(input, options) {
      calls.complete++; entered.complete.resolve()
      const current = sharedRevision
      const response = await base.authority.loginComplete(input, options)
      if (current === sharedRevision) sharedAuthenticated = true
      return response
    },
  }
  if (!missing) authority.logout = input => {
    calls.logout.push(structuredClone(input))
    // Fake shared-adapter local invalidation must occur before any asynchronous reply.
    sharedRevision++; sharedAuthenticated = false
    return logout ? logout(input) : answer
  }
  const binding = { ...base, authority, passkeySigner: async input => {
    calls.signer++; entered.signer.resolve()
    await signerGate?.promise
    return base.passkeySigner(input)
  } }
  const transport = createPrimeTransport({ ...binding, now: () => clock })
  const controller = createPrimeOwnerController({ now: () => clock, schedule: () => 1, unschedule() {} })
  controller.connect(binding)
  return { binding, transport, controller, calls, entered, sharedAuthenticated: () => sharedAuthenticated }
}
const loginTransport = f => f.transport.login({ owner_id: f.binding.owner_id, kind: 'passkey' })
function noPublicSecret(value) {
  const text = JSON.stringify(value)
  assert.equal(text.includes(token), false)
  assert.equal(text.includes('session_token'), false)
  assert.equal(text.includes('client_data_json'), false)
  assert.equal(text.includes('authenticator_data'), false)
  assert.equal(text.includes('signature'), false)
}
function unconfirmed(result, code, reason) {
  assert.deepEqual(result, { ok: false, error_code: code,
    reason: reason ?? (code === 'UNAVAILABLE' ? 'ui:server-logout-unavailable'
      : code === 'UNAUTHORIZED' ? 'ui:server-logout-refused' : 'ui:server-logout-not-confirmed') })
  assert(Object.isFrozen(result))
  noPublicSecret(result)
}

await test('transport-immediate-invalidation-coalescing-and-reauth-gate', async () => {
  const gate = deferred(), f = fixture({ logout: () => gate.promise })
  await loginTransport(f)
  assert.equal(f.sharedAuthenticated(), true)
  const first = f.transport.logout(), duplicate = f.transport.logout()
  assert.equal(f.transport.owner(), null)
  assert.equal(f.sharedAuthenticated(), false)
  assert.equal(f.calls.logout.length, 1)
  assert.deepEqual(f.calls.logout[0], { session_token: token })
  assert.equal(first, duplicate)
  const before = { challenge: f.calls.challenge, signer: f.calls.signer, complete: f.calls.complete }
  await assert.rejects(loginTransport(f), error => error.code === 'RECONCILIATION_REQUIRED' && error.message === 'ui:logout-pending')
  assert.deepEqual({ challenge: f.calls.challenge, signer: f.calls.signer, complete: f.calls.complete }, before)
  gate.resolve(confirmed)
  assert.deepEqual(await bounded(first), confirmed)
  assert.equal(f.transport.owner(), null)
  await loginTransport(f)
  assert.equal(f.transport.owner().owner_id, f.binding.owner_id)
  noPublicSecret(f.transport.owner())
})

for (const [name, answer] of [
  ['missing-status', { ok: true }], ['wrong-status', { ok: true, status: 'SIGNED_OUT' }],
  ['extra-field', { ...confirmed, session_token: token }], ['null', null], ['array', [confirmed]],
  ['string', 'LOGGED_OUT'], ['truthy-ok', { ok: 1, status: 'LOGGED_OUT' }],
  ['refusal-as-success', { ok: false, status: 'LOGGED_OUT' }],
]) await test(`transport-strict-ack-${name}`, async () => {
  const f = fixture({ answer }); await loginTransport(f)
  unconfirmed(await f.transport.logout(), 'OUTCOME_UNKNOWN')
  assert.equal(f.transport.owner(), null)
  unconfirmed(await f.transport.logout(), 'OUTCOME_UNKNOWN')
  assert.equal(f.calls.logout.length, 1)
})

for (const code of ['UNAVAILABLE', 'UNAUTHORIZED']) await test(`transport-named-refusal-${code}`, async () => {
  const f = fixture({ answer: { ok: false, error_code: code, reason: `unsafe detail ${token}` } })
  await loginTransport(f)
  unconfirmed(await f.transport.logout(), code)
  assert.equal(f.transport.owner(), null)
})

for (const [name, options, code] of [
  ['missing-method', { missing: true }, 'UNAVAILABLE'],
  ['sync-throw', { logout() { throw new Error(`unsafe detail ${token}`) } }, 'OUTCOME_UNKNOWN'],
  ['rejection', { logout: () => Promise.reject(new Error(`unsafe detail ${token}`)) }, 'OUTCOME_UNKNOWN'],
]) await test(`transport-no-confirmation-${name}`, async () => {
  const f = fixture(options); await loginTransport(f)
  unconfirmed(await f.transport.logout(), code)
  assert.equal(f.transport.owner(), null)
  unconfirmed(await f.transport.logout(), code)
  assert.equal(f.calls.logout.length, options.missing ? 0 : 1)
})

await test('transport-pending-challenge-does-not-invoke-late-signer', async () => {
  const challengeGate = deferred(), f = fixture({ challengeGate })
  const pending = loginTransport(f)
  await bounded(f.entered.challenge.promise)
  const end = f.transport.logout()
  assert.equal(f.transport.owner(), null)
  assert.deepEqual(f.calls.logout, [{}])
  challengeGate.resolve()
  await assert.rejects(bounded(pending), error => error.code === 'CANCELLED')
  await bounded(end)
  assert.equal(f.calls.signer, 0)
  assert.equal(f.calls.complete, 0)
  assert.equal(f.transport.owner(), null)
})

await test('transport-pending-signer-does-not-complete-login', async () => {
  const signerGate = deferred(), f = fixture({ signerGate })
  const pending = loginTransport(f)
  await bounded(f.entered.signer.promise)
  await f.transport.logout()
  signerGate.resolve()
  await assert.rejects(bounded(pending), error => error.code === 'CANCELLED')
  assert.equal(f.calls.complete, 0)
  assert.equal(f.transport.owner(), null)
})

await test('transport-pending-completion-cannot-restore-owner', async () => {
  const loginGate = deferred(), logoutGate = deferred(), f = fixture({ loginGate, logout: () => logoutGate.promise })
  const pending = loginTransport(f)
  await bounded(f.entered.complete.promise)
  const end = f.transport.logout()
  assert.deepEqual(f.calls.logout, [{}])
  await assert.rejects(loginTransport(f), error => error.code === 'RECONCILIATION_REQUIRED')
  loginGate.resolve()
  await assert.rejects(bounded(pending), error => error.code === 'CANCELLED')
  assert.equal(f.transport.owner(), null)
  assert.equal(f.sharedAuthenticated(), false)
  logoutGate.resolve(confirmed); await bounded(end)
  assert.equal(f.transport.owner(), null)
})

await test('controller-immediate-clear-shared-invalidate-status-and-coalescing', async () => {
  const gate = deferred(), f = fixture({ logout: () => gate.promise })
  await f.controller.login(); await f.controller.prepare(); await f.controller.approve()
  const observations = []
  const stop = f.controller.subscribe(() => observations.push(f.controller.getSnapshot().owner))
  const first = f.controller.logout(), duplicate = f.controller.logout()
  const state = f.controller.getSnapshot()
  assert.equal(state.owner, null); assert.equal(state.presentation, null)
  assert.equal(state.logout_status, 'pending'); assert.equal(state.logout_error_code, null)
  assert.equal(f.sharedAuthenticated(), false); assert.equal(f.calls.logout.length, 1)
  assert(observations.includes(null)); noPublicSecret(state)
  const before = f.calls.challenge
  assert.equal(await f.controller.login(), null)
  assert.equal(f.calls.challenge, before)
  assert.equal(f.controller.getSnapshot().logout_status, 'pending')
  gate.resolve(confirmed)
  assert.deepEqual(await bounded(first), confirmed)
  assert.deepEqual(await bounded(duplicate), confirmed)
  assert.equal(f.controller.getSnapshot().logout_status, 'confirmed')
  assert.equal(f.controller.getSnapshot().logout_error_code, null)
  await f.controller.login(); assert(f.controller.getSnapshot().owner)
  stop(); f.controller.dispose()
})

for (const [code, status, options] of [
  ['UNAVAILABLE', 'unavailable', { missing: true }],
  ['UNAUTHORIZED', 'refused', { answer: { ok: false, error_code: 'UNAUTHORIZED', reason: token } }],
  ['OUTCOME_UNKNOWN', 'unknown', { logout: () => Promise.reject(new Error(token)) }],
  ['OUTCOME_UNKNOWN', 'unknown', { answer: { ...confirmed, extra: true } }],
]) await test(`controller-terminal-status-${status}-${options.missing ? 'missing' : options.answer?.extra ? 'malformed' : 'reply'}`, async () => {
  const f = fixture(options); await f.controller.login()
  unconfirmed(await f.controller.logout(), code, 'ui:server-logout-not-confirmed')
  const state = f.controller.getSnapshot()
  assert.equal(state.owner, null); assert.equal(state.presentation, null)
  assert.equal(state.logout_status, status); assert.equal(state.logout_error_code, code)
  noPublicSecret(state)
  await f.controller.logout()
  assert.equal(f.calls.logout.length, options.missing ? 0 : 1)
  f.controller.dispose()
})

await test('controller-pending-login-late-reply-is-cancelled', async () => {
  const loginGate = deferred(), logoutGate = deferred(), f = fixture({ loginGate, logout: () => logoutGate.promise })
  const pending = f.controller.login()
  await bounded(f.entered.complete.promise)
  const end = f.controller.logout()
  assert.equal(f.controller.getSnapshot().owner, null)
  assert.equal(f.controller.getSnapshot().logout_status, 'pending')
  loginGate.resolve(); assert.equal(await bounded(pending), null)
  assert.equal(f.controller.getSnapshot().owner, null)
  assert.equal(f.controller.getSnapshot().logout_status, 'pending')
  logoutGate.resolve(confirmed); await bounded(end)
  assert.equal(f.controller.getSnapshot().logout_status, 'confirmed')
  assert.equal(f.controller.getSnapshot().owner, null)
  f.controller.dispose()
})

await test('controller-login-observer-logout-cancels-before-any-auth-call', async () => {
  const f = fixture()
  let end, cancelled = false
  const stop = f.controller.subscribe(() => {
    if (!cancelled && f.controller.getSnapshot().phase === 'login_pending') {
      cancelled = true
      end = f.controller.logout()
    }
  })
  assert.equal(await bounded(f.controller.login()), null)
  await bounded(end)
  assert.equal(f.calls.challenge, 0); assert.equal(f.calls.signer, 0); assert.equal(f.calls.complete, 0)
  assert.equal(f.calls.logout.length, 1)
  assert.equal(f.controller.getSnapshot().owner, null)
  assert.equal(f.controller.getSnapshot().logout_status, 'confirmed')
  stop(); f.controller.dispose()
})

await test('controller-logout-observer-click-coalesces-before-host-invocation', async () => {
  const gate = deferred(), f = fixture({ logout: () => gate.promise })
  await f.controller.login()
  let second, clicked = false
  const stop = f.controller.subscribe(() => {
    if (!clicked && f.controller.getSnapshot().logout_status === 'pending') {
      clicked = true
      second = f.controller.logout()
    }
  })
  const first = f.controller.logout()
  assert.equal(f.calls.logout.length, 1); assert.equal(f.controller.getSnapshot().owner, null)
  gate.resolve(confirmed)
  assert.deepEqual(await bounded(first), confirmed); assert.deepEqual(await bounded(second), confirmed)
  assert.equal(f.controller.getSnapshot().logout_status, 'confirmed')
  stop(); f.controller.dispose()
})

await test('controller-old-ack-cannot-overwrite-reconnected-owner', async () => {
  const gate = deferred(), f = fixture({ logout: () => gate.promise }), next = fixture()
  await f.controller.login()
  const old = f.controller.logout()
  f.controller.connect(next.binding)
  assert.equal(f.controller.getSnapshot().owner, null)
  // A reconnect must retain the revocation flight gate until the old reply settles.
  assert.equal(await f.controller.login(), null)
  assert.equal(next.calls.challenge, 0)
  gate.resolve(confirmed); await bounded(old)
  await f.controller.login()
  assert.equal(f.controller.getSnapshot().owner.owner_id, next.binding.owner_id)
  assert.equal(f.controller.getSnapshot().logout_status, 'idle')
  assert.equal(f.calls.logout.length, 1)
  f.controller.dispose(); next.controller.dispose()
})

await test('controller-old-rejected-ack-gates-reconnect-then-does-not-poison-fresh-owner', async () => {
  const gate = deferred(), f = fixture({ logout: () => gate.promise }), next = fixture()
  await f.controller.login()
  const old = f.controller.logout()
  f.controller.connect(next.binding)
  assert.equal(await f.controller.login(), null); assert.equal(next.calls.challenge, 0)
  gate.reject(new Error('synthetic old host reply lost'))
  unconfirmed(await bounded(old), 'OUTCOME_UNKNOWN')
  assert.equal(f.controller.getSnapshot().owner, null)
  assert.equal(f.controller.getSnapshot().logout_status, 'unknown')
  await f.controller.login()
  assert(f.controller.getSnapshot().owner)
  assert.equal(f.controller.getSnapshot().logout_status, 'idle')
  assert.equal(f.controller.getSnapshot().logout_error_code, null)
  assert.equal(f.calls.logout.length, 1)
  f.controller.dispose(); next.controller.dispose()
})

await test('controller-disconnect-old-ack-stays-detached', async () => {
  const gate = deferred(), f = fixture({ logout: () => gate.promise })
  await f.controller.login()
  const end = f.controller.disconnect()
  assert.equal(f.calls.logout.length, 1)
  const detached = f.controller.getSnapshot()
  assert.equal(detached.owner, null); assert.equal(detached.presentation, null)
  assert.equal(detached.authority_available, false); noPublicSecret(detached)
  gate.resolve(confirmed)
  assert.deepEqual(await bounded(end), confirmed)
  assert.equal(f.controller.getSnapshot().owner, null)
  assert.equal(f.controller.getSnapshot().phase, 'unavailable')
  assert.equal(f.controller.getSnapshot().logout_status, 'confirmed')
  f.controller.dispose()
})

await test('controller-connect-and-dispose-revoke-before-listener-detach', async () => {
  const f = fixture(), next = fixture()
  await f.controller.login()
  f.controller.connect(next.binding)
  assert.equal(f.calls.logout.length, 1); assert.equal(f.sharedAuthenticated(), false)
  await new Promise(resolve => setImmediate(resolve))
  await f.controller.login()
  assert(f.controller.getSnapshot().owner)
  const observed = []
  f.controller.subscribe(() => observed.push(f.controller.getSnapshot().owner))
  f.controller.dispose()
  assert.equal(next.calls.logout.length, 1); assert.equal(next.sharedAuthenticated(), false)
  assert.equal(observed.at(-1), null); assert.equal(f.controller.getSnapshot().owner, null)
  next.controller.dispose()
})

await test('http-exact-route-text-ingress-and-no-token-no-fetch', async () => {
  const requests = []
  const authority = createHttpAuthority(async (url, options) => {
    requests.push({ url, options })
    return { ok: true, text: async () => '{"ok":true,"status":"LOGGED_OUT"}',
      json() { throw new Error('logout-check:parsed-json-api-must-not-be-used') } }
  }, contracts)
  assert.deepEqual(await authority.logout({}), { ok: false, error_code: 'UNAUTHORIZED', reason: 'ui:no-known-server-session' })
  assert.equal(requests.length, 0)
  assert.deepEqual(await authority.logout({ session_token: token }), confirmed)
  assert.equal(requests.length, 1)
  assert.equal(requests[0].url, '/api/prime/authority/logoutSession')
  assert.equal(requests[0].options.method, 'POST'); assert.equal(requests[0].options.credentials, 'same-origin')
  assert.equal(requests[0].options.redirect, 'error'); assert.equal(requests[0].options.cache, 'no-store')
  assert.deepEqual(JSON.parse(requests[0].options.body), { session_token: token })
})

for (const [name, text] of [
  ['duplicate-key', '{"ok":true,"status":"LOGGED_OUT","status":"DENIED"}'],
  ['escaped-duplicate-key', '{"ok":true,"status":"LOGGED_OUT","sta\\u0074us":"DENIED"}'],
  ['invalid-json', '{"ok":true'],
]) await test(`http-invalid-text-${name}`, async () => {
  let count = 0
  const authority = createHttpAuthority(async () => { count++; return { ok: true, text: async () => text } }, contracts)
  const f = fixture(); f.binding.authority.logout = authority.logout
  const transport = createPrimeTransport({ ...f.binding, now: () => clock })
  await transport.login({ owner_id: f.binding.owner_id, kind: 'passkey' })
  unconfirmed(await transport.logout(), 'OUTCOME_UNKNOWN')
  unconfirmed(await transport.logout(), 'OUTCOME_UNKNOWN')
  assert.equal(count, 1); assert.equal(transport.owner(), null)
})

await test('http-network-failure-never-confirms-or-retries', async () => {
  let count = 0
  const authority = createHttpAuthority(async () => { count++; throw new Error('synthetic network rejection') }, contracts)
  const f = fixture(); f.binding.authority.logout = authority.logout
  const transport = createPrimeTransport({ ...f.binding, now: () => clock })
  await transport.login({ owner_id: f.binding.owner_id, kind: 'passkey' })
  unconfirmed(await transport.logout(), 'OUTCOME_UNKNOWN')
  unconfirmed(await transport.logout(), 'OUTCOME_UNKNOWN')
  assert.equal(count, 1); assert.equal(transport.owner(), null)
})

await test('http-non-success-status-cannot-authorize-confirmed-body', async () => {
  let count = 0
  const authority = createHttpAuthority(async () => {
    count++; return { ok: false, text: async () => JSON.stringify(confirmed) }
  }, contracts)
  const f = fixture(); f.binding.authority.logout = authority.logout
  const transport = createPrimeTransport({ ...f.binding, now: () => clock })
  await transport.login({ owner_id: f.binding.owner_id, kind: 'passkey' })
  unconfirmed(await transport.logout(), 'OUTCOME_UNKNOWN')
  unconfirmed(await transport.logout(), 'OUTCOME_UNKNOWN')
  assert.equal(count, 1); assert.equal(transport.owner(), null)
})

console.log(JSON.stringify({ result: 'PASS', cases, assertions, scope: 'SOURCE synthetic logout seam',
  actual_authority_audit: false, actual_memory_audit: false, real_credentials: false, real_enrollment: false,
  real_authentication: false, effects: false, network: false, runtime: false }))
