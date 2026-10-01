import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { createPrimeTransport } from '../adapters/transport.mjs'
import { createBrowserPasskeySigner } from '../adapters/passkey.mjs'

// Optional path is a read-only integration contract input, never a runtime dependency.
const contracts = await import(process.argv[2] ? pathToFileURL(process.argv[2]).href : new URL('../../contracts/src/runtime.mjs', import.meta.url).href)
const clock = Date.parse('2030-01-01T00:00:00Z')
const expiry = '2030-01-01T00:05:00Z'
const operation = {
  version: 1, operation_id: 'disposable-op', task_id: 'disposable-task', owner_id: 'disposable-owner',
  agent_id: 'disposable-agent', audience: 'prime:memory', action_type: 'memory.put',
  target_identity: { scope: 'disposable', record: 'fixture-only' },
  canonical_parameters: { text: 'Public fixture note', source_revision: 'fixture-v1' },
  data_scope: ['public-fixture'], expected_state_version: 'empty',
  provider_and_region: { provider: 'none', region: 'none' }, maximum_cost: { currency: 'USD', amount: '0.00' },
  expiry, nonce: 'disposable-nonce', policy_version: 'fixture-v1', authorization_epoch: 1,
}

function fixture(overrides = {}) {
  const counts = { login: 0, sign: 0, approve: 0, decline: 0 }
  const authority = {
    async loginChallenge({ owner_id, kind }) {
      counts.login++
      if (kind === 'passkey') return { ok: false, error_code: 'UNAVAILABLE', reason: 'passkey-verifier-not-configured' }
      return { ok: true, challenge: { version: 1, owner_id, audience: 'prime:login', challenge: 'fixture-challenge',
        issued_at: '2030-01-01T00:00:00Z', expiry, authorization_epoch: 1 } }
    },
    async loginComplete({ challenge }) {
      return { ok: true, session_token: 'fixture-in-memory-only', owner_id: challenge.owner_id, expiry }
    },
    async approvalChallenge({ operation }) {
      const digest = await contracts.operationDigest(operation)
      const request = { domain: 'aukora:owner-approval-request:v1', subject: 'aukora:1:' + '1'.repeat(64),
        activeControlDigest: '2'.repeat(64), operationDigest: digest.slice(7), challenge: '3'.repeat(64),
        issuedAt: Math.floor(clock / 1000), expiresAt: Math.floor(clock / 1000) + 120 }
      return { ok: true, operation, operation_digest: digest,
        approval_request: request,
        proof_template: { version: 1, operation_id: operation.operation_id, operation_digest: digest,
          owner_id: operation.owner_id, audience: operation.audience, authorization_epoch: operation.authorization_epoch,
          expiry: new Date(request.expiresAt * 1000).toISOString(), nonce: request.challenge,
          material: { kind: 'owner_key', request, signature: '' } } }
    },
    async approvalComplete({ proof }) { counts.approve++; return { ok: true, approval_proof: proof, status: 'APPROVED' } },
    async declineApproval() { counts.decline++; return { ok: true, status: 'DENIED' } },
    ...overrides.authority,
  }
  const ownerSigner = overrides.ownerSigner ?? (async ({ request, purpose }) => {
    counts.sign++
    return { kind: 'owner_key', ...(purpose === 'approval' ? { request } : {}), signature: 'fixture-only-not-a-real-signature' }
  })
  const transport = createPrimeTransport({ authority, contracts, ownerSigner, now: () => clock })
  return { transport, counts, authority }
}
const rejects = (promise, code) => assert.rejects(promise, error => error.code === code)
const login = f => f.transport.login({ owner_id: operation.owner_id, kind: 'owner_key' })
let cases = 0

{
  const f = fixture()
  await login(f)
  assert.equal(Object.hasOwn(f.transport.owner(), 'session_token'), false)
  const caller = structuredClone(operation)
  const view = await f.transport.prepareApproval(caller)
  caller.maximum_cost.amount = '999.00'
  assert.equal(view.operation.maximum_cost.amount, '0.00')
  assert.equal(view.rows.length, Object.keys(operation).length)
  assert.deepEqual(view.rows.map(row => row.key).sort(), Object.keys(operation).sort())
  assert.equal(view.operation_digest, await contracts.operationDigest(operation))
  assert.throws(() => { view.operation.canonical_parameters.text = 'changed' }, TypeError)
  await rejects(f.transport.approve({ ...view }, { kind: 'owner_key' }), 'INVALID')
  const results = await Promise.all([f.transport.approve(view, { kind: 'owner_key' }), f.transport.approve(view, { kind: 'owner_key' })])
  assert.equal(f.counts.approve, 1)
  assert(results.every(result => result.status === 'APPROVED'))
  await rejects(f.transport.approve(view, { kind: 'owner_key' }), 'REPLAYED')
  cases++
}
{
  const f = fixture({ authority: { async approvalChallenge({ operation }) {
    const answer = await fixture().authority.approvalChallenge({ operation })
    return { ...answer, operation: { ...operation, target_identity: { scope: 'another-owner' } } }
  } } })
  await login(f)
  await rejects(f.transport.prepareApproval(operation), 'TARGET_MISMATCH')
  assert.equal(f.counts.approve, 0)
  cases++
}
{
  const f = fixture({ authority: { async approvalComplete() { f.counts.approve++; throw new Error('fixture transport lost after submission') } } })
  await login(f)
  const view = await f.transport.prepareApproval(operation)
  await rejects(f.transport.approve(view, { kind: 'owner_key' }), 'OUTCOME_UNKNOWN')
  await rejects(f.transport.approve(view, { kind: 'owner_key' }), 'OUTCOME_UNKNOWN')
  assert.equal(f.counts.approve, 1)
  cases++
}
{
  const f = fixture()
  await rejects(f.transport.login({ owner_id: operation.owner_id }), 'UNAVAILABLE')
  assert.equal(f.counts.sign, 0)
  assert.equal(f.transport.owner(), null)
  await login(f)
  await rejects(f.transport.prepareApproval({ ...operation, expiry: '2029-12-31T23:59:59Z' }), 'EXPIRED')
  await rejects(f.transport.prepareApproval({ ...operation, owner_id: 'other-owner' }), 'UNAUTHORIZED')
  const view = await f.transport.prepareApproval(operation)
  assert.equal((await f.transport.decline(view)).status, 'DENIED')
  await rejects(f.transport.approve(view, { kind: 'owner_key' }), 'REPLAYED')
  assert.equal(f.counts.approve, 0)
  cases++
}
{
  let release
  const gate = new Promise(resolve => { release = resolve })
  const f = fixture({ ownerSigner: async ({ request, purpose }) => {
    if (purpose === 'approval') await gate
    return { kind: 'owner_key', ...(purpose === 'approval' ? { request } : {}), signature: 'fixture-only' }
  } })
  await login(f)
  const view = await f.transport.prepareApproval(operation)
  const pending = f.transport.approve(view, { kind: 'owner_key' })
  f.transport.logout()
  release()
  await rejects(pending, 'UNAUTHORIZED')
  assert.equal(f.counts.approve, 0)
  cases++
}
{
  let credentialCalls = 0
  const request = { version: 1, owner_id: operation.owner_id, audience: 'prime:login', challenge: 'fixture-challenge',
    issued_at: '2030-01-01T00:00:00Z', expiry, authorization_epoch: 1 }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('aukora-prime.owner-login.v1\0' + contracts.canonicalJson(request)))
  const public_key = { challenge: Buffer.from(digest).toString('base64url'), rpId: 'fixture.invalid',
    allowCredentials: [{ type: 'public-key', id: 'AQID' }], userVerification: 'required', timeout: 60000 }
  const signer = createBrowserPasskeySigner({ contracts, getCredential: async ({ publicKey }) => {
    credentialCalls++
    assert.equal(publicKey.userVerification, 'required')
    assert.deepEqual([...publicKey.allowCredentials[0].id], [1, 2, 3])
    return { type: 'public-key', rawId: Uint8Array.of(1, 2, 3), response: {
      clientDataJSON: Uint8Array.of(4), authenticatorData: Uint8Array.of(5), signature: Uint8Array.of(6), userHandle: null,
    } }
  } })
  const assertion = await signer({ purpose: 'login', request, public_key })
  assert.deepEqual(assertion, { kind: 'passkey', credential_id: 'AQID', client_data_json: 'BA', authenticator_data: 'BQ', signature: 'Bg', user_handle: null })
  await rejects(signer({ purpose: 'login', request, public_key: { ...public_key, challenge: 'AQID' } }), 'TARGET_MISMATCH')
  await rejects(signer({ purpose: 'login', request, public_key: null }), 'UNAVAILABLE')
  assert.equal(credentialCalls, 1)
  cases++
}
console.log(JSON.stringify({ result: 'PASS', cases, scope: 'disposable injected transport regression',
  live_auth: 'UNPERFORMED', private_keys: 'none', enrollments: 'none', effects: 'none' }))
