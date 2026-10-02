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
    return { kind: 'owner_key', ...(purpose === 'approval' ? { request } : {}), signature: '0'.repeat(128) }
  })
  const transport = createPrimeTransport({ authority, contracts, ownerSigner, now: () => clock })
  return { transport, counts, authority }
}
const rejects = (promise, code) => assert.rejects(promise, error => error.code === code)
const login = f => f.transport.login({ owner_id: operation.owner_id, kind: 'owner_key' })
let cases = 0

// Independent synthetic selected-event context, never reconstructed from a proposal.
const sourceAt = '2030-01-01T00:00:00Z'
const captureMetadata = () => ({ profile:'prime-pilot-memory-capture/v1', category:'fact',
  valid_from:sourceAt.slice(0,10), observed_at:sourceAt, confidence_percent:70, sensitivity:'none' })
const evidenceQuote = 'A separately selected synthetic source quote: café < & > 😀'

{
  const memoryCapture = { statement: '  <script>literal memory</script>\nwith\ttabs 😀  ', attributed_to: 'owner-voice',
    capture_metadata:captureMetadata(), evidence_quote:evidenceQuote }
  const parameters = { capture_sha256: 'a'.repeat(64), idempotency_key_sha256: 'b'.repeat(64),
    heads: { remembered: 'c'.repeat(64) }, ...memoryCapture }
  const proposal = { ...operation, action_type: 'memory.save', canonical_parameters: parameters }
  const f = fixture(); await login(f)
  const view = await f.transport.prepareApproval(proposal, { memoryCapture })
  memoryCapture.statement = 'Caller changed the draft after review'
  assert.equal(view.memory_review.statement, parameters.statement)
  assert.equal(view.memory_review.attributed_to, parameters.attributed_to)
  assert.deepEqual(view.memory_review.capture_metadata, captureMetadata())
  assert.equal(view.memory_review.evidence_quote, evidenceQuote)
  assert(Object.isFrozen(view.memory_review.capture_metadata))
  assert.equal(view.operation_digest, await contracts.operationDigest(proposal))
  assert(Object.isFrozen(view.memory_review))
  await f.transport.approve(view, { kind: 'owner_key' }); assert.equal(f.counts.approve, 1)
  cases++
}
{
  const draft = { statement: 'Exact memory statement', attributed_to: 'owner',
    capture_metadata:captureMetadata(), evidence_quote:evidenceQuote }
  const parameters = { capture_sha256: 'a'.repeat(64), idempotency_key_sha256: 'b'.repeat(64), heads: {}, ...draft }
  const proposal = { ...operation, action_type: 'memory.save', canonical_parameters: parameters }
  let reviews = 0
  const f = fixture({ authority: { async approvalChallenge() { reviews++; throw new Error('Must not request review') } } })
  await login(f)
  for (const memoryCapture of [undefined, { ...draft, statement: 'Changed' }, { ...draft, attributed_to: 'agent' }]) {
    await rejects(f.transport.prepareApproval(proposal, { memoryCapture }), 'TARGET_MISMATCH')
  }
  for (const bad of [
    { capture_sha256: parameters.capture_sha256, idempotency_key_sha256: parameters.idempotency_key_sha256, heads: {} },
    { ...parameters, extra: 'unreviewed' }, { ...parameters, capture_sha256: 'A'.repeat(64) },
    { ...parameters, heads: { unknown: 'a'.repeat(64) } },
  ]) await rejects(f.transport.prepareApproval({ ...proposal, canonical_parameters: bad }, { memoryCapture: draft }), 'TARGET_MISMATCH')
  for (const statement of [' ', 'x'.repeat(4097), 'a\rb', 'a\u061cb', 'a\u200eb', 'a\u200fb', 'a\u202eb', 'a\u2069b', 'a\u0000b', 'a\u007fb']) {
    await rejects(f.transport.prepareApproval({ ...proposal, canonical_parameters: { ...parameters, statement } },
      { memoryCapture: { ...draft, statement } }), 'TARGET_MISMATCH')
  }
  assert.equal(reviews, 0); assert.equal(f.counts.sign, 1); assert.equal(f.counts.approve, 0)
  cases++
}

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
    return { kind: 'owner_key', ...(purpose === 'approval' ? { request } : {}), signature: '0'.repeat(128) }
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
  const profile={profile:'https',origin:'https://fixture.invalid',rp_id:'fixture.invalid'}
  const environment={location:{origin:profile.origin},isSecureContext:true,navigator:{credentials:{get:()=>{throw Error('Real browser API must not be called')}}},PublicKeyCredential:class {}}
  const signer = createBrowserPasskeySigner({ contracts, profile, environment, getCredential: async ({ publicKey }) => {
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
  for(const [changedProfile,changedEnvironment] of [
    [undefined,environment],
    [{profile:'localhost-pilot-v1',origin:'http://127.0.0.1:18731',rp_id:'localhost'},{...environment,location:{origin:'http://127.0.0.1:18731'}}],
    [{profile:'localhost-pilot-v1',origin:'http://localhost:18732',rp_id:'localhost'},environment],
    [profile,{...environment,isSecureContext:false}],
    [profile,{...environment,PublicKeyCredential:undefined}],
    [profile,{...environment,navigator:{}}],
    [profile,{...environment,location:{origin:'https://other.invalid'}}],
  ]) {
    const unavailable=createBrowserPasskeySigner({contracts,profile:changedProfile,environment:changedEnvironment,getCredential:async()=>{credentialCalls++;throw Error('Must not run')}})
    await rejects(unavailable({purpose:'login',request,public_key}),'UNAVAILABLE')
  }
  const pilot=createBrowserPasskeySigner({contracts,profile:{profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'},
    environment:{...environment,location:{origin:'http://localhost:18731'}},getCredential:async()=>null})
  await rejects(pilot({purpose:'login',request,public_key:{...public_key,rpId:'localhost'}}),'CANCELLED')
  assert.equal(credentialCalls,1)
  cases++
}
{
  let release
  const gate = new Promise(resolve => { release = resolve })
  const f = fixture({ authority: { async declineApproval() { f.counts.decline++; await gate; return { ok:true, status:'DENIED' } } } })
  await login(f)
  const view = await f.transport.prepareApproval(operation)
  const one = f.transport.decline(view), two = f.transport.decline(view)
  await rejects(f.transport.approve(view, {kind:'owner_key'}), 'RECONCILIATION_REQUIRED')
  assert.equal(f.counts.decline, 1)
  release()
  const answers = await Promise.all([one,two])
  assert(answers.every(answer => answer.status === 'DENIED'))
  await rejects(f.transport.decline(view), 'REPLAYED')
  assert.equal(f.counts.approve, 0)
  cases++
}
{
  const f = fixture({authority:{async declineApproval() {f.counts.decline++;throw new Error('Lost denial reply')}}})
  await login(f)
  const view = await f.transport.prepareApproval(operation)
  await rejects(f.transport.decline(view), 'OUTCOME_UNKNOWN')
  await rejects(f.transport.decline(view), 'OUTCOME_UNKNOWN')
  await rejects(f.transport.approve(view,{kind:'owner_key'}), 'OUTCOME_UNKNOWN')
  assert.equal(f.counts.decline, 1)
  cases++
}
{
  const f=fixture({authority:{async approvalComplete(){f.counts.approve++;return {ok:true,status:'APPROVED'}}}})
  await login(f);const view=await f.transport.prepareApproval(operation)
  await rejects(f.transport.approve(view,{kind:'owner_key'}),'OUTCOME_UNKNOWN')
  await rejects(f.transport.approve(view,{kind:'owner_key'}),'OUTCOME_UNKNOWN')
  assert.equal(f.counts.approve,1);cases++
}
{
  for (const field of ['approval_request','proof_template']) {
    const f = fixture({authority:{async approvalChallenge(input) {const answer=await fixture().authority.approvalChallenge(input);delete answer[field];return answer}}})
    await login(f)
    await assert.rejects(f.transport.prepareApproval(operation), error=>error.name==='PrimeTransportError'&&error.code==='INVALID')
    assert.equal(f.counts.approve,0)
  }
  for (const material of [undefined,{kind:'owner_key',signature:'0'.repeat(128)}]) {
    const f = fixture({ownerSigner:async({request,purpose})=>purpose==='approval'?material:{kind:'owner_key',signature:'0'.repeat(128)}})
    await login(f)
    const view = await f.transport.prepareApproval(operation)
    await assert.rejects(f.transport.approve(view,{kind:'owner_key'}), error=>error.name==='PrimeTransportError'&&error.code==='INVALID')
    assert.equal(f.counts.approve,0)
  }
  cases++
}
console.log(JSON.stringify({ result: 'PASS', cases, scope: 'disposable injected transport regression',
  live_auth: 'UNPERFORMED', private_keys: 'none', enrollments: 'none', effects: 'none' }))
