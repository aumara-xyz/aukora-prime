// SPDX-License-Identifier: AGPL-3.0-or-later
// Published RFC6979 A.2.5 fixture only, in memory; no real authorization, seed or key generation.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { ownerRootPin } from '../src/index.mjs'
import { AUTHORIZATION_FIELDS, ownerAuthorization, ownerAuthorizationText,
  ownerAuthorizationSigningBytes, ownerAuthorizationDigest, parseOwnerAuthorization,
  ownerAuthorizationProofDigest, verifyOwnerAuthorization, consumeOwnerAuthorization,
  verifyOwnerAuthorizationReference, ownerAuthorizationOwnerState,
  ownerAuthorizationGatePin } from '../src/authorization.mjs'
import { createOwnerAuthorizationBridge } from '../../../apps/aukora-desktop/owner-key-bridge.mjs'

const b64url = hex => Buffer.from(hex, 'hex').toString('base64url')
const fixture = createPrivateKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
  d: b64url('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'),
  x: b64url('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'),
  y: b64url('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299') } })
const spki = createPublicKey(fixture).export({ format: 'der', type: 'spki' }).toString('base64')
const draft = () => ({ version: 1, kind: 'aukora-owner-authorization/v1', operation: 'change',
  proposal_id: '01234567-89ab-4cde-8123-456789abcdef', target: 'plugins/auma-theme/theme.json',
  before_sha256: 'a'.repeat(64), after_sha256: 'b'.repeat(64), gate: 'c'.repeat(64), challenge: 'd'.repeat(64),
  issued_at_ms: 100000, expires_at_ms: 200000, owner_subject: `aukora:1:${'1'.repeat(64)}`,
  owner_root_id: ownerRootPin(spki).owner_root_id, owner_epoch: 1 })
const expected = a => ({ owner_root_spki_base64: spki, authorization_digest: ownerAuthorizationDigest(a),
  ...Object.fromEntries(AUTHORIZATION_FIELDS.map(field => [field, a[field]])) })
const signed = a => ({ algorithm: 'p256-ecdsa-sha256', authorization: a,
  signature_base64: sign('sha256', ownerAuthorizationSigningBytes(a), fixture).toString('base64') })

test('separate signed authorization verifies and exact gate receipt reference resolves', () => {
  const a = draft(), proof = signed(a), e = expected(a), result = verifyOwnerAuthorization(proof, e, 150000)
  assert.equal(result.status, 'verified-owner-authorization'); assert.equal(result.grants_authority, false)
  assert.equal(result.activation, 'UNPERFORMED'); assert.equal(result.custody, 'independent-enrollment-required')
  assert.equal(result.reference.authorization_id, ownerAuthorizationDigest(a))
  assert.equal(result.reference.proof_sha256, ownerAuthorizationProofDigest(proof))
  assert.equal(verifyOwnerAuthorizationReference(proof, result.reference, e, 150000).status, result.status)
  assert(Object.isFrozen(result.proof.authorization)); assert(Object.isFrozen(result.reference))
  const absent = { ...a, before_sha256: 'absent' }
  assert.equal(verifyOwnerAuthorization(signed(absent), expected(absent), 150000).authorization.before_sha256, 'absent')
  const state = { version: 1, kind: 'aukora-owner-state/v1', owner_subject: a.owner_subject,
    owner_root_spki_base64: spki, owner_root_id: a.owner_root_id, owner_epoch: 1,
    registry_sha256: 'e'.repeat(64), activation_sha256: 'f'.repeat(64) }
  assert(Object.isFrozen(ownerAuthorizationOwnerState(state)))
  for (const change of [{ qualified: true }, { owner_epoch: 0 }, { owner_root_id: '0'.repeat(64) },
    { registry_sha256: state.registry_sha256 + '\n' }, { owner_subject: state.owner_subject + '\n' }])
    assert.throws(() => ownerAuthorizationOwnerState({ ...state, ...change }))
  assert.throws(() => ownerAuthorizationOwnerState(Promise.resolve(state)))
  // RFC8032 test1 PUBLIC Ed25519 key; not a secret or new enrollment.
  const gateSpki = createPublicKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519',
    x: b64url('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a') } })
    .export({ format: 'der', type: 'spki' }).toString('base64')
  const gatePin = ownerAuthorizationGatePin(gateSpki)
  assert.equal(gatePin.gate.length, 64); assert.equal(gatePin.pubkey_fp, gatePin.gate.slice(0, 16))
  assert.throws(() => ownerAuthorizationGatePin(spki))
  assert.throws(() => ownerAuthorizationGatePin(gateSpki + '\n'))
})

test('canonical closed authorization refuses ambiguous wire, accessors and approval/seed fields', () => {
  const a = draft(), text = ownerAuthorizationText(a)
  assert.equal(ownerAuthorizationText(parseOwnerAuthorization(text)), text)
  assert.throws(() => parseOwnerAuthorization(text.replace('"version":1', '"version":1,"version":1')))
  assert.throws(() => parseOwnerAuthorization(' ' + text))
  let reads = 0
  const accessor = { ...a }; Object.defineProperty(accessor, 'challenge', { enumerable: true, get() { reads++; return a.challenge } })
  assert.throws(() => ownerAuthorization(accessor)); assert.equal(reads, 0)
  for (const change of [{ approved: true }, { local_seed: 'not-a-key' }, { operation: 'sign-anything' },
    { challenge: a.challenge + '\n' }, { proposal_id: a.proposal_id + '\n' }, { owner_epoch: -0 },
    { expires_at_ms: 220001 }, { issued_at_ms: 0.5 }, { target: 'plugins/../theme.json' },
    { target: '/plugins/auma-theme/theme.json' }, { target: 'plugins/auma-theme\\theme.json' },
    { target: 'plugins/auma-theme/theme.json\n' },
    { after_sha256: a.before_sha256 }]) assert.throws(() => ownerAuthorization({ ...a, ...change }))
})

test('changed operation, target, hashes, gate, challenge, owner and expiry cannot be substituted', () => {
  const a = draft(), proof = signed(a), e = expected(a)
  const changes = { operation: 'revert', target: 'plugins/aukora-plugin-set/approval.json',
    before_sha256: 'e'.repeat(64), after_sha256: 'f'.repeat(64), gate: '2'.repeat(64), challenge: '3'.repeat(64),
    expires_at_ms: 199000, issued_at_ms: 100001, owner_epoch: 2, owner_subject: `aukora:1:${'4'.repeat(64)}`,
    proposal_id: '11234567-89ab-4cde-8123-456789abcdef' }
  for (const [field, value] of Object.entries(changes)) {
    assert.throws(() => verifyOwnerAuthorization({ ...proof, authorization: { ...a, [field]: value } }, e, 150000), field)
    assert.throws(() => verifyOwnerAuthorization(proof, { ...e, [field]: value }, 150000), 'expected ' + field)
  }
  const reissued = { ...a, issued_at_ms: 100001 }
  assert.throws(() => verifyOwnerAuthorization(signed(reissued), e, 150000))
  assert.throws(() => verifyOwnerAuthorization(proof, { ...e, authorization_digest: '5'.repeat(64) }, 150000))
  assert.throws(() => verifyOwnerAuthorization({ ...proof, touch_id: true }, e, 150000))
  // Even the same public fixture key cannot transplant a scoped-binding domain signature.
  const wrongDomain = { ...proof, signature_base64: sign('sha256',
    Buffer.from('aukora:owner-key:scoped-binding:v1\0' + ownerAuthorizationText(a)), fixture).toString('base64') }
  assert.throws(() => verifyOwnerAuthorization(wrongDomain, e, 150000))
  const corrupt = Buffer.from(proof.signature_base64, 'base64'); corrupt[corrupt.length - 1] ^= 1
  assert.throws(() => verifyOwnerAuthorization({ ...proof, signature_base64: corrupt.toString('base64') }, e, 150000))
  const otherRoot = { ...a, owner_root_id: '6'.repeat(64) }
  assert.throws(() => verifyOwnerAuthorization(signed(otherRoot), expected(otherRoot), 150000))
  for (const time of [99999, 200000, 200001, NaN]) assert.throws(() => verifyOwnerAuthorization(proof, e, time))
})

test('receipt reference binds both exact object and exact proof; signer-owned HMAC is insufficient', () => {
  const a = draft(), proof = signed(a), e = expected(a), result = verifyOwnerAuthorization(proof, e, 150000)
  for (const change of [{ authorization_id: '7'.repeat(64) }, { proof_sha256: '8'.repeat(64) },
    { kind: 'gate-hmac-evidence/v2' }, { version: 2 }, { approved: true }])
    assert.throws(() => verifyOwnerAuthorizationReference(proof, { ...result.reference, ...change }, e, 150000))
  assert.throws(() => verifyOwnerAuthorizationReference(proof, { approval_evidence_hmac: 'local-only' }, e, 150000))
  const secondSignature = signed(a)
  // Both valid signatures bind the same object; the gate receipt must select one exact retained proof.
  assert.equal(verifyOwnerAuthorization(secondSignature, e, 150000).reference.authorization_id, result.reference.authorization_id)
  if (secondSignature.signature_base64 !== proof.signature_base64)
    assert.throws(() => verifyOwnerAuthorizationReference(secondSignature, result.reference, e, 150000))
})

test('durable consumption is one-shot across signatures/concurrency; uncertainty has no retry or fallback', async () => {
  const a = draft(), proof = signed(a), second = signed(a), e = expected(a), seen = new Set()
  const consumeOnce = async claim => {
    assert.equal(claim.authorization.gate, a.gate); assert.equal(claim.authorization.expires_at_ms, a.expires_at_ms)
    assert.equal(claim.reference.proof_sha256, ownerAuthorizationProofDigest(claim.proof))
    assert(Object.isFrozen(claim)); assert(Object.isFrozen(claim.proof))
    const replay = claim.authorization.gate + ':' + claim.authorization.challenge
    if (seen.has(replay)) return false
    seen.add(replay); return true
  }
  const results = await Promise.allSettled([consumeOwnerAuthorization(proof, e, { nowMs: 150000, consumeOnce }),
    consumeOwnerAuthorization(second, e, { nowMs: 150000, consumeOnce })])
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1)
  assert.equal(results.filter(r => r.status === 'rejected').length, 1)
  await assert.rejects(consumeOwnerAuthorization(proof, e, { nowMs: 150000 }))
  let calls = 0
  await assert.rejects(consumeOwnerAuthorization(proof, e, { nowMs: 150000, consumeOnce: async () => { calls++; return undefined } }))
  assert.equal(calls, 1)
  // Synthetic host transaction rechecks its own clock after the await. This is a required external join.
  let clock = 150000, finish, effects = 0
  const pending = consumeOwnerAuthorization(proof, e, { nowMs: clock, consumeOnce: async claim => {
    await new Promise(resolve => { finish = resolve })
    if (clock >= claim.authorization.expires_at_ms) return false
    effects++; return true
  } })
  clock = 200001; finish()
  await assert.rejects(pending); assert.equal(effects, 0)
})

test('native bridge freezes exact signed facts and refuses cancellation, substitution, expiry and unavailable signer', async () => {
  const a = draft(), e = expected(a); let finish; let presented
  const bridge = createOwnerAuthorizationBridge({ expectations: e, nowMs: () => 150000,
    presentOwnerAction: value => { presented = value; return new Promise(resolve => { finish = resolve }) } })
  const waiting = bridge.requestAuthorization(a)
  assert.equal((await bridge.requestAuthorization(a)).reason, 'owner-authorization:busy')
  const original = parseOwnerAuthorization(presented.wire); a.after_sha256 = '9'.repeat(64)
  finish({ status: 'signed', proof: signed(original) })
  const result = await waiting; assert.equal(result.status, 'signed-authorization'); assert.equal(result.grants_authority, false)
  assert.equal(presented.preview.after_sha256, original.after_sha256)
  for (const response of [{ status: 'cancelled' }, { approved: true, local_seed: 'not-a-key' },
    { status: 'signed', proof: signed({ ...draft(), challenge: '0'.repeat(64) }) }]) {
    const one = createOwnerAuthorizationBridge({ expectations: expected(draft()), nowMs: () => 150000, presentOwnerAction: async () => response })
    assert.notEqual((await one.requestAuthorization(draft())).status, 'signed-authorization')
  }
  assert.throws(() => createOwnerAuthorizationBridge({ expectations: e }))
  const expired = createOwnerAuthorizationBridge({ expectations: expected(draft()), nowMs: () => 200000,
    presentOwnerAction: async () => ({ status: 'signed', proof: signed(draft()) }) })
  assert.equal((await expired.requestAuthorization(draft())).reason, 'owner-authorization:expired')
})
