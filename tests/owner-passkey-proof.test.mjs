// SPDX-License-Identifier: AGPL-3.0-or-later
// Software assertions exercise pinned owner proofs and guard-removal mutations; no real authenticator runs.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { registerHooks } from 'node:module'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const protocol = '/packages/owner-key/src/authorization.mjs', verifier = '/packages/owner-key/src/webauthn.mjs'
const mutants = {
  expiry: [protocol, ["if (!integer(nowMs) || a.issued_at_ms > nowMs || nowMs >= a.expires_at_ms) fail('passkey-expired')", 'void 0']],
  digest: [protocol, ["if (e.authorization_digest !== ownerAuthorizationDigest(a)) fail('passkey-challenge-mismatch')", 'void 0']],
  expectations: [protocol, ["for (const field of AUTHORIZATION_V2_FIELDS) if (e[field] !== a[field]) fail('passkey-expectation-mismatch')", 'void 0']],
  node: [protocol, ['if (a.node !== state.node || a.owner_subject !== state.owner_subject || a.owner_root_id !== state.owner_root_id\n      || a.owner_epoch !== state.owner_epoch)', 'if (false)']],
  'state-key': [protocol, ["if (point !== state.public_key_hex) fail('passkey-key-pin')", 'void 0']],
  'weaker-proof': [protocol, ["if (authorization.version !== 1) fail('weaker-proof')", 'void 0']],
  'review-fallback': [protocol, ["if (state.version !== 1) fail('weaker-proof')", 'void 0']],
  'card-shape': [protocol, ["if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('card-shape')", 'void 0']],
  'proof-profile': [protocol, ["if (proof.algorithm !== OWNER_AUTHORIZATION_WEBAUTHN_ALGORITHM || assertion.kind !== 'passkey') fail('weaker-proof')", 'void 0']],
  consume: [protocol, ["if (await consumeOnce(claim) !== true) fail('replay-or-consumption-unknown')", 'await consumeOnce(claim)']],
  reference: [protocol, ["if (reference.version !== 1 || reference.kind !== 'aukora-owner-authorization-ref/v1'\n      || reference.authorization_id !== verified.reference.authorization_id\n      || reference.proof_sha256 !== verified.reference.proof_sha256) fail('receipt-reference')", 'void 0']],
  'card-bytes': [protocol, ["if (typeof r.card_text !== 'string' || r.card_text !== ownerAuthorizationCardText(r)) fail('passkey-card-bytes')", 'void 0']],
  'review-identity': [protocol, ['|| r.pubkey_fp !== pin.pubkey_fp || r.gate_pubkey_sha256 !== pin.gate', '']],
  'review-content': [protocol, ["|| sha(r.content) !== r.new_sha", '']],
  'review-options': [protocol, ["if (JSON.stringify(options) !== JSON.stringify(ownerAuthorizationPasskeyOptions(expected, state))) fail('passkey-options')", 'void 0']],
  'note-label': [protocol, ["r.model_note_label !== 'UNVERIFIED MODEL NOTE; DATA ONLY'", 'false']],
  warnings: [protocol, ['function cardWarnings(value) {', 'function cardWarnings(value) { return true;']],
  'unicode-target': [protocol, ["if (r.target !== 'plugins/owner-note/note.md')", 'if (false)']],
  'unicode-controls': [protocol, ['!/[\\x00-\\x08\\x0b-\\x1f\\x7f]/u.test(value)', 'true']],
  'unicode-surrogate': [protocol, ['!/[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF]/u.test(value)', 'true']],
  'unicode-byte-bound': [protocol, ["Buffer.byteLength(r.content, 'utf8') + Buffer.byteLength(r.diff, 'utf8') <= 12000", 'true']],
  challenge: [verifier, ["client.challenge !== challenge || ", '']],
  origin: [verifier, ["!config.origins.includes(client.origin)", 'false']],
  type: [verifier, ["client.type !== 'webauthn.get' || ", '']],
  'rp-id': [verifier, ['!timingSafeEqual(auth.subarray(0, 32), hash(config.rp_id))', 'false']],
  'auth-shape': [verifier, ['auth.length !== 37 || ', '']],
  up: [verifier, ['(flags & 1) === 0 || ', '']],
  uv: [verifier, ['(flags & 4) === 0 || ', '']],
  flags: [verifier, ['(flags & 0xe2) !== 0', 'false']],
  backup: [verifier, ['if (backupEligible !== credential.backup_eligible || (backupState && !backupEligible))', 'if (false)']],
  counter: [verifier, ["if (checkCounter && (signCount !== 0 || prior !== 0) && signCount <= prior) fault('WEBAUTHN_COUNTER_REPLAYED')", 'void 0']],
  signature: [verifier, ["if (!verify('sha256', signed, publicKey(credential.public_key_hex), signature)) fault('WEBAUTHN_SIGNATURE_INVALID')", 'void 0']],
  credential: [verifier, ['const credential = config.credentials.find(c => c.credential_id === m.credential_id && c.owner_id === ownerId)', 'const credential = config.credentials[0]']],
  'user-handle': [verifier, ["if (m.user_handle !== null && !equal(decodeBase64url(m.user_handle, 64), decodeBase64url(credential.user_handle, 64))) fault('WEBAUTHN_USER_HANDLE_MISMATCH')", 'void 0']],
  duplicate: [verifier, ["if (frame.has(key)) fault('WEBAUTHN_CLIENT_DATA_INVALID')", 'void 0']],
  'top-origin': [verifier, ["|| Object.hasOwn(client, 'topOrigin')", '']],
  'cross-origin': [verifier, ['|| client.crossOrigin === true ', ''], ["if (client.crossOrigin !== undefined && client.crossOrigin !== false) fault('WEBAUTHN_CROSS_ORIGIN_REFUSED')", 'void 0']],
  'https-pin': [verifier, ["url.protocol !== 'https:' || ", '']],
  'utf8-client': [verifier, ['{ fatal: true }', '{ fatal: false }']],
  'client-depth': [verifier, ["if (stack.length > 512) fault('WEBAUTHN_CLIENT_DATA_INVALID')", 'void 0']],
  'unsafe-integer': [verifier, ["if (typeof value === 'number' && Number.isInteger(value) && !Number.isSafeInteger(value)) fault('WEBAUTHN_CLIENT_DATA_INVALID')", 'void 0']],
  'lone-surrogate': [verifier, ["if (typeof value === 'string' && /[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF]/u.test(value)) fault('WEBAUTHN_CLIENT_DATA_INVALID')", 'void 0']],
  'client-byte-bound': [verifier, ['bytes.length > max || ', '']],
}
const mutation = process.env.AUKORA_PASSKEY_PROOF_MUTANT
if (mutation) {
  const selected = mutants[mutation]
  assert(selected, 'known mutation')
  registerHooks({ load(url, context, next) {
    const result = next(url, context)
    if (!url.endsWith(selected[0])) return result
    let source = String(result.source)
    for (const [before, after] of selected.slice(1)) {
      // Review guards also occur in v1. Only mutate v4's first instance.
      assert(source.includes(before), 'mutation preimage present')
      source = source.replace(before, after)
    }
    return { ...result, source }
  } })
}
const { AUTHORIZATION_V2_FIELDS, ownerAuthorization, ownerAuthorizationText, ownerAuthorizationSigningBytes,
  ownerAuthorizationDigest, ownerAuthorizationProofDigest, ownerAuthorizationPasskeyState,
  ownerAuthorizationPasskeyOptions, ownerAuthorizationCardText, ownerAuthorizationGateReview,
  verifyOwnerAuthorization, verifyOwnerAuthorizationReference, consumeOwnerAuthorization } = await import('../packages/owner-key/src/authorization.mjs')
const { verifyWebauthnAssertion: authorityVerify, prepareWebauthnConfig: authorityConfig } = await import('../packages/authority/src/webauthn.mjs')
const { verifyWebauthnAssertion: standaloneVerify } = await import('../packages/owner-key/src/webauthn.mjs')
const sha = bytes => createHash('sha256').update(bytes).digest()
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const spki = pair.publicKey.export({ format: 'der', type: 'spki' }), jwk = pair.publicKey.export({ format: 'jwk' })
const point = '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex')
const state = { version: 2, kind: 'aukora-owner-state/passkey-v2', owner_subject: 'aukora:1:' + '1'.repeat(64),
  owner_root_spki_base64: spki.toString('base64'), owner_root_id: sha(spki).toString('hex'), owner_epoch: 1,
  registry_sha256: '2'.repeat(64), activation_sha256: '3'.repeat(64), node: '4'.repeat(64),
  rp_id: 'owner.test', origin: 'https://owner.test', credential_id: Buffer.from('credential-one').toString('base64url'),
  user_handle: Buffer.from('owner-one').toString('base64url'), public_key_hex: point, sign_count: 0, backup_eligible: false }
const draft = () => ({ version: 2, kind: 'aukora-owner-authorization/v2', operation: 'change',
  proposal_id: '01234567-89ab-4cde-8123-456789abcdef', target: 'plugins/auma-theme/theme.json',
  before_sha256: 'a'.repeat(64), after_sha256: 'b'.repeat(64), gate: 'c'.repeat(64), challenge: 'd'.repeat(64),
  issued_at_ms: 100000, expires_at_ms: 200000, owner_subject: state.owner_subject,
  owner_root_id: state.owner_root_id, owner_epoch: 1, node: state.node, card_sha256: 'e'.repeat(64) })
const expected = (a, s = state) => ({ owner_state: s, authorization_digest: ownerAuthorizationDigest(a),
  ...Object.fromEntries(AUTHORIZATION_V2_FIELDS.map(field => [field, a[field]])) })
function softwareProof(a = draft(), { client = {}, rp = state.rp_id, flags = 5, count = 1,
  key = pair.privateKey, credential = state.credential_id, userHandle = state.user_handle, trailing = false, raw } = {}) {
  const bytes = Buffer.from(raw ?? JSON.stringify({ type: 'webauthn.get', challenge: Buffer.from(ownerAuthorizationDigest(a), 'hex').toString('base64url'),
    origin: state.origin, crossOrigin: false, ...client }))
  const auth = Buffer.alloc(trailing ? 38 : 37); sha(rp).copy(auth); auth[32] = flags; auth.writeUInt32BE(count, 33)
  return { version: 2, algorithm: 'webauthn-es256-sha256', authorization: a, assertion: { kind: 'passkey',
    credential_id: credential, client_data_json: bytes.toString('base64url'), authenticator_data: auth.toString('base64url'),
    signature: sign('sha256', Buffer.concat([auth, sha(bytes)]), key).toString('base64url'), user_handle: userHandle } }
}
function refuse(proof, e = expected(draft()), now = 150000) { assert.throws(() => verifyOwnerAuthorization(proof, e, now)) }

test('v2 binds canonical exact-card, gate, node, expiry and nonce bytes', () => {
  const a = draft(), proof = softwareProof(a), result = verifyOwnerAuthorization(proof, expected(a), 150000)
  assert.equal(result.user_verified, true); assert.equal(result.user_present, true); assert.equal(result.sign_count, 1)
  assert.equal(result.grants_authority, false); assert.equal(result.comprehension, 'not-proven')
  assert.equal(result.reference.proof_sha256, ownerAuthorizationProofDigest(proof))
  assert.equal(ownerAuthorizationSigningBytes(a).subarray(0, 30).toString(), 'aukora:owner-authorization:v2\0')
  assert.deepEqual(Object.keys(ownerAuthorization(a)), AUTHORIZATION_V2_FIELDS)
  assert.equal(ownerAuthorizationPasskeyOptions(a, state).challenge, Buffer.from(ownerAuthorizationDigest(a), 'hex').toString('base64url'))
  for (const [field, value] of Object.entries({ node: '9'.repeat(64), gate: '9'.repeat(64), card_sha256: '9'.repeat(64),
    challenge: '9'.repeat(64), owner_epoch: 2, owner_subject: 'aukora:1:' + '9'.repeat(64) })) {
    refuse(proof, { ...expected(a), [field]: value })
    const changed = { ...a, [field]: value }
    refuse({ ...proof, authorization: changed }, expected(changed))
  }
  const changedNode = { ...a, node: '9'.repeat(64) }
  refuse(softwareProof(changedNode), expected(changedNode))
  refuse(proof, { ...expected(a), authorization_digest: '9'.repeat(64) })
})

test('v2 refuses cookie, weaker proof, unknown fields and credential/root pin substitution', () => {
  const a = draft()
  refuse({ cookie: 'session-only' })
  const weak = { algorithm: 'p256-ecdsa-sha256', authorization: a,
    signature_base64: sign('sha256', ownerAuthorizationSigningBytes(a), pair.privateKey).toString('base64') }
  assert.throws(() => ownerAuthorizationProofDigest(weak)); refuse(weak)
  assert.throws(() => ownerAuthorizationProofDigest({ ...softwareProof(a), algorithm: 'p256-ecdsa-sha256' }))
  assert.throws(() => ownerAuthorizationProofDigest({ ...softwareProof(a), cookie: 'session-only' }))
  const alternate = other.publicKey.export({ format: 'jwk' })
  assert.throws(() => ownerAuthorizationPasskeyState({ ...state, public_key_hex: '04'
    + Buffer.from(alternate.x, 'base64url').toString('hex') + Buffer.from(alternate.y, 'base64url').toString('hex') }))
  assert.throws(() => ownerAuthorizationPasskeyState({ ...state, origin: 'http://owner.test' }))
  assert.throws(() => ownerAuthorizationPasskeyState({ ...state, approved: true }))
})

test('real assertion signature requires the enrolled key, credential and user handle', () => {
  refuse(softwareProof(draft(), { key: other.privateKey }))
  refuse(softwareProof(draft(), { credential: Buffer.from('credential-two').toString('base64url') }))
  refuse(softwareProof(draft(), { userHandle: Buffer.from('owner-two').toString('base64url') }))
  const proof = softwareProof(), damaged = Buffer.from(proof.assertion.signature, 'base64url'); damaged[damaged.length - 1] ^= 1
  refuse({ ...proof, assertion: { ...proof.assertion, signature: damaged.toString('base64url') } })
  assert.equal(verifyOwnerAuthorization(softwareProof(draft(), { userHandle: null }), expected(draft()), 150000).user_verified, true)
  const config = authorityConfig({ rp_id: state.rp_id, origins: [state.origin], credentials: [{ owner_id: state.owner_subject,
    credential_id: state.credential_id, user_handle: state.user_handle, public_key_hex: point, sign_count: 0, backup_eligible: false }] })
  const challenge = Buffer.from(ownerAuthorizationDigest(draft()), 'hex').toString('base64url')
  const options = material => ({ material, config, ownerId: state.owner_subject, challenge })
  assert.deepEqual(standaloneVerify(options(softwareProof().assertion)), authorityVerify(options(softwareProof().assertion)))
  for (const proof of [softwareProof(draft(), { key: other.privateKey }), softwareProof(draft(), { rp: 'other.test' }),
    softwareProof(draft(), { flags: 1 }), softwareProof(draft(), { client: { origin: 'https://other.owner.test' } }),
    softwareProof(draft(), { client: { type: 'webauthn.create' } }), softwareProof(draft(), { client: { extra: 9007199254740992 } })]) {
    assert.throws(() => standaloneVerify(options(proof.assertion)))
    assert.throws(() => authorityVerify(options(proof.assertion)))
  }
})

test('type, challenge, RP, exact origin, cross-origin, duplicate and trailing data refuse', () => {
  for (const client of [{ type: 'webauthn.create' }, { challenge: Buffer.from('wrong digest').toString('base64url') },
    { origin: 'https://other.owner.test' }, { crossOrigin: true }, { crossOrigin: 'false' }, { topOrigin: state.origin }])
    refuse(softwareProof(draft(), { client }))
  refuse(softwareProof(draft(), { rp: 'other.test' })); refuse(softwareProof(draft(), { trailing: true }))
  const correct = Buffer.from(softwareProof().assertion.client_data_json, 'base64url').toString()
  refuse(softwareProof(draft(), { raw: correct.replace('"type":', '"type":"webauthn.create","type":') }))
  refuse(softwareProof(draft(), { client: { extra: 9007199254740992 } }))
  refuse(softwareProof(draft(), { client: { extra: '\ud800' } }))
  refuse(softwareProof(draft(), { raw: correct.slice(0, -1) + ',"extra":' + '['.repeat(513) + '0' + ']'.repeat(513) + '}' }))
  refuse(softwareProof(draft(), { raw: Buffer.concat([Buffer.from(correct.slice(0, -1) + ',"extra":"'), Buffer.from([0xff]), Buffer.from('"}')]) }))
  refuse(softwareProof(draft(), { client: { extra: 'x'.repeat(17000) } }))
})

test('UP, UV, reserved flags, backup policy and counter replay refuse', () => {
  for (const flags of [4, 1, 0x25, 0x0d, 0x15]) refuse(softwareProof(draft(), { flags }))
  const advanced = { ...state, sign_count: 1 }
  refuse(softwareProof(), expected(draft(), advanced))
  assert.equal(verifyOwnerAuthorization(softwareProof(draft(), { count: 2 }), expected(draft(), advanced), 150000).sign_count, 2)
  assert.equal(verifyOwnerAuthorization(softwareProof(draft(), { count: 0 }), expected(draft()), 150000).sign_count, 0)
  assert.equal(verifyOwnerAuthorization(softwareProof(draft(), { flags: 0x1d }), expected(draft(), { ...state, backup_eligible: true }), 150000).backup_state, true)
})

test('expired and not-yet-issued assertions refuse', () => {
  const proof = softwareProof(), e = expected(draft())
  for (const now of [99999, 200000, 200001, NaN]) refuse(proof, e, now)
})

test('consumption result spends one nonce before caller effect; denial and replay have no effect', async () => {
  const a = draft(), proof = softwareProof(a), e = expected(a), spent = new Set(); let effects = 0
  const consumeOnce = async claim => {
    assert.equal(claim.sign_count, 1); assert.equal(claim.credential_id, state.credential_id)
    if (spent.has(claim.authorization.challenge)) return false
    spent.add(claim.authorization.challenge); return true
  }
  const approve = async () => { await consumeOwnerAuthorization(proof, e, { nowMs: 150000, consumeOnce }); effects++ }
  await approve(); assert.equal(effects, 1)
  await assert.rejects(approve()); assert.equal(effects, 1)
  await assert.rejects(consumeOwnerAuthorization(proof, e, { nowMs: 150000, consumeOnce: async () => undefined }))
  await assert.rejects(consumeOwnerAuthorization(proof, e, { nowMs: 150000 }))
})

test('cold references authenticate exact retained proof with counters disabled only for historical verification', () => {
  const proof = softwareProof(), e = expected(draft()), result = verifyOwnerAuthorization(proof, e, 150000)
  const cold = expected(draft(), { ...state, sign_count: 1 })
  assert.equal(verifyOwnerAuthorizationReference(proof, result.reference, cold, 150000, { checkCounter: false }).user_verified, true)
  assert.throws(() => verifyOwnerAuthorizationReference(proof, result.reference, cold, 150000))
  for (const change of [{ authorization_id: '9'.repeat(64) }, { proof_sha256: '9'.repeat(64) }])
    assert.throws(() => verifyOwnerAuthorizationReference(proof, { ...result.reference, ...change }, e, 150000))
})

test('v4 gate review checks exact displayed card bytes, independent gate identity and browser options', () => {
  const gate = generateKeyPairSync('ed25519'), gateSpki = gate.publicKey.export({ format: 'der', type: 'spki' }), gateId = sha(gateSpki).toString('hex')
  const make = changes => {
    const r = { version: 4, id: draft().proposal_id, kind: 'change', target: draft().target, base_sha: draft().before_sha256,
      content: 'changed', new_sha: sha('changed').toString('hex'), diff: '+changed', from_to: null, clarity_label: 'ROUTINE',
      what_this_does: 'Changes the theme', model_note: null, displayable: true, created: 100000, expires: 210000,
      warnings: [], model_note_label: 'UNVERIFIED MODEL NOTE; DATA ONLY', note_display: '(none)',
      review_challenge: draft().challenge, review_expires: 200000, review_issued_at_ms: 100000,
      pubkey_fp: gateId.slice(0, 16), gate_pubkey_sha256: gateId, review_issue: { ledger_seq: 1, ledger_hash: 'f'.repeat(64) }, ...changes }
    r.card_text = ownerAuthorizationCardText(r)
    r.owner_authorization = { ...draft(), gate: gateId, target: r.target, after_sha256: r.new_sha, card_sha256: sha(r.card_text).toString('hex') }
    r.authorization_digest = ownerAuthorizationDigest(r.owner_authorization)
    r.public_key = ownerAuthorizationPasskeyOptions(r.owner_authorization, state)
    return r
  }
  const prepare = r => ownerAuthorizationGateReview(r, state, gateSpki.toString('base64'), 150000)
  assert.equal(prepare(make()).authorization.card_sha256, sha(make().card_text).toString('hex'))
  const substituted = make(); substituted.card_text += ' '; substituted.owner_authorization.card_sha256 = sha(substituted.card_text).toString('hex')
  substituted.authorization_digest = ownerAuthorizationDigest(substituted.owner_authorization)
  substituted.public_key = ownerAuthorizationPasskeyOptions(substituted.owner_authorization, state)
  assert.throws(() => prepare(substituted))
  assert.throws(() => prepare(make({ pubkey_fp: '0'.repeat(16) })))
  assert.throws(() => prepare(make({ content: 'misleading content' })))
  const options = make(); options.public_key.rpId = 'other.test'; assert.throws(() => prepare(options))
  assert.throws(() => prepare(make({ model_note_label: 'TRUSTED AUTHORITY' })))
  assert.throws(() => prepare(make({ warnings: ['warning\u001b'] })))
  const utf8 = content => ({ target: 'plugins/owner-note/note.md', content, new_sha: sha(content).toString('hex'), diff: '+note' })
  assert.equal(prepare(make(utf8('Hello 世界 🌿\n'))).review.content, 'Hello 世界 🌿\n')
  for (const content of ['note\u0000', '\ud800', '界'.repeat(5000)]) assert.throws(() => prepare(make(utf8(content))))
  assert.throws(() => prepare(make({ content: '世界', new_sha: sha('世界').toString('hex') })))
  let reads = 0
  const card = make(); Object.defineProperty(card, 'content', { enumerable: true, get() { reads++; return 'changed' } })
  assert.throws(() => ownerAuthorizationCardText(card)); assert.equal(reads, 0)
  const legacy = make(); delete legacy.card_text; delete legacy.public_key; legacy.version = 3
  delete legacy.warnings; delete legacy.model_note_label; delete legacy.note_display
  delete legacy.owner_authorization.node; delete legacy.owner_authorization.card_sha256
  legacy.owner_authorization.version = 1; legacy.owner_authorization.kind = 'aukora-owner-authorization/v1'
  legacy.authorization_digest = ownerAuthorizationDigest(legacy.owner_authorization)
  assert.throws(() => prepare(legacy))
})

test('every selected guard-removal mutant fails a completed proof test', { skip: Boolean(mutation) }, () => {
  for (const name of Object.keys(mutants)) {
    const result = spawnSync(process.execPath, ['--test', '--test-reporter=spec', fileURLToPath(import.meta.url)], {
      env: { PATH: process.env.PATH, AUKORA_PASSKEY_PROOF_MUTANT: name }, encoding: 'utf8', timeout: 15000, maxBuffer: 1048576 })
    const output = (result.stdout ?? '') + (result.stderr ?? '')
    assert.equal(result.error, undefined, name + ': completed')
    assert.equal(result.status, 1, name + ': killed\n' + output)
    assert.match(output, /tests 10/u, name + ': test suite completed')
    assert.match(output, /ERR_ASSERTION/u, name + ': assertion failure')
    assert.doesNotMatch(output, /SyntaxError|mutation preimage present/u, name + ': valid mutant')
    console.log('KILLED owner-passkey-proof:' + name)
  }
})
