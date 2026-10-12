// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable software keys exercise enrollment, the desktop caller and the latched gate; no native custody.
import assert from 'node:assert/strict'
import { generateKeyPairSync, verify } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { createGate } from '../../boundary-gate/src/gate.mjs'
import { sha256 } from '../../boundary-gate/src/ledger.mjs'
import { call, lineServer, OWNER_SOCKET_APPROVER } from '../../boundary-gate/src/server.mjs'
import { createGateOwnerAuthorizationCaller } from '../../../apps/aukora-desktop/owner-key-bridge.mjs'
import { ownerAuthorizationEnrollment, ownerAuthorizationPreview, ownerAuthorizationText,
  ownerAuthorizationSigningBytes } from '../src/authorization.mjs'
import { createSoftwareOwnerAuthorizationSigner } from './software-signer.mjs'

const root = fileURLToPath(new URL('../../../', import.meta.url))
const target = 'plugins/auma-theme/theme.json'
const before = '{"accent": "default"}', after = '{"accent": "#112233"}'
const time = 1791072000000
const pair = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const spki = publicKey => publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
const request = authorization => ({ kind: 'owner-authorization', wire: ownerAuthorizationText(authorization),
  preview: ownerAuthorizationPreview(authorization) })

function fixture(t) {
  const home = mkdtempSync(path.join(root, '.owner-signer-'))
  const ownerPair = pair(), gatePair = generateKeyPairSync('ed25519')
  const state = ownerAuthorizationEnrollment({ owner_subject: `aukora:1:${sha256('software-fixture-owner')}`,
    owner_root_spki_base64: spki(ownerPair.publicKey), owner_epoch: 1,
    registry_sha256: sha256('fixture-registry'), activation_sha256: sha256('fixture-activation') })
  let bytes = Buffer.from(before), writes = 0
  const options = { home, now: () => time, owner: {},
    key: { priv: gatePair.privateKey, pub: gatePair.publicKey,
      pubPem: gatePair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      fp: sha256(Buffer.from(spki(gatePair.publicKey), 'base64')).slice(0, 16) },
    targets: { [target]: { entry: 'auma-theme', maxBytes: 256, schema: 'fixture theme',
      ownerCardLabel: 'ROUTINE', ownerCardAction: 'Change the fixture accent.',
      validate: text => { if (![before, after].includes(text)) throw Error('fixture schema') } } },
    store: { read: () => Buffer.from(bytes), write: (_target, _spec, next) => { bytes = Buffer.from(next); writes++ } } }
  const f = { home, ownerPair, gatePair, state, options,
    gate: createGate({ ...options, readOwnerState: () => state }),
    get writes() { return writes }, get bytes() { return bytes } }
  t.after(() => { f.gate.close(); rmSync(home, { recursive: true, force: true }) })
  f.propose = () => f.gate.proposeOps.propose({ target, content: after, claimed_base: sha256(before), why: 'Software fixture' })
  f.review = () => f.gate.ownerOps.review({ id: f.propose().id })
  return f
}

function unsigned(review) {
  return { id: review.id, base_sha: review.base_sha, new_sha: review.new_sha,
    review_challenge: review.review_challenge, outcome: 'allowed-once' }
}

function noEffect(f) {
  assert.equal(f.writes, 0)
  assert.equal(f.bytes.toString(), before)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 0)
}

test('software enrollment through the actual desktop caller produces an authenticated v3 receipt', async t => {
  const f = fixture(t), seen = [], signer = createSoftwareOwnerAuthorizationSigner(f.ownerPair.privateKey)
  assert.equal(Object.keys(f.state).length, 8)
  assert.equal(f.state.owner_root_id, sha256(Buffer.from(spki(f.ownerPair.publicKey), 'base64')))
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_required').get().n, 1)
  const caller = createGateOwnerAuthorizationCaller({ nowMs: () => time, readOwnerState: () => f.state,
    gateSpkiBase64: spki(f.gatePair.publicKey), callGateOwner: async (op, args) => f.gate.ownerOps[op](args, OWNER_SOCKET_APPROVER),
    presentOwnerAction: async presentation => { seen.push(presentation); return signer(presentation) } })
  t.after(() => caller.dispose())
  const question = await caller.review(f.propose().id)
  assert.equal(question.status, 'review-ready')
  const result = await caller.decide(question.question_id, 'allowed-once', () => true)
  assert.equal(result.status, 'applied'); assert.equal(result.receipt.v, 3)
  assert.equal(result.retained_history, 'H/D/E-verification-required')
  assert.equal(result.grants_authority, false)
  assert.equal(result.receipt.approver, f.state.owner_subject)
  assert.equal(f.writes, 1); assert.equal(f.bytes.toString(), after)
  assert.equal(seen.length, 1); assert.equal(seen[0].review.content, after)
  const consumed = f.gate.db.prepare('SELECT * FROM owner_authorization_consumptions').get()
  const proof = JSON.parse(consumed.proof_text)
  assert.equal(ownerAuthorizationText(proof.authorization), seen[0].wire)
  assert.equal(consumed.authorization_id, result.receipt.owner_authorization.authorization_id)
  assert.equal(consumed.proof_sha256, result.receipt.owner_authorization.proof_sha256)
  assert.equal(verify(null, Buffer.from(JSON.stringify(result.receipt)), f.gatePair.publicKey,
    Buffer.from(result.receipt_sig, 'base64')), true)
  assert.equal(verify('sha256', ownerAuthorizationSigningBytes(proof.authorization), f.ownerPair.publicKey,
    Buffer.from(proof.signature_base64, 'base64')), true)
  assert.equal(f.gate.verify().ok, true)
})

test('an unsigned owner handler approval is refused, including after reopening without the registry', t => {
  const f = fixture(t), review = f.review()
  assert.throws(() => f.gate.ownerOps.decide_review(unsigned(review), OWNER_SOCKET_APPROVER), /owner proof/u)
  noEffect(f)
  f.gate.close(); f.gate = createGate(f.options)
  assert.throws(() => f.gate.ownerOps.decide_review(unsigned(review), OWNER_SOCKET_APPROVER), /owner proof/u)
  noEffect(f)
})

test('an unsigned approval over the actual owner socket is refused', async t => {
  const f = fixture(t), review = f.review()
  const server = lineServer(f.gate.ownerOps, () => OWNER_SOCKET_APPROVER)
  const socket = path.relative(process.cwd(), path.join(f.home, 'owner.sock'))
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve) }) }
  catch (error) {
    if (error.code === 'EPERM') { t.skip('owner socket listen EPERM in sandbox; direct owner handler refusal runs separately'); return }
    throw error
  }
  try { await assert.rejects(call(socket, 'decide_review', unsigned(review)), /owner proof/u); noEffect(f) }
  finally { await new Promise(resolve => server.close(resolve)) }
})

async function rejectsWrongRequests(makeSigner, authorization, ownerPair) {
  const signer = makeSigner(ownerPair.privateKey), valid = request(authorization)
  await assert.rejects(signer({ ...valid, kind: 'bind-scoped-nostr' }), { code: 'software-owner-signer:kind' })
  await assert.rejects(signer({ ...valid, wire: valid.wire + '\n' }), { code: 'owner-authorization:noncanonical-wire' })
  await assert.rejects(signer(request({ ...authorization, owner_root_id: '0'.repeat(64) })), { code: 'software-owner-signer:root-mismatch' })
  await assert.rejects(signer({ ...valid, preview: { ...valid.preview, target: 'plugins/other/theme.json' } }),
    { code: 'software-owner-signer:preview-mismatch' })
  assert.throws(() => makeSigner(generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).privateKey),
    { code: 'software-owner-signer:p256-private-key-required' })
}

test('software signer refuses non-P-256 keys, other actions, noncanonical bytes, wrong roots and changed previews', async t => {
  const f = fixture(t)
  await rejectsWrongRequests(createSoftwareOwnerAuthorizationSigner, f.review().owner_authorization, f.ownerPair)
})

test('removing each software signer protection is detected by the same refusal checks', async t => {
  const f = fixture(t), authorization = f.review().owner_authorization
  const url = new URL('./software-signer.mjs', import.meta.url), original = readFileSync(url, 'utf8')
  const mutations = [
    ["if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'ec'\n    || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') fail('p256-private-key-required')", 'void 0'],
    ["if (kind !== 'owner-authorization') fail('kind')", 'void 0'],
    ['const authorization = parseOwnerAuthorization(wire)', 'const authorization = JSON.parse(wire)'],
    ["if (authorization.owner_root_id !== root) fail('root-mismatch')", 'void 0'],
    ["if (JSON.stringify(preview) !== JSON.stringify(ownerAuthorizationPreview(authorization))) fail('preview-mismatch')", 'void 0'],
  ]
  for (const [before, after] of mutations) {
    assert.equal(original.split(before).length, 2, 'each mutation must match exactly one guard')
    const source = original.replace(before, after).replace(/from (['"])(\.[^'"]+)\1/gu,
      (_match, quote, specifier) => `from ${quote}${new URL(specifier, url).href}${quote}`)
    const mutant = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'))
    await assert.rejects(rejectsWrongRequests(mutant.createSoftwareOwnerAuthorizationSigner, authorization, f.ownerPair),
      { code: 'ERR_ASSERTION' })
  }
  t.diagnostic('KILLED 5/5 software signer mutants: key, kind, canonical wire, root, preview')
})
