// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic gate receipts retain exact software-authenticator proofs and signed consumption history.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createLedger, keyFingerprint, openDb, sha256 } from '../packages/boundary-gate/src/ledger.mjs'
import { verifyReceipt, verifyReceiptSignature } from '../packages/boundary-gate/src/receipts.mjs'
import { AUTHORIZATION_V2_FIELDS, ownerAuthorization, ownerAuthorizationDigest, ownerAuthorizationProofDigest,
  ownerAuthorizationProofText, ownerAuthorizationSigningBytes, ownerAuthorizationText,
  verifyOwnerAuthorizationReference } from '../packages/owner-key/src/authorization.mjs'

const NOW = 1791072000000
const hash = bytes => createHash('sha256').update(bytes).digest()
const clone = value => JSON.parse(JSON.stringify(value))

function fixture(change = {}) {
  const gate = generateKeyPairSync('ed25519'), device = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const key = { priv: gate.privateKey, pub: gate.publicKey }, spki = device.publicKey.export({ type: 'spki', format: 'der' })
  const jwk = device.publicKey.export({ format: 'jwk' })
  const state = { version: 2, kind: 'aukora-owner-state/passkey-v2', owner_subject: 'aukora:1:' + sha256('synthetic owner'),
    owner_root_spki_base64: spki.toString('base64'), owner_root_id: sha256(spki), owner_epoch: 1,
    registry_sha256: sha256('synthetic registration'), activation_sha256: sha256('synthetic activation'),
    node: sha256('synthetic C1'), rp_id: 'owner.example', origin: 'https://owner.example',
    credential_id: Buffer.from('synthetic credential').toString('base64url'), user_handle: Buffer.from('synthetic owner').toString('base64url'),
    public_key_hex: '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex'),
    sign_count: 0, backup_eligible: false }
  const id = randomUUID(), gateId = sha256(gate.publicKey.export({ type: 'spki', format: 'der' }))
  let authorization = { version: 2, kind: 'aukora-owner-authorization/v2', operation: 'change', proposal_id: id,
    target: 'plugins/fixture/theme.json', before_sha256: sha256('before'), after_sha256: sha256('after'),
    gate: gateId, challenge: sha256('durable one-use nonce'), issued_at_ms: NOW, expires_at_ms: NOW + 120000,
    owner_subject: state.owner_subject, owner_root_id: state.owner_root_id, owner_epoch: state.owner_epoch,
    card_sha256: sha256('exact card bytes'), node: state.node }
  change.authorization?.(authorization)
  authorization = ownerAuthorization(authorization)
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: hash(ownerAuthorizationSigningBytes(authorization)).toString('base64url'),
    origin: state.origin, crossOrigin: false }))
  const authenticator = Buffer.alloc(37); hash(state.rp_id).copy(authenticator); authenticator[32] = 5; authenticator.writeUInt32BE(1, 33)
  const proof = { version: 2, algorithm: 'webauthn-es256-sha256', authorization,
    assertion: { kind: 'passkey', credential_id: state.credential_id, client_data_json: client.toString('base64url'),
      authenticator_data: authenticator.toString('base64url'), signature: sign('sha256', Buffer.concat([authenticator, hash(client)]), device.privateKey).toString('base64url'),
      user_handle: state.user_handle } }
  let authorizationId = ownerAuthorizationDigest(authorization), proofId = ownerAuthorizationProofDigest(proof)
  if (change.authorizationId) authorizationId = sha256('different authorization digest')
  const ref = { version: 1, kind: 'aukora-owner-authorization-ref/v1', authorization_id: authorizationId, proof_sha256: proofId }
  const db = openDb(':memory:'), ledger = createLedger(db, key, () => new Date(NOW + 120001).toISOString())
  const common = { proposal: id, target: 'plugins/fixture/theme.json', base_sha: sha256('before'), new_sha: sha256('after') }
  const issued = { via: 'owner', authorization_text: ownerAuthorizationText(authorization), authorization_id: authorizationId,
    owner_state: state, issued_at_ms: NOW, expires_at_ms: NOW + 120000, gate_pubkey_sha256: gateId }
  change.issued?.(issued)
  const issue = ledger.append('review-issued', { ...common, detail: issued })
  const pointer = { ledger_seq: issue.seq, ledger_hash: issue.hash }
  let proofText = ownerAuthorizationProofText(proof)
  if (change.proofWhitespace) proofText += ' '
  const acceptedAt = change.expired ? NOW + 120000 : NOW + 1
  const accepted = { outcome: 'allowed-once', operation: 'change', via: 'owner-review', approver: state.owner_subject,
    channel: 'synthetic owner', spent: true, accepted_at_ms: acceptedAt, owner_authorization: ref,
    proof_text: proofText, owner_state: state, review_issue: pointer }
  change.accepted?.(accepted)
  const consume = ledger.append(change.consumeEvent ?? 'owner-authorization-consumed', { ...common, detail: accepted })
  const retained = { authorization_id: authorizationId, proof_sha256: proofId, gate: gateId, challenge: authorization.challenge,
    proposal_id: id, proof_text: proofText, accepted_at_ms: acceptedAt, consume_seq: consume.seq, consume_hash: consume.hash,
    issue_seq: issue.seq, issue_hash: issue.hash, owner_state_text: JSON.stringify(state) }
  change.retained?.(retained)
  db.prepare('INSERT INTO owner_authorization_consumptions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(...Object.values(retained))
  const receipt = { v: 3, kind: 'change', proposal: id, target: common.target, base_sha: common.base_sha, new_sha: common.new_sha,
    applied_at: new Date(NOW + 120001).toISOString(), approver: state.owner_subject, pubkey_fp: keyFingerprint(gate.publicKey),
    gate_pubkey_sha256: gateId, owner_authorization: ref, owner_accepted_at_ms: acceptedAt,
    owner_consumption: { ledger_seq: consume.seq, ledger_hash: consume.hash, review_issue: pointer } }
  change.receipt?.(receipt)
  const signature = sign(null, Buffer.from(JSON.stringify(receipt)), gate.privateKey).toString('base64')
  if (!change.noApply) ledger.append('apply', { ...common, detail: { receipt, receipt_sig: signature } })
  if (change.badChain) { db.exec('DROP TRIGGER ledger_no_update'); db.prepare('UPDATE ledger SET sig=? WHERE seq=1').run(Buffer.alloc(64).toString('base64')) }
  const expectations = { owner_state: state, authorization_digest: ownerAuthorizationDigest(authorization),
    ...Object.fromEntries(AUTHORIZATION_V2_FIELDS.map(field => [field, authorization[field]])) }
  return { db, receipt, signature, publicKey: gate.publicKey, privateKey: gate.privateKey, proof, expectations }
}
function checked(module, options) {
  const f = fixture(options)
  try { return module.verifyReceipt(f.db, f.receipt, f.signature, f.publicKey) }
  finally { f.db.close() }
}

test('v3 reader retains a real software assertion and cold owner verification survives expiry', () => {
  const f = fixture()
  try {
    assert.equal(verifyReceipt(f.db, f.receipt, f.signature, f.publicKey).ok, true)
    assert.equal(verifyOwnerAuthorizationReference(f.proof, f.receipt.owner_authorization, f.expectations,
      f.receipt.owner_accepted_at_ms, { checkCounter: false }).status, 'verified-owner-authorization')
  } finally { f.db.close() }
})

const refused = [
  ['signed consumption event', { consumeEvent: 'different-event' }],
  ['signed state snapshot', { accepted: value => { value.owner_state = { ...value.owner_state, owner_epoch: 2 } } }],
  ['exact consumed proof text', { accepted: value => { value.proof_text += ' ' } }],
  ['retained consumption coordinate', { retained: value => { value.consume_hash = sha256('wrong coordinate') } }],
  ['proof digest', { proofWhitespace: true }],
  ['authorization digest', { authorizationId: true }],
  ['exact proposal binding', { authorization: value => { value.proposal_id = randomUUID() } }],
  ['accepted expiry', { expired: true }],
  ['intact ledger', { badChain: true }],
  ['apply inclusion', { noApply: true }],
]
for (const [label, options] of refused) test('v3 receipt refuses ' + label, () => {
  assert.equal(checked({ verifyReceipt }, options).ok, false)
})

function signatureCase(module, change, signatureChange, originalSignature = false) {
  const f = fixture()
  try {
    const receipt = clone(f.receipt); change?.(receipt)
    let signature = originalSignature ? f.signature : sign(null, Buffer.from(JSON.stringify(receipt)), f.privateKey).toString('base64')
    if (signatureChange) signature = Buffer.alloc(64).toString('base64')
    return module.verifyReceiptSignature(receipt, signature, f.publicKey)
  } finally { f.db.close() }
}
test('v3 signature refuses foreign gate, extra layout fields, reversed time and signature substitution', () => {
  for (const change of [r => { r.gate_pubkey_sha256 = sha256('other gate') }, r => { r.extra = true },
    r => { r.owner_accepted_at_ms = Date.parse(r.applied_at) + 1 }]) assert.equal(signatureCase({ verifyReceiptSignature }, change).ok, false)
  assert.equal(signatureCase({ verifyReceiptSignature }, r => { r.extra = true }, false, true).ok, false)
  assert.equal(signatureCase({ verifyReceiptSignature }, null, true).ok, false)
})

const sourceUrl = new URL('../packages/boundary-gate/src/receipts.mjs', import.meta.url)
const source = readFileSync(sourceUrl, 'utf8')
async function mutant(before, after) {
  assert.equal(source.split(before).length, 2, 'mutation names exactly one receipt guard')
  const text = source.replace(before, after).replace(/from '([^']+)'/gu,
    (statement, specifier) => specifier.startsWith('.') ? statement.replace(specifier, new URL(specifier, sourceUrl).href) : statement)
  return import('data:text/javascript;base64,' + Buffer.from(text).toString('base64'))
}
test('receipt guard removals are killed by focused refusals', async t => {
  const mutations = [
    ['consumption-event', "consume.event !== 'owner-authorization-consumed'", 'false', refused[0][1]],
    ['state-snapshot', 'retained.owner_state_text !== JSON.stringify(accepted.owner_state)', 'false', refused[1][1]],
    ['exact-proof-text', 'accepted.proof_text !== retained.proof_text', 'false', refused[2][1]],
    ['consumption-coordinate', 'retained.consume_hash !== consume.hash', 'false', refused[3][1]],
    ['proof-digest', "sha256(Buffer.from((proof.version === 2 ? 'aukora:owner-authorization-proof:v2\\0' : 'aukora:owner-authorization-proof:v1\\0')\n      + retained.proof_text, 'utf8')) !== ref.proof_sha256", 'false', refused[4][1]],
    ['authorization-digest', "sha256(Buffer.from((authorization.version === 2 ? 'aukora:owner-authorization:v2\\0' : 'aukora:owner-authorization:v1\\0')\n      + issued.authorization_text, 'utf8')) !== ref.authorization_id", 'false', refused[5][1]],
    ['proposal-binding', 'authorization.proposal_id !== receipt.proposal', 'false', refused[6][1]],
    ['accepted-expiry', 'receipt.owner_accepted_at_ms >= authorization.expires_at_ms', 'false', refused[7][1]],
    ['ledger-chain', "if (!chain.ok) errors.push('ledger chain or signatures broken')", '', refused[8][1]],
    ['apply-inclusion', "if (!match) errors.push('receipt not found in an apply entry of the ledger')", 'if (!match) {}', refused[9][1]],
  ]
  for (const [label, before, after, options] of mutations) await t.test(label, async () => {
    assert.equal(checked(await mutant(before, after), options).ok, true, 'guard removal admits its forbidden receipt')
  })
  const signatureMutations = [
    ['gate-pin', "receipt.gate_pubkey_sha256 !== sha256(pub.export({ type: 'spki', format: 'der' }))", 'false', r => { r.gate_pubkey_sha256 = sha256('other gate') }],
    ['layout', 'keys.length !== fields.length || keys.some((key, i) => key !== fields[i])', 'false', r => { r.extra = true }, false, true],
    ['time-order', 'receipt.owner_accepted_at_ms > applied', 'false', r => { r.owner_accepted_at_ms = Date.parse(r.applied_at) + 1 }],
    ['receipt-signature', '!verify(null, Buffer.from(JSON.stringify(receipt)), pub, signature)', 'false', null, true],
  ]
  for (const [label, before, after, change, signatureChange, originalSignature] of signatureMutations) await t.test(label, async () => {
    assert.equal(signatureCase(await mutant(before, after), change, signatureChange, originalSignature).ok, true, 'guard removal admits its forbidden signature')
  })
})
