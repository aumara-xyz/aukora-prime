// SPDX-License-Identifier: AGPL-3.0-or-later
// Public owner-authorization protocol. No signer, seed, storage, effect or fallback.
import { createHash, createPublicKey, verify } from 'node:crypto'
import { ownerRootPin, OWNER_KEY_ALGORITHM } from './index.mjs'

export const OWNER_AUTHORIZATION_DOMAIN = 'aukora:owner-authorization:v1\0'
export const OWNER_AUTHORIZATION_PROOF_DOMAIN = 'aukora:owner-authorization-proof:v1\0'
export const AUTHORIZATION_FIELDS = Object.freeze(['after_sha256', 'before_sha256', 'challenge',
  'expires_at_ms', 'gate', 'issued_at_ms', 'kind', 'operation', 'owner_epoch', 'owner_root_id',
  'owner_subject', 'proposal_id', 'target', 'version'])
export const OWNER_STATE_FIELDS = Object.freeze(['version', 'kind', 'owner_subject',
  'owner_root_spki_base64', 'owner_root_id', 'owner_epoch', 'registry_sha256', 'activation_sha256'])
const HEX = /^[0-9a-f]{64}$/u
const hex64 = value => typeof value === 'string' && value.length === 64 && HEX.test(value)
const integer = value => Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const fail = code => { throw Object.assign(new TypeError(`owner-authorization:${code}`), { code: `owner-authorization:${code}` }) }

function closed(value, fields, preserveOrder = false) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('shape')
    const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors)
    if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) fail('shape')
    const out = Object.create(null)
    for (const key of preserveOrder ? keys : fields) {
      const descriptor = descriptors[key]
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('shape')
      out[key] = descriptor.value
    }
    return out
  } catch { fail('shape') }
}

/** Structure and public-key identity only. State MUST come from an independent trusted registry. */
export function ownerAuthorizationOwnerState(supplied) {
  const state = closed(supplied, OWNER_STATE_FIELDS)
  if (state.version !== 1 || state.kind !== 'aukora-owner-state/v1'
    || typeof state.owner_subject !== 'string' || state.owner_subject.length !== 73
    || !/^aukora:1:[0-9a-f]{64}$/u.test(state.owner_subject)
    || !integer(state.owner_epoch) || state.owner_epoch < 1
    || !['owner_root_id', 'registry_sha256', 'activation_sha256'].every(field => hex64(state[field]))
    || ownerRootPin(state.owner_root_spki_base64).owner_root_id !== state.owner_root_id) fail('owner-state')
  return Object.freeze(state)
}

/** Current gate receipts use Ed25519; this public deployment pin never comes from the receipt itself. */
export function ownerAuthorizationGatePin(spkiBase64) {
  try {
    if (typeof spkiBase64 !== 'string' || spkiBase64.length > 256) fail('gate-pin')
    const der = Buffer.from(spkiBase64, 'base64')
    if (der.toString('base64') !== spkiBase64) fail('gate-pin')
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' })
    if (key.asymmetricKeyType !== 'ed25519' || !key.export({ format: 'der', type: 'spki' }).equals(der)) fail('gate-pin')
    return Object.freeze({ gate: sha(der), spki_base64: spkiBase64, pubkey_fp: sha(der).slice(0, 16) })
  } catch { fail('gate-pin') }
}

const REVIEW_FIELDS = Object.freeze(['version', 'id', 'kind', 'target', 'base_sha', 'new_sha',
  'content', 'diff', 'from_to', 'clarity_label', 'what_this_does', 'model_note', 'displayable',
  'created', 'expires', 'review_challenge', 'review_expires', 'review_issued_at_ms', 'pubkey_fp',
  'gate_pubkey_sha256', 'owner_authorization', 'authorization_digest', 'review_issue'])
const ascii = (value, min, max, diff = false) => typeof value === 'string' && value.length >= min
  && value.length <= max && !(diff ? /[^\x09\x0a\x20-\x7e]/u : /[^\x20-\x7e]/u).test(value)
function coordinate(supplied, preserveOrder = false) {
  const value = closed(supplied, ['ledger_seq', 'ledger_hash'], preserveOrder)
  if (!integer(value.ledger_seq) || value.ledger_seq < 1 || !hex64(value.ledger_hash)) fail('ledger-coordinate')
  return Object.freeze(value)
}

/** H's actual review v3: independently pinned gate and active owner, exact stored bytes and challenge. */
export function ownerAuthorizationGateReview(supplied, suppliedState, gateSpkiBase64, nowMs) {
  const r = closed(supplied, REVIEW_FIELDS), state = ownerAuthorizationOwnerState(suppliedState)
  const pin = ownerAuthorizationGatePin(gateSpkiBase64)
  const authorization = ownerAuthorization(r.owner_authorization)
  if (r.version !== 3 || r.displayable !== true || !integer(nowMs)
    || !integer(r.created) || !integer(r.expires) || !integer(r.review_issued_at_ms) || !integer(r.review_expires)
    || r.created > r.review_issued_at_ms || r.review_issued_at_ms > nowMs || nowMs >= r.review_expires
    || r.review_expires > r.expires || r.pubkey_fp !== pin.pubkey_fp || r.gate_pubkey_sha256 !== pin.gate
    || !ascii(r.content, 0, 12000) || !ascii(r.diff, 0, 12000, true) || r.content.length + r.diff.length > 12000
    || sha(Buffer.from(r.content, 'utf8')) !== r.new_sha
    || !(r.from_to === null || ascii(r.from_to, 1, 600))
    || !['ROUTINE', 'CRITICAL'].includes(r.clarity_label) || !ascii(r.what_this_does, 1, 200)
    || !(r.model_note === null || ascii(r.model_note, 0, 200))) fail('gate-review')
  const expected = ownerAuthorization({ version: 1, kind: 'aukora-owner-authorization/v1', operation: r.kind,
    proposal_id: r.id, target: r.target, before_sha256: r.base_sha, after_sha256: r.new_sha,
    gate: pin.gate, challenge: r.review_challenge, issued_at_ms: r.review_issued_at_ms,
    expires_at_ms: r.review_expires, owner_subject: state.owner_subject,
    owner_root_id: state.owner_root_id, owner_epoch: state.owner_epoch })
  if (ownerAuthorizationText(authorization) !== ownerAuthorizationText(expected)
    || r.authorization_digest !== ownerAuthorizationDigest(expected)) fail('gate-review-mismatch')
  const review = Object.freeze({ ...r, owner_authorization: authorization, review_issue: coordinate(r.review_issue) })
  const expectations = Object.freeze({ owner_root_spki_base64: state.owner_root_spki_base64,
    authorization_digest: r.authorization_digest, ...expected })
  return Object.freeze({ review, authorization, expectations, owner_state: state, gate_pin: pin })
}

const RECEIPT_FIELDS = Object.freeze(['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha',
  'applied_at', 'approver', 'pubkey_fp', 'gate_pubkey_sha256', 'owner_authorization',
  'owner_accepted_at_ms', 'owner_consumption'])

/** Authenticate H's v3 gate acknowledgement before using its signed acceptance time. This does not
 * replace H/D/E retained-row/ledger-chain/epoch/revocation verification for historical evidence. */
export function verifyOwnerAuthorizationGateReceipt(suppliedReceipt, signatureBase64, proof, prepared, nowMs) {
  const receipt = closed(suppliedReceipt, RECEIPT_FIELDS, true)
  const pin = ownerAuthorizationGatePin(prepared.gate_pin.spki_base64)
  const ref = closed(receipt.owner_authorization, ['version', 'kind', 'authorization_id', 'proof_sha256'], true)
  const consumed = closed(receipt.owner_consumption, ['ledger_seq', 'ledger_hash', 'review_issue'], true)
  if (ref.version !== 1 || ref.kind !== 'aukora-owner-authorization-ref/v1'
    || !hex64(ref.authorization_id) || !hex64(ref.proof_sha256)
    || RECEIPT_FIELDS.filter(field => !['v', 'owner_accepted_at_ms', 'owner_authorization', 'owner_consumption'].includes(field))
      .some(field => typeof receipt[field] !== 'string')
    || !integer(receipt.v) || !integer(receipt.owner_accepted_at_ms)) fail('gate-receipt-shape')
  receipt.owner_authorization = Object.freeze(ref)
  coordinate({ ledger_seq: consumed.ledger_seq, ledger_hash: consumed.ledger_hash })
  receipt.owner_consumption = Object.freeze({ ...consumed, review_issue: coordinate(consumed.review_issue, true) })
  if (typeof signatureBase64 !== 'string' || signatureBase64.length !== 88) fail('gate-receipt-signature')
  const signature = Buffer.from(signatureBase64, 'base64')
  if (signature.length !== 64 || signature.toString('base64') !== signatureBase64) fail('gate-receipt-signature')
  const key = createPublicKey({ key: Buffer.from(pin.spki_base64, 'base64'), format: 'der', type: 'spki' })
  if (!verify(null, Buffer.from(JSON.stringify(receipt)), key, signature)) fail('gate-receipt-signature')
  const a = prepared.authorization, accepted = receipt.owner_accepted_at_ms
  const appliedAt = typeof receipt.applied_at === 'string' ? Date.parse(receipt.applied_at) : NaN
  if (receipt.v !== 3 || receipt.kind !== a.operation || receipt.proposal !== a.proposal_id
    || receipt.target !== a.target || receipt.base_sha !== a.before_sha256 || receipt.new_sha !== a.after_sha256
    || receipt.approver !== a.owner_subject || receipt.pubkey_fp !== pin.pubkey_fp
    || receipt.gate_pubkey_sha256 !== pin.gate || !integer(accepted) || !integer(nowMs) || accepted > nowMs
    || !integer(appliedAt) || appliedAt < accepted || appliedAt > nowMs
    || new Date(appliedAt).toISOString() !== receipt.applied_at
    || receipt.owner_consumption.ledger_seq <= receipt.owner_consumption.review_issue.ledger_seq
    || receipt.owner_consumption.review_issue.ledger_seq !== prepared.review.review_issue.ledger_seq
    || receipt.owner_consumption.review_issue.ledger_hash !== prepared.review.review_issue.ledger_hash) fail('gate-receipt-mismatch')
  // accepted is used ONLY after the independently pinned gate signature authenticated that exact value.
  const verified = verifyOwnerAuthorizationReference(proof, receipt.owner_authorization, prepared.expectations, accepted)
  return Object.freeze({ status: 'authenticated-gate-acknowledgement', receipt: Object.freeze(receipt),
    reference: verified.reference, grants_authority: false, retained_history: 'H/D/E-verification-required' })
}

/** Format validation only. The gate must supply and enforce its actual allowlist. */
export function ownerAuthorization(supplied) {
  const a = closed(supplied, AUTHORIZATION_FIELDS)
  if (a.version !== 1 || a.kind !== 'aukora-owner-authorization/v1'
    || !['change', 'revert'].includes(a.operation)
    || !['after_sha256', 'challenge', 'gate', 'owner_root_id'].every(key => hex64(a[key]))
    || !(a.before_sha256 === 'absent' || hex64(a.before_sha256))
    || a.before_sha256 === a.after_sha256
    || !integer(a.owner_epoch) || a.owner_epoch < 1
    || !integer(a.issued_at_ms) || !integer(a.expires_at_ms)
    || a.expires_at_ms <= a.issued_at_ms || a.expires_at_ms - a.issued_at_ms > 120000
    || typeof a.owner_subject !== 'string' || a.owner_subject.length !== 73
    || !/^aukora:1:[0-9a-f]{64}$/u.test(a.owner_subject)
    || typeof a.proposal_id !== 'string' || a.proposal_id.length !== 36
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(a.proposal_id)) fail('object')
  if (typeof a.target !== 'string' || a.target.length === 0 || a.target.length > 200 || /[^\x20-\x7e]/u.test(a.target)
    || a.target.includes('\\')) fail('target')
  const parts = a.target.split('/')
  if (parts.length < 3 || parts[0] !== 'plugins' || parts.some(part => ['', '.', '..'].includes(part))) fail('target')
  return Object.freeze(a)
}

export const ownerAuthorizationText = authorization => JSON.stringify(ownerAuthorization(authorization))
export const ownerAuthorizationSigningBytes = authorization => Buffer.from(OWNER_AUTHORIZATION_DOMAIN + ownerAuthorizationText(authorization), 'utf8')
export const ownerAuthorizationDigest = authorization => sha(ownerAuthorizationSigningBytes(authorization))
export function parseOwnerAuthorization(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 4096) fail('wire')
  let authorization
  try { authorization = ownerAuthorization(JSON.parse(text)) } catch { fail('wire') }
  if (ownerAuthorizationText(authorization) !== text) fail('noncanonical-wire')
  return authorization
}

function normalizedProof(supplied) {
  const proof = closed(supplied, ['algorithm', 'authorization', 'signature_base64'])
  if (proof.algorithm !== OWNER_KEY_ALGORITHM || typeof proof.signature_base64 !== 'string'
    || proof.signature_base64.length > 96) fail('signature')
  const signature = Buffer.from(proof.signature_base64, 'base64')
  if (signature.length < 8 || signature.length > 72 || signature.toString('base64') !== proof.signature_base64) fail('signature')
  return Object.freeze({ algorithm: proof.algorithm, authorization: ownerAuthorization(proof.authorization),
    signature_base64: proof.signature_base64 })
}

export function ownerAuthorizationProofText(proof) { return JSON.stringify(normalizedProof(proof)) }
export function ownerAuthorizationProofDigest(proof) {
  return sha(Buffer.from(OWNER_AUTHORIZATION_PROOF_DOMAIN + ownerAuthorizationProofText(proof), 'utf8'))
}

/** Full independently issued live challenge expectations, including exact unsigned-body digest. */
export function verifyOwnerAuthorization(supplied, expectations, nowMs) {
  const proof = normalizedProof(supplied), a = proof.authorization
  const e = closed(expectations, ['owner_root_spki_base64', 'authorization_digest', ...AUTHORIZATION_FIELDS])
  const pin = ownerRootPin(e.owner_root_spki_base64)
  if (!integer(nowMs) || a.issued_at_ms > nowMs || nowMs >= a.expires_at_ms) fail('expired')
  if (a.owner_root_id !== pin.owner_root_id) fail('root-mismatch')
  if (e.authorization_digest !== ownerAuthorizationDigest(a)) fail('challenge-mismatch')
  for (const field of AUTHORIZATION_FIELDS) if (e[field] !== a[field]) fail('expectation-mismatch')
  const key = createPublicKey({ key: Buffer.from(pin.spki_base64, 'base64'), format: 'der', type: 'spki' })
  if (!verify('sha256', ownerAuthorizationSigningBytes(a), key, Buffer.from(proof.signature_base64, 'base64'))) fail('signature')
  const reference = Object.freeze({ version: 1, kind: 'aukora-owner-authorization-ref/v1',
    authorization_id: ownerAuthorizationDigest(a), proof_sha256: ownerAuthorizationProofDigest(proof) })
  return Object.freeze({ status: 'verified-owner-authorization', authorization: a, proof, reference,
    custody: 'independent-enrollment-required', activation: 'UNPERFORMED', grants_authority: false })
}

/** The host transaction must recheck CURRENT commit-time expiry/epoch/state, retain the exact proof,
 * spend the challenge and mark applying BEFORE effects. A callback true is not independent evidence. */
export async function consumeOwnerAuthorization(proof, expectations, { nowMs, consumeOnce } = {}) {
  if (typeof consumeOnce !== 'function') fail('durable-consumer-required')
  const verified = verifyOwnerAuthorization(proof, expectations, nowMs)
  const claim = Object.freeze({ authorization: verified.authorization, proof: verified.proof,
    reference: verified.reference })
  if (await consumeOnce(claim) !== true) fail('replay-or-consumption-unknown')
  return verified
}

/** Compare a reference already authenticated by the gate receipt verifier. No receipt authentication here. */
export function verifyOwnerAuthorizationReference(proof, suppliedReference, expectations, nowMs) {
  const reference = closed(suppliedReference, ['version', 'kind', 'authorization_id', 'proof_sha256'])
  const verified = verifyOwnerAuthorization(proof, expectations, nowMs)
  if (reference.version !== 1 || reference.kind !== 'aukora-owner-authorization-ref/v1'
    || reference.authorization_id !== verified.reference.authorization_id
    || reference.proof_sha256 !== verified.reference.proof_sha256) fail('receipt-reference')
  return verified
}

export function ownerAuthorizationPreview(supplied) {
  const a = ownerAuthorization(supplied)
  return Object.freeze({ operation: a.operation, target: a.target, before_sha256: a.before_sha256,
    after_sha256: a.after_sha256, gate: a.gate, proposal_id: a.proposal_id, challenge: a.challenge,
    issued_at_ms: a.issued_at_ms, expires_at_ms: a.expires_at_ms, owner_epoch: a.owner_epoch,
    owner_subject: a.owner_subject, owner_root_id: a.owner_root_id,
    authorization_digest: ownerAuthorizationDigest(a) })
}
