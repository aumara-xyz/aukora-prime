// SPDX-License-Identifier: AGPL-3.0-or-later
// Test-only in-memory mutation; never imported by the package or native bridge.
import { registerHooks } from 'node:module'
const mutations = {
  signature: ["if (!verify('sha256', ownerKeySigningBytes(r), key, sig)) fail('signature')", 'void 0'],
  expiry: ["if (!integer(nowSeconds) || r.issued_at > nowSeconds || nowSeconds >= r.expires_at) fail('expired')", 'void 0'],
  challenge: ["if (e.request_digest !== ownerKeyRequestDigest(r)) fail('challenge-mismatch')", 'void 0'],
  expectations: ["for (const key of Object.keys(e)) if (!['owner_root_spki_base64', 'request_digest'].includes(key) && r[key] !== e[key]) fail('expectation-mismatch')", 'void 0'],
  wire: ["if (ownerKeyRequestText(request) !== text) fail('noncanonical-wire')", 'void 0'],
  consume: ["if (await consumeOnce(claim) !== true) fail('replay-or-consumption-unknown')", 'await consumeOnce(claim)'],
}
const authorizationMutations = {
  signature: ["if (!verify('sha256', ownerAuthorizationSigningBytes(a), key, Buffer.from(proof.signature_base64, 'base64'))) fail('signature')", 'void 0'],
  expiry: ["if (!integer(nowMs) || a.issued_at_ms > nowMs || nowMs >= a.expires_at_ms) fail('expired')", 'void 0'],
  challenge: ["if (e.authorization_digest !== ownerAuthorizationDigest(a)) fail('challenge-mismatch')", 'void 0'],
  expectations: ["for (const field of AUTHORIZATION_FIELDS) if (e[field] !== a[field]) fail('expectation-mismatch')", 'void 0'],
  wire: ["if (ownerAuthorizationText(authorization) !== text) fail('noncanonical-wire')", 'void 0'],
  consume: ["if (await consumeOnce(claim) !== true) fail('replay-or-consumption-unknown')", 'await consumeOnce(claim)'],
  reference: ["if (reference.version !== 1 || reference.kind !== 'aukora-owner-authorization-ref/v1'\n    || reference.authorization_id !== verified.reference.authorization_id\n    || reference.proof_sha256 !== verified.reference.proof_sha256) fail('receipt-reference')", 'void 0'],
}
const callerMutations = {
  'review-bytes': ['/packages/owner-key/src/authorization.mjs',
    "|| sha(Buffer.from(r.content, 'utf8')) !== r.new_sha", ''],
  'receipt-signature': ['/packages/owner-key/src/authorization.mjs',
    "if (!verify(null, Buffer.from(JSON.stringify(receipt)), key, signature)) fail('gate-receipt-signature')", 'void 0'],
  'receipt-transition': ['/packages/owner-key/src/authorization.mjs',
    '|| receipt.target !== a.target || receipt.base_sha !== a.before_sha256 || receipt.new_sha !== a.after_sha256', ''],
  'receipt-reference': ['/packages/owner-key/src/authorization.mjs',
    'const verified = verifyOwnerAuthorizationReference(proof, receipt.owner_authorization, prepared.expectations, accepted)',
    'const verified = verifyOwnerAuthorization(proof, prepared.expectations, accepted)'],
  'inflight-review': ['/apps/aukora-desktop/owner-key-bridge.mjs',
    'disposed || preparing || questions.size || inflight.size', 'disposed || preparing || questions.size'],
  'review-proposal': ['/apps/aukora-desktop/owner-key-bridge.mjs',
    "if (prepared.authorization.proposal_id !== id) return unavailable('owner-authorization:trusted-review-unavailable')", 'void 0'],
  'post-native-state': ['/apps/aukora-desktop/owner-key-bridge.mjs',
    "if (disposed || question.cancelled || stillVisible() !== true || JSON.stringify(read()) !== JSON.stringify(prepared.owner_state))\n          return unavailable('owner-authorization:question-or-owner-changed')", 'void 0'],
}
const suite = process.env.AUKORA_OWNER_KEY_SUITE
const authorization = suite === 'authorization', caller = suite === 'caller'
const callerSelected = callerMutations[process.env.AUKORA_OWNER_KEY_MUTANT]
const selected = caller ? callerSelected?.slice(1) : (authorization ? authorizationMutations : mutations)[process.env.AUKORA_OWNER_KEY_MUTANT]
if (!selected) throw Error('Unknown test-only mutation')
registerHooks({ load(url, context, next) {
  const result = next(url, context)
  if (!url.endsWith(caller ? callerSelected[0] : authorization ? '/packages/owner-key/src/authorization.mjs' : '/packages/owner-key/src/index.mjs')) return result
  const text = Buffer.isBuffer(result.source) || result.source instanceof Uint8Array
    ? Buffer.from(result.source).toString('utf8') : result.source
  if (typeof text !== 'string' || text.split(selected[0]).length !== 2) throw Error('Mutation preimage mismatch')
  return { ...result, source: text.replace(selected[0], selected[1]) }
} })
