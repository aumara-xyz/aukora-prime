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
const selected = mutations[process.env.AUKORA_OWNER_KEY_MUTANT]
if (!selected) throw Error('Unknown test-only mutation')
registerHooks({ load(url, context, next) {
  const result = next(url, context)
  if (!url.endsWith('/packages/owner-key/src/index.mjs')) return result
  const text = Buffer.isBuffer(result.source) || result.source instanceof Uint8Array
    ? Buffer.from(result.source).toString('utf8') : result.source
  if (typeof text !== 'string' || text.split(selected[0]).length !== 2) throw Error('Mutation preimage mismatch')
  return { ...result, source: text.replace(selected[0], selected[1]) }
} })
