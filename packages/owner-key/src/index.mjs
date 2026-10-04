// SPDX-License-Identifier: AGPL-3.0-or-later
// Public certificate protocol only. No key creation/storage, signing or grants.
import { createHash, createPublicKey, verify } from 'node:crypto'

export const OWNER_KEY_DOMAIN = 'aukora:owner-key:scoped-binding:v1\0'
export const OWNER_KEY_ALGORITHM = 'p256-ecdsa-sha256'
export const REQUEST_FIELDS = Object.freeze(['action', 'audience', 'epoch', 'expires_at', 'issued_at',
  'nonce', 'owner_root_id', 'owner_subject', 'previous_binding_digest', 'previous_nostr_pubkey_hex',
  'request_id', 'scope', 'scoped_nostr_pubkey_hex', 'version'])
const HEX = /^[0-9a-f]{64}$/u
const hex64 = value => typeof value === 'string' && value.length === 64 && HEX.test(value)
const SUBJECT = /^aukora:1:[0-9a-f]{64}$/u
const fail = code => { throw Object.assign(new TypeError(`owner-key:${code}`), { code: `owner-key:${code}` }) }
const integer = x => Number.isSafeInteger(x) && !Object.is(x, -0) && x >= 0
const digest = bytes => createHash('sha256').update(bytes).digest('hex')

function closed(value, fields) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('shape')
    const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors)
    if (keys.length !== fields.length || keys.some(k => typeof k !== 'string' || !fields.includes(k))) fail('shape')
    const out = Object.create(null)
    for (const key of fields) {
      const d = descriptors[key]
      if (!d?.enumerable || !Object.hasOwn(d, 'value')) fail('shape')
      out[key] = d.value
    }
    return out
  } catch { fail('shape') }
}

/** A closed scalar wire format shared with the native approval view. */
export function ownerKeyRequest(supplied) {
  const r = closed(supplied, REQUEST_FIELDS)
  if (r.version !== 1 || !['bind-scoped-nostr', 'rotate-scoped-nostr'].includes(r.action)
    || !['aukora:records', 'aukora:aura', 'aukora:recall'].includes(r.audience)
    || !['owner-recipient', 'aura-author'].includes(r.scope)
    || typeof r.owner_subject !== 'string' || r.owner_subject.length !== 73 || !SUBJECT.test(r.owner_subject)
    || !['request_id', 'nonce', 'owner_root_id', 'scoped_nostr_pubkey_hex'].every(k => hex64(r[k]))
    || !integer(r.epoch) || r.epoch < 1 || !integer(r.issued_at) || !integer(r.expires_at)
    || r.expires_at <= r.issued_at || r.expires_at - r.issued_at > 120) fail('request')
  if (r.action === 'bind-scoped-nostr') {
    if (r.epoch !== 1 || r.previous_binding_digest !== null || r.previous_nostr_pubkey_hex !== null) fail('initial-binding')
  } else if (r.epoch < 2 || !hex64(r.previous_binding_digest)
    || !hex64(r.previous_nostr_pubkey_hex)
    || r.previous_nostr_pubkey_hex === r.scoped_nostr_pubkey_hex) fail('rotation')
  return Object.freeze(r)
}

export function ownerKeyRequestText(request) { return JSON.stringify(ownerKeyRequest(request)) }
export function ownerKeySigningBytes(request) { return Buffer.from(OWNER_KEY_DOMAIN + ownerKeyRequestText(request), 'utf8') }
export function ownerKeyRequestDigest(request) { return digest(ownerKeySigningBytes(request)) }

/** Only canonical bounded text crosses the native bridge. Duplicate keys refuse. */
export function parseOwnerKeyRequest(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 4096) fail('wire')
  let request
  try { request = ownerKeyRequest(JSON.parse(text)) } catch { fail('wire') }
  if (ownerKeyRequestText(request) !== text) fail('noncanonical-wire')
  return request
}

/** Canonical SPKI, pinned by an independent enrollment procedure; never proof-supplied. */
export function ownerRootPin(spkiBase64) {
  try {
    if (typeof spkiBase64 !== 'string' || spkiBase64.length > 256) fail('root-pin')
    const der = Buffer.from(spkiBase64, 'base64')
    if (der.toString('base64') !== spkiBase64) fail('root-pin')
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' })
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
      || !key.export({ format: 'der', type: 'spki' }).equals(der)) fail('root-pin')
    return Object.freeze({ owner_root_id: digest(der), spki_base64: spkiBase64 })
  } catch { fail('root-pin') }
}

export function ownerKeyPreview(request) {
  const r = ownerKeyRequest(request)
  return Object.freeze({ operation: r.action, audience: r.audience, scope: r.scope,
    owner_subject: r.owner_subject, owner_root_id: r.owner_root_id,
    from_nostr_pubkey_hex: r.previous_nostr_pubkey_hex, to_nostr_pubkey_hex: r.scoped_nostr_pubkey_hex,
    epoch: r.epoch, expires_at: r.expires_at, request_digest: ownerKeyRequestDigest(r) })
}

/**
 * Signed binding authenticity, not a gate grant or remote hardware/biometry attestation.
 * The host MUST independently enroll/pin custody and enforce durable epoch/nonce state.
 */
export function verifyOwnerKeyBinding(supplied, expectations, nowSeconds) {
  const proof = closed(supplied, ['algorithm', 'request', 'signature_base64'])
  const e = closed(expectations, ['owner_root_spki_base64', 'owner_subject', 'audience', 'scope',
    'epoch', 'previous_binding_digest', 'previous_nostr_pubkey_hex', 'scoped_nostr_pubkey_hex', 'request_id', 'nonce', 'request_digest'])
  const r = ownerKeyRequest(proof.request), pin = ownerRootPin(e.owner_root_spki_base64)
  if (!integer(nowSeconds) || r.issued_at > nowSeconds || nowSeconds >= r.expires_at) fail('expired')
  if (proof.algorithm !== OWNER_KEY_ALGORITHM || r.owner_root_id !== pin.owner_root_id) fail('root-mismatch')
  if (e.request_digest !== ownerKeyRequestDigest(r)) fail('challenge-mismatch')
  for (const key of Object.keys(e)) if (!['owner_root_spki_base64', 'request_digest'].includes(key) && r[key] !== e[key]) fail('expectation-mismatch')
  if (typeof proof.signature_base64 !== 'string' || proof.signature_base64.length > 96) fail('signature')
  const sig = Buffer.from(proof.signature_base64, 'base64')
  if (sig.length < 8 || sig.length > 72 || sig.toString('base64') !== proof.signature_base64) fail('signature')
  const key = createPublicKey({ key: Buffer.from(pin.spki_base64, 'base64'), format: 'der', type: 'spki' })
  if (!verify('sha256', ownerKeySigningBytes(r), key, sig)) fail('signature')
  return Object.freeze({ status: 'verified-binding', request: r, binding_digest: ownerKeyRequestDigest(r),
    owner_root_id: pin.owner_root_id, grants_authority: false,
    custody: 'independent-enrollment-required', activation: 'UNPERFORMED' })
}

/** Consume only through a trusted host's atomic durable callback, never an in-memory claim. */
export async function consumeOwnerKeyBinding(proof, expectations, { nowSeconds, consumeOnce } = {}) {
  if (typeof consumeOnce !== 'function') fail('durable-consumer-required')
  const result = verifyOwnerKeyBinding(proof, expectations, nowSeconds)
  const claim = Object.freeze({ request: result.request, owner_root_id: result.owner_root_id,
    binding_digest: result.binding_digest })
  if (await consumeOnce(claim) !== true) fail('replay-or-consumption-unknown')
  return result
}
