// SPDX-License-Identifier: AGPL-3.0-or-later
// ES256 assertions require the pinned credential, challenge, RP, origin, UP/UV and advancing counter.
import { createHash, createPublicKey, timingSafeEqual, verify } from 'node:crypto'
import { isIP } from 'node:net'
const hash = bytes => createHash('sha256').update(bytes).digest()
const fault = reason => { throw Object.assign(new Error(reason), { error_code: 'UNAUTHORIZED' }) }

function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fault('WEBAUTHN_DATA_INVALID')
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) fault('WEBAUTHN_DATA_INVALID')
  const out = Object.create(null)
  for (const field of fields) {
    if (!descriptors[field]?.enumerable || !Object.hasOwn(descriptors[field], 'value')) fault('WEBAUTHN_DATA_INVALID')
    out[field] = descriptors[field].value
  }
  return out
}

export function decodeBase64url(value, max = 65536) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max * 2 || !/^[A-Za-z0-9_-]+$/.test(value)) fault('WEBAUTHN_ENCODING_INVALID')
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length > max || bytes.toString('base64url') !== value) fault('WEBAUTHN_ENCODING_INVALID')
  return bytes
}

function publicKey(hex) {
  if (typeof hex !== 'string' || !/^04[a-f0-9]{128}$/.test(hex)) fault('WEBAUTHN_KEY_INVALID')
  const point = Buffer.from(hex, 'hex')
  return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') } })
}

export function prepareWebauthnConfig(input) {
  const c = closed(input, ['rp_id', 'origins', 'credentials'])
  if (typeof c.rp_id !== 'string' || !/^[a-z0-9]+([.-][a-z0-9]+)*$/.test(c.rp_id) || isIP(c.rp_id) !== 0
    || !Array.isArray(c.origins) || c.origins.length !== 1 || !Array.isArray(c.credentials) || c.credentials.length !== 1) fault('WEBAUTHN_CONFIG_INVALID')
  const origin = c.origins[0], url = new URL(origin)
  if (url.protocol !== 'https:' || url.origin !== origin || !(url.hostname === c.rp_id || url.hostname.endsWith('.' + c.rp_id))) fault('WEBAUTHN_ORIGIN_INVALID')
  const cred = closed(c.credentials[0], ['owner_id', 'credential_id', 'public_key_hex', 'user_handle', 'sign_count', 'backup_eligible'])
  decodeBase64url(cred.credential_id, 1024); decodeBase64url(cred.user_handle, 64); publicKey(cred.public_key_hex)
  if (typeof cred.owner_id !== 'string' || !cred.owner_id || !Number.isSafeInteger(cred.sign_count)
    || cred.sign_count < 0 || cred.sign_count > 0xffffffff || typeof cred.backup_eligible !== 'boolean') fault('WEBAUTHN_CREDENTIAL_INVALID')
  return { rp_id: c.rp_id, origins: [origin], credentials: [cred] }
}

export function webauthnOptions(config, ownerId, challenge) {
  const credentials = config.credentials.filter(c => c.owner_id === ownerId)
  if (!credentials.length) fault('WEBAUTHN_CREDENTIAL_NOT_PINNED')
  return { challenge, rpId: config.rp_id, allowCredentials: credentials.map(c => ({ type: 'public-key', id: c.credential_id })),
    userVerification: 'required', timeout: 60000 }
}

// Duplicate-key scanning follows packages/authority's strict clientDataJSON reader.
function clientData(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes), stack = []
  const parsed = JSON.parse(text)
  let index = 0
  while (index < text.length) {
    const character = text[index]
    if (character === '"') {
      const start = index++
      while (index < text.length) {
        if (text[index] === '\\') { index += 2; continue }
        if (text[index] === '"') break
        index++
      }
      const raw = text.slice(start + 1, index++)
      let probe = index
      while (probe < text.length && /\s/u.test(text[probe])) probe++
      const frame = stack[stack.length - 1]
      if (text[probe] === ':' && frame !== undefined) {
        const key = JSON.parse('"' + raw + '"')
        if (frame.has(key)) fault('WEBAUTHN_CLIENT_DATA_INVALID')
        frame.add(key)
      }
      continue
    }
    if (character === '{' || character === '[') {
      stack.push(new Set()); if (stack.length > 512) fault('WEBAUTHN_CLIENT_DATA_INVALID')
    } else if (character === '}' || character === ']') stack.pop()
    index++
  }
  const values = [parsed]
  while (values.length) {
    const value = values.pop()
    if (typeof value === 'number' && Number.isInteger(value) && !Number.isSafeInteger(value)) fault('WEBAUTHN_CLIENT_DATA_INVALID')
    if (typeof value === 'string' && /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) fault('WEBAUTHN_CLIENT_DATA_INVALID')
    if (value && typeof value === 'object') values.push(...Object.values(value))
  }
  return parsed
}

// The checks follow packages/authority/src/webauthn.mjs; signature verification uses Node's P-256 implementation.
export function verifyWebauthnAssertion({ material, config, ownerId, challenge, counter, checkCounter = true }) {
  if (!config) throw Object.assign(new Error('PASSKEY_VERIFIER_NOT_CONFIGURED'), { error_code: 'UNAVAILABLE' })
  const m = closed(material, ['kind', 'credential_id', 'client_data_json', 'authenticator_data', 'signature', 'user_handle'])
  if (m.kind !== 'passkey') fault('WEBAUTHN_MATERIAL_KIND')
  const credential = config.credentials.find(c => c.credential_id === m.credential_id && c.owner_id === ownerId)
  if (!credential) fault('WEBAUTHN_CREDENTIAL_NOT_PINNED')
  decodeBase64url(m.credential_id, 1024)
  if (m.user_handle !== null && !equal(decodeBase64url(m.user_handle, 64), decodeBase64url(credential.user_handle, 64))) fault('WEBAUTHN_USER_HANDLE_MISMATCH')
  const clientBytes = decodeBase64url(m.client_data_json, 16384), auth = decodeBase64url(m.authenticator_data, 4096), signature = decodeBase64url(m.signature, 128)
  let client
  try { client = clientData(clientBytes) } catch { fault('WEBAUTHN_CLIENT_DATA_INVALID') }
  if (!client || typeof client !== 'object' || Array.isArray(client)) fault('WEBAUTHN_CLIENT_DATA_INVALID')
  if (client.type !== 'webauthn.get' || client.challenge !== challenge || !config.origins.includes(client.origin)
    || client.crossOrigin === true || Object.hasOwn(client, 'topOrigin')) fault('WEBAUTHN_CHALLENGE_OR_ORIGIN_MISMATCH')
  if (client.crossOrigin !== undefined && client.crossOrigin !== false) fault('WEBAUTHN_CROSS_ORIGIN_REFUSED')
  if (auth.length !== 37 || !timingSafeEqual(auth.subarray(0, 32), hash(config.rp_id))) fault('WEBAUTHN_RP_ID_MISMATCH')
  const flags = auth[32]
  if ((flags & 1) === 0 || (flags & 4) === 0 || (flags & 0xe2) !== 0) fault('WEBAUTHN_UP_UV_OR_FLAGS_REFUSED')
  const backupEligible = (flags & 8) !== 0, backupState = (flags & 16) !== 0
  if (backupEligible !== credential.backup_eligible || (backupState && !backupEligible)) fault('WEBAUTHN_BACKUP_ELIGIBILITY_CHANGED')
  const signCount = auth.readUInt32BE(33), prior = counter ?? credential.sign_count
  if (checkCounter && (signCount !== 0 || prior !== 0) && signCount <= prior) fault('WEBAUTHN_COUNTER_REPLAYED')
  const signed = Buffer.concat([auth, hash(clientBytes)])
  if (!verify('sha256', signed, publicKey(credential.public_key_hex), signature)) fault('WEBAUTHN_SIGNATURE_INVALID')
  return { credential_id: credential.credential_id, sign_count: signCount, backup_eligible: backupEligible,
    backup_state: backupState, signed_bytes_digest: hash(signed).toString('hex'), user_present: true,
    user_verified: true, comprehension: 'not-proven' }
}
function equal(a, b) { return a.length === b.length && timingSafeEqual(a, b) }
