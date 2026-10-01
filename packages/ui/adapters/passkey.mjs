import { PrimeTransportError } from './transport.mjs'

function binary(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  throw new PrimeTransportError('INVALID', 'ui:invalid-assertion-bytes')
}
function encode(value) {
  return btoa(Array.from(binary(value), byte => String.fromCharCode(byte)).join(''))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function decode(value) {
  if (typeof value !== 'string' || !value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new PrimeTransportError('INVALID', 'ui:invalid-passkey-options')
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)
  let bytes
  try { bytes = Uint8Array.from(atob(padded), character => character.charCodeAt(0)) }
  catch { throw new PrimeTransportError('INVALID', 'ui:invalid-passkey-options') }
  if (encode(bytes) !== value) throw new PrimeTransportError('INVALID', 'ui:noncanonical-passkey-options')
  return bytes
}

/** Existing-credential assertion only. This module has no credentials.create or enrollment route. */
export function createBrowserPasskeySigner({ getCredential, contracts, profile, environment = globalThis } = {}) {
  if (profile && typeof profile === 'object') profile = Object.freeze({ ...profile })
  const get = getCredential ?? (async options => {
    if (typeof environment.navigator?.credentials?.get !== 'function') {
      throw new PrimeTransportError('UNAVAILABLE', 'ui:passkey-api-unavailable')
    }
    return environment.navigator.credentials.get(options)
  })
  return async ({ purpose, request, public_key, signal }) => {
    if (!profile || Object.keys(profile).sort().join(',') !== 'origin,profile,rp_id' ||
        typeof profile.origin !== 'string' || typeof profile.rp_id !== 'string') {
      throw new PrimeTransportError('UNAVAILABLE', 'ui:passkey-profile-unavailable')
    }
    let origin
    try { origin = new URL(profile.origin) }
    catch { throw new PrimeTransportError('UNAVAILABLE', 'ui:passkey-profile-unavailable') }
    const validRp = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(profile.rp_id) &&
      !/^\d+(?:\.\d+){3}$/.test(profile.rp_id)
    const configuredHttps = profile.profile === 'https' && origin.protocol === 'https:' && validRp &&
      (origin.hostname === profile.rp_id || origin.hostname.endsWith('.' + profile.rp_id))
    const localhostPilot = profile.profile === 'localhost-pilot-v1' && profile.origin === 'http://localhost:18731' && profile.rp_id === 'localhost'
    if (origin.origin !== profile.origin || (!configuredHttps && !localhostPilot) || environment.location?.origin !== profile.origin ||
        environment.isSecureContext !== true || typeof environment.navigator?.credentials?.get !== 'function' ||
        typeof environment.PublicKeyCredential !== 'function' || public_key?.rpId !== profile.rp_id) {
      throw new PrimeTransportError('UNAVAILABLE', 'ui:passkey-browser-profile-unavailable')
    }
    if (!public_key || public_key.userVerification !== 'required' ||
        typeof public_key.rpId !== 'string' || !public_key.rpId ||
        !Array.isArray(public_key.allowCredentials) || !public_key.allowCredentials.length) {
      throw new PrimeTransportError('UNAVAILABLE', 'ui:passkey-not-configured')
    }
    if (typeof contracts?.canonicalJson !== 'function' || !globalThis.crypto?.subtle) {
      throw new PrimeTransportError('UNAVAILABLE', 'ui:passkey-contract-helper-unavailable')
    }
    const domain = purpose === 'login' ? 'aukora-prime.owner-login.v1'
      : purpose === 'approval' ? 'aukora:owner-approval-signature:v1' : null
    if (!domain) throw new PrimeTransportError('INVALID', 'ui:passkey-purpose-invalid')
    const expected = await globalThis.crypto.subtle.digest('SHA-256',
      new TextEncoder().encode(domain + '\0' + contracts.canonicalJson(request)))
    if (encode(expected) !== public_key.challenge) throw new PrimeTransportError('TARGET_MISMATCH', 'ui:passkey-challenge-request-mismatch')
    const options = {
      ...public_key,
      challenge: decode(public_key.challenge),
      allowCredentials: public_key.allowCredentials.map(credential => {
        if (credential.type !== 'public-key') throw new PrimeTransportError('INVALID', 'ui:invalid-passkey-options')
        return { ...credential, id: decode(credential.id) }
      }),
    }
    const credential = await get({ publicKey: options, signal })
    if (!credential || credential.type !== 'public-key' || !credential.response) {
      throw new PrimeTransportError('CANCELLED', 'ui:passkey-assertion-cancelled')
    }
    const credentialId = encode(credential.rawId)
    if (!public_key.allowCredentials.some(allowed => allowed.id === credentialId)) {
      throw new PrimeTransportError('UNAUTHORIZED', 'ui:passkey-credential-mismatch')
    }
    return Object.freeze({
      kind: 'passkey', credential_id: credentialId,
      client_data_json: encode(credential.response.clientDataJSON),
      authenticator_data: encode(credential.response.authenticatorData),
      signature: encode(credential.response.signature),
      user_handle: credential.response.userHandle === null ? null : encode(credential.response.userHandle),
    })
  }
}
