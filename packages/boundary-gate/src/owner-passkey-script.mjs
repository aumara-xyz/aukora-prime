// SPDX-License-Identifier: AGPL-3.0-or-later
// The owner page signs only the gate's displayed card digest with its enrolled passkey.
export function passkeyOwnerScript(environment = globalThis) {
  const { document, location, navigator } = environment
  const root = document.querySelector('[data-owner-passkey]'), status = document.querySelector('#status')
  const profile = { origin: root.dataset.origin, rpId: root.dataset.rpId }
  const error = code => { throw new Error(code) }
  const show = value => { status.textContent = value }
  let busy = false
  function assertProfile() {
    if (environment.isSecureContext !== true || location.origin !== profile.origin ||
      new URL(profile.origin).protocol !== 'https:' || new URL(profile.origin).hostname !== profile.rpId ||
      typeof environment.PublicKeyCredential !== 'function' || typeof navigator.credentials?.get !== 'function' ||
      typeof navigator.credentials?.create !== 'function') error('OWNER_PASSKEY_BROWSER_PROFILE_REFUSED')
  }
  function encode(value) {
    if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) error('OWNER_PASSKEY_BYTES_REQUIRED')
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    return environment.btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  function decode(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) error('OWNER_PASSKEY_OPTIONS_INVALID')
    const bytes = Uint8Array.from(environment.atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), character => character.charCodeAt(0))
    if (encode(bytes) !== value) error('OWNER_PASSKEY_OPTIONS_INVALID')
    return bytes
  }
  function assertion(credential, options) {
    if (credential?.type !== 'public-key' || !credential.response) error('OWNER_PASSKEY_ASSERTION_CANCELLED')
    const credential_id = encode(credential.rawId)
    if (!options.allowCredentials.some(allowed => allowed.id === credential_id)) error('OWNER_PASSKEY_CREDENTIAL_REFUSED')
    return { kind: 'passkey', credential_id, client_data_json: encode(credential.response.clientDataJSON),
      authenticator_data: encode(credential.response.authenticatorData), signature: encode(credential.response.signature),
      user_handle: credential.response.userHandle == null ? null : encode(credential.response.userHandle) }
  }
  function getOptions(publicKey) {
    if (!publicKey || publicKey.rpId !== profile.rpId || publicKey.userVerification !== 'required' ||
      !Array.isArray(publicKey.allowCredentials) || !publicKey.allowCredentials.length ||
      publicKey.allowCredentials.some(allowed => allowed.type !== 'public-key')) error('OWNER_PASSKEY_OPTIONS_REFUSED')
    return { ...publicKey, challenge: decode(publicKey.challenge),
      allowCredentials: publicKey.allowCredentials.map(allowed => ({ ...allowed, id: decode(allowed.id) })) }
  }
  async function post(path, body) {
    assertProfile()
    const response = await environment.fetch(path, { method: 'POST', credentials: 'omit', redirect: 'error',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    const result = await response.json()
    if (!response.ok || result.ok !== true) error(result.error || 'OWNER_PASSKEY_REQUEST_REFUSED')
    return result.result
  }
  function action(element, event, run) {
    element.addEventListener(event, async e => {
      e.preventDefault()
      if (busy) return
      busy = true; element.disabled = true
      try { await run() } catch (e) { show(e.message || 'OWNER_PASSKEY_REFUSED') }
      finally { busy = false; element.disabled = false }
    })
  }
  async function enroll() {
    const claim = document.querySelector('#claim-code')
    const started = await post('/owner/enroll/start', { claim_code: claim.value })
    claim.value = ''
    const publicKey = started.public_key
    if (!publicKey || publicKey.rp?.id !== profile.rpId || publicKey.attestation !== 'none' ||
      publicKey.authenticatorSelection?.userVerification !== 'required') error('OWNER_PASSKEY_CREATION_OPTIONS_REFUSED')
    const options = { ...publicKey, challenge: decode(publicKey.challenge), user: { ...publicKey.user, id: decode(publicKey.user.id) },
      excludeCredentials: (publicKey.excludeCredentials || []).map(credential => ({ ...credential, id: decode(credential.id) })) }
    show('Create the owner passkey on this device, then confirm possession.')
    const credential = await navigator.credentials.create({ publicKey: options })
    if (credential?.type !== 'public-key' || !credential.response) error('OWNER_PASSKEY_REGISTRATION_CANCELLED')
    const raw_id = encode(credential.rawId), extensions = credential.getClientExtensionResults()
    if (Object.keys(extensions).length !== 0) error('OWNER_PASSKEY_REGISTRATION_EXTENSIONS_REFUSED')
    const registration = { kind: 'passkey-registration', type: 'public-key', id: raw_id, raw_id,
      client_data_json: encode(credential.response.clientDataJSON), attestation_object: encode(credential.response.attestationObject),
      client_extension_results: extensions }
    const registered = await post('/owner/enroll/register', { enrollment_id: started.enrollment_id, registration })
    const get = getOptions(registered.public_key)
    const possession = await navigator.credentials.get({ publicKey: get })
    await post('/owner/enroll/finish', { enrollment_id: started.enrollment_id, assertion: assertion(possession, registered.public_key) })
    document.querySelector('#enroll-form').hidden = true
    show('Owner passkey enrolled. Enrollment is closed.')
  }
  const bearer = document.querySelector('#owner-bearer')?.value
  async function review(card) {
    const review = await post('/owner/review', { bearer, id: card.dataset.id })
    const authorization = review.owner_authorization
    if (typeof review.card_text !== 'string' || authorization?.version !== 2 || !/^[a-f0-9]{64}$/.test(review.authorization_digest)) error('OWNER_PASSKEY_REVIEW_INVALID')
    const bytes = new TextEncoder().encode(review.card_text)
    const digest = new Uint8Array(await environment.crypto.subtle.digest('SHA-256', bytes))
    const hex = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('')
    if (hex !== authorization.card_sha256) error('OWNER_PASSKEY_CARD_DIGEST_REFUSED')
    const options = review.public_key
    const challenge = Uint8Array.from(review.authorization_digest.match(/../g), byte => parseInt(byte, 16))
    if (options?.challenge !== encode(challenge)) error('OWNER_PASSKEY_CHALLENGE_REFUSED')
    getOptions(options)
    card.querySelector('[data-card-text]').textContent = review.card_text
    card.querySelector('[data-authorization]').textContent = JSON.stringify(authorization, null, 2)
    card.querySelector('[data-authorization]').hidden = false
    const approve = card.querySelector('[data-approve]')
    approve.hidden = false
    approve.onclick = async e => {
      e.preventDefault()
      if (busy) return
      busy = true; approve.disabled = true
      try {
        assertProfile()
        const credential = await navigator.credentials.get({ publicKey: getOptions(options) })
        const proof = { version: 2, algorithm: 'webauthn-es256-sha256', authorization, assertion: assertion(credential, options) }
        const result = await post('/owner/approve', { bearer, id: review.id, base_sha: review.base_sha, new_sha: review.new_sha,
          review_challenge: review.review_challenge, owner_authorization_proof: proof })
        show(result.applied ? 'Applied once. Retain the gate receipt.' : 'No effect: ' + (result.message || 'refused'))
        approve.hidden = true
      } catch (e) { show(e.message || 'OWNER_PASSKEY_REFUSED'); approve.hidden = true }
      finally { busy = false; approve.disabled = false }
    }
    show('Read the exact card and node authorization below. Approve requests this device’s local user check.')
  }
  try {
    assertProfile()
    if (root.dataset.mode === 'enroll') action(document.querySelector('#enroll-form'), 'submit', enroll)
    else {
      environment.history.replaceState(null, '', '/owner/cards')
      for (const card of document.querySelectorAll('[data-card]')) action(card.querySelector('[data-review]'), 'click', () => review(card))
    }
  } catch (e) { show(e.message || 'OWNER_PASSKEY_REFUSED') }
}

export const OWNER_PASSKEY_SCRIPT = '(' + passkeyOwnerScript.toString() + ')(globalThis)\n'
