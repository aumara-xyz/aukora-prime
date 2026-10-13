// SPDX-License-Identifier: AGPL-3.0-or-later
// Retained enrollment requests bind registration and possession to one credential.
let modules
try {
  modules = await Promise.all([import('../../contracts/src/runtime.mjs'),
    import('../../authority/src/passkey-enrollment.mjs'), import('../../authority/src/webauthn.mjs')])
} catch (error) { if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error }
const { canonicalJson } = modules?.[0] ?? {}
const { PASSKEY_PILOT_GUARANTEE, passkeyRegistrationSigningBytes, passkeyPossessionSigningBytes,
  passkeyRegistrationCandidateDigest, passkeyBootstrapEvidenceDigest, verifyPasskeyRegistration } = modules?.[1] ?? {}
const { webauthnChallenge, webauthnOptions, verifyWebauthnAssertion } = modules?.[2] ?? {}

const refuse = code => { throw Object.assign(new Error('passkey:' + code), { code: 'passkey:' + code }) }

export function retainedEnrollment(request, binding, registration = null) {
  if (!modules) refuse('enrollment-runtime-unavailable')
  passkeyRegistrationSigningBytes(request)
  if (canonicalJson(request.binding) !== canonicalJson(binding)) refuse('ceremony-binding')
  const creation = { challenge: webauthnChallenge(passkeyRegistrationSigningBytes(request)),
    rp: { id: binding.passkey_profile.rp_id, name: 'AUKORA Prime' },
    user: { id: binding.user.id, name: binding.user.name, displayName: binding.user.display_name },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 60000,
    excludeCredentials: binding.existing_credential_ids.map(id => ({ type: 'public-key', id })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }, attestation: 'none', extensions: {} }
  const live = () => { if (Date.now() >= Date.parse(request.expiry)) refuse('ceremony-expired') }
  function accepted(material) {
    const candidate = verifyPasskeyRegistration({ material, binding, challenge: creation.challenge })
    const possession = { ...request, candidate_digest: passkeyRegistrationCandidateDigest(candidate) }
    const config = { profile: binding.passkey_profile.profile, rp_id: binding.passkey_profile.rp_id,
      origins: [binding.passkey_profile.origin], credentials: [candidate.credential] }
    return { candidate, possession, config, public_key: webauthnOptions(config, binding.identity.owner_id,
      webauthnChallenge(passkeyPossessionSigningBytes(possession))) }
  }
  const retained = registration === null ? null : accepted(registration)
  return {
    creationRequest() { live(); return { request, public_key: creation } },
    resume() { live(); return { stage: retained ? 'possession' : 'registration', public_key: retained?.public_key ?? creation } },
    acceptRegistration(material) { live(); if (retained) refuse('registration-closed'); return accepted(material) },
    confirmPossession(material) {
      live(); if (!retained) refuse('registration-required')
      const verified = verifyWebauthnAssertion({ material, config: retained.config, ownerId: binding.identity.owner_id,
        challenge: retained.public_key.challenge, counter: retained.candidate.credential.sign_count })
      live()
      const evidence = { version: 1, kind: 'prime-passkey-bootstrap/v1', registration_request: request,
        registration_material: registration, candidate: retained.candidate, possession_request: retained.possession,
        possession_material: material, credential: { ...retained.candidate.credential, sign_count: verified.sign_count },
        verified_at: new Date().toISOString(), guarantee: PASSKEY_PILOT_GUARANTEE,
        identity_provenance_verified: false, owner_enrollment: false, grants_authority: false }
      return { evidence, evidence_digest: passkeyBootstrapEvidenceDigest(evidence) }
    },
  }
}
