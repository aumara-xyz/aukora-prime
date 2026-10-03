# Setup-only passkey bootstrap

This source entry is separate from v1 login, approval and operation contracts. H must select and protect the exact initial public identity and its provenance before invoking it. A supplied public-key row, a successful creation response, or a provenance label alone does not establish owner enrollment. No setup route is mounted by this package.

`createPasskeyEnrollmentCeremony(binding)` captures an immutable closed binding:

```js
{
  identity: { owner_id, subject, approval_key_did, control_digest, authorization_epoch },
  identity_provenance: {
    kind: 'owner-approved-initial-public-identity/v1',
    identity_source_sha256, // lowercase 64 hex; independently reviewed public source
    approval_reference     // exact action-time approval reference, protected by H
  },
  passkey_profile: { profile, origin, rp_id },
  user: { id, name, display_name }, // id: canonical base64url, 1..64 public bytes
  existing_credential_ids: [] // all current owners; never silently replace a credential
}
```

The identity retains the existing five-field public projection and canonical Ed25519 DID. P-256 credential possession does not derive or prove that projection's Genesis/control relationship. H must provide its approved provenance; C will not generate a placeholder DID, private key or root identity.

Profiles use existing C rules: HTTPS by default; the explicit localhost pilot is exactly `http://localhost:18731` with RP ID `localhost`. No IP alias, other port, trailing dot, origin fallback or profile inference is accepted. Browser guards require exact `location.origin`, `isSecureContext === true`, `PublicKeyCredential`, and both `navigator.credentials.create` and `get`. Browser support remains an owner/browser observation, not a source check.

The ceremony returns a creation request and `public_key` JSON options. B converts only `challenge`, `user.id` and descriptor IDs to byte arrays and calls `navigator.credentials.create({publicKey})` after presenting the exact binding and limitations. Creation requests ES256 (`alg: -7`), user verification required, attestation none and no extensions.

The request preimages are UTF-8 of `aukora-prime.passkey-registration.v1\0` plus frozen sorted compact `canonicalJson(registration_request)`, and `aukora-prime.passkey-bootstrap-possession.v1\0` plus `canonicalJson(possession_request)`. `\0` is one NUL byte. Each WebAuthn challenge is canonical base64url of SHA-256 of that exact preimage. The creation request is closed `{version:1,ceremony_id,binding,issued_at,expiry}`; possession adds exactly `candidate_digest`, the domain-separated digest of C's returned candidate. B must compare the exact immutable captured binding, candidate and request/preimage/challenge before each browser call. The five-minute lifetime is shared by both phases and is not reset at candidate acceptance. Send C this exact closed material:

```js
{
  kind: 'passkey-registration', type: 'public-key', id, raw_id,
  client_data_json, attestation_object, client_extension_results: {}
}
```

All binary fields and both credential identifiers are canonical base64url. `id` and `raw_id` must equal the credential ID in authenticator data. Do not use browser `getPublicKey()` as the trusted key source. C parses the attested ES256 COSE key itself. Unsupported formats, including packed self-attestation, are refused by this narrow none-only verifier.

`acceptRegistration(material)` produces a candidate and a separate candidate-bound possession request with one allowCredentials ID. Creation alone never returns bootstrap evidence. B displays the candidate and invokes `navigator.credentials.get` only on the owner's explicit enrollment confirmation. Send its existing six-field passkey material unchanged: `{kind:'passkey',credential_id,client_data_json,authenticator_data,signature,user_handle}`. `confirmPossession(material)` verifies the real signature and retains the verified assertion counter. User verification is not proof of comprehension.

`decline()` is terminal at either stage. Failure, expiry or decline cannot be revived; process restart invalidates any unfinished ceremony. A fresh setup attempt requires a fresh explicit owner action. No automatic retry, owner-key fallback, session, consumed grant, operation permission, store provisioning or configuration write results from these functions.

Verified evidence contains the exact captured binding, both requests/materials, derived credential and fixed guarantee description. H must commit that evidence and its domain-separated digest in the protected setup manifest before provisioning. `validatePasskeyBootstrapEvidence({evidence,expected_binding,expected_digest})` re-verifies the public transcript and exact independently protected pin; it does not authenticate a caller's self-reported pin or provenance. Persistent enrollment/configuration changes retain action-time approval requirements. A lost or conflicting manifest stays unavailable; do not reconstruct it from browser/public records.

The setup subpath is `@aukora-prime/authority/setup/passkey-enrollment`. Normal service configuration can opt in with `passkeyBootstrap: {evidence,expected_binding,expected_digest}` from that protected manifest, the exact derived `webauthn` configuration, the matching original public identity in `identities`, and `loginKinds: ['passkey']`. Initial provisioning stores a domain-separated stable binding digest in the private owner row. Every subsequent owner lookup compares it, including refusal if the opt-in configuration is later omitted. Existing rows cannot be rebaselined into the profile. The stable digest binds the captured public identity/provenance, RP/origin/profile, user and credential ID/key/backup eligibility; mutable assertion counters and transcript signatures are excluded. The actual initial counter comes from the verified possession assertion. Legacy v1 behavior applies when both trusted configuration and stored history lack this pin. Same-host custody can still tamper with local state; the pin is not an independent witness.

Every setup status/evidence states REDUCED-GUARANTEE same-host pilot and names the missing independent state witness, second-host anchor, and hardware hash display. None attestation supplies no authenticator provenance or hardware custody proof. H must preserve these limitations in its outer pilot status/receipt evidence; frozen v1 operation and receipt fields are unchanged. This does not confer full qualification or a v0.3 claim.

Verification follows the [W3C registration procedure](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential) and [none attestation](https://www.w3.org/TR/webauthn-3/#sctn-none-attestation); ES256 uses the existing pinned Noble implementation.
