// SPDX-License-Identifier: AGPL-3.0-or-later
// Test-only signer: P-256 private key, canonical authorization, matching root and preview.
import { createHash, createPublicKey, sign } from 'node:crypto'
import { OWNER_KEY_ALGORITHM } from '../src/index.mjs'
import { parseOwnerAuthorization, ownerAuthorizationPreview, ownerAuthorizationSigningBytes } from '../src/authorization.mjs'

const fail = code => { throw Object.assign(new Error(`software-owner-signer:${code}`), { code: `software-owner-signer:${code}` }) }

export function createSoftwareOwnerAuthorizationSigner(privateKey) {
  if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'ec'
    || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') fail('p256-private-key-required')
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  const root = createHash('sha256').update(publicDer).digest('hex')
  return async function presentOwnerAction({ kind, wire, preview }) {
    if (kind !== 'owner-authorization') fail('kind')
    const authorization = parseOwnerAuthorization(wire)
    if (authorization.owner_root_id !== root) fail('root-mismatch')
    if (JSON.stringify(preview) !== JSON.stringify(ownerAuthorizationPreview(authorization))) fail('preview-mismatch')
    return Object.freeze({ status: 'signed', proof: Object.freeze({ algorithm: OWNER_KEY_ALGORITHM, authorization,
      signature_base64: sign('sha256', ownerAuthorizationSigningBytes(authorization), privateKey).toString('base64') }) })
  }
}
