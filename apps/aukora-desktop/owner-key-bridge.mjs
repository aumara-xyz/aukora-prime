// SPDX-License-Identifier: AGPL-3.0-or-later
// Host-only presentation adapter. No socket/CLI signer and no renderer approval boolean.
import { ownerKeyRequest, ownerKeyRequestText, ownerKeyPreview, verifyOwnerKeyBinding } from '../../packages/owner-key/src/index.mjs'

export function createOwnerKeyBridge({ presentOwnerAction, expectations, nowSeconds = () => Math.floor(Date.now() / 1000) } = {}) {
  if (typeof presentOwnerAction !== 'function') throw Object.assign(new Error('Native owner action unavailable'), { code: 'owner-key:native-unavailable' })
  // Expectations contain public deployment pins; detach before asynchronous presentation.
  const pins = Object.freeze({ ...expectations })
  let pending = false
  return Object.freeze({
    async requestBinding(supplied) {
      if (pending) return Object.freeze({ status: 'refused', reason: 'owner-key:busy', grants_authority: false })
      pending = true
      try {
        const request = ownerKeyRequest(supplied), wire = ownerKeyRequestText(request)
        const reply = await presentOwnerAction(Object.freeze({ wire, preview: ownerKeyPreview(request) }))
        if (reply?.status === 'cancelled') return Object.freeze({ status: 'cancelled', grants_authority: false })
        if (reply?.status !== 'signed') return Object.freeze({ status: 'unavailable', reason: 'owner-key:native-unavailable', grants_authority: false })
        const proof = reply.proof
        // The reply must certify the exact immutable action displayed; no substitution.
        if (ownerKeyRequestText(proof?.request) !== wire) throw Object.assign(new Error('Changed action'), { code: 'owner-key:changed-request' })
        verifyOwnerKeyBinding(proof, pins, nowSeconds())
        return Object.freeze({ status: 'signed-binding', proof: Object.freeze({ algorithm: proof.algorithm,
          request, signature_base64: proof.signature_base64 }), grants_authority: false })
      } catch (error) {
        const reason = /^owner-key:[a-z-]+$/u.test(error?.code ?? '') ? error.code : 'owner-key:unavailable'
        return Object.freeze({ status: 'refused', reason, grants_authority: false })
      } finally { pending = false }
    },
  })
}
