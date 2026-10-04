// SPDX-License-Identifier: AGPL-3.0-or-later
// Host-only presentation adapter. No socket/CLI signer and no renderer approval boolean.
import { ownerKeyRequest, ownerKeyRequestText, ownerKeyPreview, verifyOwnerKeyBinding } from '../../packages/owner-key/src/index.mjs'
import { ownerAuthorization, ownerAuthorizationText, ownerAuthorizationPreview,
  verifyOwnerAuthorization, ownerAuthorizationOwnerState, ownerAuthorizationGatePin,
  ownerAuthorizationGateReview, verifyOwnerAuthorizationGateReceipt } from '../../packages/owner-key/src/authorization.mjs'
import { randomUUID } from 'node:crypto'

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

/** Host presentation seam only; production native custody remains unavailable, never seed-backed. */
export function createOwnerAuthorizationBridge({ presentOwnerAction, expectations, nowMs = Date.now } = {}) {
  if (typeof presentOwnerAction !== 'function') throw Object.assign(new Error('Native owner authorization unavailable'), { code: 'owner-authorization:native-unavailable' })
  const pins = Object.freeze({ ...expectations })
  let pending = false
  return Object.freeze({
    async requestAuthorization(supplied) {
      if (pending) return Object.freeze({ status: 'refused', reason: 'owner-authorization:busy', grants_authority: false })
      pending = true
      try {
        const authorization = ownerAuthorization(supplied), wire = ownerAuthorizationText(authorization)
        const reply = await presentOwnerAction(Object.freeze({ kind: 'owner-authorization', wire,
          preview: ownerAuthorizationPreview(authorization) }))
        if (reply?.status === 'cancelled') return Object.freeze({ status: 'cancelled', grants_authority: false })
        if (reply?.status !== 'signed') return Object.freeze({ status: 'unavailable',
          reason: reply?.reason === 'owner-key:secure-custody-join-unavailable'
            ? reply.reason : 'owner-authorization:native-unavailable', grants_authority: false })
        if (ownerAuthorizationText(reply.proof?.authorization) !== wire)
          throw Object.assign(new Error('Changed authorization'), { code: 'owner-authorization:changed-request' })
        const verified = verifyOwnerAuthorization(reply.proof, pins, nowMs())
        return Object.freeze({ status: 'signed-authorization', proof: verified.proof,
          reference: verified.reference, grants_authority: false })
      } catch (error) {
        const reason = /^owner-authorization:[a-z-]+$/u.test(error?.code ?? '') ? error.code : 'owner-authorization:unavailable'
        return Object.freeze({ status: 'refused', reason, grants_authority: false })
      } finally { pending = false }
    },
  })
}

/** Real H owner-operation caller for registration by the protected host. No transport or signer defaults. */
export function createGateOwnerAuthorizationCaller({ callGateOwner, readOwnerState, gateSpkiBase64,
  presentOwnerAction, nowMs = Date.now } = {}) {
  if (typeof callGateOwner !== 'function' || typeof readOwnerState !== 'function' || typeof nowMs !== 'function')
    throw Object.assign(new Error('Trusted gate caller unavailable'), { code: 'owner-authorization:caller-unavailable' })
  const gate = ownerAuthorizationGatePin(gateSpkiBase64)
  const read = () => ownerAuthorizationOwnerState(readOwnerState())
  const clock = () => {
    const value = nowMs()
    if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < 0) throw Error('Invalid caller clock')
    return value
  }
  const questions = new Map(), inflight = new Map()
  let preparing = false, disposed = false
  const unavailable = reason => Object.freeze({ status: 'unavailable', applied: false,
    reason, grants_authority: false })
  return Object.freeze({
    async review(id) {
      if (disposed || preparing || questions.size || inflight.size) return unavailable('owner-authorization:caller-busy-or-disposed')
      preparing = true
      try {
        const state = read(), response = await callGateOwner('review', { id })
        if (disposed || JSON.stringify(read()) !== JSON.stringify(state)) return unavailable('owner-authorization:owner-state-changed')
        const prepared = ownerAuthorizationGateReview(response, state, gate.spki_base64, clock())
        if (prepared.authorization.proposal_id !== id) return unavailable('owner-authorization:trusted-review-unavailable')
        const question_id = randomUUID(); questions.set(question_id, { prepared, cancelled: false })
        return Object.freeze({ status: 'review-ready', question_id, review: prepared.review,
          preview: ownerAuthorizationPreview(prepared.authorization),
          native_presentation_configured: typeof presentOwnerAction === 'function', grants_authority: false })
      } catch { return unavailable('owner-authorization:trusted-review-unavailable') }
      finally { preparing = false }
    },
    async decide(questionId, outcome, stillVisible = () => false) {
      const question = questions.get(questionId), prepared = question?.prepared
      if (disposed || !prepared || !['allowed-once', 'rejected'].includes(outcome))
        return unavailable('owner-authorization:question-unavailable')
      questions.delete(questionId) // Spend local UI state before any await; never automatically resend.
      inflight.set(questionId, question)
      let sent = false
      try {
        if (question.cancelled || stillVisible() !== true || JSON.stringify(read()) !== JSON.stringify(prepared.owner_state))
          return unavailable('owner-authorization:question-or-owner-changed')
        if (clock() >= prepared.authorization.expires_at_ms) return unavailable('owner-authorization:review-expired')
        let proof
        if (outcome === 'allowed-once') {
          if (typeof presentOwnerAction !== 'function') return unavailable('owner-authorization:native-unavailable')
          const bridge = createOwnerAuthorizationBridge({ expectations: prepared.expectations, nowMs: clock,
            presentOwnerAction: request => presentOwnerAction(Object.freeze({ ...request, review: prepared.review })) })
          const reply = await bridge.requestAuthorization(prepared.authorization)
          if (reply.status !== 'signed-authorization') return unavailable(reply.reason ?? 'owner-authorization:native-cancelled')
          proof = reply.proof
        }
        if (disposed || question.cancelled || stillVisible() !== true || JSON.stringify(read()) !== JSON.stringify(prepared.owner_state))
          return unavailable('owner-authorization:question-or-owner-changed')
        if (clock() >= prepared.authorization.expires_at_ms) return unavailable('owner-authorization:review-expired')
        const a = prepared.authorization
        const args = { id: a.proposal_id, base_sha: a.before_sha256, new_sha: a.after_sha256,
          review_challenge: a.challenge, outcome }
        if (outcome === 'allowed-once') args.owner_authorization_proof = proof
        sent = true
        const result = await callGateOwner('decide_review', Object.freeze(args))
        if (disposed || question.cancelled) throw Error('Cancelled before acknowledgement')
        if (result?.applied === true) {
          if (outcome !== 'allowed-once' || result.state !== 'applied') throw Error('Unexpected effect acknowledgement')
          const verified = verifyOwnerAuthorizationGateReceipt(result.receipt, result.receipt_sig, proof, prepared, clock())
          if (!Number.isSafeInteger(result.ledger_seq) || result.ledger_seq <= verified.receipt.owner_consumption.ledger_seq
            || typeof result.ledger_hash !== 'string' || !/^[0-9a-f]{64}$/u.test(result.ledger_hash) || result.ledger_hash.length !== 64)
            throw Error('Malformed apply ledger coordinate')
          return Object.freeze({ status: 'applied', applied: true, receipt: verified.receipt,
            receipt_sig: result.receipt_sig, ledger_seq: result.ledger_seq, ledger_hash: result.ledger_hash,
            retained_history: verified.retained_history, grants_authority: false })
        }
        if (result?.applied !== false || !['refused', 'expired', 'stale', 'failed', 'conflict', 'unknown'].includes(result.state))
          throw Error('Malformed decision acknowledgement')
        return Object.freeze({ status: result.state, applied: result.state === 'unknown' ? null : false, grants_authority: false })
      } catch { return Object.freeze({ status: sent ? 'unknown' : 'unavailable', applied: sent ? null : false,
        reason: sent ? 'owner-authorization:acknowledgement-unknown' : 'owner-authorization:caller-unavailable', grants_authority: false }) }
      finally { inflight.delete(questionId) }
    },
    forget(questionId) {
      const question = questions.get(questionId) ?? inflight.get(questionId)
      if (question) question.cancelled = true
      questions.delete(questionId)
    },
    dispose() { disposed = true; for (const question of inflight.values()) question.cancelled = true; questions.clear() },
  })
}
