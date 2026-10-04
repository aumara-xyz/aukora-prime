import { createHash, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto'
import { isAbsolute } from 'node:path'
import { connect } from 'node:net'
import { peerUid } from '../../plugins/aukora-owner-daemon/lib/peer-uid.mjs'
import { withinWindow } from './aumlok-signer-review.mjs'
import { airlockProtocolRequest, airlockProtocolPreimage } from '../../plugins/aukora-owner-daemon/lib/airlock-rollout.mjs'

// Config presence keeps daemon custody even when compatibility cannot be proved. Never fall back to a local seed.
export async function assertOwnerDaemonProtocol(config, library, request = requestOwnerSignature) {
  const challenge = randomBytes(32).toString('hex')
  try {
    const preimage = airlockProtocolPreimage(challenge)
    const raw = await request(config, airlockProtocolRequest(challenge), preimage, challenge, library)
    verifyOwnerResponse(config, raw, preimage, challenge, library)
  } catch (error) {
    const reason = error?.message === 'signer:request-malformed'
      ? 'airlock:protocol-incompatible' : 'airlock:protocol-unverified'
    throw Object.assign(new Error(`${reason}: ${error?.message ?? String(error)}`), { code: reason })
  }
}

function verifyOwnerResponse(config, raw, preimage, challenge, library) {
  const response = library.parseApprovalResponse(raw)
  if (response.kind !== 'signed') throw new Error(response.refusal)
  if (response.challenge !== challenge) throw new Error('airlock:challenge')
  const publicKey = createPublicKey({ key: Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(config.ownerPublicKeyHex, 'hex'),
  ]), format: 'der', type: 'spki' })
  if (!verify(null, preimage, publicKey, Buffer.from(response.signature, 'hex'))) throw new Error('airlock:signature')
}

// Use the connected descriptor, never the socket file's owner or a UID in JSON.
// The key pin authenticates the signed bytes independently of that kernel check.
export function requestOwnerSignature(config, wire, preimage, challenge, library) {
  return new Promise((resolve, reject) => {
    const socket = connect(config.socketPath)
    let received = Buffer.alloc(0)
    let done = false
    const finish = (error, value) => {
      if (done) return
      done = true
      clearTimeout(timer)
      socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => finish(new Error('airlock:timeout')), 5000)
    socket.once('connect', () => {
      try {
        if (peerUid(socket, config.peerHelperPath) !== config.ownerUid) throw new Error('airlock:peer-uid')
        socket.write(`${JSON.stringify(wire)}\n`)
      } catch (error) { finish(error) }
    })
    socket.on('data', chunk => {
      try {
        received = Buffer.concat([received, chunk])
        if (received.length > 4096) throw new Error('airlock:response-too-large')
        const newline = received.indexOf(10)
        if (newline < 0) return
        if (newline !== received.length - 1) throw new Error('airlock:trailing-response')
        const raw = JSON.parse(received.subarray(0, newline).toString('utf8'))
        verifyOwnerResponse(config, raw, preimage, challenge, library)
        finish(null, raw)
      } catch (error) { finish(error) }
    })
    socket.once('error', error => finish(error))
    socket.once('close', () => { if (!done) finish(new Error('airlock:closed')) })
  })
}

export function createAirlockSigner({ config, library, review, stillListed }) {
  const seen = new Set()
  const refuse = (challenge, refusal) => library.createRefusedApprovalResponse({ challenge, refusal })
  return {
    approve() { return refuse(null, 'signer:request-malformed') },
    async approveAsync(input, facts = {}) {
      let request
      try { request = library.parseApprovalRequest(input) } catch { return refuse(null, 'signer:request-malformed') }
      const no = reason => refuse(request.challenge, reason)
      if (seen.has(request.challenge)) return no('signer:challenge-already-seen')
      if (Math.floor(Date.now() / 1000) >= request.expiresAt) return no('signer:request-expired')
      seen.add(request.challenge)
      let signed = false
      try {
        if (!stillListed()) return no('aumlok:machine-signer-not-listed-by-the-record')
        const decision = await withinWindow(review({ request, operationContent: facts.operationContent }), request.expiresAt)
        if (decision?.expired || Math.floor(Date.now() / 1000) >= request.expiresAt) return no('signer:request-expired')
        if (decision?.approve !== true) return no(decision?.refusal ?? 'signer:declined')
        if (!stillListed()) return no('aumlok:machine-signer-not-listed-by-the-record')
        const response = await requestOwnerSignature(config, { kind: 'approval', request },
          library.approvalSigningBytes(request), request.challenge, library)
        if (Math.floor(Date.now() / 1000) >= request.expiresAt || !stillListed()) return no('airlock:authority-changed')
        signed = true
        return response
      } catch { return no('airlock:refused') }
      finally { if (!signed) seen.delete(request.challenge) }
    },
  }
}

// Boundary-gate is a different authority from the Aumlok signer above. Its current OWNER wire
// exposes metadata and reject, but no full stored-byte review or gate review challenge. Approve
// therefore requires the explicitly requested OWNER review/decide_review extension. There is no
// legacy approve fallback. A gate receipt must never become an Aumlok signature.
// socketPath is the Mac main process's explicitly configured, existing SSH Unix-socket forward;
// this code neither creates a forward nor makes an OWNER endpoint available to the app renderer.
export function exchangeGateOwner(socketPath, op, args = {}) {
  if (typeof socketPath !== 'string' || !isAbsolute(socketPath)
    || !['pending', 'reject', 'review', 'decide_review'].includes(op)) {
    return Promise.reject(new Error('gate:owner-route-unavailable'))
  }
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath)
    let received = Buffer.alloc(0), done = false
    const finish = (error, result) => {
      if (done) return
      done = true
      clearTimeout(timer)
      socket.destroy()
      if (error) reject(error)
      else resolve(result)
    }
    const timer = setTimeout(() => finish(new Error('gate:owner-timeout')), 5000)
    socket.once('connect', () => socket.write(JSON.stringify({ op, args }) + '\n'))
    socket.on('data', chunk => {
      try {
        received = Buffer.concat([received, chunk])
        if (received.length > 65536) throw new Error('gate:owner-response-too-large')
        const newline = received.indexOf(10)
        if (newline < 0) return
        if (newline !== received.length - 1) throw new Error('gate:owner-trailing-response')
        const raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(received.subarray(0, newline)))
        if (raw?.ok !== true) throw new Error('gate:owner-refused')
        finish(null, raw.result)
      } catch (error) { finish(error) }
    })
    socket.once('error', () => finish(new Error('gate:owner-unavailable')))
    socket.once('close', () => { if (!done) finish(new Error('gate:owner-closed')) })
  })
}

const gateSha = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const gateUuid = value => typeof value === 'string'
  && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)
function gatePending(value) {
  if (!gateUuid(value?.id) || !['change', 'revert'].includes(value.kind)
    || typeof value.target !== 'string' || !/^[a-zA-Z0-9_./-]{1,256}$/u.test(value.target)
    || !(value.base_sha === 'absent' || gateSha(value.base_sha)) || !gateSha(value.new_sha)
    || !Number.isSafeInteger(value.created) || value.created < 0
    || !Number.isSafeInteger(value.expires) || value.expires <= value.created) {
    throw new Error('gate:pending-malformed')
  }
  // Only immutable proposal identifiers are used for refusal. Notes are presentation only.
  return Object.freeze({ id: value.id, kind: value.kind, target: value.target,
    base_sha: value.base_sha, new_sha: value.new_sha, created: value.created, expires: value.expires })
}

function gateReview(value, pending, now) {
  const keys = ['version', 'id', 'kind', 'target', 'base_sha', 'new_sha', 'content', 'diff', 'from_to', 'model_note', 'tier',
    'displayable', 'created', 'expires', 'review_challenge', 'review_expires', 'pubkey_fp']
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))
    || value.version !== 3 || JSON.stringify(gatePending(value)) !== JSON.stringify(pending)
    || !['reveal', 'hash4'].includes(value.tier)
    || !(value.from_to === null || (typeof value.from_to === 'string' && /^[\x20-\x7e]{1,600}$/u.test(value.from_to)))
    || !(value.model_note === null || (typeof value.model_note === 'string' && /^[\x20-\x7e]{0,200}$/u.test(value.model_note)))
    || !gateSha(value.review_challenge) || !Number.isSafeInteger(value.review_expires)
    || value.review_expires <= now() || value.review_expires > value.expires
    || value.displayable !== true || typeof value.content !== 'string'
    || !/^[\x20-\x7e]*$/u.test(value.content) || typeof value.diff !== 'string'
    || !/^[\x09\x0a\x20-\x7e]*$/u.test(value.diff)
    || value.content.length + value.diff.length > 12000
    || typeof value.pubkey_fp !== 'string' || !/^[0-9a-f]{16}$/u.test(value.pubkey_fp)
    || createHash('sha256').update(value.content, 'utf8').digest('hex') !== pending.new_sha) {
    throw new Error('gate:stored-byte-review-unavailable')
  }
  return Object.freeze({ ...value })
}

// THE OWNER CARD'S ORDER (Peter, 2026-10-04, after a half-awake approval of a card whose model note said "safe to
// refuse"): the GATE'S facts and its exact from->to diff come FIRST; the model's words come LAST, inside a fence labelled
// MODEL-AUTHORED. Section headers are whole lines no other section can produce: every fact line starts with two spaces,
// every diff line with ' ', '-' or '+' (lineDiff), and the model's note with '> ' (it is one sanitised ASCII line), so
// model text cannot forge a header or move itself above the gate's facts. The card parses exactly these headers.
export const GATE_CARD = Object.freeze({
  facts: 'GATE FACTS (written by the gate, not by the model)',
  diff: 'GATE DIFF (the exact stored change, from -> to)',
  diffEnd: 'END OF GATE DIFF',
  model: 'MODEL-AUTHORED (written by the model, NOT verified by the gate; not a reason to approve or to refuse)',
  modelEnd: 'END OF MODEL-AUTHORED',
})
export function gateReviewText(review) {
  return [GATE_CARD.facts,
    '  Change (gate-computed): ' + (review.from_to ?? '(this target has no gate summary; read the diff)'),
    '  Approval tier: ' + (review.tier === 'hash4'
      ? 'TYPED - open the change, then type the first 4 characters of the new SHA-256' : 'REVEAL - open the change'),
    '  Target: ' + review.target, '  Kind: ' + review.kind,
    '  Base SHA-256: ' + review.base_sha, '  New SHA-256: ' + review.new_sha,
    '  New stored content (' + review.content.length + ' ASCII bytes): ' + review.content,
    '  Proposal: ' + review.id, '  Receipt key fingerprint: ' + review.pubkey_fp,
    '  Gate review challenge: ' + review.review_challenge,
    '  Proposal expires (unix ms): ' + review.expires, '  Review expires (unix ms): ' + review.review_expires,
    GATE_CARD.diff, ...review.diff.split('\n').map(line => /^[ +-]/u.test(line) ? line : ' ' + line), GATE_CARD.diffEnd,
    GATE_CARD.model, '> ' + (review.model_note === null || review.model_note === '' ? '(no note)' : review.model_note),
    GATE_CARD.modelEnd].join('\n')
}

export function createGateOwnerAdapter({ socketPath, call = exchangeGateOwner, now = Date.now } = {}) {
  if (typeof socketPath !== 'string' || !isAbsolute(socketPath)) throw new Error('gate:owner-route-unavailable')
  const reviews = new Map()
  let disposed = false, preparing = false
  const read = async () => {
    if (disposed) throw new Error('gate:owner-adapter-disposed')
    const response = await call(socketPath, 'pending', {})
    if (disposed) throw new Error('gate:owner-adapter-disposed')
    if (!Array.isArray(response?.pending) || response.pending.length > 16) throw new Error('gate:pending-malformed')
    return response.pending.map(gatePending)
  }
  return Object.freeze({
    async pending() {
      // Fence concurrent preparations before the first await; a second review would replace its nonce.
      if (preparing || reviews.size !== 0) return null
      preparing = true
      try {
        const rows = await read()
        if (rows.length === 0) return null
        const pending = rows[0], uiQuestionId = randomUUID()
        let review = null
        try { review = gateReview(await call(socketPath, 'review', { id: pending.id }), pending, now) }
        catch { /* Actual missing/malformed review remains unavailable; metadata never enables apply. */ }
        if (disposed) throw new Error('gate:owner-adapter-disposed')
        const text = review ? gateReviewText(review) : null
        const question = Object.freeze({ mode: 'boundary-gate', uiQuestionId, pending,
          approveAvailable: review !== null, reason: review ? null : 'gate:stored-byte-review-unavailable',
          review, text, textDigest: text === null ? null : createHash('sha256')
            .update('aukora:approval-words:v1\0' + text, 'utf8').digest('hex') })
        reviews.set(uiQuestionId, { pending, review })
        return question
      } finally { preparing = false }
    },
    async decide(uiQuestionId, approve, stillVisible = () => false, confirm = null) {
      const expected = reviews.get(uiQuestionId)
      if (disposed || !expected) return { state: 'unavailable', applied: false, reason: 'gate:question-not-pending' }
      if (typeof approve !== 'boolean' || (approve && !expected.review)) {
        return { state: 'unavailable', applied: false, reason: 'gate:stored-byte-review-unavailable' }
      }
      // TIERED APPROVAL: a 'hash4' approve needs the owner's typed first 4 characters of the new SHA-256. Checked before the
      // question is spent, so a typo leaves the card answerable; the gate checks it again and is the authority.
      const typed = approve && expected.review?.tier === 'hash4'
      if (typed && (typeof confirm !== 'string' || confirm.toLowerCase() !== expected.review.new_sha.slice(0, 4))) {
        return { state: 'unavailable', applied: false, reason: 'gate:typed-confirmation-required' }
      }
      reviews.delete(uiQuestionId) // Spend the local question before any await or dispatch; no blind retry.
      let sent = false
      try {
        const current = (await read()).find(row => row.id === expected.pending.id)
        if (!current || JSON.stringify(current) !== JSON.stringify(expected.pending)) {
          return { state: 'unavailable', applied: false, reason: 'gate:pending-changed' }
        }
        if (disposed || stillVisible() !== true) {
          return { state: 'unavailable', applied: false, reason: 'gate:question-unavailable' }
        }
        const review = expected.review
        if (review && (now() >= review.review_expires || now() >= review.expires)) {
          return { state: 'expired', applied: false, reason: 'gate:review-expired' }
        }
        sent = true
        const result = review
          ? await call(socketPath, 'decide_review', { id: review.id, base_sha: review.base_sha,
            new_sha: review.new_sha, review_challenge: review.review_challenge,
            outcome: approve ? 'allowed-once' : 'rejected', ...(typed ? { confirm: confirm.toLowerCase() } : {}) })
          : await call(socketPath, 'reject', { id: expected.pending.id })
        if (disposed) return { state: 'unknown', applied: null, reason: 'gate:acknowledgement-unavailable' }
        if (typeof result?.applied !== 'boolean'
          || !['refused', 'expired', 'stale', 'applying', 'applied', 'failed', 'conflict', 'unknown'].includes(result.state)) {
          throw new Error('gate:result-malformed')
        }
        if (result.applied === true) {
          const r = result.receipt
          if (!approve || !review || result.state !== 'applied' || r?.v !== 2
            || r.proposal !== review.id || r.kind !== review.kind || r.target !== review.target
            || r.base_sha !== review.base_sha || r.new_sha !== review.new_sha || r.pubkey_fp !== review.pubkey_fp
            || typeof result.receipt_sig !== 'string' || result.receipt_sig.length !== 88
            || !Number.isSafeInteger(result.ledger_seq) || result.ledger_seq <= 0) throw new Error('gate:receipt-mismatch')
          return Object.freeze({ state: 'applied', applied: true, reason: 'gate:apply-reported',
            receipt: Object.freeze({ ...r }), receipt_sig: result.receipt_sig, ledger_seq: result.ledger_seq })
        }
        return Object.freeze({ state: result.state, applied: false,
          reason: result.state === 'refused' ? approve ? 'gate:apply-refused' : 'gate:owner-rejected'
            : 'gate:proposal-closed' })
      } catch {
        return Object.freeze({ state: sent ? 'unknown' : 'unavailable', applied: sent ? null : false,
          reason: sent ? 'gate:acknowledgement-unavailable' : 'gate:owner-unavailable' })
      }
    },
    forget(uiQuestionId) { reviews.delete(uiQuestionId) },
    dispose() { disposed = true; reviews.clear() },
  })
}
