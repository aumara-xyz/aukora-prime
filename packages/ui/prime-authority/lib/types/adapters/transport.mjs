/**
 * UI transport boundary. Authority owns challenges, signature verification and durable grants.
 * The composition injects browser-safe frozen contract helpers and transport methods; no URLs
 * or signing keys live here. Session tokens remain in memory, outside presentation objects.
 */
import { validateCaptureReview } from './capture-review.mjs'
import { validateCaptureMetadata } from './capture-metadata.mjs'
import { validateForgetReview } from './forget-review.mjs'

export class PrimeTransportError extends Error {
  constructor(code, reason) {
    super(reason)
    this.name = 'PrimeTransportError'
    this.code = code
  }
}

const fail = (code, reason) => { throw new PrimeTransportError(code, reason) }
const kinds = new Set(['owner_key', 'passkey'])
const labels = Object.freeze({
  version: 'Version', operation_id: 'Operation', task_id: 'Task', owner_id: 'Owner',
  agent_id: 'Agent', audience: 'Audience', action_type: 'Action', target_identity: 'Target',
  canonical_parameters: 'Exact parameters', data_scope: 'Data scope',
  expected_state_version: 'Expected state', provider_and_region: 'Provider and region',
  maximum_cost: 'Maximum cost', expiry: 'Expires', nonce: 'Nonce',
  policy_version: 'Policy version', authorization_epoch: 'Authorization epoch',
})

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child)
    Object.freeze(value)
  }
  return value
}

export function createPrimeTransport({ authority, contracts, ownerSigner, passkeySigner, now = Date.now }) {
  for (const name of ['validateContract', 'validateApprovalTemplate', 'canonicalJson', 'operationDigest']) {
    if (typeof contracts?.[name] !== 'function') fail('UNAVAILABLE', `ui:contract-helper-unavailable:${name}`)
  }
  const { canonicalJson, operationDigest } = contracts
  const validateContract = (kind, value) => {
    try { return contracts.validateContract(kind, value) }
    catch { fail('INVALID', `ui:invalid-${kind}`) }
  }
  const exact = (value, label = 'transport-json') => {
    try { return canonicalJson(value) }
    catch { fail('INVALID', `ui:invalid-${label}`) }
  }
  const copy = (value, label) => freeze(JSON.parse(exact(value, label)))
  const object = (value, label) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('INVALID', `ui:invalid-${label}`)
    return value
  }
  let session = null
  let loginPending = null
  let loginOwner = null
  let authRevision = 0
  let logoutFlight = null
  let logoutResult = null
  const presentations = new WeakMap()
  const submissions = new Map()

  function checkSignal(signal) {
    if (signal?.aborted) fail('CANCELLED', 'ui:cancelled')
  }
  function checkExpiry(expiry) {
    if (typeof expiry !== 'string' || !Number.isFinite(Date.parse(expiry))) fail('INVALID', 'ui:invalid-expiry')
    if (Date.parse(expiry) <= now()) fail('EXPIRED', 'ui:expired')
  }
  function ownerSession() {
    if (!session) fail('UNAUTHORIZED', 'ui:login-required')
    checkExpiry(session.expiry)
    return session
  }
  function sameSession(current) {
    if (session !== current) fail('UNAUTHORIZED', 'ui:approval-session-changed')
    checkExpiry(current.expiry)
  }
  async function call(name, input, signal, mutation = false) {
    checkSignal(signal)
    if (typeof authority?.[name] !== 'function') fail('UNAVAILABLE', `ui:authority-method-unavailable:${name}`)
    let answer
    try {
      answer = await authority[name](input, { signal })
    } catch (error) {
      if (error instanceof PrimeTransportError) throw error
      if (mutation) fail('OUTCOME_UNKNOWN', 'ui:approval-submission-outcome-unknown')
      if (signal?.aborted || error?.name === 'AbortError') fail('CANCELLED', 'ui:cancelled')
      fail('UNAVAILABLE', `ui:authority-transport-unavailable:${name}`)
    }
    if (!answer || typeof answer !== 'object') fail(mutation ? 'OUTCOME_UNKNOWN' : 'INVALID', 'ui:invalid-authority-answer')
    if (answer.ok !== true) {
      fail(typeof answer.error_code === 'string' ? answer.error_code : 'INVALID',
        typeof answer.reason === 'string' ? answer.reason : 'ui:authority-refused')
    }
    return answer
  }
  async function sign(kind, purpose, request, signal, public_key) {
    checkSignal(signal)
    const signer = kind === 'owner_key' ? ownerSigner : passkeySigner
    if (typeof signer !== 'function') fail('UNAVAILABLE', `ui:${kind}-signer-unavailable`)
    let material
    try { material = await signer({ purpose, request, signal, public_key }) }
    catch (error) {
      if (signal?.aborted || error?.name === 'AbortError' || error?.name === 'NotAllowedError') fail('CANCELLED', 'ui:credential-request-cancelled')
      if (error instanceof PrimeTransportError) throw error
      fail('UNAVAILABLE', `ui:${kind}-signer-unavailable`)
    }
    checkSignal(signal)
    object(material, 'signature-material')
    if (material.kind !== kind) fail('INVALID', 'ui:signature-kind-mismatch')
    if (typeof material.signature !== 'string' || !material.signature) fail('INVALID', 'ui:invalid-signature-material')
    if (kind === 'owner_key' && purpose === 'login' &&
        Object.keys(material).sort().join(',') !== 'kind,signature') {
      fail('INVALID', 'ui:login-material-fields')
    }
    if (kind === 'owner_key' && purpose === 'approval') {
      object(material.request, 'signed-review-request')
      if (exact(material.request, 'signed-review-request') !== exact(request, 'review-request')) {
        fail('TARGET_MISMATCH', 'ui:signed-review-request-changed')
      }
    }
    return copy(material)
  }
  function proofMatches(proof, operation, digest, request) {
    const expected = {
      version: 1, operation_id: operation.operation_id, operation_digest: digest,
      owner_id: operation.owner_id, audience: operation.audience,
      authorization_epoch: operation.authorization_epoch,
      expiry: new Date(request.expiresAt * 1000).toISOString(), nonce: request.challenge,
    }
    for (const [key, value] of Object.entries(expected)) {
      if (proof?.[key] !== value) fail('TARGET_MISMATCH', `ui:approval-binding-mismatch:${key}`)
    }
    checkExpiry(proof.expiry)
    if (Date.parse(proof.expiry) > Date.parse(operation.expiry)) fail('EXPIRED', 'ui:approval-outlives-operation')
  }
  function reviewMatches(request, digest) {
    object(request, 'review-request')
    const keys = ['domain', 'subject', 'activeControlDigest', 'operationDigest', 'challenge', 'issuedAt', 'expiresAt']
    if (Object.keys(request).sort().join(',') !== keys.sort().join(',') ||
        request.domain !== 'aukora:owner-approval-request:v1' ||
        request.operationDigest !== digest.slice(7) ||
        !/^aukora:1:[a-f0-9]{64}$/.test(request.subject) ||
        !/^[a-f0-9]{64}$/.test(request.activeControlDigest) ||
        !/^[a-f0-9]{64}$/.test(request.challenge) ||
        !Number.isSafeInteger(request.issuedAt) || !Number.isSafeInteger(request.expiresAt) ||
        request.issuedAt < 0 || request.expiresAt <= request.issuedAt) {
      fail('TARGET_MISMATCH', 'ui:approval-review-request-mismatch')
    }
  }

  async function login({ owner_id, kind = 'passkey', signal } = {}) {
    if (typeof owner_id !== 'string' || !owner_id || !kinds.has(kind)) fail('INVALID', 'ui:invalid-login-request')
    if (logoutFlight) fail('RECONCILIATION_REQUIRED', 'ui:logout-pending')
    if (loginPending) {
      if (loginOwner !== `${kind}:${owner_id}`) fail('UNAUTHORIZED', 'ui:another-login-in-progress')
      return loginPending
    }
    session = null
    logoutResult = null
    const revision = ++authRevision
    loginOwner = `${kind}:${owner_id}`
    const flight = (async () => {
      const answer = await call('loginChallenge', { owner_id, kind }, signal)
      if (authRevision !== revision) fail('CANCELLED', 'ui:login-cancelled')
      checkSignal(signal)
      const challenge = copy(object(answer.challenge, 'login-challenge'), 'login-challenge')
      if (challenge.owner_id !== owner_id) fail('UNAUTHORIZED', 'ui:login-owner-mismatch')
      if (challenge.version !== 1 || typeof challenge.challenge !== 'string' || !challenge.challenge ||
          typeof challenge.audience !== 'string' || !challenge.audience ||
          !Number.isSafeInteger(challenge.authorization_epoch) || challenge.authorization_epoch < 0) {
        fail('INVALID', 'ui:invalid-login-challenge')
      }
      checkExpiry(challenge.expiry)
      const material = await sign(kind, 'login', challenge, signal, answer.public_key ? copy(answer.public_key) : undefined)
      if (authRevision !== revision) fail('CANCELLED', 'ui:login-cancelled')
      checkExpiry(challenge.expiry)
      const complete = await call('loginComplete', { challenge, material }, signal)
      if (authRevision !== revision) fail('CANCELLED', 'ui:login-cancelled')
      checkSignal(signal)
      if (complete.owner_id !== owner_id || typeof complete.session_token !== 'string' || !complete.session_token) {
        fail('UNAUTHORIZED', 'ui:login-session-mismatch')
      }
      checkExpiry(complete.expiry)
      session = { owner_id, session_token: complete.session_token, expiry: complete.expiry }
      return freeze({ owner_id, expiry: complete.expiry })
    })()
    loginPending = flight
    try { return await flight }
    finally { if (loginPending === flight) { loginPending = null; loginOwner = null } }
  }

  function logout() {
    if (logoutFlight) return logoutFlight
    if (!session && !loginPending && logoutResult) return Promise.resolve(logoutResult)
    const current = session
    session = null; authRevision++; loginPending = null; loginOwner = null
    const unconfirmed = code => freeze({ ok: false, error_code: code,
      reason: code === 'UNAVAILABLE' ? 'ui:server-logout-unavailable'
        : code === 'UNAUTHORIZED' ? 'ui:server-logout-refused' : 'ui:server-logout-not-confirmed' })
    let resolveAnswer
    const answer = new Promise(resolve => { resolveAnswer = resolve })
    const flight = answer.then(result => {
      if (result && !Array.isArray(result) && Object.keys(result).sort().join(',') === 'ok,status' &&
          result.ok === true && result.status === 'LOGGED_OUT') return freeze({ ok: true, status: 'LOGGED_OUT' })
      return unconfirmed(result?.ok === false && ['UNAUTHORIZED', 'UNAVAILABLE'].includes(result.error_code)
        ? result.error_code : 'OUTCOME_UNKNOWN')
    }).catch(() => unconfirmed('OUTCOME_UNKNOWN')).then(result => {
      logoutResult = result
      return result
    }).finally(() => { if (logoutFlight === flight) logoutFlight = null })
    logoutFlight = flight
    try {
      // Invoke immediately: a shared bridge adapter must also fence its local
      // memory/review generation before another owner action can run.
      resolveAnswer(typeof authority?.logout === 'function'
        ? authority.logout(current ? { session_token: current.session_token } : {})
        : unconfirmed('UNAVAILABLE'))
    } catch { resolveAnswer(unconfirmed('OUTCOME_UNKNOWN')) }
    return flight
  }

  async function prepareApproval(proposal, { signal, memoryCapture, captureMetadata, recordSummary } = {}) {
    const current = ownerSession()
    validateContract('OperationProposal', proposal)
    const operation = copy(proposal)
    let memoryDraft = null
    let forgetDraft = null
    let metadata = null
    if (operation.action_type === 'memory.save') {
      try { validateCaptureReview(operation.canonical_parameters, memoryCapture) }
      catch { fail('TARGET_MISMATCH', 'ui:memory-capture-review-missing-or-mismatched') }
      memoryDraft = copy(memoryCapture, 'memory-capture-draft')
      if (captureMetadata !== undefined) {
        try { metadata = validateCaptureMetadata(captureMetadata) }
        catch { fail('TARGET_MISMATCH', 'ui:fixed-capture-metadata-required') }
      }
    } else if (operation.action_type === 'memory.forget') {
      try { forgetDraft = validateForgetReview(operation, recordSummary) }
      catch { fail('TARGET_MISMATCH', 'ui:forget-record-review-missing-or-mismatched') }
    }
    if (operation.owner_id !== current.owner_id) fail('UNAUTHORIZED', 'ui:operation-owner-mismatch')
    checkExpiry(operation.expiry)
    const digest = await operationDigest(operation)
    const answer = await call('approvalChallenge', { session_token: current.session_token, operation }, signal)
    sameSession(current)
    validateContract('OperationProposal', answer.operation)
    if (canonicalJson(answer.operation) !== canonicalJson(operation) || answer.operation_digest !== digest) {
      fail('TARGET_MISMATCH', 'ui:approval-operation-changed')
    }
    const proofTemplate = copy(object(answer.proof_template, 'approval-template'), 'approval-template')
    const request = copy(object(answer.approval_request, 'review-request'), 'review-request')
    reviewMatches(request, digest)
    try { contracts.validateApprovalTemplate(proofTemplate) }
    catch { fail('INVALID', 'ui:invalid-approval-template') }
    proofMatches(proofTemplate, operation, digest, request)
    checkSignal(signal)
    checkExpiry(operation.expiry)
    const presentation = freeze({
      operation,
      operation_digest: digest,
      approval_expiry: proofTemplate.expiry,
      review_challenge: request,
      // This is the complete exact operation, suitable for the existing approval seat.
      canonical_operation: canonicalJson(operation),
      rows: Object.keys(labels).map(key => ({ key, label: labels[key], value: operation[key], exact: canonicalJson(operation[key]) })),
      memory_review: memoryDraft ? { statement: memoryDraft.statement, attributed_to: memoryDraft.attributed_to,
        capture_sha256: operation.canonical_parameters.capture_sha256 } : null,
      capture_metadata: metadata,
      forget_review: forgetDraft ? { ...forgetDraft, canonical_sha256: operation.canonical_parameters.canonical_sha256 } : null,
    })
    presentations.set(presentation, { operation, digest, proofTemplate, request, owner_id: current.owner_id,
      session_token: current.session_token, public_key: answer.public_key ? copy(answer.public_key) : undefined, memoryDraft, forgetDraft })
    return presentation
  }

  async function approve(presentation, { kind = 'passkey', signal } = {}) {
    if (!kinds.has(kind)) fail('INVALID', 'ui:invalid-signature-kind')
    const record = presentations.get(presentation)
    if (!record) fail('INVALID', 'ui:foreign-approval-presentation')
    if (kind !== record.proofTemplate.material.kind) fail('INVALID', 'ui:signature-kind-mismatch')
    const current = ownerSession()
    if (record.owner_id !== current.owner_id || record.session_token !== current.session_token) {
      fail('UNAUTHORIZED', 'ui:approval-session-changed')
    }
    const prior = submissions.get(record.digest)
    if (prior?.pending) {
      if (prior.decision !== 'approve') fail('RECONCILIATION_REQUIRED', 'ui:another-decision-pending')
      return prior.pending
    }
    if (prior) fail(prior.code, prior.reason)
    if (record.operation.action_type === 'memory.save') {
      try { validateCaptureReview(record.operation.canonical_parameters, record.memoryDraft) }
      catch { fail('TARGET_MISMATCH', 'ui:memory-capture-review-missing-or-mismatched') }
    } else if (record.operation.action_type === 'memory.forget') {
      try { validateForgetReview(record.operation, record.forgetDraft) }
      catch { fail('TARGET_MISMATCH', 'ui:forget-record-review-missing-or-mismatched') }
    }
    checkExpiry(record.operation.expiry)
    checkExpiry(record.proofTemplate.expiry)
    const pending = (async () => {
      const material = await sign(kind, 'approval', record.request, signal, record.public_key)
      sameSession(current)
      checkExpiry(record.operation.expiry)
      checkSignal(signal)
      const proof = copy({ ...record.proofTemplate, material })
      validateContract('ApprovalProof', proof)
      proofMatches(proof, record.operation, record.digest, record.request)
      // The server is about to receive an approval. Never blindly repeat an uncertain submission.
      submissions.set(record.digest, { code: 'RECONCILIATION_REQUIRED', reason: 'ui:approval-submission-needs-reconciliation' })
      let answer
      try { answer = await call('approvalComplete', { session_token: current.session_token, proof }, signal, true) }
      catch (error) {
        submissions.set(record.digest, { code: error.code ?? 'OUTCOME_UNKNOWN', reason: error.message })
        throw error
      }
      if (answer.status !== 'APPROVED') fail('OUTCOME_UNKNOWN', 'ui:approval-result-unknown')
      try {
        validateContract('ApprovalProof', answer.approval_proof)
        proofMatches(answer.approval_proof, record.operation, record.digest, record.request)
        if (exact(answer.approval_proof) !== exact(proof)) fail('TARGET_MISMATCH', 'ui:approval-proof-changed')
      } catch {
        submissions.set(record.digest, { code:'OUTCOME_UNKNOWN', reason:'ui:approval-result-invalid-needs-reconciliation' })
        fail('OUTCOME_UNKNOWN', 'ui:approval-result-invalid-needs-reconciliation')
      }
      submissions.set(record.digest, { code: 'REPLAYED', reason: 'ui:approval-already-submitted' })
      return freeze({ status: 'APPROVED', approval_proof: copy(answer.approval_proof) })
    })()
    submissions.set(record.digest, { pending, decision: 'approve' })
    try { return await pending }
    catch (error) {
      // Credential refusal occurs before submission and can be re-presented with a fresh challenge.
      if (submissions.get(record.digest)?.pending === pending) submissions.delete(record.digest)
      throw error
    }
  }

  async function decline(presentation, { signal } = {}) {
    const record = presentations.get(presentation)
    if (!record) fail('INVALID', 'ui:foreign-approval-presentation')
    const current = ownerSession()
    if (record.session_token !== current.session_token) fail('UNAUTHORIZED', 'ui:approval-session-changed')
    const prior = submissions.get(record.digest)
    if (prior?.pending) {
      if (prior.decision !== 'decline') fail('RECONCILIATION_REQUIRED', 'ui:another-decision-pending')
      return prior.pending
    }
    if (prior) fail(prior.code, prior.reason)
    checkSignal(signal)
    checkExpiry(record.operation.expiry)
    checkExpiry(record.proofTemplate.expiry)
    // Store the in-flight decision before dispatch. DENIED is recorded only after host confirmation.
    const pending = Promise.resolve().then(async () => {
      try {
        const answer = await call('declineApproval', { session_token: current.session_token, operation_id: record.operation.operation_id }, signal, true)
        if (answer.status !== 'DENIED') fail('OUTCOME_UNKNOWN', 'ui:denial-result-unknown')
        submissions.set(record.digest, { code: 'REPLAYED', reason: 'ui:approval-denied' })
        return freeze({ status: 'DENIED' })
      } catch (error) {
        submissions.set(record.digest, { code: error.code ?? 'OUTCOME_UNKNOWN', reason: error.message })
        throw error
      }
    })
    submissions.set(record.digest, { pending, decision: 'decline' })
    return pending
  }

  return Object.freeze({ login, prepareApproval, approve, decline, logout,
    owner() { return session ? freeze({ owner_id: session.owner_id, expiry: session.expiry }) : null },
  })
}
