/**
 * UI transport boundary. Authority owns challenges, signature verification and durable grants.
 * The composition injects browser-safe frozen contract helpers and transport methods; no URLs
 * or signing keys live here. Session tokens remain in memory, outside presentation objects.
 */
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
  for (const name of ['validateContract', 'canonicalJson', 'operationDigest']) {
    if (typeof contracts?.[name] !== 'function') fail('UNAVAILABLE', `ui:contract-helper-unavailable:${name}`)
  }
  const { validateContract, canonicalJson, operationDigest } = contracts
  const copy = value => freeze(JSON.parse(canonicalJson(value)))
  let session = null
  let loginPending = null
  let loginOwner = null
  let authRevision = 0
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
    if (material?.kind !== kind) fail('INVALID', 'ui:signature-kind-mismatch')
    if (kind === 'owner_key' && purpose === 'login' &&
        Object.keys(material).sort().join(',') !== 'kind,signature') {
      fail('INVALID', 'ui:login-material-fields')
    }
    if (kind === 'owner_key' && purpose === 'approval' && canonicalJson(material.request) !== canonicalJson(request)) {
      fail('TARGET_MISMATCH', 'ui:signed-review-request-changed')
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
    if (loginPending) {
      if (loginOwner !== `${kind}:${owner_id}`) fail('UNAUTHORIZED', 'ui:another-login-in-progress')
      return loginPending
    }
    session = null
    const revision = ++authRevision
    loginOwner = `${kind}:${owner_id}`
    loginPending = (async () => {
      const answer = await call('loginChallenge', { owner_id, kind }, signal)
      const challenge = copy(answer.challenge)
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
    try { return await loginPending }
    finally { loginPending = null; loginOwner = null }
  }

  async function prepareApproval(proposal, { signal } = {}) {
    const current = ownerSession()
    validateContract('OperationProposal', proposal)
    const operation = copy(proposal)
    if (operation.owner_id !== current.owner_id) fail('UNAUTHORIZED', 'ui:operation-owner-mismatch')
    checkExpiry(operation.expiry)
    const digest = await operationDigest(operation)
    const answer = await call('approvalChallenge', { session_token: current.session_token, operation }, signal)
    sameSession(current)
    validateContract('OperationProposal', answer.operation)
    if (canonicalJson(answer.operation) !== canonicalJson(operation) || answer.operation_digest !== digest) {
      fail('TARGET_MISMATCH', 'ui:approval-operation-changed')
    }
    const proofTemplate = copy(answer.proof_template)
    const request = copy(answer.approval_request)
    reviewMatches(request, digest)
    validateContract('ApprovalProof', proofTemplate)
    proofMatches(proofTemplate, operation, digest, request)
    checkSignal(signal)
    checkExpiry(operation.expiry)
    const presentation = freeze({
      operation,
      operation_digest: digest,
      approval_expiry: proofTemplate.expiry,
      // This is the complete exact operation, suitable for the existing approval seat.
      canonical_operation: canonicalJson(operation),
      rows: Object.keys(labels).map(key => ({ key, label: labels[key], value: operation[key], exact: canonicalJson(operation[key]) })),
    })
    presentations.set(presentation, { operation, digest, proofTemplate, request, owner_id: current.owner_id,
      session_token: current.session_token, public_key: answer.public_key ? copy(answer.public_key) : undefined })
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
    if (prior?.pending) return prior.pending
    if (prior) fail(prior.code, prior.reason)
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
      validateContract('ApprovalProof', answer.approval_proof)
      proofMatches(answer.approval_proof, record.operation, record.digest, record.request)
      if (canonicalJson(answer.approval_proof) !== canonicalJson(proof)) fail('TARGET_MISMATCH', 'ui:approval-proof-changed')
      submissions.set(record.digest, { code: 'REPLAYED', reason: 'ui:approval-already-submitted' })
      return freeze({ status: 'APPROVED', approval_proof: copy(answer.approval_proof) })
    })()
    submissions.set(record.digest, { pending })
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
    if (submissions.has(record.digest)) fail('RECONCILIATION_REQUIRED', 'ui:approval-already-in-progress-or-submitted')
    submissions.set(record.digest, { code: 'REPLAYED', reason: 'ui:approval-denied' })
    const answer = await call('declineApproval', { session_token: current.session_token, operation_id: record.operation.operation_id }, signal, true)
    if (answer.status !== 'DENIED') fail('OUTCOME_UNKNOWN', 'ui:denial-result-unknown')
    return freeze({ status: 'DENIED' })
  }

  return Object.freeze({ login, prepareApproval, approve, decline,
    logout() { session = null; authRevision++ },
    owner() { return session ? freeze({ owner_id: session.owner_id, expiry: session.expiry }) : null },
  })
}
