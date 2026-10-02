import { createPrimeTransport, PrimeTransportError } from '../../../adapters/transport.mjs'
import { createBrowserPasskeySigner } from '../../../adapters/passkey.mjs'
import { CAPTURE_METADATA_FIELDS, validateCaptureReview } from '../../../adapters/capture-review.mjs'
import { validateCaptureMetadata } from '../../../adapters/capture-metadata.mjs'
import { validateForgetReview } from '../../../adapters/forget-review.mjs'
import { validateForgetWorkflowResult, validateCancelledForgetWorkflow } from '../../../adapters/forget-result.mjs'
import { validateSaveRecovery, validateSavedCaptureContent } from '../../../adapters/save-recovery.mjs'

async function readJson(response, contracts) {
  if (typeof contracts?.parseStrictJson !== 'function') throw new PrimeTransportError('UNAVAILABLE', 'ui:strict-json-helper-unavailable')
  try { return contracts.parseStrictJson(await response.text(), { maxBytes: 8388608, maxDepth: 64 }) }
  catch { throw new PrimeTransportError('INVALID', 'ui:invalid-response-json') }
}

export function createHttpAuthority(fetcher = globalThis.fetch, contracts) {
  return Object.freeze(Object.fromEntries(['loginChallenge', 'loginComplete', 'approvalChallenge', 'approvalComplete', 'declineApproval', 'logout'].map(method => [method,
    async (input, { signal } = {}) => {
      if (method === 'logout' && (typeof input?.session_token !== 'string' || !input.session_token)) {
        return { ok:false, error_code:'UNAUTHORIZED', reason:'ui:no-known-server-session' }
      }
      if (typeof contracts?.parseStrictJson !== 'function' || typeof contracts?.canonicalJson !== 'function') {
        throw new PrimeTransportError('UNAVAILABLE', 'ui:strict-json-helper-unavailable')
      }
      let body
      try { body = contracts.canonicalJson(input) }
      catch { throw new PrimeTransportError('INVALID', 'ui:invalid-request-json') }
      const response = await fetcher('/api/prime/authority/' + (method === 'logout' ? 'logoutSession' : method), { method: 'POST', credentials: 'same-origin',
        redirect: 'error', cache: 'no-store', headers: { 'content-type': 'application/json' }, body, signal })
      let answer
      try { answer = await readJson(response, contracts) }
      catch (error) {
        if (method === 'approvalComplete' || method === 'declineApproval' || method === 'logout') {
          throw new PrimeTransportError('OUTCOME_UNKNOWN', 'ui:decision-response-invalid-needs-reconciliation')
        }
        throw error
      }
      if (!response.ok && answer?.ok !== false) throw new Error('Authority response unavailable')
      return answer
    }])) )
}

const capabilityIds = Object.freeze(['owner-passkey', 'approved-shell', 'sdk-child-launchers', 'model-inference', 'durable-memory', 'messaging', 'media-generation'])
export const CAPABILITY_LABELS = Object.freeze({ 'owner-passkey': 'Owner passkey', 'approved-shell': 'Approved shell',
  'sdk-child-launchers': 'SDK child launchers', 'model-inference': 'Model inference', 'durable-memory': 'Durable memory',
  messaging: 'Messaging', 'media-generation': 'Media generation' })
export function validateCapabilities(value) {
  const fields = ['version', 'source_commit', 'runtime_pid', 'release_digest', 'unavailable_capabilities', 'phase', 'qualification']
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== fields.sort().join(',') ||
      value.version !== 1 || !/^[a-f0-9]{40}$/.test(value.source_commit) ||
      !Number.isSafeInteger(value.runtime_pid) || value.runtime_pid <= 0 ||
      !/^sha256:[a-f0-9]{64}$/.test(value.release_digest) ||
      value.phase !== 'disposable-preview' || value.qualification !== 'PENDING' ||
      !Array.isArray(value.unavailable_capabilities) || value.unavailable_capabilities.some(id => !capabilityIds.includes(id)) ||
      new Set(value.unavailable_capabilities).size !== value.unavailable_capabilities.length) {
    throw new PrimeTransportError('INVALID', 'ui:invalid-capability-status')
  }
  return immutable({ ...value, unavailable_capabilities: [...value.unavailable_capabilities] })
}
export async function readHttpCapabilities(fetcher = globalThis.fetch, contracts, signal) {
  const response = await fetcher('/api/prime/capabilities', { method:'GET', credentials:'same-origin', redirect:'error', cache:'no-store', signal })
  if (!response.ok) throw new PrimeTransportError('UNAVAILABLE', 'ui:capability-status-unavailable')
  return validateCapabilities(await readJson(response, contracts))
}

const immutable = value => {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) immutable(child); Object.freeze(value) }
  return value
}

/** Observable presentation owner; only the injected host can authenticate or approve. */
export function createPrimeOwnerController({ now = Date.now, schedule = setTimeout, unschedule = clearTimeout } = {}) {
  const listeners = new Set()
  const connectionWitnesses = new WeakMap()
  let binding, transport, pending, timer, revision = 0, operation, ownerKind, memoryCapture, captureMetadata, recordSummary
  let connectionGeneration = 0, disposed = false
  let logoutFlight = null
  let approvalAction = null, forgetAction = null, approvalFlight = null, approvalActionBlocked = false
  let reconciliation = null, recoveryFlight = null, actionGeneration = 0, settledPresentation = null
  const configuredAction = () => operation?.action_type === 'memory.forget' ? forgetAction : approvalAction
  let state = Object.freeze({ phase: 'unavailable', owner: null, owner_id: '', presentation: null,
    operation_available: false, login_kinds: ['passkey'], fixture: false, expired: false, reason: 'Authority transport is unavailable.', error_code: 'UNAVAILABLE',
    capabilities:null, capability_status:'pending', authority_available:false,
    approval_action_available:false, approval_action_pending:false, approval_action_result:null, forget_action_result:null,
    logout_status:'idle', logout_error_code:null })
  const notify = patch => { state = Object.freeze({ ...state, ...patch }); for (const listen of listeners) listen() }
  const stopTimer = () => { const selected = timer; timer = undefined; if (selected) unschedule(selected) }
  const checkExpiry = () => {
    stopTimer()
    // A recovered applied receipt consumes its old review. Only the live owner
    // session expiry can disable subsequent proposals; no approval is replayed.
    const expires = [state.owner?.expiry, ...(state.presentation === settledPresentation ? []
      : [state.presentation?.approval_expiry, state.presentation?.operation.expiry])]
      .filter(Boolean).map(Date.parse)
    if (!expires.length) return
    const remaining = Math.min(...expires) - now()
    if (remaining <= 0) {
      notify({ expired: true, ...(pending ? {} : { phase: 'expired', reason: 'This session or review has expired. Sign in or request a fresh review.' }) })
      return
    }
    timer = schedule(checkExpiry, Math.min(remaining, 2 ** 31 - 1))
  }
  const fail = error => {
    const code = typeof error?.code === 'string' ? error.code : 'UNAVAILABLE'
    const uncertain = ['OUTCOME_UNKNOWN', 'RECONCILIATION_REQUIRED'].includes(code)
    notify({ phase: uncertain ? 'outcome_unknown'
      : code === 'EXPIRED' ? 'expired' : code === 'UNAVAILABLE' ? 'unavailable' : 'refused', error_code: code,
      reason: uncertain
        ? 'The host has not confirmed the result. Reconciliation is required; do not retry this approval.'
        : String(error?.message ?? 'Authority request failed.'), expired: code === 'EXPIRED' || state.expired })
  }
  async function action(phase, work, finish) {
    if (pending) return pending.promise
    const current = revision
    const abort = new AbortController()
    const flight = { abort, promise:null }
    pending = flight
    const promise = Promise.resolve().then(async () => {
      try {
        if (current !== revision || abort.signal.aborted) return null
        const result = await work(abort.signal); if (current === revision) finish(result); return result
      }
      catch (error) { if (current === revision) fail(error); return null }
      finally { if (pending === flight) { pending = undefined; if (current === revision) checkExpiry() } }
    })
    flight.promise = promise
    notify({ phase, error_code: null, reason: phase === 'login_pending' ? 'Waiting for the authenticator and host confirmation.'
      : phase === 'review_pending' ? 'Requesting a fresh review challenge.' : 'Waiting for host confirmation.' })
    return promise
  }
  const cancelApprovalAction = () => {
    approvalFlight?.abort.abort()
  }
  function revokeTransport(selected, patch, showReason) {
    if (logoutFlight) {
      logoutFlight.revision = revision; logoutFlight.showReason = showReason
      notify({ ...patch, logout_status:'pending', logout_error_code:null })
      return logoutFlight.promise
    }
    let resolveAnswer
    const answer = new Promise(resolve => { resolveAnswer = resolve })
    const flight = { revision, showReason, promise:null }
    logoutFlight = flight
    flight.promise = answer.catch(() => ({ok:false,error_code:'OUTCOME_UNKNOWN'})).then(result => {
      const confirmed = result?.ok === true && result.status === 'LOGGED_OUT' &&
        Object.keys(result).sort().join(',') === 'ok,status'
      const code = confirmed ? null : ['UNAVAILABLE','UNAUTHORIZED'].includes(result?.error_code) ? result.error_code : 'OUTCOME_UNKNOWN'
      const status = confirmed ? 'confirmed' : code === 'UNAVAILABLE' ? 'unavailable' : code === 'UNAUTHORIZED' ? 'refused' : 'unknown'
      const outcome = confirmed ? Object.freeze({ok:true,status:'LOGGED_OUT'})
        : Object.freeze({ok:false,error_code:code,reason:'ui:server-logout-not-confirmed'})
      if (logoutFlight === flight) logoutFlight = null
      if (flight.revision === revision) notify({ logout_status:status, logout_error_code:code,
        ...(flight.showReason ? { reason:confirmed
          ? 'Local access was removed. The host confirmed server logout.'
          : 'Local access was removed. Server logout is unconfirmed; no retry was sent.' } : {}) })
      return outcome
    })
    // Publish owner loss before the server call and before any workflow can
    // receive a late proof. A logout never cancels a dispatched factual effect.
    notify({ ...patch, logout_status:'pending', logout_error_code:null })
    try { resolveAnswer(selected ? selected.logout() : {ok:false,error_code:'UNAVAILABLE'}) }
    catch { resolveAnswer({ok:false,error_code:'OUTCOME_UNKNOWN'}) }
    return flight.promise
  }
  function workflowSnapshot(value, flight) {
    const result = immutable(JSON.parse(flight.contracts.canonicalJson(value)))
    const fields = ['phase','operation','memory_capture','operation_digest','approval','save','saved','record','receipt',
      'receipt_digest','citation','citation_status','index','authority_settlement','reconciliation_required','error_code','read_error_code']
    if (!result || Array.isArray(result) || Object.keys(result).sort().join(',') !== fields.sort().join(',') ||
        !['idle','proposal_pending','proposed','approval_pending','save_pending','saved','refused','outcome_unknown','unavailable'].includes(result.phase) ||
        !['not_requested','pending','approved','refused','unknown'].includes(result.approval) ||
        !['not_attempted','pending','saved','refused','unknown'].includes(result.save) ||
        ![true,false,null].includes(result.saved) || typeof result.reconciliation_required !== 'boolean' ||
        !result.index || Object.keys(result.index).sort().join(',') !== 'indexed,searchable,status' ||
        !['unconfirmed','pending','failed','indexed','searchable'].includes(result.index.status) ||
        ![true,false,null].includes(result.index.indexed) || ![true,false,null].includes(result.index.searchable) ||
        !['not_requested','pending','verified','unverified','missing','unavailable'].includes(result.citation_status) ||
        ![null,'completed','pending'].includes(result.authority_settlement) ||
        [result.error_code,result.read_error_code].some(code => code !== null && (typeof code !== 'string' || code.length > 128)) ||
        (result.receipt_digest !== null && !/^sha256:[a-f0-9]{64}$/.test(result.receipt_digest))) {
      throw new PrimeTransportError('INVALID', 'ui:invalid-memory-workflow-result')
    }
    return result
  }
  function cancelledWorkflowResult(value, flight) {
    let result
    try { result = workflowSnapshot(value, flight) }
    catch { throw new PrimeTransportError('OUTCOME_UNKNOWN', 'ui:invalid-cancelled-memory-action-result') }
    // Owner loss deliberately removes private content. These terminal facts
    // only release the pending flight; they are never presented as a receipt.
    const cleared = ['idle','unavailable'].includes(result.phase) &&
      ['operation','memory_capture','operation_digest','record','receipt','receipt_digest','citation'].every(field => result[field] === null) &&
      result.citation_status === 'not_requested' && result.read_error_code === null &&
      result.index.status === 'unconfirmed' && result.index.indexed === null && result.index.searchable === null &&
      [null,'UNAVAILABLE'].includes(result.error_code) && result.reconciliation_required === false
    const unsent = result.save === 'not_attempted' && result.saved === false &&
      result.approval === 'not_requested' && result.authority_settlement === null
    const completed = result.save === 'saved' && result.saved === true &&
      result.approval === 'approved' && result.authority_settlement === 'completed'
    if (!cleared || (!unsent && !completed)) {
      throw new PrimeTransportError('OUTCOME_UNKNOWN', 'ui:cancelled-memory-action-needs-reconciliation')
    }
  }
  function workflowResult(value, flight) {
    const result = workflowSnapshot(value, flight), contracts = flight.contracts
    if (result.operation) {
      if (contracts.canonicalJson(result.operation) !== flight.presentation.canonical_operation ||
          result.operation_digest !== flight.presentation.operation_digest) {
        throw new PrimeTransportError('TARGET_MISMATCH', 'ui:memory-workflow-operation-changed')
      }
      validateCaptureReview(result.operation.canonical_parameters, result.memory_capture)
    }
    if (result.saved === true || result.save === 'saved') {
      contracts.validateContract('MemoryRecord', result.record)
      validateSavedCaptureContent(result.record, result.memory_capture)
      const original = JSON.parse(result.record.canonical_bytes)
      const view = flight.presentation, receipt = result.receipt
      if (!flight.approved || result.saved !== true || result.save !== 'saved' || result.approval !== 'approved' ||
          !result.operation || result.record.storage_status !== 'saved' ||
          result.record.owner_subject !== view.operation.target_identity.owner_subject || result.record.task_id !== view.operation.task_id ||
          original.statement !== view.memory_review.statement || original.attributedTo !== view.memory_review.attributed_to ||
          receipt?.status !== 'applied' || receipt.operation_id !== view.operation.operation_id ||
          receipt.operation_digest !== view.operation_digest || receipt.grant_id !== 'grant:' + flight.proofNonce ||
          contracts.canonicalJson(receipt.result) !== contracts.canonicalJson(result.record) ||
          !['completed','pending'].includes(result.authority_settlement) ||
          (result.authority_settlement === 'completed' && result.reconciliation_required) ||
          (result.authority_settlement === 'pending' && !result.reconciliation_required)) {
        throw new PrimeTransportError('TARGET_MISMATCH', 'ui:memory-workflow-receipt-mismatch')
      }
    }
    return result
  }
  const liveApprovalFlight = flight => approvalFlight === flight && revision === flight.revision &&
    binding === flight.binding && state.owner === flight.owner && state.presentation === flight.presentation &&
    actionGeneration === flight.actionGeneration && configuredAction() === flight.handler &&
    !flight.abort.signal.aborted && state.authority_available === true && state.expired === false &&
    Date.parse(state.owner?.expiry) > now()
  function requestApproval(flight = null) {
    if (state.phase !== 'review_ready' || state.expired || !state.authority_available) return Promise.resolve(null)
    const presentation = state.presentation
    return action('approval_pending', signal => transport.approve(presentation, { kind: ownerKind ?? 'passkey', signal }), result => {
      // A raw approval never attributes its proof to an owned workflow flight.
      if (flight && liveApprovalFlight(flight)) {
        flight.approved = true; flight.proofNonce = result.approval_proof.nonce
      }
      notify({ phase: 'approved', error_code: null, reason: result.status === 'APPROVED'
        ? 'The host confirmed approval of this exact operation. Execution has not been confirmed.' : 'The result is unknown.' })
    })
  }
  function hookApproval(flight) {
    if (!liveApprovalFlight(flight)) return Promise.resolve(null)
    if (flight.approvalPromise) return flight.approvalPromise
    if (pending || state.phase !== 'review_ready') return Promise.resolve(null)
    // Reserve before requestApproval publishes approval_pending. Reentrant
    // calls receive this same private promise, never another pending action.
    flight.approvalPromise = Promise.resolve().then(async () => {
      if (!liveApprovalFlight(flight) || pending) return null
      const result = await requestApproval(flight)
      return liveApprovalFlight(flight) ? result : null
    })
    return flight.approvalPromise
  }
  const api = {
    getSnapshot: () => state,
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener) },
    connect(next, { onConnection } = {}) {
      if (disposed) return null
      // Separate from session/operation revisions: only binding replacement,
      // disconnection or disposal invalidates this connection witness.
      const connection = ++connectionGeneration
      const connecting = () => !disposed && connectionGeneration === connection
      let completed = false, selected
      const witness = Object.freeze({ isCurrent: () => completed && connecting() && binding === next && transport === selected })
      connectionWitnesses.set(witness, connection)
      // The native lifecycle must retain ownership before any synchronous
      // notification can remove its scope. Completion remains false until end.
      if (onConnection) onConnection(witness)
      if (!connecting()) return null
      reconciliation = null; settledPresentation = null
      cancelApprovalAction()
      if (!connecting()) return null
      approvalAction = null; forgetAction = null
      const previous = transport
      const hadPending = !!pending
      ++revision; pending?.abort.abort()
      if (!connecting()) return null
      stopTimer()
      if (!connecting()) return null
      pending = undefined; transport = undefined
      operation = undefined; ownerKind = undefined; memoryCapture = undefined; captureMetadata = undefined; recordSummary = undefined
      if (previous && (previous.owner() || hadPending || logoutFlight)) {
        revokeTransport(previous, { owner:null, presentation:null, operation_available:false, approval_action_pending:false, approval_action_result:null, forget_action_result:null }, false)
      } else if (previous) { void previous.logout() }
      if (!connecting()) return null
      binding = next
      try {
        selected = createPrimeTransport({ authority: next.authority, contracts: next.contracts,
          ownerSigner: next.ownerSigner, passkeySigner: next.passkeySigner ?? createBrowserPasskeySigner({ contracts: next.contracts, profile:next.passkeyProfile }), now })
        if (!connecting() || binding !== next) return null
        transport = selected
        const available = next.requiresCapabilities !== true
        notify({ phase: available ? 'logged_out' : 'unavailable', owner: null, owner_id: next.owner_id ?? '', presentation: null, operation_available: false,
          login_kinds: Object.freeze((next.loginKinds ?? ['passkey']).filter(kind => kind === 'passkey' || kind === 'owner_key')),
          fixture: next.fixture === true, capabilities:null, capability_status:next.fixture === true ? 'fixture' : 'pending', authority_available:available,
          approval_action_available:false, approval_action_pending:false, approval_action_result:null, forget_action_result:null,
          ...(!logoutFlight ? {logout_status:'idle',logout_error_code:null} : {}),
          expired: false, error_code: available ? null : 'UNAVAILABLE', reason: available
            ? 'Sign in with an existing credential. The host must confirm your identity.' : 'Owner access is unavailable until the host supplies its capability status.' })
        if (!connecting() || binding !== next || transport !== selected) return null
        if (next.operation) api.setOperation(next.operation, { memoryCapture: next.memoryCapture, captureMetadata: next.captureMetadata, recordSummary: next.recordSummary })
        if (!connecting() || binding !== next || transport !== selected || next.operation && !operation) return null
        // An opaque, read-only lifetime witness. It carries no owner/session,
        // capability, proof or authority material and performs no request.
        completed = true
        return witness
      } catch (error) {
        // A synchronous observer may already have established a replacement.
        if (connecting()) { transport = undefined; fail(error) }
        return null
      }
    },
    setCapabilities(value) {
      const capabilities = validateCapabilities(value)
      const available = binding?.requiresCapabilities !== true || !capabilities.unavailable_capabilities.includes('owner-passkey')
      notify({ capabilities, capability_status:'loaded', authority_available:available,
        ...(!pending && !state.owner && transport ? { phase:available ? 'logged_out' : 'unavailable', error_code:available ? null : 'UNAVAILABLE',
          reason:available ? 'Sign in with an existing credential. The host must confirm your identity.' : 'Owner passkey access is unavailable in this disposable preview.' } : {}) })
    },
    capabilitiesUnavailable() {
      notify({ capabilities:null, capability_status:'unavailable', ...(binding?.requiresCapabilities === true ? { authority_available:false } : {}) })
    },
    setOwnerId(owner_id) { if (!pending && !state.owner) notify({ owner_id }) },
    setOperation(proposal, options = {}) {
      if (pending || approvalFlight || approvalActionBlocked || state.phase === 'outcome_unknown') throw new PrimeTransportError('RECONCILIATION_REQUIRED', 'An authority request is pending or needs reconciliation.')
      try {
        binding.contracts.validateContract('OperationProposal', proposal)
        const proposed = immutable(JSON.parse(binding.contracts.canonicalJson(proposal)))
        let captureDraft
        if (proposed.action_type === 'memory.save') {
          try {
            captureDraft = validateCaptureReview(proposed.canonical_parameters, options.memoryCapture)
            if (options.captureMetadata !== undefined) {
              const metadata = validateCaptureMetadata(options.captureMetadata)
              if (CAPTURE_METADATA_FIELDS.some(key => metadata[key] !== captureDraft.capture_metadata[key])) {
                throw new TypeError('ui:fixed-capture-metadata-mismatched')
              }
            }
          } catch { throw new PrimeTransportError('TARGET_MISMATCH', 'ui:memory-capture-review-missing-or-mismatched') }
        } else if (proposed.action_type === 'memory.forget') {
          try { validateForgetReview(proposed, options.recordSummary) }
          catch { throw new PrimeTransportError('TARGET_MISMATCH', 'ui:forget-record-review-missing-or-mismatched') }
        }
        memoryCapture = captureDraft
        captureMetadata = memoryCapture?.capture_metadata
        recordSummary = proposed.action_type === 'memory.forget' ? validateForgetReview(proposed, options.recordSummary) : undefined
        operation = proposed
      } catch (error) {
        operation = undefined; memoryCapture = undefined; captureMetadata = undefined; recordSummary = undefined
        notify({ operation_available: false, presentation: null })
        fail(error)
        throw error
      }
      settledPresentation = null
      notify({ operation_available: true, presentation: null, expired: false, approval_action_result:null, forget_action_result:null,
        approval_action_available:!!configuredAction() && !approvalActionBlocked,
        phase: state.owner ? 'authenticated' : state.phase, reason: 'The host supplied an operation. Request a fresh review before deciding.' })
      checkExpiry()
    },
    login(kind = 'passkey') {
      if (logoutFlight) { notify({reason:'Local access was removed. Waiting for the server logout response.'}); return Promise.resolve(null) }
      if (!transport || !state.authority_available || !state.login_kinds.includes(kind)) { fail(new PrimeTransportError('UNAVAILABLE', 'This credential method is unavailable.')); return Promise.resolve(null) }
      return action('login_pending', signal => transport.login({ owner_id: state.owner_id, kind, signal }), owner => {
        ownerKind = kind
        notify({ phase: 'authenticated', owner, presentation: null, expired: false, error_code: null,
          reason: 'The host confirmed this owner session.', logout_status:'idle', logout_error_code:null })
      })
    },
    prepare() {
      if (approvalFlight || approvalActionBlocked) { fail(new PrimeTransportError('RECONCILIATION_REQUIRED', 'A memory action is pending or needs reconciliation.')); return Promise.resolve(null) }
      if (!transport || !state.authority_available || !operation) { fail(new PrimeTransportError('UNAVAILABLE', 'An available authority and a host operation are required.')); return Promise.resolve(null) }
      return action('review_pending', signal => transport.prepareApproval(operation, { signal, memoryCapture, captureMetadata, recordSummary }), presentation => {
        notify({ phase: 'review_ready', presentation, expired: false, error_code: null,
          reason: 'Review every field below. Approval requests a fresh assertion and requires host confirmation.' })
      })
    },
    approve() {
      if (approvalFlight || approvalActionBlocked) return Promise.resolve(null)
      return requestApproval()
    },
    setApprovalAction(handler) {
      if (handler !== null && typeof handler !== 'function') throw new PrimeTransportError('INVALID', 'ui:invalid-approval-action')
      if (approvalFlight && handler !== null) throw new PrimeTransportError('RECONCILIATION_REQUIRED', 'A memory action is still pending.')
      // A detached workflow must not receive a late approved proof and save.
      // Dropping the local owner fences the same adapter/workflow generation.
      if (handler === null && approvalFlight) api.logout()
      else if (handler === null) cancelApprovalAction()
      ++actionGeneration; reconciliation = null
      approvalAction = handler
      notify({ approval_action_available: !!configuredAction() && !approvalActionBlocked })
    },
    setForgetAction(handler) {
      if (handler !== null && typeof handler !== 'function') throw new PrimeTransportError('INVALID', 'ui:invalid-forget-action')
      if (approvalFlight && handler !== null) throw new PrimeTransportError('RECONCILIATION_REQUIRED', 'A memory action is still pending.')
      if (handler === null && approvalFlight) void api.logout()
      else if (handler === null) cancelApprovalAction()
      ++actionGeneration; reconciliation = null
      forgetAction = handler
      notify({ approval_action_available:!!configuredAction() && !approvalActionBlocked })
    },
    reconcileApprovalAction(value) {
      if (recoveryFlight) return recoveryFlight.promise
      const retained = reconciliation
      // An idle reply or a new owner/binding cannot resolve an old uncertain
      // effect. Only the exact retained review and confirmed approval can.
      const current = () => retained && reconciliation === retained && approvalActionBlocked &&
        revision === retained.revision && binding === retained.binding && state.owner === retained.owner &&
        state.presentation === retained.presentation && configuredAction() === retained.handler &&
        actionGeneration === retained.actionGeneration && !approvalFlight && !pending && !logoutFlight &&
        state.authority_available === true && state.owner !== null &&
        retained.approved === true && !retained.abort.signal.aborted &&
        Date.parse(state.owner?.expiry) > now()
      if (approvalFlight || pending || logoutFlight || !current()) return Promise.resolve(null)
      const flight = {promise:null}
      recoveryFlight = flight
      flight.promise = Promise.resolve().then(async () => {
        try {
          if (!current()) return null
          const forgetting = retained.presentation.operation.action_type === 'memory.forget'
          const result = forgetting ? await validateForgetWorkflowResult(value, retained)
            : await validateSaveRecovery(workflowSnapshot(value, retained), retained)
          if (!current()) return null
          if (result.authority_settlement !== 'completed' || result.reconciliation_required !== false ||
              result.error_code !== null || (forgetting ? result.forgotten !== true : result.saved !== true)) {
            throw new PrimeTransportError('OUTCOME_UNKNOWN', 'ui:memory-recovery-not-completed')
          }
          approvalActionBlocked = false; reconciliation = null; settledPresentation = retained.presentation
          stopTimer()
          notify({phase:'approved',error_code:null,expired:false,approval_action_pending:false,
            ...(forgetting ? {forget_action_result:result,approval_action_result:null} : {approval_action_result:result,forget_action_result:null}),
            approval_action_available:!!configuredAction(),reason:forgetting
              ? 'The host recovered the logical forget receipt and confirmed authority settlement. Canonical payloads and external copies remain retained.'
              : 'The host recovered the save receipt and confirmed authority settlement. Index and citation status are shown separately.'})
          checkExpiry()
          return result
        } catch {
          if (current()) fail(new PrimeTransportError('OUTCOME_UNKNOWN', 'ui:memory-recovery-not-confirmed'))
          return null
        } finally {
          if (recoveryFlight === flight) recoveryFlight = null
        }
      })
      return flight.promise
    },
    submitApproval() {
      if (approvalActionBlocked) { fail(new PrimeTransportError('RECONCILIATION_REQUIRED', 'The memory action needs reconciliation; do not retry.')); return Promise.resolve(null) }
      if (approvalFlight) {
        if (approvalFlight.revision === revision && approvalFlight.presentation === state.presentation) return approvalFlight.promise
        fail(new PrimeTransportError('RECONCILIATION_REQUIRED', 'A previous memory action is unresolved.')); return Promise.resolve(null)
      }
      if (state.phase !== 'review_ready' || state.expired || !state.authority_available) return Promise.resolve(null)
      const forgetting = state.presentation.operation.action_type === 'memory.forget'
      if (!forgetting && state.presentation.operation.action_type !== 'memory.save') return api.approve()
      const handler = configuredAction()
      if (!handler) { fail(new PrimeTransportError('UNAVAILABLE', forgetting ? 'ui:forget-approval-action-unavailable' : 'ui:memory-approval-action-unavailable')); return Promise.resolve(null) }
      const flight = { revision, binding, actionGeneration, presentation: state.presentation, owner: state.owner, handler,
        contracts: binding.contracts, started: false, approved: false, abort: new AbortController(), promise: null }
      approvalFlight = flight
      // Publish only after the shared promise exists; listener-triggered clicks coalesce too.
      flight.promise = Promise.resolve().then(async () => {
        try {
          if (revision !== flight.revision || state.owner !== flight.owner || flight.abort.signal.aborted) return null
          flight.started = true
          const value = await flight.handler(flight.presentation, Object.freeze({
            signal:flight.abort.signal, approve:() => hookApproval(flight),
          }))
          const stale = revision !== flight.revision || state.owner !== flight.owner || flight.abort.signal.aborted
          if (stale) {
            if (forgetting) validateCancelledForgetWorkflow(value, flight.contracts)
            else cancelledWorkflowResult(value, flight)
            return null
          }
          const result = forgetting ? await validateForgetWorkflowResult(value, flight) : workflowResult(value, flight)
          if (revision !== flight.revision || state.owner !== flight.owner || flight.abort.signal.aborted) {
            if (!(forgetting && result.forgotten === true && result.authority_settlement === 'completed' && !result.reconciliation_required)) {
              if (forgetting) validateCancelledForgetWorkflow(result, flight.contracts)
              else cancelledWorkflowResult(result, flight)
            }
            return null
          }
          const unresolved = result.reconciliation_required || (forgetting ? result.forget : result.save) === 'unknown' || result.phase === 'outcome_unknown'
          if (unresolved) { approvalActionBlocked = true; reconciliation = flight }
          const completed = forgetting ? result.forget === 'forgotten' : result.save === 'saved'
          notify({ ...(forgetting ? {forget_action_result:result,approval_action_result:null} : {approval_action_result:result,forget_action_result:null}), approval_action_available: !!configuredAction() && !approvalActionBlocked,
            phase: unresolved ? 'outcome_unknown' : completed ? 'approved' : result.phase === 'refused' ? 'refused' : state.phase,
            error_code: unresolved ? 'RECONCILIATION_REQUIRED' : result.error_code,
            reason: forgetting ? (completed ? (unresolved
              ? 'The host confirmed logical forget; authority settlement needs reconciliation.'
              : 'The host confirmed logical forget with its receipt. Canonical payloads and external copies remain retained.')
              : unresolved ? 'The host has not confirmed the forget outcome. Reconciliation is required; do not retry.'
              : 'The host workflow did not confirm logical forget.') : result.save === 'saved' ? (unresolved
              ? 'The host workflow confirmed the save; authority settlement needs reconciliation.'
              : 'The host workflow confirmed the save with its receipt. Index and citation status are shown separately.')
              : unresolved ? 'The host has not confirmed the memory save outcome. Reconciliation is required; do not retry.'
              : 'The host workflow did not confirm a memory save. Approval alone does not confirm storage.' })
          return result
        } catch (error) {
          if (flight.approved || (flight.started && (revision !== flight.revision || state.owner !== flight.owner || flight.abort.signal.aborted)) ||
              ['OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED'].includes(error?.code)) approvalActionBlocked = true
          if (revision === flight.revision && state.owner === flight.owner) {
            if (approvalActionBlocked) reconciliation = flight
            fail(approvalActionBlocked ? new PrimeTransportError('OUTCOME_UNKNOWN', 'ui:memory-action-outcome-unknown') : error)
            notify({ approval_action_available: !!configuredAction() && !approvalActionBlocked })
          }
          return null
        } finally {
          if (approvalFlight === flight) approvalFlight = null
          notify({ approval_action_available: !!configuredAction() && !approvalActionBlocked,
            ...(revision === flight.revision ? { approval_action_pending:false } : {}) })
        }
      })
      notify({ approval_action_pending:true, approval_action_result:null, forget_action_result:null })
      return flight.promise
    },
    decline() {
      if (approvalFlight || approvalActionBlocked) { fail(new PrimeTransportError('RECONCILIATION_REQUIRED', 'A memory action is pending or needs reconciliation.')); return Promise.resolve(null) }
      if (state.phase !== 'review_ready' || state.expired || !state.authority_available) return Promise.resolve(null)
      const presentation = state.presentation
      return action('decline_pending', signal => transport.decline(presentation, { signal }), () => {
        notify({ phase: 'denied', error_code: null, reason: 'The host confirmed that this operation was declined.' })
      })
    },
    logout() {
      reconciliation = null; settledPresentation = null
      if (logoutFlight?.revision === revision) return logoutFlight.promise
      cancelApprovalAction()
      ++revision; pending?.abort.abort(); pending = undefined; stopTimer()
      ownerKind = undefined
      return revokeTransport(transport, { phase: transport && state.authority_available ? 'logged_out' : 'unavailable', owner: null, presentation: null, expired: false,
        approval_action_pending:false, approval_action_result:null, forget_action_result:null, approval_action_available:!!configuredAction() && !approvalActionBlocked,
        reason:'Local access was removed. Waiting for the server logout response.', error_code:null }, true)
    },
    disconnect(expectedWitness) {
      // This also admits our still-connecting lifetime. A retained old witness
      // cannot remove any later connection, even one to the identical binding.
      if (expectedWitness !== undefined && connectionWitnesses.get(expectedWitness) !== connectionGeneration) {
        return Promise.resolve(Object.freeze({ok:false,error_code:'UNAVAILABLE',reason:'ui:binding-disconnect-superseded'}))
      }
      const connection = ++connectionGeneration
      const previous = transport
      const disconnecting = () => connectionGeneration === connection
      const superseded = () => Promise.resolve(Object.freeze({ok:false,error_code:'UNAVAILABLE',reason:'ui:binding-disconnect-superseded'}))
      reconciliation = null; settledPresentation = null
      cancelApprovalAction()
      if (!disconnecting()) return superseded()
      approvalAction = null; forgetAction = null
      ++revision; pending?.abort.abort()
      if (!disconnecting()) return superseded()
      stopTimer()
      if (!disconnecting()) return superseded()
      pending = undefined; transport = undefined; ownerKind = undefined; operation = undefined; memoryCapture = undefined; captureMetadata = undefined; recordSummary = undefined
      return revokeTransport(previous, { phase:'unavailable',owner:null,presentation:null,operation_available:false,expired:false,error_code:'UNAVAILABLE',reason:'Authority transport is unavailable.',authority_available:false,
        approval_action_available:false,approval_action_pending:false,approval_action_result:null,forget_action_result:null }, false)
    },
    dispose() { disposed = true; void api.disconnect(); listeners.clear() },
  }
  return Object.freeze(api)
}
