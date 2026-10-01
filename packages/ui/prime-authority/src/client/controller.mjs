import { createPrimeTransport, PrimeTransportError } from '../../../adapters/transport.mjs'
import { createBrowserPasskeySigner } from '../../../adapters/passkey.mjs'

async function readJson(response, contracts) {
  if (typeof contracts?.parseStrictJson !== 'function') throw new PrimeTransportError('UNAVAILABLE', 'ui:strict-json-helper-unavailable')
  try { return contracts.parseStrictJson(await response.text(), { maxBytes: 8388608, maxDepth: 64 }) }
  catch { throw new PrimeTransportError('INVALID', 'ui:invalid-response-json') }
}

export function createHttpAuthority(fetcher = globalThis.fetch, contracts) {
  return Object.freeze(Object.fromEntries(['loginChallenge', 'loginComplete', 'approvalChallenge', 'approvalComplete', 'declineApproval'].map(method => [method,
    async (input, { signal } = {}) => {
      if (typeof contracts?.parseStrictJson !== 'function' || typeof contracts?.canonicalJson !== 'function') {
        throw new PrimeTransportError('UNAVAILABLE', 'ui:strict-json-helper-unavailable')
      }
      let body
      try { body = contracts.canonicalJson(input) }
      catch { throw new PrimeTransportError('INVALID', 'ui:invalid-request-json') }
      const response = await fetcher('/api/prime/authority/' + method, { method: 'POST', credentials: 'same-origin',
        redirect: 'error', cache: 'no-store', headers: { 'content-type': 'application/json' }, body, signal })
      let answer
      try { answer = await readJson(response, contracts) }
      catch (error) {
        if (method === 'approvalComplete' || method === 'declineApproval') {
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
  let binding, transport, pending, timer, revision = 0, operation, ownerKind
  let state = Object.freeze({ phase: 'unavailable', owner: null, owner_id: '', presentation: null,
    operation_available: false, login_kinds: ['passkey'], fixture: false, expired: false, reason: 'Authority transport is unavailable.', error_code: 'UNAVAILABLE',
    capabilities:null, capability_status:'pending', authority_available:false })
  const notify = patch => { state = Object.freeze({ ...state, ...patch }); for (const listen of listeners) listen() }
  const stopTimer = () => { if (timer) unschedule(timer); timer = undefined }
  const checkExpiry = () => {
    stopTimer()
    const expires = [state.owner?.expiry, state.presentation?.approval_expiry, state.presentation?.operation.expiry]
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
    notify({ phase, error_code: null, reason: phase === 'login_pending' ? 'Waiting for the authenticator and host confirmation.'
      : phase === 'review_pending' ? 'Requesting a fresh review challenge.' : 'Waiting for host confirmation.' })
    pending = { abort, promise: null }
    const promise = (async () => {
      try { const result = await work(abort.signal); if (current === revision) finish(result); return result }
      catch (error) { if (current === revision) fail(error); return null }
      finally { if (current === revision) { pending = undefined; checkExpiry() } }
    })()
    pending.promise = promise
    return promise
  }
  const api = {
    getSnapshot: () => state,
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener) },
    connect(next) {
      ++revision; pending?.abort.abort(); pending = undefined; transport?.logout(); stopTimer(); operation = undefined; ownerKind = undefined
      binding = next
      try {
        transport = createPrimeTransport({ authority: next.authority, contracts: next.contracts,
          ownerSigner: next.ownerSigner, passkeySigner: next.passkeySigner ?? createBrowserPasskeySigner({ contracts: next.contracts, profile:next.passkeyProfile }), now })
        const available = next.requiresCapabilities !== true
        notify({ phase: available ? 'logged_out' : 'unavailable', owner: null, owner_id: next.owner_id ?? '', presentation: null, operation_available: false,
          login_kinds: Object.freeze((next.loginKinds ?? ['passkey']).filter(kind => kind === 'passkey' || kind === 'owner_key')),
          fixture: next.fixture === true, capabilities:null, capability_status:next.fixture === true ? 'fixture' : 'pending', authority_available:available,
          expired: false, error_code: available ? null : 'UNAVAILABLE', reason: available
            ? 'Sign in with an existing credential. The host must confirm your identity.' : 'Owner access is unavailable until the host supplies its capability status.' })
        if (next.operation) api.setOperation(next.operation)
      } catch (error) { transport = undefined; fail(error) }
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
    setOperation(proposal) {
      if (pending || state.phase === 'outcome_unknown') throw new PrimeTransportError('RECONCILIATION_REQUIRED', 'An authority request is pending or needs reconciliation.')
      binding.contracts.validateContract('OperationProposal', proposal)
      operation = immutable(JSON.parse(binding.contracts.canonicalJson(proposal)))
      notify({ operation_available: true, presentation: null, expired: false,
        phase: state.owner ? 'authenticated' : state.phase, reason: 'The host supplied an operation. Request a fresh review before deciding.' })
      checkExpiry()
    },
    login(kind = 'passkey') {
      if (!transport || !state.authority_available || !state.login_kinds.includes(kind)) { fail(new PrimeTransportError('UNAVAILABLE', 'This credential method is unavailable.')); return Promise.resolve(null) }
      return action('login_pending', signal => transport.login({ owner_id: state.owner_id, kind, signal }), owner => {
        ownerKind = kind
        notify({ phase: 'authenticated', owner, presentation: null, expired: false, error_code: null,
          reason: 'The host confirmed this owner session.' })
      })
    },
    prepare() {
      if (!transport || !state.authority_available || !operation) { fail(new PrimeTransportError('UNAVAILABLE', 'An available authority and a host operation are required.')); return Promise.resolve(null) }
      return action('review_pending', signal => transport.prepareApproval(operation, { signal }), presentation => {
        notify({ phase: 'review_ready', presentation, expired: false, error_code: null,
          reason: 'Review every field below. Approval requests a fresh assertion and requires host confirmation.' })
      })
    },
    approve() {
      if (state.phase !== 'review_ready' || state.expired || !state.authority_available) return Promise.resolve(null)
      const presentation = state.presentation
      return action('approval_pending', signal => transport.approve(presentation, { kind: ownerKind ?? 'passkey', signal }), result => {
        notify({ phase: 'approved', error_code: null, reason: result.status === 'APPROVED'
          ? 'The host confirmed approval of this exact operation. Execution has not been confirmed.' : 'The result is unknown.' })
      })
    },
    decline() {
      if (state.phase !== 'review_ready' || state.expired || !state.authority_available) return Promise.resolve(null)
      const presentation = state.presentation
      return action('decline_pending', signal => transport.decline(presentation, { signal }), () => {
        notify({ phase: 'denied', error_code: null, reason: 'The host confirmed that this operation was declined.' })
      })
    },
    logout() {
      ++revision; pending?.abort.abort(); pending = undefined; transport?.logout(); stopTimer()
      ownerKind = undefined
      notify({ phase: transport && state.authority_available ? 'logged_out' : 'unavailable', owner: null, presentation: null, expired: false,
        reason: 'Signed out. A new host-confirmed session is required.', error_code: null })
    },
    disconnect() {
      ++revision; pending?.abort.abort(); pending = undefined; transport?.logout(); transport = undefined; ownerKind = undefined; operation = undefined; stopTimer()
      notify({ phase:'unavailable',owner:null,presentation:null,operation_available:false,expired:false,error_code:'UNAVAILABLE',reason:'Authority transport is unavailable.',authority_available:false })
    },
    dispose() { ++revision; pending?.abort.abort(); pending = undefined; transport?.logout(); stopTimer(); listeners.clear() },
  }
  return Object.freeze(api)
}
