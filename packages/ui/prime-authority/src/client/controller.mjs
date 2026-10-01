import { createPrimeTransport, PrimeTransportError } from '../../../adapters/transport.mjs'
import { createBrowserPasskeySigner } from '../../../adapters/passkey.mjs'

export function createHttpAuthority(fetcher = globalThis.fetch) {
  return Object.freeze(Object.fromEntries(['loginChallenge', 'loginComplete', 'approvalChallenge', 'approvalComplete', 'declineApproval'].map(method => [method,
    async (input, { signal } = {}) => {
      const response = await fetcher('/api/prime/authority/' + method, { method: 'POST', credentials: 'same-origin',
        redirect: 'error', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input), signal })
      const answer = await response.json()
      if (!response.ok && answer?.ok !== false) throw new Error('Authority response unavailable')
      return answer
    }])) )
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
    operation_available: false, login_kinds: ['passkey'], fixture: false, expired: false, reason: 'Authority transport is unavailable.', error_code: 'UNAVAILABLE' })
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
    const uncertain = ['OUTCOME_UNKNOWN', 'RECONCILIATION_REQUIRED'].includes(code) ||
      (['approval_pending', 'decline_pending'].includes(state.phase) && ['TARGET_MISMATCH', 'INVALID'].includes(code))
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
          ownerSigner: next.ownerSigner, passkeySigner: next.passkeySigner ?? createBrowserPasskeySigner({ contracts: next.contracts }), now })
        notify({ phase: 'logged_out', owner: null, owner_id: next.owner_id ?? '', presentation: null, operation_available: false,
          login_kinds: Object.freeze((next.loginKinds ?? ['passkey']).filter(kind => kind === 'passkey' || kind === 'owner_key')),
          fixture: next.fixture === true,
          expired: false, error_code: null, reason: 'Sign in with an existing credential. The host must confirm your identity.' })
        if (next.operation) api.setOperation(next.operation)
      } catch (error) { transport = undefined; fail(error) }
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
      if (!transport || !state.login_kinds.includes(kind)) { fail(new PrimeTransportError('UNAVAILABLE', 'This credential method is unavailable.')); return Promise.resolve(null) }
      return action('login_pending', signal => transport.login({ owner_id: state.owner_id, kind, signal }), owner => {
        ownerKind = kind
        notify({ phase: 'authenticated', owner, presentation: null, expired: false, error_code: null,
          reason: 'The host confirmed this owner session.' })
      })
    },
    prepare() {
      if (!transport || !operation) { fail(new PrimeTransportError('UNAVAILABLE', 'No operation has been supplied by the host.')); return Promise.resolve(null) }
      return action('review_pending', signal => transport.prepareApproval(operation, { signal }), presentation => {
        notify({ phase: 'review_ready', presentation, expired: false, error_code: null,
          reason: 'Review every field below. Approval requests a fresh assertion and requires host confirmation.' })
      })
    },
    approve() {
      if (state.phase !== 'review_ready' || state.expired) return Promise.resolve(null)
      const presentation = state.presentation
      return action('approval_pending', signal => transport.approve(presentation, { kind: ownerKind ?? 'passkey', signal }), result => {
        notify({ phase: 'approved', error_code: null, reason: result.status === 'APPROVED'
          ? 'The host confirmed approval of this exact operation. Execution has not been confirmed.' : 'The result is unknown.' })
      })
    },
    decline() {
      if (state.phase !== 'review_ready' || state.expired) return Promise.resolve(null)
      const presentation = state.presentation
      return action('decline_pending', signal => transport.decline(presentation, { signal }), () => {
        notify({ phase: 'denied', error_code: null, reason: 'The host confirmed that this operation was declined.' })
      })
    },
    logout() {
      ++revision; pending?.abort.abort(); pending = undefined; transport?.logout(); stopTimer()
      ownerKind = undefined
      notify({ phase: transport ? 'logged_out' : 'unavailable', owner: null, presentation: null, expired: false,
        reason: 'Signed out. A new host-confirmed session is required.', error_code: null })
    },
    disconnect() {
      ++revision; pending?.abort.abort(); pending = undefined; transport?.logout(); transport = undefined; ownerKind = undefined; operation = undefined; stopTimer()
      notify({ phase:'unavailable',owner:null,presentation:null,operation_available:false,expired:false,error_code:'UNAVAILABLE',reason:'Authority transport is unavailable.' })
    },
    dispose() { ++revision; pending?.abort.abort(); pending = undefined; transport?.logout(); stopTimer(); listeners.clear() },
  }
  return Object.freeze(api)
}
