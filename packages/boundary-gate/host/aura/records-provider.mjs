// SPDX-License-Identifier: AGPL-3.0-or-later
// Trusted-host read-only adapter. It creates no identity, grant, source association or evidence.
// Publish service only; retain dispose in the existing Cordis owner lifecycle.

const HEX64 = /^[0-9a-f]{64}$/u
const SUBJECT = /^aukora:1:[0-9a-f]{64}$/u
const JOURNAL = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u
const CONTROLS = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u
const SOURCE_KEYS = ['journal_id', 'position', 'hash']
const OPTION_KEYS = ['ownerSubject', 'reader', 'isLive', 'hasReadGrant', 'referenceForRecord']

class ProviderRefusal extends TypeError {
  constructor(reason) {
    super(`aura-citation:${reason}`)
    this.name = 'AuraRecordsProviderRefusal'
    this.code = this.message
  }
}
const refuse = reason => { throw new ProviderRefusal(reason) }

function descriptors(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return null
  return Object.getOwnPropertyDescriptors(value)
}
function fields(value, required, optional = []) {
  const members = descriptors(value)
  if (!members) return null
  const keys = Reflect.ownKeys(members)
  if (keys.some(key => typeof key !== 'string' || (!required.includes(key) && !optional.includes(key)))
    || required.some(key => !Object.hasOwn(members, key))) return null
  for (const key of keys) {
    if (members[key].enumerable !== true || !Object.hasOwn(members[key], 'value')) return null
  }
  return Object.fromEntries(keys.map(key => [key, members[key].value]))
}
function readerMethods(reader) {
  const members = descriptors(reader)
  if (!members) return null
  const methods = {}
  for (const key of ['readCitation', 'dispose']) {
    const descriptor = members[key]
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') return null
    methods[key] = descriptor.value
  }
  return methods
}
function detachedSelector(value) {
  const selected = fields(value, ['source'], ['record_id'])
  const source = selected && fields(selected.source, SOURCE_KEYS)
  if (!selected || !source || typeof source.journal_id !== 'string' || !JOURNAL.test(source.journal_id)
    || !Number.isSafeInteger(source.position) || source.position < 1
    || typeof source.hash !== 'string' || !HEX64.test(source.hash)
    || (Object.hasOwn(selected, 'record_id') && (typeof selected.record_id !== 'string' || !HEX64.test(selected.record_id))))
    refuse('selector-invalid')
  return Object.freeze({ source: Object.freeze({ journal_id: source.journal_id, position: source.position, hash: source.hash }),
    ...(Object.hasOwn(selected, 'record_id') ? { record_id: selected.record_id } : {}) })
}
function validRecordId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256
    && value.isWellFormed() && Buffer.byteLength(value, 'utf8') <= 256 && !CONTROLS.test(value)
}
function consumeNativeRejection(value) {
  // The native intrinsic does not read or invoke an arbitrary object's then method.
  try { Promise.prototype.then.call(value, undefined, () => {}) } catch {}
}
function synchronousTrue(predicate, ...args) {
  const value = Reflect.apply(predicate, undefined, args)
  if (value !== true && value !== false) {
    // Consume native Promise rejection diagnostics, but do not await/authorize or invoke thenables.
    consumeNativeRejection(value)
  }
  return value === true
}
const incomplete = reason => Object.freeze({ ok: false, status: 'incomplete', reason,
  grants_authority: false, citation: null, verification: null })

/**
 * ownerSubject/reader/predicates/callback come only from the existing trusted host context.
 * Predicates must inspect that owner's live scope and SAME retained read grant on every call.
 * referenceForRecord is an actual host association lookup, or explicit null when absent.
 * This adapter does not authenticate a request or derive note-to-source associations.
 */
export function createAuraRecordsProvider(options) {
  let input, methods
  try {
    input = fields(options, OPTION_KEYS)
    methods = input && readerMethods(input.reader)
  } catch { refuse('provider-unconfigured') }
  if (!input || !methods || typeof input.isLive !== 'function' || typeof input.hasReadGrant !== 'function'
    || (input.referenceForRecord !== null && typeof input.referenceForRecord !== 'function')) refuse('provider-unconfigured')
  if (typeof input.ownerSubject !== 'string' || !SUBJECT.test(input.ownerSubject)) refuse('owner-scope-invalid')
  const ownerSubject = input.ownerSubject, reader = input.reader
  const isLive = input.isLive, hasReadGrant = input.hasReadGrant, lookup = input.referenceForRecord
  const read = methods.readCitation, release = methods.dispose
  let disposed = false
  const checkAccess = () => {
    try {
      if (disposed || !synchronousTrue(isLive) || disposed) refuse('owner-inactive')
      if (!synchronousTrue(hasReadGrant, ownerSubject)) refuse('read-grant-unavailable')
      if (disposed || !synchronousTrue(isLive) || disposed) refuse('owner-inactive')
    } catch (error) {
      if (error instanceof ProviderRefusal) throw error
      refuse('read-guard-unavailable')
    }
  }
  const service = Object.freeze({
    async referenceForRecord(memoryRecordId) {
      try {
        checkAccess()
        if (!validRecordId(memoryRecordId)) refuse('record-id-invalid')
        const value = lookup === null ? null : await Reflect.apply(lookup, undefined, [memoryRecordId])
        checkAccess()
        if (value === null) return null
        let selected
        try { selected = detachedSelector(value) } catch { refuse('association-invalid') }
        checkAccess()
        return selected
      } catch (error) {
        // A failed awaited lookup must still respect a concurrently disposed/revoked scope.
        checkAccess()
        if (error instanceof ProviderRefusal) throw error
        refuse('association-unavailable')
      }
    },
    async readCitation(selector) {
      try {
        checkAccess()
        const selected = detachedSelector(selector)
        checkAccess()
        const result = await Reflect.apply(read, reader, [ownerSubject, selected])
        checkAccess()
        return result
      } catch (error) {
        try { checkAccess() } catch (guardError) { return incomplete(guardError.code) }
        return incomplete(error instanceof ProviderRefusal ? error.code : 'aura-citation:reader-unavailable')
      }
    },
  })
  return Object.freeze({ service,
    dispose() {
      if (disposed) return
      disposed = true
      try { consumeNativeRejection(Reflect.apply(release, reader, [])) } catch { refuse('dispose-unavailable') }
    },
  })
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
const RELEASE_SHA = /^[0-9a-f]{40}$/u
const PROPOSAL_SCOPE_FIELDS = ['owner_subject', 'proposal_id', 'source', 'receipt_sha256',
  'context_sha256', 'release_sha', 'genesis_instance_id']
const GRANT_FIELDS = [...PROPOSAL_SCOPE_FIELDS, 'version', 'kind', 'issued_at_ms',
  'expires_at_ms', 'grants_authority', 'custody']
const LIFECYCLE_FIELDS = ['version', 'kind', 'context_sha256', 'release_sha', 'genesis_instance_id']
const RETAINED_PROPOSAL_SCOPES = new WeakSet()
const MAX_READ_GRANT_TTL_MS = 300000
const hex64 = value => typeof value === 'string' && HEX64.test(value)
const uuid = value => typeof value === 'string' && UUID.test(value)

function proposalBound(value) {
  const bound = fields(value, PROPOSAL_SCOPE_FIELDS)
  const source = bound && fields(bound.source, [...SOURCE_KEYS, 'key_sha256'])
  if (!bound || !source || typeof bound.owner_subject !== 'string' || !SUBJECT.test(bound.owner_subject)
    || !uuid(bound.proposal_id) || !uuid(bound.genesis_instance_id)
    || typeof bound.release_sha !== 'string' || !RELEASE_SHA.test(bound.release_sha)
    || !hex64(bound.receipt_sha256) || !hex64(bound.context_sha256)
    || typeof source.journal_id !== 'string' || !JOURNAL.test(source.journal_id)
    || !Number.isSafeInteger(source.position) || source.position < 1
    || !hex64(source.hash) || !hex64(source.key_sha256)) refuse('read-scope-invalid')
  return Object.freeze({ ...bound, source: Object.freeze({ ...source }) })
}
function boundValues(bound) {
  return [bound.owner_subject, bound.proposal_id, bound.source.journal_id, bound.source.position,
    bound.source.hash, bound.source.key_sha256, bound.receipt_sha256, bound.context_sha256,
    bound.release_sha, bound.genesis_instance_id]
}
function primitiveFingerprint(values) {
  // Only validated scalars reach this encoder; no JSON hooks, getters or object coercion.
  return values.map(value => typeof value === 'string' ? `s${value.length}:${value}`
    : typeof value === 'number' ? `n${value};` : value === false ? 'b0;' : 'b1;').join('')
}
function grantSnapshot(value) {
  const grant = fields(value, GRANT_FIELDS)
  if (!grant || grant.version !== 1 || grant.kind !== 'aukora-aura-proposal-read-grant/v1'
    || grant.grants_authority !== false || grant.custody !== 'INTERIM'
    || !Number.isSafeInteger(grant.issued_at_ms) || grant.issued_at_ms < 0
    || !Number.isSafeInteger(grant.expires_at_ms)) refuse('read-grant-invalid')
  const ttl = grant.expires_at_ms - grant.issued_at_ms
  if (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > MAX_READ_GRANT_TTL_MS) refuse('read-grant-invalid')
  const bound = proposalBound(Object.fromEntries(PROPOSAL_SCOPE_FIELDS.map(key => [key, grant[key]])))
  return Object.freeze({ ...bound, version: grant.version, kind: grant.kind,
    issued_at_ms: grant.issued_at_ms, expires_at_ms: grant.expires_at_ms,
    grants_authority: false, custody: 'INTERIM' })
}
function sameSource(source, bound) {
  return source.journal_id === bound.journal_id && source.position === bound.position && source.hash === bound.hash
}

/**
 * Retain a root-supplied read grant, never issue one. The host owns the completed
 * proposal projection, protected reads and lifecycle. INTERIM custody is not an
 * owner enrollment or an effect approval. Internal cold verification still reads
 * the complete owner prefix; this scope limits citation output to one source row.
 */
export function createRetainedProposalReadScope(expected, options) {
  let bound, input
  try {
    bound = proposalBound(expected)
    input = fields(options, ['readGrant', 'readLifecycle', 'isLive'], ['now'])
  } catch { refuse('read-scope-unconfigured') }
  const suppliedNow = input && Object.hasOwn(input, 'now') ? input.now : undefined
  if (!input || typeof input.readGrant !== 'function' || typeof input.readLifecycle !== 'function'
    || typeof input.isLive !== 'function' || (suppliedNow !== undefined && typeof suppliedNow !== 'function'))
    refuse('read-scope-unconfigured')
  const readGrant = input.readGrant, readLifecycle = input.readLifecycle, isLive = input.isLive
  const now = suppliedNow === undefined ? Date.now : suppliedNow
  const expectedFingerprint = primitiveFingerprint(boundValues(bound))
  let revoked = null, checking = false, retainedFingerprint, lastNow
  const fail = reason => {
    revoked ??= reason
    refuse(revoked)
  }
  const assertOpen = () => { if (revoked !== null) refuse(revoked) }
  const invoke = (callback, reason) => {
    let value
    try { value = Reflect.apply(callback, undefined, []) } catch { fail(reason) }
    consumeNativeRejection(value)
    assertOpen() // A callback can synchronously dispose/revoke this retained scope.
    return value
  }
  const check = () => {
    assertOpen()
    if (checking) fail('read-scope-reentrant')
    checking = true
    try {
      if (invoke(isLive, 'read-guard-unavailable') !== true) fail('owner-inactive')
      let grant, lifecycle
      try { grant = grantSnapshot(invoke(readGrant, 'read-grant-unavailable')) }
      catch { fail('read-grant-invalid') }
      assertOpen()
      if (primitiveFingerprint(boundValues(grant)) !== expectedFingerprint) fail('read-grant-mismatch')
      const fingerprint = primitiveFingerprint([...boundValues(grant), grant.version, grant.kind,
        grant.issued_at_ms, grant.expires_at_ms, grant.grants_authority, grant.custody])
      if (retainedFingerprint !== undefined && fingerprint !== retainedFingerprint) fail('read-grant-changed')
      try { lifecycle = fields(invoke(readLifecycle, 'read-lifecycle-unavailable'), LIFECYCLE_FIELDS) }
      catch { fail('read-lifecycle-unavailable') }
      assertOpen()
      if (!lifecycle || lifecycle.version !== 1 || lifecycle.kind !== 'aukora-aura-read-lifecycle/v1'
        || lifecycle.context_sha256 !== bound.context_sha256 || lifecycle.release_sha !== bound.release_sha
        || lifecycle.genesis_instance_id !== bound.genesis_instance_id) fail('read-lifecycle-mismatch')
      const time = invoke(now, 'read-clock-unavailable')
      if (!Number.isSafeInteger(time) || time < 0) fail('read-clock-unavailable')
      if (lastNow !== undefined && time < lastNow) fail('read-clock-rollback')
      if (time < grant.issued_at_ms) fail('read-grant-not-yet-valid')
      if (time >= grant.expires_at_ms) fail('read-grant-expired')
      if (invoke(isLive, 'read-guard-unavailable') !== true) fail('owner-inactive')
      assertOpen()
      retainedFingerprint ??= fingerprint
      lastNow = time
      return true
    } finally { checking = false }
  }
  const scope = Object.freeze({ bound, custody: 'INTERIM', grants_authority: false,
    checkOwner(owner) {
      if (typeof owner !== 'string' || owner !== bound.owner_subject) refuse('owner-mismatch')
      return check()
    },
    checkSelector(selector) {
      const selected = detachedSelector(selector)
      if (!sameSource(selected.source, bound.source)) refuse('source-outside-read-scope')
      check()
      return selected
    },
    dispose() { revoked ??= 'read-scope-disposed' },
  })
  check() // Missing or invalid initial data cannot be replaced to resurrect this scope.
  RETAINED_PROPOSAL_SCOPES.add(scope)
  return scope
}

export const isRetainedProposalReadScope = scope => RETAINED_PROPOSAL_SCOPES.has(scope)

const COLD_ANCHOR_SCOPE = 'provided-data-consistency-only; retrieval, provenance and witness independence unperformed'
const COLD_FIELDS = ['ok', 'status', 'source', 'aura_head', 'coverage', 'grants_authority',
  'selected_head', 'anchor_scope', 'anchor_status', 'anchors_checked']
const COLD_REASONS = new Set([
  ...['source-shape', 'source-head-shape', 'gate-public-key-invalid', 'verification-failed',
    'json-duplicate-key', 'json-depth', 'json-size', 'json-unicode', 'json-number', 'json-invalid',
    'record-metadata-shape', 'aura-sequence-gap', 'aura-chain-mismatch', 'source-reference-mismatch',
    'action-reference-shape', 'gate-key-pin-mismatch', 'codec-required', 'events-shape', 'verified-prefix-invalid',
    'event-shape', 'nostr-verification-failed', 'observation-payload-shape', 'entry-shape', 'gate-record-invalid',
    'gate-chain-mismatch', 'entry-body-mismatch', 'action-reference-mismatch', 'source-snapshot-shape',
    'source-identity-mismatch', 'source-sequence-gap', 'source-record-shape', 'source-record-mismatch',
    'selected-head-mismatch', 'anchors-shape', 'anchor-shape', 'anchor-sequence-gap', 'anchor-beyond-selected-head',
    'anchor-key-mismatch', 'anchor-source-mismatch', 'source-snapshot-incomplete', 'source-truncated',
    'source-prefix-altered', 'coverage-incomplete', 'anchor-unperformed', 'store-path-invalid',
    'store-read-unavailable'].map(reason => `aura-collected:${reason}`),
  ...['source-id-invalid', 'source-path-invalid', 'public-key-invalid', 'key-pin-required', 'bounds-invalid',
    'key-pin-mismatch', 'selected-head-invalid', 'row-count-invalid', 'row-bound-exceeded', 'record-bound-exceeded',
    'record-shape', 'record-types', 'record-hash-shape', 'signature-shape', 'hash-mismatch', 'signature-invalid',
    'record-verification-failed', 'sequence-gap', 'chain-mismatch', 'byte-bound-exceeded', 'selected-head-mismatch',
    'snapshot-unavailable'].map(reason => `gate-source:${reason}`),
])
const CITATION_FAILURE_REASONS = new Set(['owner-mismatch', 'owner-inactive', 'read-grant-unavailable',
  'read-guard-unavailable', 'selector-invalid', 'scope-invalid', 'verification-incomplete',
  'verification-unavailable', 'source-not-found', 'record-id-mismatch', 'reader-unavailable',
  'read-scope-invalid', 'read-scope-unconfigured', 'read-scope-reentrant', 'read-scope-disposed',
  'read-grant-invalid', 'read-grant-mismatch', 'read-grant-changed', 'read-lifecycle-unavailable',
  'read-lifecycle-mismatch', 'read-clock-unavailable', 'read-clock-rollback', 'read-grant-not-yet-valid',
  'read-grant-expired'].map(reason => `aura-citation:${reason}`))

function publicHead(value) {
  const head = fields(value, ['position', 'hash'])
  if (!head || !Number.isSafeInteger(head.position) || Object.is(head.position, -0) || head.position < 0
    || (head.position === 0 ? head.hash !== 'GENESIS' : !hex64(head.hash))) refuse('reader-result-invalid')
  return Object.freeze({ ...head })
}
function publicColdSummary(value, bound) {
  const summary = fields(value, COLD_FIELDS, ['reason', 'anchored_head'])
  if (!summary || (summary.ok !== true && summary.ok !== false) || summary.grants_authority !== false
    || summary.anchor_scope !== COLD_ANCHOR_SCOPE) refuse('reader-result-invalid')
  let source = null
  if (summary.source !== null) {
    const selected = fields(summary.source, ['journal_id', 'key_sha256'])
    if (!selected || selected.journal_id !== bound.source.journal_id
      || selected.key_sha256 !== bound.source.key_sha256) refuse('reader-result-invalid')
    source = Object.freeze({ ...selected })
  }
  const aura = fields(summary.aura_head, ['sequence', 'id'])
  if (!aura || !Number.isSafeInteger(aura.sequence) || Object.is(aura.sequence, -0) || aura.sequence < 0 || aura.sequence > 50000
    || !hex64(aura.id) || (aura.sequence === 0 && aura.id !== '0'.repeat(64))) refuse('reader-result-invalid')
  const aura_head = Object.freeze({ ...aura }), coverage = publicHead(summary.coverage)
  const selected_head = summary.selected_head === null ? null : publicHead(summary.selected_head)
  if (coverage.position !== aura.sequence) refuse('reader-result-invalid')
  const copied = { ok: summary.ok, status: summary.status, source, aura_head, coverage,
    grants_authority: false, selected_head, anchor_scope: COLD_ANCHOR_SCOPE,
    anchor_status: summary.anchor_status, anchors_checked: summary.anchors_checked }
  if (summary.ok === true) {
    if (summary.status !== 'complete' || source === null || selected_head === null
      || Object.hasOwn(summary, 'reason') || !Object.hasOwn(summary, 'anchored_head')
      || summary.anchor_status !== 'verified' || !Number.isSafeInteger(summary.anchors_checked)
      || summary.anchors_checked < 1 || summary.anchors_checked > 50000
      || selected_head.position !== coverage.position || selected_head.hash !== coverage.hash)
      refuse('reader-result-invalid')
    const anchored_head = publicHead(summary.anchored_head)
    if (anchored_head.position < 1 || anchored_head.position > selected_head.position
      || summary.anchors_checked > anchored_head.position) refuse('reader-result-invalid')
    return Object.freeze({ ...copied, anchored_head })
  }
  if (summary.status !== 'incomplete' || !Object.hasOwn(summary, 'reason')
    || typeof summary.reason !== 'string' || !COLD_REASONS.has(summary.reason)
    || Object.hasOwn(summary, 'anchored_head') || summary.anchor_status !== 'unperformed'
    || summary.anchors_checked !== 0 || Object.is(summary.anchors_checked, -0)) refuse('reader-result-invalid')
  return Object.freeze({ ...copied, reason: summary.reason })
}

function successfulScopedCitation(result, selected, bound) {
  const envelope = fields(result, ['ok', 'status', 'reason', 'grants_authority', 'citation', 'verification'])
  if (!envelope || envelope.ok !== true || envelope.status !== 'verified' || envelope.reason !== null
    || envelope.grants_authority !== false) refuse('reader-result-invalid')
  const verification = publicColdSummary(envelope.verification, bound)
  if (verification.ok !== true || verification.coverage.position < selected.source.position) refuse('reader-result-invalid')
  const citation = fields(envelope.citation, ['record_id', 'source', 'key_sha256', 'owner_subject',
    'owner_pubkey_hex', 'binding_digest', 'grants_authority'])
  const source = citation && fields(citation.source, SOURCE_KEYS)
  if (!citation || !source || !hex64(citation.record_id) || !hex64(citation.owner_pubkey_hex)
    || !hex64(citation.binding_digest) || citation.grants_authority !== false
    || citation.owner_subject !== bound.owner_subject || citation.key_sha256 !== bound.source.key_sha256
    || !sameSource(source, bound.source) || !sameSource(source, selected.source)
    || (Object.hasOwn(selected, 'record_id') && citation.record_id !== selected.record_id))
    refuse('citation-outside-read-scope')
  // Actual D already freezes these fields. Detach host adapter results as well;
  // preserve only the same closed evidence fields and D's public cold summary.
  return Object.freeze({ ...envelope, verification,
    citation: Object.freeze({ ...citation, source: Object.freeze({ ...source }) }) })
}

/** Publish this service only; keep the underlying reader and retained scope with the host. */
export function createProposalScopedAuraRecordsProvider(options) {
  let input
  try { input = fields(options, ['ownerSubject', 'reader', 'scope', 'referenceForRecord']) }
  catch { refuse('provider-unconfigured') }
  if (!input || !isRetainedProposalReadScope(input.scope)) refuse('read-scope-unconfigured')
  const scope = input.scope, ownerSubject = input.ownerSubject
  scope.checkOwner(ownerSubject)
  const base = createAuraRecordsProvider({ ownerSubject, reader: input.reader,
    isLive: () => scope.checkOwner(ownerSubject), hasReadGrant: owner => scope.checkOwner(owner),
    referenceForRecord: input.referenceForRecord })
  const safeReason = error => error instanceof ProviderRefusal ? error.code : 'aura-citation:reader-unavailable'
  const service = Object.freeze({
    async referenceForRecord(memoryRecordId) {
      try {
        scope.checkOwner(ownerSubject)
        const selected = await base.service.referenceForRecord(memoryRecordId)
        scope.checkOwner(ownerSubject)
        if (selected === null || !sameSource(selected.source, scope.bound.source)) return null
        const detached = scope.checkSelector(selected)
        scope.checkOwner(ownerSubject)
        return detached
      } catch (error) {
        scope.checkOwner(ownerSubject)
        if (error instanceof ProviderRefusal) throw error
        refuse('association-unavailable')
      }
    },
    async readCitation(selector) {
      try {
        scope.checkOwner(ownerSubject)
        const selected = scope.checkSelector(selector)
        const result = await base.service.readCitation(selected)
        scope.checkOwner(ownerSubject)
        scope.checkSelector(selected)
        const envelope = fields(result, ['ok', 'status', 'reason', 'grants_authority', 'citation', 'verification'])
        if (!envelope || envelope.grants_authority !== false) refuse('reader-result-invalid')
        let detached
        if (envelope.ok === true) detached = successfulScopedCitation(result, selected, scope.bound)
        else {
          if (envelope.ok !== false || envelope.status !== 'incomplete' || envelope.citation !== null
            || typeof envelope.reason !== 'string'
            || (!COLD_REASONS.has(envelope.reason) && !CITATION_FAILURE_REASONS.has(envelope.reason)))
            refuse('reader-result-invalid')
          const verification = envelope.verification === null ? null : publicColdSummary(envelope.verification, scope.bound)
          detached = Object.freeze({ ...envelope, citation: null, verification })
        }
        scope.checkOwner(ownerSubject)
        return detached
      } catch (error) {
        try { scope.checkOwner(ownerSubject) } catch (scopeError) { return incomplete(safeReason(scopeError)) }
        return incomplete(safeReason(error))
      }
    },
  })
  return Object.freeze({ service, custody: 'INTERIM', grants_authority: false,
    dispose() { scope.dispose(); base.dispose() },
  })
}
