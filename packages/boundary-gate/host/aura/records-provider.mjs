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
