// SPDX-License-Identifier: AGPL-3.0-or-later
import { validateCaptureLiterals } from './capture-review.mjs'

// New pilot captures only. Import codecs retain historical metadata and exact original bytes.
// Omitted links and explicit [] are both permitted fixed empty values; their request hashes remain distinct.
export const PILOT_CAPTURE_POLICY = Object.freeze({
  version: 1,
  category: 'fact', confidence: 0.7, sensitivity: 'none', privacy: 'local', scope: 'owner',
  links: Object.freeze([]), origin: Object.freeze({ by: 'prime.capture/v1' }), bodyAtCapture: null,
  observedAt: 'exact source.at', validFrom: 'source.at calendar date',
  evidence: 'derived from the exact selected source event',
  grantsAuthority: false,
})

const fail = () => { throw Object.assign(new TypeError('memory:pilot-capture-profile-refused'),
  { code: 'memory:pilot-capture-profile-refused' }) }
const plain = value => value && [Object.prototype, null].includes(Object.getPrototypeOf(value))
function closed(value, required, optional = []) {
  if (!plain(value)) fail()
  const fields = Reflect.ownKeys(value)
  if (required.some(key => !fields.includes(key)) || fields.some(key => typeof key !== 'string'
    || !required.includes(key) && !optional.includes(key))) fail()
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail()
  }
}
function valueAt(host, key) {
  const descriptor = Object.getOwnPropertyDescriptor(host, key)
  if (!descriptor) return { present: false }
  if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail()
  return { present: true, value: descriptor.value }
}
function defaultField(host, key, expected) {
  const field = valueAt(host, key)
  if (field.present && field.value !== expected) fail()
}
function canonicalInstant(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().replace('.000Z', 'Z') === value
}

/**
 * Validate fixed, documented metadata before a NEW pilot capture is hashed or authorized.
 * Authentication/runtime host fields are checked by the host and authority layer; this function closes
 * the metadata used to construct the note. It never supplies defaults, rewrites strings, or validates imports.
 * Returns the identical input object, preserving both exact strings and optional-field presence.
 */
export function validatePilotCaptureMetadata(host, input) {
  if (!plain(host)) fail()
  closed(input, ['category', 'statement', 'validFrom', 'observedAt', 'confidence', 'sensitivity'], ['links'])
  if (input.category !== PILOT_CAPTURE_POLICY.category || input.confidence !== PILOT_CAPTURE_POLICY.confidence
    || input.sensitivity !== PILOT_CAPTURE_POLICY.sensitivity) fail()
  if (Object.hasOwn(input, 'links')) {
    if (!Array.isArray(input.links) || Reflect.ownKeys(input.links).length !== 1 || input.links.length !== 0) fail()
  }
  const sourceField = valueAt(host, 'source'), attribution = valueAt(host, 'attributedTo')
  const privacy = valueAt(host, 'privacy')
  if (!sourceField.present || !attribution.present || privacy.value !== 'local') fail()
  const source = sourceField.value
  closed(source, ['sessionId', 'seq', 'at', 'sha256'])
  if (typeof source.sessionId !== 'string' || !source.sessionId || source.sessionId.length > 256
    || !Number.isSafeInteger(source.seq) || source.seq < 0 || !canonicalInstant(source.at)
    || typeof source.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(source.sha256)) fail()
  if (input.observedAt !== source.at || input.validFrom !== source.at.slice(0, 10)) fail()
  defaultField(host, 'scope', 'owner')
  defaultField(host, 'bodyAtCapture', null)
  defaultField(host, 'evidence', null)
  const origin = valueAt(host, 'origin')
  if (origin.present) {
    closed(origin.value, ['by'])
    if (origin.value.by !== 'prime.capture/v1') fail()
  }
  // Attribution is shown and bound by the existing exact statement review helper.
  try { validateCaptureLiterals({ statement: input.statement, attributed_to: attribution.value }) }
  catch { fail() }
  return input
}
