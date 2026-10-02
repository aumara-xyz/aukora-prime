// SPDX-License-Identifier: AGPL-3.0-or-later
// Exact display comparison only. D verifies original bytes, chain heads and
// current owner scope under its lock; this helper creates no such proof.
export const FORGET_PROFILE = 'prime-logical-forget/v1'
export const FORGET_STATEMENT_MAX_BYTES = 16384
export const FORGET_REFERENCE_MAX_BYTES = 1024
export const FORGET_SUMMARY_FIELDS = Object.freeze(['record_id','revision','statement','attributed_to'])
export const FORGET_PARAMETER_FIELDS = Object.freeze(['profile','record_id','revision','canonical_sha256','at','heads','statement','attributed_to'])
const OPERATION_FIELDS = Object.freeze(['version','operation_id','task_id','owner_id','agent_id','audience','action_type',
  'target_identity','canonical_parameters','data_scope','expected_state_version','provider_and_region','maximum_cost',
  'expiry','nonce','policy_version','authorization_epoch'])
const HEX64 = /^[a-f0-9]{64}$/
const DOMAINS = Object.freeze(['remembered','approved','legacy-presplit'])
const encoder = new TextEncoder()
const fail = () => { throw new TypeError('ui:forget-review-invalid') }

function scalar(value) {
  if (typeof value !== 'string') fail()
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index)
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail()
    } else if (unit >= 0xdc00 && unit <= 0xdfff) fail()
  }
}
function text(value, maxBytes) {
  scalar(value)
  if (!value.length || encoder.encode(value).length > maxBytes) fail()
}
function dataObject(value, fields) {
  if (!value || ![Object.prototype,null].includes(Object.getPrototypeOf(value))) fail()
  const keys = Reflect.ownKeys(value)
  if (fields && (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key)))) fail()
  const detached = Object.create(null)
  for (const key of keys) {
    if (typeof key !== 'string') fail()
    scalar(key)
    const descriptor = Object.getOwnPropertyDescriptor(value,key)
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor,'value')) fail()
    detached[key] = descriptor.value
  }
  return detached
}
// Reading descriptors rather than properties prevents an accessor from running
// even in envelope fields displayed elsewhere by the full contract presenter.
function dataOnly(value, ancestors = new Set(), depth = 0) {
  if (depth > 64) fail()
  if (value === null || typeof value === 'boolean') return
  if (typeof value === 'string') { scalar(value); return }
  if (typeof value === 'number') { if (!Number.isSafeInteger(value) || Object.is(value,-0)) fail(); return }
  if (typeof value !== 'object' || ancestors.has(value)) fail()
  ancestors.add(value)
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) fail()
    const length = Object.getOwnPropertyDescriptor(value,'length')
    if (!length || !Object.hasOwn(length,'value') || !Number.isSafeInteger(length.value) || length.value < 0) fail()
    const keys = Reflect.ownKeys(value)
    if (keys.length !== length.value + 1 || keys.some(key => typeof key !== 'string' ||
        (key !== 'length' && !/^(?:0|[1-9][0-9]*)$/.test(key)))) fail()
    for (let index = 0; index < length.value; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value,String(index))
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor,'value')) fail()
      dataOnly(descriptor.value,ancestors,depth + 1)
    }
  } else {
    for (const child of Object.values(dataObject(value))) dataOnly(child,ancestors,depth + 1)
  }
  ancestors.delete(value)
}

/** Match an independent retained record summary to the signed forget proposal.
 * Hash/head syntax is checked; their values are not independently audited here.
 * Legacy text, attribution, whitespace and Unicode remain literal and unchanged. */
export function validateForgetReview(operation, independentlyRetainedRecordSummary) {
  const op = dataObject(operation,OPERATION_FIELDS)
  dataOnly(operation)
  if (op.version !== 1 || op.action_type !== 'memory.forget' || op.audience !== 'aukora-prime.memory') fail()
  const target = dataObject(op.target_identity,['kind','owner_subject'])
  if (target.kind !== 'prime-memory' || typeof target.owner_subject !== 'string' ||
      !/^aukora:1:[a-f0-9]{64}$/.test(target.owner_subject) || typeof op.expected_state_version !== 'string' ||
      !/^sha256:[a-f0-9]{64}$/.test(op.expected_state_version)) fail()
  const parameters = dataObject(op.canonical_parameters,FORGET_PARAMETER_FIELDS)
  if (parameters.profile !== FORGET_PROFILE || typeof parameters.canonical_sha256 !== 'string' ||
      !HEX64.test(parameters.canonical_sha256)) fail()
  const heads = dataObject(parameters.heads)
  for (const [domain,head] of Object.entries(heads)) {
    if (!DOMAINS.includes(domain) || typeof head !== 'string' ||
        (head !== 'aukora:aura-record:v1' && !HEX64.test(head))) fail()
  }
  if (typeof parameters.at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(parameters.at)) fail()
  const at = new Date(parameters.at)
  if (!Number.isFinite(at.valueOf()) || at.toISOString().slice(0,19) + 'Z' !== parameters.at) fail()
  const summary = dataObject(independentlyRetainedRecordSummary,FORGET_SUMMARY_FIELDS)
  for (const source of [summary,parameters]) {
    text(source.record_id,FORGET_REFERENCE_MAX_BYTES)
    text(source.revision,FORGET_REFERENCE_MAX_BYTES)
    text(source.statement,FORGET_STATEMENT_MAX_BYTES)
    if (source.attributed_to !== null) text(source.attributed_to,FORGET_REFERENCE_MAX_BYTES)
  }
  if (FORGET_SUMMARY_FIELDS.some(field => parameters[field] !== summary[field])) fail()
  return Object.freeze({record_id:summary.record_id,revision:summary.revision,
    statement:summary.statement,attributed_to:summary.attributed_to})
}
