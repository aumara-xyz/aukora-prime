// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe presentation consistency checks. These do not verify C authority,
// execute a mutation, or establish physical erasure of retained memory payloads.
import { validateForgetReview } from './forget-review.mjs'

const DIGEST = /^sha256:[a-f0-9]{64}$/, HEX = /^[a-f0-9]{64}$/
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
const FIELDS = ['phase','operation','record_summary','operation_digest','approval','forget','forgotten',
  'result','receipt','receipt_digest','authority_settlement','reconciliation_required','error_code',
  'recovery_status','recovery_operation_id','recovery_operation_digest']
const SUMMARY = ['record_id','revision','statement','attributed_to']
const REVIEW = [...SUMMARY,'canonical_sha256']
const RESULT = ['record_id','state','canonical_payload_retained','physical_media_erasure',
  'authority_approval_history_erased','backups_erased','wal_erased','grants_authority']
const RECEIPT = ['version','kind','operation_id','operation_digest','grant_id','request_id',
  'request_digest','owner_subject','action_type','status','result_digest','result']
const ERRORS = ['UNAVAILABLE','INVALID','UNAUTHORIZED','STALE','REVOKED','REPLAYED','EXPIRED',
  'TARGET_MISMATCH','SCOPE_MISMATCH','CANCELLED','OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED']
const fault = (code, reason) => { throw Object.assign(new TypeError(reason), { code, error_code: code }) }
const requireValue = (condition, reason = 'ui:invalid-forget-workflow-snapshot', code = 'INVALID') => {
  if (!condition) fault(code, reason)
}
function closed(value, fields) {
  requireValue(value && [Object.prototype,null].includes(Object.getPrototypeOf(value)))
  const keys = Reflect.ownKeys(value)
  requireValue(keys.length === fields.length && keys.every(key => typeof key === 'string' && fields.includes(key)))
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    requireValue(descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value'))
  }
  return value
}
function immutable(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) immutable(child)
    Object.freeze(value)
  }
  return value
}
function copied(value, contracts) {
  requireValue(typeof contracts?.canonicalJson === 'function' && typeof contracts?.parseStrictJson === 'function',
    'ui:forget-contract-helper-unavailable', 'UNAVAILABLE')
  try { return contracts.parseStrictJson(contracts.canonicalJson(value), { maxBytes: 65536, maxDepth: 32 }) }
  catch { fault('INVALID', 'ui:invalid-forget-workflow-json') }
}
const text = (value, max) => typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= max
const digestValue = value => typeof value === 'string' && DIGEST.test(value)
function logicalResult(value) {
  closed(value, RESULT)
  requireValue(text(value.record_id, 1024) && value.state === 'tombstoned' && value.canonical_payload_retained === true &&
    value.physical_media_erasure === false && value.authority_approval_history_erased === false &&
    value.backups_erased === false && value.wal_erased === false && value.grants_authority === false)
}
function receiptShape(value) {
  closed(value, RECEIPT)
  requireValue(value.version === 1 && value.kind === 'prime-memory-effect/v1' && text(value.operation_id, 1024) &&
    digestValue(value.operation_digest) && typeof value.grant_id === 'string' && /^grant:[a-f0-9]{64}$/.test(value.grant_id) &&
    typeof value.request_id === 'string' && UUID.test(value.request_id) && digestValue(value.request_digest) &&
    typeof value.owner_subject === 'string' && /^aukora:1:[a-f0-9]{64}$/.test(value.owner_subject) &&
    value.action_type === 'memory.forget' && value.status === 'applied' && digestValue(value.result_digest))
  logicalResult(value.result)
}

/** Detached exact current 16-field bridge snapshot; no cryptographic authority claim. */
export function validateForgetWorkflowSnapshot(value, contracts) {
  closed(value, FIELDS)
  const result = copied(value, contracts)
  requireValue(['idle','proposal_pending','proposed','approval_pending','forget_pending','forgotten','refused','outcome_unknown','unavailable'].includes(result.phase) &&
    ['not_requested','pending','approved','refused','unknown'].includes(result.approval) &&
    ['not_attempted','pending','forgotten','refused','unknown'].includes(result.forget) &&
    [true,false,null].includes(result.forgotten) && typeof result.reconciliation_required === 'boolean' &&
    [null,'completed','pending'].includes(result.authority_settlement) &&
    (result.error_code === null || ERRORS.includes(result.error_code)) &&
    ['not_requested','pending','idle','known_unsent','saved','forgotten','unknown','refused'].includes(result.recovery_status))
  requireValue(result.operation_digest === null || digestValue(result.operation_digest))
  requireValue(result.receipt_digest === null || digestValue(result.receipt_digest))
  requireValue(result.recovery_operation_id === null || text(result.recovery_operation_id, 1024))
  requireValue(result.recovery_operation_digest === null || digestValue(result.recovery_operation_digest))
  requireValue((result.recovery_operation_id === null) === (result.recovery_operation_digest === null))
  requireValue(!['not_requested','idle'].includes(result.recovery_status) || result.recovery_operation_id === null)
  requireValue(!['known_unsent','saved','forgotten','unknown'].includes(result.recovery_status) || result.recovery_operation_id !== null)
  requireValue((result.operation === null) === (result.record_summary === null) &&
    (result.operation === null) === (result.operation_digest === null))
  if (result.operation !== null) {
    requireValue(typeof contracts?.validateContract === 'function', 'ui:forget-contract-helper-unavailable', 'UNAVAILABLE')
    try { contracts.validateContract('OperationProposal', result.operation); validateForgetReview(result.operation, result.record_summary) }
    catch { fault('INVALID', 'ui:invalid-forget-workflow-operation') }
  }
  requireValue((result.result === null) === (result.receipt === null))
  if (result.result !== null) logicalResult(result.result)
  if (result.receipt !== null) receiptShape(result.receipt)
  requireValue(result.receipt_digest === null || result.receipt !== null)
  return immutable(result)
}

function reviewed(presentation, contracts) {
  requireValue(presentation && [Object.prototype,null].includes(Object.getPrototypeOf(presentation)),
    'ui:forget-review-required', 'TARGET_MISMATCH')
  const selected = {}
  for (const name of ['operation','canonical_operation','operation_digest','forget_review']) {
    const descriptor = Object.getOwnPropertyDescriptor(presentation, name)
    requireValue(descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value'), 'ui:forget-review-required', 'TARGET_MISMATCH')
    selected[name] = descriptor.value
  }
  const view = copied(selected, contracts)
  closed(view.forget_review, REVIEW)
  const summary = Object.fromEntries(SUMMARY.map(name => [name, view.forget_review[name]]))
  try {
    contracts.validateContract('OperationProposal', view.operation)
    validateForgetReview(view.operation, summary)
  } catch { fault('TARGET_MISMATCH', 'ui:forget-review-mismatch') }
  requireValue(view.canonical_operation === contracts.canonicalJson(view.operation) && digestValue(view.operation_digest) &&
    view.forget_review.canonical_sha256 === view.operation.canonical_parameters.canonical_sha256,
    'ui:forget-review-mismatch', 'TARGET_MISMATCH')
  return immutable({ ...view, summary })
}
async function digest(domain, value, contracts) {
  requireValue(typeof globalThis.crypto?.subtle?.digest === 'function', 'ui:forget-digest-unavailable', 'UNAVAILABLE')
  let result
  try { result = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(domain + '\0' + contracts.canonicalJson(value))) }
  catch { fault('UNAVAILABLE', 'ui:forget-digest-unavailable') }
  return 'sha256:' + Array.from(new Uint8Array(result), byte => byte.toString(16).padStart(2, '0')).join('')
}

/** The caller must fence its captured owner/revision again after this async check. */
export async function validateForgetWorkflowResult(value, { presentation, approved, proofNonce, contracts } = {}) {
  const result = validateForgetWorkflowSnapshot(value, contracts), view = reviewed(presentation, contracts)
  requireValue(typeof contracts.operationDigest === 'function', 'ui:forget-contract-helper-unavailable', 'UNAVAILABLE')
  let originalDigest
  try { originalDigest = await contracts.operationDigest(view.operation) }
  catch { fault('TARGET_MISMATCH', 'ui:forget-operation-digest-mismatch') }
  requireValue(originalDigest === view.operation_digest, 'ui:forget-operation-digest-mismatch', 'TARGET_MISMATCH')
  if (result.operation !== null) {
    requireValue(contracts.canonicalJson(result.operation) === view.canonical_operation && result.operation_digest === view.operation_digest &&
      contracts.canonicalJson(result.record_summary) === contracts.canonicalJson(view.summary), 'ui:forget-operation-changed', 'TARGET_MISMATCH')
  }
  if (['proposal_pending','approval_pending','forget_pending'].includes(result.phase) || result.approval === 'pending' ||
      result.forget === 'pending' || result.recovery_status === 'pending') {
    fault('OUTCOME_UNKNOWN', 'ui:forget-action-still-pending')
  }
  const claimsEffect = result.forgotten === true || result.forget === 'forgotten' || result.phase === 'forgotten' || result.result !== null
  if (!claimsEffect) {
    requireValue(result.authority_settlement === null && result.receipt_digest === null && result.forgotten !== true,
      'ui:forget-result-contradictory', 'OUTCOME_UNKNOWN')
    const uncertain = [result.approval, result.forget].includes('unknown') || result.phase === 'outcome_unknown' ||
      result.approval === 'approved' || result.forgotten === null || ['OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED'].includes(result.error_code)
    requireValue(!uncertain || result.reconciliation_required,
      'ui:forget-result-contradictory', 'OUTCOME_UNKNOWN')
    return result
  }
  requireValue(approved === true && typeof proofNonce === 'string' && HEX.test(proofNonce) &&
    result.phase === 'forgotten' && result.approval === 'approved' && result.forget === 'forgotten' && result.forgotten === true &&
    result.result !== null && result.receipt !== null, 'ui:forget-result-not-bound-to-approval', 'TARGET_MISMATCH')
  if (result.operation === null) {
    requireValue(result.recovery_status === 'forgotten' && result.recovery_operation_id === view.operation.operation_id &&
      result.recovery_operation_digest === view.operation_digest, 'ui:forget-recovery-not-bound-to-review', 'TARGET_MISMATCH')
  }
  const receipt = result.receipt, operation = view.operation
  requireValue(result.result.record_id === view.forget_review.record_id && receipt.operation_id === operation.operation_id &&
    receipt.operation_digest === view.operation_digest && receipt.grant_id === 'grant:' + proofNonce &&
    receipt.owner_subject === operation.target_identity.owner_subject &&
    contracts.canonicalJson(receipt.result) === contracts.canonicalJson(result.result), 'ui:forget-receipt-mismatch', 'TARGET_MISMATCH')
  requireValue((result.authority_settlement === 'completed' && result.reconciliation_required === false && digestValue(result.receipt_digest)) ||
    (result.authority_settlement === 'pending' && result.reconciliation_required === true),
    'ui:forget-settlement-mismatch', 'OUTCOME_UNKNOWN')
  requireValue(result.authority_settlement !== 'completed' || !['OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED'].includes(result.error_code),
    'ui:forget-result-uncertain', 'OUTCOME_UNKNOWN')
  requireValue(receipt.result_digest === await digest('aukora-prime.memory-result.v1', result.result, contracts),
    'ui:forget-result-digest-mismatch', 'TARGET_MISMATCH')
  const request = { version: 1, action_type: 'memory.forget', owner_subject: operation.target_identity.owner_subject,
    operation_id: operation.operation_id, operation_digest: view.operation_digest, parameters: operation.canonical_parameters }
  requireValue(receipt.request_digest === await digest('aukora-prime.memory.effect.v1', request, contracts),
    'ui:forget-request-digest-mismatch', 'TARGET_MISMATCH')
  if (result.receipt_digest !== null) requireValue(result.receipt_digest === await digest('aukora-prime.memory-receipt.v1', receipt, contracts),
    'ui:forget-receipt-digest-mismatch', 'TARGET_MISMATCH')
  return result
}

/** Content-free terminal facts only; this never presents a recovered receipt. */
export function validateCancelledForgetWorkflow(value, contracts) {
  let result
  try { result = validateForgetWorkflowSnapshot(value, contracts) }
  catch { fault('OUTCOME_UNKNOWN', 'ui:invalid-cancelled-forget-result') }
  const cleared = ['idle','unavailable'].includes(result.phase) &&
    ['operation','record_summary','operation_digest','result','receipt','receipt_digest','recovery_operation_id','recovery_operation_digest']
      .every(name => result[name] === null) && result.recovery_status === 'not_requested' &&
    [null,'UNAVAILABLE'].includes(result.error_code) && result.reconciliation_required === false
  const unsent = result.approval === 'not_requested' && result.forget === 'not_attempted' &&
    result.forgotten === false && result.authority_settlement === null
  const completed = result.approval === 'approved' && result.forget === 'forgotten' &&
    result.forgotten === true && result.authority_settlement === 'completed'
  requireValue(cleared && (unsent || completed), 'ui:cancelled-forget-needs-reconciliation', 'OUTCOME_UNKNOWN')
  return result
}
