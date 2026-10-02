// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe consistency checks for a retained, already approved save.
// This presents host recovery facts; it grants no authority and sends no effect.
import { PrimeTransportError } from './transport.mjs'
import { validateCaptureReview, validateCaptureDraft } from './capture-review.mjs'

const RECEIPT = ['version','kind','operation_id','operation_digest','grant_id','request_id',
  'request_digest','owner_subject','action_type','status','result_digest','result']
const DIGEST = /^sha256:[a-f0-9]{64}$/
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
const requireValue = (condition, reason) => {
  if (!condition) throw new PrimeTransportError('TARGET_MISMATCH', reason)
}
const EVIDENCE = ['log','turn','turnDigest','quote']
const evidenceEntry = value => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...EVIDENCE].sort().join(',') &&
  typeof value.log === 'string' && value.log.length > 0 && Number.isSafeInteger(value.turn) && value.turn >= 0 &&
  typeof value.turnDigest === 'string' && /^[a-f0-9]{64}$/.test(value.turnDigest) && typeof value.quote === 'string'

/**
 * Compare a retained NEW-capture review with the exact saved donor content.
 * The legacy original byte string is only read for equality; its text is never
 * admitted as a new capture, normalized, trimmed, or reserialized here.
 * The caller validates the frozen outer MemoryRecord before calling this helper.
 */
export function validateSavedCaptureContent(record, memoryDraft) {
  let draft, original
  try {
    draft = validateCaptureDraft(memoryDraft)
    original = JSON.parse(record.canonical_bytes)
  } catch { requireValue(false, 'ui:save-recovery-record-mismatch') }
  const metadata = draft.capture_metadata
  requireValue(original && typeof original === 'object' && !Array.isArray(original) &&
    original.statement === draft.statement && original.attributedTo === draft.attributed_to &&
    original.category === metadata.category && original.validFrom === metadata.valid_from &&
    original.observedAt === metadata.observed_at && original.confidence === metadata.confidence_percent / 100 &&
    original.sensitivity === metadata.sensitivity, 'ui:save-recovery-record-mismatch')
  // D's fixed pilot derives one evidence entry from the selected source event;
  // it refuses custom host evidence. Bind both its original and outer views.
  const source = original.source
  requireValue(Array.isArray(original.evidence) && original.evidence.length === 1 &&
    Array.isArray(record.evidence) && record.evidence.length === 1 &&
    evidenceEntry(original.evidence[0]) && evidenceEntry(record.evidence[0]) &&
    source && typeof source === 'object' && !Array.isArray(source) &&
    original.evidence[0].log === source.sessionId && original.evidence[0].turn === source.seq &&
    original.evidence[0].turnDigest === source.sha256 && record.source_event_digest === 'sha256:' + source.sha256 &&
    original.evidence[0].quote === draft.evidence_quote &&
    EVIDENCE.every(key => record.evidence[0][key] === original.evidence[0][key]),
    'ui:save-recovery-evidence-mismatch')
  return record
}

async function digest(domain, value, contracts) {
  if (typeof globalThis.crypto?.subtle?.digest !== 'function') {
    throw new PrimeTransportError('UNAVAILABLE', 'ui:save-recovery-digest-unavailable')
  }
  const bytes = new TextEncoder().encode(domain + String.fromCharCode(0) + contracts.canonicalJson(value))
  const hash = await globalThis.crypto.subtle.digest('SHA-256', bytes)
  return 'sha256:' + Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('')
}

/** The controller checks its captured owner/binding again after these awaits. */
export async function validateSaveRecovery(result, { presentation:view, approved, proofNonce, contracts }) {
  const operation = view.operation, receipt = result.receipt
  requireValue(approved === true && typeof proofNonce === 'string' && /^[a-f0-9]{64}$/.test(proofNonce) &&
    operation.action_type === 'memory.save' && view.memory_review !== null &&
    result.phase === 'saved' && result.approval === 'approved' && result.save === 'saved' && result.saved === true &&
    result.authority_settlement === 'completed' && result.reconciliation_required === false && result.error_code === null &&
    result.operation_digest === view.operation_digest, 'ui:save-recovery-not-completed-or-bound')
  contracts.validateContract('OperationProposal', operation)
  const memoryDraft = validateCaptureReview(operation.canonical_parameters, view.memory_review && {
    statement:view.memory_review.statement, attributed_to:view.memory_review.attributed_to,
    capture_metadata:view.memory_review.capture_metadata, evidence_quote:view.memory_review.evidence_quote,
  })
  requireValue(view.memory_review.capture_sha256 === operation.canonical_parameters.capture_sha256 &&
    contracts.canonicalJson(view.capture_metadata) === contracts.canonicalJson(memoryDraft.capture_metadata),
    'ui:save-recovery-review-mismatch')
  requireValue(view.canonical_operation === contracts.canonicalJson(operation) &&
    view.operation_digest === await contracts.operationDigest(operation), 'ui:save-recovery-review-mismatch')
  requireValue((result.operation === null && result.memory_capture === null) ||
    (contracts.canonicalJson(result.operation) === view.canonical_operation &&
      contracts.canonicalJson(result.memory_capture) === contracts.canonicalJson(memoryDraft)),
    'ui:save-recovery-operation-changed')
  contracts.validateContract('MemoryRecord', result.record)
  validateSavedCaptureContent(result.record, memoryDraft)
  requireValue(result.record.storage_status === 'saved' && result.record.grants_authority === false &&
    result.record.owner_subject === operation.target_identity.owner_subject && result.record.task_id === operation.task_id,
    'ui:save-recovery-record-mismatch')
  requireValue(receipt && Object.keys(receipt).sort().join(',') === [...RECEIPT].sort().join(',') &&
    receipt.version === 1 && receipt.kind === 'prime-memory-effect/v1' && receipt.action_type === 'memory.save' &&
    receipt.operation_id === operation.operation_id && receipt.operation_digest === view.operation_digest &&
    receipt.grant_id === 'grant:' + proofNonce && receipt.owner_subject === operation.target_identity.owner_subject &&
    typeof receipt.request_id === 'string' && UUID.test(receipt.request_id) && receipt.status === 'applied' &&
    DIGEST.test(receipt.request_digest) && DIGEST.test(receipt.result_digest) && DIGEST.test(result.receipt_digest) &&
    contracts.canonicalJson(receipt.result) === contracts.canonicalJson(result.record), 'ui:save-recovery-receipt-mismatch')
  const request = {version:1,action_type:'memory.save',owner_subject:operation.target_identity.owner_subject,
    operation_id:operation.operation_id,operation_digest:view.operation_digest,parameters:operation.canonical_parameters}
  requireValue(receipt.request_digest === await digest('aukora-prime.memory.effect.v1', request, contracts) &&
    receipt.result_digest === await digest('aukora-prime.memory-result.v1', result.record, contracts) &&
    result.receipt_digest === await digest('aukora-prime.memory-receipt.v1', receipt, contracts),
    'ui:save-recovery-digest-mismatch')
  const index = result.index
  requireValue((index.indexed === null && index.searchable === null && index.status === result.record.index_status) ||
    (typeof index.indexed === 'boolean' && typeof index.searchable === 'boolean' &&
      index.indexed === ['indexed','searchable'].includes(index.status) && index.searchable === (index.status === 'searchable')),
    'ui:save-recovery-index-mismatch')
  if (result.citation !== null) {
    const citation = result.citation, record = result.record
    const required = ['record_id','revision','chain_domain','chain_sequence','aura_entry_hash','verified_head','verdict','grants_authority']
    const optional = ['reason','source_digest','source_span','source_span_integrity']
    requireValue(required.every(key => Object.hasOwn(citation,key)) && Object.keys(citation).every(key => [...required,...optional].includes(key)) &&
      citation.record_id === record.record_id && citation.revision === record.revision && citation.chain_domain === record.chain_domain &&
      Number.isSafeInteger(citation.chain_sequence) && citation.chain_sequence > 0 &&
      typeof citation.aura_entry_hash === 'string' && /^[a-f0-9]{64}$/.test(citation.aura_entry_hash) &&
      typeof citation.verified_head === 'string' && /^[a-f0-9]{64}$/.test(citation.verified_head) &&
      ['VERIFIED','UNVERIFIED','MISSING'].includes(citation.verdict) && citation.grants_authority === false &&
      result.citation_status === citation.verdict.toLowerCase(), 'ui:save-recovery-citation-mismatch')
    if (citation.verdict === 'VERIFIED') requireValue('sha256:' + citation.source_digest === record.source_event_digest &&
      contracts.canonicalJson(citation.source_span) === contracts.canonicalJson(record.source_span), 'ui:save-recovery-citation-source-mismatch')
  } else requireValue(result.citation_status === 'unavailable', 'ui:save-recovery-citation-mismatch')
  return result
}
