// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only consumer of D's cold citation reader. The host supplies the association;
// this module creates no identity, record, approval, source mapping or transport.
export const AURA_RECALL_PROVIDER = 'aura.records'
export const AURA_RECALL_LIMIT = 50
const HEX = /^[0-9a-f]{64}$/u
const JOURNAL = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u
const SCOPE = 'provided-data-consistency-only; retrieval, provenance and witness independence unperformed'
const RESULT = ['ok', 'status', 'reason', 'grants_authority', 'citation', 'verification']
const CITATION = ['record_id', 'source', 'key_sha256', 'owner_subject', 'owner_pubkey_hex', 'binding_digest', 'grants_authority']
const SUMMARY = ['ok', 'status', 'source', 'aura_head', 'coverage', 'grants_authority', 'selected_head', 'anchor_scope', 'anchor_status', 'anchors_checked']
function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return Reflect.ownKeys(descriptors).length === fields.length
    && fields.every(key => descriptors[key]?.enumerable && Object.hasOwn(descriptors[key], 'value'))
}
const hex = value => typeof value === 'string' && HEX.test(value)
const position = value => Number.isSafeInteger(value) && value >= 0
function head(value) {
  return closed(value, ['position', 'hash']) && position(value.position)
    && (value.position === 0 ? value.hash === 'GENESIS' : hex(value.hash))
}
function source(value) {
  return closed(value, ['journal_id', 'position', 'hash'])
    && typeof value.journal_id === 'string' && JOURNAL.test(value.journal_id)
    && position(value.position) && value.position > 0 && hex(value.hash)
}
function selector(value) {
  if (!closed(value, value && Object.hasOwn(value, 'record_id') ? ['source', 'record_id'] : ['source'])
    || !source(value.source) || (Object.hasOwn(value, 'record_id') && !hex(value.record_id))) return null
  return { source: { ...value.source }, ...(Object.hasOwn(value, 'record_id') ? { record_id: value.record_id } : {}) }
}
const sameSource = (a, b) => a.journal_id === b.journal_id && a.position === b.position && a.hash === b.hash
const sameSelector = (a, b) => a && b && sameSource(a.source, b.source) && a.record_id === b.record_id
const stableReason = value => typeof value === 'string' && /^(?:aura-(?:citation|collected)|gate-source):[a-z0-9:-]{1,100}$/u.test(value)
/** Only the existing PUBLIC cold summary can leave the reader. */
function publicSummary(value) {
  const incomplete = value && Object.hasOwn(value, 'reason')
  const anchored = value && Object.hasOwn(value, 'anchored_head')
  const fields = [...SUMMARY, ...(incomplete ? ['reason'] : []), ...(anchored ? ['anchored_head'] : [])]
  if (!closed(value, fields) || value.grants_authority !== false
    || typeof value.ok !== 'boolean' || value.status !== (value.ok ? 'complete' : 'incomplete')
    || (incomplete && !stableReason(value.reason)) || value.anchor_scope !== SCOPE
    || !['verified', 'unperformed'].includes(value.anchor_status) || !position(value.anchors_checked)
    || (value.source !== null && (!closed(value.source, ['journal_id', 'key_sha256'])
      || typeof value.source.journal_id !== 'string' || !JOURNAL.test(value.source.journal_id) || !hex(value.source.key_sha256)))
    || !closed(value.aura_head, ['sequence', 'id']) || !position(value.aura_head.sequence) || !hex(value.aura_head.id)
    || !head(value.coverage) || (value.selected_head !== null && !head(value.selected_head))
    || (value.anchor_status === 'verified' ? !anchored || !head(value.anchored_head)
      || value.anchored_head.position > value.coverage.position : anchored)) return null
  return structuredClone(value)
}
export function sameRecallRecord(left, right) {
  return !!left && !!right && left.id === right.id
    && (left.subject === undefined || left.subject === right.subject)
    && left.contentHash === right.contentHash
    && (left.statement === undefined ? typeof left.text === 'string' && left.text === right.statement?.slice(0, left.text.length)
      : left.statement === right.statement)
    && JSON.stringify(left.source) === JSON.stringify(right.source)
    && JSON.stringify(left.rememberedChain ?? left.aura) === JSON.stringify(right.rememberedChain ?? right.aura)
}
/**
 * Existing host capability: {referenceForRecord(memoryRecordId), readCitation(selector)}.
 * readCitation is D's reader with the ROOT configured deployment owner already bound.
 * The caller's currentRecord rereads governed memory; neither session nor model supplies identity.
 */
export async function recallAuraCitations(records, { getProvider, currentRecord } = {}) {
  const answers = []
  for (const record of (Array.isArray(records) ? records : []).slice(0, AURA_RECALL_LIMIT)) {
    const answer = (reason, citation = null, verification = null) => Object.freeze({
      recordId: record.id, status: reason === null ? 'verified' : 'undetermined', reason,
      ownerStatus: 'INTERIM', grantsAuthority: false, citation, verification,
    })
    try {
      const provider = getProvider?.()
      if (!provider || typeof provider.referenceForRecord !== 'function' || typeof provider.readCitation !== 'function') {
        answers.push(answer('aura-recall:provider-unavailable')); continue
      }
      const initial = typeof currentRecord === 'function' ? await currentRecord(record.id) : undefined
      if (!sameRecallRecord(record, initial) || typeof initial.subject !== 'string') {
        answers.push(answer('aura-recall:record-changed')); continue
      }
      const query = selector(await provider.referenceForRecord(record.id))
      if (!query) { answers.push(answer('aura-recall:source-association-unavailable')); continue }
      const result = await provider.readCitation(query)
      if (getProvider?.() !== provider) {
        answers.push(answer('aura-recall:record-changed')); continue
      }
      const currentQuery = selector(await provider.referenceForRecord(record.id))
      if (!sameSelector(query, currentQuery)) { answers.push(answer('aura-recall:reference-changed')); continue }
      const finalRecord = await currentRecord(record.id)
      if (getProvider?.() !== provider || !sameRecallRecord(record, finalRecord)) {
        answers.push(answer('aura-recall:record-changed')); continue
      }
      if (!closed(result, RESULT) || result.grants_authority !== false) {
        answers.push(answer('aura-recall:invalid-result')); continue
      }
      if (result.ok === false && result.status === 'incomplete' && result.citation === null) {
        answers.push(answer(stableReason(result.reason) ? result.reason : 'aura-recall:verification-incomplete',
          null, publicSummary(result.verification))); continue
      }
      const cited = result.citation, verification = publicSummary(result.verification)
      if (result.ok !== true || result.status !== 'verified' || result.reason !== null
        || !closed(cited, CITATION) || cited.grants_authority !== false || !source(cited.source)
        || !sameSource(query.source, cited.source) || !hex(cited.record_id)
        || (query.record_id !== undefined && query.record_id !== cited.record_id)
        || cited.owner_subject !== initial.subject || !hex(cited.owner_pubkey_hex)
        || !hex(cited.binding_digest) || !hex(cited.key_sha256)
        || !verification || verification.ok !== true || verification.anchor_status !== 'verified'
        || verification.source?.journal_id !== cited.source.journal_id || verification.source?.key_sha256 !== cited.key_sha256
        || verification.coverage.position < cited.source.position
        || verification.coverage.position !== verification.selected_head?.position
        || verification.coverage.hash !== verification.selected_head?.hash) {
        answers.push(answer('aura-recall:invalid-result')); continue
      }
      answers.push(answer(null, structuredClone(cited), verification))
    } catch {
      answers.push(answer('aura-recall:reader-unavailable'))
    }
  }
  return Object.freeze(answers)
}
