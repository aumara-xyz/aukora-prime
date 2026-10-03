// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto'
import { assertNoDuplicateKeys, deepestNesting } from '../genesis/plugins/aukora-kira/lib/strict-read.mjs'
import { canonicalJSON, verifyKiraMemoryRecord, kiraRecordContentSha256 } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { recomputeNoteId, recomputeRecordId, ATTRIBUTIONS, SENSITIVITIES, noteKind } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'

export class MemoryRefusal extends Error {
  constructor(code) { super(code); this.name = 'MemoryRefusal'; this.code = code }
}
export function requireMemory(condition, code) { if (!condition) throw new MemoryRefusal(code) }
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
export const AURA_RECORD_DOMAIN = 'aukora:aura-record:v1'
export const CHAIN_DOMAINS = ['remembered', 'approved', 'legacy-presplit']
export const MAX_BYTES = 64 * 1024 * 1024
export const closedKeys = (value, keys, code) => requireMemory(value && typeof value === 'object'
  && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key)), code)
const HEX64 = /^[0-9a-f]{64}$/
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u
export function requireMemoryUnicode(value, code = 'memory:json-string-invalid') {
  requireMemory(typeof value === 'string' && !LONE_SURROGATE.test(value), code)
}
const nonempty = value => typeof value === 'string' && value.length > 0
const digestHex = value => typeof value === 'string' && HEX64.test(value)
const instant = value => typeof value === 'string' && INSTANT.test(value)

// These are the donor's stored JSON forms, not an additional identity formula. Record IDs cover
// their versioned envelopes; the returned digest separately binds every original byte, including
// the serializer and final LF. Never normalize a historical record and claim it was the original.
function requireRecordSerialization(bytes, record) {
  const text = Buffer.from(bytes).toString('utf8'), body = text.endsWith('\n') ? text.slice(0, -1) : text
  requireMemory(body === JSON.stringify(record) || body === JSON.stringify(record, null, 2),
    'memory:record-not-canonical')
}

function validateAura(record) {
  closedKeys(record.aura, ['index','entryHash'], 'memory:aura-fields-invalid')
  requireMemory(Number.isSafeInteger(record.aura.index) && record.aura.index >= 0
    && digestHex(record.aura.entryHash), 'memory:aura-invalid')
}

function validateRememberedMetadata(record, statement) {
  validateAura(record)
  if (record.contentHash !== undefined) requireMemory(digestHex(record.contentHash)
    && record.contentHash === sha256(Buffer.from(statement, 'utf8')), 'memory:content-commitment-changed')
  if (record.bodyAtCapture !== undefined && record.bodyAtCapture !== null) requireMemory(
    typeof record.bodyAtCapture === 'object' && !Array.isArray(record.bodyAtCapture), 'memory:capture-body-invalid')
}

function validateNoteEnvelope(record) {
  requireMemory(nonempty(record.subject) && nonempty(record.scope) && nonempty(record.category)
    && typeof record.statement === 'string' && record.statement.trim() !== ''
    && ATTRIBUTIONS.includes(record.attributedTo) && SENSITIVITIES.includes(record.sensitivity),
  'memory:note-envelope-invalid')
  requireMemory(typeof record.validFrom === 'string' && /^\d{4}-\d{2}-\d{2}$/u.test(record.validFrom)
    && (record.validTo === null || typeof record.validTo === 'string') && instant(record.observedAt)
    && Number.isFinite(record.confidence) && record.confidence >= 0 && record.confidence <= 1
    && (record.possibleChange === undefined || typeof record.possibleChange === 'boolean'),
  'memory:note-envelope-invalid')
  requireMemory(Array.isArray(record.links) && record.links.every(link => link && typeof link === 'object'
    && !Array.isArray(link) && typeof link.relation === 'string' && typeof link.id === 'string')
    && record.origin && typeof record.origin === 'object' && !Array.isArray(record.origin)
    && nonempty(record.origin.by), 'memory:note-envelope-invalid')
  requireMemory(Array.isArray(record.evidence) && record.evidence.length > 0 && record.evidence.every(one =>
    one && typeof one === 'object' && !Array.isArray(one) && typeof one.log === 'string'
    && Number.isSafeInteger(one.turn) && digestHex(one.turnDigest) && typeof one.quote === 'string'),
  'memory:note-evidence-invalid')
  const source = record.source
  requireMemory(source && typeof source === 'object' && !Array.isArray(source), 'memory:note-evidence-missing')
  if (source.state === 'UNLINKED') {
    const hasSession = nonempty(source.sessionId), hasTurn = Number.isSafeInteger(source.citedTurn)
    requireMemory(typeof source.cited === 'boolean' && nonempty(source.because)
      && (source.cited ? hasSession && hasTurn : !hasSession && !hasTurn), 'memory:unlinked-source-invalid')
  } else requireMemory(digestHex(source.sha256), 'memory:source-digest-invalid')
  if (record.editedFrom !== undefined) {
    closedKeys(record.editedFrom, ['id','statement','originallyCapturedFrom'], 'memory:edit-fields-invalid')
    requireMemory(record.attributedTo === 'owner-edit' && typeof record.editedFrom.id === 'string'
      && /^rem:[0-9a-f]{64}$/.test(record.editedFrom.id)
      && typeof record.editedFrom.statement === 'string'
      && (record.editedFrom.originallyCapturedFrom === null || typeof record.editedFrom.originallyCapturedFrom === 'string'),
    'memory:edit-metadata-invalid')
  }
}

// Keep the v0 decimal encoder. The strict donor parser's integer policy cannot read historical v0.
export function parseOriginal(bytes) {
  const buffer = Buffer.from(bytes)
  requireMemory(buffer.length > 0 && buffer.length <= MAX_BYTES, 'memory:bytes-limit')
  let text, value
  try {
    // ignoreBOM:true preserves the BOM for rejection; the default decoder silently drops it.
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer)
    requireMemory(text[0] !== '\uFEFF' && Buffer.from(text, 'utf8').equals(buffer), 'memory:original-encoding-invalid')
    requireMemory(deepestNesting(text) <= 64, 'memory:json-depth')
    assertNoDuplicateKeys(text, 'memory-original')
    value = JSON.parse(text)
    const finite = node => {
      if (typeof node === 'number') requireMemory(Number.isFinite(node)
        && (!Number.isInteger(node) || Number.isSafeInteger(node)), 'memory:json-number-invalid')
      else if (typeof node === 'string') requireMemoryUnicode(node)
      else if (node && typeof node === 'object') for (const [key, child] of Object.entries(node)) {
        requireMemoryUnicode(key); finite(child)
      }
    }
    finite(value)
  } catch (error) {
    if (error instanceof MemoryRefusal) throw error
    throw new MemoryRefusal('memory:original-json-invalid')
  }
  requireMemory(value !== null && typeof value === 'object' && !Array.isArray(value), 'memory:original-not-object')
  return value
}

export function validateOriginal(bytes, owner) {
  const record = parseOriginal(bytes)
  requireRecordSerialization(bytes, record)
  requireMemory(record.subject === owner, 'memory:owner-mismatch')
  requireMemory(record.grantsAuthority === false, 'memory:record-claims-authority')
  let id, format, canon, tier
  if (typeof record.recordId === 'string' && record.recordId.startsWith('kira:')) {
    const verdict = verifyKiraMemoryRecord(record)
    requireMemory(verdict.verified === true, 'memory:kira-record-invalid')
    id = record.recordId; format = record.envelope?.format ?? 'v0'
    canon = record.envelope?.canon ?? 'aukora:canon-json:v0-ecmascript-number'; tier = 'approved'
  } else if (record.v === 1 && Array.isArray(record.evidence)) {
    // The donor ID covers its envelope, not arbitrary extension fields. Extensions require a new format.
    closedKeys(record, ['v','subject','scope','category','statement','attributedTo','evidence','validFrom','validTo',
      'observedAt','confidence','sensitivity','privacy','links','origin','source','possibleChange','grantsAuthority','salt',
      'id','tier','kind','text','createdAt','label','receiptState','contentHash','aura','bodyAtCapture','editedFrom'],
    'memory:note-fields-invalid')
    validateNoteEnvelope(record)
    id = recomputeNoteId(record)
    requireMemory(id === record.id && /^rem:[0-9a-f]{64}$/.test(id), 'memory:note-id-changed')
    requireMemory(digestHex(record.salt), 'memory:note-salt-invalid')
    requireMemory(record.tier === 'remembered', 'memory:note-tier-invalid')
    requireMemory(record.label===undefined || record.label===(record.source?.state==='UNLINKED'
      ? 'remembered, source not found':'unreviewed'),'memory:note-label-invalid')
    requireMemory(record.receiptState===undefined || record.receiptState===(record.source?.state==='UNLINKED'?'UNLINKED':'LINKED'),
      'memory:note-receipt-state-invalid')
    requireMemory((record.kind === undefined || record.kind === record.category)
      && (record.text === undefined || record.text === record.statement)
      && (record.createdAt === undefined || record.createdAt === record.observedAt),
      'memory:note-alias-changed')
    requireMemory(record.evidence.length > 0 && record.source && typeof record.source === 'object', 'memory:note-evidence-missing')
    validateRememberedMetadata(record, record.statement)
    format = 'remembered-note/v1'; canon = 'aukora:remembered-canonicalOf/v1'; tier = 'remembered'
  } else {
    closedKeys(record, ['id','tier','kind','text','createdAt','source','aura','subject','privacy','grantsAuthority','label',
      'contentHash','bodyAtCapture'], 'memory:legacy-fields-invalid')
    requireMemory(noteKind.includes(record.kind) && typeof record.text === 'string' && record.text.trim() !== ''
      && instant(record.createdAt) && record.source && typeof record.source === 'object'
      && !Array.isArray(record.source) && nonempty(record.source.sessionId)
      && Number.isSafeInteger(record.source.seq) && record.source.seq >= 0 && instant(record.source.at)
      && digestHex(record.source.sha256)
      && (record.source.sessionTitle === undefined || typeof record.source.sessionTitle === 'string'),
    'memory:legacy-envelope-invalid')
    id = recomputeRecordId(record)
    requireMemory(id === record.id && /^[0-9a-f]{64}$/.test(id), 'memory:legacy-id-changed')
    requireMemory(record.tier === 'remembered', 'memory:legacy-tier-invalid')
    requireMemory(record.label === undefined || record.label === 'unreviewed', 'memory:legacy-label-invalid')
    validateRememberedMetadata(record, record.text)
    format = 'remembered-record/v0'; canon = 'aukora:remembered-canonicalOf/v0'; tier = 'remembered'
  }
  requireMemory(['local', 'private', 'exportable'].includes(record.privacy), 'memory:privacy-invalid')
  return { record, id, format, canon, tier, scope: record.scope ?? 'owner', privacy: record.privacy,
    statement: record.statement ?? record.text ?? canonicalJSON(record.content), digest: sha256(bytes) }
}

export const chainRecordId = entry => entry.id ?? entry.recordId ?? entry.key
export const isCreation = entry => ['remember','add','index-content','memory.put'].includes(entry.op)
  || (entry.operation==='memory.put' && ['accepted','settled'].includes(entry.verdict))

// A redacted export cannot rewrite hash-bearing historical bytes to remove text. Refuse such a chain.
export function requireRedactableChain(entries) {
  for (const entry of entries) {
    closedKeys(entry, ['prev','hash','sequence','op','id','recordId','key','at','tier','by','contentHash',
      'contentSha256','entryHash','originKey','bodyAtCapture','verdict','operation','scope','controlDigest'], 'memory:redacted-chain-contains-payload')
    requireMemory(Number.isSafeInteger(entry.sequence) && entry.sequence > 0 && digestHex(entry.hash)
      && (entry.prev === AURA_RECORD_DOMAIN || digestHex(entry.prev)), 'memory:redacted-chain-contains-payload')
    const memoryPut = entry.op === 'memory.put' || entry.operation === 'memory.put'
    requireMemory(entry.op === undefined ? memoryPut && ['accepted','settled'].includes(entry.verdict)
      : ['remember','add','index-content','memory.put','forget','control'].includes(entry.op),
    'memory:redacted-chain-contains-payload')
    requireMemory(entry.operation === undefined || (entry.operation === 'memory.put'
      && (entry.op === undefined || entry.op === 'memory.put')), 'memory:redacted-chain-contains-payload')
    requireMemory(entry.verdict === undefined || (memoryPut && ['accepted','settled'].includes(entry.verdict)),
      'memory:redacted-chain-contains-payload')
    for (const key of ['id','recordId','key']) if (entry[key] !== undefined) requireMemory(
      typeof entry[key] === 'string' && /^(?:rem:|kira:)?[0-9a-f]{64}$/.test(entry[key]),
    'memory:redacted-chain-contains-payload')
    if (entry.at !== undefined) requireMemory(instant(entry.at) && Number.isFinite(Date.parse(entry.at))
      && new Date(entry.at).toISOString() === entry.at.slice(0, -1) + '.000Z', 'memory:redacted-chain-contains-payload')
    requireMemory(entry.tier === undefined || ['remembered','approved'].includes(entry.tier),
      'memory:redacted-chain-contains-payload')
    for (const key of ['contentHash','contentSha256','entryHash','originKey','controlDigest']) if (entry[key] !== undefined) {
      requireMemory(digestHex(entry[key]), 'memory:redacted-chain-contains-payload')
    }
    requireMemory(entry.bodyAtCapture === undefined || entry.bodyAtCapture === null,
      'memory:redacted-chain-contains-payload')
    requireMemory(entry.scope===undefined || entry.scope==='owner','memory:redacted-chain-contains-payload')
    requireMemory(entry.by === undefined || ['prime.capture/v1','prime.forget/v1','prime.erase/v1',
      'kira-extract/v1','kira-capture/v1','backfill','owner','memory-owner'].includes(entry.by),
    'memory:redacted-chain-contains-payload')
  }
}

// Exact functions lifted from Genesis memory-owner.mjs; their preimage and separator are unchanged.
export function auraEntryHash(prev, fields) {
  return createHash('sha256').update(auraEntryPreimage(prev, fields), 'utf8').digest('hex')
}
export function auraEntryPreimage(prev, fields) {
  return canonicalJSON({ prev, ...fields, domain: AURA_RECORD_DOMAIN })
}

export function verifyChain(bytes, expectedHead) {
  let text
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) }
  catch { throw new MemoryRefusal('memory:original-encoding-invalid') }
  requireMemory(text[0] !== '\uFEFF', 'memory:original-encoding-invalid')
  requireMemory(text === '' || text.endsWith('\n'), 'memory:chain-torn')
  let prev = AURA_RECORD_DOMAIN; const entries = []
  for (const line of text === '' ? [] : text.slice(0, -1).split('\n')) {
    const entry = parseOriginal(Buffer.from(line))
    // readAuraHistory in the pinned donor uses this exact compact round-trip test.
    requireMemory(JSON.stringify(entry) === line, 'memory:chain-not-canonical')
    const { prev: named, hash, ...fields } = entry
    requireMemory(entry.sequence === entries.length + 1 && named === prev && auraEntryHash(prev, fields) === hash,
      'memory:chain-broken')
    entries.push(entry); prev = hash
  }
  if (expectedHead !== undefined) requireMemory(prev === expectedHead, 'memory:retained-head-mismatch')
  return { entries, head: prev, sequence: entries.length }
}

export function verifyMembership(meta, entries, sequence) {
  requireMemory(Number.isSafeInteger(sequence) && sequence > 0, 'memory:membership-sequence-invalid')
  const entry = entries[sequence - 1]
  requireMemory(entry && (entry.id === meta.id || entry.recordId === meta.id || entry.key === meta.id), 'memory:membership-missing')
  if (meta.tier === 'remembered') {
    requireMemory(['remember', 'add', 'index-content'].includes(entry.op), 'memory:membership-operation')
    requireMemory(meta.record.aura.index === sequence - 1, 'memory:membership-index-changed')
    requireMemory(entry.entryHash === meta.record.aura?.entryHash, 'memory:membership-pointer-changed')
    const content = sha256(Buffer.from(meta.statement))
    requireMemory(entry.contentHash === undefined || (digestHex(entry.contentHash) && entry.contentHash === content),
      'memory:content-commitment-changed')
    // Prime's writer names this marker explicitly. Historical donor writers retain their own
    // opaque marker; do not reinterpret that field using a new identity rule.
    if (entry.by === 'prime.capture/v1') requireMemory(entry.entryHash === sha256(Buffer.from(`${meta.id}\0${content}`, 'utf8')),
      'memory:membership-marker-changed')
    requireMemory(canonicalJSON(meta.record.bodyAtCapture ?? null) === canonicalJSON(entry.bodyAtCapture ?? null),
      'memory:capture-body-changed')
  } else if (entry.contentSha256 !== undefined) {
    requireMemory(digestHex(entry.contentSha256) && entry.contentSha256 === kiraRecordContentSha256(meta.record),
      'memory:content-commitment-changed')
  }
  return entry
}

export function verifySources(meta, eventMap) {
  if (meta.tier !== 'remembered') return { verdict: 'UNVERIFIED', reason: 'approved-evidence-verifier-required' }
  const source = meta.record.source
  if (source?.state === 'UNLINKED') return { verdict: 'MISSING', reason: 'source-unlinked' }
  requireMemory(/^[0-9a-f]{64}$/.test(source?.sha256 ?? ''), 'memory:source-digest-invalid')
  const bytes = eventMap.get(source.sha256)
  if (!bytes) return { verdict: 'MISSING', reason: 'source-event-missing' }
  requireMemory(sha256(bytes) === source.sha256, 'memory:source-event-changed')
  const event = parseOriginal(bytes)
  if (source.span) {
    const { start, end, unit, total } = source.span
    requireMemory(unit === 'utf16' && Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end >= start
      && Number.isSafeInteger(total) && total >= end, 'memory:source-span-invalid')
  }
  for (const evidence of meta.record.evidence ?? []) {
    requireMemory(/^[0-9a-f]{64}$/.test(evidence.turnDigest ?? ''), 'memory:evidence-digest-invalid')
    const quoteBytes = eventMap.get(evidence.turnDigest)
    if (!quoteBytes) return { verdict: 'MISSING', reason: 'evidence-event-missing' }
    requireMemory(sha256(quoteBytes) === evidence.turnDigest, 'memory:evidence-event-changed')
    const quotedEvent = parseOriginal(quoteBytes)
    requireMemory(typeof evidence.quote === 'string' && typeof quotedEvent.text === 'string'
      && quotedEvent.text.includes(evidence.quote), 'memory:evidence-quote-changed')
  }
  return { verdict: 'VERIFIED', source_digest: source.sha256, source_span: source.span ?? null,
    source_span_integrity: source.span ? 'covered-by-original-record-id' : null }
}
