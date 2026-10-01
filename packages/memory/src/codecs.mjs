// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto'
import { assertNoDuplicateKeys, deepestNesting } from '../genesis/plugins/aukora-kira/lib/strict-read.mjs'
import { canonicalJSON, verifyKiraMemoryRecord } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { recomputeNoteId, recomputeRecordId } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'

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

// Keep the v0 decimal encoder. The strict donor parser's integer policy cannot read historical v0.
export function parseOriginal(bytes) {
  const buffer = Buffer.from(bytes)
  requireMemory(buffer.length > 0 && buffer.length <= MAX_BYTES, 'memory:bytes-limit')
  let text, value
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer)
    requireMemory(deepestNesting(text) <= 64, 'memory:json-depth')
    assertNoDuplicateKeys(text, 'memory-original')
    value = JSON.parse(text)
    const finite = node => {
      if (typeof node === 'number') requireMemory(Number.isFinite(node), 'memory:json-number-invalid')
      else if (node && typeof node === 'object') for (const child of Object.values(node)) finite(child)
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
  requireMemory(record.subject === owner, 'memory:owner-mismatch')
  requireMemory(record.grantsAuthority === false, 'memory:record-claims-authority')
  let id, format, canon, tier
  if (record.recordId?.startsWith('kira:')) {
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
    if (record.aura) closedKeys(record.aura,['index','entryHash'],'memory:aura-fields-invalid')
    if (record.editedFrom) closedKeys(record.editedFrom,['id','statement','originallyCapturedFrom'],'memory:edit-fields-invalid')
    id = recomputeNoteId(record)
    requireMemory(id === record.id && /^rem:[0-9a-f]{64}$/.test(id), 'memory:note-id-changed')
    requireMemory(/^[0-9a-f]{64}$/.test(record.salt ?? ''), 'memory:note-salt-invalid')
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
    format = 'remembered-note/v1'; canon = 'aukora:remembered-canonicalOf/v1'; tier = 'remembered'
  } else {
    closedKeys(record, ['id','tier','kind','text','createdAt','source','aura','subject','privacy','grantsAuthority','label',
      'contentHash','bodyAtCapture'], 'memory:legacy-fields-invalid')
    if (record.aura) closedKeys(record.aura,['index','entryHash'],'memory:aura-fields-invalid')
    id = recomputeRecordId(record)
    requireMemory(id === record.id && /^[0-9a-f]{64}$/.test(id), 'memory:legacy-id-changed')
    requireMemory(record.tier === 'remembered', 'memory:legacy-tier-invalid')
    format = 'remembered-record/v0'; canon = 'aukora:remembered-canonicalOf/v0'; tier = 'remembered'
  }
  requireMemory(['local', 'private', 'exportable'].includes(record.privacy), 'memory:privacy-invalid')
  return { record, id, format, canon, tier, scope: record.scope ?? 'owner', privacy: record.privacy,
    statement: record.statement ?? record.text ?? canonicalJSON(record.content), digest: sha256(bytes) }
}

export const chainRecordId = entry => entry.id ?? entry.recordId ?? entry.key
export const isCreation = entry => ['remember','add','index-content','memory.put'].includes(entry.op)
  || (entry.operation==='memory.put' && entry.verdict==='accepted')

// A redacted export cannot rewrite hash-bearing historical bytes to remove text. Refuse such a chain.
export function requireRedactableChain(entries) {
  for (const entry of entries) {
    closedKeys(entry, ['prev','hash','sequence','op','id','recordId','key','at','tier','by','contentHash',
      'contentSha256','entryHash','originKey','bodyAtCapture','verdict','operation','scope','controlDigest'], 'memory:redacted-chain-contains-payload')
    for (const key of ['contentHash','contentSha256','entryHash','originKey','controlDigest']) if (entry[key] !== undefined) {
      requireMemory(/^[0-9a-f]{64}$/.test(entry[key]), 'memory:redacted-chain-contains-payload')
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
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  requireMemory(text === '' || text.endsWith('\n'), 'memory:chain-torn')
  let prev = AURA_RECORD_DOMAIN; const entries = []
  for (const line of text === '' ? [] : text.slice(0, -1).split('\n')) {
    const entry = parseOriginal(Buffer.from(line))
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
    requireMemory(entry.entryHash === meta.record.aura?.entryHash, 'memory:membership-pointer-changed')
    const content = sha256(Buffer.from(meta.statement))
    requireMemory(!entry.contentHash || entry.contentHash === content, 'memory:content-commitment-changed')
    requireMemory(!meta.record.contentHash || meta.record.contentHash === content, 'memory:content-commitment-changed')
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
