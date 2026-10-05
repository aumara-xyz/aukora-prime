/** One deterministic floor for vector indexing. No model or clock.
 * Short facts and corrections survive; byte length alone says nothing about quality.
 * Existing objects/chains are never edited when a record falls below this floor. */
import { sha256Hex } from './memory-tiers.mjs'

export const QUALITY_VERSION = 'kira-quality/v1'
// Tune semantic eligibility here, not independently in either store. Length is
// necessary, never sufficient. These are UTF-8 bytes and Unicode word tokens.
export const QUALITY_FLOOR = Object.freeze({ minBytes: 12, minWords: 2 })
export const contentHash = text => sha256Hex(String(text))
// Instruction-shaped turns are orders to whoever reads them, not claims about the world. Recalled
// beside a later question they act as a prompt injection, so they never enter the vector index;
// the chain keeps them and exact-word recall still finds them. A short turn that opens by dictating
// the exact reply (a colon, a quote or "the … characters/word" after exactly/only/verbatim) is one; a turn of any length that tells the reader to drop its instructions is one.
const DICTATED_REPLY = [
  /^(?:(?:please|now|just|ok(?:ay)?|so)[\s,]+)*(?:reply|respond|answer|say|output|print|return|write|type|repeat|echo)\b(?:[\s:,]+[^\s:,]+){0,8}?[\s:,]+(?:(?:exactly|only|verbatim)\s*(?::|["“'‘]|the\s+(?:[^\s]+\s+){0,2}(?:words?|letters?|characters?|numbers?|strings?|tokens?|phrases?)\b)|nothing\s+(?:but|else|more)\s*:?\s*["“'‘])/iu,
  /^(?:(?:please|now|just)[\s,]+)*(?:reply|respond|answer)\s+(?:with|using)\s+(?:a\s+single|one|the\s+(?:single\s+)?(?:word|letter|number|character|string|token))\b/iu,
  /^(?:(?:please|now|just)[\s,]+)*repeat\s+after\s+me\b/iu,
  /^(?:you\s+are\s+now|pretend\s+(?:to\s+be|you\s+are))\b/iu,
]
const OVERRIDE = /\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|every|your|the|of)\s+)*(?:previous|prior|above|earlier|preceding|system|original)\s+(?:instructions?|prompts?|messages?|rules?|directions?)\b/iu
export const DICTATED_REPLY_MAX_WORDS = 40
export const CLAIMLESS_MAX_BYTES = 60
export const instructionShaped = (normalized, words) => OVERRIDE.test(normalized)
  || (words.length <= DICTATED_REPLY_MAX_WORDS && DICTATED_REPLY.some(pattern => pattern.test(normalized)))

export function memoryQuality(text) {
  const normalized = typeof text === 'string' ? text.normalize('NFKC').replace(/^From: [^\n]+\nWhen: [^\n]+\n\n/u, '').trim() : ''
  let reason = null
  const words = normalized.match(/[\p{L}\p{N}]+(?:['’][\p{L}]+)?/gu) ?? []
  const assertion = /\b(?:am|is|are|was|were|have|has|had|want|wants|prefer|prefers|need|needs|must|should|shall|will|won't|cannot|can't|decided|agreed|preserve|requires?|uses?|lives?|means|contains?|works?|failed|succeeded|stands?|finished)\b/iu.test(normalized)
  const entity = (normalized !== normalized.toUpperCase() && /\b[A-Z][A-Z0-9_-]{1,}\b/u.test(normalized))
    || words.some(word => /^\p{Lu}\p{Ll}{2,}/u.test(word)
      && !/^(?:I|The|This|That|It|We|You|My|Our|Your|Please|Thanks|Yes|Okay|Stay|Keep|Continue|Go|Do|What|How|When|Where|Why|Can|Could|Would|Should|Just|Now|All|And|But|From|When)$/u.test(word))
    || /(?:https?:\/\/\S+|\b[\w-]+\.(?:mjs|js|py|json|md)\b|["“][^"”]{2,80}["”])/u.test(normalized)
  // A standing rule ("never …", "only …", "no tests") is a claim about how to work, even without a verb above.
  const directive = /\b(?:never|always|only|exactly|don['’]?t|not|no|stop|must)\b/iu.test(normalized)
  if (!normalized) reason = 'empty'
  else if (!/[\p{L}\p{N}]/u.test(normalized)) reason = 'no-content'
  else if (!/\s/u.test(normalized) || words.length < QUALITY_FLOOR.minWords || Buffer.byteLength(normalized, 'utf8') < QUALITY_FLOOR.minBytes) reason = 'too-short'
  else if (/^(?:(?:ok(?:ay)?|yes|yeah|yep|yup|sure|thanks?|thank you|got it|understood|cool|great|awesome|done|continue|go ahead|please continue|stay vigilant|keep going|carry on)[\s,.!;:\-]*)+$/iu.test(normalized)) reason = 'acknowledgement'
  else if (/^(?:([\p{L}\p{N}])\1{7,})$/iu.test(normalized)) reason = 'repeated-character'
  else if (instructionShaped(normalized, words)) reason = 'instruction'
  // Only SHORT turns can be judged claimless: a long note without these verbs is still a real note.
  else if (!assertion && !entity && !directive && Buffer.byteLength(normalized, 'utf8') <= CLAIMLESS_MAX_BYTES) reason = 'no-assertion-or-entity'
  return Object.freeze({ keep: reason === null, reason, version: QUALITY_VERSION })
}

/** Callers with legacy envelopes must verify that envelope first, then supply its
 * independently verified hash explicitly. Never silently manufacture a commitment. */
export function verifyContentHash(text, expected) {
  if (typeof expected !== 'string' || !/^[0-9a-f]{64}$/u.test(expected)) return { ok: false, reason: 'content-hash-missing' }
  if (typeof text !== 'string' || contentHash(text) !== expected) return { ok: false, reason: 'content-hash-mismatch' }
  return { ok: true, contentHash: expected }
}

const isHash = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const isByteRange = range => range?.unit === 'utf8-bytes' && Number.isSafeInteger(range.start)
  && Number.isSafeInteger(range.end) && range.start >= 0 && range.end >= range.start

/** Hash domains are explicit: contentHash remains the historical full statement
 * commitment, never the hash of a displayed excerpt. A projection can verify
 * its displayed part only; it cannot independently verify the parent statement.
 * Callers still verify the original chained record before making a projection. */
export function verifyMemoryRecordHashes(note) {
  const statementHash = note.statementHash ?? note.contentHash
  if (statementHash === undefined && note.partHash === undefined && note.byteRange === undefined) return { ok: true, domain: 'uncommitted' }
  if (!isHash(statementHash) || (note.contentHash !== undefined && note.contentHash !== statementHash)) return { ok: false, reason: 'content-hash-mismatch' }
  const full = typeof note.statement === 'string'
  const text = full ? note.statement : note.text
  if (full || (note.partHash === undefined && note.byteRange === undefined)) {
    if (!verifyContentHash(text, statementHash).ok) return { ok: false, reason: 'content-hash-mismatch' }
    if (note.partHash === undefined && note.byteRange === undefined) return { ok: true, domain: 'statement', statementVerified: true, statementHash }
  }
  const displayed = note.text ?? text, range = note.byteRange
  if (typeof displayed !== 'string' || !isHash(note.partHash) || !isByteRange(range)
    || Buffer.byteLength(displayed, 'utf8') !== range.end - range.start || !verifyContentHash(displayed, note.partHash).ok) {
    return { ok: false, reason: 'content-hash-mismatch' }
  }
  if (full) {
    const bytes = Buffer.from(note.statement, 'utf8')
    if (range.end > bytes.length || !bytes.subarray(range.start, range.end).equals(Buffer.from(displayed, 'utf8'))) return { ok: false, reason: 'content-hash-mismatch' }
  }
  return { ok: true, domain: 'part', statementVerified: full, statementHash, partHash: note.partHash, byteRange: range }
}

/** Project exact bytes from an already verified record. start is relative to the
 * input representation in UTF-8 bytes, not JavaScript characters. No note ID,
 * canonical statement or parent commitment is changed. */
export function projectMemoryText(note, text, { start = 0 } = {}) {
  const checked = verifyMemoryRecordHashes(note)
  if (!checked.ok) throw new Error('content-hash-mismatch')
  const source = note.statement ?? note.text
  // String.slice can end halfway through a surrogate pair; omit that unfinished
  // point rather than hash replacement bytes that never occurred in the source.
  const shown = typeof text === 'string' ? text.replace(/[\uD800-\uDBFF]$/u, '') : text
  if (typeof source !== 'string' || typeof shown !== 'string' || !Number.isSafeInteger(start) || start < 0) throw new Error('memory-byte-range-invalid')
  const bytes = Buffer.from(source, 'utf8'), selected = Buffer.from(shown, 'utf8')
  if (start + selected.length > bytes.length || !bytes.subarray(start, start + selected.length).equals(selected)) throw new Error('memory-byte-range-invalid')
  if (checked.domain === 'uncommitted') return { text: shown }
  const absoluteStart = (typeof note.statement === 'string' || checked.domain === 'statement' ? 0 : note.byteRange.start) + start
  return { text: shown, statementHash: checked.statementHash, contentHash: checked.statementHash, contentHashScope: 'full-statement',
    partHash: contentHash(shown), byteRange: { start: absoluteStart, end: absoluteStart + selected.length, unit: 'utf8-bytes' } }
}
