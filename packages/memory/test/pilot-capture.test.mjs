// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { PILOT_CAPTURE_POLICY, validatePilotCaptureMetadata } from '../src/pilot-capture.mjs'
import { capturePresentationWarnings } from '../src/capture-presentation.mjs'
import { CAPTURE_PARAMETER_FIELDS, validateCaptureLiterals, validateCaptureMetadata,
  validateCaptureDraft, validateCaptureReview } from '../src/capture-review.mjs'

const at = '2026-10-01T11:03:00Z'
const host = () => ({ owner_id: 'synthetic-owner', owner_subject: 'synthetic-owner-subject', task_id: 'synthetic-task',
  conversation_id: 'synthetic-conversation', privacy: 'local', scope: 'owner', attributedTo: 'owner',
  source: { sessionId: 'synthetic-session', seq: 0, at, sha256: 'a'.repeat(64) }, events: [new Uint8Array([1])] })
const input = () => ({ category: 'fact', statement: 'Exact synthetic banana < & >.', validFrom: '2026-10-01',
  observedAt: at, confidence: 0.7, sensitivity: 'none' })
const refused = (h, extraction) => assert.throws(() => validatePilotCaptureMetadata(h, extraction),
  { code: 'memory:pilot-capture-profile-refused' })
const metadata = () => ({ profile: 'prime-pilot-memory-capture/v1', category: 'fact',
  valid_from: '2026-10-01', observed_at: at, confidence_percent: 70, sensitivity: 'none' })
const draft = () => ({ statement: input().statement, attributed_to: 'owner',
  capture_metadata: metadata(), evidence_quote: 'Exact synthetic source event < & >.' })
const parameters = capture => ({ capture_sha256: 'a'.repeat(64), idempotency_key_sha256: 'b'.repeat(64),
  heads: {}, ...structuredClone(capture) })
const reviewRefused = fn => assert.throws(fn, { message: 'memory:capture-review-invalid' })

test('new pilot metadata uses documented fixed defaults and does not rewrite input or host', () => {
  const h = host(), extraction = input(), before = structuredClone({ h, extraction })
  assert.equal(validatePilotCaptureMetadata(h, extraction), extraction)
  assert.deepEqual({ h, extraction }, before)
  assert.equal(PILOT_CAPTURE_POLICY.confidence, 0.7)
  assert.equal(PILOT_CAPTURE_POLICY.grantsAuthority, false)
  assert.equal(Object.isFrozen(PILOT_CAPTURE_POLICY.origin), true)
  assert.equal(Object.isFrozen(PILOT_CAPTURE_POLICY.links), true)
  delete h.scope
  assert.equal(validatePilotCaptureMetadata(h, extraction), extraction)
  assert.equal(Object.hasOwn(h, 'scope'), false)
  const explicit = { ...extraction, links: [] }
  assert.equal(validatePilotCaptureMetadata(h, explicit), explicit)
  assert.equal(Object.hasOwn(extraction, 'links'), false)
  assert.equal(Object.hasOwn(explicit, 'links'), true)
})

test('pilot metadata rejects hidden extraction policy changes and malformed closures', () => {
  const mutations = [{ category: 'preference' }, { confidence: 0.71 }, { sensitivity: 'private' },
    { validFrom: '2026-09-30' }, { observedAt: '2026-10-01T11:03:01Z' }, { links: [{ relation: 'context', id: 'other' }] },
    { links: undefined }, { possibleChange: true }, { salt: 'f'.repeat(64) }, { validTo: null }]
  for (const change of mutations) refused(host(), { ...input(), ...change })
  const missing = input(); delete missing.confidence; refused(host(), missing)
  const hidden = input(); Object.defineProperty(hidden, 'category', { value: 'fact', enumerable: false }); refused(host(), hidden)
  const getter = input(); Object.defineProperty(getter, 'confidence', { enumerable: true, get: () => 0.7 }); refused(host(), getter)
  const symbolic = input(); symbolic[Symbol('hidden')] = true; refused(host(), symbolic)
  const links = []; links.hidden = true; refused(host(), { ...input(), links })
})

test('pilot host cannot override scope, evidence, body, origin, or source provenance shape', () => {
  const mutations = [{ privacy: 'public' }, { scope: 'team' }, { scope: undefined }, { evidence: [] },
    { bodyAtCapture: {} }, { origin: { by: 'other' } }, { origin: { by: 'prime.capture/v1', model: 'hidden-model' } }]
  for (const change of mutations) refused({ ...host(), ...change }, input())
  const h = host()
  h.evidence = null; h.bodyAtCapture = null; h.origin = { by: 'prime.capture/v1' }
  assert.equal(validatePilotCaptureMetadata(h, input()).category, 'fact')
  for (const change of [{ sessionTitle: 'hidden' }, { span: { start: 0, end: 1 } }, { seq: -1 }, { seq: 0.5 },
    { at: '2026-10-01T11:03:00.000Z' }, { at: '2026-02-30T11:03:00Z' }, { sha256: 'A'.repeat(64) }]) {
    const changed = { ...host(), source: { ...host().source, ...change } }
    refused(changed, input())
  }
})

test('reviewed attribution stays explicit and new NFC Unicode spelling remains exact', () => {
  for (const attribution of ['owner', 'owner-voice', 'owner-edit', 'backfill', 'lane-requester', 'dream', 'agent']) {
    assert.equal(validatePilotCaptureMetadata({ ...host(), attributedTo: attribution }, input()).statement, input().statement)
  }
  const decomposed = { ...input(), statement: 'Exact cafe\u0301 p\u0430ypal statement.' }
  refused(host(), decomposed)
  assert.equal(decomposed.statement.includes('e\u0301'), true)
  assert.notEqual(decomposed.statement, decomposed.statement.normalize('NFC'))
  const composed = { ...input(), statement: 'Exact caf\u00e9 p\u0430ypal statement.' }
  assert.equal(validatePilotCaptureMetadata(host(), composed), composed)
})

test('capture review binds the exact six metadata fields and evidence quote to a retained draft', () => {
  const capture = draft(), before = structuredClone(capture), operationParameters = parameters(capture)
  assert.deepEqual(CAPTURE_PARAMETER_FIELDS, ['capture_sha256', 'idempotency_key_sha256', 'heads',
    'statement', 'attributed_to', 'capture_metadata', 'evidence_quote'])
  const retained = validateCaptureDraft(capture)
  assert.deepEqual(retained, capture)
  assert.equal(Object.isFrozen(retained), true)
  assert.equal(Object.isFrozen(retained.capture_metadata), true)
  assert.deepEqual(capture, before)
  assert.deepEqual(validateCaptureReview(operationParameters, retained), retained)
  capture.capture_metadata.valid_from = '2026-10-02'
  assert.equal(retained.capture_metadata.valid_from, '2026-10-01')
  for (const changes of [{ statement: 'Changed literal.' }, { attributed_to: 'agent' },
    { evidence_quote: 'Changed source quote.' }, { capture_metadata: { ...metadata(), observed_at: '2026-10-02T11:03:00Z', valid_from: '2026-10-02' } }]) {
    reviewRefused(() => validateCaptureReview({ ...operationParameters, ...changes }, retained))
  }
  const oldDraft = { statement: retained.statement, attributed_to: retained.attributed_to }
  reviewRefused(() => validateCaptureDraft(oldDraft))
  for (const field of ['capture_metadata', 'evidence_quote']) {
    const incomplete = { ...retained }; delete incomplete[field]
    reviewRefused(() => validateCaptureDraft(incomplete))
  }
  reviewRefused(() => validateCaptureDraft({ ...retained, hidden: 'unreviewed' }))
  const oldParameters = { capture_sha256: 'a'.repeat(64), idempotency_key_sha256: 'b'.repeat(64), heads: {}, ...oldDraft }
  reviewRefused(() => validateCaptureReview(oldParameters, retained))
  assert.deepEqual(validateCaptureLiterals(oldDraft), oldDraft)
  reviewRefused(() => validateCaptureLiterals(retained))
})

test('capture metadata is a closed literal profile with canonical date and UTC seconds', () => {
  assert.deepEqual(validateCaptureMetadata(metadata()), metadata())
  for (const change of [{ profile: 'other' }, { category: 'preference' }, { confidence_percent: 0.7 },
    { confidence_percent: '70' }, { confidence_percent: 71 }, { sensitivity: 'private' },
    { valid_from: '2026-02-30' }, { valid_from: '2026-10-1' }, { valid_from: '2026-10-02' },
    { observed_at: '2026-10-01T11:03:00.000Z' }, { observed_at: '2026-10-01T11:03:00+00:00' },
    { observed_at: '2026-02-30T11:03:00Z' }, { observed_at: 1790852580 }, { hidden: true }]) {
    reviewRefused(() => validateCaptureMetadata({ ...metadata(), ...change }))
  }
  const missing = metadata(); delete missing.sensitivity
  reviewRefused(() => validateCaptureMetadata(missing))
  const symbolic = metadata(); symbolic[Symbol('hidden')] = true
  reviewRefused(() => validateCaptureMetadata(symbolic))
  const hidden = metadata(); Object.defineProperty(hidden, 'category', { value: 'fact', enumerable: false })
  reviewRefused(() => validateCaptureMetadata(hidden))
  let getterReads = 0
  const getter = metadata(); Object.defineProperty(getter, 'profile', { enumerable: true, get: () => {
    getterReads++; return 'prime-pilot-memory-capture/v1'
  } })
  reviewRefused(() => validateCaptureMetadata(getter))
  assert.equal(getterReads, 0)
})

test('review refuses hidden draft getters and non-string digest or head values without coercion', () => {
  const capture = draft()
  let getterReads = 0
  const hiddenQuote = draft(); Object.defineProperty(hiddenQuote, 'evidence_quote', { enumerable: true, get: () => {
    getterReads++; return capture.evidence_quote
  } })
  reviewRefused(() => validateCaptureDraft(hiddenQuote))
  assert.equal(getterReads, 0)
  for (const change of [{ capture_sha256: ['a'.repeat(64)] }, { idempotency_key_sha256: ['b'.repeat(64)] },
    { heads: { remembered: ['c'.repeat(64)] } }, { heads: { other: 'c'.repeat(64) } }, { evidence_quote: [capture.evidence_quote] }]) {
    reviewRefused(() => validateCaptureReview({ ...parameters(capture), ...change }, capture))
  }
  const hiddenParameters = parameters(capture)
  Object.defineProperty(hiddenParameters, 'capture_metadata', { enumerable: true, get: () => {
    getterReads++; return metadata()
  } })
  reviewRefused(() => validateCaptureReview(hiddenParameters, capture))
  assert.equal(getterReads, 0)
})

test('new statement and evidence quote refuse unsafe formatting, filler, separators, and malformed Unicode without rewriting', () => {
  const refusedTexts = ['Exact cafe\u0301.', '\u0301', '\u200c\u200d', '\t\n ', '\u00a0\u3000',
    'x\u0000y', 'x\u000by', 'x\r\ny', 'x\u001fy', 'x\u007fy', 'x\u0080y', 'x\u0085y', 'x\u009fy',
    'x\u061cy', 'x\u200ey', 'x\u200fy', 'x\u202ay', 'x\u2066y', 'x\ufeffy', 'x\u00ady',
    'x\u2060y', 'x\u{e0001}y', 'x\u2028y', 'x\u2029y', 'x\u034fy', 'x\u115fy', 'x\u1160y', 'x\u17b4y', 'x\u17b5y',
    'x\u3164y', 'x\uffa0y', 'x\u2800y', 'x\ud800y', 'x\udc00y']
  for (const text of refusedTexts) {
    for (const field of ['statement', 'evidence_quote']) {
      const capture = { ...draft(), [field]: text }, before = structuredClone(capture)
      reviewRefused(() => validateCaptureDraft(capture))
      assert.deepEqual(capture, before)
    }
  }
  for (const text of ['Exact caf\u00e9 p\u0430ypal.', '\u65e5\u672c\u8a9e', '\u0627\u0644\u0639\u0631\u0628\u064a\u0629',
    '\u05e2\u05d1\u05e8\u05d9\u05ea', '\u0627\u200c\u0644', '\ud83d\udc69\u200d\ud83d\udcbb', 'Exact\tline\nnext < & >.']) {
    const capture = { ...draft(), statement: text, evidence_quote: text }
    assert.deepEqual(validateCaptureDraft(capture), capture)
  }
  const boundary = { ...draft(), statement: 'a'.repeat(4096), evidence_quote: 'b'.repeat(4096) }
  assert.deepEqual(validateCaptureDraft(boundary), boundary)
  reviewRefused(() => validateCaptureDraft({ ...boundary, statement: `${boundary.statement}a` }))
  reviewRefused(() => validateCaptureDraft({ ...boundary, evidence_quote: `${boundary.evidence_quote}b` }))
})

test('presentation warnings identify exact UTF-16 positions and code points without altering text', () => {
  const text = '\ud83c\udf4c p\u0430ypal\u200d'
  const warnings = capturePresentationWarnings(text)
  assert.deepEqual(warnings.map(warning => warning.code), ['format-controls', 'ascii-lookalikes', 'mixed-scripts'])
  assert.deepEqual(warnings[0].examples, [{ index: 9, code_point: 'U+200D' }])
  assert.deepEqual(warnings[1].examples, [{ index: 4, code_point: 'U+0430', resembles: 'a', script: 'Cyrillic' }])
  assert.deepEqual(warnings[2].examples, [{ index: 3, length: 6, scripts: ['Latin', 'Cyrillic'] }])
  assert.equal(text, '\ud83c\udf4c p\u0430ypal\u200d')
  assert.equal(Object.isFrozen(warnings[2].examples[0].scripts), true)
  assert.equal(capturePresentationWarnings('\u0430')[0].code, 'ascii-lookalikes')
})

test('presentation hints remain exact for historical text while new capture enforces NFC without blocking languages', () => {
  for (const text of ['Exact caf\u00e9', '\u65e5\u672c\u8a9e', '\u0627\u0644\u0639\u0631\u0628\u064a\u0629', '\u05e2\u05d1\u05e8\u05d9\u05ea']) {
    assert.deepEqual(capturePresentationWarnings(text), [])
    assert.equal(validatePilotCaptureMetadata(host(), { ...input(), statement: text }).statement, text)
  }
  const historicalNfd = 'Exact cafe\u0301'
  assert.deepEqual(capturePresentationWarnings(historicalNfd), [])
  refused(host(), { ...input(), statement: historicalNfd })
  assert.equal(historicalNfd, 'Exact cafe\u0301')
  // Permitted joiners remain exact and are still flagged for owner presentation.
  const shaping = '\u0627\u200c\u0644'
  assert.equal(capturePresentationWarnings(shaping)[0].code, 'format-controls')
  assert.equal(validatePilotCaptureMetadata(host(), { ...input(), statement: shaping }).statement, shaping)
  const bounded = capturePresentationWarnings(('a\u0430\u200d ').repeat(40))
  for (const warning of bounded) {
    assert.equal(warning.count, 40)
    assert.equal(warning.examples.length, 16)
    assert.equal(typeof warning.text, 'string')
  }
  assert.throws(() => capturePresentationWarnings(null), { message: 'memory:capture-presentation-invalid' })
  const source = readFileSync(new URL('../src/capture-presentation.mjs', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /node:|Buffer|\.normalize\(/)
})
