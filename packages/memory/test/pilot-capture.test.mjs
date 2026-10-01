// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { PILOT_CAPTURE_POLICY, validatePilotCaptureMetadata } from '../src/pilot-capture.mjs'
import { capturePresentationWarnings } from '../src/capture-presentation.mjs'

const at = '2026-10-01T11:03:00Z'
const host = () => ({ owner_id: 'synthetic-owner', owner_subject: 'synthetic-owner-subject', task_id: 'synthetic-task',
  conversation_id: 'synthetic-conversation', privacy: 'local', scope: 'owner', attributedTo: 'owner',
  source: { sessionId: 'synthetic-session', seq: 0, at, sha256: 'a'.repeat(64) }, events: [new Uint8Array([1])] })
const input = () => ({ category: 'fact', statement: 'Exact synthetic banana < & >.', validFrom: '2026-10-01',
  observedAt: at, confidence: 0.7, sensitivity: 'none' })
const refused = (h, extraction) => assert.throws(() => validatePilotCaptureMetadata(h, extraction),
  { code: 'memory:pilot-capture-profile-refused' })

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

test('reviewed attribution stays explicit and Unicode spelling remains exact', () => {
  for (const attribution of ['owner', 'owner-voice', 'owner-edit', 'backfill', 'lane-requester', 'dream', 'agent']) {
    assert.equal(validatePilotCaptureMetadata({ ...host(), attributedTo: attribution }, input()).statement, input().statement)
  }
  const decomposed = { ...input(), statement: 'Exact cafe\u0301 p\u0430ypal statement.' }
  assert.equal(validatePilotCaptureMetadata(host(), decomposed), decomposed)
  assert.equal(decomposed.statement.includes('e\u0301'), true)
  assert.notEqual(decomposed.statement, decomposed.statement.normalize('NFC'))
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

test('presentation hints do not block languages, rely on normalization, or claim exhaustive detection', () => {
  for (const text of ['Exact cafe\u0301', '\u65e5\u672c\u8a9e', '\u0627\u0644\u0639\u0631\u0628\u064a\u0629', '\u05e2\u05d1\u05e8\u05d9\u05ea']) {
    assert.deepEqual(capturePresentationWarnings(text), [])
    assert.equal(validatePilotCaptureMetadata(host(), { ...input(), statement: text }).statement, text)
  }
  // Cf characters are flagged for presentation, including legitimate shaping; they are never removed.
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
