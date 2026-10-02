// SPDX-License-Identifier: AGPL-3.0-or-later
// Focused NEW-capture source checks. No real signer, service, database or effect.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'
import { createPrimeOwnerController } from '../src/client/controller.mjs'
import { createOwnerUiFixture } from './fixture.mjs'
import * as contracts from '../../../contracts/src/browser.mjs'
import { CAPTURE_TEXT_POLICY, validateCaptureDraft, validateCaptureReview } from '../../adapters/capture-review.mjs'

const clock = Date.parse('2030-01-01T00:00:00Z')
const metadata = () => ({profile:'prime-pilot-memory-capture/v1',category:'fact',valid_from:'2030-01-01',
  observed_at:'2030-01-01T00:00:00Z',confidence_percent:70,sensitivity:'none'})
const draft = () => ({statement:'  Captured café <b>statement</b>\n😀  ',attributed_to:'owner-edit',
  capture_metadata:metadata(),evidence_quote:'  Selected source <mark>quote differs</mark>\n& remains exact 😀  '})
const parameters = capture => ({capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),
  heads:{remembered:'aukora:aura-record:v1'},...structuredClone(capture)})
const make = () => {
  const binding = createOwnerUiFixture(contracts,{now:() => clock})
  let signerCalls = 0
  const controller = createPrimeOwnerController({now:() => clock,schedule:() => 1,unschedule() {}})
  controller.connect({...binding,passkeySigner:async input => { signerCalls++; return binding.passkeySigner(input) }})
  return {binding,controller,signerCalls:() => signerCalls,
    operation:capture => ({...binding.operation,action_type:'memory.save',canonical_parameters:parameters(capture)})}
}
const refused = error => error instanceof TypeError && error.message === 'memory:capture-review-invalid'

test('expanded NEW-capture draft preserves exact four fields and independent metadata', async () => {
  const f = make(), capture = draft(), expected = structuredClone(capture), op = f.operation(capture)
  try {
    await f.controller.login()
    const detached = validateCaptureReview(op.canonical_parameters,capture)
    assert.deepEqual(detached,expected); assert(Object.isFrozen(detached)); assert(Object.isFrozen(detached.capture_metadata))
    f.controller.setOperation(op,{memoryCapture:capture})
    capture.statement = 'Changed caller statement'; capture.capture_metadata.observed_at = '2030-01-02T00:00:00Z'
    capture.evidence_quote = 'Changed caller quote'
    await f.controller.prepare()
    const review = f.controller.getSnapshot().presentation
    assert.equal(f.controller.getSnapshot().phase,'review_ready')
    assert.equal(review.memory_review.statement,expected.statement)
    assert.equal(review.memory_review.evidence_quote,expected.evidence_quote)
    assert.deepEqual(review.memory_review.capture_metadata,expected.capture_metadata)
    assert.deepEqual(review.capture_metadata,expected.capture_metadata)
    assert.equal(review.canonical_operation,contracts.canonicalJson(op))
    assert.equal(review.operation_digest,await contracts.operationDigest(op))
    assert.equal(f.binding.counts.review,1); assert.equal(f.binding.counts.approve,0); assert.equal(f.signerCalls(),1)
  } finally { f.controller.dispose() }
})

test('missing and changed metadata or quote refuse before challenge and signer', async () => {
  const mutations = [
    ['missing metadata',(_op,options) => { delete options.memoryCapture.capture_metadata }],
    ['missing quote',(_op,options) => { delete options.memoryCapture.evidence_quote }],
    ['missing operation metadata',(op) => { delete op.canonical_parameters.capture_metadata }],
    ['missing operation quote',(op) => { delete op.canonical_parameters.evidence_quote }],
    ['changed independent quote',(_op,options) => { options.memoryCapture.evidence_quote += ' changed' }],
    ['changed operation quote',(op) => { op.canonical_parameters.evidence_quote += ' changed' }],
    ['old two-field draft',(_op,options) => { options.memoryCapture={statement:options.memoryCapture.statement,attributed_to:options.memoryCapture.attributed_to} }],
  ]
  const metadataChanges={profile:'changed-profile',category:'instruction',valid_from:'2030-01-02',
    observed_at:'2030-01-02T00:00:00Z',confidence_percent:71,sensitivity:'private'}
  for (const [key,value] of Object.entries(metadataChanges)) {
    mutations.push([`changed draft metadata ${key}`,(_op,options) => { options.memoryCapture.capture_metadata[key]=value }])
    mutations.push([`changed operation metadata ${key}`,(op) => { op.canonical_parameters.capture_metadata[key]=value }])
    mutations.push([`changed optional metadata ${key}`,(_op,options) => { options.captureMetadata[key]=value }])
  }
  // Changing both date fields remains structurally valid; literal pairing must
  // still reject it rather than accepting two independently valid metadata sets.
  mutations.push(['valid but different independent metadata dates',(_op,options) => {
    options.memoryCapture.capture_metadata.valid_from='2030-01-02'
    options.memoryCapture.capture_metadata.observed_at='2030-01-02T00:00:00Z'
  }])
  mutations.push(['valid but different optional metadata dates',(_op,options) => {
    options.captureMetadata.valid_from='2030-01-02';options.captureMetadata.observed_at='2030-01-02T00:00:00Z'
  }])
  for (const [label,mutate] of mutations) {
    const f = make(), capture = draft(), op = f.operation(capture), options={memoryCapture:capture,captureMetadata:metadata()}
    try {
      await f.controller.login(); const signerBefore=f.signerCalls()
      mutate(op,options)
      assert.throws(() => f.controller.setOperation(op,options),error => error.code==='TARGET_MISMATCH',label)
      assert.equal(f.controller.getSnapshot().presentation,null,label)
      assert.equal(f.controller.getSnapshot().operation_available,false,label)
      await f.controller.prepare(); await f.controller.approve()
      assert.equal(f.binding.counts.review,0,label); assert.equal(f.binding.counts.approve,0,label)
      assert.equal(f.signerCalls(),signerBefore,label)
    } finally { f.controller.dispose() }
  }
})

test('NEW-capture text policy rejects defined controls, fillers and non-NFC without replacing input', () => {
  assert.equal(CAPTURE_TEXT_POLICY.scope,'new-capture-only')
  assert.equal(CAPTURE_TEXT_POLICY.normal_form,'NFC-required-never-normalized')
  const unsafe=[...Array.from({length:32},(_,n)=>n).filter(n=>n!==9&&n!==10),0x7f,
    ...Array.from({length:32},(_,n)=>0x80+n),0x00ad,0x061c,0x200b,0x200e,0x200f,0x202a,0x202b,0x202c,
    0x202d,0x202e,0x2060,0x2066,0x2067,0x2068,0x2069,0xfeff,
    0x034f,0x115f,0x1160,0x17b4,0x17b5,0x2800,0x3164,0xffa0,0x2028,0x2029]
  const invalidStrings=[...unsafe.map(codepoint=>'visible'+String.fromCodePoint(codepoint)+'text'),
    '  \t\n  ','\u200c\u200d','\u0301','\ud800','\udc00','cafe\u0301','x'.repeat(4097)]
  for (const field of ['statement','evidence_quote']) for (const value of invalidStrings) {
    const capture=draft();capture[field]=value;const before=structuredClone(capture)
    assert.throws(() => validateCaptureDraft(capture),refused,`${field} ${JSON.stringify(value.slice(0,32))}`)
    assert.deepEqual(capture,before)
  }
})

test('NFC languages, confusable letters and joiners remain exact permitted NEW-capture text', () => {
  const permitted=['  café\n\t😀  ','Русский аa','Ελληνικά ΑA','العربية','שלום','नमस्ते','中文 日本語',
    'q\u0301 visible combining mark','می\u200cخواهم','👩\u200d💻','x'.repeat(4096)]
  for (const text of permitted) {
    assert.equal(text.normalize('NFC'),text)
    const capture=draft();capture.statement=text;capture.evidence_quote=text
    const before=structuredClone(capture), checked=validateCaptureReview(parameters(capture),capture)
    assert.equal(checked.statement,text);assert.equal(checked.evidence_quote,text)
    assert.deepEqual(capture,before)
  }
})

test('historical forget review retains exact original NFD bytes and script text', async () => {
  const f=make(), statement='  cafe\u0301 Русский 👩\u200d💻  ',attribution='owner-edit'
  const original=JSON.stringify({statement,attributedTo:attribution,confidence:0.7},null,2)
  const digest=createHash('sha256').update(original).digest('hex')
  // Original bytes belong to the historical record summary path, never to the
  // NEW-capture helper. This scoped check establishes review retention only.
  const summary={record_id:'historical-nfd-record',revision:'historical-nfd-revision',statement,attributed_to:attribution}
  const op={...f.binding.operation,action_type:'memory.forget',audience:'aukora-prime.memory',
    target_identity:{kind:'prime-memory',owner_subject:'aukora:1:'+'1'.repeat(64)},expected_state_version:'sha256:'+'2'.repeat(64),
    canonical_parameters:{profile:'prime-logical-forget/v1',...summary,canonical_sha256:digest,
      at:'2030-01-01T00:00:00Z',heads:{remembered:'aukora:aura-record:v1'}}}
  try {
    await f.controller.login();f.controller.setOperation(op,{recordSummary:summary});await f.controller.prepare()
    assert.equal(f.controller.getSnapshot().phase,'review_ready')
    assert.equal(f.controller.getSnapshot().presentation.forget_review.statement,statement)
    assert.equal(f.controller.getSnapshot().presentation.operation.canonical_parameters.statement,statement)
    assert.equal(original,JSON.stringify({statement,attributedTo:attribution,confidence:0.7},null,2))
    assert.notEqual(statement.normalize('NFC'),statement);assert.equal(f.binding.counts.approve,0)
  } finally {f.controller.dispose()}
})
