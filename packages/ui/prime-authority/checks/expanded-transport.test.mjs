// SPDX-License-Identifier: AGPL-3.0-or-later
// Bounded transport/content consistency checks with synthetic authority replies.
// No real enrollment, crypto verification, database, effect or browser claim.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../../contracts/src/browser.mjs'
import {createPrimeTransport} from '../../adapters/transport.mjs'
import {validateSavedCaptureContent} from '../../adapters/save-recovery.mjs'
import {createOwnerUiFixture} from './fixture.mjs'

const clock = Date.parse('2030-01-01T00:00:00Z')
const metadata = () => ({profile:'prime-pilot-memory-capture/v1',category:'fact',valid_from:'2030-01-01',
  observed_at:'2030-01-01T00:00:00Z',confidence_percent:70,sensitivity:'none'})
const draft = () => ({statement:'  Exact café < & >\n\t🙂  ',attributed_to:'owner-edit',capture_metadata:metadata(),
  evidence_quote:'Source quote differs from statement: Москва café < & > 🙂'})
function fixture() {
  const binding = createOwnerUiFixture(contracts,{now:()=>clock})
  const capture = draft()
  const operation = {...binding.operation,action_type:'memory.save',
    canonical_parameters:{capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),heads:{},...structuredClone(capture)}}
  const transport = createPrimeTransport({...binding,now:()=>clock})
  return {binding,capture,operation,transport,
    login:()=>transport.login({owner_id:operation.owner_id,kind:'passkey'})}
}
const mismatch = error => error?.code === 'TARGET_MISMATCH'

test('expanded independent draft is mandatory and all four fields bind before authority review',async()=>{
  const f=fixture();await f.login()
  const variants = [undefined,{statement:f.capture.statement,attributed_to:f.capture.attributed_to},
    {...f.capture,statement:'Changed statement'}, {...f.capture,attributed_to:'agent'},
    {...f.capture,evidence_quote:'Changed selected source quote'},
    {...f.capture,capture_metadata:{...f.capture.capture_metadata,observed_at:'2030-01-02T00:00:00Z',valid_from:'2030-01-02'}}]
  for (const memoryCapture of variants) await assert.rejects(f.transport.prepareApproval(f.operation,{memoryCapture}),mismatch)
  assert.equal(f.binding.counts.review,0)
  const view=await f.transport.prepareApproval(f.operation,{memoryCapture:f.capture})
  assert.deepEqual(view.memory_review,{...f.capture,capture_sha256:'a'.repeat(64)})
  assert.deepEqual(view.capture_metadata,f.capture.capture_metadata)
  assert.equal(Object.isFrozen(view.memory_review.capture_metadata),true)
  assert.equal(await f.transport.approve(view,{kind:'passkey'}).then(result=>result.status),'APPROVED')
  assert.equal(f.binding.counts.approve,1)
})

test('optional old metadata sibling cannot replace or disagree with independent reviewed metadata',async()=>{
  const f=fixture();await f.login()
  const mutations = [{profile:'other'},{category:'preference'},{valid_from:'2029-12-31'},
    {observed_at:'2030-01-02T00:00:00Z',valid_from:'2030-01-02'},{confidence_percent:71},{sensitivity:'health'}]
  for (const change of mutations) await assert.rejects(f.transport.prepareApproval(f.operation,
    {memoryCapture:f.capture,captureMetadata:{...metadata(),...change}}),mismatch)
  assert.equal(f.binding.counts.review,0)
  const view=await f.transport.prepareApproval(f.operation,{memoryCapture:f.capture,captureMetadata:metadata()})
  assert.deepEqual(view.capture_metadata,view.memory_review.capture_metadata)
})

test('expanded review snapshot is detached before challenge wait and survives caller mutation through signing',async()=>{
  const f=fixture();await f.login()
  let release,entered
  const gate=new Promise(resolve=>{release=resolve}),ready=new Promise(resolve=>{entered=resolve})
  const challenge=f.binding.authority.approvalChallenge
  f.binding.authority.approvalChallenge=async input=>{entered();await gate;return challenge(input)}
  const expected=structuredClone(f.capture),pending=f.transport.prepareApproval(f.operation,{memoryCapture:f.capture})
  await ready
  f.capture.statement='Mutated caller text';f.capture.evidence_quote='Mutated caller quote'
  f.capture.capture_metadata.observed_at='2030-01-02T00:00:00Z';f.capture.capture_metadata.valid_from='2030-01-02'
  f.operation.canonical_parameters.statement='Mutated proposed text'
  release()
  const view=await pending
  assert.deepEqual(view.memory_review,{...expected,capture_sha256:'a'.repeat(64)})
  assert.equal((await f.transport.approve(view,{kind:'passkey'})).status,'APPROVED')
  assert.equal(f.binding.counts.approve,1)
})

function saved(capture) {
  const source={sessionId:'synthetic-source',seq:3,sha256:'c'.repeat(64)}
  const evidence=[{log:source.sessionId,turn:source.seq,turnDigest:source.sha256,quote:capture.evidence_quote}]
  const original={statement:capture.statement,attributedTo:capture.attributed_to,category:'fact',validFrom:'2030-01-01',
    observedAt:'2030-01-01T00:00:00Z',confidence:0.7,sensitivity:'none',source,evidence,
    legacy_annotation:'Cafe\u0301\u2028\u2060'}
  return {canonical_bytes:JSON.stringify(original,null,2),source_event_digest:'sha256:'+source.sha256,evidence:structuredClone(evidence)}
}

test('saved content equals every reviewed metadata value and exact selected source evidence without byte rewriting',()=>{
  const capture=draft(),record=saved(capture),bytes=record.canonical_bytes
  assert.equal(validateSavedCaptureContent(record,capture),record)
  assert.equal(record.canonical_bytes,bytes)
  const changes=[{statement:'changed'},{attributedTo:'agent'},{category:'preference'},
    {validFrom:'2030-01-02'},{observedAt:'2030-01-02T00:00:00Z'},{confidence:0.71},{sensitivity:'health'}]
  for(const change of changes){
    const changed={...record,canonical_bytes:JSON.stringify({...JSON.parse(bytes),...change})}
    assert.throws(()=>validateSavedCaptureContent(changed,capture),mismatch)
  }
  for(const field of ['log','turn','turnDigest','quote']){
    const changed=structuredClone(record)
    changed.evidence[0][field]=field==='turn'?4:'changed'
    assert.throws(()=>validateSavedCaptureContent(changed,capture),mismatch)
  }
  const changedQuote=structuredClone(record),original=JSON.parse(bytes)
  original.evidence[0].quote='changed selected source quote';changedQuote.evidence[0].quote=original.evidence[0].quote
  changedQuote.canonical_bytes=JSON.stringify(original)
  assert.throws(()=>validateSavedCaptureContent(changedQuote,capture),mismatch)
  assert.throws(()=>validateSavedCaptureContent({...record,source_event_digest:'sha256:'+'d'.repeat(64)},capture),mismatch)
  assert.throws(()=>validateSavedCaptureContent({...record,canonical_bytes:'not donor JSON'},capture),mismatch)
  assert.equal(record.canonical_bytes,bytes)
})
