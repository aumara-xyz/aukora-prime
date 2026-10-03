// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure synthetic scope checks only: no pool, retention files, keys, bootstrap, or effects.
import test from 'node:test'
import assert from 'node:assert/strict'
import { REDUCED_PILOT_SCOPE, REDUCED_PILOT_CAPTURE_ORIGIN, validateReducedPilotScope,
  validateCaptureOrigin, captureProfileForOrigin, validateCaptureScopeParity }
  from '../src/reduced-pilot-scope.mjs'
import { PILOT_CAPTURE_PROFILE, REDUCED_PILOT_CAPTURE_PROFILE, CAPTURE_METADATA_FIELDS,
  validateCaptureDraft, validateCaptureReview, validateCaptureMetadata }
  from '../src/capture-review.mjs'
import { validatePilotCaptureMetadata } from '../src/pilot-capture.mjs'
import { buildRememberedNote, recomputeNoteId } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { sha256, validateOriginal } from '../src/codecs.mjs'

const at = '2026-10-02T11:03:00Z', text = 'Exact synthetic reduced pilot < & >.'
const eventBytes = Buffer.from(JSON.stringify({type:'turn',text,seq:0,at}) + '\n')
const source = {sessionId:'synthetic-reduced-pilot',seq:0,at,sha256:sha256(eventBytes)}
const extraction = () => ({category:'fact',statement:text,validFrom:'2026-10-02',observedAt:at,confidence:0.7,sensitivity:'none'})
const host = origin => ({owner_id:'synthetic-owner-id',owner_subject:'synthetic-owner-subject',task_id:'synthetic-task',
  attributedTo:'owner',scope:'owner',privacy:'local',source:{...source},...(origin === undefined ? {} : {origin})})
const metadata = profile => ({profile,category:'fact',valid_from:'2026-10-02',observed_at:at,confidence_percent:70,sensitivity:'none'})
const draft = profile => ({statement:text,attributed_to:'owner',capture_metadata:metadata(profile),evidence_quote:text})
const failScope = fn => assert.throws(fn,{code:'memory:reduced-pilot-scope-refused'})
const failPilot = fn => assert.throws(fn,{code:'memory:pilot-capture-profile-refused'})

test('scope is exact eight inert factual fields, immutable, with no elevated claim', () => {
  assert.equal(REDUCED_PILOT_CAPTURE_PROFILE,'REDUCED-GUARANTEE/prime-pilot-memory-capture/v1')
  assert.deepEqual(REDUCED_PILOT_SCOPE,{version:1,kind:'prime-reduced-guarantee-pilot/v1',guarantee:'REDUCED-GUARANTEE',
    deployment:'same-host',owner_approval:'passkey-required',storage:'postgresql-required',authority_independence:false,hardware_display:false})
  assert.equal(Object.isFrozen(REDUCED_PILOT_CAPTURE_ORIGIN),true)
  assert.equal(Object.isFrozen(REDUCED_PILOT_CAPTURE_ORIGIN.pilot_scope),true)
  for(const key of Object.keys(REDUCED_PILOT_SCOPE)) {
    const missing = {...REDUCED_PILOT_SCOPE}; delete missing[key]
    failScope(() => validateReducedPilotScope(missing))
    failScope(() => validateReducedPilotScope({...REDUCED_PILOT_SCOPE,[key]:null}))
  }
  for(const change of [{enrolled:true},{authority_independence:true},{hardware_display:true},{owner_approval:'optional'},
    {storage:'sqlite'},{deployment:'independent-host'},{version:'1'},{guarantee:'FULL-GUARANTEE'}])
    failScope(() => validateReducedPilotScope({...REDUCED_PILOT_SCOPE,...change}))
  let reads = 0
  const getter = {...REDUCED_PILOT_SCOPE}
  Object.defineProperty(getter,'guarantee',{enumerable:true,get:() => {reads++; return 'REDUCED-GUARANTEE'}})
  failScope(() => validateReducedPilotScope(getter)); assert.equal(reads,0)
  failScope(() => validateReducedPilotScope(new Proxy(REDUCED_PILOT_SCOPE,{})))
  const symbolic = {...REDUCED_PILOT_SCOPE}; symbolic[Symbol('extra')] = true
  failScope(() => validateReducedPilotScope(symbolic))
})

test('trusted origin selects exactly one paired profile; normal captures remain accepted', () => {
  assert.equal(captureProfileForOrigin(),PILOT_CAPTURE_PROFILE)
  assert.equal(captureProfileForOrigin({by:'prime.capture/v1'}),PILOT_CAPTURE_PROFILE)
  assert.equal(captureProfileForOrigin(REDUCED_PILOT_CAPTURE_ORIGIN),REDUCED_PILOT_CAPTURE_PROFILE)
  assert.deepEqual(validateCaptureOrigin(REDUCED_PILOT_CAPTURE_ORIGIN),REDUCED_PILOT_CAPTURE_ORIGIN)
  for(const origin of [{by:'other'},{by:'prime.capture/v1',extra:true},{by:'prime.capture/v1',pilot_scope:undefined},
    {by:'prime.capture/v1',pilot_scope:{}},{pilot_scope:REDUCED_PILOT_SCOPE}]) {
    failScope(() => validateCaptureOrigin(origin))
    failPilot(() => validatePilotCaptureMetadata(host(origin),extraction()))
  }
  for(const origin of [undefined,{by:'prime.capture/v1'},REDUCED_PILOT_CAPTURE_ORIGIN]) {
    const h = host(origin), input = extraction(), before = structuredClone({h,input})
    assert.equal(validatePilotCaptureMetadata(h,input),input)
    assert.deepEqual({h,input},before)
  }
  const explicitUndefined = {...host(),origin:undefined}
  failPilot(() => validatePilotCaptureMetadata(explicitUndefined,extraction()))
})

test('mismatched profile/origin and extraction policy overrides refuse', () => {
  failScope(() => validateCaptureScopeParity({by:'prime.capture/v1'},REDUCED_PILOT_CAPTURE_PROFILE))
  failScope(() => validateCaptureScopeParity(REDUCED_PILOT_CAPTURE_ORIGIN,PILOT_CAPTURE_PROFILE))
  assert.deepEqual(validateCaptureScopeParity(REDUCED_PILOT_CAPTURE_ORIGIN,REDUCED_PILOT_CAPTURE_PROFILE),REDUCED_PILOT_CAPTURE_ORIGIN)
  for(const change of [{confidence:0.71},{sensitivity:'private'},{origin:REDUCED_PILOT_CAPTURE_ORIGIN},
    {capture_metadata:metadata(REDUCED_PILOT_CAPTURE_PROFILE)},{pilot_scope:REDUCED_PILOT_SCOPE}])
    failPilot(() => validatePilotCaptureMetadata(host(REDUCED_PILOT_CAPTURE_ORIGIN),{...extraction(),...change}))
})

test('browser review remains closed six metadata fields and binds the explicit reduced literal', () => {
  assert.deepEqual(CAPTURE_METADATA_FIELDS,['profile','category','valid_from','observed_at','confidence_percent','sensitivity'])
  for(const profile of [PILOT_CAPTURE_PROFILE,REDUCED_PILOT_CAPTURE_PROFILE]) assert.deepEqual(validateCaptureMetadata(metadata(profile)),metadata(profile))
  for(const profile of ['reduced','prime-reduced-guarantee-pilot/v1','REDUCED-GUARANTEE',null,[REDUCED_PILOT_CAPTURE_PROFILE]])
    assert.throws(() => validateCaptureMetadata(metadata(profile)),{message:'memory:capture-review-invalid'})
  const reduced = validateCaptureDraft(draft(REDUCED_PILOT_CAPTURE_PROFILE))
  const parameters = {capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),heads:{},...reduced}
  assert.deepEqual(validateCaptureReview(parameters,reduced),reduced)
  assert.throws(() => validateCaptureReview({...parameters,capture_metadata:metadata(PILOT_CAPTURE_PROFILE)},reduced),
    {message:'memory:capture-review-invalid'})
  assert.notEqual(canonicalJSON(parameters),canonicalJSON({...parameters,capture_metadata:metadata(PILOT_CAPTURE_PROFILE)}))
})

test('new donor record ID, original bytes, and capture hash all cover the fixed scope', () => {
  const evidence = [{log:source.sessionId,turn:source.seq,turnDigest:source.sha256,quote:text}]
  const noteInput = {...extraction(),subject:host().owner_subject,attributedTo:'owner',scope:'owner',privacy:'local',
    source,evidence,salt:'1'.repeat(64)}
  const normal = buildRememberedNote({...noteInput,origin:{by:'prime.capture/v1'}})
  const reduced = buildRememberedNote({...noteInput,origin:validateCaptureOrigin(REDUCED_PILOT_CAPTURE_ORIGIN)})
  const contentHash = sha256(Buffer.from(reduced.statement))
  const candidate = {...reduced,contentHash,aura:{index:0,entryHash:sha256(Buffer.from(reduced.id + '\0' + contentHash))},bodyAtCapture:null}
  const original = Buffer.from(JSON.stringify(candidate) + '\n'), checked = validateOriginal(original,host().owner_subject)
  assert.notEqual(normal.id,reduced.id)
  assert.equal(checked.id,reduced.id); assert.equal(recomputeNoteId(checked.record),reduced.id)
  assert.deepEqual(checked.record.origin,REDUCED_PILOT_CAPTURE_ORIGIN)
  assert.equal(checked.record.grantsAuthority,false)
  assert.equal(checked.record.confidence,0.7)
  validateCaptureScopeParity(checked.record.origin,REDUCED_PILOT_CAPTURE_PROFILE)
  const changed = structuredClone(checked.record); changed.origin.pilot_scope.hardware_display = true
  assert.throws(() => validateOriginal(Buffer.from(JSON.stringify(changed) + '\n'),host().owner_subject),
    {code:'memory:note-id-changed'})
  const capture = origin => ({input:extraction(),subject:host().owner_subject,task:host().task_id,source,evidence:null,
    attribution:'owner',scope:'owner',privacy:'local',origin,bodyAtCapture:null,events:[source.sha256]})
  assert.notEqual(sha256(Buffer.from(canonicalJSON(capture(normal.origin)))),sha256(Buffer.from(canonicalJSON(capture(reduced.origin)))))
  assert.equal(sha256(original),checked.digest)
  assert.deepEqual(validateOriginal(original,host().owner_subject).record,checked.record)
})
