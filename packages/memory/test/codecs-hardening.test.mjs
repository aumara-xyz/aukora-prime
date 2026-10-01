// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildRememberedNote, buildRememberedRecord } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'
import { canonicalJSON, stageKiraMemoryRecord, kiraRecordContentSha256 } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { AURA_RECORD_DOMAIN, auraEntryHash, isCreation, parseOriginal, requireRedactableChain,
  sha256, validateOriginal, verifyChain, verifyMembership, verifySources } from '../src/codecs.mjs'

// Package-local synthetic records only. These checks do not exercise PostgreSQL or authority.
const owner = 'synthetic-codec-owner', at = '2026-10-01T11:03:00Z'
const eventBytes = Buffer.from(JSON.stringify({ type:'turn', text:'Synthetic owner chooses banana.', seq:0, at })+'\n')
const source = { sessionId:'synthetic-codec-session', sessionTitle:'Synthetic codec fixture', seq:0, at, sha256:sha256(eventBytes) }
const encode = (record, space, ending = '\n') => Buffer.from(JSON.stringify(record, null, space)+ending)
const creation = (fields, prev = AURA_RECORD_DOMAIN) => ({ ...fields, prev, hash:auraEntryHash(prev, fields) })
const candidate = { subject:owner, kind:'observation', source:[], content:{decimal:1.5}, links:[], privacy:'local', createdAt:at }

function noteFixture({ prime = false, bodyAtCapture = null } = {}) {
  const note = buildRememberedNote({ category:'fact', statement:'Synthetic codec note about banana.', attributedTo:'owner',
    evidence:[{log:source.sessionId, turn:0, turnDigest:source.sha256, quote:'banana'}], validFrom:'2026-10-01', observedAt:at,
    confidence:0.7, sensitivity:'none', privacy:'local', subject:owner, salt:'1'.repeat(64), source })
  const contentHash = sha256(Buffer.from(note.statement))
  // Historical donor aura markers are opaque pointers. Only Prime's writer declares the id/content formula.
  const marker = prime ? sha256(Buffer.from(note.id+'\0'+contentHash)) : '2'.repeat(64)
  const stored = { ...note, contentHash, aura:{index:0, entryHash:marker}, bodyAtCapture }
  const entry = creation({sequence:1, op:'remember', id:note.id, at, tier:'remembered',
    by:prime ? 'prime.capture/v1' : 'kira-capture/v1', contentHash, entryHash:marker, bodyAtCapture})
  return { note, stored, entry, marker }
}

test('synthetic historical byte forms retain envelope IDs, salt, opaque aura and separate byte hashes', () => {
  const { note, stored, entry, marker } = noteFixture()
  assert.equal(note.id, 'rem:d39d7fdc63499c2dbc130659e88c409000b250f15635038cf0cf16e7fcb1fe13')
  assert.notEqual(marker, sha256(Buffer.from(note.id+'\0'+stored.contentHash)))
  const digests = new Set()
  for (const space of [undefined, 2]) for (const ending of ['', '\n']) {
    const bytes = encode(stored, space, ending), meta = validateOriginal(bytes, owner)
    assert.equal(meta.id, note.id); assert.equal(meta.record.salt, note.salt)
    assert.equal(meta.record.confidence, 0.7); assert.equal(meta.digest, sha256(bytes))
    assert.equal(verifyMembership(meta, [entry], 1), entry)
    assert.equal(verifySources(meta, new Map([[source.sha256,eventBytes]])).verdict, 'VERIFIED')
    digests.add(meta.digest)
  }
  assert.equal(digests.size, 4, 'serializer and final LF are covered separately from the envelope ID')
  const legacy = buildRememberedRecord({kind:'fact', text:note.statement, createdAt:at, source,
    aura:{index:0,entryHash:marker}, subject:owner, privacy:'local'})
  assert.equal(legacy.id, '074f41f945e943f441aadd92eef715637f2fc5a6b666cc8262367b31fada7a64')
  const meta = validateOriginal(encode(legacy, 2), owner)
  assert.equal(meta.id, legacy.id); assert.equal(meta.format, 'remembered-record/v0')
  assert.equal(verifyMembership(meta, [{...entry,id:legacy.id}], 1).id, legacy.id)
})

test('synthetic v0 decimals retain their donor profile and v1 refuses numeric decimal reinterpretation', () => {
  const v0 = stageKiraMemoryRecord(candidate).record, meta = validateOriginal(encode(v0,2),owner)
  assert.equal(meta.id, 'kira:e6258c2939c9f4466c279fdd10f7dd413dfc28e892918f6e8ae1e15173edb931')
  assert.equal(meta.format,'v0'); assert.equal(meta.canon,'aukora:canon-json:v0-ecmascript-number')
  assert.equal(meta.record.content.decimal,1.5)
  assert.throws(()=>stageKiraMemoryRecord(candidate,{format:'v1'}),{code:'kira.stage:content-unsupported-number'})
  const v1 = stageKiraMemoryRecord({...candidate,content:{decimal:'1.5'}},{format:'v1'}).record
  assert.equal(validateOriginal(encode(v1,undefined,''),owner).canon,'aukora:canon-json:v1-safe-integer')
  assert.throws(()=>validateOriginal(encode({...v1,content:{decimal:1.5}}),owner),{code:'memory:kira-record-invalid'})
  const entry = creation({sequence:1,verdict:'settled',key:v0.recordId,
    contentSha256:kiraRecordContentSha256(v0),operation:'memory.put'})
  assert.equal(isCreation(entry),true); assert.equal(verifyMembership(meta,[entry],1),entry)
  assert.throws(()=>verifyMembership(meta,[{...entry,contentSha256:'f'.repeat(64)}],1),
    {code:'memory:content-commitment-changed'})
})

test('synthetic BOM, CRLF, redundant whitespace and lossy JSON encodings refuse without changing IDs', () => {
  const { stored } = noteFixture(), pretty = encode(stored,2)
  assert.throws(()=>validateOriginal(Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),pretty]),owner),
    {code:'memory:original-encoding-invalid'})
  for (const text of [pretty.toString().replace(/\n/g,'\r\n'), ' '+JSON.stringify(stored),
    pretty.toString()+'\n', JSON.stringify(stored).replace('0.7','7e-1')]) {
    assert.throws(()=>validateOriginal(Buffer.from(text),owner),{code:'memory:record-not-canonical'})
  }
  assert.throws(()=>parseOriginal(Buffer.from('{"number":9007199254740993}')),{code:'memory:json-number-invalid'})
  assert.throws(()=>parseOriginal(Buffer.from('{"value":"\\ud800"}')),{code:'memory:json-string-invalid'})
  assert.throws(()=>parseOriginal(Buffer.from('{"\\ud800":"value"}')),{code:'memory:json-string-invalid'})
  assert.throws(()=>parseOriginal(Buffer.from('{"duplicate":1,"duplicate":2}')),{code:'memory:original-json-invalid'})
})

test('synthetic same-ID derived metadata cannot contradict its exact creation chain', () => {
  const { note, stored, entry } = noteFixture({prime:true,bodyAtCapture:{version:1,source:'synthetic-host-report'}})
  assert.throws(()=>validateOriginal(encode({...stored,contentHash:'f'.repeat(64)}),owner),
    {code:'memory:content-commitment-changed'})
  for (const index of [-1,0.5,'0']) assert.throws(()=>validateOriginal(encode({...stored,aura:{...stored.aura,index}}),owner),
    {code:'memory:aura-invalid'})
  assert.throws(()=>validateOriginal(encode({...stored,aura:{...stored.aura,entryHash:'invalid'}}),owner),
    {code:'memory:aura-invalid'})
  const indexChanged = validateOriginal(encode({...stored,aura:{...stored.aura,index:1}}),owner)
  assert.equal(indexChanged.id,note.id)
  assert.throws(()=>verifyMembership(indexChanged,[entry],1),{code:'memory:membership-index-changed'})
  const bodyChanged = validateOriginal(encode({...stored,bodyAtCapture:{version:1,source:'changed-host-report'}}),owner)
  assert.equal(bodyChanged.id,note.id)
  assert.throws(()=>verifyMembership(bodyChanged,[entry],1),{code:'memory:capture-body-changed'})
  assert.throws(()=>verifyMembership(validateOriginal(encode(stored),owner),[{...entry,contentHash:'f'.repeat(64)}],1),
    {code:'memory:content-commitment-changed'})
  const pointerChanged = validateOriginal(encode({...stored,aura:{index:0,entryHash:'3'.repeat(64)}}),owner)
  assert.equal(pointerChanged.id,note.id)
  assert.throws(()=>verifyMembership(pointerChanged,[entry],1),{code:'memory:membership-pointer-changed'})
  assert.throws(()=>verifyMembership(pointerChanged,[{...entry,entryHash:'3'.repeat(64)}],1),
    {code:'memory:membership-marker-changed'})
  for (const mutation of [{text:'altered alias'},{kind:'preference'},{createdAt:'2026-10-01T11:04:00Z'}]) {
    assert.throws(()=>validateOriginal(encode({...stored,...mutation}),owner),{code:'memory:note-alias-changed'})
  }
  assert.throws(()=>validateOriginal(encode({...stored,label:'approved'}),owner),{code:'memory:note-label-invalid'})
  assert.throws(()=>validateOriginal(encode({...stored,injected:'unhashed extra field'}),owner),
    {code:'memory:note-fields-invalid'})
})

test('synthetic chains retain donor compact encoding and refuse byte-only or hash mutations', () => {
  const { entry } = noteFixture(), compact = JSON.stringify(entry)+'\n'
  assert.equal(verifyChain(Buffer.from(compact),entry.hash).head,entry.hash)
  assert.equal(verifyChain(Buffer.from(canonicalJSON(entry)+'\n'),entry.hash).head,entry.hash)
  for (const text of [compact.replace(/\n/g,'\r\n'),' '+compact]) {
    assert.throws(()=>verifyChain(Buffer.from(text),entry.hash),{code:'memory:chain-not-canonical'})
  }
  assert.throws(()=>verifyChain(Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(compact)]),entry.hash),
    {code:'memory:original-encoding-invalid'})
  assert.throws(()=>verifyChain(Buffer.from(JSON.stringify({...entry,at:'2026-10-01T11:04:00Z'})+'\n'),entry.hash),
    {code:'memory:chain-broken'})
  assert.throws(()=>verifyChain(Buffer.from(compact), 'f'.repeat(64)),{code:'memory:retained-head-mismatch'})
})

test('synthetic redacted export metadata is opaque and admits exact donor settled and accepted literals', () => {
  const { entry } = noteFixture({prime:true}), opaque = {...entry,originKey:'4'.repeat(64)}
  requireRedactableChain([opaque])
  const mutations = {id:'plaintext payload',recordId:'plaintext payload',key:{payload:'secret'},at:'plaintext payload',
    tier:'plaintext payload',op:'plaintext payload',operation:'plaintext payload',verdict:'plaintext payload',
    contentHash:'plaintext payload',originKey:'plaintext payload',bodyAtCapture:{payload:'secret'},
    by:'plaintext payload',scope:'plaintext payload',hash:'plaintext payload',sequence:'plaintext payload'}
  for (const [key,value] of Object.entries(mutations)) assert.throws(()=>requireRedactableChain([{...opaque,[key]:value}]),
    {code:'memory:redacted-chain-contains-payload'}, key)
  assert.throws(()=>requireRedactableChain([{...opaque,at:'2026-02-30T11:03:00Z'}]),
    {code:'memory:redacted-chain-contains-payload'})
  for (const verdict of ['settled','accepted']) {
    const v0 = stageKiraMemoryRecord(candidate).record
    const donor = creation({sequence:1,verdict,key:v0.recordId,contentSha256:kiraRecordContentSha256(v0),operation:'memory.put'})
    assert.equal(isCreation(donor),true); requireRedactableChain([donor])
  }
  assert.throws(()=>requireRedactableChain([creation({sequence:1,verdict:'approved',key:'kira:'+'5'.repeat(64),operation:'memory.put'})]),
    {code:'memory:redacted-chain-contains-payload'})
})
