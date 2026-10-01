// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure pilot capture profile checks; no runtime qualification is claimed.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {preparePilotCapture,PILOT_CAPTURE_PROFILE} from '../src/pilot-capture.mjs'

const sourceAt='2026-10-01T11:03:00Z'
const statement='  banana <tag>&\n\t🍌  '
const fixedCapture={statement,category:'fact',validFrom:'2026-10-01',observedAt:sourceAt,
  confidence:0.7,sensitivity:'none'}
const fixedMetadata={profile:'prime-pilot-memory-capture/v1',category:'fact',valid_from:'2026-10-01',
  observed_at:sourceAt,confidence_percent:70,sensitivity:'none'}

test('statement-only pilot capture preserves the exact literal and fixes metadata from source time',()=>{
  const result=preparePilotCapture({statement},sourceAt)
  assert.equal(PILOT_CAPTURE_PROFILE,'prime-pilot-memory-capture/v1')
  assert.deepEqual(result,{capture:fixedCapture,metadata:fixedMetadata})
  assert.equal(result.capture.statement,statement)
  const laterSourceAt='2026-10-02T00:00:01Z'
  assert.deepEqual(preparePilotCapture({statement},laterSourceAt),{
    capture:{...fixedCapture,validFrom:'2026-10-02',observedAt:laterSourceAt},
    metadata:{...fixedMetadata,valid_from:'2026-10-02',observed_at:laterSourceAt},
  })
})

test('pilot capture returns detached immutable copies',()=>{
  const input={...fixedCapture}
  const result=preparePilotCapture(input,sourceAt)
  input.statement='Changed caller statement'
  input.category='preference'
  assert.deepEqual(result,{capture:fixedCapture,metadata:fixedMetadata})
  assert.notEqual(result.capture,input)
  assert.equal(Object.isFrozen(input),false)
  for(const value of [result,result.capture,result.metadata])assert.equal(Object.isFrozen(value),true)
  assert.throws(()=>{result.capture.statement='Changed returned statement'},TypeError)
  assert.throws(()=>{result.metadata.confidence_percent=90},TypeError)
  assert.throws(()=>{result.capture={statement:'Replacement'}},TypeError)
  const second=preparePilotCapture({...fixedCapture},sourceAt)
  assert.deepEqual(second,result)
  assert.notEqual(second,result)
  assert.notEqual(second.capture,result.capture)
  assert.notEqual(second.metadata,result.metadata)
})

test('older pilot callers may provide the exact fixed metadata',()=>{
  const input={...fixedCapture},before={...input}
  assert.deepEqual(preparePilotCapture(input,sourceAt),{capture:fixedCapture,metadata:fixedMetadata})
  assert.deepEqual(input,before)
})

for(const [field,value] of [
  ['category','preference'],
  ['validFrom','2026-09-30'],
  ['observedAt','2026-10-01T11:03:01Z'],
  ['confidence',0.9],
  ['sensitivity','high'],
]){
  test('pilot capture refuses a caller '+field+' override',()=>{
    assert.throws(()=>preparePilotCapture({statement,[field]:value},sourceAt),
      {name:'TypeError',message:'INVALID: pilot capture metadata is fixed'})
  })
}

test('pilot capture refuses links outside its closed input grammar',()=>{
  assert.throws(()=>preparePilotCapture({statement,links:['https://example.test/note']},sourceAt),
    {name:'TypeError',message:'INVALID: pilot capture profile'})
})
