// SPDX-License-Identifier: AGPL-3.0-or-later
// Source correctness ONLY: actual B controller, C passkey verification/stores
// and D memory APIs. Same-process calls, synthetic P-256 credentials and the
// SQLite dialect fixture do not prove deployed UID separation or PostgreSQL.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/runtime.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {at,extraction,ok,fixture,assertSaved} from './owner-memory-fixture.mjs'

const pilotDraft=key=>({extraction_json:JSON.stringify({statement:extraction.statement}),idempotency_key:key})
const refused=result=>{assert.equal(result?.ok,false,JSON.stringify(result));return result}

async function approvedForget(t,key) {
  const f=await fixture(t,{actions:['memory.save','memory.forget']})
  await f.login();await f.prepare(pilotDraft(key+'-save'))
  await f.workflow.approveAndSave()
  const saved=f.workflow.getSnapshot();assertSaved(saved)
  const proposedSave=ok(f.replies.find(reply=>reply.method==='memory.proposeSave').result)
  assert.deepEqual(proposedSave.capture_metadata,{profile:'prime-pilot-memory-capture/v1',category:'fact',
    valid_from:at.slice(0,10),observed_at:at,confidence_percent:70,sensitivity:'none'})
  assert.equal(JSON.parse(saved.record.canonical_bytes).statement,extraction.statement)
  const proposed=ok(await f.adapters.memory.proposeForget({record_id:saved.record.record_id}))
  const operation=proposed.operation,parameters=operation.canonical_parameters
  assert.equal(operation.action_type,'memory.forget')
  assert.equal(parameters.profile,'prime-logical-forget/v1')
  assert.equal(parameters.record_id,saved.record.record_id);assert.equal(parameters.revision,saved.record.revision)
  assert.equal(parameters.canonical_sha256,sha256(Buffer.from(saved.record.canonical_bytes)))
  assert.equal(parameters.heads[saved.record.chain_domain],saved.citation.verified_head)
  assert.deepEqual(proposed.record_summary,{record_id:saved.record.record_id,revision:saved.record.revision,
    statement:extraction.statement,attributed_to:'owner'})
  f.controller.setOperation(operation,{recordSummary:proposed.record_summary})
  const review=await f.controller.prepare()
  assert.notEqual(review,null)
  assert.equal(review.canonical_operation,contracts.canonicalJson(operation))
  assert.equal(review.operation_digest,await contracts.operationDigest(operation))
  const approved=await f.controller.approve()
  assert.equal(approved.status,'APPROVED')
  assert.equal(approved.approval_proof.operation_digest,review.operation_digest)
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
  return {...f,saved,operation,proof:approved.approval_proof,input:{operation,approval_proof:approved.approval_proof}}
}

function assertLogicalForget(f,reply) {
  assert.deepEqual(reply.result,{record_id:f.saved.record.record_id,state:'tombstoned',canonical_payload_retained:true,
    physical_media_erasure:false,authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false})
  const receipt=reply.receipt
  assert.equal(receipt.kind,'prime-memory-effect/v1');assert.equal(receipt.action_type,'memory.forget');assert.equal(receipt.status,'applied')
  assert.equal(receipt.operation_id,f.operation.operation_id)
  assert.equal(receipt.operation_digest,f.proof.operation_digest)
  assert.equal(receipt.grant_id,'grant:'+f.proof.nonce)
  assert.equal(receipt.owner_subject,f.saved.record.owner_subject)
  assert.deepEqual(receipt.result,reply.result)
  const effect=f.pool.db.prepare('SELECT receipt_bytes FROM prime_memory_effects WHERE operation_id=?').get(f.operation.operation_id)
  assert.deepEqual(JSON.parse(Buffer.from(effect.receipt_bytes).toString('utf8')),receipt,'the returned receipt is the actual D ledger receipt')
  assert.equal(f.tableCount('prime_memory_tombstones'),1)
  assert.equal(f.tableCount('prime_memory_records'),1)
  const retained=f.pool.db.prepare('SELECT canonical_bytes FROM prime_memory_records WHERE record_id=?').get(f.saved.record.record_id)
  assert.equal(Buffer.from(retained.canonical_bytes).toString('utf8'),f.saved.record.canonical_bytes)
  const row=Object.values(f.state().broker.operations).find(row=>row.operation_digest===f.proof.operation_digest)
  assert.equal(row.dispatch.request_id,receipt.request_id);assert.equal(row.dispatch.request_digest,receipt.request_digest)
  assert.ok(f.state().state.consumedIds.includes('approval:'+f.proof.nonce))
}

test('statement-only pilot save followed by an actual owner-approved forget returns the genuine receipt and excludes the logically tombstoned record',async t=>{
  const f=await approvedForget(t,'owner-logical-forget')
  // Only this test harness invokes the private D indexer, establishing a
  // searchable record before testing immediate removal through approved forget.
  assert.equal((await f.memory.drainOutbox(f.boundHost())).indexed,1)
  assert.equal(ok(await f.adapters.memory.recall({query:'banana',limit:10})).records.length,1)
  const forgotten=ok(await f.adapters.memory.forget(f.input));assertLogicalForget(f,forgotten)
  assert.equal(forgotten.authority_settlement,'completed');assert.equal(forgotten.reconciliation_required,false)
  assert.equal(f.operationState(f.operation.operation_id).status,'COMPLETED')
  const row=Object.values(f.state().broker.operations).find(row=>row.operation_digest===f.proof.operation_digest)
  assert.equal(row.dispatch.receipt_digest,forgotten.receipt_digest)
  assert.equal(row.dispatch.result_digest,forgotten.receipt.result_digest)
  assert.equal(f.tableCount('prime_memory_fts'),0)
  assert.equal(ok(await f.adapters.memory.recall({query:'banana',limit:10})).records.length,0)
  const read={record_id:f.saved.record.record_id,revision:f.saved.record.revision}
  assert.equal(refused(await f.adapters.memory.status(read)).reason,'memory:record-tombstoned')
  assert.equal(refused(await f.adapters.memory.cite({...read,retained_head:null})).reason,'memory:record-tombstoned')
  const replay=refused(await f.adapters.memory.forget(f.input))
  assert.equal(replay.error_code,'RECONCILIATION_REQUIRED')
  assert.equal(f.count('memory.forget'),1);assert.equal(f.count('owner.approvalComplete'),2)
  assert.equal(f.tableCount('prime_memory_effects'),2)
})

test('a real applied logical forget retains its receipt when C settlement delivery is pending and never repeats the effect',async t=>{
  const f=await approvedForget(t,'owner-forget-pending-settlement')
  f.setSettlementFailure(true)
  const forgotten=ok(await f.adapters.memory.forget(f.input));assertLogicalForget(f,forgotten)
  assert.equal(forgotten.authority_settlement,'pending');assert.equal(forgotten.reconciliation_required,true)
  assert.equal(f.operationState(f.operation.operation_id).status,'DISPATCHED')
  f.setSettlementFailure(false)
  assert.equal(refused(await f.adapters.memory.forget(f.input)).error_code,'RECONCILIATION_REQUIRED')
  assert.equal(f.count('memory.forget'),1);assert.equal(f.tableCount('prime_memory_effects'),2)
  assert.equal(f.operationState(f.operation.operation_id).status,'DISPATCHED')
})

test('a lost logical-forget reply after the actual effect leaves the caller uncertain and blocks actor replay',async t=>{
  const f=await approvedForget(t,'owner-forget-lost-reply')
  f.delivery.set('memory.forget',reply=>{ok(reply);throw new Error('synthetic logical-forget reply lost after the actual effect')})
  await assert.rejects(f.adapters.memory.forget(f.input),/synthetic logical-forget reply lost/)
  const actual=ok(f.replies.find(reply=>reply.method==='memory.forget').result);assertLogicalForget(f,actual)
  assert.equal(f.operationState(f.operation.operation_id).status,'COMPLETED')
  f.delivery.delete('memory.forget')
  assert.equal(refused(await f.adapters.memory.forget(f.input)).error_code,'RECONCILIATION_REQUIRED')
  assert.equal(f.count('memory.forget'),1);assert.equal(f.tableCount('prime_memory_effects'),2)
  assert.equal(f.tableCount('prime_memory_tombstones'),1)
})
