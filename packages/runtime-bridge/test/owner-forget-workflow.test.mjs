// SPDX-License-Identifier: AGPL-3.0-or-later
// Source correctness ONLY: actual B controller, C passkey verification/stores,
// and D APIs/ledger receipts. Disposable synthetic credentials, same-process
// server object remounts and SQLite SQL fixtures do not establish deployed
// owner/process isolation, OS process restart or PostgreSQL durability.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/runtime.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {createOwnerForgetWorkflow} from '../src/owner-forget-workflow.mjs'
import {extraction,ok,fixture,assertSaved} from './owner-memory-fixture.mjs'

const fromBytes=value=>JSON.parse(Buffer.from(value).toString('utf8'))
const mount=(t,services)=>{
  const workflow=createOwnerForgetWorkflow({controller:services.controller,memory:services.adapters.memory,contracts})
  t.after(()=>workflow.dispose())
  return workflow
}
const effectFor=(f,operation)=>{
  const row=f.pool.db.prepare('SELECT result_bytes,receipt_bytes FROM prime_memory_effects WHERE operation_id=?').get(operation.operation_id)
  assert.ok(row,'the forget outcome must come from the actual D effect ledger')
  return {result:fromBytes(row.result_bytes),receipt:fromBytes(row.receipt_bytes)}
}
const logicalResult=record_id=>({record_id,state:'tombstoned',canonical_payload_retained:true,physical_media_erasure:false,
  authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false})

async function seeded(t,key){
  const f=await fixture(t,{actions:['memory.save','memory.forget']})
  await f.login()
  await f.prepare({extraction_json:JSON.stringify({statement:extraction.statement}),idempotency_key:key+'-save'})
  await f.workflow.approveAndSave()
  const saved=f.workflow.getSnapshot();assertSaved(saved)
  const workflow=mount(t,f)
  return {...f,saved,forgetWorkflow:workflow}
}
async function prepareForget(workflow,services,record_id){
  const proposed=await workflow.proposeForget({record_id})
  assert.equal(proposed.phase,'proposed')
  assert.equal(proposed.operation.action_type,'memory.forget')
  assert.notEqual(await services.controller.prepare(),null)
  assert.equal(services.controller.getSnapshot().phase,'review_ready')
  return proposed.operation
}
function assertForgotten(snapshot,f,operation,effect){
  assert.equal(snapshot.phase,'forgotten');assert.equal(snapshot.approval,'approved')
  assert.equal(snapshot.forget,'forgotten');assert.equal(snapshot.forgotten,true)
  assert.deepEqual(snapshot.result,logicalResult(f.saved.record.record_id))
  assert.deepEqual(snapshot.result,effect.result)
  assert.deepEqual(snapshot.receipt,effect.receipt,'the coordinator exposes the unchanged genuine D receipt')
  assert.equal(snapshot.receipt.action_type,'memory.forget');assert.equal(snapshot.receipt.status,'applied')
  assert.equal(snapshot.receipt.operation_id,operation.operation_id)
  assert.equal(snapshot.receipt.owner_subject,f.saved.record.owner_subject)
  assert.deepEqual(snapshot.receipt.result,snapshot.result)
  assert.equal(snapshot.authority_settlement,'completed');assert.equal(snapshot.reconciliation_required,false)
  assert.match(snapshot.receipt_digest,/^sha256:[a-f0-9]{64}$/)
  for(const key of ['saved','save','record','memory_capture','citation','index'])assert.equal(Object.hasOwn(snapshot,key),false)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.tableCount('prime_memory_tombstones'),1);assert.equal(f.tableCount('prime_memory_records'),1)
  const retained=f.pool.db.prepare('SELECT canonical_bytes FROM prime_memory_records WHERE record_id=?').get(f.saved.record.record_id)
  assert.equal(Buffer.from(retained.canonical_bytes).toString('utf8'),f.saved.record.canonical_bytes)
}

test('coalesced owner approval forgets once with the exact signed literals and genuine D receipt',async t=>{
  const f=await seeded(t,'forget-workflow-approved'),workflow=f.forgetWorkflow
  const first=workflow.proposeForget({record_id:f.saved.record.record_id})
  assert.equal(workflow.proposeForget({record_id:f.saved.record.record_id}),first)
  const proposed=await first,operation=proposed.operation,parameters=operation.canonical_parameters
  assert.deepEqual(Object.keys(parameters).sort(),['profile','record_id','revision','canonical_sha256','at','heads','statement','attributed_to'].sort())
  assert.equal(parameters.profile,'prime-logical-forget/v1');assert.equal(parameters.record_id,f.saved.record.record_id)
  assert.equal(parameters.revision,f.saved.record.revision)
  assert.equal(parameters.canonical_sha256,sha256(Buffer.from(f.saved.record.canonical_bytes)))
  assert.equal(parameters.heads[f.saved.record.chain_domain],f.saved.citation.verified_head)
  assert.equal(parameters.statement,extraction.statement);assert.equal(parameters.attributed_to,'owner')
  assert.deepEqual(proposed.record_summary,{record_id:parameters.record_id,revision:parameters.revision,
    statement:parameters.statement,attributed_to:parameters.attributed_to})
  assert.equal(proposed.operation_digest,await contracts.operationDigest(operation))
  assert.notEqual(await f.controller.prepare(),null)
  const review=f.controller.getSnapshot().presentation
  assert.equal(contracts.canonicalJson(review.operation),contracts.canonicalJson(operation))
  assert.equal(review.operation_digest,proposed.operation_digest)
  const signatures=f.signerCalls(),pending=workflow.approveAndForget()
  assert.equal(workflow.approveAndForget(),pending)
  const forgotten=await pending,effect=effectFor(f,operation)
  assertForgotten(forgotten,f,operation,effect)
  const call=f.calls.find(item=>item.method==='memory.forget')
  assert.deepEqual(call.input.operation,operation)
  assert.equal(forgotten.receipt.grant_id,'grant:'+call.input.approval_proof.nonce)
  assert.equal(forgotten.receipt.operation_digest,proposed.operation_digest)
  assert.equal(f.signerCalls(),signatures+1)
  assert.equal(f.count('memory.forget'),1);assert.equal(f.count('owner.approvalComplete'),2)
  assert.equal(f.tableCount('prime_memory_effects'),2)
  assert.equal((await workflow.approveAndForget()).error_code,'REPLAYED')
  assert.equal(f.count('memory.forget'),1)
})

test('a lost actual forget reply recovers after server object remount without another effect or signature',async t=>{
  const f=await seeded(t,'forget-workflow-lost-reply'),workflow=f.forgetWorkflow
  const operation=await prepareForget(workflow,f,f.saved.record.record_id)
  f.delivery.set('memory.forget',reply=>{ok(reply);throw new Error('synthetic delivery loss after the genuine forget effect')})
  const uncertain=await workflow.approveAndForget()
  assert.equal(uncertain.phase,'outcome_unknown');assert.equal(uncertain.forget,'unknown')
  assert.equal(uncertain.forgotten,null);assert.equal(uncertain.reconciliation_required,true)
  assert.equal(uncertain.receipt,null)
  const effect=effectFor(f,operation)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.tableCount('prime_memory_effects'),2);assert.equal(f.tableCount('prime_memory_tombstones'),1)
  f.delivery.delete('memory.forget');workflow.dispose()
  const fresh=await f.remount(),recoveredWorkflow=mount(t,fresh),signatures=f.signerCalls()
  const pending=recoveredWorkflow.recover()
  assert.equal(recoveredWorkflow.recover(),pending)
  const recovered=await pending
  assertForgotten(recovered,f,operation,effect)
  assert.equal(recovered.operation,null);assert.equal(recovered.record_summary,null);assert.equal(recovered.operation_digest,null)
  assert.equal(recovered.recovery_status,'forgotten');assert.equal(recovered.recovery_operation_id,operation.operation_id)
  assert.equal(recovered.recovery_operation_digest,await contracts.operationDigest(operation))
  assert.equal((await fresh.workflowStore.get(f.boundHost(),operation.operation_id)).phase,'forgotten')
  assert.equal(f.signerCalls(),signatures);assert.equal(f.count('owner.approvalComplete'),2)
  assert.equal(f.count('memory.forget'),1);assert.equal(f.tableCount('prime_memory_effects'),2)
  assert.deepEqual(effectFor(f,operation),effect)
})

test('an unsent forget remains active unknown and refuses a fresh proposal and approval',async t=>{
  const f=await seeded(t,'forget-workflow-known-unsent'),workflow=f.forgetWorkflow
  const operation=await prepareForget(workflow,f,f.saved.record.record_id)
  assert.equal(f.count('memory.forget'),0);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.tableCount('prime_memory_tombstones'),0);assert.equal(f.tableCount('prime_memory_effects'),1)
  workflow.dispose()
  const fresh=await f.remount(),recoveredWorkflow=mount(t,fresh),signatures=f.signerCalls()
  const recovered=await recoveredWorkflow.recover({operation_id:operation.operation_id})
  assert.equal(recovered.phase,'outcome_unknown');assert.equal(recovered.recovery_status,'unknown')
  assert.equal(recovered.recovery_operation_id,operation.operation_id)
  assert.equal(recovered.recovery_operation_digest,await contracts.operationDigest(operation))
  assert.equal(recovered.reconciliation_required,true);assert.equal(recovered.forgotten,null)
  assert.equal(recovered.approval,'unknown');assert.equal(recovered.forget,'unknown')
  assert.equal(recovered.error_code,'RECONCILIATION_REQUIRED')
  for(const key of ['operation','record_summary','result','receipt','receipt_digest','authority_settlement'])assert.equal(recovered[key],null)
  const reference=await fresh.workflowStore.get(f.boundHost(),operation.operation_id)
  assert.equal(reference.phase,'proposed')
  assert.deepEqual((await fresh.workflowStore.list(f.boundHost(),{active:true})).items,[reference])
  const calls=f.calls.length
  const next=await recoveredWorkflow.proposeForget({record_id:f.saved.record.record_id})
  assert.equal(next.phase,'outcome_unknown');assert.equal(next.reconciliation_required,true)
  assert.equal(next.error_code,'RECONCILIATION_REQUIRED')
  assert.equal((await recoveredWorkflow.approveAndForget()).error_code,'RECONCILIATION_REQUIRED')
  assert.equal(f.operationState(operation.operation_id).status,'PROPOSED')
  assert.deepEqual(await fresh.workflowStore.get(f.boundHost(),operation.operation_id),reference)
  assert.equal(f.signerCalls(),signatures,'recovery and refused fresh proposal do not sign the old proposal')
  assert.equal(f.calls.length,calls,'unknown recovery blocks proposal and approval before C/D calls')
  assert.equal(f.count('memory.proposeForget'),1);assert.equal(f.count('memory.forget'),0)
  assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.tableCount('prime_runtime_workflows'),2)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_tombstones'),0)
  assert.equal(f.tableCount('prime_memory_effects'),1)
})
