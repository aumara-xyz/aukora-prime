// SPDX-License-Identifier: AGPL-3.0-or-later
// Source correctness ONLY: W1 fail-closed limitation through real B/C/D services.
// Synthetic P-256 credentials, same-process restarts and the SQLite dialect
// fixture do not establish owner enrollment, isolation or PostgreSQL durability.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/runtime.mjs'
import {draft,ok,fixture} from './owner-memory-fixture.mjs'

const refused=result=>{assert.equal(result?.ok,false,JSON.stringify(result));return result}
const authorityFacts=(f,operation)=>{
  const state=f.state(),row=Object.values(state.broker.operations)
    .find(value=>value.operation_digest===contracts.operationDigest(operation))
  assert.ok(row,'approval must belong to an actual persisted C operation')
  return structuredClone({operation:row,prepared:state.prepared,
    consumedIds:state.state.consumedIds,receiptHead:state.state.receiptHead})
}
const assertNoEffect=f=>{
  for(const table of ['prime_memory_intents','prime_memory_effects','prime_memory_requests',
    'prime_memory_records','prime_memory_replay_fences'])assert.equal(f.tableCount(table),0,table)
}

test('a real pre-reservation refusal leaves an attempted journal unresolved despite no C consumption or D intent',async t=>{
  const f=await fixture(t);await f.login()
  const input=draft('pre-reservation-altered-proof')
  const operation=await f.prepare(input)
  const approved=await f.controller.approve()
  assert.equal(approved?.status,'APPROVED')
  assert.equal(f.controller.getSnapshot().phase,'approved')
  const proof=approved.approval_proof
  contracts.validateContract('ApprovalProof',proof)
  const authority=authorityFacts(f,operation)
  assert.equal(authority.operation.status,'APPROVED')
  assert.deepEqual(authority.operation.approval.proof,proof)
  assert.equal(authority.prepared.length,0)
  assert.equal(authority.consumedIds.includes('approval:'+proof.nonce),false)
  assertNoEffect(f)
  const proposed=await f.workflowStore.get(f.boundHost(),operation.operation_id)
  assert.equal(proposed.phase,'proposed')

  // Keep every binding and the genuine assertion; alter only the envelope's
  // expiry. Both bridge/D shallow checks accept this live, bounded timestamp.
  // C reserve refuses its mismatch with the actual persisted approved proof
  // before kernel preparation, consumption or D's durable intent insertion.
  const altered=structuredClone(proof)
  altered.expiry=new Date(Date.parse(proof.expiry)-1000).toISOString()
  contracts.validateContract('ApprovalProof',altered)
  assert.ok(Date.parse(altered.expiry)>Date.now())
  assert.ok(Date.parse(altered.expiry)<=Date.parse(operation.expiry))
  assert.notEqual(altered.expiry,proof.expiry)
  const session=f.calls.find(call=>call.method==='owner.approvalComplete').input.session_token
  const result=refused(await f.bridgeCall('memory.save',{
    ...input,session_token:session,operation,approval_proof:altered,
  }))
  assert.equal(result.reason,'memory:authority-refused','D must have reached actual C reservation')
  const attempted=await f.workflowStore.get(f.boundHost(),operation.operation_id)
  assert.deepEqual(attempted,{...proposed,phase:'attempted'})
  assert.deepEqual(authorityFacts(f,operation),authority)
  assertNoEffect(f)
  const signatures=f.signerCalls()

  // W1 remains deliberately fail closed: an attempted reference has no
  // authoritative not-consumed/known-unsent reconciliation receipt to close it.
  // Reopening the genuine services cannot manufacture that missing evidence.
  for(const reopen of [false,true]) {
    if(reopen)await f.restartServer()
    const recovered=ok(await f.adapters.memory.recover({operation_id:operation.operation_id}))
    assert.equal(recovered.state,'unknown');assert.equal(recovered.reconciliation_required,true)
    assert.equal(recovered.operation_id,operation.operation_id)
    assert.equal(recovered.operation_digest,contracts.operationDigest(operation))
    for(const field of ['result','receipt','receipt_digest','authority_settlement','citation','index'])
      assert.equal(recovered[field],null)
    assert.deepEqual(await f.workflowStore.get(f.boundHost(),operation.operation_id),attempted)
  }
  const next=refused(await f.adapters.memory.proposeSave(draft('pre-reservation-fresh-key-blocked')))
  assert.equal(next.error_code,'RECONCILIATION_REQUIRED')
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
  assert.deepEqual(authorityFacts(f,operation),authority)
  assertNoEffect(f)
  assert.equal(f.tableCount('prime_runtime_workflows'),1)
  assert.equal(f.signerCalls(),signatures);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.count('memory.save'),1,'recovery and fresh proposal refusal must not retry the effect')
  assert.equal(f.settlementCalls(),0)
})
