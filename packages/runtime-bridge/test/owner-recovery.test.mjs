// SPDX-License-Identifier: AGPL-3.0-or-later
// Source correctness ONLY: real B controller, C passkey/stores and D effects.
// Same-process delivery gates, disposable synthetic credentials and the SQLite
// dialect fixture do not establish deployed isolation or PostgreSQL durability.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/runtime.mjs'
import {draft,ok,fixture,assertSaved,assertUnknown} from './owner-memory-fixture.mjs'

const refused=result=>{assert.equal(result?.ok,false,JSON.stringify(result));return result}
const fromBytes=value=>JSON.parse(Buffer.from(value).toString('utf8'))
const effectFor=(f,operation)=>{
  const row=f.pool.db.prepare('SELECT result_bytes,receipt_bytes FROM prime_memory_effects WHERE operation_id=?').get(operation.operation_id)
  assert.ok(row,'recovery must use an actual committed D effect')
  return {result:fromBytes(row.result_bytes),receipt:fromBytes(row.receipt_bytes)}
}
const saveReply=(f,operation)=>ok(f.replies.find(reply=>reply.method==='memory.save'
  &&reply.result.receipt?.operation_id===operation.operation_id)?.result)

async function assertRecoveredSave(f,operation,recovered,effect) {
  assert.equal(recovered.state,'saved');assert.equal(recovered.reconciliation_required,false)
  assert.equal(recovered.operation_id,operation.operation_id)
  assert.equal(recovered.operation_digest,await contracts.operationDigest(operation))
  assert.equal(recovered.action_type,'memory.save')
  contracts.validateContract('MemoryRecord',recovered.result)
  assert.deepEqual(recovered.result,effect.result)
  assert.deepEqual(recovered.receipt,effect.receipt,'recovery returns the unchanged genuine D ledger receipt')
  assert.equal(recovered.receipt.operation_digest,recovered.operation_digest)
  assert.equal(recovered.receipt.result.canonical_bytes,recovered.result.canonical_bytes)
  assert.equal(recovered.authority_settlement,'completed')
  assert.match(recovered.receipt_digest,/^sha256:[a-f0-9]{64}$/)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(recovered.citation.verdict,'VERIFIED')
  assert.equal(recovered.citation.record_id,recovered.result.record_id)
  assert.equal(recovered.citation.revision,recovered.result.revision)
  assert.equal(recovered.citation.grants_authority,false)
  assert.equal(recovered.index.saved,true);assert.equal(recovered.index.index_status,'pending')
  assert.equal(recovered.index.indexed,false);assert.equal(recovered.index.searchable,false)
  const reference=await f.workflowStore.get(f.boundHost(),operation.operation_id)
  assert.equal(reference.phase,'saved');assert.equal(reference.record_id,recovered.result.record_id)
  assert.equal(reference.request_id,recovered.receipt.request_id)
  assert.equal(reference.request_digest,recovered.receipt.request_digest)
  assert.equal(reference.receipt_digest,recovered.receipt_digest)
}

test('remount after a lost actual save reply recovers its genuine completed receipt without another effect',async t=>{
  const f=await fixture(t);await f.login()
  const operation=await f.prepare(draft('recovery-lost-save-reply'))
  f.delivery.set('memory.save',reply=>{ok(reply);throw new Error('synthetic delivery loss after the actual committed save')})
  await f.workflow.approveAndSave();assertUnknown(f.workflow.getSnapshot())
  const actual=saveReply(f,operation),effect=effectFor(f,operation)
  assert.deepEqual(actual.receipt,effect.receipt)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  f.delivery.delete('memory.save')
  const fresh=await f.remount(),signatures=f.signerCalls()
  const recovered=ok(await fresh.adapters.memory.recover({operation_id:null}))
  await assertRecoveredSave(f,operation,recovered,effect)
  assert.equal(recovered.result.canonical_bytes,actual.record.canonical_bytes)
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.signerCalls(),signatures,'factual recovery requires no new approval signature')
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  assert.deepEqual(effectFor(f,operation),effect)
})

test('a reviewed proposal with no save recovers as known unsent and permits a fresh idempotency key',async t=>{
  const f=await fixture(t);await f.login()
  const operation=await f.prepare(draft('recovery-reviewed-unsent'))
  assert.equal(f.count('owner.approvalComplete'),0);assert.equal(f.count('memory.save'),0)
  assert.equal(f.tableCount('prime_memory_intents'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
  const fresh=await f.remount(),signatures=f.signerCalls()
  const recovered=ok(await fresh.adapters.memory.recover({operation_id:operation.operation_id}))
  assert.equal(recovered.state,'known_unsent');assert.equal(recovered.reconciliation_required,false)
  assert.equal(recovered.operation_id,operation.operation_id)
  assert.equal(recovered.operation_digest,await contracts.operationDigest(operation))
  assert.equal(recovered.action_type,'memory.save')
  for(const key of ['result','receipt','receipt_digest','authority_settlement','citation','index'])assert.equal(recovered[key],null)
  assert.equal((await f.workflowStore.get(f.boundHost(),operation.operation_id)).phase,'known_unsent')
  assert.equal((await f.workflowStore.list(f.boundHost(),{active:true})).items.length,0)
  const next=await fresh.prepare(draft('recovery-reviewed-fresh-key'))
  assert.notEqual(next.operation_id,operation.operation_id)
  assert.notEqual(next.canonical_parameters.idempotency_key_sha256,operation.canonical_parameters.idempotency_key_sha256)
  assert.equal(f.signerCalls(),signatures,'review and recovery do not approve the old or new proposal')
  assert.equal(f.count('memory.proposeSave'),2);assert.equal(f.count('memory.save'),0)
  assert.equal(f.count('owner.approvalComplete'),0)
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
})

test('recovery with restored C settlement delivery resends only the actual committed receipt',async t=>{
  const f=await fixture(t);await f.login()
  const operation=await f.prepare(draft('recovery-pending-settlement'))
  f.setSettlementFailure(true)
  await f.workflow.approveAndSave();assertSaved(f.workflow.getSnapshot())
  assert.equal(f.workflow.getSnapshot().authority_settlement,'pending')
  assert.equal(f.workflow.getSnapshot().reconciliation_required,true)
  assert.equal(f.operationState(operation.operation_id).status,'DISPATCHED')
  const effect=effectFor(f,operation),settlements=f.settlementInputs.length
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  f.setSettlementFailure(false)
  const fresh=await f.remount(),signatures=f.signerCalls()
  const recovered=ok(await fresh.adapters.memory.recover({operation_id:operation.operation_id}))
  await assertRecoveredSave(f,operation,recovered,effect)
  assert.ok(f.settlementInputs.length>settlements,'recovery sends existing receipt evidence to actual C')
  for(const input of f.settlementInputs.slice(settlements)) {
    assert.deepEqual(input.operation,operation)
    assert.deepEqual(input.receipt,effect.receipt)
    assert.equal(input.request_id,effect.receipt.request_id)
    assert.equal(input.request_digest,effect.receipt.request_digest)
  }
  assert.equal(f.signerCalls(),signatures);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.count('memory.save'),1);assert.equal(f.tableCount('prime_memory_records'),1)
  assert.equal(f.tableCount('prime_memory_effects'),1);assert.deepEqual(effectFor(f,operation),effect)
})

test('a durable dispatched intent without an effect remains unknown after remount and blocks a fresh proposal',async t=>{
  const f=await fixture(t);await f.login()
  const operation=await f.prepare(draft('recovery-unresolved-durable-intent'))
  f.pool.failAfterDispatch=true
  await f.workflow.approveAndSave();assertUnknown(f.workflow.getSnapshot())
  assert.equal(f.operationState(operation.operation_id).status,'OUTCOME_UNKNOWN')
  assert.equal(f.tableCount('prime_memory_intents'),1)
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
  const proof=f.calls.find(call=>call.method==='memory.save').input.approval_proof
  assert.ok(f.state().state.consumedIds.includes('approval:'+proof.nonce))
  f.pool.failAfterDispatch=false
  const fresh=await f.remount(),signatures=f.signerCalls()
  const recovered=ok(await fresh.adapters.memory.recover({operation_id:null}))
  assert.equal(recovered.state,'unknown');assert.equal(recovered.reconciliation_required,true)
  assert.equal(recovered.operation_id,operation.operation_id)
  assert.equal(recovered.operation_digest,await contracts.operationDigest(operation))
  assert.equal(recovered.action_type,'memory.save')
  for(const key of ['result','receipt','receipt_digest','authority_settlement','citation','index'])assert.equal(recovered[key],null)
  assert.equal((await f.workflowStore.get(f.boundHost(),operation.operation_id)).phase,'attempted')
  const next=refused(await fresh.adapters.memory.proposeSave(draft('recovery-blocked-fresh-key')))
  assert.equal(next.error_code,'RECONCILIATION_REQUIRED')
  assert.equal(f.operationState(operation.operation_id).status,'OUTCOME_UNKNOWN')
  assert.ok(f.state().state.consumedIds.includes('approval:'+proof.nonce))
  assert.equal(f.signerCalls(),signatures);assert.equal(f.count('memory.save'),1)
  assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.tableCount('prime_runtime_workflows'),1)
  assert.equal(f.tableCount('prime_memory_intents'),1)
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
})
