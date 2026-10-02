// SPDX-License-Identifier: AGPL-3.0-or-later
// Source correctness ONLY: ordinary retries through actual C/D source services.
// Disposable passkeys and SQLite dialect fixtures do not establish deployed
// owner/process isolation or PostgreSQL durability acceptance.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../contracts/src/runtime.mjs'
import {draft,ok,fixture,assertSaved} from './owner-memory-fixture.mjs'

const refused=result=>{assert.equal(result?.ok,false,JSON.stringify(result));return result}
const operationRow=(f,operation)=>{
  const row=Object.values(f.state().broker.operations).find(value=>value.operation_digest===contracts.operationDigest(operation))
  assert.ok(row,'the operation must have an actual persisted C row')
  return row
}
const authorityFacts=(f,operation)=>{
  const state=f.state()
  return structuredClone({operation:operationRow(f,operation),prepared:state.prepared,
    consumedIds:state.state.consumedIds,receiptHead:state.state.receiptHead})
}
const rowBytes=row=>{
  assert.ok(row,'the genuine saved row must remain present')
  return Object.fromEntries(Object.entries(row).map(([key,value])=>[key,
    ArrayBuffer.isView(value)?Buffer.from(value.buffer,value.byteOffset,value.byteLength).toString('hex'):value]))
}
const ledgerFacts=(f,request,saved)=>({
  effect:rowBytes(f.pool.db.prepare('SELECT * FROM prime_memory_effects WHERE owner_subject=? AND operation_id=?')
    .get(f.auth.identity.subject,request.operation.operation_id)),
  intent:rowBytes(f.pool.db.prepare('SELECT * FROM prime_memory_intents WHERE owner_subject=? AND operation_id=?')
    .get(f.auth.identity.subject,request.operation.operation_id)),
  request:rowBytes(f.pool.db.prepare('SELECT * FROM prime_memory_requests WHERE owner_subject=? AND idempotency_key=?')
    .get(f.auth.identity.subject,request.idempotency_key)),
  record:rowBytes(f.pool.db.prepare('SELECT * FROM prime_memory_records WHERE owner_subject=? AND record_id=? AND revision=?')
    .get(f.auth.identity.subject,saved.record.record_id,saved.record.revision)),
  heads:f.pool.db.prepare('SELECT * FROM prime_memory_heads WHERE owner_subject=? ORDER BY chain_domain')
    .all(f.auth.identity.subject).map(rowBytes),
  counts:Object.fromEntries(['prime_runtime_workflows','prime_memory_intents','prime_memory_effects',
    'prime_memory_requests','prime_memory_records'].map(table=>[table,f.tableCount(table)])),
})
const firstSave=(f,operation)=>{
  const request=f.calls.find(call=>call.method==='memory.save'&&call.input.operation.operation_id===operation.operation_id)
  const reply=f.replies.find(reply=>reply.method==='memory.save'&&reply.result.receipt?.operation_id===operation.operation_id)
  assert.ok(request,'the request comes from the actual ordinary approval/save flow')
  return {request:structuredClone(request.input),saved:ok(reply?.result)}
}
function assertLedgerReceipt(ledger,saved) {
  assert.deepEqual(JSON.parse(Buffer.from(ledger.effect.result_bytes,'hex').toString('utf8')),saved.record)
  assert.deepEqual(JSON.parse(Buffer.from(ledger.effect.receipt_bytes,'hex').toString('utf8')),saved.receipt)
  assert.equal(ledger.effect.request_id,saved.receipt.request_id)
  assert.equal(ledger.effect.request_digest,saved.receipt.request_digest)
  assert.equal(ledger.intent.request_id,saved.receipt.request_id)
  assert.equal(ledger.intent.request_digest,saved.receipt.request_digest)
}
async function assertFactualSave(f,request,saved,reply,receiptDigest=saved.receipt_digest) {
  ok(reply);contracts.validateContract('MemoryRecord',reply.record)
  assert.deepEqual(reply.record,saved.record,'retry returns the original retained D result')
  assert.deepEqual(reply.receipt,saved.receipt,'retry returns the original genuine D receipt')
  assert.equal(reply.receipt_digest,receiptDigest)
  assert.equal(reply.receipt.grant_id,'grant:'+request.approval_proof.nonce)
  assert.equal(reply.authority_settlement,'completed');assert.equal(reply.reconciliation_required,false)
  assert.equal(f.operationState(request.operation.operation_id).status,'COMPLETED')
  const reference=await f.workflowStore.get(f.boundHost(),request.operation.operation_id)
  assert.equal(reference.phase,'saved');assert.equal(reference.record_id,saved.record.record_id)
  assert.equal(reference.request_id,saved.receipt.request_id)
  assert.equal(reference.request_digest,saved.receipt.request_digest)
  assert.equal(reference.receipt_digest,receiptDigest)
}

test('an exact successful save retry returns the same genuine receipt before advanced heads, including after server restart',async t=>{
  const f=await fixture(t);await f.login()
  const operation=await f.prepare(draft('ordinary-completed-save-retry'))
  await f.workflow.approveAndSave();assertSaved(f.workflow.getSnapshot())
  const {request,saved}=firstSave(f,operation)
  assert.equal(saved.authority_settlement,'completed');assert.equal(saved.reconciliation_required,false)
  const ledger=ledgerFacts(f,request,saved),authority=authorityFacts(f,operation),signatures=f.signerCalls()
  const reference=await f.workflowStore.get(f.boundHost(),operation.operation_id)
  assertLedgerReceipt(ledger,saved)
  assert.notDeepEqual(Object.fromEntries(ledger.heads.map(head=>[head.chain_domain,head.hash])),operation.canonical_parameters.heads,
    'the completed save has already advanced the heads bound by its approval')
  assert.ok(authority.consumedIds.includes('approval:'+request.approval_proof.nonce))
  assert.ok(Array.isArray(authority.prepared));assert.equal(authority.prepared.length,1)
  assert.equal(authority.operation.status,'COMPLETED')
  assert.equal(authority.operation.dispatch.request_id,saved.receipt.request_id)
  assert.equal(authority.operation.dispatch.request_digest,saved.receipt.request_digest)
  assert.equal(authority.operation.dispatch.receipt_digest,saved.receipt_digest)
  for(const count of Object.values(ledger.counts))assert.equal(count,1)
  const retry=ok(await f.bridgeCall('memory.save',structuredClone(request)))
  await assertFactualSave(f,request,saved,retry)
  assert.deepEqual(ledgerFacts(f,request,saved),ledger)
  assert.deepEqual(authorityFacts(f,operation),authority,'receipt delivery must not reserve or dispatch another effect')
  assert.deepEqual(await f.workflowStore.get(f.boundHost(),operation.operation_id),reference)
  assert.equal(f.signerCalls(),signatures);assert.equal(f.count('owner.approvalComplete'),1)
  const previous={authority:f.auth.service,memory:f.memory,workflowStore:f.workflowStore,bridge:f.bridge}
  const restarted=await f.restartServer()
  for(const name of Object.keys(previous))assert.notEqual(restarted[name],previous[name],'restart replaces '+name+' while retaining its persisted facts')
  assert.equal(ok(f.auth.service.authenticateSession({session_token:request.session_token})).owner_id,operation.owner_id)
  const reopened=ok(await f.bridgeCall('memory.save',structuredClone(request)))
  await assertFactualSave(f,request,saved,reopened)
  assert.deepEqual(ledgerFacts(f,request,saved),ledger)
  assert.deepEqual(authorityFacts(f,operation),authority)
  assert.deepEqual(await f.workflowStore.get(f.boundHost(),operation.operation_id),reference)
  assert.equal(f.signerCalls(),signatures);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.count('memory.proposeSave'),1);assert.equal(f.count('memory.save'),3)
  assert.equal((await f.bridge.capability()).state,'unqualified')
})

test('retry of a genuinely saved but unsettled operation refuses until actual receipt recovery, then returns the original effect',async t=>{
  const f=await fixture(t);await f.login()
  const operation=await f.prepare(draft('ordinary-pending-save-retry'))
  f.setSettlementFailure(true)
  await f.workflow.approveAndSave();assertSaved(f.workflow.getSnapshot())
  const {request,saved}=firstSave(f,operation)
  assert.equal(saved.authority_settlement,'pending');assert.equal(saved.reconciliation_required,true)
  assert.equal(f.operationState(operation.operation_id).status,'DISPATCHED')
  const ledger=ledgerFacts(f,request,saved),authority=authorityFacts(f,operation),signatures=f.signerCalls()
  const attempted=await f.workflowStore.get(f.boundHost(),operation.operation_id)
  assert.equal(attempted.phase,'attempted');assertLedgerReceipt(ledger,saved)
  assert.ok(Array.isArray(authority.prepared));assert.equal(authority.prepared.length,1)
  assert.ok(authority.consumedIds.includes('approval:'+request.approval_proof.nonce))
  for(const count of Object.values(ledger.counts))assert.equal(count,1)
  const retry=refused(await f.bridgeCall('memory.save',structuredClone(request)))
  assert.equal(retry.record,undefined);assert.equal(retry.receipt,undefined)
  assert.deepEqual(ledgerFacts(f,request,saved),ledger)
  assert.deepEqual(authorityFacts(f,operation),authority)
  assert.deepEqual(await f.workflowStore.get(f.boundHost(),operation.operation_id),attempted)
  assert.equal(f.operationState(operation.operation_id).status,'DISPATCHED')
  assert.equal(f.signerCalls(),signatures);assert.equal(f.count('owner.approvalComplete'),1)
  f.setSettlementFailure(false)
  const settlements=f.settlementInputs.length
  const recovered=ok(await f.adapters.memory.recover({operation_id:operation.operation_id}))
  assert.equal(recovered.state,'saved');assert.equal(recovered.authority_settlement,'completed')
  assert.equal(recovered.reconciliation_required,false)
  assert.deepEqual(recovered.result,saved.record);assert.deepEqual(recovered.receipt,saved.receipt)
  assert.match(recovered.receipt_digest,/^sha256:[a-f0-9]{64}$/)
  assert.ok(f.settlementInputs.length>settlements,'recovery delivers the existing genuine D receipt to actual C')
  const completed=authorityFacts(f,operation),reference=await f.workflowStore.get(f.boundHost(),operation.operation_id)
  assert.equal(completed.operation.status,'COMPLETED')
  assert.deepEqual(completed.prepared,authority.prepared);assert.deepEqual(completed.consumedIds,authority.consumedIds)
  assert.deepEqual(completed.receiptHead,authority.receiptHead)
  assert.equal(completed.operation.dispatch.request_id,authority.operation.dispatch.request_id)
  assert.equal(completed.operation.dispatch.request_digest,authority.operation.dispatch.request_digest)
  const factual=ok(await f.bridgeCall('memory.save',structuredClone(request)))
  await assertFactualSave(f,request,saved,factual,recovered.receipt_digest)
  assert.deepEqual(ledgerFacts(f,request,saved),ledger)
  assert.deepEqual(authorityFacts(f,operation),completed)
  assert.deepEqual(await f.workflowStore.get(f.boundHost(),operation.operation_id),reference)
  for(const input of f.settlementInputs.slice(settlements))assert.deepEqual(input,f.settlementInputs[0],
    'recovery and completed retry deliver only the original operation, grant, request and receipt')
  assert.equal(f.signerCalls(),signatures);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.count('memory.proposeSave'),1);assert.equal(f.count('memory.save'),3)
  assert.equal((await f.bridge.capability()).public_routes,'unavailable')
})
