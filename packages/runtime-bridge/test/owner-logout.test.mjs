// SPDX-License-Identifier: AGPL-3.0-or-later
// TEST ONLY: ordinary owner logout through the real B/C/D source join.
// Disposable passkeys and the SQLite SQL fixture do not establish deployed
// owner isolation, process boundaries or PostgreSQL durability acceptance.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {draft,ok,fixture} from './owner-memory-fixture.mjs'

const session=f=>f.replies.filter(reply=>reply.method==='owner.loginComplete'&&reply.result.ok).at(-1).result.session_token
const deniedSession=(authority,session_token)=>{
  const result=authority.authenticateSession({session_token})
  assert.equal(result.ok,false);assert.equal(result.error_code,'UNAUTHORIZED')
}
const rowFor=(f,digest)=>Object.values(f.state().broker.operations).find(row=>row.operation_digest===digest)

test('workflow logout clears the local owner immediately and sends one durable C logout even while its reply is held',async t=>{
  const f=await fixture(t);await f.login()
  const oldSession=session(f),epochs=Object.values(f.state().broker.owners).map(owner=>owner.authorization_epoch)
  assert.equal(ok(f.auth.service.authenticateSession({session_token:oldSession})).owner_id,f.auth.identity.owner_id)
  const gate=f.gate('owner.logout')
  const first=f.workflow.logout(),second=f.workflow.logout()
  assert.equal(f.controller.getSnapshot().owner,null)
  assert.equal(f.controller.getSnapshot().phase,'logged_out')
  assert.equal(f.workflow.getSnapshot().record,null);assert.equal(f.workflow.getSnapshot().receipt,null)
  await gate.entered(1)
  assert.equal(f.count('owner.logout'),1)
  assert.deepEqual(gate.entries[0].input,{session_token:oldSession})
  assert.deepEqual(gate.entries[0].result,{ok:true,status:'LOGGED_OUT'})
  deniedSession(f.auth.service,oldSession);deniedSession(f.auth.restart(),oldSession)
  assert.deepEqual(Object.values(f.state().broker.owners).map(owner=>owner.authorization_epoch),epochs)
  const pendingLogin=await f.adapters.authority.loginChallenge({owner_id:f.auth.identity.owner_id,kind:'passkey'})
  assert.equal(pendingLogin.ok,false);assert.equal(pendingLogin.error_code,'UNAVAILABLE')
  assert.equal(pendingLogin.reason,'UI_OWNER_LOGOUT_PENDING');assert.equal(f.count('owner.loginChallenge'),1)
  gate.release()
  assert.deepEqual(await first,{ok:true,status:'LOGGED_OUT'})
  assert.deepEqual(await second,{ok:true,status:'LOGGED_OUT'})
  assert.equal(f.count('owner.logout'),1)
  assert.equal((await f.bridge.capability()).state,'unqualified')
})

test('an old approved review cannot reserve after actual logout, including after a new ordinary login',async t=>{
  const f=await fixture(t);await f.login()
  const operation=await f.prepare(draft('old-approved-review-logout'))
  const approved=await f.controller.approve()
  assert.equal(approved.status,'APPROVED')
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
  const oldSession=session(f),proof=approved.approval_proof
  assert.deepEqual(await f.workflow.logout(),{ok:true,status:'LOGGED_OUT'})
  deniedSession(f.auth.restart(),oldSession)
  const reserve=()=>f.memory.withAuthorityTargetObservation(f.boundHost(),operation,
    ()=>f.auth.service.reserve({operation,approval_proof:proof}))
  const oldReview=await reserve()
  assert.equal(oldReview.ok,false);assert.equal(oldReview.error_code,'UNAUTHORIZED')
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
  assert.equal(f.tableCount('prime_memory_intents'),0)
  await f.login()
  assert.notEqual(session(f),oldSession)
  const afterLogin=await reserve()
  assert.equal(afterLogin.ok,false);assert.equal(afterLogin.error_code,'UNAUTHORIZED')
  assert.equal(f.count('memory.save'),0)
  assert.equal(rowFor(f,proof.operation_digest).grant,null)
})

test('logout retains a dispatched D receipt and a new ordinary session recovers factual settlement without repeating the effect',async t=>{
  const f=await fixture(t);await f.login()
  const operation=await f.prepare(draft('dispatched-receipt-survives-logout'))
  f.setSettlementFailure(true)
  await f.workflow.approveAndSave()
  const saved=f.workflow.getSnapshot(),receipt=structuredClone(saved.receipt),digest=saved.operation_digest
  assert.equal(saved.saved,true);assert.equal(saved.authority_settlement,'pending');assert.equal(saved.reconciliation_required,true)
  assert.equal(f.operationState(operation.operation_id).status,'DISPATCHED')
  const effect=structuredClone(f.pool.db.prepare('SELECT * FROM prime_memory_effects').get())
  const dispatch=structuredClone(rowFor(f,digest).dispatch),originalSettlement=structuredClone(f.settlementInputs[0]),oldSession=session(f)
  assert.equal(dispatch.request_id,receipt.request_id);assert.equal(dispatch.request_digest,receipt.request_digest)
  assert.deepEqual(await f.workflow.logout(),{ok:true,status:'LOGGED_OUT'})
  assert.equal(f.controller.getSnapshot().owner,null)
  assert.equal(f.workflow.getSnapshot().record,null);assert.equal(f.workflow.getSnapshot().receipt,null)
  deniedSession(f.auth.restart(),oldSession)
  assert.deepEqual(rowFor(f,digest).dispatch,dispatch)
  assert.deepEqual({...f.pool.db.prepare('SELECT * FROM prime_memory_effects').get()},effect)
  f.setSettlementFailure(false);await f.login()
  assert.notEqual(session(f),oldSession)
  await f.workflow.recover({operation_id:operation.operation_id})
  const recovered=f.workflow.getSnapshot()
  assert.equal(recovered.phase,'saved');assert.equal(recovered.saved,true)
  assert.equal(recovered.authority_settlement,'completed');assert.equal(recovered.reconciliation_required,false)
  assert.deepEqual(recovered.receipt,receipt)
  assert.equal(recovered.record.canonical_bytes,receipt.result.canonical_bytes)
  assert.equal(recovered.citation.verdict,'VERIFIED');assert.equal(recovered.citation.grants_authority,false)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_intents'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  assert.deepEqual({...f.pool.db.prepare('SELECT * FROM prime_memory_effects').get()},effect)
  assert.equal(rowFor(f,digest).dispatch.request_id,dispatch.request_id)
  assert.equal(rowFor(f,digest).dispatch.request_digest,dispatch.request_digest)
  assert.ok(f.settlementInputs.length>1)
  for(const resent of f.settlementInputs.slice(1))assert.deepEqual(resent,originalSettlement)
})

test('a lost genuine logout reply leaves local access cleared and reports unknown while C durably rejects the old token',async t=>{
  const f=await fixture(t);await f.login()
  const oldSession=session(f)
  f.delivery.set('owner.logout',()=>{throw new Error('synthetic loss of the real C logout response')})
  const pending=f.workflow.logout()
  assert.equal(f.controller.getSnapshot().owner,null);assert.equal(f.controller.getSnapshot().phase,'logged_out')
  const result=await pending
  assert.equal(result.ok,false);assert.equal(result.error_code,'OUTCOME_UNKNOWN');assert.equal(result.status,undefined)
  assert.equal(f.count('owner.logout'),1)
  assert.deepEqual(f.replies.find(reply=>reply.method==='owner.logout').result,{ok:true,status:'LOGGED_OUT'})
  deniedSession(f.auth.service,oldSession);deniedSession(f.auth.restart(),oldSession)
  const repeated=await f.workflow.logout()
  assert.equal(repeated.ok,false);assert.equal(repeated.status,undefined)
  assert.equal(f.count('owner.logout'),1,'an unknown reply must not cause logout redispatch')
  f.delivery.delete('owner.logout');await f.login()
  assert.notEqual(session(f),oldSession)
  assert.equal(f.controller.getSnapshot().phase,'authenticated')
})
