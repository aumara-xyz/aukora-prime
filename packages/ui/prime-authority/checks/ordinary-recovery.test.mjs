// SPDX-License-Identifier: AGPL-3.0-or-later
// Bounded disposable source join: actual B/C/D, synthetic P-256 and SQLite.
// No real owner, PostgreSQL, deployment, browser or process-isolation claim.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../../contracts/src/browser.mjs'
import {loadOwnerJoinFixture,loadApprovalHookController,assertExpandedCapture,assertExpandedSaved} from './approval-hook-fixture.mjs'

const {fixture,draft,ok,assertSaved,assertUnknown,createOwnerForgetWorkflow}=await loadOwnerJoinFixture(process.env.PRIME_OWNER_JOIN_ROOT)

const harness=process.env.PRIME_RECOVERY_DSH
const nativeFactory=await loadApprovalHookController(harness,process.env.PRIME_RECOVERY_CLIENT)
const controllerFactory=nativeFactory
const implementation=harness?'built':'source'

async function hooked(t,options={}){
  const f=await fixture(t,{uiContracts:contracts,controllerFactory,...options})
  assert.equal(typeof f.controller.reconcileApprovalAction,'function','the same-controller verified recovery seam must exist')
  let hookCalls=0
  f.controller.setApprovalAction((_view,options)=>{hookCalls++;assert.equal(typeof options?.approve,'function');return f.workflow.approveAndSave(options)})
  await f.login()
  return{...f,hookCalls:()=>hookCalls}
}
async function save(f,key){
  const input=draft(key),proposed=await f.workflow.proposeSave(input)
  assert.equal(proposed.phase,'proposed')
  assert.notEqual(await f.controller.prepare(),null)
  const capture=assertExpandedCapture(f,input)
  const first=f.controller.submitApproval(),second=f.controller.submitApproval()
  assert.equal(first,second,'ordinary repeated clicks share one mutation flight')
  const result=await first
  if(result.saved===true)assertExpandedSaved(result,capture)
  return result
}
function unchangedEffects(f,before){
  assert.equal(f.signerCalls(),before.signatures,'recovery requests no new signature')
  assert.equal(f.count('owner.approvalComplete'),before.approvals,'recovery requests no new approval')
  assert.equal(f.count('memory.save'),before.saves,'recovery never repeats a save')
  assert.equal(f.tableCount('prime_memory_effects'),before.effects,'recovery adds no mutation row')
  assert.equal(f.hookCalls(),before.hooks,'recovery does not re-enter the mutation hook')
}
const counts=f=>({signatures:f.signerCalls(),approvals:f.count('owner.approvalComplete'),saves:f.count('memory.save'),effects:f.tableCount('prime_memory_effects'),hooks:f.hookCalls()})
function presented(f,recovered){
  const state=f.controller.getSnapshot()
  assert.equal(state.phase,'approved')
  assert.equal(state.error_code,null)
  assert.equal(state.approval_action_pending,false)
  assert.equal(state.approval_action_available,true)
  assert.equal(state.approval_action_result.saved,true)
  assert.equal(state.approval_action_result.save,'saved')
  assert.equal(state.approval_action_result.authority_settlement,'completed')
  assert.equal(state.approval_action_result.reconciliation_required,false)
  assert.deepEqual(state.approval_action_result.record,recovered.record)
  assert.deepEqual(state.approval_action_result.receipt,recovered.receipt)
  assert.equal(state.approval_action_result.receipt_digest,recovered.receipt_digest)
  assert.equal(state.approval_action_result.index.status,recovered.index.status)
  assert.equal(state.approval_action_result.citation_status,recovered.citation_status)
}

test('same controller ingests a genuine recovered lost-save receipt and resumes a fresh save',async t=>{
  const f=await hooked(t)
  f.delivery.set('memory.save',reply=>{ok(reply);throw Error('ordinary fixture committed save reply delivery unavailable')})
  const uncertain=await save(f,'ordinary-recovery-lost-save')
  assertUnknown(uncertain)
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
  assert.equal(f.controller.getSnapshot().approval_action_result.saved,null)
  const operation=uncertain.operation,committed=ok(f.replies.find(reply=>reply.method==='memory.save').result)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  const before=counts(f)
  f.delivery.delete('memory.save')

  // Lose delivery of an actual recovery reply once. No payload is forged and
  // no receipt is invented; the uncertain UI must remain fenced until observed.
  f.delivery.set('memory.recover',reply=>{ok(reply);throw Error('ordinary fixture recovery reply delivery unavailable')})
  const unknownRecovery=await f.workflow.recover({operation_id:null})
  assert.equal(unknownRecovery.reconciliation_required,true)
  assert.equal(await f.controller.reconcileApprovalAction(unknownRecovery),null)
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
  assert.equal(f.controller.getSnapshot().approval_action_available,false)
  assert.equal(await f.controller.submitApproval(),null)
  unchangedEffects(f,before)
  f.delivery.delete('memory.recover')

  const recovered=await f.workflow.recover({operation_id:null})
  assert.equal(recovered.operation,null)
  assert.equal(recovered.memory_capture,null)
  assert.equal(recovered.saved,true)
  assert.equal(recovered.authority_settlement,'completed')
  assert.equal(recovered.reconciliation_required,false)
  assert.deepEqual(recovered.record,committed.record)
  assert.deepEqual(recovered.receipt,committed.receipt)
  const firstRecovery=f.controller.reconcileApprovalAction(recovered),secondRecovery=f.controller.reconcileApprovalAction(recovered)
  assert.equal(firstRecovery,secondRecovery,'ordinary repeated reconciliation calls share one receipt-validation flight')
  assert.notEqual(await firstRecovery,null)
  assert.deepEqual(await secondRecovery,await firstRecovery)
  presented(f,recovered)
  unchangedEffects(f,before)

  const next=await save(f,'ordinary-recovery-fresh-after-lost-save')
  assertSaved(next)
  assert.notEqual(next.operation.operation_id,operation.operation_id)
  assert.equal(f.controller.getSnapshot().approval_action_result.saved,true)
  assert.equal(f.count('memory.save'),2)
  assert.equal(f.count('owner.approvalComplete'),2)
  assert.equal(f.tableCount('prime_memory_effects'),2)
  assert.equal(f.signerCalls(),before.signatures+1)
  console.log(JSON.stringify({case:'ordinary-same-controller-lost-save-recovery',implementation,result:'PASS',save_calls:f.count('memory.save'),approval_calls:f.count('owner.approvalComplete'),
    signatures_during_recovery:0,effects_during_recovery:0,synthetic_credentials:true,sqlite_fixture:true,real_enrollment:false}))
})

test('same controller clears pending settlement only after the genuine retained receipt completes',async t=>{
  const f=await hooked(t)
  f.setSettlementFailure(true)
  const pending=await save(f,'ordinary-recovery-pending-settlement')
  assertSaved(pending)
  assert.equal(pending.authority_settlement,'pending')
  assert.equal(pending.reconciliation_required,true)
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
  const before=counts(f),retained=structuredClone(f.settlementInputs[0])

  const unresolved=await f.workflow.recover({operation_id:null})
  assert.equal(unresolved.reconciliation_required,true)
  assert.equal(await f.controller.reconcileApprovalAction(unresolved),null)
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
  assert.equal(f.controller.getSnapshot().approval_action_available,false)
  unchangedEffects(f,before)

  f.setSettlementFailure(false)
  const recovered=await f.workflow.recover({operation_id:null})
  assert.equal(recovered.saved,true)
  assert.equal(recovered.authority_settlement,'completed')
  assert.equal(recovered.reconciliation_required,false)
  assert.deepEqual(recovered.receipt,pending.receipt)
  assert.notEqual(await f.controller.reconcileApprovalAction(recovered),null)
  presented(f,recovered)
  unchangedEffects(f,before)
  assert.ok(f.settlementInputs.length>1)
  for(const input of f.settlementInputs.slice(1))assert.deepEqual(input,retained,'only the original retained settlement receipt is delivered')

  assertSaved(await save(f,'ordinary-recovery-fresh-after-settlement'))
  assert.equal(f.count('memory.save'),2)
  assert.equal(f.count('owner.approvalComplete'),2)
  assert.equal(f.tableCount('prime_memory_effects'),2)
  assert.equal(f.signerCalls(),before.signatures+1)
  console.log(JSON.stringify({case:'ordinary-same-controller-settlement-recovery',implementation,result:'PASS',save_calls:f.count('memory.save'),approval_calls:f.count('owner.approvalComplete'),
    signatures_during_recovery:0,effects_during_recovery:0,synthetic_credentials:true,sqlite_fixture:true,real_enrollment:false}))
})

test('a verified completed receipt resolves an expired old review while the owner session remains live',async t=>{
  let uiClock=Date.now(),scheduled
  const f=await hooked(t,{controllerFactory:options=>controllerFactory({...options,now:()=>uiClock,
    schedule:fn=>{scheduled=fn;return{fn}},unschedule:()=>{}})})
  f.delivery.set('memory.save',reply=>{ok(reply);throw Error('ordinary fixture saved reply delivery unavailable before review expiry')})
  assertUnknown(await save(f,'ordinary-recovery-expired-review'))
  f.delivery.delete('memory.save')
  // Obtain genuine verified facts first, then simulate this controller's own
  // review timer firing before receipt ingestion. C's real clock is unchanged.
  const recovered=await f.workflow.recover({operation_id:null}),before=counts(f)
  assert.equal(recovered.saved,true)
  const presentation=f.controller.getSnapshot().presentation
  uiClock=Math.max(uiClock+120000,Date.parse(presentation.approval_expiry)+1)
  assert.ok(Date.parse(f.controller.getSnapshot().owner.expiry)>uiClock,'owner TTL outlasts the old review')
  assert.equal(typeof scheduled,'function');scheduled()
  assert.equal(f.controller.getSnapshot().expired,true)
  assert.notEqual(await f.controller.reconcileApprovalAction(recovered),null)
  assert.equal(f.controller.getSnapshot().expired,false)
  assert.equal(f.controller.getSnapshot().presentation,presentation,'the exact consumed review remains visible')
  scheduled()
  assert.equal(f.controller.getSnapshot().expired,false,'the consumed review timer no longer expires the live owner session')
  presented(f,recovered);unchangedEffects(f,before)
  const proposed=await f.workflow.proposeSave(draft('ordinary-recovery-proposal-after-expired-review'))
  assert.equal(proposed.phase,'proposed');assert.equal(f.controller.getSnapshot().expired,false)
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1)
  console.log(JSON.stringify({case:'ordinary-expired-review-receipt-ingestion',implementation,result:'PASS',fresh_proposal:true,
    signatures_during_recovery:0,effects_during_recovery:0,real_clock_changed:false,real_enrollment:false}))
})

test('same controller ingests a genuine lost logical-forget receipt and resumes a fresh save',async t=>{
  const f=await hooked(t,{actions:['memory.save','memory.forget']})
  const forgetting=createOwnerForgetWorkflow({controller:f.controller,memory:f.adapters.memory,contracts})
  t.after(()=>forgetting.dispose())
  let forgetHooks=0
  f.controller.setForgetAction((_view,options)=>{forgetHooks++;assert.equal(typeof options?.approve,'function');return forgetting.approveAndForget(options)})
  const saved=await save(f,'ordinary-recovery-before-forget');assertSaved(saved)
  assert.equal((await forgetting.proposeForget({record_id:saved.record.record_id})).phase,'proposed')
  assert.notEqual(await f.controller.prepare(),null)
  f.delivery.set('memory.forget',reply=>{ok(reply);throw Error('ordinary fixture committed logical-forget reply delivery unavailable')})
  const first=f.controller.submitApproval(),second=f.controller.submitApproval();assert.equal(first,second)
  const uncertain=await first
  assert.equal(uncertain.forget,'unknown');assert.equal(uncertain.forgotten,null)
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
  const before=counts(f),committed=ok(f.replies.find(reply=>reply.method==='memory.forget').result)
  f.delivery.delete('memory.forget')
  const recovered=await forgetting.recover({operation_id:null})
  assert.equal(recovered.forgotten,true);assert.equal(recovered.authority_settlement,'completed');assert.equal(recovered.reconciliation_required,false)
  assert.deepEqual(recovered.receipt,committed.receipt)
  assert.notEqual(await f.controller.reconcileApprovalAction(recovered),null)
  const state=f.controller.getSnapshot()
  assert.equal(state.phase,'approved');assert.equal(state.approval_action_available,true)
  assert.equal(state.forget_action_result.forgotten,true);assert.equal(state.forget_action_result.authority_settlement,'completed')
  assert.deepEqual(state.forget_action_result.receipt,committed.receipt)
  assert.equal(state.forget_action_result.result.canonical_payload_retained,true)
  assert.equal(state.forget_action_result.result.physical_media_erasure,false)
  unchangedEffects(f,before);assert.equal(forgetHooks,1);assert.equal(f.count('memory.forget'),1)
  assertSaved(await save(f,'ordinary-recovery-save-after-forget'))
  assert.equal(f.count('memory.save'),2);assert.equal(f.count('memory.forget'),1)
  assert.equal(f.count('owner.approvalComplete'),3);assert.equal(f.tableCount('prime_memory_effects'),3)
  assert.equal(f.signerCalls(),before.signatures+1)
  console.log(JSON.stringify({case:'ordinary-same-controller-forget-recovery',implementation,result:'PASS',forget_calls:f.count('memory.forget'),
    signatures_during_recovery:0,effects_during_recovery:0,canonical_payload_retained:true,physical_erasure:false,real_enrollment:false}))
})
