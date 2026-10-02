// SPDX-License-Identifier: AGPL-3.0-or-later
// REQUIRED ordinary actual B/C/D hook regressions. Synthetic P-256, disposable
// SQLite and same-process delivery establish no real enrollment or deployment.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import * as contracts from '../../../contracts/src/browser.mjs'
import {loadOwnerJoinFixture,loadApprovalHookController,assertExpandedCapture,assertExpandedSaved} from './approval-hook-fixture.mjs'

const {fixture,draft,assertSaved,ok}=await loadOwnerJoinFixture(process.env.PRIME_OWNER_JOIN_ROOT)

const harness=process.env.PRIME_HOOK_DSH
const nativeFactory=await loadApprovalHookController(harness,process.env.PRIME_HOOK_CLIENT),implementation=harness?'built':'source'
async function hooked(t){
  const f=await fixture(t,{uiContracts:contracts,controllerFactory:nativeFactory})
  let hooks=0
  f.controller.setApprovalAction((_view,options)=>{hooks++;assert.equal(typeof options?.approve,'function');return f.workflow.approveAndSave(options)})
  const input=draft('ordinary-native-hook-'+t.name)
  await f.login();await f.prepare(input)
  const capture=assertExpandedCapture(f,input)
  return{...f,native:f.controller,capture,hooks:()=>hooks}
}
function savedOnce(f,saved){
  assertSaved(saved)
  assertExpandedSaved(saved,f.capture)
  assert.equal(f.native.getSnapshot().phase,'approved')
  assert.equal(f.native.getSnapshot().approval_action_result.saved,true)
  assert.deepEqual(f.native.getSnapshot().approval_action_result.receipt,saved.receipt)
  assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.count('memory.save'),1)
  assert.equal(f.tableCount('prime_memory_effects'),1)
  assert.equal(f.tableCount('prime_memory_records'),1)
  assert.equal(f.signerCalls(),2,'only login plus the owned hook approval are signed')
  assert.equal(f.hooks(),1)
}
test('ordinary native raw approve cannot preempt a synchronously reserved hook',async t=>{
  const f=await hooked(t),review=f.native.getSnapshot().presentation
  const first=f.native.submitApproval(),raw=f.native.approve(),second=f.native.submitApproval()
  assert.equal(first,second,'hook clicks coalesce before its microtask starts')
  assert.equal(f.native.getSnapshot().phase,'review_ready','raw approve leaves the reserved hook review intact')
  assert.equal(f.native.getSnapshot().presentation,review)
  assert.equal(f.native.getSnapshot().approval_action_pending,true)
  assert.equal(f.count('owner.approvalComplete'),0,'public raw call dispatches no approval')
  assert.equal(await raw,null)
  const saved=await first;assert.deepEqual(await second,saved);savedOnce(f,saved)
  console.log(JSON.stringify({case:'ordinary-native-hook-reservation',implementation,result:'PASS',required:true,skipped:0,
    approval_calls:1,save_calls:1,effects:1,synthetic_credentials:true,sqlite_fixture:true,real_enrollment:false}))
})
test('ordinary native raw approve cannot steal a held genuine hook approval proof',async t=>{
  const f=await hooked(t),held=f.gate('owner.approvalComplete')
  try{
    const first=f.native.submitApproval();await held.entered(1)
    assert.equal(ok(held.entries[0].result).status,'APPROVED','the held reply is actual C approval')
    assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),0)
    assert.equal(await f.native.approve(),null,'public raw call gets no in-flight private proof')
    const second=f.native.submitApproval();assert.equal(second,first)
    assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.signerCalls(),2)
    assert.equal(f.native.getSnapshot().approval_action_result,null,'held approval does not claim a stored effect')
    held.release();const saved=await first;assert.deepEqual(await second,saved);savedOnce(f,saved)
    console.log(JSON.stringify({case:'ordinary-native-held-hook-approval',implementation,result:'PASS',required:true,skipped:0,
      approval_calls:1,save_calls:1,effects:1,synthetic_credentials:true,sqlite_fixture:true,real_enrollment:false}))
  }finally{held.release()}
})
