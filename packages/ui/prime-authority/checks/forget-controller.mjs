// SPDX-License-Identifier: AGPL-3.0-or-later
// B source join only: fake authority/signature and truthful synthetic effect
// digests, no C verification, D worker, storage, network or runtime action.
import assert from 'node:assert/strict'
import {pathToFileURL} from 'node:url'
import {createPrimeOwnerController} from '../src/client/controller.mjs'
import {createOwnerUiFixture} from './fixture.mjs'
const contracts = await import(pathToFileURL(process.argv[2]).href)
const copy = value => contracts.parseStrictJson(contracts.canonicalJson(value))
const hash = async (domain,value) => 'sha256:' + Buffer.from(await crypto.subtle.digest('SHA-256',
  new TextEncoder().encode(domain+'\0'+contracts.canonicalJson(value)))).toString('hex')
const idle = () => ({phase:'idle',operation:null,record_summary:null,operation_digest:null,approval:'not_requested',
  forget:'not_attempted',forgotten:false,result:null,receipt:null,receipt_digest:null,authority_settlement:null,
  reconciliation_required:false,error_code:null,recovery_status:'not_requested',recovery_operation_id:null,recovery_operation_digest:null})
let groups=0
function make() {
  const now=Date.now(),base=createOwnerUiFixture(contracts,{now:()=>now})
  const summary={record_id:'synthetic-record',revision:'7',statement:'  <script>Exact legacy statement</script>\n🍌 e\u0301  ',attributed_to:null}
  const operation={...base.operation,operation_id:'synthetic-forget',audience:'aukora-prime.memory',action_type:'memory.forget',
    target_identity:{kind:'prime-memory',owner_subject:'aukora:1:'+'1'.repeat(64)},expected_state_version:'sha256:'+'2'.repeat(64),
    canonical_parameters:{profile:'prime-logical-forget/v1',...summary,canonical_sha256:'3'.repeat(64),
      at:new Date(now).toISOString().slice(0,19)+'Z',heads:{remembered:'aukora:aura-record:v1'}}}
  let logoutCalls=0
  const controller=createPrimeOwnerController({now:()=>now,schedule:()=>null,unschedule:()=>{}})
  controller.connect({...base,operation:undefined,authority:{...base.authority,logout(){logoutCalls++;return {ok:true,status:'LOGGED_OUT'}}}})
  return {base,summary,operation,controller,get logoutCalls(){return logoutCalls},
    async ready(){await controller.login();controller.setOperation(operation,{recordSummary:summary});await controller.prepare();assert.equal(controller.getSnapshot().phase,'review_ready')},
    async dispose(){await controller.disconnect();controller.dispose()}}
}
async function completed(f,proof) {
  const operation=copy(f.operation),operation_digest=await contracts.operationDigest(operation)
  const result={record_id:f.summary.record_id,state:'tombstoned',canonical_payload_retained:true,physical_media_erasure:false,
    authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false}
  const receipt={version:1,kind:'prime-memory-effect/v1',operation_id:operation.operation_id,operation_digest,
    grant_id:'grant:'+proof.nonce,request_id:'11111111-1111-4111-8111-111111111111',
    request_digest:await hash('aukora-prime.memory.effect.v1',{version:1,action_type:'memory.forget',owner_subject:operation.target_identity.owner_subject,
      operation_id:operation.operation_id,operation_digest,parameters:operation.canonical_parameters}),
    owner_subject:operation.target_identity.owner_subject,action_type:'memory.forget',status:'applied',result_digest:await hash('aukora-prime.memory-result.v1',result),result}
  return {...idle(),phase:'forgotten',operation,record_summary:copy(f.summary),operation_digest,approval:'approved',forget:'forgotten',forgotten:true,
    result,receipt,receipt_digest:await hash('aukora-prime.memory-receipt.v1',receipt),authority_settlement:'completed'}
}
{
  const f=make();await f.controller.login()
  for(const summary of [undefined,{...f.summary,statement:'Changed'},{...f.summary,attributed_to:'agent'},
    {...f.summary,record_id:'other'},{...f.summary,revision:'8'}]){
    assert.throws(()=>f.controller.setOperation(f.operation,{recordSummary:summary}),e=>e.code==='TARGET_MISMATCH')
  }
  assert.equal(f.base.counts.review,0);assert.equal(f.base.counts.approve,0)
  await f.dispose();groups++
}
{
  const f=make();await f.ready();const view=f.controller.getSnapshot().presentation
  assert.equal(view.forget_review.statement,f.summary.statement);assert.equal(view.forget_review.attributed_to,null)
  assert.equal(view.forget_review.canonical_sha256,f.operation.canonical_parameters.canonical_sha256)
  assert.equal(view.memory_review,null);assert.equal(view.canonical_operation,contracts.canonicalJson(f.operation))
  assert.equal(await f.controller.submitApproval(),null);assert.equal(f.base.counts.approve,0)
  assert.equal(f.controller.getSnapshot().error_code,'UNAVAILABLE');await f.dispose();groups++
}
{
  const f=make();let invocations=0;await f.ready()
  f.controller.setForgetAction(async()=>{invocations++;const approval=await f.controller.approve();return completed(f,approval.approval_proof)})
  const [first,second]=await Promise.all([f.controller.submitApproval(),f.controller.submitApproval()])
  assert.deepEqual(first,second);assert.equal(invocations,1);assert.equal(f.base.counts.approve,1)
  const state=f.controller.getSnapshot();assert.equal(state.forget_action_result.forgotten,true)
  assert.equal(state.forget_action_result.result.canonical_payload_retained,true);assert.equal(state.forget_action_result.result.physical_media_erasure,false)
  assert.equal(state.approval_action_result,null);assert.equal(state.phase,'approved');assert(!JSON.stringify(state).includes('synthetic-in-memory-only'))
  await f.dispose();groups++
}
for(const mutate of [value=>{value.record_summary.statement='Changed'},value=>{value.receipt.operation_digest='sha256:'+'a'.repeat(64)},
  value=>{value.result.backups_erased=true},value=>{value.receipt.result_digest='sha256:'+'b'.repeat(64)},
  value=>{value.receipt_digest='sha256:'+'c'.repeat(64)},value=>{value.receipt.grant_id='grant:'+'f'.repeat(64)}]){
  const f=make();let invocations=0;await f.ready()
  f.controller.setForgetAction(async()=>{invocations++;const approval=await f.controller.approve(),value=await completed(f,approval.approval_proof);mutate(value);return value})
  assert.equal(await f.controller.submitApproval(),null);assert.equal(f.controller.getSnapshot().forget_action_result,null)
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown');await f.controller.submitApproval();assert.equal(invocations,1)
  assert.throws(()=>f.controller.setOperation(f.operation,{recordSummary:f.summary}),e=>e.code==='RECONCILIATION_REQUIRED')
  await f.dispose();groups++
}
{
  const f=make();await f.ready();let invocations=0
  f.controller.setForgetAction(async()=>{invocations++;await f.controller.approve();return {...idle(),phase:'outcome_unknown',operation:copy(f.operation),
    record_summary:copy(f.summary),operation_digest:await contracts.operationDigest(f.operation),approval:'approved',forget:'unknown',forgotten:null,
    reconciliation_required:true,error_code:'OUTCOME_UNKNOWN'}})
  const result=await f.controller.submitApproval();assert.equal(result.reconciliation_required,true)
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown');await f.controller.submitApproval();assert.equal(invocations,1)
  await f.dispose();groups++
}
{
  const f=make();await f.ready();let release,started
  const entered=new Promise(resolve=>{started=resolve}),gate=new Promise(resolve=>{release=resolve})
  f.controller.setForgetAction(async()=>{started();await gate;return idle()})
  const pending=f.controller.submitApproval();await entered;const logout=f.controller.logout()
  assert.equal(f.controller.getSnapshot().owner,null);release();assert.equal(await pending,null);await logout
  assert.equal(f.controller.getSnapshot().forget_action_result,null);assert.equal(f.base.counts.approve,0)
  await f.controller.login();f.controller.setOperation(f.operation,{recordSummary:f.summary});assert.equal(f.controller.getSnapshot().operation_available,true)
  await f.dispose();groups++
}
{
  const f=make();await f.ready();let release,started
  const entered=new Promise(resolve=>{started=resolve}),gate=new Promise(resolve=>{release=resolve})
  f.controller.setForgetAction(async()=>{await f.controller.approve();started();await gate;return {...idle(),phase:'outcome_unknown',
    approval:'approved',forget:'unknown',forgotten:null,reconciliation_required:true,error_code:'OUTCOME_UNKNOWN'}})
  const pending=f.controller.submitApproval();await entered;const logout=f.controller.logout();release();await pending;await logout
  assert.equal(f.controller.getSnapshot().owner,null);assert.equal(f.controller.getSnapshot().forget_action_result,null)
  assert.throws(()=>f.controller.setOperation(f.operation,{recordSummary:f.summary}),e=>e.code==='RECONCILIATION_REQUIRED')
  await f.dispose();groups++
}
console.log(JSON.stringify({result:'PASS',groups,scope:'B source synthetic forget controller join',C_verification:false,D_worker:false,
  runtime:false,network:false,storage:false,real_credentials:false,compiled_client:false}))
