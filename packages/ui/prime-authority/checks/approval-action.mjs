// SPDX-License-Identifier: AGPL-3.0-or-later
// One focused source join check. Real B controller + real bridge adapter/workflow;
// injected synthetic replies are not C crypto, PostgreSQL or live acceptance.
import assert from 'node:assert/strict'
import {pathToFileURL} from 'node:url'
import {resolve} from 'node:path'
import {createPrimeOwnerController} from '../src/client/controller.mjs'
import {createOwnerUiFixture} from './fixture.mjs'
import {createApprovalHookPort} from './approval-hook-fixture.mjs'

const contracts = await import(process.argv[2] ? pathToFileURL(resolve(process.argv[2])).href : new URL('../../../contracts/src/browser.mjs',import.meta.url).href)
const bridgeSource = process.argv[3] ? pathToFileURL(resolve(process.argv[3]) + '/').href : new URL('../../../runtime-bridge/src/',import.meta.url).href
const {createUiAdapters} = await import(new URL('ui-adapter.mjs', bridgeSource))
const {createOwnerMemoryWorkflow} = await import(new URL('owner-memory-workflow.mjs', bridgeSource))
const copy = value => JSON.parse(contracts.canonicalJson(value))
const literal = '  Exact <script>literal</script> &\n\t🍌 e\u0301  '
const capture = Object.freeze({statement:literal,attributed_to:'owner-edit'})
let cases = 0

function gate() {
  let enter, release, timeout
  const entered = new Promise((resolve,reject) => {
    enter = () => {clearTimeout(timeout);resolve()}
    timeout = setTimeout(()=>reject(new Error('synthetic reply gate was never entered')),5000)
  })
  const held = new Promise(resolve => { release = () => {clearTimeout(timeout);resolve()} })
  return {entered, release, async hold(value) { enter(); await held; return value }}
}

function make({saveUnknown=false,approvalGate,saveGate,approvalDelivery}={}) {
  const now = Date.now()
  const base = createOwnerUiFixture(contracts,{now:()=>now})
  const calls = [], saves = [], events = []
  let signerCalls = 0, nextOperation = 0, saved
  const operationFor = draft => ({...base.operation,operation_id:'memory-hook-' + (++nextOperation),
    audience:'aukora-prime.memory',action_type:'memory.save',target_identity:{kind:'prime-memory',owner_subject:'aukora:1:'+'1'.repeat(64)},
    canonical_parameters:{capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),heads:{remembered:'aukora:aura-record:v1'},
      statement:JSON.parse(draft.extraction_json).statement,attributed_to:capture.attributed_to}})
  function savedReply(input) {
    const record = {version:1,record_id:'synthetic-record',owner_subject:input.operation.target_identity.owner_subject,
      task_id:input.operation.task_id,scope:'owner',privacy:'local',record_format:'synthetic-unchanged-bytes',canonicalizer:'fixture',
      canonical_bytes:JSON.stringify({statement:JSON.parse(input.extraction_json).statement,attributedTo:capture.attributed_to}),
      revision:'synthetic-revision',grants_authority:false,source_event_digest:'sha256:'+'c'.repeat(64),evidence:[],chain_domain:'remembered',
      source_span:{fixture:true},storage_status:'saved',index_status:'pending'}
    const receipt = {version:1,kind:'prime-memory-effect/v1',operation_id:input.operation.operation_id,
      operation_digest:input.approval_proof.operation_digest,grant_id:'grant:'+input.approval_proof.nonce,
      request_id:'11111111-1111-4111-8111-111111111111',request_digest:'sha256:'+'d'.repeat(64),owner_subject:record.owner_subject,
      action_type:'memory.save',status:'applied',result_digest:'sha256:'+'e'.repeat(64),result:record}
    saved = {ok:true,record,receipt,authority_settlement:'completed',reconciliation_required:false,receipt_digest:'sha256:'+'f'.repeat(64)}
    return copy(saved)
  }
  const adapters = createUiAdapters({call:async(method,input)=>{
    calls.push({method,input:copy(input)})
    if (method.startsWith('owner.')) {
      const response = await base.authority[method.slice(6)](input)
      if (method==='owner.approvalComplete') {
        if (approvalGate) await approvalGate.hold(response)
        if (approvalDelivery) return approvalDelivery(response)
      }
      return response
    }
    if (method==='memory.proposeSave') {
      const operation=operationFor(input)
      return {ok:true,operation,operation_digest:await contracts.operationDigest(operation),memory_capture:{...capture}}
    }
    if (method==='memory.save') {
      saves.push(copy(input));const response=savedReply(input)
      if (saveGate) await saveGate.hold(response)
      if (saveUnknown) throw new Error('synthetic lost save reply after dispatch')
      return response
    }
    if (method==='memory.status') return {ok:true,record:copy(saved.record),saved:true,indexed:false,searchable:false,index_status:'pending'}
    if (method==='memory.cite') return {ok:true,citation:{record_id:saved.record.record_id,revision:saved.record.revision,
      chain_domain:'remembered',chain_sequence:1,aura_entry_hash:'1'.repeat(64),verified_head:'2'.repeat(64),verdict:'UNVERIFIED',grants_authority:false}}
    throw new Error('Unexpected synthetic method '+method)
  }})
  const controller = createApprovalHookPort(createPrimeOwnerController({now:()=>now,schedule:()=>null,unschedule:()=>{}}))
  controller.connect({...base,operation:undefined,authority:adapters.authority,
    passkeySigner:async input=>{signerCalls++;return base.passkeySigner(input)}})
  const workflow = createOwnerMemoryWorkflow({controller,memory:adapters.memory,contracts})
  const off=workflow.subscribe(()=>events.push(workflow.getSnapshot()))
  const draft = {extraction_json:JSON.stringify({statement:literal,category:'fact'}),idempotency_key:'synthetic-single-use'}
  return {controller,workflow,base,adapters,calls,saves,events,draft,
    count:method=>calls.filter(call=>call.method===method).length,signers:()=>signerCalls,
    getStored:()=>saved ? copy(saved) : null,
    async login(){assert.notEqual(await controller.login(),null);assert.equal(controller.getSnapshot().phase,'authenticated')},
    async prepare(){assert.equal((await workflow.proposeSave(draft)).phase,'proposed');assert.notEqual(await controller.prepare(),null)},
    bind(){controller.setApprovalAction(()=>workflow.approveAndSave())},
    dispose(){off();workflow.dispose();controller.dispose();adapters.logout()}}
}

{
  const f=make();try {
    await f.login();await f.prepare();const signed=f.signers()
    await f.controller.submitApproval()
    assert.equal(f.signers(),signed,'missing action must refuse before the signer')
    assert.equal(f.count('owner.approvalComplete'),0);assert.equal(f.count('memory.save'),0)
    assert.equal(f.workflow.getSnapshot().save,'not_attempted')
    assert.equal(f.controller.getSnapshot().approval_action_available,false)
  } finally {f.dispose()} cases++
}
{
  const f=make();try {
    await f.login();f.controller.setOperation(f.base.operation);await f.controller.prepare()
    const result=await f.controller.submitApproval()
    assert.equal(result.status,'APPROVED');assert.equal(f.count('owner.approvalComplete'),1)
    assert.equal(f.count('memory.save'),0,'ordinary approval must not invent a save')
    assert.equal(f.controller.getSnapshot().phase,'approved')
  } finally {f.dispose()} cases++
}
{
  const held=gate(),f=make({saveGate:held});try {
    await f.login();f.bind()
    const original=copy(f.draft),proposing=f.workflow.proposeSave(f.draft)
    f.draft.extraction_json=JSON.stringify({statement:'caller mutation'});f.draft.idempotency_key='caller mutation'
    assert.equal((await proposing).phase,'proposed');await f.controller.prepare()
    const view=f.controller.getSnapshot().presentation
    assert.equal(view.memory_review.statement,literal);assert.equal(view.memory_review.attributed_to,capture.attributed_to)
    let reentrant,requested=false
    const unsubscribe=f.controller.subscribe(()=>{
      if (!requested && f.controller.getSnapshot().phase==='approval_pending') {requested=true;reentrant=f.controller.submitApproval()}
    })
    const first=f.controller.submitApproval(),second=f.controller.submitApproval()
    assert.equal(first,second,'pending clicks must share one B action')
    await held.entered
    assert.equal(reentrant,first,'a reentrant click must share the reserved action')
    assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1)
    const input=f.saves[0]
    assert.equal(input.extraction_json,original.extraction_json);assert.equal(input.idempotency_key,original.idempotency_key)
    assert.deepEqual(input.operation,view.operation)
    assert.equal(input.approval_proof.operation_digest,view.operation_digest)
    assert.equal(input.approval_proof.material.kind,'passkey');assert.equal(input.approval_proof.material.signature,'Zml4dHVyZQ')
    assert.equal(f.workflow.getSnapshot().save,'pending');assert.equal(f.workflow.getSnapshot().saved,null)
    assert.equal(f.workflow.getSnapshot().receipt,null,'approval is not a save receipt')
    assert.equal(f.controller.getSnapshot().approval_action_pending,true)
    assert.notEqual(f.controller.getSnapshot().approval_action_result?.saved,true)
    held.release();await Promise.all([first,second,reentrant]);unsubscribe()
    const saved=f.workflow.getSnapshot();assert.equal(saved.saved,true);assert.equal(saved.save,'saved')
    assert.equal(JSON.parse(saved.record.canonical_bytes).statement,view.memory_review.statement)
    assert.equal(JSON.parse(saved.record.canonical_bytes).attributedTo,view.memory_review.attributed_to)
    assert.equal(saved.citation_status,'unverified');assert.equal(saved.index.searchable,false)
    assert.equal(saved.authority_settlement,'completed');assert(saved.receipt)
    const displayed=f.controller.getSnapshot().approval_action_result
    assert.equal(displayed.saved,true);assert.equal(displayed.index.searchable,false)
    assert.equal(displayed.citation_status,'unverified');assert.equal(displayed.authority_settlement,'completed')
    assert.deepEqual(displayed.receipt,saved.receipt);assert(Object.isFrozen(displayed));assert(Object.isFrozen(displayed.receipt))
    assert.equal(f.controller.getSnapshot().approval_action_pending,false)
    await f.controller.submitApproval();assert.equal(f.count('memory.save'),1)
  } finally {held.release();f.dispose()} cases++
}
{
  const f=make();try {
    await f.login();f.bind();await f.prepare();const op=f.workflow.getSnapshot().operation,signed=f.signers()
    for (const memoryCapture of [undefined,{...capture,statement:'changed literal'},{...capture,attributed_to:'agent'}]) {
      assert.throws(()=>f.controller.setOperation(op,{memoryCapture}),error=>error.code==='TARGET_MISMATCH')
      await f.controller.submitApproval()
    }
    assert.equal(f.signers(),signed);assert.equal(f.count('owner.approvalComplete'),0);assert.equal(f.count('memory.save'),0)
  } finally {f.dispose()} cases++
}
{
  const f=make({saveUnknown:true});try {
    await f.login();f.bind();await f.prepare();await f.controller.submitApproval()
    assert.equal(f.workflow.getSnapshot().phase,'outcome_unknown');assert.equal(f.workflow.getSnapshot().saved,null)
    assert.equal(f.workflow.getSnapshot().receipt,null);assert.equal(f.workflow.getSnapshot().approval,'approved')
    assert.equal(f.controller.getSnapshot().approval_action_result.save,'unknown')
    assert.equal(f.controller.getSnapshot().approval_action_result.saved,null)
    assert.equal(f.controller.getSnapshot().approval_action_result.error_code,'OUTCOME_UNKNOWN')
    await f.controller.submitApproval();await f.workflow.approveAndSave();await f.workflow.proposeSave({...f.draft,idempotency_key:'replacement'})
    assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.proposeSave'),1)
    assert.equal(f.count('memory.cite'),0);assert.equal(f.count('memory.status'),0)
  } finally {f.dispose()} cases++
}
{
  const held=gate(),f=make({approvalGate:held});try {
    await f.login();f.bind();await f.prepare();const pending=f.controller.submitApproval()
    await held.entered;f.controller.logout();f.adapters.logout();await f.login()
    const owner=f.controller.getSnapshot().owner
    held.release();await pending
    assert.equal(f.controller.getSnapshot().owner,owner);assert.equal(f.controller.getSnapshot().phase,'authenticated')
    assert.equal(f.count('memory.save'),0);assert.equal(f.workflow.getSnapshot().receipt,null)
    await f.controller.submitApproval();assert.equal(f.count('memory.save'),0)
  } finally {held.release();f.dispose()} cases++
}
{
  const held=gate(),f=make({saveGate:held});try {
    await f.login();f.bind();await f.prepare();const pending=f.controller.submitApproval()
    await held.entered;f.controller.logout();f.adapters.logout();await f.login()
    const owner=f.controller.getSnapshot().owner
    held.release();await pending
    assert.equal(f.controller.getSnapshot().owner,owner);assert.equal(f.controller.getSnapshot().phase,'authenticated')
    assert.equal(f.workflow.getSnapshot().phase,'outcome_unknown');assert.equal(f.workflow.getSnapshot().saved,null)
    assert.equal(f.workflow.getSnapshot().receipt,null)
    await f.controller.submitApproval();await f.workflow.proposeSave({...f.draft,idempotency_key:'replacement-after-logout'})
    assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.proposeSave'),1)
  } finally {held.release();f.dispose()} cases++
}
{
  const f=make();try {
    await f.login();f.bind();await f.prepare();f.controller.setApprovalAction(null)
    const signed=f.signers();await f.controller.submitApproval()
    assert.equal(f.signers(),signed);assert.equal(f.count('memory.save'),0)
    assert.throws(()=>f.controller.setApprovalAction({}),error=>error.code==='INVALID')
  } finally {f.dispose()} cases++
}
{
  const f=make({approvalDelivery:answer=>({...answer,approval_proof:{...answer.approval_proof,operation_digest:'sha256:'+'9'.repeat(64)}})})
  try {
    await f.login();f.bind();await f.prepare();await f.controller.submitApproval()
    assert.equal(f.workflow.getSnapshot().phase,'outcome_unknown')
    assert.equal(f.workflow.getSnapshot().approval,'unknown');assert.equal(f.workflow.getSnapshot().save,'not_attempted')
    assert.equal(f.controller.getSnapshot().approval_action_result.receipt,null)
    assert.equal(f.count('memory.save'),0);assert.equal(f.count('owner.approvalComplete'),1)
    await f.controller.submitApproval();assert.equal(f.count('owner.approvalComplete'),1)
  } finally {f.dispose()} cases++
}
{
  const held=gate(),f=make({saveGate:held});try {
    await f.login();f.bind();await f.prepare();const pending=f.controller.submitApproval()
    await held.entered
    let replacementCalls=0
    assert.throws(()=>f.controller.setApprovalAction(()=>{replacementCalls++;return f.workflow.approveAndSave()}),
      error=>error.code==='RECONCILIATION_REQUIRED')
    f.controller.setApprovalAction(null)
    assert.equal(f.controller.getSnapshot().approval_action_available,false)
    assert.equal(await f.controller.submitApproval(),null)
    held.release();assert.equal(await pending,null,'removed action must not publish its old result')
    assert.equal(f.workflow.getSnapshot().phase,'outcome_unknown')
    assert.equal(f.workflow.getSnapshot().saved,null)
    assert.equal(f.workflow.getSnapshot().reconciliation_required,true)
    assert.equal(f.getStored().record.storage_status,'saved','removal does not erase the synthetic applied record')
    assert.equal(f.getStored().receipt.status,'applied')
    assert.equal(JSON.parse(f.getStored().record.canonical_bytes).statement,literal)
    assert.equal(f.controller.getSnapshot().owner,null)
    assert.equal(f.controller.getSnapshot().approval_action_result,null)
    assert.equal(replacementCalls,0);assert.equal(f.count('memory.save'),1)
    await f.controller.submitApproval();assert.equal(f.count('memory.save'),1)
  } finally {held.release();f.dispose()} cases++
}
{
  const held=gate(),f=make({approvalGate:held});try {
    await f.login();f.bind();await f.prepare();const pending=f.controller.submitApproval()
    await held.entered
    assert.equal(f.count('owner.approvalComplete'),1)
    assert.equal(f.count('memory.save'),0)
    f.controller.setApprovalAction(null)
    assert.equal(f.controller.getSnapshot().owner,null)
    assert.equal(f.controller.getSnapshot().approval_action_available,false)
    // No adapter logout is needed for this local controller/workflow fence.
    held.release();assert.equal(await pending,null)
    assert.equal(f.count('memory.save'),0,'a late approval must not dispatch a removed workflow')
    assert.equal(f.getStored(),null)
    assert.equal(f.controller.getSnapshot().approval_action_result,null)
    assert.notEqual(f.workflow.getSnapshot().saved,true)
    await f.controller.submitApproval()
    assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),0)
  } finally {held.release();f.dispose()} cases++
}
{
  const f=make();try {
    await f.login();await f.prepare()
    f.controller.setApprovalAction(async()=>{
      await f.controller.approve()
      throw new Error('synthetic action result lost after approval')
    })
    assert.equal(await f.controller.submitApproval(),null)
    assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
    assert.equal(f.controller.getSnapshot().approval_action_result,null)
    assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),0)
    await f.controller.submitApproval();assert.equal(f.count('owner.approvalComplete'),1)
  } finally {f.dispose()} cases++
}
{
  const f=make();try {
    await f.login();await f.prepare();const signed=f.signers()
    f.controller.setApprovalAction(()=>({...f.workflow.getSnapshot(),phase:'saved',approval:'approved',save:'saved',saved:true}))
    assert.equal(await f.controller.submitApproval(),null)
    assert.equal(f.controller.getSnapshot().approval_action_result,null)
    assert.notEqual(f.controller.getSnapshot().phase,'approved')
    assert.equal(f.signers(),signed);assert.equal(f.count('owner.approvalComplete'),0);assert.equal(f.count('memory.save'),0)
  } finally {f.dispose()} cases++
}
// A stale hook may have crossed its own dispatch boundary even when it never
// called B's raw approval. Only an exact content-free terminal fact can clear it.
async function staleHookFence(reply,label,{reject=false}={}) {
  const held=gate(),f=make();try {
    const cleared=copy(f.workflow.getSnapshot())
    await f.login();await f.prepare()
    const operation=f.workflow.getSnapshot().operation
    let handlerCalls=0
    f.controller.setApprovalAction(async()=>{
      handlerCalls++
      const value=await held.hold(reply(cleared))
      if (reject) throw new Error('synthetic stale action rejection without code')
      return value
    })
    const pending=f.controller.submitApproval();await held.entered
    f.controller.logout();f.adapters.logout();await f.login()
    const owner=f.controller.getSnapshot().owner
    held.release();assert.equal(await pending,null,label)
    assert.equal(f.controller.getSnapshot().owner,owner,label+' must preserve the new owner')
    assert.equal(f.controller.getSnapshot().approval_action_result,null,label+' must hide the old result')
    assert.equal(f.controller.getSnapshot().approval_action_available,false,label+' must leave the action unavailable')
    const fresh={...operation,operation_id:operation.operation_id+'-fresh'}
    assert.throws(()=>f.controller.setOperation(fresh,{memoryCapture:capture}),
      error=>error.code==='RECONCILIATION_REQUIRED',label+' must fence a fresh operation')
    assert.equal(await f.controller.prepare(),null)
    assert.equal(f.controller.getSnapshot().error_code,'RECONCILIATION_REQUIRED')
    assert.equal(await f.controller.submitApproval(),null)
    assert.equal(handlerCalls,1);assert.equal(f.count('owner.approvalComplete'),0)
    assert.equal(f.count('memory.save'),0);assert.equal(f.getStored(),null)
    assert.equal(f.count('owner.approvalChallenge'),1,'a refused fresh review must not call the host')
    assert.equal(f.signers(),2,'only the two synthetic logins may invoke the signer')
  } finally {held.release();f.dispose()} cases++
}
await staleHookFence(()=>null,'null stale result')
await staleHookFence(()=>({phase:'idle'}),'malformed closed stale result')
await staleHookFence(empty=>({...empty,approval:'approved',save:'saved',saved:true,authority_settlement:'pending',
  reconciliation_required:true,error_code:'RECONCILIATION_REQUIRED'}),'pending stale settlement')
await staleHookFence(empty=>({...empty,approval:'approved',save:'saved',saved:true,authority_settlement:'pending'}),
  'contradictory pending stale settlement')
await staleHookFence(empty=>({...empty,saved:true}),'contradictory saved stale summary')
await staleHookFence(()=>null,'rejected stale action',{reject:true})
{
  const held=gate(),f=make();try {
    const cleared=copy(f.workflow.getSnapshot())
    await f.login();await f.prepare()
    f.controller.setApprovalAction(()=>held.hold(cleared))
    const pending=f.controller.submitApproval();await held.entered
    f.controller.logout();f.adapters.logout();await f.login()
    held.release();assert.equal(await pending,null)
    assert.equal(f.controller.getSnapshot().approval_action_result,null)
    f.bind()
    assert.equal((await f.workflow.proposeSave({...f.draft,idempotency_key:'fresh-after-exact-unsent'})).phase,'proposed')
    assert.notEqual(await f.controller.prepare(),null)
    await f.controller.submitApproval()
    assert.equal(f.count('memory.save'),1,'an exact unsent stale fact must release the flight for one fresh save')
    assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.workflow.getSnapshot().saved,true)
    assert.equal(f.controller.getSnapshot().approval_action_result.saved,true)
  } finally {held.release();f.dispose()} cases++
}
console.log(JSON.stringify({result:'PASS',cases,passed:cases,failed:0,skipped:0,actual_ui_controller:true,actual_bridge_adapter:true,actual_bridge_workflow:true,
  synthetic_replies:true,real_C_crypto:false,actual_postgres:false,real_enrollment:false,real_authentication:false,effects:false}))
