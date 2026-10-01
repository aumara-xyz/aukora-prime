// SPDX-License-Identifier: AGPL-3.0-or-later
// Test ONLY: real B controller, C passkey verification/stores and D effects.
// Synthetic P-256 credentials and SQLite dialect fixtures are neither
// PostgreSQL durability nor deployed owner/process isolation acceptance.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtempSync,readFileSync,realpathSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import * as browserContracts from '../../contracts/src/browser.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {createPrimeOwnerController} from '../../ui/prime-authority/src/client/controller.mjs'
import {createRuntimeBridge,createTrustedTaskRegistry} from '../src/index.mjs'
import {createOwnerMemoryWorkflow} from '../src/owner-memory-workflow.mjs'
import {createUiAdapters} from '../src/ui-adapter.mjs'
import {authorityFixture} from './authority-fixture.mjs'
import {FixturePool} from './sql-fixture.mjs'

const ownerId='synthetic-owner',at='2026-10-01T11:03:00Z'
const extraction={category:'fact',statement:'  banana <tag>&\n\t🍌  ',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}
const draft=key=>({extraction_json:JSON.stringify(extraction,null,2),idempotency_key:key})
const ok=result=>{assert.equal(result?.ok,true,JSON.stringify(result));return result}
const observe=promise=>Promise.resolve(promise).then(value=>({value}),error=>({error}))
const attempt=action=>observe(Promise.resolve().then(action))

function deliveryGate() {
  const entries=[],waiters=[]
  let released=false
  return {
    entries,
    hold(result,input) {
      if(released)return Promise.resolve(result)
      return new Promise(resolve=>{
        entries.push({result,input,resolve})
        for(let index=waiters.length-1;index>=0;index--)if(entries.length>=waiters[index].count) {
          const [waiter]=waiters.splice(index,1);clearTimeout(waiter.timer);waiter.resolve()
        }
      })
    },
    entered(count) {
      if(entries.length>=count)return Promise.resolve()
      return new Promise((resolve,reject)=>{
        const waiter={count,resolve,timer:setTimeout(()=>reject(new Error('real reply gate did not receive '+count+' replies')),5000)}
        waiters.push(waiter)
      })
    },
    release() {
      released=true;for(const entry of entries)entry.resolve(entry.result)
      for(const waiter of waiters){clearTimeout(waiter.timer);waiter.resolve()}
      waiters.length=0
    },
  }
}

async function fixture(t,{uiContracts=contracts}={}) {
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-owner-memory-'))
  const pool=new FixturePool(join(root,'memory.sqlite')),calls=[],replies=[],gates=new Map(),allGates=[],delivery=new Map()
  const task={version:1,task_id:'synthetic-task',owner_id:ownerId,agent_id:'synthetic-agent',
    conversation_id:'synthetic-conversation',status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],
    max_input_tokens:100,max_output_tokens:100,max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}}
  const taskRegistry=createTrustedTaskRegistry([{task,provider_and_region:{provider:'local',region:'local'},
    audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']}])
  let queue=Promise.resolve(),memory,sessionToken,signerCalls=0,settlementCalls=0,failSettlement=false
  const auth=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:taskRegistry.authorizeTask,
    observeTarget:operation=>memory.authorityTargetObservation(operation)})
  // This is a delivery failure around actual C. It never manufactures a
  // grant, approval, receipt, target observation or effect result.
  const authority=new Proxy({...auth.service},{get(target,name) {
    const value=Reflect.get(target,name)
    if(name==='settleMemory')return async input=>{
      settlementCalls++
      if(failSettlement)throw new Error('synthetic C settlement delivery unavailable')
      return value.call(target,input)
    }
    return typeof value==='function'?value.bind(target):value
  }})
  const event=Buffer.from(JSON.stringify({type:'turn',text:'Synthetic owner likes banana.',seq:0,at})+'\n')
  const host={privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(event)},events:[event]}
  memory=createPostgresMemory({pool,authority,contracts});await memory.migrate()
  const bridge=createRuntimeBridge({authority,memory,taskRegistry,resolveHostContext:({request,session})=>{
    if(request?.route!=='owner-memory-fixture')throw new Error('synthetic trusted request association missing')
    return session?{task_id:task.task_id,memory_host:host}:{login_owner_id:ownerId}
  }})
  const adapters=createUiAdapters({call:async(method,input)=>{
    calls.push({method,input:structuredClone(input)})
    const gate=gates.get(method),deliver=delivery.get(method)
    // FixturePool has one SQLite connection. Serialize real database work;
    // keep delivery outside that queue so genuine responses can remain held.
    const work=queue.then(()=>bridge.handleTrusted(method,input,{role:'owner_control',request:{route:'owner-memory-fixture'}}))
    queue=work.then(()=>undefined,()=>undefined)
    const result=await work
    replies.push({method,result:structuredClone(result)})
    if(method==='owner.loginComplete'&&result.ok)sessionToken=result.session_token
    const answer=gate?await gate.hold(result,input):result
    return deliver?deliver(answer,input):answer
  }})
  const controller=createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}})
  controller.connect({authority:adapters.authority,contracts:uiContracts,owner_id:ownerId,fixture:true,
    passkeySigner:({public_key})=>{signerCalls++;return auth.assertion(public_key.challenge)}})
  const workflow=createOwnerMemoryWorkflow({controller,memory:adapters.memory,contracts:uiContracts})
  t.after(async()=>{
    workflow.dispose();controller.dispose();adapters.logout()
    for(const gate of allGates)gate.release()
    await queue;pool.close();rmSync(root,{recursive:true,force:true})
  })
  const gate=method=>{const value=deliveryGate();gates.set(method,value);allGates.push(value);return value}
  const count=method=>calls.filter(call=>call.method===method).length
  const tableCount=table=>pool.db.prepare('SELECT count(*) AS n FROM '+table).get().n
  const state=()=>JSON.parse(readFileSync(auth.config.statePath,'utf8'))
  const operationState=id=>ok(auth.service.status({session_token:sessionToken,operation_id:id}))
  const boundHost=()=>({...host,owner_id:ownerId,owner_subject:auth.identity.subject,task_id:task.task_id})
  const login=async()=>{
    assert.notEqual(await controller.login(),null)
    assert.equal(controller.getSnapshot().phase,'authenticated')
  }
  const prepare=async input=>{
    await workflow.proposeSave(input)
    const proposed=workflow.getSnapshot()
    assert.equal(proposed.operation.action_type,'memory.save')
    assert.notEqual(await controller.prepare(),null)
    assert.equal(controller.getSnapshot().phase,'review_ready')
    return proposed.operation
  }
  return {pool,auth,host,memory,adapters,controller,workflow,calls,replies,delivery,gate,count,tableCount,state,operationState,boundHost,login,prepare,
    signerCalls:()=>signerCalls,settlementCalls:()=>settlementCalls,setSettlementFailure:value=>{failSettlement=value}}
}

function assertSaved(snapshot) {
  assert.equal(snapshot.phase,'saved');assert.equal(snapshot.approval,'approved')
  assert.equal(snapshot.save,'saved');assert.equal(snapshot.saved,true)
  assert.equal(snapshot.record.storage_status,'saved')
  assert.equal(snapshot.receipt.kind,'prime-memory-effect/v1');assert.equal(snapshot.receipt.status,'applied')
  assert.equal(snapshot.receipt.operation_id,snapshot.operation.operation_id)
  assert.equal(snapshot.receipt.operation_digest,snapshot.operation_digest)
  assert.equal(snapshot.receipt.result.record_id,snapshot.record.record_id)
  assert.equal(snapshot.receipt.result.revision,snapshot.record.revision)
  assert.equal(snapshot.receipt.result.canonical_bytes,snapshot.record.canonical_bytes)
}

function assertUnknown(snapshot) {
  assert.equal(snapshot.phase,'outcome_unknown')
  assert.equal(snapshot.save,'unknown');assert.equal(snapshot.saved,null)
  assert.equal(snapshot.receipt,null);assert.equal(snapshot.reconciliation_required,true)
}

test('real owner workflow retains the exact paired literal and coalesces approval/save clicks into one D effect',async t=>{
  const f=await fixture(t);await f.login()
  const input=draft('exact-owner-save'),original=structuredClone(input),changes=[]
  let reentrant,requested=false
  const unsubscribe=f.workflow.subscribe(()=>{
    const snapshot=f.workflow.getSnapshot();changes.push(snapshot)
    if(snapshot.phase==='approval_pending'&&!requested){requested=true;reentrant=f.workflow.approveAndSave()}
  })
  const proposal=f.workflow.proposeSave(input)
  input.extraction_json=JSON.stringify({...extraction,statement:'changed caller draft'});input.idempotency_key='changed-caller-key'
  await proposal
  const proposed=f.workflow.getSnapshot()
  assert.ok(Object.isFrozen(proposed));assert.ok(Object.isFrozen(proposed.operation));assert.ok(Object.isFrozen(proposed.memory_capture))
  assert.equal(proposed.memory_capture.statement,extraction.statement)
  assert.equal(proposed.memory_capture.attributed_to,'owner')
  assert.equal(proposed.operation.canonical_parameters.statement,extraction.statement)
  assert.equal(proposed.operation.canonical_parameters.attributed_to,'owner')
  assert.equal(proposed.operation_digest,await contracts.operationDigest(proposed.operation))
  await f.controller.prepare()
  const review=f.controller.getSnapshot().presentation
  assert.equal(review.memory_review.statement,extraction.statement)
  assert.equal(review.memory_review.attributed_to,'owner')
  assert.equal(review.operation_digest,proposed.operation_digest)
  const gate=f.gate('memory.save')
  const first=f.workflow.approveAndSave(),second=f.workflow.approveAndSave()
  await gate.entered(1)
  assert.ok(reentrant instanceof Promise,'a click from a synchronous observer must share the pending action')
  assert.equal(first,second);assert.equal(reentrant,first)
  const saveCall=f.calls.find(call=>call.method==='memory.save').input
  assert.equal(saveCall.extraction_json,original.extraction_json)
  assert.equal(saveCall.idempotency_key,original.idempotency_key)
  assert.deepEqual(saveCall.operation,proposed.operation)
  assert.equal(saveCall.approval_proof.operation_digest,proposed.operation_digest)
  assert.notEqual(saveCall.approval_proof.nonce,proposed.operation.nonce)
  assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),1)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  gate.release();await Promise.all([first,second,reentrant])
  const saved=f.workflow.getSnapshot();assertSaved(saved)
  const realReply=ok(f.replies.find(reply=>reply.method==='memory.save').result)
  assert.deepEqual(saved.receipt,realReply.receipt)
  assert.equal(saved.authority_settlement,'completed');assert.equal(saved.reconciliation_required,false)
  assert.equal(saved.citation_status,'verified');assert.equal(saved.citation.verdict,'VERIFIED')
  assert.equal(saved.citation.record_id,saved.record.record_id);assert.equal(saved.citation.revision,saved.record.revision)
  assert.equal(saved.citation.grants_authority,false)
  assert.equal(saved.index.status,'pending');assert.equal(saved.index.indexed,false);assert.equal(saved.index.searchable,false)
  const originalBytes=JSON.parse(saved.record.canonical_bytes)
  assert.equal(originalBytes.statement,review.memory_review.statement);assert.equal(originalBytes.attributedTo,'owner')
  assert.equal(f.signerCalls(),2);assert.equal(f.operationState(proposed.operation.operation_id).status,'COMPLETED')
  assert.ok(changes.some(snapshot=>snapshot.save==='pending'))
  assert.ok(changes.some(snapshot=>snapshot.save==='saved'))
  unsubscribe();const notificationCount=changes.length
  await attempt(()=>f.workflow.approveAndSave())
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1)
  await f.workflow.refresh();assert.equal(changes.length,notificationCount)
})

test('a real committed save with a lost delivered reply remains unknown and cannot be automatically replayed',async t=>{
  const f=await fixture(t);await f.login();const operation=await f.prepare(draft('lost-save-reply'))
  f.delivery.set('memory.save',answer=>{ok(answer);throw new Error('synthetic save reply lost after the real effect')})
  await attempt(()=>f.workflow.approveAndSave())
  assertUnknown(f.workflow.getSnapshot())
  assert.equal(f.workflow.getSnapshot().error_code,'OUTCOME_UNKNOWN')
  assert.equal(f.workflow.getSnapshot().approval,'approved')
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.count('memory.save'),1)
  f.delivery.delete('memory.save')
  await attempt(()=>f.workflow.approveAndSave())
  await attempt(()=>f.workflow.proposeSave(draft('unsafe-replacement-after-unknown')))
  await attempt(()=>f.workflow.refresh())
  assertUnknown(f.workflow.getSnapshot())
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.proposeSave'),1)
  assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
})

test('a real D database interruption after dispatch consumes authority and never grants a save retry',async t=>{
  const f=await fixture(t);await f.login();const operation=await f.prepare(draft('post-dispatch-interruption'))
  f.pool.failAfterDispatch=true
  await attempt(()=>f.workflow.approveAndSave())
  assertUnknown(f.workflow.getSnapshot())
  assert.equal(f.workflow.getSnapshot().error_code,'OUTCOME_UNKNOWN')
  assert.equal(f.operationState(operation.operation_id).status,'OUTCOME_UNKNOWN')
  assert.equal(f.tableCount('prime_memory_intents'),1)
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
  const stored=Object.values(f.state().broker.operations).find(row=>row.operation.operation_id===operation.operation_id)
  assert.notEqual(stored.grant,null)
  const proof=f.calls.find(call=>call.method==='memory.save').input.approval_proof
  assert.ok(f.state().state.consumedIds.includes('approval:'+proof.nonce))
  assert.equal(stored.dispatch.receipt,null)
  f.pool.failAfterDispatch=false
  await attempt(()=>f.workflow.approveAndSave())
  await attempt(()=>f.workflow.proposeSave(draft('replacement-after-consumed-grant')))
  await attempt(()=>f.workflow.refresh())
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.proposeSave'),1)
  assert.equal(f.operationState(operation.operation_id).status,'OUTCOME_UNKNOWN')
  assert.equal(f.tableCount('prime_memory_records'),0)
  const reconciliation=await f.memory.reconcileEffect(f.boundHost(),operation.operation_id)
  assert.equal(reconciliation.status,'unresolved');assert.equal(reconciliation.automatic_retry,false)
  assert.equal(reconciliation.reconciliation_required,true)
})

test('real saved bytes and receipt survive a C settlement delivery interruption; refresh performs only reads',async t=>{
  const f=await fixture(t);await f.login();const operation=await f.prepare(draft('settlement-delivery-pending'))
  f.setSettlementFailure(true)
  await f.workflow.approveAndSave()
  const saved=f.workflow.getSnapshot();assertSaved(saved)
  assert.equal(saved.authority_settlement,'pending');assert.equal(saved.reconciliation_required,true)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  const authorityStatus=f.operationState(operation.operation_id)
  assert.equal(authorityStatus.status,'DISPATCHED')
  const proof=f.calls.find(call=>call.method==='memory.save').input.approval_proof
  assert.ok(f.state().state.consumedIds.includes('approval:'+proof.nonce))
  const receipt=structuredClone(saved.receipt),settlements=f.settlementCalls()
  f.setSettlementFailure(false)
  await f.workflow.refresh();await attempt(()=>f.workflow.approveAndSave())
  const refreshed=f.workflow.getSnapshot();assertSaved(refreshed)
  assert.deepEqual(refreshed.receipt,receipt)
  assert.equal(refreshed.authority_settlement,'pending');assert.equal(refreshed.reconciliation_required,true)
  assert.equal(f.count('memory.save'),1);assert.equal(f.settlementCalls(),settlements)
  assert.equal(f.operationState(operation.operation_id).status,authorityStatus.status)
})

for(const readMethod of ['memory.cite','memory.status']) {
  test('a failed real '+readMethod+' reply preserves the confirmed save receipt and can recover through read-only refresh',async t=>{
    const f=await fixture(t);await f.login();const operation=await f.prepare(draft('read-delivery-'+readMethod))
    f.delivery.set(readMethod,answer=>{ok(answer);throw new Error('synthetic '+readMethod+' reply unavailable')})
    await f.workflow.approveAndSave()
    const saved=f.workflow.getSnapshot();assertSaved(saved)
    assert.equal(saved.authority_settlement,'completed');assert.equal(saved.reconciliation_required,false)
    assert.ok(saved.read_error_code)
    if(readMethod==='memory.cite')assert.equal(saved.citation_status,'unavailable')
    else {assert.equal(saved.index.indexed,null);assert.equal(saved.index.searchable,null)}
    const receipt=structuredClone(saved.receipt),writeCount=f.count('memory.save'),decisions=f.count('owner.approvalComplete')
    f.delivery.delete(readMethod)
    await f.workflow.refresh()
    const recovered=f.workflow.getSnapshot();assertSaved(recovered)
    assert.deepEqual(recovered.receipt,receipt)
    assert.equal(recovered.read_error_code,null)
    assert.equal(recovered.citation_status,'verified');assert.equal(recovered.index.status,'pending')
    assert.equal(recovered.index.indexed,false);assert.equal(recovered.index.searchable,false)
    assert.equal(f.count('memory.save'),writeCount);assert.equal(f.count('owner.approvalComplete'),decisions)
    assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  })
}

test('logout while the real approval reply is held prevents a stale-session save dispatch',async t=>{
  const f=await fixture(t);await f.login();const operation=await f.prepare(draft('logout-held-approval'))
  const gate=f.gate('owner.approvalComplete'),pending=attempt(()=>f.workflow.approveAndSave())
  await gate.entered(1);assert.equal(ok(gate.entries[0].result).status,'APPROVED')
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
  f.controller.logout();gate.release();await pending
  assert.equal(f.controller.getSnapshot().phase,'logged_out')
  assert.equal(f.count('memory.save'),0)
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
  const snapshot=f.workflow.getSnapshot()
  assert.notEqual(snapshot.saved,true);assert.equal(snapshot.receipt,null)
  await attempt(()=>f.workflow.approveAndSave());assert.equal(f.count('memory.save'),0)
})

for(const injected of [{owner_id:'guest-owner'},{source:{sessionId:'guest-session',sha256:'f'.repeat(64)}},{expected_state_version:'guest-head'}]) {
  test('owner workflow refuses closed-draft '+Object.keys(injected)[0]+' smuggling before proposal or approval',async t=>{
    const f=await fixture(t);await f.login()
    await attempt(()=>f.workflow.proposeSave({...draft('closed-draft-'+Object.keys(injected)[0]),...injected}))
    assert.equal(f.count('memory.proposeSave'),0);assert.equal(f.count('owner.approvalChallenge'),0)
    assert.equal(f.count('owner.approvalComplete'),0);assert.equal(f.count('memory.save'),0)
    assert.equal(f.signerCalls(),1);assert.equal(f.tableCount('prime_memory_records'),0)
    assert.equal(Object.keys(f.state().broker.operations).length,0)
    assert.equal(f.workflow.getSnapshot().operation,null)
  })
}

test('a real source change after review cannot apply the approved draft or authorize a retry',async t=>{
  const f=await fixture(t);await f.login();const operation=await f.prepare(draft('source-changed-after-review'))
  const changed=Buffer.from(JSON.stringify({type:'turn',text:'Changed actual trusted source',seq:0,at})+'\n')
  f.host.events=[changed];f.host.source={...f.host.source,sha256:sha256(changed)}
  await attempt(()=>f.workflow.approveAndSave())
  const snapshot=f.workflow.getSnapshot()
  // The real bridge wraps D's pre-dispatch refusal as UNAVAILABLE. A caller
  // without receipt must conservatively preserve uncertainty and not replay.
  assertUnknown(snapshot)
  const refusal=f.replies.find(reply=>reply.method==='memory.save').result
  assert.equal(refusal.ok,false);assert.equal(refusal.reason,'memory:capture-operation-mismatch')
  assert.equal(f.count('memory.save'),1);assert.equal(f.tableCount('prime_memory_records'),0)
  assert.equal(f.tableCount('prime_memory_effects'),0)
  assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
  await attempt(()=>f.workflow.approveAndSave());assert.equal(f.count('memory.save'),1)
})

for(const field of ['operation_id','grant_id']) {
  test('an altered '+field+' in a genuine saved receipt cannot become confirmed workflow state',async t=>{
    const f=await fixture(t);await f.login();const operation=await f.prepare(draft('altered-real-receipt-'+field))
    f.delivery.set('memory.save',answer=>{
      const altered=structuredClone(ok(answer))
      altered.receipt[field]=field==='grant_id'?'grant:'+'f'.repeat(64):'foreign-operation'
      return altered
    })
    await attempt(()=>f.workflow.approveAndSave())
    assertUnknown(f.workflow.getSnapshot())
    assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
    assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
    const genuine=ok(f.replies.find(reply=>reply.method==='memory.save').result)
    const proof=f.calls.find(call=>call.method==='memory.save').input.approval_proof
    assert.equal(genuine.receipt.operation_id,operation.operation_id)
    assert.equal(genuine.receipt.grant_id,'grant:'+proof.nonce)
    assert.equal(JSON.parse(genuine.record.canonical_bytes).statement,extraction.statement)
    assert.equal(f.count('memory.cite'),0);assert.equal(f.count('memory.status'),0)
    f.delivery.delete('memory.save')
    await attempt(()=>f.workflow.approveAndSave());assert.equal(f.count('memory.save'),1)
  })
}

test('saved and searchable remain independent until an explicit test-only D index drain and read-only refresh',async t=>{
  const f=await fixture(t);await f.login();await f.prepare(draft('saved-independent-of-index'))
  await f.workflow.approveAndSave()
  const pending=f.workflow.getSnapshot();assertSaved(pending)
  assert.equal(pending.index.status,'pending');assert.equal(pending.index.indexed,false);assert.equal(pending.index.searchable,false)
  const receipt=structuredClone(pending.receipt),writeCount=f.count('memory.save'),settlements=f.settlementCalls()
  assert.equal(Object.hasOwn(f.adapters.memory,'drainOutbox'),false)
  f.pool.failIndex=true
  // The workflow has no writer/indexer seam. Only this test harness invokes D.
  assert.equal((await f.memory.drainOutbox(f.boundHost())).failed,1)
  await f.workflow.refresh()
  const failed=f.workflow.getSnapshot();assertSaved(failed)
  assert.equal(failed.index.status,'failed');assert.equal(failed.index.searchable,false)
  assert.deepEqual(failed.receipt,receipt)
  f.pool.failIndex=false
  assert.equal((await f.memory.drainOutbox(f.boundHost())).indexed,1)
  await f.workflow.refresh()
  const searchable=f.workflow.getSnapshot();assertSaved(searchable)
  assert.equal(searchable.record.record_id,pending.record.record_id);assert.equal(searchable.record.revision,pending.record.revision)
  assert.equal(searchable.citation.record_id,pending.record.record_id);assert.equal(searchable.citation.revision,pending.record.revision)
  assert.equal(searchable.index.status,'searchable');assert.equal(searchable.index.indexed,true);assert.equal(searchable.index.searchable,true)
  assert.deepEqual(searchable.receipt,receipt)
  assert.equal(f.count('memory.save'),writeCount);assert.equal(f.settlementCalls(),settlements)
  assert.equal(f.count('memory.proposeSave'),1);assert.equal(f.count('owner.approvalComplete'),1)
})

function assertOwnerContentCleared(snapshot) {
  for(const field of ['operation','memory_capture','operation_digest','record','receipt','citation'])
    assert.equal(snapshot[field],null,field+' must not retain the previous owner content')
  assert.notEqual(snapshot.phase,'outcome_unknown')
  assert.notEqual(snapshot.save,'unknown')
}

test('logout before the scheduled proposal microtask makes no old call and releases the proposal flight',async t=>{
  const f=await fixture(t);await f.login()
  const pending=f.workflow.proposeSave(draft('logout-before-proposal-call'))
  f.controller.logout();await pending
  assert.equal(f.count('memory.proposeSave'),0)
  assert.equal(Object.keys(f.state().broker.operations).length,0)
  assertOwnerContentCleared(f.workflow.getSnapshot())
  assert.equal(f.workflow.getSnapshot().saved,false)
  await f.login();await f.prepare(draft('fresh-proposal-after-scheduled-logout'))
  assert.equal(f.count('memory.proposeSave'),1)
  assert.equal(f.workflow.getSnapshot().operation.action_type,'memory.save')
  assert.equal(f.tableCount('prime_memory_records'),0)
})

test('logout before the scheduled approval microtask makes no old decision and releases the action flight',async t=>{
  const f=await fixture(t);await f.login();const oldOperation=await f.prepare(draft('logout-before-approval-call'))
  const pending=f.workflow.approveAndSave()
  f.controller.logout();await pending
  assert.equal(f.count('owner.approvalComplete'),0);assert.equal(f.count('memory.save'),0)
  assert.equal(f.operationState(oldOperation.operation_id).status,'PROPOSED')
  assertOwnerContentCleared(f.workflow.getSnapshot())
  assert.equal(f.workflow.getSnapshot().saved,false)
  await f.login();const freshOperation=await f.prepare(draft('fresh-proposal-after-scheduled-approval-logout'))
  assert.notEqual(freshOperation.operation_id,oldOperation.operation_id)
  assert.equal(f.count('memory.proposeSave'),2)
  await f.workflow.approveAndSave();assertSaved(f.workflow.getSnapshot())
  assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),1)
})

for(const lifecycle of ['logout','dispose']) {
  test('a workflow observer '+lifecycle+' during save_pending prevents the real save invocation without inventing uncertainty',async t=>{
    const f=await fixture(t);await f.login();const operation=await f.prepare(draft('observer-'+lifecycle+'-before-save-call'))
    let changed=false
    const unsubscribe=f.workflow.subscribe(()=>{
      if(f.workflow.getSnapshot().phase==='save_pending'&&!changed) {
        changed=true
        if(lifecycle==='logout')f.controller.logout()
        else f.workflow.dispose()
      }
    })
    await f.workflow.approveAndSave();unsubscribe()
    assert.equal(changed,true)
    assert.equal(f.count('owner.approvalComplete'),1)
    assert.equal(f.operationState(operation.operation_id).status,'APPROVED')
    assert.equal(f.count('memory.save'),0)
    assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
    const snapshot=f.workflow.getSnapshot();assertOwnerContentCleared(snapshot)
    assert.equal(snapshot.saved,false);assert.equal(snapshot.reconciliation_required,false)
    assert.equal(snapshot.authority_settlement,null)
    if(lifecycle==='logout') {
      await f.login();await f.prepare(draft('fresh-after-observer-'+lifecycle))
      assert.equal(f.count('memory.proposeSave'),2)
    }
  })

  for(const pendingSettlement of [false,true]) {
    test('confirmed real save facts survive '+lifecycle+' while status/cite replies are held with settlement '+(pendingSettlement?'pending':'completed'),async t=>{
      const f=await fixture(t);await f.login();const operation=await f.prepare(draft('confirmed-save-'+lifecycle+'-'+pendingSettlement))
      f.setSettlementFailure(pendingSettlement)
      const status=f.gate('memory.status'),cite=f.gate('memory.cite'),pending=f.workflow.approveAndSave()
      await Promise.all([status.entered(1),cite.entered(1)])
      const confirmed=f.workflow.getSnapshot();assertSaved(confirmed)
      assert.equal(confirmed.authority_settlement,pendingSettlement?'pending':'completed')
      assert.equal(confirmed.reconciliation_required,pendingSettlement)
      assert.equal(f.operationState(operation.operation_id).status,pendingSettlement?'DISPATCHED':'COMPLETED')
      if(lifecycle==='logout')f.controller.logout()
      else f.workflow.dispose()
      const cleared=f.workflow.getSnapshot();assertOwnerContentCleared(cleared)
      assert.equal(cleared.save,'saved');assert.equal(cleared.saved,true)
      assert.equal(cleared.authority_settlement,confirmed.authority_settlement)
      assert.equal(cleared.reconciliation_required,pendingSettlement)
      status.release();cite.release();await pending
      const released=f.workflow.getSnapshot();assertOwnerContentCleared(released)
      assert.equal(released.save,'saved');assert.equal(released.saved,true)
      assert.equal(released.authority_settlement,confirmed.authority_settlement)
      assert.equal(released.reconciliation_required,pendingSettlement)
      assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1)
      assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
    })
  }
}

test('logout from the index update observer cannot publish the old citation into a cleared owner snapshot',async t=>{
  const f=await fixture(t);await f.login();const operation=await f.prepare(draft('logout-from-read-index-observer'))
  let loggedOut=false
  const afterLogout=[]
  const unsubscribe=f.workflow.subscribe(()=>{
    const snapshot=f.workflow.getSnapshot()
    if(loggedOut)afterLogout.push(snapshot)
    if(!loggedOut&&snapshot.index.indexed!==null) {
      loggedOut=true;f.controller.logout()
    }
  })
  await f.workflow.approveAndSave();unsubscribe()
  assert.equal(loggedOut,true);assert.ok(afterLogout.length>0)
  for(const snapshot of afterLogout)assertOwnerContentCleared(snapshot)
  const snapshot=f.workflow.getSnapshot();assertOwnerContentCleared(snapshot)
  assert.equal(snapshot.save,'saved');assert.equal(snapshot.saved,true)
  assert.equal(snapshot.authority_settlement,'completed');assert.equal(snapshot.reconciliation_required,false)
  assert.equal(f.count('memory.status'),1);assert.equal(f.count('memory.cite'),1)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.tableCount('prime_memory_records'),1)
})

test('the browser contract exports drive a full real B/C/D owner workflow with the same frozen v1 operation digest',async t=>{
  const f=await fixture(t,{uiContracts:browserContracts});await f.login()
  const operation=await f.prepare(draft('browser-contract-owner-save'))
  const browserDigest=browserContracts.operationDigest(operation)
  assert.ok(browserDigest instanceof Promise,'the browser operation digest uses asynchronous WebCrypto')
  assert.equal(await browserDigest,await contracts.operationDigest(operation))
  assert.equal(operation.version,1);assert.ok(Object.isFrozen(operation))
  assert.equal(f.controller.getSnapshot().presentation.operation_digest,await browserDigest)
  await f.workflow.approveAndSave()
  const snapshot=f.workflow.getSnapshot();assertSaved(snapshot)
  assert.equal(snapshot.operation_digest,await browserDigest)
  assert.equal(snapshot.authority_settlement,'completed');assert.equal(snapshot.citation_status,'verified')
  assert.equal(snapshot.index.indexed,false);assert.equal(snapshot.index.searchable,false)
  assert.equal(JSON.parse(snapshot.record.canonical_bytes).statement,extraction.statement)
  const realReply=ok(f.replies.find(reply=>reply.method==='memory.save').result)
  assert.deepEqual(snapshot.receipt,realReply.receipt)
  assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),1)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
})

test('a finished unknown save retains content-free uncertainty through logout and subsequent disposal',async t=>{
  const f=await fixture(t);await f.login();const operation=await f.prepare(draft('finished-unknown-repeated-clear'))
  f.delivery.set('memory.save',answer=>{ok(answer);throw new Error('synthetic committed reply lost before repeated clear')})
  await f.workflow.approveAndSave();assertUnknown(f.workflow.getSnapshot())
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
  f.controller.logout()
  const loggedOut=f.workflow.getSnapshot();assertUnknown(loggedOut)
  for(const field of ['operation','memory_capture','operation_digest','record','receipt','citation'])assert.equal(loggedOut[field],null)
  f.workflow.dispose()
  const disposed=f.workflow.getSnapshot();assertUnknown(disposed)
  for(const field of ['operation','memory_capture','operation_digest','record','receipt','citation'])assert.equal(disposed[field],null)
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1)
})

test('a finished confirmed save with pending settlement retains its content-free facts through logout and subsequent disposal',async t=>{
  const f=await fixture(t);await f.login();const operation=await f.prepare(draft('finished-saved-repeated-clear'))
  f.setSettlementFailure(true)
  await f.workflow.approveAndSave();assertSaved(f.workflow.getSnapshot())
  assert.equal(f.workflow.getSnapshot().authority_settlement,'pending')
  assert.equal(f.operationState(operation.operation_id).status,'DISPATCHED')
  f.controller.logout()
  const loggedOut=f.workflow.getSnapshot();assertOwnerContentCleared(loggedOut)
  assert.equal(loggedOut.save,'saved');assert.equal(loggedOut.saved,true)
  assert.equal(loggedOut.authority_settlement,'pending');assert.equal(loggedOut.reconciliation_required,true)
  f.workflow.dispose()
  const disposed=f.workflow.getSnapshot();assertOwnerContentCleared(disposed)
  assert.equal(disposed.save,'saved');assert.equal(disposed.saved,true)
  assert.equal(disposed.authority_settlement,'pending');assert.equal(disposed.reconciliation_required,true)
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1)
  assert.equal(f.tableCount('prime_memory_records'),1);assert.equal(f.tableCount('prime_memory_effects'),1)
})

test('logout from the controller operation notification cannot resurrect the proposed owner capture and permits a fresh proposal',async t=>{
  const f=await fixture(t);await f.login()
  let loggedOut=false
  const unsubscribe=f.controller.subscribe(()=>{
    if(f.controller.getSnapshot().operation_available&&!loggedOut) {
      loggedOut=true;f.controller.logout()
    }
  })
  await f.workflow.proposeSave(draft('controller-notification-logout'))
  assert.equal(loggedOut,true)
  assert.equal(f.controller.getSnapshot().phase,'logged_out')
  assertOwnerContentCleared(f.workflow.getSnapshot())
  assert.equal(f.workflow.getSnapshot().saved,false)
  assert.equal(f.count('memory.proposeSave'),1);assert.equal(f.count('memory.save'),0)
  assert.equal(f.count('owner.approvalChallenge'),0);assert.equal(f.count('owner.approvalComplete'),0)
  const oldOperation=ok(f.replies.find(reply=>reply.method==='memory.proposeSave').result).operation
  assert.equal(f.operationState(oldOperation.operation_id).status,'PROPOSED')
  const freshLiteral='Fresh owner draft after the controller listener logout.'
  await f.login()
  await f.workflow.proposeSave({extraction_json:JSON.stringify({...extraction,statement:freshLiteral}),idempotency_key:'fresh-after-controller-notification-logout'})
  unsubscribe()
  const fresh=f.workflow.getSnapshot()
  assert.equal(fresh.phase,'proposed');assert.notEqual(fresh.operation.operation_id,oldOperation.operation_id)
  assert.equal(fresh.memory_capture.statement,freshLiteral)
  assert.equal(fresh.operation.canonical_parameters.statement,freshLiteral)
  assert.equal(f.count('memory.proposeSave'),2);assert.equal(f.count('memory.save'),0)
  assert.equal(f.tableCount('prime_memory_records'),0);assert.equal(f.tableCount('prime_memory_effects'),0)
})
