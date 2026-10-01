// SPDX-License-Identifier: AGPL-3.0-or-later
// Test ONLY: real B controller, C passkey verification/stores and D effects.
// Synthetic P-256 credentials and SQLite dialect fixtures are neither
// PostgreSQL durability nor deployed owner/process isolation acceptance.
import assert from 'node:assert/strict'
import {mkdtempSync,readFileSync,realpathSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {createPrimeOwnerController} from '../../ui/prime-authority/src/client/controller.mjs'
import {createRuntimeBridge,createTrustedTaskRegistry} from '../src/index.mjs'
import {createOwnerMemoryWorkflow} from '../src/owner-memory-workflow.mjs'
import {createUiAdapters} from '../src/ui-adapter.mjs'
import {createPostgresWorkflowStore} from '../src/workflow-store.mjs'
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

async function fixture(t,{uiContracts=contracts,controllerFactory=createPrimeOwnerController,wrapCall,actions=['memory.save']}={}) {
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-owner-memory-'))
  const pool=new FixturePool(join(root,'memory.sqlite')),calls=[],replies=[],settlementInputs=[],gates=new Map(),allGates=[],delivery=new Map()
  const task={version:1,task_id:'synthetic-task',owner_id:ownerId,agent_id:'synthetic-agent',
    conversation_id:'synthetic-conversation',status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],
    max_input_tokens:100,max_output_tokens:100,max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}}
  const taskRegistry=createTrustedTaskRegistry([{task,provider_and_region:{provider:'local',region:'local'},
    audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']}])
  let queue=Promise.resolve(),memory,workflowStore,bridge,adapters,controller,workflow,sessionToken,signerCalls=0,settlementCalls=0,failSettlement=false
  const provisionedAuth=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:taskRegistry.authorizeTask,actions,
    observeTarget:operation=>memory.authorityTargetObservation(operation)})
  let service=provisionedAuth.service
  const auth={...provisionedAuth,get service(){return service}}
  // This is a delivery failure around actual C. It never manufactures a
  // grant, approval, receipt, target observation or effect result.
  const authority=new Proxy({},{get(_target,name) {
    if(name==='settleMemory')return async input=>{
      settlementCalls++
      settlementInputs.push(structuredClone(input))
      if(failSettlement)throw new Error('synthetic C settlement delivery unavailable')
      return service.settleMemory(input)
    }
    const value=Reflect.get(service,name)
    return typeof value==='function'?value.bind(service):value
  }})
  const event=Buffer.from(JSON.stringify({type:'turn',text:'Synthetic owner likes banana.',seq:0,at})+'\n')
  const host={privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(event)},events:[event]}
  const resolveHostContext=({request,session})=>{
    if(request?.route!=='owner-memory-fixture')throw new Error('synthetic trusted request association missing')
    return session?{task_id:task.task_id,memory_host:host}:{login_owner_id:ownerId}
  }
  const buildServer=()=>{
    memory=createPostgresMemory({pool,authority,contracts})
    workflowStore=createPostgresWorkflowStore({pool})
    bridge=createRuntimeBridge({authority,memory,workflowStore,taskRegistry,resolveHostContext})
  }
  buildServer();await memory.migrate();await workflowStore.migrate()
  const restartServer=async()=>{
    await queue
    // New service objects reopen the existing C files and persisted SQL facts.
    // This creates no store, credentials, migrations or PostgreSQL process.
    service=provisionedAuth.restart();buildServer()
    return {authority:service,memory,workflowStore,bridge}
  }
  const bridgeCall=async(method,input)=>{
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
  }
  function mount(){
    const freshAdapters=createUiAdapters({call:typeof wrapCall==='function'?wrapCall(bridgeCall):bridgeCall})
    const freshController=controllerFactory({schedule:()=>null,unschedule:()=>{}})
    const reconnect=()=>freshController.connect({authority:freshAdapters.authority,contracts:uiContracts,owner_id:ownerId,fixture:true,
      passkeySigner:({public_key})=>{signerCalls++;return auth.assertion(public_key.challenge)}})
    reconnect()
    const freshWorkflow=createOwnerMemoryWorkflow({controller:freshController,memory:freshAdapters.memory,contracts:uiContracts})
    adapters=freshAdapters;controller=freshController;workflow=freshWorkflow
    const login=async()=>{
      assert.notEqual(await freshController.login(),null)
      assert.equal(freshController.getSnapshot().phase,'authenticated')
    }
    const prepare=async input=>{
      await freshWorkflow.proposeSave(input)
      const proposed=freshWorkflow.getSnapshot()
      assert.equal(proposed.operation.action_type,'memory.save')
      assert.notEqual(await freshController.prepare(),null)
      assert.equal(freshController.getSnapshot().phase,'review_ready')
      return proposed.operation
    }
    return {adapters:freshAdapters,controller:freshController,workflow:freshWorkflow,login,prepare,reconnect,memory,bridge,workflowStore,bridgeCall,restartServer}
  }
  const initialMount=mount()
  const remount=async()=>{
    const oldSession=sessionToken
    assert.equal(ok(await adapters.logout()).status,'LOGGED_OUT','remount requires actual C session revocation')
    assert.equal(auth.service.authenticateSession({session_token:oldSession}).ok,false,'the old session must no longer authenticate')
    workflow.dispose();controller.dispose();sessionToken=undefined
    await restartServer()
    const next=mount();await next.login();return next
  }
  t.after(async()=>{
    workflow.dispose();controller.dispose();const loggedOut=adapters.logout()
    for(const gate of allGates)gate.release()
    await loggedOut;await queue;pool.close();rmSync(root,{recursive:true,force:true})
  })
  const gate=method=>{const value=deliveryGate();gates.set(method,value);allGates.push(value);return value}
  const count=method=>calls.filter(call=>call.method===method).length
  const tableCount=table=>pool.db.prepare('SELECT count(*) AS n FROM '+table).get().n
  const state=()=>JSON.parse(readFileSync(auth.config.statePath,'utf8'))
  const operationState=id=>ok(auth.service.status({session_token:sessionToken,operation_id:id}))
  const boundHost=()=>({...host,owner_id:ownerId,owner_subject:auth.identity.subject,task_id:task.task_id})
  return {pool,auth,host,...initialMount,get memory(){return memory},get bridge(){return bridge},get workflowStore(){return workflowStore},
    remount,restartServer,bridgeCall,calls,replies,settlementInputs,delivery,gate,count,tableCount,state,operationState,boundHost,
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

export {ownerId,at,extraction,draft,ok,observe,attempt,deliveryGate,fixture,assertSaved,assertUnknown}
