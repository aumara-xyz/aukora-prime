// SPDX-License-Identifier: AGPL-3.0-or-later
// Focused synthetic presentation checks. requestOne is an injected callback;
// these checks use no browser assertion, real credential, provider, HTTP or effect.
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {createPilotInferenceController} from '../src/client/inference-controller.mjs'

const CLOCK = Date.parse('2030-01-01T00:00:00Z')
const UUID = '11111111-1111-4111-8111-111111111111'
const NEXT_UUID = '22222222-2222-4222-8222-222222222222'
const CONTEXT = Object.freeze({owner_id:'synthetic-owner',task_id:'synthetic-task',conversation_id:'synthetic-conversation'})
const clone = value => JSON.parse(JSON.stringify(value))
function deferred() {
  let resolve, reject
  const promise = new Promise((yes,no) => {resolve=yes;reject=no})
  return {promise,resolve,reject}
}
function observable(value) {
  let snapshot=value
  const listeners=new Set()
  return {
    getSnapshot:()=>snapshot,
    subscribe(listener) {listeners.add(listener);return()=>listeners.delete(listener)},
    emit(next) {snapshot=next;for(const listener of [...listeners])listener()},
    get listenerCount() {return listeners.size},
  }
}
function ownerState(patch={}) {
  return {owner:{owner_id:CONTEXT.owner_id,expiry:new Date(CLOCK+300000).toISOString()},
    owner_id:CONTEXT.owner_id,authority_available:true,expired:false,logout_status:'idle',...patch}
}
function completed(uuid=UUID,context=CONTEXT,mode='mock') {
  return {outcome:'completed',request_uuid:uuid,route_id:'externalDeepSeek',mode,
    proposal:{text:'  synthetic <reply>\n\tunchanged Ω  ',source_ids:[],grantsAuthority:false},
    usage:{input_tokens:1,output_tokens:2,cost_microusd:3},
    receipt:{sessionId:context.conversation_id,line:'synthetic model-request record',turn:1,spokenAt:CLOCK,
      request_uuid:uuid,body_sha256:'a'.repeat(64),
      source_citation:{sessionId:context.conversation_id,turn:1,sha256:'b'.repeat(64),requestId:'synthetic-record-id'},citations:[]},
    omitted:[]}
}
function unknown(uuid=UUID,context=CONTEXT) {
  return {outcome:'outcome_unknown',request_uuid:uuid,receipt:completed(uuid,context).receipt,
    error:'PROVIDER_UNAVAILABLE',reservation_retained:true}
}
function fixture({state='ready',mode='mock',context=CONTEXT,current=true,ownerSnapshot=ownerState(),ownerController=null,requestId}={}) {
  let connected=current,clock=CLOCK,requestImpl,ids=0
  const owner=observable(ownerSnapshot)
  const exactBinding={owner_id:context.owner_id}
  const availability=observable({state,mode,reason:state==='ready'?'Synthetic callback ready.':'Synthetic callback unavailable.'})
  const calls=[]
  const client={binding:exactBinding,context:{...context},availability,
    requestOne(draft,options) {calls.push({draft,options});return requestImpl?requestImpl(draft,options):Promise.resolve(completed(draft.request_uuid,context,mode))}}
  const binding={ownerController:ownerController??owner,client}
  const controller=createPilotInferenceController({ownerController:owner,isConnected:value=>connected&&value===exactBinding,
    now:()=>clock,requestId:()=>{ids++;return requestId?requestId():ids===1?UUID:NEXT_UUID}})
  return {controller,owner,binding,client,availability,calls,
    connect:()=>controller.connect(binding),setRequest(fn){requestImpl=fn},setConnected(value){connected=value},
    advance(ms){clock+=ms},get ids(){return ids},dispose(){controller.dispose()}}
}
function assertFrozenTree(value) {
  if(value===null||typeof value!=='object')return
  assert.equal(Object.isFrozen(value),true,'projected result objects are frozen')
  for(const child of Object.values(value))assertFrozenTree(child)
}

test('default and absent explicit readiness stay unavailable without minting a request',async()=>{
  const f=fixture({state:'unavailable',mode:null})
  try {
    assert.equal(f.controller.getSnapshot().available,false)
    assert.equal(await f.controller.request('synthetic text'),null)
    const off=f.connect()
    assert.equal(f.controller.getSnapshot().phase,'unavailable')
    assert.equal(f.controller.getSnapshot().available,false)
    assert.equal(f.controller.getSnapshot().mode,null)
    assert.equal(await f.controller.request('synthetic text'),null)
    assert.equal(f.calls.length,0);assert.equal(f.ids,0)
    off()
  } finally {f.dispose()}
})

test('ready mock and production modes require exact native connection and current owner',async()=>{
  for(const mode of ['mock','production']) {
    const f=fixture({mode})
    try {
      f.connect()
      assert.equal(f.controller.getSnapshot().phase,'idle')
      assert.equal(f.controller.getSnapshot().available,true)
      assert.equal(f.controller.getSnapshot().mode,mode)
      assert.deepEqual(f.controller.getSnapshot().context,CONTEXT)
      f.setConnected(false)
      assert.equal(await f.controller.request('synthetic text'),null)
      assert.equal(f.calls.length,0)
    } finally {f.dispose()}
  }
  const variants=[{current:false},{ownerController:{}},
    {ownerSnapshot:ownerState({owner:{owner_id:'synthetic-other-owner',expiry:new Date(CLOCK+300000).toISOString()}})},
    {ownerSnapshot:ownerState({owner:null})},{ownerSnapshot:ownerState({authority_available:false})},
    {ownerSnapshot:ownerState({expired:true})},{ownerSnapshot:ownerState({logout_status:'pending'})},
    {ownerSnapshot:ownerState({owner:{owner_id:CONTEXT.owner_id,expiry:new Date(CLOCK).toISOString()}})}]
  for(const options of variants) {
    const f=fixture(options)
    try {f.connect();assert.equal(await f.controller.request('synthetic text'),null);assert.equal(f.calls.length,0);assert.equal(f.ids,0)}
    finally {f.dispose()}
  }
})

test('one pending request captures immutable literal text and UUID and coalesces duplicate clicks',async()=>{
  const f=fixture(),hold=deferred(),text='  synthetic <prompt>\n\tΩ  '
  try {
    f.connect();f.setRequest(()=>hold.promise)
    const first=f.controller.request(text),second=f.controller.request('changed while pending')
    assert.equal(second,first,'duplicate click keeps the exact pending promise')
    await Promise.resolve()
    assert.equal(f.ids,1);assert.equal(f.calls.length,1)
    assert.equal(f.controller.getSnapshot().phase,'pending')
    assert.equal(f.controller.getSnapshot().request_uuid,UUID)
    assert.deepEqual(f.calls[0].draft,{request_uuid:UUID,text})
    assert.equal(Object.isFrozen(f.calls[0].draft),true)
    assert.deepEqual(Object.keys(f.calls[0].options),['signal'])
    assert.equal(f.calls[0].options.signal.aborted,false)
    assert.throws(()=>{f.calls[0].draft.text='changed'})
    assert.throws(()=>{f.calls[0].draft.request_uuid=NEXT_UUID})
    hold.resolve(completed())
    assert.deepEqual(await first,completed())
    assert.equal(f.controller.getSnapshot().phase,'completed')
    assert.equal(f.calls.length,1)
  } finally {hold.resolve(completed());f.dispose()}
})

test('completed projection preserves gateway fields and detaches its exact result',async()=>{
  const f=fixture(),supplied=completed()
  try {
    f.connect();f.setRequest(()=>Promise.resolve(supplied))
    const result=await f.controller.request('synthetic text')
    assert.deepEqual(result,supplied)
    assert.notEqual(result,supplied)
    assert.notEqual(result.receipt,supplied.receipt)
    assert.equal(result.receipt.source_citation.requestId,'synthetic-record-id','model-record citation ID is not the UI request UUID')
    assertFrozenTree(result)
    const before=clone(result)
    supplied.proposal.text='mutated after callback';supplied.receipt.sessionId='changed';supplied.usage.input_tokens=99
    assert.deepEqual(result,before)
    assert.deepEqual(f.controller.getSnapshot().result,before)
    assert.equal(f.controller.getSnapshot().mode,'mock','mock readiness does not become production')
    assert.equal(f.calls.length,1)
  } finally {f.dispose()}
})

test('actual gateway unknown is projected unchanged and retains no-retry lock across same-context rebind and logout',async()=>{
  const f=fixture(),supplied=unknown()
  try {
    const off=f.connect();f.setRequest(()=>Promise.resolve(supplied))
    const result=await f.controller.request('synthetic text')
    assert.deepEqual(result,supplied);assert.notEqual(result,supplied);assertFrozenTree(result)
    assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
    assert.equal(await f.controller.request('retry forbidden'),null);assert.equal(f.calls.length,1)
    off();f.owner.emit(ownerState({owner:null,authority_available:false}));f.connect()
    f.owner.emit(ownerState())
    assert.equal(await f.controller.request('retry after fresh owner login forbidden'),null)
    assert.equal(f.calls.length,1);assert.equal(f.ids,1)
  } finally {f.dispose()}
})

test('entered callback failure is unknown without fabricating a receipt or reservation',async()=>{
  const f=fixture()
  try {
    f.connect();f.setRequest(()=>{throw Error('synthetic callback response lost')})
    assert.equal(await f.controller.request('synthetic text'),null)
    const snapshot=f.controller.getSnapshot()
    assert.equal(snapshot.phase,'outcome_unknown');assert.equal(snapshot.result,null)
    assert.equal(snapshot.request_uuid,UUID)
    assert.equal(await f.controller.request('retry forbidden'),null)
    assert.equal(f.calls.length,1);assert.equal(f.ids,1)
    assert.equal('reservation_retained' in snapshot,false,'UI never invents a provider reservation')
  } finally {f.dispose()}
})

test('foreign UUID, conversation, mode and invalid completed fields refuse completion without retry',async()=>{
  const mutations=[result=>({...result,request_uuid:NEXT_UUID}),
    result=>({...result,receipt:{...result.receipt,request_uuid:NEXT_UUID}}),
    result=>({...result,receipt:{...result.receipt,sessionId:'synthetic-other-conversation'}}),
    result=>({...result,receipt:{...result.receipt,source_citation:{...result.receipt.source_citation,sessionId:'synthetic-other-conversation'}}}),
    result=>({...result,mode:'production'}),result=>({...result,route_id:'other-provider'}),
    result=>({...result,proposal:{...result.proposal,grantsAuthority:true}}),
    result=>({...result,usage:{...result.usage,cost_microusd:-1}}),
    ()=>({aukora_prime:{request_uuid:UUID,grants_authority:false}})]
  for(const mutate of mutations) {
    const f=fixture()
    try {
      f.connect();f.setRequest(()=>Promise.resolve(mutate(completed())))
      assert.equal(await f.controller.request('synthetic text'),null)
      assert.equal(f.controller.getSnapshot().phase,'outcome_unknown')
      assert.equal(f.controller.getSnapshot().result,null)
      assert.equal(await f.controller.request('retry forbidden'),null)
      assert.equal(f.calls.length,1)
    } finally {f.dispose()}
  }
})

test('pending owner logout, owner replacement, disconnect and availability loss fence late completion',async()=>{
  const changes=[f=>f.owner.emit(ownerState({owner:null,authority_available:false})),
    f=>f.owner.emit(ownerState()), // A fresh owner object means a fresh session, even with equal public fields.
    f=>f.controller.disconnect(),
    f=>f.availability.emit({state:'unavailable',mode:null,reason:'Synthetic callback disconnected.'}),
    f=>f.availability.emit({state:'ready',mode:'production',reason:'Synthetic mode replacement.'})]
  for(const change of changes) {
    const f=fixture(),hold=deferred()
    try {
      f.connect();f.setRequest(()=>hold.promise)
      const pending=f.controller.request('synthetic text')
      await Promise.resolve()
      assert.equal(f.calls.length,1)
      change(f)
      assert.equal(f.calls[0].options.signal.aborted,true)
      hold.resolve(completed())
      assert.equal(await pending,null)
      assert.equal(f.controller.getSnapshot().result,null,'late result is not shown in a different owner/native lifetime')
      f.owner.emit(ownerState());f.availability.emit({state:'ready',mode:'mock',reason:'Synthetic callback ready.'});f.connect()
      assert.equal(await f.controller.request('retry after lost projection forbidden'),null)
      assert.equal(f.calls.length,1)
    } finally {hold.resolve(completed());f.dispose()}
  }
})

test('mutated task, conversation, native binding or request callback fences the pending result',async()=>{
  const changes=[f=>{f.client.context.task_id='synthetic-other-task'},
    f=>{f.client.context.conversation_id='synthetic-other-conversation'},
    f=>{f.client.binding={owner_id:CONTEXT.owner_id}},
    f=>{f.client.requestOne=async()=>completed()}]
  for(const change of changes) {
    const f=fixture(),hold=deferred()
    try {
      f.connect();f.setRequest(()=>hold.promise)
      const pending=f.controller.request('synthetic text')
      await Promise.resolve()
      change(f);hold.resolve(completed())
      assert.equal(await pending,null);assert.equal(f.controller.getSnapshot().result,null)
      assert.equal(f.calls.length,1)
    } finally {hold.resolve(completed());f.dispose()}
  }
})

test('old connect cleanup preserves a replacement frame and its pending request',async()=>{
  const f=fixture(),hold=deferred()
  try {
    const off=f.connect(),replacement={...f.binding,client:{...f.client,context:{...CONTEXT}}}
    f.controller.connect(replacement);off()
    assert.equal(f.controller.getSnapshot().available,true)
    f.setRequest(()=>hold.promise)
    const pending=f.controller.request('synthetic replacement text')
    await Promise.resolve()
    assert.equal(f.calls.length,1)
    assert.equal(f.calls[0].options.signal.aborted,false)
    hold.resolve(completed())
    assert.deepEqual(await pending,completed())
  } finally {hold.resolve(completed());f.dispose()}
})

test('reentrant subscriber disconnect before callback sends nothing and does not taint a future request',async()=>{
  const f=fixture()
  let disconnected=false
  try {
    f.connect()
    const off=f.controller.subscribe(()=>{
      if(!disconnected&&f.controller.getSnapshot().phase==='pending') {disconnected=true;f.controller.disconnect()}
    })
    assert.equal(await f.controller.request('synthetic request cancelled before callback'),null)
    off();assert.equal(disconnected,true);assert.equal(f.calls.length,0)
    f.connect()
    const result=await f.controller.request('synthetic next request')
    assert.equal(result?.outcome,'completed')
    assert.equal(f.calls.length,1,'no dispatched callback means no permanent unknown lock')
  } finally {f.dispose()}
})

test('disposal aborts pending callback, clears subscriptions and fences late results',async()=>{
  const f=fixture(),hold=deferred()
  f.connect();f.setRequest(()=>hold.promise)
  const pending=f.controller.request('synthetic text')
  await Promise.resolve()
  f.dispose()
  assert.equal(f.calls[0].options.signal.aborted,true)
  assert.equal(f.owner.listenerCount,0);assert.equal(f.availability.listenerCount,0)
  hold.resolve(completed())
  assert.equal(await pending,null);assert.equal(f.controller.getSnapshot().result,null)
  f.connect()
  assert.equal(await f.controller.request('disposed request refused'),null)
  assert.equal(f.calls.length,1)
})

test('new exact context projection copies only three native pins and excludes irrelevant host metadata',async()=>{
  const f=fixture({context:{...CONTEXT,host_metadata:{note:'synthetic irrelevant host metadata'},unrelated:'synthetic-extra'}})
  try {
    f.connect()
    const snapshot=f.controller.getSnapshot(),context=snapshot.context
    assert.deepEqual(context,CONTEXT)
    assert.deepEqual(Object.keys(context),['owner_id','task_id','conversation_id'])
    assert.equal(Object.isFrozen(context),true)
    assert.notEqual(context,f.client.context)
    assert.equal(JSON.stringify(snapshot).includes('synthetic irrelevant host metadata'),false)
    f.client.context.host_metadata.note='changed irrelevant host metadata'
    f.client.context.unrelated='changed extra field'
    const result=await f.controller.request('synthetic text')
    assert.equal(result?.outcome,'completed','irrelevant host metadata does not replace the three selected pins')
    assert.deepEqual(f.controller.getSnapshot().context,CONTEXT)
    assert.equal(f.calls.length,1)
  } finally {f.dispose()}
})

test('new presentation generation remounts owner and binding lifetimes while remaining stable during a request',async()=>{
  const f=fixture(),hold=deferred()
  try {
    const initial=f.controller.getSnapshot().generation
    assert.equal(Number.isSafeInteger(initial),true)
    f.connect()
    const connected=f.controller.getSnapshot().generation
    assert.ok(connected>initial)
    f.setRequest(()=>hold.promise)
    const pending=f.controller.request('synthetic literal text')
    assert.equal(f.controller.getSnapshot().generation,connected,'pending does not remount the captured textarea')
    await Promise.resolve()
    hold.resolve(completed())
    assert.equal((await pending)?.outcome,'completed')
    assert.equal(f.controller.getSnapshot().generation,connected,'completed projection keeps its current presentation lifetime')
    f.availability.emit(f.availability.getSnapshot())
    assert.equal(f.controller.getSnapshot().generation,connected,'an unchanged availability notification does not remount')
    f.owner.emit(ownerState())
    const renewed=f.controller.getSnapshot().generation
    assert.ok(renewed>connected,'a fresh owner object clears the old transient input lifetime')
    assert.equal(f.controller.getSnapshot().result,null)
    f.connect()
    const rebound=f.controller.getSnapshot().generation
    assert.ok(rebound>renewed,'a new native binding frame remounts transient text')
    f.owner.emit(ownerState({owner:null,authority_available:false}))
    assert.ok(f.controller.getSnapshot().generation>rebound,'logout clears the owner presentation lifetime')
  } finally {hold.resolve(completed());f.dispose()}
})

test('new invalid or throwing request identity reports one fixed reason and sends no callback',async()=>{
  const reason='A fresh request identity could not be created. No request was sent.'
  for(const requestId of [()=>null,()=>'',()=> 'not-a-uuid',()=>{throw Error('synthetic internal identity detail')}]) {
    const f=fixture({requestId})
    try {
      f.connect()
      const generation=f.controller.getSnapshot().generation
      assert.equal(await f.controller.request('synthetic text'),null)
      const snapshot=f.controller.getSnapshot()
      assert.equal(snapshot.reason,reason)
      assert.equal(snapshot.phase,'idle')
      assert.equal(snapshot.result,null);assert.equal(snapshot.request_uuid,null)
      assert.equal(snapshot.generation,generation)
      assert.equal(f.calls.length,0);assert.equal(f.ids,1)
      assert.equal(JSON.stringify(snapshot).includes('synthetic internal identity detail'),false)
    } finally {f.dispose()}
  }
})

test('new reused request identity is refused after completion and fresh owner binding without dispatch',async()=>{
  const f=fixture({requestId:()=>UUID})
  try {
    f.connect()
    const result=await f.controller.request('synthetic first text')
    assert.equal(result?.outcome,'completed');assert.equal(f.calls.length,1)
    assert.equal(await f.controller.request('synthetic second text'),null)
    assert.equal(f.calls.length,1);assert.equal(f.ids,2)
    assert.equal(f.controller.getSnapshot().reason,'A fresh request identity could not be created. No request was sent.')
    assert.deepEqual(f.controller.getSnapshot().result,result,'refused duplicate does not invent a second completion')
    f.owner.emit(ownerState());f.connect()
    assert.equal(await f.controller.request('synthetic reused identity after rebind'),null)
    assert.equal(f.calls.length,1);assert.equal(f.ids,3)
    assert.equal(f.controller.getSnapshot().result,null,'fresh owner view retains no former result')
    assert.equal(f.controller.getSnapshot().reason,'A fresh request identity could not be created. No request was sent.')
  } finally {f.dispose()}
})

test('regression reentrant availability unsubscribe preserves its newer replacement frame',async()=>{
  for(const action of ['connect','disconnect','cleanup']) {
    const f=fixture(),context={...CONTEXT,task_id:'synthetic-replacement-task',conversation_id:'synthetic-replacement-conversation'}
    const replacementCalls=[]
    let armed=false
    try {
      const originalSubscribe=f.availability.subscribe.bind(f.availability)
      const replacement={ownerController:f.owner,client:{...f.client,context,
        requestOne:async draft=>{replacementCalls.push(draft);return completed(draft.request_uuid,context)}}}
      f.availability.subscribe=listener=>{
        const off=originalSubscribe(listener)
        return()=>{off();if(armed){armed=false;f.controller.connect(replacement)}}
      }
      const oldCleanup=f.connect()
      armed=true
      let abandonedCleanup
      if(action==='connect') abandonedCleanup=f.controller.connect({...f.binding,client:{...f.client,
        context:{...CONTEXT,task_id:'synthetic-abandoned-outer-task'}}})
      else if(action==='disconnect') f.controller.disconnect()
      else oldCleanup()
      abandonedCleanup?.();oldCleanup()
      assert.deepEqual(f.controller.getSnapshot().context,context,action+' cannot overwrite unsubscribe-created replacement')
      assert.equal(f.controller.getSnapshot().available,true)
      assert.equal(f.availability.listenerCount,1,'only the newer frame keeps its subscription')
      assert.deepEqual(await f.controller.request('synthetic replacement request'),completed(UUID,context))
      assert.equal(replacementCalls.length,1);assert.equal(f.calls.length,0)
    } finally {armed=false;f.dispose()}
  }
})

test('regression entered abort callback preserves its newer frame through outer cleanup and stale refresh',async()=>{
  for(const action of ['connect','disconnect','cleanup','availability-loss']) {
    const f=fixture(),hold=deferred()
    const context={...CONTEXT,task_id:'synthetic-abort-replacement-task',conversation_id:'synthetic-abort-replacement-conversation'}
    const ready=observable({state:'ready',mode:'mock',reason:'Synthetic replacement ready.'}),replacementCalls=[]
    const replacement={ownerController:f.owner,client:{...f.client,context,availability:ready,
      requestOne:async draft=>{replacementCalls.push(draft);return completed(draft.request_uuid,context)}}}
    try {
      const oldCleanup=f.connect()
      f.setRequest((_draft,{signal})=>{
        signal.addEventListener('abort',()=>f.controller.connect(replacement),{once:true})
        return hold.promise
      })
      const pending=f.controller.request('synthetic old request')
      await Promise.resolve()
      assert.equal(f.calls.length,1)
      if(action==='connect') f.controller.connect({...f.binding,client:{...f.client,
        context:{...CONTEXT,task_id:'synthetic-abandoned-outer-task'}}})
      else if(action==='disconnect') f.controller.disconnect()
      else if(action==='cleanup') oldCleanup()
      else f.availability.emit({state:'unavailable',mode:null,reason:'Synthetic original availability lost.'})
      assert.equal(await pending,null)
      assert.equal(f.calls[0].options.signal.aborted,true)
      assert.deepEqual(f.controller.getSnapshot().context,context,action+' cannot overwrite abort-created replacement')
      assert.equal(f.controller.getSnapshot().available,true)
      assert.equal(f.availability.listenerCount,0);assert.equal(ready.listenerCount,1)
      hold.resolve(completed())
      await Promise.resolve()
      assert.equal(f.controller.getSnapshot().result,null,'discarded older callback cannot project into replacement')
      assert.deepEqual(await f.controller.request('synthetic replacement request'),completed(NEXT_UUID,context))
      assert.equal(replacementCalls.length,1);assert.equal(f.calls.length,1)
    } finally {hold.resolve(completed());f.dispose()}
  }
})

test('regression unrelated owner pending or unknown operation blocks new calls without cancelling an in-flight review',async()=>{
  const busy=[{phase:'login_pending'},{phase:'review_pending'},{phase:'approval_pending'},
    {phase:'outcome_unknown'},{phase:'idle',approval_action_pending:true}]
  for(const patch of busy) {
    const f=fixture({ownerSnapshot:ownerState(patch)})
    try {
      f.connect()
      assert.equal(f.controller.getSnapshot().available,false)
      assert.equal(await f.controller.request('synthetic new request while owner busy'),null)
      assert.equal(f.calls.length,0);assert.equal(f.ids,0)
      const previous=f.owner.getSnapshot()
      f.owner.emit({...previous,phase:'idle',approval_action_pending:false})
      assert.equal((await f.controller.request('synthetic request after owner operation settles'))?.outcome,'completed')
      assert.equal(f.calls.length,1)
    } finally {f.dispose()}
  }
  const f=fixture(),hold=deferred()
  try {
    f.connect();f.setRequest(()=>hold.promise)
    const pending=f.controller.request('synthetic reviewed inference request')
    await Promise.resolve()
    const previous=f.owner.getSnapshot()
    f.owner.emit({...previous,phase:'review_pending',approval_action_pending:true})
    assert.equal(f.controller.getSnapshot().phase,'pending')
    assert.equal(f.calls[0].options.signal.aborted,false,'the existing inference review does not cancel its own request')
    assert.equal(f.controller.request('duplicate during existing review'),pending)
    hold.resolve(completed())
    assert.deepEqual(await pending,completed())
    assert.equal(await f.controller.request('new request while review still pending'),null)
    assert.equal(f.calls.length,1);assert.equal(f.ids,1)
    f.owner.emit({...previous,phase:'idle',approval_action_pending:false})
    assert.equal(f.controller.getSnapshot().available,true)
  } finally {hold.resolve(completed());f.dispose()}
})

test('regression logout during completed notification discards caller text and leaves unavailable presentation',async()=>{
  const f=fixture()
  let loggedOut=false
  try {
    f.connect()
    const off=f.controller.subscribe(()=>{
      if(!loggedOut&&f.controller.getSnapshot().phase==='completed') {
        loggedOut=true
        f.owner.emit({...f.owner.getSnapshot(),owner:null,authority_available:false,logout_status:'confirmed'})
      }
    })
    assert.equal(await f.controller.request('synthetic reply followed by synchronous logout'),null)
    off()
    assert.equal(loggedOut,true);assert.equal(f.calls.length,1)
    const snapshot=f.controller.getSnapshot()
    assert.equal(snapshot.phase,'unavailable');assert.equal(snapshot.available,false)
    assert.equal(snapshot.context,null);assert.equal(snapshot.result,null)
    assert.equal(snapshot.request_uuid,null)
  } finally {f.dispose()}
})

test('regression abort-triggered same-frame logout cannot resurrect captured private context',async()=>{
  const f=fixture(),hold=deferred()
  let loggedOut=false
  try {
    f.connect()
    f.setRequest((_draft,{signal})=>{
      signal.addEventListener('abort',()=>{
        loggedOut=true
        f.owner.emit({...f.owner.getSnapshot(),owner:null,authority_available:false,logout_status:'confirmed'})
      },{once:true})
      return hold.promise
    })
    const pending=f.controller.request('synthetic request interrupted before its response')
    await Promise.resolve()
    assert.equal(f.calls.length,1)
    f.availability.emit({state:'unavailable',mode:null,reason:'Synthetic original availability lost.'})
    assert.equal(await pending,null)
    assert.equal(loggedOut,true);assert.equal(f.calls[0].options.signal.aborted,true)
    const snapshot=f.controller.getSnapshot()
    assert.equal(snapshot.phase,'unavailable');assert.equal(snapshot.available,false)
    assert.equal(snapshot.context,null,'refresh must re-read logged-out owner after the abort callback')
    assert.equal(snapshot.request_uuid,null,'unknown identity stays internal while owner is absent')
    assert.equal(snapshot.result,null)
    assert.equal(await f.controller.request('synthetic request while logged out'),null)
    assert.equal(f.calls.length,1);assert.equal(f.ids,1)
    hold.resolve(completed())
    await Promise.resolve()
    assert.equal(f.controller.getSnapshot().context,null,'late older callback cannot republish owner context')
    f.owner.emit(ownerState());f.availability.emit({state:'ready',mode:'mock',reason:'Synthetic callback ready.'})
    assert.equal(f.controller.getSnapshot().phase,'outcome_unknown','fresh authenticated view still retains unresolved request identity')
    assert.equal(await f.controller.request('synthetic blind retry after login'),null)
    assert.equal(f.calls.length,1)
  } finally {hold.resolve(completed());f.dispose()}
})
