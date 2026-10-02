// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic source checks only: no network, enrolled credential or crypto claim.
import assert from 'node:assert/strict'
import {pathToFileURL} from 'node:url'
import {createPrimeProviderController,createPublicProviderApi} from '../src/client/provider-controller.mjs'

let contractPath=null
const selectedNames=new Set(),arguments_=process.argv.slice(2)
for(let index=0;index<arguments_.length;index++){
  const argument=arguments_[index]
  if(argument==='--case'){
    const name=arguments_[++index]
    if(!name||name.startsWith('--'))throw new TypeError('provider-controller: --case requires an exact case name')
    selectedNames.add(name)
  }else if(argument.startsWith('--')||contractPath!==null)throw new TypeError('provider-controller: unexpected argument')
  else contractPath=argument
}
const contracts=await import(contractPath?pathToFileURL(contractPath).href:new URL('../../../contracts/src/browser.mjs',import.meta.url))
const START=Date.parse('2030-01-01T00:00:00.000Z'),ORIGIN='https://prime.example',ENTRY='/api/prime/inference/credential-entry'
const KEY='synthetic-key-provider-check-only',TICKET='T'.repeat(42)+'A'
const clone=value=>JSON.parse(JSON.stringify(value))
const iso=value=>new Date(value).toISOString()
let assertions=0,proofSerial=0
const eq=(actual,expected,message)=>{assertions++;assert.deepEqual(actual,expected,message)}
const ok=(value,message)=>{assertions++;assert.ok(value,message)}
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject}}
const turn=()=>new Promise(resolve=>queueMicrotask(resolve))
function namespace(configured=false){return{namespace:'prime-inference',section:{providers:{externalDeepSeek:{
  endpoint:'https://api.deepseek.com',model:'',region:'',allowedDataClasses:[],maxInputTokens:0,maxOutputTokens:0,maxRequests:0,
  enabled:false,credentialConfigured:configured,taskSpendCeiling:null}}}}}
function catalog(){return{version:1,providers:[{provider:'externalDeepSeek',displayName:'DeepSeek',settingsNs:'prime-inference',
  settingsPath:['providers','externalDeepSeek'],declared:false,active:false,endpoint:'https://api.deepseek.com',
  credential_entry:'separated_owner_handoff',paid_requests_enabled:false,models:[{id:'deepseek-flash',name:'DeepSeek V4.1 Flash',
    status:'unavailable',qualification:'documentation_only',source:'https://api-docs.deepseek.com/updates/',documented_release:'2026-09-10'}],
  credential_status:'unknown',pending:['owner_auth_join','secure_credential_service','approved_numeric_spend_cap','qualified_route']}],namespace:namespace()}}
function status(generation=null){return{version:1,provider:'externalDeepSeek',configured:false,config_digest:null,profile:null,
  credential:{configured:generation!==null,generation},paid_requests_enabled:false,pending:['qualified_separated_dispatch_join'],namespace:namespace(generation!==null)}}
function proof(owner_id='synthetic-owner',expiry=START+120000){const n=++proofSerial,raw=n.toString(16).padStart(64,'0');return{
  version:1,operation_id:`synthetic-operation-${n}`,operation_digest:'sha256:'+raw,owner_id,audience:'aukora-prime.inference',
  authorization_epoch:1,expiry:iso(expiry),nonce:raw,material:{kind:'owner_key',request:{domain:'aukora:owner-approval-request:v1',
    subject:'aukora:1:'+'1'.repeat(64),activeControlDigest:'2'.repeat(64),operationDigest:raw,challenge:'3'.repeat(64),
    issuedAt:START/1000,expiresAt:Math.floor(expiry/1000)},signature:'a'.repeat(128)}}}
function ownerObservable(expiry=START+300000){let snapshot={owner:{owner_id:'synthetic-owner',expiry:iso(expiry)},authority_available:true,expired:false};const listeners=new Set();return{
  getSnapshot:()=>snapshot,subscribe(fn){listeners.add(fn);return()=>listeners.delete(fn)},
  emit(patch){snapshot={...snapshot,...patch};for(const listener of [...listeners])listener()},
  logout(){this.emit({owner:null,authority_available:false})}}}
function response(text='{"configured":true,"generation":1}',ok=true){return{ok,status:ok?200:503,async text(){return text}}}
function fixture(options={}){
  let clock=START,owner=ownerObservable(options.ownerExpiry),handoffImpl,statusImpl,fetchImpl
  const calls={catalog:[],status:[],handoff:[],fetch:[],forbidden:[]},timers=new Set()
  const descriptor=()=>({provider:'externalDeepSeek',method:'POST',path:ENTRY,ticket:TICKET,expires_at:iso(clock+59000)})
  const api={catalog:async()=>{calls.catalog.push(true);return catalog()},status:async()=>{calls.status.push(true);return statusImpl?statusImpl():status()},
    credentialHandoff:async input=>{calls.handoff.push(clone(input));return handoffImpl?handoffImpl(input):descriptor()}}
  for(const name of ['credentials','settings','getCredential','setCredential'])Object.defineProperty(api,name,{get(){calls.forbidden.push(name);throw Error('forbidden generic API')}})
  const fetcher=async(path,init)=>{calls.fetch.push({path,init});return fetchImpl?fetchImpl(path,init):response()}
  const support=options.support??{origin:ORIGIN,isSecureContext:true}
  const controller=createPrimeProviderController({now:()=>clock,fetcher,browser:()=>support,
    schedule(fn,delay){const timer={fn,at:clock+delay,unref(){}};timers.add(timer);return timer},unschedule(timer){timers.delete(timer)}})
  const binding={contracts,ownerController:owner,api,entryProfile:options.profile===null?undefined:options.profile??{origin:ORIGIN,qualified_separate_worker:true}}
  controller.connect(binding)
  return{controller,binding,owner,calls,descriptor,
    setHandoff(fn){handoffImpl=fn},setStatus(fn){statusImpl=fn},setFetch(fn){fetchImpl=fn},
    advance(ms,{fire=true}={}){clock+=ms;if(fire)for(const timer of [...timers])if(timer.at<=clock){timers.delete(timer);timer.fn()}},
    async ready(generation=0){await controller.refreshOwner();const input={expected_generation:generation,approval_proof:proof()};eq(await controller.prepareCredentialEntry(input),{ready:true});return input},
    clean(){controller.dispose();eq(calls.forbidden,[],'no generic credential/settings access')},
  }
}
function noPrivateState(f){const text=JSON.stringify(f.controller.getSnapshot());for(const privateValue of [KEY,TICKET,'a'.repeat(128),'session-token-synthetic'])ok(!text.includes(privateValue),'state contains no credential/ticket/proof/token');
  eq(Object.keys(f.controller.getSnapshot()).sort(),['model_draft','catalog_status','owner_status','row','entry_status','reason'].sort())}
const cases=[],failures=[]
function test(name,run){cases.push({name,run})}

test('public default uses catalog only and preserves unconfigured backend',async()=>{
  const requests=[],publicApi=createPublicProviderApi(contracts,async(path,init)=>{requests.push({path,init});return response(JSON.stringify(catalog()))})
  eq(Object.keys(publicApi),['catalog']);eq(await publicApi.catalog(),catalog())
  eq(requests,[{path:'/api/prime/inference/catalog',init:{method:'GET',credentials:'same-origin',redirect:'error',cache:'no-store'}}])
  const f=fixture();await f.controller.load();eq(f.calls.catalog.length,1);eq(f.calls.status.length,0);eq(f.calls.handoff.length,0)
  eq(f.controller.getSnapshot().model_draft,'deepseek-flash');eq(f.controller.getSnapshot().row,namespace().section.providers.externalDeepSeek)
  f.controller.setModel('deepseek-flash');eq(f.calls.fetch.length,0);eq(f.controller.getSnapshot().row.model,'');eq(f.controller.getSnapshot().row.credentialConfigured,false)
  assertions++;assert.throws(()=>f.controller.setModel('invented-model'));noPrivateState(f);f.clean()
})
test('public textual ingress refuses duplicate keys and non-2xx',async()=>{
  for(const reply of [response('{"version":1,"version":1}'),response(JSON.stringify(catalog()),false)]){
    assertions++;await assert.rejects(createPublicProviderApi(contracts,async()=>reply).catalog())
  }
})
test('owner metadata maps null generation to zero and key goes once to fixed worker path',async()=>{
  const f=fixture(),input=await f.ready();eq(f.calls.handoff[0],input);ok(f.calls.handoff[0]!==input,'handoff input detached');eq(f.controller.getSnapshot().row.enabled,false);noPrivateState(f)
  const pending=deferred(),element={value:KEY};f.setFetch(()=>{eq(element.value,'','input cleared before fake dispatch is entered');return pending.promise});const submitted=f.controller.submitCredential(element)
  eq(element.value,'','input cleared before fetch reply');eq(f.calls.fetch.length,1)
  const request=f.calls.fetch[0];eq(request.path,ENTRY);eq({...request.init,body:undefined},{method:'POST',credentials:'same-origin',redirect:'error',cache:'no-store',headers:{'content-type':'application/json'},body:undefined})
  eq(contracts.parseStrictJson(request.init.body),{ticket:TICKET,secret:KEY});eq(f.controller.getSnapshot().entry_status,'pending');noPrivateState(f)
  pending.resolve(response());eq(await submitted,{configured:true,generation:1});eq(f.controller.getSnapshot().entry_status,'configured');eq(f.controller.getSnapshot().row.credentialConfigured,true);eq(f.controller.getSnapshot().row.enabled,false)
  eq(await f.controller.submitCredential({value:KEY}),null);eq(f.calls.fetch.length,1);noPrivateState(f);f.clean()
})
test('invalid credential input preserves unused ticket for corrected single dispatch',async()=>{
  const invalid=[['short','A'.repeat(7)],['long','A'.repeat(4097)],['space','synthetic key rejected'],
    ['control','synthetic\u0000key-rejected'],['non-ASCII','synthetic-\u00e9-key-rejected']]
  for(const [kind,secret]of invalid){
    const f=fixture();await f.ready();const rejected={value:secret}
    eq(await f.controller.submitCredential(rejected),null,kind+' input refused')
    eq(rejected.value,'',kind+' input cleared');eq(f.calls.fetch.length,0,kind+' refusal sends nothing')
    eq(f.calls.handoff.length,1,kind+' refusal mints no new ticket');eq(f.controller.getSnapshot().entry_status,'ready',kind+' refusal preserves unused ready ticket')
    ok(!JSON.stringify(f.controller.getSnapshot()).includes(secret),kind+' input stays out of public state');noPrivateState(f)
    const corrected={value:KEY}
    eq(await f.controller.submitCredential(corrected),{configured:true,generation:1},kind+' correction uses retained unexpired ticket')
    eq(corrected.value,'');eq(f.calls.fetch.length,1);eq(f.calls.handoff.length,1)
    eq(contracts.parseStrictJson(f.calls.fetch[0].init.body),{ticket:TICKET,secret:KEY},kind+' correction retains exact original ticket and literal synthetic key')
    const repeat={value:KEY};eq(await f.controller.submitCredential(repeat),null);eq(repeat.value,'');eq(f.calls.fetch.length,1,kind+' correction dispatched once')
    noPrivateState(f);f.clean()
  }
})
test('ticket expiry after invalid input prevents corrected dispatch before timer notification',async()=>{
  const f=fixture();await f.ready();const rejected={value:'short'}
  eq(await f.controller.submitCredential(rejected),null);eq(rejected.value,'');eq(f.controller.getSnapshot().entry_status,'ready');eq(f.calls.fetch.length,0)
  f.advance(59001,{fire:false})
  eq(f.controller.getSnapshot().entry_status,'ready','expiry notification has deliberately not fired')
  const corrected={value:KEY};eq(await f.controller.submitCredential(corrected),null);eq(corrected.value,'')
  eq(f.calls.fetch.length,0,'expired retained ticket sends no corrected key');eq(f.calls.handoff.length,1,'no replacement handoff requested')
  eq(f.controller.getSnapshot().entry_status,'unavailable');noPrivateState(f);f.clean()
})
test('existing credential generation requires exact next acknowledgement',async()=>{
  const f=fixture();f.setStatus(()=>status(2));await f.ready(2);f.setFetch(()=>response('{"configured":true,"generation":3}'))
  eq(await f.controller.submitCredential({value:KEY}),{configured:true,generation:3});eq(f.calls.handoff[0].expected_generation,2);f.clean()
})
test('proof shape owner expiry generation and request closure refuse before handoff',async()=>{
  const invalid=[()=>({expected_generation:1,approval_proof:proof()}),()=>({expected_generation:0,approval_proof:proof('other-owner')}),
    ()=>({expected_generation:0,approval_proof:proof('synthetic-owner',START)}),()=>{const p=proof();p.material.signature='';return{expected_generation:0,approval_proof:p}},
    ()=>({expected_generation:0,approval_proof:proof(),secret:KEY})]
  for(const make of invalid){const f=fixture();await f.controller.refreshOwner();eq(await f.controller.prepareCredentialEntry(make()),null);eq(f.calls.handoff.length,0);eq(f.calls.fetch.length,0);noPrivateState(f);f.clean()}
})
test('malformed owner namespace or credential generation disables handoff',async()=>{
  const invalid=[s=>({...s,secret:KEY}),s=>({...s,version:2}),s=>({...s,provider:'other'}),
    s=>({...s,credential:{configured:false,generation:0}}),s=>({...s,credential:{configured:false,generation:1.5}}),
    s=>({...s,credential:{configured:false,generation:-1}}),s=>({...s,credential:{configured:false,generation:null,secret:KEY}}),
    s=>({...s,namespace:namespace(true)}),s=>{s.namespace.section.providers.externalDeepSeek.enabled=true;return s}]
  for(const mutate of invalid){const f=fixture();f.setStatus(()=>mutate(status()));eq(await f.controller.refreshOwner(),null);eq(f.controller.getSnapshot().owner_status,'unavailable')
    eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null);eq(f.calls.handoff.length,0);eq(f.calls.fetch.length,0);noPrivateState(f);f.clean()}
})
test('entry requires exact qualified secure origin without an HTTP pilot fallback',async()=>{
  const unsupported=[{profile:null},{profile:{origin:ORIGIN,qualified_separate_worker:false}},
    {profile:{origin:ORIGIN,qualified_separate_worker:true,extra:true}},
    ...['http://localhost:18731','http://127.0.0.1:18731'].map(origin=>({profile:{origin,qualified_separate_worker:true},support:{origin,isSecureContext:true}})),
    {support:{origin:'https://other.example',isSecureContext:true}},{support:{origin:ORIGIN,isSecureContext:false}}]
  for(const options of unsupported){const f=fixture(options);await f.controller.refreshOwner();eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null);eq(f.calls.handoff.length,0);eq(f.calls.fetch.length,0);f.clean()}
  // The trusted exact HTTPS profile governs eligibility; hostname alone adds no B restriction.
  const origin='https://localhost:18731',f=fixture({profile:{origin,qualified_separate_worker:true},support:{origin,isSecureContext:true}});await f.ready();f.clean()
})
test('pending handoff coalesces and a ready ticket does not mint another',async()=>{
  const f=fixture(),hold=deferred();await f.controller.refreshOwner();f.setHandoff(()=>hold.promise)
  const input={expected_generation:0,approval_proof:proof()},first=f.controller.prepareCredentialEntry(input),second=f.controller.prepareCredentialEntry(input)
  eq(first,second,'pending promise is coalesced');await turn();eq(f.calls.handoff.length,1);eq(f.controller.getSnapshot().entry_status,'pending')
  hold.resolve(f.descriptor());eq(await first,{ready:true});eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null);eq(f.calls.handoff.length,1);f.clean()
})
test('malformed or expired handoff results are unknown and never retried',async()=>{
  const mutators=[d=>({...d,provider:'other'}),d=>({...d,method:'GET'}),d=>({...d,path:'/generic/credentials'}),d=>({...d,ticket:'A'.repeat(42)}),
    d=>({...d,ticket:'='.repeat(43)}),d=>({...d,expires_at:iso(START)}),d=>({...d,expires_at:iso(START+60001)}),d=>({...d,extra:true})]
  for(const mutate of mutators){const f=fixture();await f.controller.refreshOwner();f.setHandoff(()=>mutate(f.descriptor()));eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null)
    eq(f.controller.getSnapshot().entry_status,'unknown');eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null);eq(f.calls.handoff.length,1);eq(f.calls.fetch.length,0);noPrivateState(f);f.clean()}
  const f=fixture({ownerExpiry:START+30000});await f.controller.refreshOwner();f.setHandoff(()=>({...f.descriptor(),expires_at:iso(START+31000)}));eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null);eq(f.controller.getSnapshot().entry_status,'unknown');f.clean()
})
test('lost handoff remains unknown across status refresh and repeated prepare',async()=>{
  const f=fixture();await f.controller.refreshOwner();f.setHandoff(()=>{throw Error('synthetic lost handoff reply')})
  eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null);eq(f.controller.getSnapshot().entry_status,'unknown')
  await f.controller.refreshOwner();eq(f.controller.getSnapshot().entry_status,'unknown');eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null);eq(f.calls.handoff.length,1);f.clean()
})
test('failed metadata refresh cannot reopen an unknown handoff or storage result',async()=>{
  for(const stage of ['handoff','worker'])for(const badStatus of [()=>{throw Error('synthetic status failure')},()=>({version:1})]){
    const f=fixture();await f.controller.refreshOwner()
    if(stage==='handoff'){f.setHandoff(()=>{throw Error('synthetic handoff failure')});await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()})}
    else{await f.ready();f.setFetch(()=>{throw Error('synthetic storage failure')});await f.controller.submitCredential({value:KEY})}
    eq(f.controller.getSnapshot().entry_status,'unknown');f.setStatus(badStatus);eq(await f.controller.refreshOwner(),null);eq(f.controller.getSnapshot().entry_status,'unknown')
    eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null);const input={value:KEY};eq(await f.controller.submitCredential(input),null);eq(input.value,'')
    eq(f.calls.handoff.length,1);eq(f.calls.fetch.length,stage==='handoff'?0:1);noPrivateState(f);f.clean()
  }
})
test('secret echoes duplicates non-2xx malformed ACK and lost replies cannot retry',async()=>{
  const replies=[()=>response('{"configured":true,"generation":1,"secret":"'+KEY+'"}'),()=>response('{"configured":true,"generation":1,"ticket":"'+TICKET+'"}'),
    ()=>response('{"configured":true,"generation":1,"configured":true}'),()=>response('{"configured":true,"generation":1}',false),
    ()=>response('{"configured":false,"generation":1}'),()=>response('{"configured":true,"generation":2}'),()=>response('invalid json'),()=>{throw Error('synthetic lost worker reply')}]
  for(const reply of replies){const f=fixture();await f.ready();f.setFetch(reply);const element={value:KEY};eq(await f.controller.submitCredential(element),null);eq(element.value,'');eq(f.controller.getSnapshot().entry_status,'unknown')
    await f.controller.refreshOwner();eq(f.controller.getSnapshot().entry_status,'unknown');const repeat={value:KEY};eq(await f.controller.submitCredential(repeat),null);eq(repeat.value,'');eq(await f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()}),null)
    eq(f.calls.fetch.length,1);eq(f.calls.handoff.length,1);noPrivateState(f);f.clean()}
})
test('refresh while handoff or key reply is pending cannot reopen entry',async()=>{
  for(const stage of ['handoff','worker']){const f=fixture(),hold=deferred();await f.controller.refreshOwner();let pending
    if(stage==='handoff'){f.setHandoff(()=>hold.promise);pending=f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()});await turn()}
    else{await f.ready();f.setFetch(()=>hold.promise);pending=f.controller.submitCredential({value:KEY})}
    eq(f.controller.getSnapshot().entry_status,'pending');await f.controller.refreshOwner();eq(f.controller.getSnapshot().entry_status,'pending')
    const repeated=f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()})
    if(stage==='handoff')eq(repeated,pending,'in-flight handoff remains coalesced');else eq(await repeated,null)
    eq(f.calls.handoff.length,1)
    hold.resolve(stage==='handoff'?f.descriptor():response());await pending;f.clean()
  }
})
test('approved handoff keeps its reviewed generation during a concurrent status refresh',async()=>{
  const f=fixture(),hold=deferred();await f.controller.refreshOwner();f.setHandoff(()=>hold.promise)
  const pending=f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()});await turn();f.setStatus(()=>status(1));await f.controller.refreshOwner()
  hold.resolve(f.descriptor());eq(await pending,{ready:true});eq(await f.controller.submitCredential({value:KEY}),{configured:true,generation:1},'ACK follows approved generation zero, not later display status')
  f.clean()
})
test('a status read started before storage ACK cannot regress acknowledged metadata',async()=>{
  const f=fixture(),hold=deferred();await f.ready();f.setStatus(()=>hold.promise)
  const refreshing=f.controller.refreshOwner();eq(await f.controller.submitCredential({value:KEY}),{configured:true,generation:1})
  hold.resolve(status());await refreshing
  eq(f.controller.getSnapshot().entry_status,'configured');eq(f.controller.getSnapshot().row.credentialConfigured,true,'older metadata must not erase the completed storage acknowledgement')
  eq(await f.controller.prepareCredentialEntry({expected_generation:1,approval_proof:proof()}),{ready:true},'older status must not roll back the next expected generation')
  f.clean()
})
test('overlapping status reads retain the newest authenticated generation',async()=>{
  const f=fixture(),older=deferred(),newer=deferred();f.setStatus(()=>f.calls.status.length===1?older.promise:newer.promise)
  const first=f.controller.refreshOwner(),second=f.controller.refreshOwner();eq(f.calls.status.length,2)
  newer.resolve(status(2));await second;older.resolve(status(1));await first
  eq(f.controller.getSnapshot().row.credentialConfigured,true);eq(f.controller.getSnapshot().owner_status,'loaded')
  eq(await f.controller.prepareCredentialEntry({expected_generation:2,approval_proof:proof()}),{ready:true});eq(f.calls.handoff[0].expected_generation,2)
  f.setFetch(()=>response('{"configured":true,"generation":3}'));eq(await f.controller.submitCredential({value:KEY}),{configured:true,generation:3});f.clean()
})
test('owner loss during status pending notification prevents owner API dispatch',async()=>{
  const f=fixture(),off=f.controller.subscribe(()=>{if(f.controller.getSnapshot().owner_status==='pending')f.owner.logout()})
  eq(await f.controller.refreshOwner(),null);eq(f.calls.status.length,0);eq(f.controller.getSnapshot().owner_status,'unavailable');eq(f.calls.fetch.length,0);off();f.clean()
})
test('logout before microtask or during handoff prevents any stale ready state',async()=>{
  const f=fixture();await f.controller.refreshOwner();const pending=f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()});f.owner.logout();eq(await pending,null);eq(f.calls.handoff.length,0);eq(f.calls.fetch.length,0);eq(f.controller.getSnapshot().entry_status,'unavailable');f.clean()
  const g=fixture(),hold=deferred();await g.controller.refreshOwner();g.setHandoff(()=>hold.promise);const waiting=g.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()});await turn();g.owner.logout();hold.resolve(g.descriptor());eq(await waiting,null);eq(g.controller.getSnapshot().entry_status,'unavailable');eq(g.calls.fetch.length,0);g.clean()
})
test('logout immediately before send or after send fences worker completion',async()=>{
  const f=fixture();await f.ready();const off=f.controller.subscribe(()=>{if(f.controller.getSnapshot().entry_status==='pending')f.owner.logout()})
  const input={value:KEY};eq(await f.controller.submitCredential(input),null);eq(input.value,'');eq(f.calls.fetch.length,0);eq(f.controller.getSnapshot().entry_status,'unavailable');off();f.clean()
  const g=fixture(),hold=deferred();await g.ready();g.setFetch(()=>hold.promise);const element={value:KEY},pending=g.controller.submitCredential(element);eq(g.calls.fetch.length,1);g.owner.logout()
  g.owner.emit({owner:{owner_id:'new-synthetic-owner',expiry:iso(START+300000)},authority_available:true});await g.controller.refreshOwner();hold.resolve(response());eq(await pending,null)
  eq(g.controller.getSnapshot().row.credentialConfigured,false);ok(g.controller.getSnapshot().entry_status!=='configured','late acknowledgement cannot configure replacement owner');noPrivateState(g);g.clean()
})
test('same-owner authority loss revokes an unused ticket and cannot revive it',async()=>{
  for(const loss of [{authority_available:false},{expired:true}]){const f=fixture();await f.ready();f.owner.emit(loss);eq(f.controller.getSnapshot().entry_status,'unavailable');f.owner.emit({authority_available:true,expired:false});const input={value:KEY};eq(await f.controller.submitCredential(input),null);eq(input.value,'');eq(f.calls.fetch.length,0);f.clean()}
})
test('same-owner authority loss fences pending handoff and worker replies',async()=>{
  for(const stage of ['handoff','worker']){const f=fixture(),hold=deferred();await f.controller.refreshOwner();let pending
    if(stage==='handoff'){f.setHandoff(()=>hold.promise);pending=f.controller.prepareCredentialEntry({expected_generation:0,approval_proof:proof()});await turn()}
    else{await f.ready();f.setFetch(()=>hold.promise);pending=f.controller.submitCredential({value:KEY})}
    f.owner.emit({authority_available:false});f.owner.emit({authority_available:true});hold.resolve(stage==='handoff'?f.descriptor():response());eq(await pending,null)
    eq(f.controller.getSnapshot().entry_status,'unavailable');eq(f.controller.getSnapshot().row.credentialConfigured,false);eq(f.calls.fetch.length,stage==='worker'?1:0);f.clean()
  }
})
test('logout during delayed textual ACK parsing cannot configure replacement owner',async()=>{
  const f=fixture(),entered=deferred(),body=deferred();await f.ready();f.setFetch(()=>({ok:true,status:200,text(){entered.resolve();return body.promise}}))
  const pending=f.controller.submitCredential({value:KEY});await entered.promise;f.owner.logout();f.owner.emit({owner:{owner_id:'replacement-synthetic-owner',expiry:iso(START+300000)},authority_available:true})
  await f.controller.refreshOwner();body.resolve('{"configured":true,"generation":1}');eq(await pending,null);eq(f.controller.getSnapshot().row.credentialConfigured,false)
  ok(f.controller.getSnapshot().entry_status!=='configured');eq(f.calls.fetch.length,1);f.clean()
})
test('expiry disables an unused ticket and clears attempted key without a send',async()=>{
  const f=fixture();await f.ready();f.advance(59001);eq(f.controller.getSnapshot().entry_status,'unavailable');const input={value:KEY};eq(await f.controller.submitCredential(input),null);eq(input.value,'');eq(f.calls.fetch.length,0);f.clean()
})
test('public reload retains owner metadata and used approval cannot mint again',async()=>{
  const f=fixture();f.setStatus(()=>status(2));const input=await f.ready(2);await f.controller.load();eq(f.controller.getSnapshot().row.credentialConfigured,true)
  f.setFetch(()=>response('{"configured":true,"generation":3}'));eq(await f.controller.submitCredential({value:KEY}),{configured:true,generation:3});eq(await f.controller.prepareCredentialEntry({...input,expected_generation:3}),null);eq(f.calls.handoff.length,1);f.clean()
})

for(const name of selectedNames)if(!cases.some(test=>test.name===name))throw new TypeError('provider-controller: unknown selected case '+name)
const selected=selectedNames.size?cases.filter(test=>selectedNames.has(test.name)):cases
for(const {name,run}of selected){try{await run()}catch(error){failures.push({name,error:error?.message??String(error)})}}
console.log(JSON.stringify({check:'provider-controller',source_only:true,network_calls:0,cryptographic_verification_claimed:false,
  cases:selected.length,available_cases:cases.length,excluded_cases:cases.length-selected.length,case_names:selected.map(test=>test.name),
  assertions,passed:selected.length-failures.length,failures},null,2))
if(failures.length)process.exitCode=1
