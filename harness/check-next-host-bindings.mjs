// SPDX-License-Identifier: AGPL-3.0-or-later
// Scoped SOURCE fixtures only: no listener, provider network, keys, enrollment,
// live services or runtime qualification. TEST_ONLY doubles cannot qualify a
// host. The producer arms use the actual pinned Cordis/DSH adapter registry.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {EventEmitter} from 'node:events';
import {createRequire} from 'node:module';
import * as contracts from '../packages/contracts/src/runtime.mjs';
import {createNextHostRoutes,HOST_BROWSER_MODULES} from './next-host-services.mjs';
import {createOwnerInferenceClient,mountOwnerInferenceClient} from './owner-inference-client.mjs';
import {createDshOwnerInferenceProducer} from './owner-inference-producer.mjs';
import {createAcceptedOwnerSessionObserver} from './native-host-client.mjs';
import {prepareRequest} from '../packages/inference/src/policy.mjs';
import {fixture as TEST_ONLY_inferencePolicy} from '../packages/runtime-bridge/checks/inference-fixture.mjs';

const TEST_ONLY_CONTEXT=Object.freeze({owner_id:'source-owner',task_id:'source-task',conversation_id:'source-conversation'});
const TEST_ONLY_UUID='11111111-1111-4111-8111-111111111111';
const TEST_ONLY_OTHER_UUID='22222222-2222-4222-8222-222222222222';
const TEST_ONLY_SESSION='a'.repeat(64);
const TEST_ONLY_DRAFT=Object.freeze({request_uuid:TEST_ONLY_UUID,text:'Literal source-only request <tag>\n🍌'});
const TEST_ONLY_READY=Object.freeze({state:'ready',mode:'production',reason:'TEST_ONLY source fixture, no runtime qualification.'});
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
const flush=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
const owner=()=>Object.freeze({owner_id:TEST_ONLY_CONTEXT.owner_id,expiry:new Date(Date.now()+60000).toISOString()});
const result=(uuid=TEST_ONLY_UUID)=>({request_uuid:uuid,outcome:'completed',mode:'production',route_id:'source-route',
 proposal:{text:'TEST_ONLY source reply',grantsAuthority:false},usage:{input_tokens:1,output_tokens:1,cost_microusd:1},
 receipt:{request_uuid:uuid,sessionId:TEST_ONLY_CONTEXT.conversation_id,body_sha256:'b'.repeat(64),
  source_citation:{sha256:'c'.repeat(64),requestId:'source-request'},citations:[]}});

function TEST_ONLY_request(text,{method='POST',headers={},chunks}={}){
 let reads=0,destroyed=false;
 return {method,headers:{host:'localhost:18731',origin:'http://localhost:18731','content-type':'application/json',...headers},
  async *[Symbol.asyncIterator](){reads++;for(const chunk of chunks??[Buffer.from(text??'')])yield chunk;},
  destroy(){destroyed=true;},get reads(){return reads;},get destroyed(){return destroyed;}};
}
function TEST_ONLY_response(){
 const value=new EventEmitter();Object.assign(value,{destroyed:false,writableEnded:false,status:null,headers:null,bytes:null,
  writeHead(status,headers){this.status=status;this.headers=headers;},
  end(bytes){this.bytes=bytes;this.writableEnded=true;},
  json(){return this.bytes===undefined?undefined:contracts.parseStrictJson(String(this.bytes));}});return value;
}
function TEST_ONLY_routes(getServices,requestRejection=()=>undefined){
 const routes=createNextHostRoutes({root:new URL('..',import.meta.url).pathname,contracts,
  connection:{requestRejection},getServices});
 return {routes,handler(path){const selected=routes.find(route=>route.path===path);assert.ok(selected);return selected.handler;}};
}
const TEST_ONLY_runtime=(changes={})=>{const actor=owner();return {
 guardRequest:()=>({origin:'http://localhost:18731'}),authenticateOwner:async()=>actor,
 producer:{context:TEST_ONLY_CONTEXT,status:async()=>TEST_ONLY_READY,requestOne:async()=>result()},...changes};};
const statusBody=()=>contracts.canonicalJson({session_token:TEST_ONLY_SESSION});
const requestBody=()=>contracts.canonicalJson({...TEST_ONLY_DRAFT,session_token:TEST_ONLY_SESSION});

test('SOURCE host refuses unmounted services and a missing preview guard before reading any body',async()=>{
 for(const suffix of ['status','request-one']){
  const req=TEST_ONLY_request('must not be read'),res=TEST_ONLY_response();
  await TEST_ONLY_routes(()=>undefined).handler('/api/prime/inference/'+suffix)(req,res);
  assert.equal(res.status,503);assert.equal(req.reads,0);
  assert.equal(res.json().reason,'GENUINE_INFERENCE_HOST_UNMOUNTED');
 }
 let serviceReads=0;
 const req=TEST_ONLY_request(requestBody()),res=TEST_ONLY_response();
 await TEST_ONLY_routes(()=>{serviceReads++;return {inference:TEST_ONLY_runtime()};},()=>403)
  .handler('/api/prime/inference/request-one')(req,res);
 assert.equal(res.status,403);assert.equal(req.reads,0);assert.equal(serviceReads,0);
 const missing=createNextHostRoutes({root:'.',contracts,getServices:()=>assert.fail('guard must precede services')});
 const noGuard=TEST_ONLY_response();await missing.find(row=>row.path==='/api/prime/host/bootstrap').handler(TEST_ONLY_request(''),noGuard);
 assert.equal(noGuard.status,403);
});

test('SOURCE guarded browser closure exposes exact browser modules only; bootstrap remains unavailable',async()=>{
 const {routes,handler}=TEST_ONLY_routes(()=>undefined);
 assert.equal(new Set(HOST_BROWSER_MODULES).size,HOST_BROWSER_MODULES.length);
 assert.ok(HOST_BROWSER_MODULES.includes('harness/owner-inference-client.mjs'));
 assert.equal(HOST_BROWSER_MODULES.some(path=>/producer|credential|worker|node_modules|(^|\/)\.\.(\/|$)/.test(path)),false);
 assert.ok(routes.every(row=>row.kind==='exact'));
 assert.equal(routes.some(row=>row.path==='/prime/harness/owner-inference-producer.mjs'),false);
 const res=TEST_ONLY_response();await handler('/api/prime/host/bootstrap')(TEST_ONLY_request('',{method:'GET'}),res);
 assert.equal(res.status,503);assert.equal(res.json().error_code,'UNAVAILABLE');
 const moduleRes=TEST_ONLY_response();await handler('/prime/harness/owner-inference-client.mjs')
  (TEST_ONLY_request('',{method:'DELETE'}),moduleRes);
 assert.equal(moduleRes.status,405);
 const valid={context:TEST_ONLY_CONTEXT,ownerBinding:{owner_id:TEST_ONLY_CONTEXT.owner_id,
  passkeyProfile:{profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'}}};
 const positive=TEST_ONLY_response();await TEST_ONLY_routes(()=>({browserBinding:valid})).handler('/api/prime/host/bootstrap')
  (TEST_ONLY_request('',{method:'GET'}),positive);assert.equal(positive.status,200);assert.equal(positive.json().ok,true);
 for(const change of [{origin:'http://127.0.0.1:18731'},{origin:'http://localhost:18732'},{rp_id:'localhost.'},{extra:true}]){
  const selected=structuredClone(valid);Object.assign(selected.ownerBinding.passkeyProfile,change);
  const refused=TEST_ONLY_response();await TEST_ONLY_routes(()=>({browserBinding:selected})).handler('/api/prime/host/bootstrap')
   (TEST_ONLY_request('',{method:'GET'}),refused);
  assert.equal(refused.status,503);assert.equal(refused.json().reason,'GENUINE_HOST_BINDING_INVALID');
 }
});

test('SOURCE strict duplicate, invalid UTF-8, extra session fields and origin mismatches never authenticate',async()=>{
 let authCalls=0;
 const runtime=TEST_ONLY_runtime({authenticateOwner:async()=>{authCalls++;return owner();}});
 const cases=[
  {text:`{"session_token":"${TEST_ONLY_SESSION}","session_token":"${TEST_ONLY_SESSION}"}`},
  {text:contracts.canonicalJson({session_token:TEST_ONLY_SESSION,owner_id:'guest-owner'})},
  {chunks:[Buffer.from([0xc3,0x28])]},
  {text:statusBody(),headers:{'content-type':'text/plain'}},
  {text:statusBody(),headers:{origin:'http://foreign.example'}},
 ];
 for(const [index,item] of cases.entries()){const req=TEST_ONLY_request(item.text,item),res=TEST_ONLY_response();
  await TEST_ONLY_routes(()=>({inference:runtime})).handler('/api/prime/inference/status')(req,res);
  assert.ok([400,401].includes(res.status),`ingress case ${index}: status=${res.status}, code=${res.json().error_code}`);assert.equal(res.json().ok,false);
 }
 assert.equal(authCalls,0);
});

test('SOURCE withdrawing runtime during real route waits prevents status or request dispatch',async()=>{
 for(const suffix of ['status','request-one']){
  const admitted=deferred(),entered=deferred();let statusCalls=0,requestCalls=0;
  const runtime=TEST_ONLY_runtime({authenticateOwner:async()=>{entered.resolve();return admitted.promise;},producer:{context:TEST_ONLY_CONTEXT,
   status:async()=>{statusCalls++;return TEST_ONLY_READY;},requestOne:async()=>{requestCalls++;return result();}}});
  let selected=runtime;const req=TEST_ONLY_request(suffix==='status'?statusBody():requestBody()),res=TEST_ONLY_response();
  const pending=TEST_ONLY_routes(()=>({inference:selected})).handler('/api/prime/inference/'+suffix)(req,res);
  await entered.promise;selected=undefined;admitted.resolve(owner());await pending;
  assert.equal(res.status,503);assert.equal(statusCalls,0);assert.equal(requestCalls,0);
 }
 const wait=deferred(),entered=deferred();
 const runtime=TEST_ONLY_runtime({producer:{context:TEST_ONLY_CONTEXT,status:async()=>{entered.resolve();return wait.promise;}}});
 let selected=runtime;const res=TEST_ONLY_response();
 const pending=TEST_ONLY_routes(()=>({inference:selected})).handler('/api/prime/inference/status')(TEST_ONLY_request(statusBody()),res);
 await entered.promise;selected=undefined;wait.resolve(TEST_ONLY_READY);await pending;
 assert.equal(res.status,503);assert.equal(res.json().error_code,'UNAVAILABLE');
});

test('SOURCE returned request result requires the same live service and a freshly confirmed owner lifetime',async()=>{
 for(const scenario of ['withdrawn','logout','changed-expiry','auth-throws']){
  const entered=deferred(),reply=deferred();let authCalls=0,current=true;const original=owner();
  const runtime=TEST_ONLY_runtime({authenticateOwner:async()=>{authCalls++;if(authCalls===1)return original;
   if(scenario==='auth-throws')throw Object.assign(new Error('TEST_ONLY missing owner after attempt'),{error_code:'UNAUTHORIZED'});
   return scenario==='logout'?null:{...original,expiry:new Date(Date.parse(original.expiry)+1000).toISOString()};},
   producer:{context:TEST_ONLY_CONTEXT,requestOne:async(_draft,{isCurrent})=>{assert.equal(isCurrent(),true);entered.resolve();await reply.promise;return result();}}});
  const res=TEST_ONLY_response();const pending=TEST_ONLY_routes(()=>({inference:current?runtime:undefined}))
   .handler('/api/prime/inference/request-one')(TEST_ONLY_request(requestBody()),res);
  await entered.promise;if(scenario==='withdrawn')current=false;reply.resolve();await pending;
  assert.equal(res.status,503);assert.equal(res.json().error_code,'OUTCOME_UNKNOWN');
  assert.equal(authCalls,scenario==='withdrawn'?1:2);
 }
});

function TEST_ONLY_controller(){
 let state={owner:null,authority_available:true},offCalls=0;const listeners=new Set();
 return {getSnapshot:()=>state,subscribe(callback){listeners.add(callback);return()=>{offCalls++;listeners.delete(callback);};},
  setOwner(value,{notify=true}={}){state={...state,owner:value};if(notify)for(const fn of [...listeners])fn();},
  emit(){for(const fn of [...listeners])fn();},get offCalls(){return offCalls;},get listenerCount(){return listeners.size;}};
}
function TEST_ONLY_client({readAvailability=async()=>TEST_ONLY_READY,requestOne=async()=>result()}={}){
 const controller=TEST_ONLY_controller(),binding=Object.freeze({owner_id:TEST_ONLY_CONTEXT.owner_id});let connected=true;
 const client=createOwnerInferenceClient({controller,binding,context:TEST_ONLY_CONTEXT,contracts,
  isCurrentConnection:value=>connected&&value===binding,readAvailability,requestOne});
 return {controller,binding,client,async login(){controller.setOwner(owner());await flush();},
  disconnect({notify=true}={}){connected=false;if(notify)controller.emit();}};
}

test('SOURCE raw login material is staged until B publishes the exact new accepted owner lifetime',()=>{
 const controller=TEST_ONLY_controller(),prior=owner();controller.setOwner(prior);
 const sessions=createAcceptedOwnerSessionObserver(controller,TEST_ONLY_CONTEXT.owner_id);
 const login=actor=>({ok:true,owner_id:actor.owner_id,expiry:actor.expiry,session_token:TEST_ONLY_SESSION});
 const begin=()=>{sessions.observeCall('owner.loginChallenge');return sessions.observeCall('owner.loginComplete');};
 const accepted=owner(),observation=begin();sessions.observeReply('owner.loginComplete',{},login(accepted),observation);
 assert.equal(sessions.forOwner(prior),null); // Raw C reply is not accepted B state.
 controller.setOwner(accepted);assert.equal(sessions.forOwner(accepted),TEST_ONLY_SESSION);
 assert.equal(sessions.forOwner({...accepted}),null); // A value-equal owner is a different lifetime.
 const failedRepeat=begin();sessions.observeReply('owner.loginComplete',{},login(accepted),failedRepeat);
 assert.equal(sessions.forOwner(accepted),null); // Failed repeat retains the preceding B object.
 const afterLogout=owner(),stale=begin();sessions.observeCall('owner.logout');
 sessions.observeReply('owner.loginComplete',{},login(afterLogout),stale);controller.setOwner(afterLogout);
 assert.equal(sessions.forOwner(afterLogout),null);
 const renewed=owner(),old=begin();sessions.observeCall('owner.loginChallenge');
 sessions.observeReply('owner.loginComplete',{},login(renewed),old);controller.setOwner(renewed);
 assert.equal(sessions.forOwner(renewed),null);
 const latest=owner(),fresh=begin();sessions.observeReply('owner.loginComplete',{},login(latest),fresh);controller.setOwner(latest);
 assert.equal(sessions.forOwner(latest),TEST_ONLY_SESSION);sessions.dispose();assert.equal(sessions.forOwner(latest),null);
 sessions.observeReply('owner.loginComplete',{},login(latest),fresh);assert.equal(sessions.forOwner(latest),null);
});

test('SOURCE client needs a genuine owner/native lifetime; status is read-only and extra readiness fields refuse',async()=>{
 let reads=0,requests=0;const f=TEST_ONLY_client({readAvailability:async()=>{reads++;return {...TEST_ONLY_READY,qualification:true};},
  requestOne:async()=>{requests++;return result();}});
 try{assert.equal(f.client.availability.getSnapshot().state,'unavailable');
  await assert.rejects(f.client.requestOne(TEST_ONLY_DRAFT),{error_code:'UNAVAILABLE'});
  await f.login();assert.equal(reads,1);assert.equal(requests,0);
  assert.equal(f.client.availability.getSnapshot().state,'unavailable');
  f.disconnect();await assert.rejects(f.client.requestOne(TEST_ONLY_DRAFT),{error_code:'UNAVAILABLE'});
 }finally{f.client.dispose();}
 const disconnected=TEST_ONLY_client();try{await disconnected.login();assert.equal(disconnected.client.availability.getSnapshot().state,'ready');
  disconnected.disconnect({notify:false});assert.equal(disconnected.client.availability.getSnapshot().state,'unavailable');
 }finally{disconnected.client.dispose();}
});

test('SOURCE unreadable post-attempt replies become unknown and retain their request identity',async()=>{
 const f=TEST_ONLY_client({requestOne:async()=>({...result(),malformed:NaN})});
 try{await f.login();await assert.rejects(f.client.requestOne(TEST_ONLY_DRAFT),{error_code:'OUTCOME_UNKNOWN'});
  await assert.rejects(f.client.requestOne(TEST_ONLY_DRAFT),{error_code:'RECONCILIATION_REQUIRED'});
 }finally{f.client.dispose();}
 for(const value of [null,[],false]){const malformed=TEST_ONLY_client({requestOne:async()=>value});
  try{await malformed.login();await assert.rejects(malformed.client.requestOne(TEST_ONLY_DRAFT),{error_code:'OUTCOME_UNKNOWN'});
   await assert.rejects(malformed.client.requestOne(TEST_ONLY_DRAFT),{error_code:'RECONCILIATION_REQUIRED'});
  }finally{malformed.client.dispose();}
 }
});

test('SOURCE an unobserved replacement owner cannot issue against the preceding cached readiness',async()=>{
 let calls=0;const f=TEST_ONLY_client({requestOne:async()=>{calls++;return result();}});
 try{await f.login();assert.equal(f.client.availability.getSnapshot().state,'ready');
  f.controller.setOwner(owner(),{notify:false});assert.equal(f.client.availability.getSnapshot().state,'unavailable');
  await assert.rejects(f.client.requestOne(TEST_ONLY_DRAFT),{error_code:'UNAVAILABLE'});assert.equal(calls,0);
 }finally{f.client.dispose();}
});

test('SOURCE late status cannot revive a logged-out owner and late reply cannot cross owner lifetime',async()=>{
 const availability=deferred(),readEntered=deferred();
 const first=TEST_ONLY_client({readAvailability:async()=>{readEntered.resolve();return availability.promise;}});
 try{first.controller.setOwner(owner());await readEntered.promise;first.controller.setOwner(null);
  availability.resolve(TEST_ONLY_READY);await flush();assert.equal(first.client.availability.getSnapshot().state,'unavailable');
 }finally{first.client.dispose();}
 const reply=deferred(),entered=deferred();let signal;
 const second=TEST_ONLY_client({requestOne:async(_draft,options)=>{signal=options.signal;entered.resolve();return reply.promise;}});
 try{await second.login();const pending=second.client.requestOne(TEST_ONLY_DRAFT);await entered.promise;
  second.controller.setOwner(null);assert.equal(signal.aborted,true);reply.resolve(result());
  await assert.rejects(pending,{error_code:'OUTCOME_UNKNOWN'});
  await second.login();await assert.rejects(second.client.requestOne(TEST_ONLY_DRAFT),{error_code:'RECONCILIATION_REQUIRED'});
 }finally{second.client.dispose();}
});

test('SOURCE duplicate/in-flight drafts never call twice; aborted wait retains UUID and disconnection fences replies',async()=>{
 const reply=deferred(),entered=deferred();let calls=0;
 const f=TEST_ONLY_client({requestOne:async()=>{calls++;entered.resolve();return reply.promise;}});
 try{await f.login();const abort=new AbortController(),pending=f.client.requestOne(TEST_ONLY_DRAFT,{signal:abort.signal});await entered.promise;
  await assert.rejects(f.client.requestOne(TEST_ONLY_DRAFT),{error_code:'RECONCILIATION_REQUIRED'});
  await assert.rejects(f.client.requestOne({...TEST_ONLY_DRAFT,request_uuid:TEST_ONLY_OTHER_UUID}),{error_code:'RECONCILIATION_REQUIRED'});
  abort.abort();reply.resolve(result());await assert.rejects(pending,{error_code:'OUTCOME_UNKNOWN'});
  await assert.rejects(f.client.requestOne(TEST_ONLY_DRAFT),{error_code:'RECONCILIATION_REQUIRED'});assert.equal(calls,1);
 }finally{f.client.dispose();}
 const wait=deferred(),began=deferred();const disconnected=TEST_ONLY_client({requestOne:async()=>{began.resolve();return wait.promise;}});
 try{await disconnected.login();const pending=disconnected.client.requestOne(TEST_ONLY_DRAFT);await began.promise;
  disconnected.disconnect();wait.resolve(result());await assert.rejects(pending,{error_code:'OUTCOME_UNKNOWN'});
 }finally{disconnected.client.dispose();}
});

test('SOURCE throwing observers cannot prevent withdrawal and native service cleanup is retryable',async()=>{
 const f=TEST_ONLY_client();let notifications=0;
 f.client.availability.subscribe(()=>{throw new Error('TEST_ONLY observer failure');});
 f.client.availability.subscribe(()=>{notifications++;});await f.login();const before=notifications;
 assert.doesNotThrow(()=>f.client.dispose());assert.ok(notifications>before);
 assert.equal(f.controller.listenerCount,0);assert.equal(f.controller.offCalls,1);
 assert.equal(f.client.availability.getSnapshot().state,'unavailable');f.client.dispose();assert.equal(f.controller.offCalls,1);
 const controller=TEST_ONLY_controller(),binding={owner_id:TEST_ONLY_CONTEXT.owner_id};let service,removals=0;
 const ack={controller,isConnected:value=>value===binding};
 const scope={primeOwnerUi:controller,primeOwnerNativeConnection:ack,primeAuthority:binding,
  reflect:{provide(name,value){assert.equal(name,'primePilotInference');service=value;return()=>{removals++;if(removals===1)throw new Error('TEST_ONLY first remove failure');service=undefined;};}}};
 const mounted=mountOwnerInferenceClient(scope,{contracts,context:TEST_ONLY_CONTEXT});
 assert.equal(service.ownerController,controller);assert.equal(service.client.binding,binding);
 assert.throws(()=>mounted.dispose(),AggregateError);assert.equal(controller.listenerCount,0);
 assert.doesNotThrow(()=>mounted.dispose());assert.equal(service,undefined);assert.equal(removals,2);
 assert.throws(()=>mountOwnerInferenceClient({...scope,primeOwnerNativeConnection:{controller,isConnected:()=>false}},
  {contracts,context:TEST_ONLY_CONTEXT}),{error_code:'UNAVAILABLE'});
});

async function TEST_ONLY_producer({stream,ledgerResult,resolveRequest,alterRetained,outcome='completed'}={}){
 const entry=new URL('../vendor/dsh/packages/llm/llm/lib/index.js',import.meta.url);
 const dsh=await import(entry.href),requireDsh=createRequire(entry);
 const {Context}=await import(requireDsh.resolve('@deepseek-ai/cordis'));
 const context=new Context();await context.plugin(dsh.default);let gatewayCalls=0;
 const policy=TEST_ONLY_inferencePolicy({owner:{owner_id:TEST_ONLY_CONTEXT.owner_id,subject:'aukora:1:'+'a'.repeat(64)}});
 const route=policy.facts.route;let row=ledgerResult===undefined?undefined:{result:ledgerResult};
 const ledger={get:()=>row,task:()=>policy.facts.local_task};
 const returnedResult=uuid=>outcome==='completed'?result(uuid):{outcome:'outcome_unknown',request_uuid:uuid,
  receipt:result(uuid).receipt,error:'PROVIDER_UNAVAILABLE',reservation_retained:true};
 const gateway={ledger,route,provider:{mode:'production'},async generate(request){gatewayCalls++;
  const returned=returnedResult(request.request_uuid),prepared=prepareRequest(policy.facts.local_task,route,request);
  returned.receipt.body_sha256=prepared.body_hash;
  row={...TEST_ONLY_CONTEXT,request_uuid:request.request_uuid,body_hash:prepared.body_hash,binding_hash:prepared.binding_hash,
   status:returned.outcome,receipt:returned.receipt,result:outcome==='completed'?returned:undefined};alterRetained?.(row,returned);return returned;}};
 const selected=draft=>({request:{...TEST_ONLY_CONTEXT,request_uuid:draft.request_uuid,max_output_tokens:32,
  fragments:[{...TEST_ONLY_CONTEXT,data_class:'conversation',role:'user',text:draft.text}]},
  options:{provider:'externalDeepSeek',model:gateway.route.model,sessionId:TEST_ONLY_CONTEXT.conversation_id,maxTokens:32,
   messages:[{role:'user',source:{kind:'user'},content:[{type:'text',text:draft.text}]}],tools:[]}});
 const scope={llm:{registerAdapter:context.llm.registerAdapter.bind(context.llm),
  stream:options=>stream?stream(options,context,value=>{row=value;}):context.llm.stream(options)}};
 const producer=createDshOwnerInferenceProducer(scope,{context:TEST_ONLY_CONTEXT,gateway,ledger,LlmAdapter:dsh.LlmAdapter,
  resolveRequest:resolveRequest??(async({draft})=>selected(draft)),attributionHeaders:()=>({}),
  observeAvailability:async()=>({paid_requests_enabled:true,config_digest:gateway.route.config_digest,credential:{configured:true,generation:1}})});
 const expected=()=>{const value=returnedResult(TEST_ONLY_UUID);value.receipt.body_sha256=prepareRequest(policy.facts.local_task,route,selected(TEST_ONLY_DRAFT).request).body_hash;return value;};
 return {producer,context,selected,expected,get gatewayCalls(){return gatewayCalls;},
  async dispose(){producer.dispose();await context.fiber.dispose();}};
}

test('SOURCE actual pinned DSH registry returns current gateway bytes once, then retained UUID refuses',async()=>{
 const f=await TEST_ONLY_producer();try{
  assert.equal((await f.producer.status(owner())).state,'ready');
  assert.deepEqual(await f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),f.expected());assert.equal(f.gatewayCalls,1);
  await assert.rejects(f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),{error_code:'RECONCILIATION_REQUIRED'});
  assert.equal(f.gatewayCalls,1);
 }finally{await f.dispose();}
});

test('SOURCE actual captured unknown result preserves the retained receipt without a completed ledger result',async()=>{
 const f=await TEST_ONLY_producer({outcome:'outcome_unknown'});
 try{const value=await f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()});assert.deepEqual(value,f.expected());
  assert.equal(value.outcome,'outcome_unknown');assert.equal(value.reservation_retained,true);assert.equal(f.gatewayCalls,1);
  await assert.rejects(f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),{error_code:'RECONCILIATION_REQUIRED'});
  assert.equal(f.gatewayCalls,1);
 }finally{await f.dispose();}
});

test('SOURCE completed results require committed result bytes while unknown rows cannot contain them',async()=>{
 for(const outcome of ['completed','outcome_unknown']){
  const f=await TEST_ONLY_producer({outcome,alterRetained:(row,returned)=>{
   if(outcome==='completed')delete row.result;else row.result=returned;
  }});
  try{await assert.rejects(f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),{error_code:'OUTCOME_UNKNOWN'});
   assert.equal(f.gatewayCalls,1);
  }finally{await f.dispose();}
 }
});

test('SOURCE stale ledger bytes cannot replace a stream that never entered this gateway',async()=>{
 const retained=await TEST_ONLY_producer({ledgerResult:result()});try{
  await assert.rejects(retained.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),{error_code:'RECONCILIATION_REQUIRED'});
  assert.equal(retained.gatewayCalls,0);
 }finally{await retained.dispose();}
 const f=await TEST_ONLY_producer({stream:async function*(_options,_context,install){install({result:result()});throw new Error('TEST_ONLY before gateway');}});
 try{await assert.rejects(f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),{error_code:'OUTCOME_UNKNOWN'});
  assert.equal(f.gatewayCalls,0);
  await assert.rejects(f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),{error_code:'RECONCILIATION_REQUIRED'});
 }finally{await f.dispose();}
 const mismatched=await TEST_ONLY_producer({alterRetained:row=>{row.body_hash='f'.repeat(64);}});
 try{await assert.rejects(mismatched.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),{error_code:'OUTCOME_UNKNOWN'});
  assert.equal(mismatched.gatewayCalls,1);
 }finally{await mismatched.dispose();}
});

test('SOURCE foreign signal cannot enter the owned adapter; runtime withdrawal during resolve prevents stream',async()=>{
 const f=await TEST_ONLY_producer({stream:(options,context)=>context.llm.stream({...options,signal:new AbortController().signal})});
 try{await assert.rejects(f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner()}),{error_code:'OUTCOME_UNKNOWN'});
  assert.equal(f.gatewayCalls,0);
 }finally{await f.dispose();}
 const hold=deferred(),entered=deferred();let current=true;
 const withdrawn=await TEST_ONLY_producer({resolveRequest:async({draft})=>{entered.resolve();await hold.promise;return withdrawn.selected(draft);}});
 try{const pending=withdrawn.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner(),isCurrent:()=>current});
  await entered.promise;current=false;hold.resolve();await assert.rejects(pending,{error_code:'UNAVAILABLE'});
  assert.equal(withdrawn.gatewayCalls,0);
 }finally{hold.resolve();await withdrawn.dispose();}
});

test('SOURCE host currentness must remain exact true after waits and current gateway entry',async()=>{
 for(const replacement of [undefined,null,1]){
  let current=true;
  const f=await TEST_ONLY_producer({resolveRequest:async({draft})=>{current=replacement;return f.selected(draft);}});
  try{await assert.rejects(f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner(),isCurrent:()=>current}),{error_code:'UNAVAILABLE'});
   assert.equal(f.gatewayCalls,0);
  }finally{await f.dispose();}
 }
 let current=true;const f=await TEST_ONLY_producer({alterRetained:()=>{current=undefined;}});
 try{await assert.rejects(f.producer.requestOne(TEST_ONLY_DRAFT,{owner:owner(),isCurrent:()=>current}),{error_code:'UNAVAILABLE'});
  assert.equal(f.gatewayCalls,1);
 }finally{await f.dispose();}
});
