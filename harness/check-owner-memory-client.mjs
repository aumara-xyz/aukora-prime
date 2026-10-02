// SPDX-License-Identifier: AGPL-3.0-or-later
// Scoped source composition check. Actual B controller/bridge workflow/H HTTP
// factories; synthetic replies, no listener, C crypto, PostgreSQL or acceptance.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {mkdtempSync,mkdirSync,cpSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import * as contracts from '../packages/contracts/src/browser.mjs';
import {createPrimeOwnerController} from '../packages/ui/prime-authority/src/client/controller.mjs';
import {createOwnerUiFixture} from '../packages/ui/prime-authority/checks/fixture.mjs';
import {createOwnerMemoryClient} from './owner-memory-client.mjs';
import {createOwnerMemoryNativeBinding} from './owner-memory-native.mjs';
import {createOwnerMemoryHost} from './owner-memory-host.mjs';
import {createOwnerMemoryHttpRoutes} from './owner-memory-transport.mjs';
import {createLocalhostPilotGuard} from '../packages/runtime-bridge/src/pilot-origin.mjs';
let checks=0;
const literal='  <tag>&\n\t🍌 \u00e9  ';
// Synthetic trusted source bytes and independent review data. The full selected
// quote deliberately differs from the extracted statement; neither is rewritten.
const selectedEventBytes=Buffer.from(JSON.stringify({text:'  Selected source <quote>&\n\t🍌 \u00e9 remains exact.  '}));
const selectedEvent=JSON.parse(selectedEventBytes.toString('utf8'));
const source=Object.freeze({sessionId:'source-fixture-session',seq:0,at:'2026-10-01T11:02:03Z',
 sha256:createHash('sha256').update(selectedEventBytes).digest('hex')});
const captureMetadata=Object.freeze({profile:'prime-pilot-memory-capture/v1',category:'fact',valid_from:source.at.slice(0,10),
 observed_at:source.at,confidence_percent:70,sensitivity:'none'});
const capture=Object.freeze({statement:literal,attributed_to:'owner-edit',capture_metadata:captureMetadata,evidence_quote:selectedEvent.text});
const ownerBinding={owner_id:'ui-fixture-owner',passkeyProfile:{profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'}};
const caps={version:1,source_commit:'a'.repeat(40),runtime_pid:1,release_digest:'sha256:'+'b'.repeat(64),
 unavailable_capabilities:[],phase:'disposable-preview',qualification:'PENDING'};
const guardRequest=createLocalhostPilotGuard(ownerBinding.passkeyProfile);
const connection={requestRejection:()=>undefined};
const digest=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+contracts.canonicalJson(value)).digest('hex');

function fixture({lostSave=false,lostLogin=false,lostLogout=false,lostForget=false,onClearHook,reconcile}={}){
 const base=createOwnerUiFixture(contracts),calls=[];
 let saved,forgotten,proposed,holdLogin,releaseLogin;
 const entered=new Promise(resolve=>{holdLogin=resolve;});
 const wait=new Promise(resolve=>{releaseLogin=resolve;});
 const boundary={async handlePublic(method,input){
  calls.push({method,input});
  if(method==='owner.logout')return {ok:true,status:'LOGGED_OUT'};
  if(method.startsWith('owner.')){
   const result=await base.authority[method.slice(6)](input);
   if(lostLogin&&method==='owner.loginComplete'){holdLogin();await wait;}
   return result;
  }
  if(method==='memory.proposeSave'){
   const operation={...base.operation,operation_id:'source-host-memory',action_type:'memory.save',audience:'aukora-prime.memory',
    target_identity:{kind:'prime-memory',owner_subject:'aukora:1:'+'1'.repeat(64)},canonical_parameters:{capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),
     heads:{remembered:'aukora:aura-record:v1'},...capture}};
   proposed=operation;
   return {ok:true,operation,operation_digest:await contracts.operationDigest(operation),memory_capture:{...capture}};
  }
  if(method==='memory.proposeForget'){
   const operation={...base.operation,operation_id:'source-host-forget',action_type:'memory.forget',audience:'aukora-prime.memory',
    target_identity:{kind:'prime-memory',owner_subject:'aukora:1:'+'1'.repeat(64)},expected_state_version:'sha256:'+'a'.repeat(64),
    canonical_parameters:{profile:'prime-logical-forget/v1',record_id:input.record_id,revision:'source-fixture-revision',canonical_sha256:'a'.repeat(64),
     at:new Date().toISOString().slice(0,19)+'Z',heads:{remembered:'aukora:aura-record:v1'},statement:literal,attributed_to:capture.attributed_to}};
   proposed=operation;
   return {ok:true,operation,operation_digest:await contracts.operationDigest(operation),record_summary:{record_id:input.record_id,
    revision:operation.canonical_parameters.revision,statement:literal,attributed_to:capture.attributed_to}};
  }
  if(method==='memory.save'){
   const op=input.operation,evidence=[{log:source.sessionId,turn:source.seq,turnDigest:source.sha256,quote:capture.evidence_quote}];
   const original={statement:literal,attributedTo:capture.attributed_to,category:captureMetadata.category,validFrom:captureMetadata.valid_from,
    observedAt:captureMetadata.observed_at,confidence:captureMetadata.confidence_percent/100,sensitivity:captureMetadata.sensitivity,source,evidence};
   const record={version:1,record_id:'source-fixture-record',owner_subject:op.target_identity.owner_subject,task_id:op.task_id,
    scope:'owner',privacy:'local',record_format:'source-fixture',canonicalizer:'source-fixture',canonical_bytes:JSON.stringify(original),
    revision:'source-fixture-revision',grants_authority:false,source_event_digest:'sha256:'+source.sha256,evidence,chain_domain:'remembered',
    source_span:{fixture:true},storage_status:'saved',index_status:'pending'};
   const receipt={version:1,kind:'prime-memory-effect/v1',operation_id:op.operation_id,operation_digest:input.approval_proof.operation_digest,
    grant_id:'grant:'+input.approval_proof.nonce,request_id:'11111111-1111-4111-8111-111111111111',request_digest:digest('aukora-prime.memory.effect.v1',
     {version:1,action_type:op.action_type,owner_subject:record.owner_subject,operation_id:op.operation_id,
      operation_digest:input.approval_proof.operation_digest,parameters:op.canonical_parameters}),
    owner_subject:record.owner_subject,action_type:'memory.save',status:'applied',result_digest:digest('aukora-prime.memory-result.v1',record),result:record};
   saved={ok:true,record,receipt,authority_settlement:'completed',reconciliation_required:false,receipt_digest:digest('aukora-prime.memory-receipt.v1',receipt)};
   return saved;
  }
  if(method==='memory.forget'){
   const op=input.operation,result={record_id:op.canonical_parameters.record_id,state:'tombstoned',canonical_payload_retained:true,
    physical_media_erasure:false,authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false};
   const receipt={version:1,kind:'prime-memory-effect/v1',operation_id:op.operation_id,operation_digest:input.approval_proof.operation_digest,
    grant_id:'grant:'+input.approval_proof.nonce,request_id:'22222222-2222-4222-8222-222222222222',request_digest:digest('aukora-prime.memory.effect.v1',
     {version:1,action_type:op.action_type,owner_subject:op.target_identity.owner_subject,operation_id:op.operation_id,
      operation_digest:input.approval_proof.operation_digest,parameters:op.canonical_parameters}),
    owner_subject:op.target_identity.owner_subject,action_type:op.action_type,status:'applied',result_digest:digest('aukora-prime.memory-result.v1',result),result};
   forgotten={ok:true,result,receipt,authority_settlement:'completed',reconciliation_required:false,receipt_digest:digest('aukora-prime.memory-receipt.v1',receipt)};
   return forgotten;
  }
  if(method==='memory.recover'){
   const effect=forgotten??saved,op=effect?null:proposed;
   return {ok:true,owner_id:base.owner_id,owner_subject:'aukora:1:'+'1'.repeat(64),task_id:base.operation.task_id,
    operation_id:effect?.receipt.operation_id??op?.operation_id??null,
    operation_digest:effect?.receipt.operation_digest??(op?await contracts.operationDigest(op):null),
    action_type:effect?.receipt.action_type??op?.action_type??null,state:forgotten?'forgotten':saved?'saved':op?'known_unsent':'idle',
    reconciliation_required:false,result:forgotten?.result??saved?.record??null,receipt:effect?.receipt??null,
    receipt_digest:effect?.receipt_digest??null,authority_settlement:effect?'completed':null,citation:null,index:null};
  }
  if(method==='memory.status')return {ok:true,record:saved.record,saved:true,indexed:false,searchable:false,index_status:'pending'};
  if(method==='memory.cite')return {ok:true,citation:{record_id:saved.record.record_id,revision:saved.record.revision,chain_domain:'remembered',chain_sequence:1,
   aura_entry_hash:'1'.repeat(64),verified_head:'2'.repeat(64),verdict:'UNVERIFIED',grants_authority:false}};
  throw new Error('Unexpected source-fixture method');
 }};
 const routes=createOwnerMemoryHttpRoutes({connection,guardRequest,contracts,publicBoundary:boundary});
 const fetcher=async(url,options)=>{
  const req=Readable.from([Buffer.from(options.body)]);req.method=options.method;req.url=url;
  req.headers={host:'localhost:18731',origin:'http://localhost:18731','content-type':'application/json'};
  let status,headers,body;
  const res={destroyed:false,writableEnded:false,writeHead(s,h){status=s;headers=h;},end(value){body=value;this.writableEnded=true;}};
  await routes.find(route=>route.path===url).handler(req,res);
  if(lostSave&&url.endsWith('/memory.save'))throw new Error('synthetic delivered reply lost');
  if(lostLogout&&url.endsWith('/owner.logout'))throw new Error('synthetic delivered logout reply lost');
  if(lostForget&&url.endsWith('/memory.forget'))throw new Error('synthetic delivered forget reply lost');
  return new Response(body,{status,headers});
 };
 const controller=createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}});
 const joinedController={...controller,setApprovalAction(handler){if(handler===null)onClearHook?.();return controller.setApprovalAction(handler);},
  reconcileApprovalAction:snapshot=>reconcile?reconcile(snapshot,()=>controller.reconcileApprovalAction(snapshot)):controller.reconcileApprovalAction(snapshot)};
 let connectionWitness;
 const client=createOwnerMemoryClient({controller:joinedController,contracts,ownerBinding,fetcher,passkeySigner:base.passkeySigner,
  isCurrentConnection:()=>connectionWitness?.isCurrent()===true});
 // Source simulation of native primeAuthority injection. No Cordis mount or
 // default-browser effect is claimed by this check.
 assert.throws(()=>client.proposeSave({}),/not attached/);checks++;
 assert.throws(()=>client.recall({query:'literal',limit:1}),/not attached/);
 assert.throws(()=>client.getRecallSnapshot(),/not attached/);
 assert.throws(()=>client.providePilotMemory({}),/not attached/);checks++;
 connectionWitness=controller.connect(client.binding);client.attach();assert.equal(client.attach(),client.workflow);checks++;
 return {client,controller,nativeController:joinedController,calls,entered,releaseLogin,
  // Invoke through B so the handler receives B's actual captured options.
  approvalAction:()=>controller.submitApproval(),
  freshClient(){
   const freshController=createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}});
   let freshWitness;
   const fresh=createOwnerMemoryClient({controller:freshController,contracts,ownerBinding,fetcher,passkeySigner:base.passkeySigner,
    isCurrentConnection:()=>freshWitness?.isCurrent()===true});
   freshWitness=freshController.connect(fresh.binding);fresh.attach();
   return {client:fresh,controller:freshController,dispose(){fresh.dispose();freshController.dispose();}};
  },
  count:method=>calls.filter(value=>value.method===method).length,
  async prepare(){client.setCapabilities(caps);assert(await controller.login());
   assert.equal((await client.proposeSave({extraction_json:JSON.stringify({statement:literal,category:'fact'}),idempotency_key:'source-single-use'})).phase,'proposed');
   assert(await controller.prepare());},
  dispose(){releaseLogin();client.dispose();controller.dispose();}};
}
{
 const f=fixture();try{
  assert.equal(await f.controller.login(),null);assert.equal(f.calls.length,0);checks++;
  await f.prepare();
  const view=f.controller.getSnapshot().presentation,params=view.operation.canonical_parameters;
  assert.deepEqual(Object.keys(params).sort(),['capture_sha256','idempotency_key_sha256','heads','statement','attributed_to','capture_metadata','evidence_quote'].sort());
  assert.deepEqual(f.client.workflow.getSnapshot().memory_capture,capture);
  assert.deepEqual(view.memory_review,{...capture,capture_sha256:params.capture_sha256});
  assert.deepEqual(view.capture_metadata,captureMetadata);assert.notEqual(capture.evidence_quote,literal);checks++;
  const one=f.approvalAction(),two=f.controller.submitApproval();assert.equal(one,two);
  const result=await one;assert.equal(result.saved,true);assert.equal(result.index.searchable,false);assert.equal(result.citation_status,'unverified');
  assert.equal(result.authority_settlement,'completed');assert.equal(f.count('memory.save'),1);checks++;
  assert.throws(()=>f.client.approveAndForget(),/exact logical-forget review required/);assert.equal(f.count('memory.forget'),0);checks++;
  const save=f.calls.find(value=>value.method==='memory.save').input;
  assert.equal(save.operation.canonical_parameters.statement,literal);assert.equal(save.operation.canonical_parameters.attributed_to,capture.attributed_to);
  assert.deepEqual(save.operation.canonical_parameters.capture_metadata,captureMetadata);assert.equal(save.operation.canonical_parameters.evidence_quote,selectedEvent.text);
  const original=JSON.parse(result.record.canonical_bytes);
  assert.equal(original.confidence,0.7);assert.deepEqual(original.source,source);assert.deepEqual(original.evidence,result.record.evidence);
  assert.equal(result.record.evidence[0].quote,selectedEvent.text);
  assert.equal(save.approval_proof.operation_digest,await contracts.operationDigest(save.operation));checks++;
  f.controller.logout();assert.equal((await f.client.logout()).status,'LOGGED_OUT');assert.equal(f.count('owner.logout'),1);checks++;
  const before=f.calls.length;await f.client.refresh();assert.equal(f.calls.length,before);checks++;
  const old=await f.client.binding.authority.approvalChallenge({session_token:'synthetic-in-memory-only',operation:save.operation});
  assert.equal(old.error_code,'UNAUTHORIZED');assert.equal(f.calls.length,before);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture({lostSave:true});try{
  await f.prepare();const result=await f.controller.submitApproval();assert.equal(result.save,'unknown');assert.equal(result.saved,null);checks++;
  await f.controller.submitApproval();await f.client.proposeSave({extraction_json:JSON.stringify({statement:literal}),idempotency_key:'replacement'});
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.proposeSave'),1);checks++;
  f.client.dispose();const fresh=f.freshClient();try{
   fresh.client.setCapabilities(caps);assert(await fresh.controller.login());assert.equal(f.count('memory.recover'),0);
   const recovered=await fresh.client.recover();assert.equal(recovered.saved,true);assert.equal(recovered.authority_settlement,'completed');
   assert.equal(f.count('memory.recover'),1);assert.equal(f.count('memory.save'),1);assert.equal(f.count('owner.approvalComplete'),1);checks++;
  }finally{fresh.dispose();}
 }finally{f.dispose();}
}
{
 const f=fixture({lostLogin:true});try{
  f.client.setCapabilities(caps);const pending=f.controller.login();await f.entered;
  f.controller.logout();f.releaseLogin();await pending;assert.equal(f.controller.getSnapshot().owner,null);checks++;
  const stale=await f.client.binding.authority.approvalChallenge({session_token:'synthetic-in-memory-only',operation:createOwnerUiFixture(contracts).operation});
  assert.equal(stale.error_code,'UNAUTHORIZED');assert.equal(f.count('owner.approvalChallenge'),0);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture({lostLogout:true});try{
  f.client.setCapabilities(caps);assert(await f.controller.login());
  const first=f.client.logout(),second=f.client.logout();
  assert.equal(f.controller.getSnapshot().owner,null);
  assert.equal((await first).error_code,'OUTCOME_UNKNOWN');assert.deepEqual(await second,await first);
  assert.equal(f.count('owner.logout'),1);checks++;
  assert.equal((await f.client.binding.authority.logout()).error_code,'OUTCOME_UNKNOWN');
  f.client.dispose();await new Promise(resolve=>setImmediate(resolve));assert.equal(f.count('owner.logout'),1);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture();try{
  await f.client.recover();assert.equal(f.count('memory.recover'),0);checks++;
  f.client.setCapabilities(caps);assert(await f.controller.login());
  assert.equal(f.count('memory.recover'),0);assert.equal((await f.client.recover()).phase,'idle');
  assert.equal(f.count('memory.recover'),1);assert.equal(f.count('memory.save'),0);checks++;
  await f.prepare();const operation=f.client.workflow.getSnapshot().operation;
  const unsent=await f.client.recover({operation_id:operation.operation_id});
  assert.equal(unsent.phase,'proposed');assert.equal(unsent.error_code,'RECONCILIATION_REQUIRED');
  assert.equal(unsent.operation.operation_id,operation.operation_id);
  assert.equal(f.count('memory.save'),0);assert.equal(f.count('owner.approvalComplete'),0);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture({lostForget:true});try{
  f.client.setCapabilities(caps);assert(await f.controller.login());
  const proposed=await f.client.proposeForget({record_id:'source-fixture-record'});
  assert.equal(proposed.phase,'proposed');assert.equal(proposed.record_summary.statement,literal);checks++;
  assert(await f.controller.prepare());
  const one=f.controller.submitApproval(),two=f.controller.submitApproval();assert.equal(one,two);
  const uncertain=await one;assert.equal(uncertain.forgotten,null);assert.equal(uncertain.reconciliation_required,true);
  assert.equal(f.count('memory.forget'),1);assert.equal(f.count('memory.save'),0);checks++;
  await f.controller.submitApproval();assert.equal(f.count('memory.forget'),1);checks++;
  const recovered=await f.client.recoverForget();assert.equal(recovered.forgotten,true);
  assert.equal(recovered.result.physical_media_erasure,false);assert.equal(recovered.authority_settlement,'completed');
  assert.equal(f.count('memory.forget'),1);assert.equal(f.count('owner.approvalComplete'),1);
  assert.equal(Object.hasOwn(recovered,'saved'),false);checks++;
  f.client.dispose();assert.equal(f.client.forgetWorkflow.getSnapshot().phase,'unavailable');
  assert.equal(f.client.forgetWorkflow.getSnapshot().result,null);await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.count('owner.logout'),1);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture();try{
  f.client.setCapabilities(caps);assert(await f.controller.login());
  const proposed=await f.client.proposeForget({record_id:'source-fixture-record'});assert.equal(proposed.phase,'proposed');
  assert(await f.controller.prepare());
  const recovered=await f.client.recoverForget({operation_id:proposed.operation.operation_id});
  assert.equal(recovered.recovery_status,'refused');assert.equal(recovered.error_code,'RECONCILIATION_REQUIRED');
  assert.equal(recovered.operation.operation_id,proposed.operation.operation_id);
  assert.equal(f.count('memory.forget'),0);assert.equal(f.count('owner.approvalComplete'),0);checks++;
  assert.equal((await f.client.proposeSave({extraction_json:JSON.stringify({statement:literal,category:'fact'}),idempotency_key:'source-after-unsent-forget'})).phase,'proposed');
  assert(await f.controller.prepare());assert.equal((await f.controller.submitApproval()).saved,true);
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.forget'),0);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture();try{
  f.client.setCapabilities(caps);assert(await f.controller.login());
  assert.equal((await f.client.proposeForget({record_id:'source-fixture-record'})).phase,'proposed');assert(await f.controller.prepare());
  let detached=false;
  const off=f.client.forgetWorkflow.subscribe(()=>{if(!detached&&f.client.forgetWorkflow.getSnapshot().phase==='forget_pending'){detached=true;f.client.dispose();}});
  await f.controller.submitApproval();off();
  assert.equal(detached,true);assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.forget'),0);checks++;
  assert.equal(f.controller.getSnapshot().owner,null);assert.equal(f.client.forgetWorkflow.getSnapshot().record_summary,null);
  // Disposal happened before the local memory method was invoked. The actual
  // zero-call assertion above distinguishes this from an attempted effect;
  // earlier lost-forget and lost-save cases retain their uncertainty fences.
  assert.equal(f.client.forgetWorkflow.getSnapshot().forgotten,false);assert.equal(f.client.forgetWorkflow.getSnapshot().reconciliation_required,false);checks++;
  await new Promise(resolve=>setImmediate(resolve));assert.equal(f.count('owner.logout'),1);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture();try{
  f.client.setCapabilities(caps);assert(await f.controller.login());
  assert.equal((await f.client.proposeForget({record_id:'source-fixture-record'})).phase,'proposed');
  assert(await f.controller.prepare());
  const one=f.client.approveAndForget(),two=f.controller.submitApproval();assert.equal(one,two);
  const result=await one;assert.equal(result.forgotten,true);assert.equal(result.result.physical_media_erasure,false);
  assert.equal(result.authority_settlement,'completed');assert.equal(f.count('memory.forget'),1);assert.equal(f.count('memory.save'),0);checks++;
  assert.equal(f.controller.getSnapshot().forget_action_result.forgotten,true);
  assert.equal(f.controller.getSnapshot().approval_action_result,null);checks++;
 }finally{f.dispose();}
}
{
 const host=createOwnerMemoryHost({connection,guardRequest,contracts});
 assert.equal((await host.publicBoundary.handlePublic('memory.save',{})).error_code,'UNAVAILABLE');checks++;
 assert(Object.isFrozen(host.routes));assert.equal(host.routes.length,16);checks++;
}
{
 let f,teardownOrdered=false;
 f=fixture({onClearHook(){assert.equal(f.client.workflow.getSnapshot().phase,'unavailable');assert.equal(f.client.workflow.getSnapshot().operation,null);teardownOrdered=true;}});try{
  await f.prepare();let disposed=false;
  const off=f.client.workflow.subscribe(()=>{if(!disposed&&f.client.workflow.getSnapshot().phase==='save_pending'){disposed=true;f.client.dispose();}});
  await f.controller.submitApproval();off();
  assert.equal(disposed,true);assert.equal(teardownOrdered,true);assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),0);checks++;
  assert.equal(f.controller.getSnapshot().owner,null);assert.equal(f.client.workflow.getSnapshot().saved,false);
  assert.equal(f.client.workflow.getSnapshot().reconciliation_required,false);checks++;
 }finally{f.dispose();}
}
// NEXT focused source regressions; synthetic native registry, never activation.
// A fake native service scope checks ordering only; it is not a Cordis render.
{
 let removed=false;
 const f=fixture({onClearHook(){assert.equal(removed,true);}});try{
  let projection,unprovides=0;
  const scope={primeOwnerUi:f.nativeController,reflect:{provide(name,value){
   assert.equal(name,'primePilotMemory');projection=value;
   return ()=>{removed=true;unprovides++;};
  }}};
  assert.throws(()=>f.client.providePilotMemory({...scope,primeOwnerUi:f.controller}),/matching native owner UI scope/);
  const before=f.calls.length,release=f.client.providePilotMemory(scope);
  assert.equal(projection.ownerController,f.nativeController);assert.equal(projection.client,f.client);
  assert(Object.isFrozen(projection));assert.equal(f.calls.length,before);
  assert.throws(()=>f.client.providePilotMemory(scope),/already provided/);checks++;
  assert.equal(f.client.getRecallSnapshot(),f.client.workflow.getRecallSnapshot());
  await f.client.recall({query:'literal',limit:1});assert.equal(f.calls.length,before);checks++;
  f.client.dispose();assert.equal(unprovides,1);release();assert.equal(unprovides,1);
  assert.throws(()=>f.client.getRecallSnapshot(),/not attached/);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture();try{
  let unprovides=0;
  const scope={primeOwnerUi:f.nativeController,reflect:{provide(){f.client.dispose();return ()=>{unprovides++;};}}};
  const release=f.client.providePilotMemory(scope);
  assert.equal(unprovides,1);release();assert.equal(unprovides,1);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture();try{
  let attempts=0,removed=false;
  const scope={primeOwnerUi:f.nativeController,reflect:{provide(){
   f.client.dispose();
   return ()=>{attempts++;f.client.dispose();if(attempts<3)throw new Error('synthetic native removal failure');removed=true;};
  }}};
  assert.throws(()=>f.client.providePilotMemory(scope),/synthetic native removal failure/);
  assert.equal(attempts,2);assert.equal(removed,false);
  f.client.dispose();assert.equal(attempts,3);assert.equal(removed,true);
  f.client.dispose();assert.equal(attempts,3);checks++;
 }finally{f.dispose();}
}
// Optional native provider ownership, with actual B controller but a fake
// scoped service registry. No Cordis runtime or browser connection is implied.
function nativeFixture({removeAuthorityFailures=0}={}){
 const base=createOwnerUiFixture(contracts),events=[];
 const actual=createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}});
 const controller={...actual,setForgetAction(handler){events.push(handler?'install:forget':'clear:forget');return actual.setForgetAction(handler);}};
 let fetches=0,authorityRemovals=0,witness,selected;
 const scope={primeOwnerUi:controller,reflect:{provide(name,value){
  assert.equal(scope[name],undefined);scope[name]=value;events.push('provide:'+name);
  return ()=>{
   events.push('remove:'+name);
   if(name==='primeAuthority'&&++authorityRemovals<=removeAuthorityFailures)throw new Error('synthetic authority removal failure');
   if(scope[name]===value)delete scope[name];
  };
 }}};
 scope.primeOwnerNativeConnection=Object.freeze({controller,isConnected:binding=>binding===selected&&witness?.isCurrent()===true});
 const native=createOwnerMemoryNativeBinding(scope,{contracts,ownerBinding,passkeySigner:base.passkeySigner,
  fetcher:async()=>{fetches++;throw new Error('unexpected native source-fixture fetch');}});
 return {scope,native,controller,events,get fetches(){return fetches;},get authorityRemovals(){return authorityRemovals;},
  // Explicit source simulation of B's connect notification, never a host probe.
  connect(){selected=scope.primeAuthority;witness=controller.connect(selected);},dispose(){native.dispose();controller.dispose();}};
}
{
 const f=nativeFixture();try{
  assert.equal(f.fetches,0);assert.equal(f.scope.primePilotMemory,undefined);
  assert.throws(()=>f.native.client,/not attached/);
  assert.throws(()=>f.native.setCapabilities(caps),/not attached/);checks++;
  f.connect();const client=f.native.attachAfterNativeConnection();
  assert.equal(client,f.native.client);assert.equal(f.native.attachAfterNativeConnection(),client);
  assert.equal(f.scope.primePilotMemory.ownerController,f.controller);
  assert.equal(f.scope.primePilotMemory.client,client);assert.equal(f.fetches,0);checks++;
  f.native.setCapabilities(caps);assert.equal(f.controller.getSnapshot().capability_status,'loaded');
  f.native.capabilitiesUnavailable();assert.equal(f.controller.getSnapshot().capability_status,'unavailable');
  f.native.dispose();assert.deepEqual(f.events.filter(event=>event.startsWith('remove:')),['remove:primePilotMemory','remove:primeAuthority']);
  assert.equal(f.scope.primeAuthority,undefined);assert.equal(f.scope.primePilotMemory,undefined);
  assert.throws(()=>f.native.attachAfterNativeConnection(),/no longer current/);
  assert.throws(()=>f.native.setCapabilities(caps),/no longer current/);assert.equal(f.fetches,0);checks++;
 }finally{f.dispose();}
}
{
 const f=nativeFixture();try{
  assert.throws(()=>f.native.attachAfterNativeConnection(),/exact native connection is not current/);
  assert.notEqual(f.scope.primeAuthority,undefined);assert.equal(f.scope.primePilotMemory,undefined);
  f.connect();assert.equal(f.native.attachAfterNativeConnection(),f.native.client);
  assert.equal(f.fetches,0);checks++;
 }finally{f.dispose();}
}
{
 const f=nativeFixture({removeAuthorityFailures:1});try{
  f.connect();f.native.attachAfterNativeConnection();
  assert.throws(()=>f.native.dispose(),/OWNER_MEMORY_NATIVE_CLEANUP_FAILED/);
  assert.equal(f.scope.primePilotMemory,undefined);assert.notEqual(f.scope.primeAuthority,undefined);
  assert.throws(()=>f.native.capabilitiesUnavailable(),/no longer current/);
  f.native.dispose();assert.equal(f.scope.primeAuthority,undefined);assert.equal(f.authorityRemovals,2);
  f.native.dispose();assert.equal(f.authorityRemovals,2);assert.equal(f.fetches,0);checks++;
 }finally{f.dispose();}
}
{
 const f=nativeFixture();let off;try{
  f.connect();let detached=false;
  off=f.controller.subscribe(()=>{if(!detached){detached=true;f.native.dispose();}});
  assert.throws(()=>f.native.attachAfterNativeConnection(),/disposed during attachment/);
  assert.equal(detached,true);assert.equal(f.events.includes('install:forget'),false);
  assert.equal(f.scope.primeAuthority,undefined);assert.equal(f.scope.primePilotMemory,undefined);
  assert.equal(f.fetches,0);checks++;
 }finally{off?.();f.dispose();}
}
{
 const f=nativeFixture();let off;try{
  f.connect();let reentered=false;
  off=f.controller.subscribe(()=>{if(!reentered){reentered=true;
   assert.throws(()=>f.native.attachAfterNativeConnection(),/attachment in progress/);
  }});
  const client=f.native.attachAfterNativeConnection();
  assert.equal(reentered,true);assert.equal(f.native.client,client);
  assert.equal(f.events.filter(event=>event==='provide:primePilotMemory').length,1);
  assert.equal(f.events.filter(event=>event==='install:forget').length,1);assert.equal(f.fetches,0);checks++;
 }finally{off?.();f.dispose();}
}
{
 const f=nativeFixture();let off;try{
  f.connect();let replaced=false,replacementWitness;
  off=f.controller.subscribe(()=>{if(!replaced){replaced=true;
   replacementWitness=f.controller.connect({...f.scope.primeAuthority});
   f.controller.setForgetAction(async()=>null);
  }});
  assert.throws(()=>f.native.attachAfterNativeConnection(),/disposed during attachment|exact native connection/);
  assert.equal(replacementWitness.isCurrent(),true);
  assert.equal(f.events.filter(event=>event==='install:forget').length,1);
  assert.equal(f.events.includes('clear:forget'),false);
  f.native.dispose();assert.equal(replacementWitness.isCurrent(),true);assert.equal(f.fetches,0);checks++;
 }finally{off?.();f.dispose();}
}
{
 const f=nativeFixture();let off;try{
  f.connect();const client=f.native.attachAfterNativeConnection();
  let replaced=false,replacementWitness;
  off=f.controller.subscribe(()=>{if(!replaced){replaced=true;
   replacementWitness=f.controller.connect({...f.scope.primeAuthority});
   f.controller.setForgetAction(async()=>null);
  }});
  f.native.dispose();assert.equal(replacementWitness.isCurrent(),true);
  assert.equal(f.events.includes('clear:forget'),false);
  assert.throws(()=>client.setCapabilities(caps),/not attached/);
  assert.equal(f.fetches,0);checks++;
 }finally{off?.();f.dispose();}
}
{
 const f=nativeFixture();try{
  f.connect();const client=f.native.attachAfterNativeConnection();
  // Reusing exactly the same object still creates a different connection.
  const replacement=f.controller.connect(f.scope.primeAuthority);
  assert.equal(replacement.isCurrent(),true);
  assert.throws(()=>client.refresh(),/not attached|exact native connection/);
  assert.throws(()=>f.native.setCapabilities(caps),/exact native connection/);
  f.native.dispose();assert.equal(replacement.isCurrent(),true);assert.equal(f.fetches,0);checks++;
 }finally{f.dispose();}
}
{
 const f=nativeFixture();try{
  f.connect();const client=f.native.attachAfterNativeConnection(),ack=f.scope.primeOwnerNativeConnection;
  f.scope.primeOwnerNativeConnection=Object.freeze({...ack});
  assert.throws(()=>client.getRecallSnapshot(),/exact native connection/);
  assert.throws(()=>f.native.setCapabilities(caps),/exact native connection/);assert.equal(f.fetches,0);checks++;
 }finally{f.dispose();}
}
{
 let enter,release;
 const entered=new Promise(resolve=>{enter=resolve;}),gate=new Promise(resolve=>{release=resolve;});
 const f=fixture({reconcile:async(_snapshot,apply)=>{enter();await gate;return apply();}});
 try{
  await f.prepare();await f.controller.submitApproval();
  const pending=f.client.recover();await entered;
  f.controller.logout();release();
  await assert.rejects(pending,/recovery owner is no longer current/);
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.recover'),1);checks++;
 }finally{release();f.dispose();}
}
// Import the exact release module closure from a disposable layout containing
// no source checkout or node_modules. Never run the full composer/boot here.
const stage=mkdtempSync(join(tmpdir(),'prime-owner-client-import-'));
try{
 mkdirSync(join(stage,'harness'));mkdirSync(join(stage,'prime-packages'),{recursive:true});
 for(const [name,files] of Object.entries({contracts:['src/shared.mjs','src/json.mjs'],memory:['src/capture-review.mjs'],
  'runtime-bridge':['src/ui-adapter.mjs','src/owner-memory-workflow.mjs','src/owner-forget-workflow.mjs','src/pilot-capture.mjs']})){
  for(const file of files){const destination=join(stage,'prime-packages',name,file);mkdirSync(resolve(destination,'..'),{recursive:true});
   cpSync(new URL('../packages/'+name+'/'+file,import.meta.url),destination);}
 }
 cpSync(new URL('./owner-memory-browser.mjs',import.meta.url),join(stage,'harness/owner-memory-browser.mjs'));
 cpSync(new URL('./owner-memory-native.mjs',import.meta.url),join(stage,'harness/owner-memory-native.mjs'));
 const source=readFileSync(new URL('./owner-memory-client.mjs',import.meta.url),'utf8');
 writeFileSync(join(stage,'harness/owner-memory-client.mjs'),source.replaceAll("'../packages/runtime-bridge/src/","'../prime-packages/runtime-bridge/src/"));
 const module=await import(pathToFileURL(join(stage,'harness/owner-memory-client.mjs')).href);
 assert.equal(typeof module.createOwnerMemoryClient,'function');checks++;
 const nativeModule=await import(pathToFileURL(join(stage,'harness/owner-memory-native.mjs')).href);
 assert.equal(typeof nativeModule.createOwnerMemoryNativeBinding,'function');checks++;
}finally{rmSync(stage,{recursive:true,force:true});}
console.log(JSON.stringify({result:'PASS',checks,scope:'actual B controller + bridge workflow + H root/browser/HTTP assembly',
 synthetic_replies:true,listener_started:false,actual_C_crypto:false,actual_postgres:false,production_acceptance:false,runtime_changes:false}));
