// SPDX-License-Identifier: AGPL-3.0-or-later
// Scoped source composition check. Actual B controller/bridge workflow/H HTTP
// factories; synthetic replies, no listener, C crypto, PostgreSQL or acceptance.
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {mkdtempSync,mkdirSync,cpSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import * as contracts from '../packages/contracts/src/browser.mjs';
import {createPrimeOwnerController} from '../packages/ui/prime-authority/src/client/controller.mjs';
import {createOwnerUiFixture} from '../packages/ui/prime-authority/checks/fixture.mjs';
import {createOwnerMemoryClient} from './owner-memory-client.mjs';
import {createOwnerMemoryHost} from './owner-memory-host.mjs';
import {createOwnerMemoryHttpRoutes} from './owner-memory-transport.mjs';
import {createLocalhostPilotGuard} from '../packages/runtime-bridge/src/pilot-origin.mjs';
let checks=0;
const literal='  <tag>&\n\t🍌 e\u0301  ',capture={statement:literal,attributed_to:'owner-edit'};
const ownerBinding={owner_id:'ui-fixture-owner',passkeyProfile:{profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'}};
const caps={version:1,source_commit:'a'.repeat(40),runtime_pid:1,release_digest:'sha256:'+'b'.repeat(64),
 unavailable_capabilities:[],phase:'disposable-preview',qualification:'PENDING'};
const guardRequest=createLocalhostPilotGuard(ownerBinding.passkeyProfile);
const connection={requestRejection:()=>undefined};

function fixture({lostSave=false,lostLogin=false}={}){
 const base=createOwnerUiFixture(contracts),calls=[];
 let saved,holdLogin,releaseLogin;
 const entered=new Promise(resolve=>{holdLogin=resolve;});
 const wait=new Promise(resolve=>{releaseLogin=resolve;});
 const boundary={async handlePublic(method,input){
  calls.push({method,input});
  if(method.startsWith('owner.')){
   const result=await base.authority[method.slice(6)](input);
   if(lostLogin&&method==='owner.loginComplete'){holdLogin();await wait;}
   return result;
  }
  if(method==='memory.proposeSave'){
   const operation={...base.operation,operation_id:'source-host-memory',action_type:'memory.save',audience:'aukora-prime.memory',
    target_identity:{kind:'prime-memory',owner_subject:'aukora:1:'+'1'.repeat(64)},canonical_parameters:{capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),
     heads:{remembered:'aukora:aura-record:v1'},...capture}};
   return {ok:true,operation,operation_digest:await contracts.operationDigest(operation),memory_capture:{...capture}};
  }
  if(method==='memory.save'){
   const op=input.operation,record={version:1,record_id:'source-fixture-record',owner_subject:op.target_identity.owner_subject,task_id:op.task_id,
    scope:'owner',privacy:'local',record_format:'source-fixture',canonicalizer:'source-fixture',canonical_bytes:JSON.stringify({statement:literal,attributedTo:capture.attributed_to}),
    revision:'source-fixture-revision',grants_authority:false,source_event_digest:'sha256:'+'c'.repeat(64),evidence:[],chain_domain:'remembered',
    source_span:{fixture:true},storage_status:'saved',index_status:'pending'};
   const receipt={version:1,kind:'prime-memory-effect/v1',operation_id:op.operation_id,operation_digest:input.approval_proof.operation_digest,
    grant_id:'grant:'+input.approval_proof.nonce,request_id:'11111111-1111-4111-8111-111111111111',request_digest:'sha256:'+'d'.repeat(64),
    owner_subject:record.owner_subject,action_type:'memory.save',status:'applied',result_digest:'sha256:'+'e'.repeat(64),result:record};
   saved={ok:true,record,receipt,authority_settlement:'completed',reconciliation_required:false,receipt_digest:'sha256:'+'f'.repeat(64)};
   return saved;
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
  return new Response(body,{status,headers});
 };
 const controller=createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}});
 const client=createOwnerMemoryClient({controller,contracts,ownerBinding,fetcher,passkeySigner:base.passkeySigner});
 // Source simulation of native primeAuthority injection. No Cordis mount or
 // default-browser effect is claimed by this check.
 assert.throws(()=>client.proposeSave({}),/not attached/);checks++;
 controller.connect(client.binding);client.attach();assert.equal(client.attach(),client.workflow);checks++;
 return {client,controller,calls,entered,releaseLogin,
  count:method=>calls.filter(value=>value.method===method).length,
  async prepare(){client.setCapabilities(caps);assert(await controller.login());
   assert.equal((await client.proposeSave({extraction_json:JSON.stringify({statement:literal,category:'fact'}),idempotency_key:'source-single-use'})).phase,'proposed');
   assert(await controller.prepare());},
  dispose(){releaseLogin();client.dispose();controller.dispose();}};
}
{
 const f=fixture();try{
  assert.equal(await f.controller.login(),null);assert.equal(f.calls.length,0);checks++;
  await f.prepare();const one=f.controller.submitApproval(),two=f.controller.submitApproval();assert.equal(one,two);
  const result=await one;assert.equal(result.saved,true);assert.equal(result.index.searchable,false);assert.equal(result.citation_status,'unverified');
  assert.equal(result.authority_settlement,'completed');assert.equal(f.count('memory.save'),1);checks++;
  const save=f.calls.find(value=>value.method==='memory.save').input;
  assert.equal(save.operation.canonical_parameters.statement,literal);assert.equal(save.operation.canonical_parameters.attributed_to,capture.attributed_to);
  assert.equal(save.approval_proof.operation_digest,await contracts.operationDigest(save.operation));checks++;
  f.controller.logout();const before=f.calls.length;await f.client.refresh();assert.equal(f.calls.length,before);checks++;
  const old=await f.client.binding.authority.approvalChallenge({session_token:'synthetic-in-memory-only',operation:save.operation});
  assert.equal(old.error_code,'UNAUTHORIZED');assert.equal(f.calls.length,before);checks++;
 }finally{f.dispose();}
}
{
 const f=fixture({lostSave:true});try{
  await f.prepare();const result=await f.controller.submitApproval();assert.equal(result.save,'unknown');assert.equal(result.saved,null);checks++;
  await f.controller.submitApproval();await f.client.proposeSave({extraction_json:JSON.stringify({statement:literal}),idempotency_key:'replacement'});
  assert.equal(f.count('memory.save'),1);assert.equal(f.count('memory.proposeSave'),1);checks++;
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
 const host=createOwnerMemoryHost({connection,guardRequest,contracts});
 assert.equal((await host.publicBoundary.handlePublic('memory.save',{})).error_code,'UNAVAILABLE');checks++;
 assert(Object.isFrozen(host.routes));assert.equal(host.routes.length,12);checks++;
}
// Import the exact release module closure from a disposable layout containing
// no source checkout or node_modules. Never run the full composer/boot here.
const stage=mkdtempSync(join(tmpdir(),'prime-owner-client-import-'));
try{
 mkdirSync(join(stage,'harness'));mkdirSync(join(stage,'prime-packages'),{recursive:true});
 for(const [name,files] of Object.entries({contracts:['src/shared.mjs','src/json.mjs'],memory:['src/capture-review.mjs'],
  'runtime-bridge':['src/ui-adapter.mjs','src/owner-memory-workflow.mjs']})){
  for(const file of files){const destination=join(stage,'prime-packages',name,file);mkdirSync(resolve(destination,'..'),{recursive:true});
   cpSync(new URL('../packages/'+name+'/'+file,import.meta.url),destination);}
 }
 cpSync(new URL('./owner-memory-browser.mjs',import.meta.url),join(stage,'harness/owner-memory-browser.mjs'));
 const source=readFileSync(new URL('./owner-memory-client.mjs',import.meta.url),'utf8');
 writeFileSync(join(stage,'harness/owner-memory-client.mjs'),source.replaceAll("'../packages/runtime-bridge/src/","'../prime-packages/runtime-bridge/src/"));
 const module=await import(pathToFileURL(join(stage,'harness/owner-memory-client.mjs')).href);
 assert.equal(typeof module.createOwnerMemoryClient,'function');checks++;
}finally{rmSync(stage,{recursive:true,force:true});}
console.log(JSON.stringify({result:'PASS',checks,scope:'actual B controller + bridge workflow + H root/browser/HTTP assembly',
 synthetic_replies:true,listener_started:false,actual_C_crypto:false,actual_postgres:false,production_acceptance:false,runtime_changes:false}));
