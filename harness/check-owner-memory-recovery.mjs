// SPDX-License-Identifier: AGPL-3.0-or-later
// Focused H assembly check: real B/C/D objects, synthetic P-256 credentials,
// bounded in-memory HTTP and a disposable SQLite dialect fixture. No public
// qualification, PostgreSQL, worker IPC, UI rendering or deployed effects.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import * as contracts from '../packages/contracts/src/browser.mjs';
import {createPrimeOwnerController} from '../packages/ui/prime-authority/src/client/controller.mjs';
import {createOwnerMemoryClient} from './owner-memory-client.mjs';
import {createOwnerMemoryHttpRoutes} from './owner-memory-transport.mjs';
import * as fixtures from '../packages/runtime-bridge/test/owner-memory-fixture.mjs';
import {assertRecoveryContinuation} from '../packages/runtime-bridge/test/owner-memory-recovery-continuation.mjs';

const profile=Object.freeze({profile:'https',origin:'https://prime.example.test',rp_id:'prime.example.test'});
const caps={version:1,source_commit:'1b7bd3d7909996c8d515a5c588059e5b2257e39a',runtime_pid:1,
 release_digest:'sha256:'+'b'.repeat(64),unavailable_capabilities:[],phase:'disposable-preview',qualification:'PENDING'};
const ownerBinding={owner_id:fixtures.ownerId,passkeyProfile:profile};

async function http(routes,url,options){
 const request=Readable.from([Buffer.from(options.body)]);
 request.method=options.method;request.url=url;
 request.headers={host:profile.rp_id,origin:profile.origin,'content-type':'application/json'};
 let status,headers,body;
 const response={destroyed:false,writableEnded:false,writeHead(value,next){status=value;headers=next;},
  end(value){body=value;this.writableEnded=true;}};
 try{await routes.find(route=>route.path===url).handler(request,response);}finally{request.destroy();}
 return new Response(body,{status,headers});
}
async function assembled(t,{reconcile}={}){
 const mounts=[];let signatures=0;
 t.after(async()=>{for(const m of mounts)if(!m.disposed){await m.client.logout();m.dispose();}});
 const f=await fixtures.fixture(t,{actions:['memory.save','memory.forget']});
 // This explicit fixture boundary calls actual C/D through bridge.handleTrusted;
 // it is never installed as a production/public acceptance callback.
 const routes=createOwnerMemoryHttpRoutes({contracts,connection:{requestRejection:()=>undefined},guardRequest:()=>profile,
  publicBoundary:{handlePublic:(method,input)=>f.bridgeCall(method,input)}});
 const mount=()=>{
  const controller=createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}});
  const joined=reconcile?{...controller,reconcileApprovalAction:snapshot=>reconcile(snapshot,()=>controller.reconcileApprovalAction(snapshot))}:controller;
  let connectionWitness;
  const client=createOwnerMemoryClient({controller:joined,contracts,ownerBinding,
   isCurrentConnection:()=>connectionWitness?.isCurrent()===true,
   passkeySigner:({public_key})=>{signatures++;return f.auth.assertion(public_key.challenge);},
   fetcher:(url,options)=>http(routes,url,options)});
  connectionWitness=controller.connect(client.binding);client.attach();client.setCapabilities(caps);
  const m={client,controller,disposed:false,
   async login(){assert(await controller.login());assert.equal(controller.getSnapshot().phase,'authenticated');},
   dispose(){if(this.disposed)return;this.disposed=true;client.dispose();controller.dispose();}};
  mounts.push(m);return m;
 };
 return {f,mount,signatures:()=>signatures};
}
async function save(m,key){
 assert.equal((await m.client.proposeSave(fixtures.draft(key))).phase,'proposed');
 assert(await m.controller.prepare());
 const first=m.controller.submitApproval(),second=m.controller.submitApproval();assert.equal(first,second);
 return first;
}

test('H recovered actual save updates the same B controller and permits one unrelated new save',async t=>{
 const result=await assertRecoveryContinuation(t,{assembled,save});
 const view=result.recoveredController;
 assert.equal(view.phase,'approved');assert.equal(view.error_code,null);
 assert.equal(view.approval_action_pending,false);assert.equal(view.approval_action_available,true);
 assert.equal(view.approval_action_result.saved,true);
 assert.equal(view.approval_action_result.reconciliation_required,false);
 assert.equal(view.approval_action_result.authority_settlement,'completed');
 assert.deepEqual(view.approval_action_result.receipt,result.recovered.receipt);
 assert.deepEqual(view.approval_action_result.record,result.recovered.record);
 assert.equal(view.presentation.operation.operation_id,result.oldOperation.operation_id);
 assert.equal(view.presentation.operation_digest,result.recovered.operation_digest);
});

test('H awaits B reconciliation and passes the exact workflow snapshot without rewriting it',async t=>{
 let enter,release,passed;
 const entered=new Promise(resolve=>{enter=resolve;});
 const held=new Promise(resolve=>{release=resolve;});
 t.after(()=>release());
 const a=await assembled(t,{async reconcile(snapshot,complete){passed=snapshot;const result=await complete();enter();await held;return result;}});
 const m=a.mount();await m.login();
 a.f.delivery.set('memory.save',reply=>{fixtures.ok(reply);throw new Error('test-only committed reply lost');});
 assert.equal((await save(m,'await-recovery')).save,'unknown');a.f.delivery.delete('memory.save');
 const signatures=a.signatures();let returned=false;
 const pending=m.client.recover().then(snapshot=>{returned=true;return snapshot;});
 await entered;await new Promise(resolve=>setImmediate(resolve));
 assert.equal(returned,false,'H must not return before B reconciliation settles');
 release();const recovered=await pending;
 assert.equal(passed,recovered);assert.equal(passed,m.client.workflow.getSnapshot());
 assert.equal(m.controller.getSnapshot().approval_action_result.saved,true);
 assert.equal(a.signatures(),signatures);assert.equal(a.f.count('memory.save'),1);
});

test('H recovered actual forget updates the same B controller without repeating forget',async t=>{
 const a=await assembled(t),m=a.mount();await m.login();
 const saved=await save(m,'before-recovered-forget');fixtures.assertSaved(saved);
 assert.equal((await m.client.proposeForget({record_id:saved.record.record_id})).phase,'proposed');
 assert(await m.controller.prepare());
 a.f.delivery.set('memory.forget',reply=>{fixtures.ok(reply);throw new Error('test-only committed forget reply lost');});
 assert.equal((await m.controller.submitApproval()).forget,'unknown');a.f.delivery.delete('memory.forget');
 const signatures=a.signatures(),committed=fixtures.ok(a.f.replies.find(reply=>reply.method==='memory.forget').result);
 const recovered=await m.client.recoverForget(),view=m.controller.getSnapshot();
 assert.equal(recovered.forgotten,true);assert.deepEqual(recovered.receipt,committed.receipt);
 assert.equal(view.phase,'approved');assert.equal(view.error_code,null);
 assert.equal(view.forget_action_result.forgotten,true);assert.equal(view.approval_action_result,null);
 assert.deepEqual(view.forget_action_result.receipt,committed.receipt);
 assert.equal(view.forget_action_result.result.physical_media_erasure,false);
 assert.equal(view.approval_action_available,true);
 const repeated=await m.client.recoverForget();assert.deepEqual(repeated.receipt,recovered.receipt);
 assert.equal(a.signatures(),signatures);assert.equal(a.f.count('memory.forget'),1);
 fixtures.assertSaved(await save(m,'new-save-after-recovered-forget'));
 assert.equal(a.f.count('memory.forget'),1);assert.equal(a.f.count('memory.save'),2);
 assert.equal(a.signatures(),signatures+1);assert.equal(a.f.tableCount('prime_memory_effects'),3);
});

test('H unknown recovery keeps the retained action fenced and refuses a new save',async t=>{
 let passed,reconciliationResult;
 const a=await assembled(t,{async reconcile(snapshot,complete){passed=snapshot;reconciliationResult=await complete();return reconciliationResult;}}),m=a.mount();await m.login();
 a.f.delivery.set('memory.save',reply=>{fixtures.ok(reply);throw new Error('test-only committed reply lost');});
 assert.equal((await save(m,'unresolved-recovery')).save,'unknown');a.f.delivery.delete('memory.save');
 const signatures=a.signatures();
 a.f.delivery.set('memory.recover',reply=>{fixtures.ok(reply);throw new Error('test-only recovery reply unavailable');});
 const recovered=await m.client.recover();
 assert.equal(passed,recovered);assert.equal(reconciliationResult,null);
 assert.equal(recovered.reconciliation_required,true);assert.equal(recovered.saved,null);
 assert.equal(m.controller.getSnapshot().phase,'outcome_unknown');
 assert.equal(m.controller.getSnapshot().approval_action_result.saved,null);
 assert.equal(m.controller.getSnapshot().approval_action_available,false);
 const next=await m.client.proposeSave(fixtures.draft('blocked-after-unknown-recovery'));
 assert.equal(next.phase,'outcome_unknown');assert.equal(next.error_code,'RECONCILIATION_REQUIRED');
 assert.equal(a.signatures(),signatures);assert.equal(a.f.count('memory.save'),1);
 assert.equal(a.f.count('owner.approvalComplete'),1);assert.equal(a.f.count('memory.proposeSave'),1);
});

test('H propagates a rejected reconciliation hook without retrying approval or effect',async t=>{
 const failure=new Error('test-only reconciliation hook rejected');let calls=0;
 const a=await assembled(t,{reconcile(){calls++;throw failure;}}),m=a.mount();await m.login();
 a.f.delivery.set('memory.save',reply=>{fixtures.ok(reply);throw new Error('test-only committed reply lost');});
 assert.equal((await save(m,'rejected-reconciliation')).save,'unknown');a.f.delivery.delete('memory.save');
 const signatures=a.signatures();
 await assert.rejects(m.client.recover(),error=>error===failure);
 assert.equal(calls,1);assert.equal(a.signatures(),signatures);
 assert.equal(a.f.count('memory.save'),1);assert.equal(a.f.count('owner.approvalComplete'),1);
 assert.equal(m.controller.getSnapshot().phase,'outcome_unknown');
 assert.equal(m.controller.getSnapshot().approval_action_result.saved,null);
});

test('H rejects a controller without its reconciliation method before attachment',()=>{
 const controller=createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}});
 try{
  const {reconcileApprovalAction,...unsupported}=controller;
  assert.equal(typeof reconcileApprovalAction,'function');
  assert.throws(()=>createOwnerMemoryClient({controller:unsupported,contracts,ownerBinding}),/native owner controller required/);
 }finally{controller.dispose();}
});
