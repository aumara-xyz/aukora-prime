// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable, local synthetic bindings only; no IPC listener, C signer, DB or live setup.
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,rmSync,mkdirSync,cpSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createTrustedTaskRegistry} from '../packages/runtime-bridge/src/registry.mjs';
import {sha256} from '../packages/memory/src/codecs.mjs';
import {createOwnerMemoryContext} from './owner-memory-context.mjs';

const root=mkdtempSync(join(tmpdir(),'prime-owner-memory-context-'));
let checks=0;
const refused=(fn,code)=>{assert.throws(fn,error=>error.error_code===code);checks++;};
const clone=value=>structuredClone(value);
try{
  const at='2026-10-01T20:00:00Z',subject='aukora:1:'+'a'.repeat(64),owner='synthetic-owner',taskId='synthetic-task';
  const bytes=Buffer.from(JSON.stringify({seq:0,at,text:'Synthetic exact bytes: Café <literal>\n'})+'\n');
  writeFileSync(join(root,'event.json'),bytes,{mode:0o600});
  const entry={task:{version:1,task_id:taskId,owner_id:owner,agent_id:'synthetic-agent',conversation_id:'synthetic-conversation',status:'running',created_at:at,
    route_id:null,allowed_data_classes:['synthetic'],max_input_tokens:100,max_output_tokens:100,max_requests:1,task_spend_ceiling:{currency:'USD',amount:'0'}},
    provider_and_region:{provider:'local',region:'local'},audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']};
  const registry=createTrustedTaskRegistry([entry]);
  const binding={credential_id:'synthetic-owner-control',owner_id:owner,task_id:taskId,memory_host:{owner_subject:subject,privacy:'local',scope:'owner',attributedTo:'owner',
    source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(bytes)},events:[readFileSync(join(root,'event.json'))],controls:{pause:false},origin:{by:'synthetic-check'}}};
  const session={ok:true,owner_id:owner,subject,authorization_epoch:0,expiry:new Date(Date.now()+60_000).toISOString()};
  const request={transport:'ipc',credential_id:binding.credential_id};
  const resolve=createOwnerMemoryContext({taskRegistry:registry,bindings:[binding]});
  assert.deepEqual(resolve({request,session:null}),{login_owner_id:owner});checks++;
  const result=resolve({request,session});
  assert.equal(result.task_id,taskId);assert.equal(result.memory_host.owner_subject,subject);assert.ok(Buffer.from(result.memory_host.events[0]).equals(bytes));checks++;
  // Copy only the exact first-party dependency closure into the composed layout;
  // no source-layout packages directory exists there to conceal import mistakes.
  const composed=join(root,'composed'),sourceRoot=fileURLToPath(new URL('../',import.meta.url));
  const copy=(source,target)=>{mkdirSync(dirname(target),{recursive:true});cpSync(source,target,{recursive:true});};
  copy(join(sourceRoot,'harness/owner-memory-context.mjs'),join(composed,'harness/owner-memory-context.mjs'));
  copy(join(sourceRoot,'packages/contracts/src'),join(composed,'prime-packages/contracts/src'));
  copy(join(sourceRoot,'packages/runtime-bridge/src/registry.mjs'),join(composed,'prime-packages/runtime-bridge/src/registry.mjs'));
  for(const part of ['src','genesis','package.json'])copy(join(sourceRoot,'packages/memory',part),join(composed,'prime-packages/memory',part));
  writeFileSync(join(composed,'prime-release.json'),'{}\n');
  const releaseModule=await import(pathToFileURL(join(composed,'harness/owner-memory-context.mjs')).href);
  const releaseResolver=releaseModule.createOwnerMemoryContext({taskRegistry:registry,bindings:[binding]});
  assert.deepEqual(releaseResolver({request,session}),result);assert.deepEqual(releaseResolver({request,session:null}),{login_owner_id:owner});checks++;
  // Config and returned byte arrays never retain a reference to the private snapshot.
  binding.owner_id='changed';binding.memory_host.source.sha256='b'.repeat(64);binding.memory_host.events[0].fill(0);binding.memory_host.controls.pause=true;
  result.memory_host.events[0].fill(1);result.memory_host.source.sessionId='changed';
  const next=resolve({request,session});assert.ok(Buffer.from(next.memory_host.events[0]).equals(bytes));assert.equal(next.memory_host.source.sha256,sha256(bytes));assert.equal(next.memory_host.controls.pause,false);checks++;
  for(const changed of [{transport:'http',credential_id:request.credential_id},{transport:'ipc',credential_id:'other'}, {...request,owner_id:owner},{...request,headers:{owner_id:owner}}])refused(()=>resolve({request:changed,session}),Object.keys(changed).length===2?'UNAUTHORIZED':'INVALID');
  refused(()=>resolve({request,session,body:{task_id:taskId}}),'INVALID');
  for(const changed of [{...session,ok:false},{...session,owner_id:'other'},{...session,subject:'aukora:1:'+'b'.repeat(64)},
    {...session,authorization_epoch:-1},{...session,expiry:new Date(0).toISOString()}])refused(()=>resolve({request,session:changed}),'UNAUTHORIZED');
  refused(()=>resolve({request,session:{...session,task_id:taskId}}),'INVALID');
  refused(()=>createOwnerMemoryContext()({request,session}),'UNAVAILABLE');
  const original={...clone(binding),owner_id:owner,memory_host:clone(next.memory_host)};
  const shared=clone(original),sharedBytes=new Uint8Array(new SharedArrayBuffer(bytes.length));sharedBytes.set(bytes);
  Object.defineProperty(sharedBytes,'buffer',{value:new ArrayBuffer(bytes.length)});shared.memory_host.events=[sharedBytes];
  refused(()=>createOwnerMemoryContext({taskRegistry:registry,bindings:[shared]}),'INVALID');
  const shadowed=clone(original);let byteGetterCalls=0;
  Object.defineProperties(shadowed.memory_host.events[0],{buffer:{get(){byteGetterCalls++;return new SharedArrayBuffer(0);}},byteLength:{get(){byteGetterCalls++;return 0;}},byteOffset:{get(){byteGetterCalls++;return 999999;}}});
  const clean=createOwnerMemoryContext({taskRegistry:registry,bindings:[shadowed]});
  assert.ok(Buffer.from(clean({request,session}).memory_host.events[0]).equals(bytes));assert.equal(byteGetterCalls,0);checks++;
  const proxied=clone(original);proxied.memory_host.events=[new Proxy(proxied.memory_host.events[0],{})];
  refused(()=>createOwnerMemoryContext({taskRegistry:registry,bindings:[proxied]}),'INVALID');
  for(const mutate of [b=>{b.memory_host.source.sha256='c'.repeat(64);},b=>{b.memory_host.events[0][0]^=1;},b=>{b.memory_host.task_id='other';},
    b=>{b.memory_host.owner_id='other';},b=>{b.memory_host.privacy='exportable';},b=>{b.memory_host.source.at='2026-02-30T20:00:00Z';},
    b=>{b.memory_host.source_span={start:0,end:1};},b=>{b.memory_host.events=[{text:'guest'}];},b=>{b.extra='guest';}]){
    const changed=clone(original);mutate(changed);assert.throws(()=>createOwnerMemoryContext({taskRegistry:registry,bindings:[changed]}));checks++;
  }
  refused(()=>createOwnerMemoryContext({taskRegistry:registry,bindings:[original,clone(original)]}),'INVALID');
  let getterCalls=0;const getter=clone(original);Object.defineProperty(getter.memory_host,'origin',{enumerable:true,get(){getterCalls++;return {by:'guest'};}});
  refused(()=>createOwnerMemoryContext({taskRegistry:registry,bindings:[getter]}),'INVALID');assert.equal(getterCalls,0);checks++;
  const mutableEntry=clone(entry),mutableRegistry={getOwned:()=>mutableEntry,authorizeTask:registry.authorizeTask};
  const pinned=createOwnerMemoryContext({taskRegistry:mutableRegistry,bindings:[original]});mutableEntry.task.status='completed';
  refused(()=>pinned({request,session}),'UNAUTHORIZED');
  const wrongOwner=clone(entry);wrongOwner.task.owner_id='another-owner';
  refused(()=>createOwnerMemoryContext({taskRegistry:createTrustedTaskRegistry([wrongOwner]),bindings:[original]}),'INVALID');
  const entry2=clone(entry);entry2.task.task_id='synthetic-task-2';entry2.task.owner_id='synthetic-owner-2';
  const second=clone(original);second.credential_id='synthetic-owner-control-2';second.owner_id=entry2.task.owner_id;second.task_id=entry2.task.task_id;
  refused(()=>createOwnerMemoryContext({taskRegistry:createTrustedTaskRegistry([entry,entry2]),bindings:[original,second]}),'INVALID');
  second.memory_host.owner_subject='aukora:1:'+'b'.repeat(64);
  const separate=createOwnerMemoryContext({taskRegistry:createTrustedTaskRegistry([entry,entry2]),bindings:[original,second]});
  refused(()=>separate({request:{transport:'ipc',credential_id:second.credential_id},session}),'UNAUTHORIZED');
  console.log(JSON.stringify({status:'PASS',checks,scope:'immutable host capture/task/IPC identity binding, synthetic local data only',public_qualification:'UNPERFORMED'}));
}finally{rmSync(root,{recursive:true,force:true});}
