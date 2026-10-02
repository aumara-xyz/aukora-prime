// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only HTTP → fixed authenticated worker channel. The worker must apply
// the existing bridge.handlePublic gate to every public-dispatch request. A
// synthetic/internal handleTrusted listener never satisfies this profile.
import {existsSync} from 'node:fs';
import {OWNER_MEMORY_METHODS} from './owner-memory-browser.mjs';
const owned=existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/';
const contracts=await import(new URL(owned+'contracts/src/runtime.mjs',import.meta.url));
const {createIpcClient}=await import(new URL(owned+'runtime-bridge/src/ipc.mjs',import.meta.url));
const reads=new Set(['capability.status','owner.status','memory.status','memory.cite','memory.recall']);
const failure=(error_code,reason)=>({ok:false,error_code,reason});
/** channel/deployment are protected host config, never request fields. connect
 * is a trusted transport primitive (default actual authenticated IPC client).
 * No credentials are generated/discovered and no server is started. */
export function createOwnerMemoryIpcBoundary({channel,deployment,connect=createIpcClient,isActive=()=>true}={}) {
 if(!channel||!deployment)return Object.freeze({async handlePublic(){return failure('UNAVAILABLE','PUBLIC_WORKER_UNMOUNTED');}});
 const pinned=contracts.parseStrictJson(contracts.canonicalJson({channel,deployment}),{maxBytes:8192,maxDepth:16});
 if(Object.keys(pinned).sort().join(',')!=='channel,deployment'
  ||Object.keys(pinned.deployment).sort().join(',')!=='release_digest,source_commit'
  ||!/^[a-f0-9]{40}$/.test(pinned.deployment.source_commit)
  ||!/^sha256:[a-f0-9]{64}$/.test(pinned.deployment.release_digest)
  ||typeof connect!=='function'||typeof isActive!=='function')throw new TypeError('INVALID: protected deployment/channel required');
 const active=()=>{try{return isActive()===true;}catch{return false;}};
 let inflight=0;
 return Object.freeze({async handlePublic(method,input) {
  if(!active())return failure('UNAVAILABLE','PUBLIC_WORKER_DISPOSED');
  if(!OWNER_MEMORY_METHODS.includes(method))return failure('INVALID','BRIDGE_METHOD_NOT_PUBLIC');
  let detached;
  try {detached=contracts.parseStrictJson(contracts.canonicalJson(input),{maxBytes:65536,maxDepth:32});
   if(!detached||typeof detached!=='object'||Array.isArray(detached)||(method==='capability.status'&&Object.keys(detached).length))throw new TypeError('CLOSED_CAPABILITY_REQUIRED');}
  catch{return failure('INVALID','INVALID_BRIDGE_JSON');}
  if(inflight>=8)return failure('UNAVAILABLE','IPC_PROXY_INFLIGHT_BOUND');
  inflight++;let client,submitted=false;
  try {
   // One fresh channel for this unsent call; there is no reconnect/resubmission
   // after request(). HTTP association/role never becomes IPC source context.
   client=await connect(structuredClone(pinned.channel));
   if(!active())return failure('UNAVAILABLE','PUBLIC_WORKER_DISPOSED');
   const capability=await client.request('capability.status',{});
   if(!active())return failure('UNAVAILABLE','PUBLIC_WORKER_DISPOSED');
   const record=capability?.qualification;
   if(capability?.ok!==true||capability.available!==true||capability.public_routes!=='available'
    ||capability.public_dispatch!=='qualified-owner-memory/v1'
    ||record?.source_commit!==pinned.deployment.source_commit
    ||record?.release_digest!==pinned.deployment.release_digest)return failure('UNAVAILABLE','QUALIFIED_PUBLIC_WORKER_REQUIRED');
   if(method==='capability.status')return capability;
   // The authenticated worker still rechecks its public qualification when it
   // handles this second request. A prior capability read never grants authority.
   submitted=true;
   return await client.request(method,detached);
  } catch{return failure(submitted&&!reads.has(method)?'OUTCOME_UNKNOWN':'UNAVAILABLE','PUBLIC_WORKER_REPLY_UNAVAILABLE');}
  finally {try {await client?.close();}catch{/* Closing never retries a request. */}inflight--;}
 }});
}
