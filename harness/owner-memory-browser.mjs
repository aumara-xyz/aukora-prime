// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-only HTTP adapter for the existing closed runtime bridge. No mounting,
// credentials, owner discovery, signing, qualification, or mutation retries.
export const OWNER_MEMORY_METHODS=Object.freeze([
 'capability.status','owner.status','memory.status','memory.cite','memory.recall',
 'memory.proposeSave','owner.loginChallenge','owner.loginComplete',
 'owner.approvalChallenge','owner.approvalComplete','owner.declineApproval','memory.save',
 'owner.logout','memory.proposeForget','memory.forget','memory.recover',
]);
const reads=new Set(['capability.status','owner.status','memory.status','memory.cite','memory.recall']);
const failure=(error_code,reason)=>Object.freeze({ok:false,error_code,reason});
export function createOwnerMemoryHttpCall({contracts,fetcher=globalThis.fetch}={}) {
 if(typeof contracts?.canonicalJson!=='function'||typeof contracts?.parseStrictJson!=='function'||typeof fetcher!=='function')throw new TypeError('UNAVAILABLE: frozen browser contracts and HTTP transport required');
 let inflight=0;
 return async function call(method,input,{signal}={}) {
  if(!OWNER_MEMORY_METHODS.includes(method))return failure('INVALID','BRIDGE_METHOD_NOT_PUBLIC');
  if(signal?.aborted)return failure('UNAVAILABLE','REQUEST_CANCELLED_BEFORE_SEND');
  let body;
  try {body=contracts.canonicalJson(input);contracts.parseStrictJson(body,{maxBytes:65536,maxDepth:32});}
  catch{return failure('INVALID','INVALID_BRIDGE_JSON');}
  if(inflight>=8)return failure('UNAVAILABLE','HTTP_INFLIGHT_BOUND');
  inflight++;
  try {
   // One fetch only. Lost/redirected/oversized/malformed mutation replies are
   // unknown; the coordinator must retain its fence and reconcile separately.
   const response=await fetcher('/api/prime/bridge/'+method,{method:'POST',
    headers:{'content-type':'application/json'},body,credentials:'same-origin',
    mode:'same-origin',redirect:'error',cache:'no-store',signal});
   if(response.redirected||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??''))throw new TypeError('INVALID_BRIDGE_RESPONSE');
   const reader=response.body?.getReader();if(!reader)throw new TypeError('BOUNDED_BODY_REQUIRED');
   const chunks=[];let size=0;
   try {for(;;){const {done,value}=await reader.read();if(done)break;
    if(!(value instanceof Uint8Array)||(size+=value.byteLength)>65536)throw new TypeError('HTTP_RESPONSE_BOUND');chunks.push(value);
   }}catch(error){await reader.cancel().catch(()=>{});throw error;}finally{reader.releaseLock();}
   const bytes=new Uint8Array(size);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.byteLength;}
   if(bytes[0]===0xef&&bytes[1]===0xbb&&bytes[2]===0xbf)throw new TypeError('INVALID_UTF8');
   const value=contracts.parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{maxBytes:65536,maxDepth:32});
   if(!value||typeof value!=='object'||Array.isArray(value)||typeof value.ok!=='boolean')throw new TypeError('INVALID_BRIDGE_RESULT');
   if(!response.ok&&value.ok)throw new TypeError('HTTP_RESULT_MISMATCH');
   return value;
  } catch{return failure(reads.has(method)?'UNAVAILABLE':'OUTCOME_UNKNOWN','BRIDGE_REPLY_UNAVAILABLE');}
  finally {inflight--;}
 };
}
