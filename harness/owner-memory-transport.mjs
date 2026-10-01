// SPDX-License-Identifier: AGPL-3.0-or-later
// Unmounted H HTTP seam. The injected boundary must use the existing bridge
// handlePublic qualification gate. A worker's handleTrusted is not this gate.
import {randomUUID} from 'node:crypto';
import {OWNER_MEMORY_METHODS} from './owner-memory-browser.mjs';
const reads=new Set(['capability.status','owner.status','memory.status','memory.cite','memory.recall']);
const result=(error_code,reason)=>({ok:false,error_code,reason});
const statusOf=value=>value?.ok?200:({INVALID:400,UNAUTHORIZED:403,UNAVAILABLE:503,OUTCOME_UNKNOWN:504}[value?.error_code]??503);
function requestBody(request,{maxBytes,timeoutMs}) {
 return new Promise((resolve,reject)=>{
  const chunks=[];let size=0,finished=false;
  const finish=(error)=>{if(finished)return;finished=true;clearTimeout(timer);
   request.off('data',data);request.off('end',end);request.off('error',fault);request.off('aborted',fault);
   if(error){request.pause();reject(error);}else resolve(Buffer.concat(chunks,size));
  };
  const data=chunk=>{if(!(chunk instanceof Uint8Array))return finish(new Error('RAW_BYTES_REQUIRED'));const bytes=Buffer.from(chunk);size+=bytes.length;
   if(size>maxBytes)return finish(new Error('BOUND'));chunks.push(bytes);};
  const end=()=>finish();const fault=()=>finish(new Error('BODY_UNAVAILABLE'));
  const timer=setTimeout(()=>finish(new Error('BODY_TIMEOUT')),timeoutMs);
  request.on('data',data);request.once('end',end);request.once('error',fault);request.once('aborted',fault);
 });
}
/** Factories create no listener or authority. guardRequest returns the exact
 * trusted C/B profile {profile,origin,rp_id}; booleans/defaults refuse. HTTP
 * request metadata is diagnostic association only, never captured source. */
export function createOwnerMemoryHttpRoutes({connection,publicBoundary,guardRequest,contracts}={}) {
 let inflight=0;
 const mounted=typeof connection?.requestRejection==='function'&&typeof publicBoundary?.handlePublic==='function'
  &&typeof guardRequest==='function'&&typeof contracts?.parseStrictJson==='function'&&typeof contracts?.canonicalJson==='function';
 function send(response,status,value) {
  if(response.destroyed||response.writableEnded)return;
  response.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store',
   'x-content-type-options':'nosniff','connection':'close'});
  response.end(contracts?.canonicalJson?contracts.canonicalJson(value):JSON.stringify(value));
 }
 return Object.freeze(OWNER_MEMORY_METHODS.map(method=>Object.freeze({kind:'exact',path:'/api/prime/bridge/'+method,
  async handler(request,response) {
   if(!mounted){send(response,503,result('UNAVAILABLE','OWNER_MEMORY_BOUNDARY_UNMOUNTED'));return;}
   try {const rejection=connection.requestRejection(request);if(rejection!==undefined){send(response,[401,403].includes(rejection)?rejection:403,result('UNAUTHORIZED','CONNECTION_ACCESS_REFUSED'));return;}}
   catch{send(response,403,result('UNAUTHORIZED','CONNECTION_ACCESS_REFUSED'));return;}
   if(request.method!=='POST'){send(response,405,result('INVALID','POST_REQUIRED'));return;}
   let association;
   try {
    if(request.url!=='/api/prime/bridge/'+method)throw new TypeError('EXACT_ROUTE_REQUIRED');
    const host=request.headers.host,origin=request.headers.origin;
    if(typeof host!=='string'||typeof origin!=='string')throw new TypeError('ORIGIN_REQUIRED');
    const pin=guardRequest({host,origin});
    if(!pin||typeof pin!=='object'||Array.isArray(pin)||Object.keys(pin).sort().join(',')!=='origin,profile,rp_id'
      ||!['https','localhost-pilot-v1'].includes(pin.profile)||pin.origin!==origin||new URL(pin.origin).origin!==origin
      ||new URL(pin.origin).host!==host)throw new TypeError('EXACT_ORIGIN_REQUIRED');
    if(pin.profile==='localhost-pilot-v1'&&(pin.origin!=='http://localhost:18731'||pin.rp_id!=='localhost'))throw new TypeError('EXACT_PILOT_REQUIRED');
    if(pin.profile==='https'&&(new URL(origin).protocol!=='https:'||!(new URL(origin).hostname===pin.rp_id||new URL(origin).hostname.endsWith('.'+pin.rp_id))))throw new TypeError('EXACT_HTTPS_REQUIRED');
    if(!/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type']??''))throw new TypeError('JSON_REQUIRED');
    const length=request.headers['content-length'];
    if(length!==undefined&&(!/^(0|[1-9]\d{0,5})$/.test(length)||Number(length)>65536))throw new TypeError('BODY_BOUND');
    association=Object.freeze({transport:'http',request_id:randomUUID(),host,origin});
   } catch{send(response,400,result('INVALID','HTTP_ROUTE_OR_ORIGIN_REFUSED'));return;}
   if(inflight>=8){send(response,503,result('UNAVAILABLE','HTTP_INFLIGHT_BOUND'));return;}
   inflight++;let submitted=false,timer;
   try {
    const bytes=await requestBody(request,{maxBytes:65536,timeoutMs:5000});
    if(bytes[0]===0xef&&bytes[1]===0xbb&&bytes[2]===0xbf)throw new TypeError('INVALID_UTF8');
    const input=contracts.parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{maxBytes:65536,maxDepth:32});
    if(!input||typeof input!=='object'||Array.isArray(input))throw new TypeError('OBJECT_REQUIRED');
    // Role is host-chosen; never a body/header field. The existing public gate
    // owns acceptance. Do not abort or replay its mutation when HTTP disappears.
    submitted=true;
    timer=setTimeout(()=>send(response,504,result(reads.has(method)?'UNAVAILABLE':'OUTCOME_UNKNOWN','HTTP_REPLY_TIMEOUT')),5000);
    const reply=await publicBoundary.handlePublic(method,input,{request:association,role:reads.has(method)?'read_only':'owner_control'});
    const json=contracts.canonicalJson(reply);
    if(Buffer.byteLength(json)>65536||!reply||typeof reply.ok!=='boolean')throw new TypeError('BOUNDED_RESULT_REQUIRED');
    send(response,statusOf(reply),reply);
   } catch {send(response,submitted?504:400,result(submitted?(reads.has(method)?'UNAVAILABLE':'OUTCOME_UNKNOWN'):'INVALID',submitted?'BRIDGE_REPLY_UNAVAILABLE':'INVALID_BRIDGE_JSON'));}
   finally {clearTimeout(timer);inflight--;}
  }
 })));
}
