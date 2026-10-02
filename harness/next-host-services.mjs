// SPDX-License-Identifier: AGPL-3.0-or-later
// Optional genuine host services. The default composition provisions none.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {mountOwnerMemoryHost} from './owner-memory-host.mjs';
import {validateInferenceContext,validateInferenceDraft} from './owner-inference-producer.mjs';
const refused=(code,reason)=>({ok:false,error_code:code,reason});
const codeOf=e=>['INVALID','UNAUTHORIZED','UNAVAILABLE','OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED'].includes(e?.error_code)?e.error_code:'UNAVAILABLE';
export function validateBrowserBinding(value){
 if(!value||Object.keys(value).sort().join(',')!=='context,ownerBinding'
  ||!value.ownerBinding||Object.keys(value.ownerBinding).sort().join(',')!=='owner_id,passkeyProfile')throw new TypeError('INVALID_HOST_BOOTSTRAP');
 validateInferenceContext(value.context);
 if(value.ownerBinding.owner_id!==value.context.owner_id)throw new TypeError('INVALID_HOST_OWNER_CONTEXT');
 const profile=value.ownerBinding.passkeyProfile;
 if(!profile||Object.keys(profile).sort().join(',')!=='origin,profile,rp_id')throw new TypeError('INVALID_HOST_PASSKEY_PROFILE');
 const url=new URL(profile.origin);
 if(url.origin!==profile.origin||url.username||url.password||typeof profile.rp_id!=='string'
  ||!/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(profile.rp_id))throw new TypeError('INVALID_HOST_PASSKEY_PROFILE');
 if(profile.profile==='localhost-pilot-v1'){
  if(profile.origin!=='http://localhost:18731'||profile.rp_id!=='localhost')throw new TypeError('INVALID_HOST_PASSKEY_PROFILE');
 }else if(profile.profile!=='https'||url.protocol!=='https:'||!profile.rp_id.includes('.')
  ||/^[0-9.]+$/.test(profile.rp_id)||url.hostname!==profile.rp_id&&!url.hostname.endsWith('.'+profile.rp_id))throw new TypeError('INVALID_HOST_PASSKEY_PROFILE');
 return value;
}
export const HOST_BROWSER_MODULES=Object.freeze([
 'harness/native-host-client.mjs','harness/owner-memory-native.mjs','harness/owner-memory-client.mjs',
 'harness/owner-memory-browser.mjs','harness/owner-inference-client.mjs',
 'prime-packages/runtime-bridge/src/ui-adapter.mjs','prime-packages/runtime-bridge/src/owner-memory-workflow.mjs',
 'prime-packages/runtime-bridge/src/owner-forget-workflow.mjs','prime-packages/memory/src/capture-review.mjs',
 'prime-packages/contracts/src/browser.mjs','prime-packages/contracts/src/shared.mjs','prime-packages/contracts/src/json.mjs',
]);
export function createNextHostRoutes({root,contracts,connection,getServices=()=>undefined}={}){
 const send=(res,status,value)=>{res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'});res.end(contracts.canonicalJson(value));};
 const guard=work=>async(req,res)=>{const reject=connection?.requestRejection?.(req);
  if(typeof connection?.requestRejection!=='function'||reject!==undefined){res.writeHead(reject??403);res.end();return;}await work(req,res);};
 const routes=HOST_BROWSER_MODULES.map(path=>({kind:'exact',path:'/prime/'+path,handler:guard((req,res)=>{
  if(!['GET','HEAD'].includes(req.method)){send(res,405,refused('INVALID','HOST_MODULE_METHOD'));return;}
  const bytes=readFileSync(resolve(root,path));res.writeHead(200,{'content-type':'text/javascript; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(req.method==='HEAD'?undefined:bytes);
 })}));
 routes.push({kind:'exact',path:'/api/prime/host/bootstrap',handler:guard((req,res)=>{
  if(req.method!=='GET'){send(res,405,refused('INVALID','HOST_BOOTSTRAP_METHOD'));return;}
  const selected=getServices()?.browserBinding;
  if(!selected){send(res,503,refused('UNAVAILABLE','GENUINE_HOST_BINDING_UNMOUNTED'));return;}
  // A nonsecret host identity/profile is not an owner login or qualification.
  try{const value=validateBrowserBinding(contracts.parseStrictJson(contracts.canonicalJson(selected),{maxBytes:4096,maxDepth:8}));send(res,200,{ok:true,...value});}
  catch{send(res,503,refused('UNAVAILABLE','GENUINE_HOST_BINDING_INVALID'));}
 })});
 for(const method of ['status','request-one'])routes.push({kind:'exact',path:'/api/prime/inference/'+method,handler:guard(async(req,res)=>{
  const runtime=getServices()?.inference;
  // Refuse missing genuine services BEFORE body read. Preview cookies alone
  // never authenticate an owner; C must verify the opaque session independently.
  if(!runtime?.producer||typeof runtime.authenticateOwner!=='function'||typeof runtime.guardRequest!=='function'){
   send(res,503,refused('UNAVAILABLE','GENUINE_INFERENCE_HOST_UNMOUNTED'));return;
  }
  if(req.method!=='POST'){send(res,405,refused('INVALID','OWNER_INFERENCE_METHOD'));return;}
  const abort=new AbortController();let timer;
  // Own cancellation before body/admission awaits: a close during owner
  // authentication must not begin a provider attempt when that wait resolves.
  const closed=()=>abort.abort();res.on('close',closed);
  const requireOpen=()=>{if(abort.signal.aborted||res.closed||res.destroyed||res.writableEnded){
   abort.abort();throw Object.assign(new Error(),{error_code:'UNAVAILABLE'});
  }};
  try{
   requireOpen();
   const profile=runtime.guardRequest({host:req.headers.host??'',origin:req.headers.origin??''});
   if(!profile||profile.origin!==req.headers.origin||new URL(profile.origin).host!==req.headers.host)throw Object.assign(new Error(),{error_code:'UNAUTHORIZED'});
   if(!/^application\/json(?:\s*;.*)?$/i.test(req.headers['content-type']??''))throw Object.assign(new Error(),{error_code:'INVALID'});
   let size=0;const chunks=[];
   timer=setTimeout(()=>{abort.abort();req.destroy();},5000);
   for await(const chunk of req){size+=chunk.length;if(size>65536)throw Object.assign(new Error(),{error_code:'INVALID'});chunks.push(Buffer.from(chunk));}
   clearTimeout(timer);
   const raw=Buffer.concat(chunks);let text;
   try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw);}
   catch{throw Object.assign(new Error(),{error_code:'INVALID'});}
   const input=contracts.parseStrictJson(text,{maxBytes:65536,maxDepth:16});
   const expected=method==='status'?'session_token':'request_uuid,session_token,text';
   if(!input||Object.getPrototypeOf(input)!==Object.prototype||Object.keys(input).sort().join(',')!==expected
    ||typeof input.session_token!=='string'||!/^[a-f0-9]{64}$/.test(input.session_token))throw Object.assign(new Error(),{error_code:'INVALID'});
   requireOpen();
   const owner=await runtime.authenticateOwner({session_token:input.session_token});
   requireOpen();
   if(getServices()?.inference!==runtime)throw Object.assign(new Error(),{error_code:'UNAVAILABLE'});
   if(owner?.owner_id!==runtime.producer.context?.owner_id||!Number.isFinite(Date.parse(owner.expiry))||Date.parse(owner.expiry)<=Date.now())throw Object.assign(new Error(),{error_code:'UNAUTHORIZED'});
   if(method==='status'){const observed=await runtime.producer.status(owner);
    requireOpen();if(getServices()?.inference!==runtime)throw Object.assign(new Error(),{error_code:'UNAVAILABLE'});send(res,200,observed);return;}
   const draft=validateInferenceDraft({request_uuid:input.request_uuid,text:input.text});
   // Waiting/cancellation is not proof of provider cancellation. The existing
   // producer/C/E path owns the attempt, reservation and factual uncertainty.
   requireOpen();
   const result=await runtime.producer.requestOne(draft,{signal:abort.signal,owner,isCurrent:()=>getServices()?.inference===runtime});
    if(getServices()?.inference!==runtime||abort.signal.aborted)throw Object.assign(new Error(),{error_code:'OUTCOME_UNKNOWN'});
    let confirmed;
    try{confirmed=await runtime.authenticateOwner({session_token:input.session_token});}
    catch{throw Object.assign(new Error(),{error_code:'OUTCOME_UNKNOWN'});}
    if(getServices()?.inference!==runtime||confirmed?.owner_id!==owner.owner_id||confirmed.expiry!==owner.expiry
     ||Date.parse(confirmed.expiry)<=Date.now())throw Object.assign(new Error(),{error_code:'OUTCOME_UNKNOWN'});
    if(!abort.signal.aborted&&!res.closed&&!res.destroyed&&!res.writableEnded)send(res,200,result);
  }catch(error){if(!abort.signal.aborted&&!res.closed&&!res.destroyed&&!res.writableEnded){const code=codeOf(error);send(res,code==='INVALID'?400:code==='UNAUTHORIZED'?401:503,refused(code,'OWNER_INFERENCE_REPLY_UNAVAILABLE'));}}
  finally{clearTimeout(timer);res.removeListener('close',closed);}
 })});
 return Object.freeze(routes);
}
export function mountNextHostServices({webServer,connection,contracts,services}={}){
 const removers=[];
 try{
  if(services?.ownerMemory)removers.push(mountOwnerMemoryHost({...services.ownerMemory,webServer:{register:route=>webServer.register({...route,handler:async(req,res)=>{
   const reject=connection.requestRejection(req);if(reject!==undefined){res.writeHead(reject);res.end();return;}return route.handler(req,res);
  }})},connection,contracts}));
 }catch(error){for(const remove of removers.reverse())remove();throw error;}
 return ()=>{const errors=[];for(let i=removers.length-1;i>=0;i--)try{removers[i]();removers.splice(i,1);}catch(error){errors.push(error);}if(errors.length)throw new AggregateError(errors,'NEXT_HOST_CLEANUP_FAILED');};
}
