// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-only presentation binding. Authentication, exact review and effects
// remain in the configured host/authority path. This module creates no proof.
const absent=Object.freeze({state:'unavailable',mode:null,reason:'The host inference path is unavailable.'});
const fail=(code,reason)=>{throw Object.assign(new Error(reason),{code,error_code:code});};
const freeze=v=>{if(v&&typeof v==='object'){for(const x of Object.values(v))freeze(x);Object.freeze(v);}return v;};
export function createOwnerInferenceClient({controller,binding,context,contracts,isCurrentConnection,
 readAvailability,requestOne}={}){
 if(!controller||!binding||typeof controller.getSnapshot!=='function'||typeof controller.subscribe!=='function'
  ||typeof contracts?.parseStrictJson!=='function'||typeof contracts.canonicalJson!=='function'||typeof isCurrentConnection!=='function')
  fail('UNAVAILABLE','OWNER_INFERENCE_NATIVE_BINDING_REQUIRED');
 const copy=v=>freeze(contracts.parseStrictJson(contracts.canonicalJson(v),{maxBytes:262144,maxDepth:32}));
 const fixed=copy(context);
 if(Object.keys(fixed).sort().join(',')!=='conversation_id,owner_id,task_id'||Object.values(fixed).some(v=>typeof v!=='string'||!/^[A-Za-z0-9_.-]{1,128}$/.test(v))||binding.owner_id!==fixed.owner_id)
  fail('INVALID','OWNER_INFERENCE_CONTEXT');
 let disposed=false,availability=absent,revision=0,flight=null,observedOwner=null;
 const listeners=new Set(),attempts=new Set();
 // A presentation subscriber must not prevent withdrawal or another observer.
 const notify=()=>{for(const listener of [...listeners])try{listener();}catch{}};
 const connected=()=>{try{return !disposed&&isCurrentConnection(binding)===true;}catch{return false;}};
 const owner=()=>{const state=controller.getSnapshot(),v=state.owner;
  if(!connected()||state.authority_available!==true||!v||v.owner_id!==fixed.owner_id
   ||!Number.isFinite(Date.parse(v.expiry))||Date.parse(v.expiry)<=Date.now())return null;return v;};
 const invalidate=()=>{revision++;flight?.abort.abort();availability=absent;notify();};
 // Only a new actual authenticated owner lifetime schedules a read-only status
 // observation. It never requests a reply, signs, approves or recovers anything.
 const changed=()=>{const current=owner();if(current===observedOwner)return;observedOwner=current;invalidate();
  if(!current||typeof readAvailability!=='function'||typeof requestOne!=='function')return;
  const stamp=revision;
  void Promise.resolve().then(()=>readAvailability(current)).then(value=>{
   if(stamp!==revision||owner()!==current)return;
   if(value&&Object.keys(value).sort().join(',')==='mode,reason,state'&&value.state==='ready'&&value.mode==='production'
    &&typeof value.reason==='string'&&value.reason.length<=1024)availability=copy(value);
   notify();
  }).catch(()=>{/* Missing genuine services remain unavailable. */});
 };
 let off=controller.subscribe(changed);changed();
 const client=Object.freeze({binding,context:fixed,availability:Object.freeze({getSnapshot:()=>owner()===observedOwner&&owner()!==null?availability:absent,subscribe(listener){listeners.add(listener);return()=>listeners.delete(listener);}}),
  async requestOne(input,{signal}={}){
   const actor=owner(),draft=copy(input),stamp=revision;
   if(!actor||actor!==observedOwner||availability.state!=='ready'||typeof requestOne!=='function')fail('UNAVAILABLE','OWNER_INFERENCE_PATH_UNAVAILABLE');
   if(!draft||Object.getPrototypeOf(draft)!==Object.prototype||Object.keys(draft).sort().join(',')!=='request_uuid,text'||typeof draft.text!=='string'||!draft.text.trim()
    ||new TextEncoder().encode(draft.text).length>32768||typeof draft.request_uuid!=='string'
    ||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(draft.request_uuid))fail('INVALID','OWNER_INFERENCE_DRAFT');
   if(signal?.aborted)fail('UNAVAILABLE','OWNER_INFERENCE_WAIT_ABORTED');
   if(flight||attempts.has(draft.request_uuid))fail('RECONCILIATION_REQUIRED','OWNER_INFERENCE_ATTEMPT_RETAINED');
   if(attempts.size>=128)fail('UNAVAILABLE','OWNER_INFERENCE_ATTEMPT_BOUND');
   attempts.add(draft.request_uuid);
   const abort=new AbortController(),combined=signal?AbortSignal.any([signal,abort.signal]):abort.signal,f={abort};flight=f;
   try{let value;
    const result=await requestOne(draft,{signal:combined,owner:actor});
    try{value=copy(result);}catch{fail('OUTCOME_UNKNOWN','OWNER_INFERENCE_RESULT_UNREADABLE');}
    if(stamp!==revision||owner()!==actor||combined.aborted)fail('OUTCOME_UNKNOWN','OWNER_INFERENCE_REPLY_LIFETIME_CHANGED');
    if(!value||Object.getPrototypeOf(value)!==Object.prototype||value.request_uuid!==draft.request_uuid||value.receipt?.request_uuid!==draft.request_uuid||value.receipt.sessionId!==fixed.conversation_id
     ||!['completed','outcome_unknown'].includes(value.outcome))fail('OUTCOME_UNKNOWN','OWNER_INFERENCE_REPLY_BINDING_CHANGED');
    return value;
   }finally{if(flight===f)flight=null;abort.abort();}
  },
  dispose(){if(!disposed){disposed=true;invalidate();}listeners.clear();if(off){off();off=undefined;}}
 });
 return client;
}
export function mountOwnerInferenceClient(scope,options){
 const controller=scope?.primeOwnerUi,ack=scope?.primeOwnerNativeConnection,binding=scope?.primeAuthority;
 if(!controller||ack?.controller!==controller||typeof ack.isConnected!=='function'||!binding||ack.isConnected(binding)!==true
  ||typeof scope.reflect?.provide!=='function'||scope.primePilotInference!==undefined)fail('UNAVAILABLE','OWNER_INFERENCE_NATIVE_CONNECTION_REQUIRED');
 const client=createOwnerInferenceClient({...options,controller,binding,isCurrentConnection:value=>
  scope.primeOwnerUi===controller&&scope.primeOwnerNativeConnection===ack&&scope.primeAuthority===value&&ack.isConnected(value)===true});
 let disposed=false,remove;
 const dispose=()=>{disposed=true;const errors=[];
  try{client.dispose();}catch(error){errors.push(error);}
  if(remove)try{remove();remove=undefined;}catch(error){errors.push(error);}
  if(errors.length)throw new AggregateError(errors,'OWNER_INFERENCE_CLEANUP_FAILED');
 };
 try{const off=scope.reflect.provide('primePilotInference',Object.freeze({ownerController:controller,client}));
  if(typeof off!=='function')fail('UNAVAILABLE','OWNER_INFERENCE_DISPOSER_REQUIRED');remove=off;
  if(disposed)dispose();
 }catch(error){try{dispose();}catch{}throw error;}
 return Object.freeze({client,dispose});
}
