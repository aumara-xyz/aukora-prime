// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual native assembly, using B's controller/witness and the H helpers.
import {createOwnerMemoryNativeBinding} from './owner-memory-native.mjs';
import {mountOwnerInferenceClient} from './owner-inference-client.mjs';
// Observe existing C replies, then wait for B to accept the new owner lifetime.
// This creates neither an owner session nor a signer. Tokens remain private.
export function createAcceptedOwnerSessionObserver(controller,ownerId){
 let active=true,session=null,pending=null,revision=0;
 return Object.freeze({
  observeCall(method){if(method==='owner.logout'||method==='owner.loginChallenge'){session=null;pending=null;revision++;}
   return {stamp:revision,before:controller.getSnapshot().owner};},
  observeReply(method,_input,reply,observation){
   if(active&&observation?.stamp===revision&&method==='owner.loginComplete'&&reply?.ok===true&&reply.owner_id===ownerId
    &&typeof reply.expiry==='string'&&Number.isFinite(Date.parse(reply.expiry))&&Date.parse(reply.expiry)>Date.now()
    &&typeof reply.session_token==='string'&&/^[a-f0-9]{64}$/.test(reply.session_token))
    pending={token:reply.session_token,owner_id:reply.owner_id,expiry:reply.expiry,...observation};
  },
  forOwner(actor){
   const current=controller.getSnapshot().owner;
   if(pending&&current&&current!==pending.before&&pending.stamp===revision&&current.owner_id===pending.owner_id&&current.expiry===pending.expiry){
    session={actor:current,token:pending.token};pending=null;
   }
   return active&&actor&&current===actor&&session?.actor===actor&&Date.parse(actor.expiry)>Date.now()?session.token:null;
  },
  dispose(){active=false;session=null;pending=null;revision++;},
 });
}
export async function apply(scope){
 let active=true,native,inference,off,sessions;
 const controller=scope.primeOwnerUi;
 const cleanup=()=>{active=false;sessions?.dispose();const errors=[];
  if(off)try{off();off=undefined;}catch(error){errors.push(error);}
  try{inference?.dispose();}catch(error){errors.push(error);}
  try{native?.dispose();}catch(error){errors.push(error);}
  if(errors.length)throw new AggregateError(errors,'NATIVE_HOST_CLEANUP_FAILED');
 };
 // Register ownership before any await or synchronous controller notification.
 scope.effect(()=>cleanup,'prime native host lifetime');
 const contracts=await import('/prime/contracts/browser.mjs');if(!active)return;
 const read=async(url,options={})=>{const response=await fetch(url,{...options,credentials:'same-origin',redirect:'error',cache:'no-store'});
  const value=contracts.parseStrictJson(await response.text(),{maxBytes:262144,maxDepth:32});
  if(!response.ok||value?.ok===false)throw Object.assign(new Error('GENUINE_HOST_UNAVAILABLE'),{code:value?.error_code??'UNAVAILABLE'});return value;};
 let config;try{config=await read('/api/prime/host/bootstrap');}catch{return;}
 if(!active)return;
 if(Object.keys(config).sort().join(',')!=='context,ok,ownerBinding'||config.ok!==true)throw new TypeError('INVALID_HOST_BOOTSTRAP');
 sessions=createAcceptedOwnerSessionObserver(controller,config.ownerBinding.owner_id);
 const call=async(method,input,{signal,owner}={})=>{
  const token=sessions.forOwner(owner);
  if(!active||!token)throw Object.assign(new Error('OWNER_SESSION_UNAVAILABLE'),{code:'UNAVAILABLE'});
  return read('/api/prime/inference/'+method,{method:'POST',headers:{'content-type':'application/json'},body:contracts.canonicalJson({...input,session_token:token}),signal});
 };
 native=createOwnerMemoryNativeBinding(scope,{contracts,ownerBinding:config.ownerBinding,
  observeAuthorityCall:sessions.observeCall,observeAuthorityReply:sessions.observeReply});
 if(!active){native.dispose();return;}
 const attach=()=>{if(!active||inference)return;
  const ack=scope.primeOwnerNativeConnection,binding=scope.primeAuthority;
  if(ack?.controller!==controller||ack.isConnected(binding)!==true)return;
  native.attachAfterNativeConnection();
  inference=mountOwnerInferenceClient(scope,{contracts,context:config.context,
   readAvailability:owner=>call('status',{},{owner}),requestOne:(draft,{signal,owner})=>call('request-one',draft,{signal,owner})});
  if(!active){inference.dispose();return;}
  // Actual guarded observation; no capability is inferred from service presence.
  void read('/api/prime/capabilities').then(value=>{if(active)native.setCapabilities(value);}).catch(()=>{if(active)try{native.capabilitiesUnavailable();}catch{try{cleanup();}catch{}}});
 };
 off=controller.subscribe(()=>{queueMicrotask(()=>{if(active)try{attach();}catch{try{cleanup();}catch{}}});});
 if(!active){off();off=undefined;return;}
 try{attach();}catch(error){cleanup();throw error;}
}
