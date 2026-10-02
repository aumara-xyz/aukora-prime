// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit private composition. No configuration discovery, setup or activation.
import {existsSync} from 'node:fs';
import {types} from 'node:util';
import {createOwnerMemoryContext} from './owner-memory-context.mjs';
const packageRoot=new URL(existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/',import.meta.url);
const [contracts,{createAuthorityService},{createPrivateV2Memory},{createPrivateV2FileRetentionReader},
 {createPrivateV2Coordinator},{createRetainedRuntimeBridge,createTrustedTaskRegistry,RETAINED_JOURNAL_DESCRIPTORS},
 {createIpcServer,IPC_METHOD_ROLES}]=await Promise.all([
 import(new URL('contracts/src/runtime.mjs',packageRoot)),
 import(new URL('authority/src/index.mjs',packageRoot)),
 import(new URL('memory/src/private-v2-memory.mjs',packageRoot)),
 import(new URL('memory/src/private-v2-retention.mjs',packageRoot)),
 import(new URL('memory/src/private-v2-coordinator.mjs',packageRoot)),
 import(new URL('runtime-bridge/src/index.mjs',packageRoot)),
 import(new URL('runtime-bridge/src/ipc.mjs',packageRoot)),
]);
const cores=new WeakMap();
const refusal=reason=>({ok:false,error_code:'UNAVAILABLE',reason});
function record(value,keys){
 if(!value||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)throw new TypeError('INVALID: closed retained host configuration');
 const ds=Object.getOwnPropertyDescriptors(value);
 if(Reflect.ownKeys(ds).length!==keys.length||keys.some(key=>!ds[key]?.enumerable||!Object.hasOwn(ds[key],'value')))
  throw new TypeError('INVALID: closed retained host configuration');
 return Object.fromEntries(keys.map(key=>[key,ds[key].value]));
}
const detached=value=>contracts.parseStrictJson(contracts.canonicalJson(value),{maxBytes:8*1024*1024,maxDepth:64});

/** Successful construction transfers ownership of the caller's real Pool.
 * publisher must already be
 * an authenticated private transport to the separately owned D file publisher.
 * No returned status, transport reply or constructor establishes qualification.
 */
export function createRetainedMemoryComposition(input){
 const config=record(input,['pool','retention','publisher','authorityConfig','registryEntries','bindings','closureProfile']);
 if(typeof config.pool?.query!=='function'||typeof config.pool?.connect!=='function'||typeof config.pool?.end!=='function')
  throw new TypeError('UNAVAILABLE: owned PostgreSQL Pool required');
 const profile=detached(config.closureProfile);
 const retention=detached(record(config.retention,['directory','publisher_uid','retention_gid','reader_uid']));
 const authorityConfig=detached(config.authorityConfig);
 for(const key of ['authorizeTask','observeTarget','retainedMemoryParticipant','provisionTrustedState'])
  if(Object.hasOwn(authorityConfig,key))throw new TypeError('INVALID: retained host owns authority binding; setup is separate');
 if(authorityConfig.audience!=='aukora-prime.memory'||authorityConfig.closureProfile?.version!==2
  ||authorityConfig.closureProfile.kind!=='prime-authority-closure-retention/v2'
  ||authorityConfig.closureProfile.expected_store_id!==profile.expected_authority_store_id)
  throw new TypeError('INVALID: protected C/D store profile mismatch');
 const taskRegistry=createTrustedTaskRegistry(detached(config.registryEntries));
 const resolveHostContext=createOwnerMemoryContext({taskRegistry,bindings:config.bindings});
 const reader=createPrivateV2FileRetentionReader({...retention,contracts,profile});
 const coordinator=createPrivateV2Coordinator({reader,publisher:config.publisher,profile,contracts});
 let authority,active=true,closing;
 // These own methods become actual C calls after the construction cycle closes.
 // They never supply permits, discover another service or fall back to v1.
 const retainedAuthority=Object.freeze(Object.fromEntries(
  ['reserveRetained','claimDispatchRetained','settleMemoryRetained','markOutcomeUnknown'].map(name=>[name,input=>{
   if(!authority||!active)return refusal('RETAINED_AUTHORITY_UNAVAILABLE');
   return authority[name](input);
  }])));
 const memory=createPrivateV2Memory({pool:config.pool,coordinator,profile,contracts,
  statements:RETAINED_JOURNAL_DESCRIPTORS,authority:retainedAuthority});
 authority=createAuthorityService({...authorityConfig,authorizeTask:taskRegistry.authorizeTask,
  observeTarget:operation=>memory.authorityTargetObservation(operation),
  retainedMemoryParticipant:memory.retainedMemoryParticipant});
 // Bridge captures D's genuine journal/recovery participant and coordinator
 // before narrowing its public facade. The C phase participant is a different
 // genuine object from that same D module instance, never an RPC proxy brand.
 const bridge=createRetainedRuntimeBridge({authority,memory,closureProfile:profile,taskRegistry,resolveHostContext});
 const flights=new Set();let accepting=true;
 const dispatch=(method,input,context)=>{
  if(!accepting)return Promise.resolve(refusal('RETAINED_HOST_DISPOSED'));
  // Detach the exact IPC input/context before the first wait. This private
  // association comes from the authenticated server, never a browser request.
  const request=detached(input),association=context===undefined?undefined:detached(context);
  const call=Promise.resolve().then(()=>accepting?bridge.handleTrusted(method,request,association):refusal('RETAINED_HOST_DISPOSED'));
  flights.add(call);call.then(()=>flights.delete(call),()=>flights.delete(call));return call;
 };
 const withdraw=()=>{accepting=false;};
 const ownership={withdraw,dispatch,canStart:()=>accepting&&!closing,boundaryStarted:false,boundaryStart:null};
 const core=Object.freeze({handlePrivate:dispatch,
  status:()=>Object.freeze({kind:'prime-retained-memory-source-composition/v1',qualification:'UNPERFORMED',
   public_routes:'unavailable',restore:'unavailable',accepting_private_calls:accepting}),
  close(){
   withdraw();
   if(!closing)closing=(async()=>{
    const errors=[];let boundary;
    // A start admitted before withdrawal remains owned until it actually
    // settles. No close path can leave its eventual listener behind.
    try{boundary=await ownership.boundaryStart;}catch{/* Start caller retains its original error. */}
    if(boundary)try{await boundary.close();}catch(error){errors.push(error);}
    // Keep C forwards alive for already admitted work through D final owner
    // inspection/unlock and actual C settlement. Transport timeout is not drain.
    await Promise.allSettled([...flights]);active=false;
    try{await config.pool.end();}catch(error){errors.push(error);}
    if(errors.length)throw new AggregateError(errors,'RETAINED_HOST_CLEANUP_FAILED');
   })();
   return closing;
  }});
 cores.set(core,ownership);return core;
}

/** Operator-invoked private app boundary, using the original authenticated IPC
 * implementation and its unchanged closed method/role profile. Not mounted by
 * the default composition. Credentials and socket custody are external inputs.
 */
export async function startRetainedMemoryIpc(input){
 const {composition,ipc}=record(input,['composition','ipc']);
 const owned=cores.get(composition);
 if(!owned||!owned.canStart()||owned.boundaryStarted)throw new TypeError('INVALID: one live owned retained boundary required');
 owned.boundaryStarted=true;
 try{
  owned.boundaryStart=createIpcServer({...detached(ipc),handlePublic(method,input,context){
   if(!Object.hasOwn(IPC_METHOD_ROLES,method)||!IPC_METHOD_ROLES[method].includes(context?.role))
    return {ok:false,error_code:'UNAUTHORIZED',reason:'RETAINED_HOST_PRIVATE_METHOD_REFUSED'};
   return owned.dispatch(method,input,context);
  }});
  await owned.boundaryStart;
  if(!owned.canStart()){
   await composition.close();
   throw new TypeError('UNAVAILABLE: retained boundary start withdrawn');
  }
 }catch(error){
  owned.withdraw();
  try{await composition.close();}catch(cleanup){throw new AggregateError([error,cleanup],'RETAINED_HOST_STARTUP_CLEANUP_FAILED');}
  throw error;
 }
 return Object.freeze({status:composition.status,close:()=>composition.close()});
}
