// SPDX-License-Identifier: AGPL-3.0-or-later
import {existsSync} from 'node:fs';
// Same fixed own-root layout selection as the Prime CLI. No repository, PATH,
// environment or external package discovery; a composed release never falls back.
const packageRoot=new URL(existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/',import.meta.url);
const [{canonicalJson},{createTrustedTaskRegistry},{MAX_BYTES,parseOriginal,sha256},{CAPTURE_ATTRIBUTIONS},{CONTROLS}]=await Promise.all([
  import(new URL('contracts/src/runtime.mjs',packageRoot).href),
  import(new URL('runtime-bridge/src/registry.mjs',packageRoot).href),
  import(new URL('memory/src/codecs.mjs',packageRoot).href),
  import(new URL('memory/src/capture-review.mjs',packageRoot).href),
  import(new URL('memory/genesis/plugins/aukora-kira/lib/memory-forget.mjs',packageRoot).href),
]);

const refuse=(error_code,reason)=>{throw Object.assign(new Error(reason),{error_code,reason});};
const invalid=reason=>refuse('INVALID',reason);
const text=value=>typeof value==='string'&&value.length>0&&value.length<=4096;
const subject=value=>typeof value==='string'&&/^aukora:1:[a-f0-9]{64}$/.test(value);
const id=value=>typeof value==='string'&&/^[a-zA-Z0-9_.-]{1,128}$/.test(value);
const typedArray=Object.getPrototypeOf(Uint8Array.prototype);
const intrinsicBytes=Object.getOwnPropertyDescriptor(typedArray,'byteLength').get;
const intrinsicBuffer=Object.getOwnPropertyDescriptor(typedArray,'buffer').get;
const intrinsicOffset=Object.getOwnPropertyDescriptor(typedArray,'byteOffset').get;
const record=(value,required,optional=[])=>{
  if(!value||Object.getPrototypeOf(value)!==Object.prototype)invalid('OWNER_MEMORY_CLOSED_RECORD_REQUIRED');
  const keys=Reflect.ownKeys(value),allowed=[...required,...optional];
  if(required.some(key=>!Object.hasOwn(value,key))||keys.some(key=>typeof key!=='string'||!allowed.includes(key)))invalid('OWNER_MEMORY_CLOSED_FIELDS_REQUIRED');
  for(const key of keys){const d=Object.getOwnPropertyDescriptor(value,key);if(!d.enumerable||!Object.hasOwn(d,'value'))invalid('OWNER_MEMORY_DATA_FIELDS_REQUIRED');}
};
function data(value,ancestors=new Set(),depth=0){
  if(depth>64)invalid('OWNER_MEMORY_DATA_DEPTH');
  if(value===null||typeof value==='boolean')return;
  if(typeof value==='string'){if(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value))invalid('OWNER_MEMORY_TEXT_INVALID');return;}
  if(typeof value==='number'){if(!Number.isFinite(value)||(Number.isInteger(value)&&!Number.isSafeInteger(value)))invalid('OWNER_MEMORY_NUMBER_INVALID');return;}
  if(!value||typeof value!=='object'||ancestors.has(value))invalid('OWNER_MEMORY_DATA_REQUIRED');
  ancestors.add(value);
  if(Array.isArray(value)){
    if(Reflect.ownKeys(value).length!==value.length+1)invalid('OWNER_MEMORY_DENSE_ARRAY_REQUIRED');
    for(let i=0;i<value.length;i++){const d=Object.getOwnPropertyDescriptor(value,String(i));if(!d?.enumerable||!Object.hasOwn(d,'value'))invalid('OWNER_MEMORY_DATA_FIELDS_REQUIRED');data(d.value,ancestors,depth+1);}
  }else{
    if(Object.getPrototypeOf(value)!==Object.prototype)invalid('OWNER_MEMORY_PLAIN_DATA_REQUIRED');
    for(const key of Reflect.ownKeys(value)){const d=Object.getOwnPropertyDescriptor(value,key);if(typeof key!=='string'||!d.enumerable||!Object.hasOwn(d,'value'))invalid('OWNER_MEMORY_DATA_FIELDS_REQUIRED');data(key,ancestors,depth+1);data(d.value,ancestors,depth+1);}
  }
  ancestors.delete(value);
}
function freeze(value){
  // Event buffers are private snapshots. Nonempty typed arrays cannot be frozen;
  // no reference to these stored buffers is returned to a caller.
  if(value instanceof Uint8Array)return value;
  if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}
  return value;
}
function capture(host,ownerId,taskId){
  record(host,['owner_subject','privacy','scope','attributedTo','source','events'],
    ['owner_id','task_id','origin','bodyAtCapture','controls','evidence','paused','offTheRecord','permittedPrivacy','permittedScopes']);
  if(!subject(host.owner_subject)||host.privacy!=='local'||!text(host.scope)||!CAPTURE_ATTRIBUTIONS.includes(host.attributedTo)
    ||host.owner_id!==undefined&&host.owner_id!==ownerId||host.task_id!==undefined&&host.task_id!==taskId)invalid('OWNER_MEMORY_CAPTURE_BINDING_INVALID');
  record(host.source,['sessionId','seq','at','sha256'],['sessionTitle','span']);
  const source=host.source;
  if(!text(source.sessionId)||!Number.isSafeInteger(source.seq)||source.seq<0||typeof source.at!=='string'
    ||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(source.at)||!Number.isFinite(Date.parse(source.at))
    ||new Date(source.at).toISOString()!==source.at.slice(0,-1)+'.000Z'||!/^[a-f0-9]{64}$/.test(source.sha256)
    ||source.sessionTitle!==undefined&&typeof source.sessionTitle!=='string')invalid('OWNER_MEMORY_SOURCE_INVALID');
  if(source.span!==undefined){
    record(source.span,['start','end','unit','total']);const {start,end,unit,total}=source.span;
    if(unit!=='utf16'||!Number.isSafeInteger(start)||start<0||!Number.isSafeInteger(end)||end<start||!Number.isSafeInteger(total)||total<end)invalid('OWNER_MEMORY_SOURCE_SPAN_INVALID');
  }
  if(!Array.isArray(host.events)||host.events.length===0||Reflect.ownKeys(host.events).length!==host.events.length+1)invalid('OWNER_MEMORY_EVENT_BYTES_REQUIRED');
  let size=0,sourceFound=false;const capturedEvents=[];
  for(let i=0;i<host.events.length;i++){
    const d=Object.getOwnPropertyDescriptor(host.events,String(i));
    if(!d?.enumerable||!Object.hasOwn(d,'value'))invalid('OWNER_MEMORY_DATA_FIELDS_REQUIRED');
    const input=d.value;
    if(!ArrayBuffer.isView(input)||!(input instanceof Uint8Array))invalid('OWNER_MEMORY_EVENT_BYTES_REQUIRED');
    // Own properties can shadow .buffer/.byteLength/.byteOffset. Read internal
    // slots and copy ordinary backing storage before parsing or retaining bytes.
    const length=intrinsicBytes.call(input),buffer=intrinsicBuffer.call(input),offset=intrinsicOffset.call(input);
    if(length===0||(size+=length)>MAX_BYTES||!(buffer instanceof ArrayBuffer))invalid('OWNER_MEMORY_EVENT_BYTES_REQUIRED');
    const bytes=new Uint8Array(new Uint8Array(buffer,offset,length));capturedEvents.push(bytes);
    // This is D's exact-byte parser/digest, including duplicate-key and UTF-8 checks.
    const event=parseOriginal(bytes);
    if(sha256(bytes)===source.sha256){if(typeof event.text!=='string'||event.text.length===0)invalid('OWNER_MEMORY_SOURCE_TEXT_REQUIRED');sourceFound=true;}
  }
  if(!sourceFound)invalid('OWNER_MEMORY_SOURCE_BYTES_MISMATCH');
  for(const key of Object.keys(host))if(key!=='events')data(host[key]);
  for(const key of ['paused','offTheRecord'])if(host[key]!==undefined&&typeof host[key]!=='boolean')invalid('OWNER_MEMORY_CONTROL_INVALID');
  if(host.controls!==undefined){
    record(host.controls,[],Object.keys(CONTROLS));
    if(Object.values(host.controls).some(value=>typeof value!=='boolean'))invalid('OWNER_MEMORY_CONTROL_INVALID');
  }
  if(host.permittedPrivacy!==undefined&&(!Array.isArray(host.permittedPrivacy)||host.permittedPrivacy.length===0
    ||host.permittedPrivacy.some(value=>!['local','private','exportable'].includes(value))))invalid('OWNER_MEMORY_READ_POLICY_INVALID');
  if(host.permittedScopes!==undefined&&(!Array.isArray(host.permittedScopes)||host.permittedScopes.length===0
    ||host.permittedScopes.some(value=>!text(value))))invalid('OWNER_MEMORY_READ_POLICY_INVALID');
  return capturedEvents;
}

/** Trusted worker configuration only. The request below comes from createIpcServer
 * after channel authentication; this resolver does not authenticate an arbitrary
 * request object or owner session itself. Bindings contain exact captured events,
 * not an extraction or a guest-controlled source. No listener or setup is created. */
export function createOwnerMemoryContext({taskRegistry,bindings=[]}={}){
  if(!Array.isArray(bindings)||Reflect.ownKeys(bindings).length!==bindings.length+1)invalid('OWNER_MEMORY_BINDINGS_REQUIRED');
  if(bindings.length&&(!taskRegistry||typeof taskRegistry.getOwned!=='function'||typeof taskRegistry.authorizeTask!=='function'))invalid('OWNER_MEMORY_TRUSTED_REGISTRY_REQUIRED');
  const getOwned=taskRegistry?.getOwned?.bind(taskRegistry),pins=new Map(),subjects=new Map(),owners=new Map();
  for(let i=0;i<bindings.length;i++){
    const d=Object.getOwnPropertyDescriptor(bindings,String(i));if(!d?.enumerable||!Object.hasOwn(d,'value'))invalid('OWNER_MEMORY_DATA_FIELDS_REQUIRED');
    const binding=d.value;
    record(binding,['credential_id','owner_id','task_id','memory_host']);
    if(!id(binding.credential_id)||!text(binding.owner_id)||!text(binding.task_id)||pins.has(binding.credential_id))invalid('OWNER_MEMORY_BINDING_INVALID');
    const events=capture(binding.memory_host,binding.owner_id,binding.task_id);
    const entry=getOwned(binding.task_id,binding.owner_id);
    if(!entry||!createTrustedTaskRegistry([entry]).getOwned(binding.task_id,binding.owner_id))invalid('OWNER_MEMORY_ACTIVE_OWNED_TASK_REQUIRED');
    if(subjects.has(binding.memory_host.owner_subject)&&subjects.get(binding.memory_host.owner_subject)!==binding.owner_id
      ||owners.has(binding.owner_id)&&owners.get(binding.owner_id)!==binding.memory_host.owner_subject)invalid('OWNER_MEMORY_DISTINCT_OWNER_BINDING_REQUIRED');
    subjects.set(binding.memory_host.owner_subject,binding.owner_id);owners.set(binding.owner_id,binding.memory_host.owner_subject);
    const pin=freeze(structuredClone({...binding,memory_host:{...binding.memory_host,events}}));
    pins.set(pin.credential_id,{binding:pin,task:canonicalJson(entry)});
  }
  return Object.freeze(function resolveHostContext(input){
    if(pins.size===0)refuse('UNAVAILABLE','OWNER_MEMORY_CONTEXT_UNMOUNTED');
    record(input,['request','session']);record(input.request,['transport','credential_id']);
    if(input.request.transport!=='ipc'||!id(input.request.credential_id))refuse('UNAUTHORIZED','OWNER_MEMORY_AUTHENTICATED_CHANNEL_REQUIRED');
    const pin=pins.get(input.request.credential_id);
    if(!pin)refuse('UNAUTHORIZED','OWNER_MEMORY_CHANNEL_UNBOUND');
    const binding=pin.binding;
    if(input.session===null)return {login_owner_id:binding.owner_id};
    record(input.session,['ok','owner_id','subject','authorization_epoch','expiry']);
    const session=input.session;
    if(session.ok!==true||session.owner_id!==binding.owner_id||session.subject!==binding.memory_host.owner_subject
      ||!Number.isSafeInteger(session.authorization_epoch)||session.authorization_epoch<0||typeof session.expiry!=='string'
      ||!Number.isFinite(Date.parse(session.expiry))||Date.parse(session.expiry)<=Date.now())refuse('UNAUTHORIZED','OWNER_MEMORY_VERIFIED_SESSION_MISMATCH');
    const entry=getOwned(binding.task_id,binding.owner_id);
    if(!entry||canonicalJson(entry)!==pin.task)refuse('UNAUTHORIZED','OWNER_MEMORY_PINNED_TASK_CHANGED');
    return {task_id:binding.task_id,memory_host:structuredClone(binding.memory_host)};
  });
}
