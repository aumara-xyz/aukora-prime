// SPDX-License-Identifier: AGPL-3.0-or-later
// Host presentation producer over the existing E adapter/ledger. No provider,
// authority, credential store, budget, signer or recovery loop is created here.
import {existsSync} from 'node:fs';
const owned=existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/';
const contracts=await import(new URL(owned+'contracts/src/runtime.mjs',import.meta.url));
const {createDshAdapter}=await import(new URL(owned+'inference/src/dsh-adapter.mjs',import.meta.url));
const {prepareRequest}=await import(new URL(owned+'inference/src/policy.mjs',import.meta.url));
const failure=(code,reason)=>Object.assign(new Error(reason),{code,error_code:code});
const unavailable=Object.freeze({state:'unavailable',mode:null,reason:'Genuine owner, review, route and separated provider services are not configured.'});
const detach=value=>contracts.parseStrictJson(contracts.canonicalJson(value),{maxBytes:262144,maxDepth:32});
const freeze=v=>{if(v&&typeof v==='object'){for(const x of Object.values(v))freeze(x);Object.freeze(v);}return v;};
const closed=(v,keys)=>{if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).sort().join(',')!==[...keys].sort().join(','))throw failure('INVALID','OWNER_INFERENCE_FIELDS');};
export function validateInferenceContext(input){
 const v=detach(input);closed(v,['owner_id','task_id','conversation_id']);
 if(!Object.values(v).every(x=>typeof x==='string'&&/^[A-Za-z0-9_.-]{1,128}$/.test(x)))throw failure('INVALID','OWNER_INFERENCE_CONTEXT');
 return Object.freeze(v);
}
export function validateInferenceDraft(input){
 const v=detach(input);closed(v,['request_uuid','text']);
 if(typeof v.request_uuid!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v.request_uuid)
  ||typeof v.text!=='string'||!v.text.trim()||Buffer.byteLength(v.text)>32768)throw failure('INVALID','OWNER_INFERENCE_DRAFT');
 return Object.freeze(v);
}

/** resolveRequest belongs to the authenticated host and existing exact review
 * path. It must return the original selected request/options, never a guest
 * route/policy/cap. observeAvailability is E's actual owner settings status.
 * Neither this constructor nor an availability read approves or reserves work. */
export function createDshOwnerInferenceProducer(scope,{context,gateway,ledger,LlmAdapter,
 resolveRequest,observeAvailability,attributionHeaders}={}){
 const fixed=context===undefined?null:validateInferenceContext(context);
 let disposed=false,flight=null,removeAdapter;
 const attempts=new Set();
 const configured=!!fixed&&typeof scope?.llm?.registerAdapter==='function'&&typeof scope.llm.stream==='function'
  &&typeof LlmAdapter==='function'&&typeof gateway?.generate==='function'&&gateway.ledger===ledger
  &&typeof ledger?.get==='function'&&typeof resolveRequest==='function'
  &&typeof observeAvailability==='function'&&typeof attributionHeaders==='function';
 const current=()=>{if(disposed||!configured||flight&&flight.isCurrent()!==true)throw failure('UNAVAILABLE','OWNER_INFERENCE_UNMOUNTED');};
 if(configured){
  // Own exactly one existing adapter. No second agent loop or direct provider call.
  const projection=Object.freeze({route:gateway.route,async generate(request,options){
   current();const f=flight;if(!f||!f.bound||f.generated||options.signal!==f.signal||f.signal.aborted
    ||contracts.canonicalJson(request)!==f.requestCanonical)throw failure('UNAVAILABLE','OWNER_INFERENCE_REQUEST_UNBOUND');
   f.generated=true;
   const result=await gateway.generate(request,options);f.result=freeze(detach(result));return result;
  }});
  const adapter=createDshAdapter(LlmAdapter,{gateway:projection,attributionHeaders,bindRequest(options){
   current();const f=flight;
   if(!f||f.bound||options.signal!==f.signal||f.signal.aborted||options.provider!==f.options.provider||options.model!==f.options.model
    ||options.sessionId!==fixed.conversation_id||options.maxTokens!==f.request.max_output_tokens
    ||options.tools?.length||contracts.canonicalJson(options.messages)!==f.messagesCanonical)
    throw failure('UNAUTHORIZED','OWNER_INFERENCE_STREAM_BINDING_CHANGED');
   f.bound=true;
   return detach(f.request);
  }});
  removeAdapter=scope.llm.registerAdapter(['externalDeepSeek'],adapter);
  if(typeof removeAdapter!=='function')throw failure('UNAVAILABLE','OWNER_INFERENCE_ADAPTER_DISPOSER_REQUIRED');
 }
 async function status(owner){
  if(disposed||!configured)return unavailable;
  const row=await observeAvailability(owner);current();
  // This is a projection of existing E readiness, not a new qualification gate.
  if(row?.paid_requests_enabled!==true||row.config_digest!==gateway.route.config_digest
   ||row.credential?.configured!==true||row.credential.generation!==gateway.route.credential_generation
   ||gateway.route.mode!=='production'||gateway.provider?.mode!=='production')return unavailable;
  return Object.freeze({state:'ready',mode:'production',reason:'The configured host reports the existing qualified owner/provider path.'});
 }
 return Object.freeze({context:fixed,status,
  async requestOne(input,{signal,owner,isCurrent=()=>!disposed}={}){
   current();const draft=validateInferenceDraft(input);
   if(signal?.aborted)throw failure('UNAVAILABLE','OWNER_INFERENCE_WAIT_ABORTED');
   if(owner?.owner_id!==fixed.owner_id||typeof owner.expiry!=='string'||!Number.isFinite(Date.parse(owner.expiry))||Date.parse(owner.expiry)<=Date.now())throw failure('UNAUTHORIZED','OWNER_INFERENCE_OWNER_REQUIRED');
   if(typeof isCurrent!=='function'||isCurrent()!==true)throw failure('UNAVAILABLE','OWNER_INFERENCE_HOST_WITHDRAWN');
   if(flight||attempts.has(draft.request_uuid)||ledger.get(fixed.owner_id,fixed.task_id,draft.request_uuid))throw failure('RECONCILIATION_REQUIRED','OWNER_INFERENCE_ATTEMPT_RETAINED');
   if((await status(owner)).state!=='ready')throw failure('UNAVAILABLE','OWNER_INFERENCE_PATH_UNAVAILABLE');
   current();if(isCurrent()!==true)throw failure('UNAVAILABLE','OWNER_INFERENCE_HOST_WITHDRAWN');
   if(flight||attempts.has(draft.request_uuid)||ledger.get(fixed.owner_id,fixed.task_id,draft.request_uuid)||signal?.aborted)throw failure('RECONCILIATION_REQUIRED','OWNER_INFERENCE_ATTEMPT_RETAINED');
   if(attempts.size>=128)throw failure('UNAVAILABLE','OWNER_INFERENCE_ATTEMPT_BOUND');
   attempts.add(draft.request_uuid); // Never clear on interruption or uncertain outcome.
   const abort=new AbortController(),combined=signal?AbortSignal.any([signal,abort.signal]):abort.signal;
   const f={signal:combined,abort,isCurrent,bound:false,generated:false};flight=f;
   try{
    const selected=await resolveRequest(Object.freeze({draft,context:fixed,owner}),{signal:combined});current();
    if(combined.aborted)throw failure('OUTCOME_UNKNOWN','OWNER_INFERENCE_WAIT_ABORTED');
    closed(selected,['request','options']);f.request=freeze(detach(selected.request));f.options=freeze(detach(selected.options));
    const request=f.request,options=f.options;
    const span=request.fragments?.[0],message=options.messages?.[0],block=message?.content?.[0];
    if(request.request_uuid!==draft.request_uuid||Object.keys(fixed).some(k=>request[k]!==fixed[k])
     ||options.provider!=='externalDeepSeek'||options.model!==gateway.route.model||options.sessionId!==fixed.conversation_id
     ||options.maxTokens!==request.max_output_tokens||options.tools?.length
     ||request.fragments?.length!==1||span.role!=='user'||span.data_class!=='conversation'||span.text!==draft.text||Object.keys(fixed).some(k=>span[k]!==fixed[k])
     ||options.messages?.length!==1||message.role!=='user'||message.source?.kind!=='user'||message.content?.length!==1
     ||block.type!=='text'||block.text!==draft.text||Object.keys(block).sort().join(',')!=='text,type')
     throw failure('UNAUTHORIZED','OWNER_INFERENCE_SELECTED_REQUEST_MISMATCH');
    f.requestCanonical=contracts.canonicalJson(request);f.messagesCanonical=contracts.canonicalJson(options.messages);
    const prepared=prepareRequest(ledger.task(fixed.owner_id,fixed.task_id),gateway.route,request);
    let streamError;
    try{for await(const _chunk of scope.llm.stream({...options,signal:combined})){current();}}
    catch(error){streamError=error;}
    current();
    // The gateway already committed this result. Never generate again to render.
    const stored=ledger.get(fixed.owner_id,fixed.task_id,draft.request_uuid);
    const result=f.result;
    if(!result){throw failure('OUTCOME_UNKNOWN',streamError?'OWNER_INFERENCE_STREAM_UNCONFIRMED':'OWNER_INFERENCE_RESULT_MISSING');}
    const value=detach(result);
    if(!value||Object.getPrototypeOf(value)!==Object.prototype)throw failure('OUTCOME_UNKNOWN','OWNER_INFERENCE_RESULT_UNREADABLE');
    if(!f.bound||!f.generated||!stored||stored.owner_id!==fixed.owner_id||stored.task_id!==fixed.task_id
     ||stored.conversation_id!==fixed.conversation_id||stored.request_uuid!==draft.request_uuid
     ||stored.binding_hash!==prepared.binding_hash||stored.body_hash!==prepared.body_hash||value.receipt.body_sha256!==prepared.body_hash
     ||stored.status!==value.outcome||contracts.canonicalJson(stored.receipt)!==contracts.canonicalJson(value.receipt))
     throw failure('OUTCOME_UNKNOWN','OWNER_INFERENCE_RETAINED_BINDING_CHANGED');
    if(value.outcome==='completed'&&(!stored?.result||contracts.canonicalJson(stored.result)!==contracts.canonicalJson(value))
     ||value.outcome==='outcome_unknown'&&stored?.result!==undefined)throw failure('OUTCOME_UNKNOWN','OWNER_INFERENCE_STORED_RESULT_CHANGED');
    if(value.request_uuid!==draft.request_uuid||value.receipt?.request_uuid!==draft.request_uuid
     ||value.receipt.sessionId!==fixed.conversation_id||!['completed','outcome_unknown'].includes(value.outcome))
     throw failure('OUTCOME_UNKNOWN','OWNER_INFERENCE_RESULT_BINDING_CHANGED');
    if(combined.aborted)throw failure('OUTCOME_UNKNOWN','OWNER_INFERENCE_WAIT_ABORTED');
    return value;
   }finally{abort.abort();if(flight===f)flight=null;}
  },
  dispose(){disposed=true;flight?.abort.abort();if(removeAdapter){const remove=removeAdapter;remove();removeAdapter=undefined;}}
 });
}
