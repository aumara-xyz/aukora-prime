// SPDX-License-Identifier: AGPL-3.0-or-later
// Host-owned single-message selection for the existing DSH/E producer. This
// supplies no owner proof, readiness, reservation, credentials or model call.
import {existsSync} from 'node:fs';
import {validateInferenceContext,validateInferenceDraft} from './owner-inference-producer.mjs';
const owned=existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/';
const contracts=await import(new URL(owned+'contracts/src/runtime.mjs',import.meta.url));
const {validateRoute,validateTask,prepareRequest}=await import(new URL(owned+'inference/src/policy.mjs',import.meta.url));
const {fromPrimeTask}=await import(new URL(owned+'inference/src/prime-contracts.mjs',import.meta.url));
const fail=(code,reason)=>{throw Object.assign(new Error(reason),{code,error_code:code});};
const copy=value=>contracts.parseStrictJson(contracts.canonicalJson(value),{maxBytes:262144,maxDepth:32});
const freeze=value=>{if(value&&typeof value==='object'){for(const item of Object.values(value))freeze(item);Object.freeze(value);}return value;};
const same=(left,right)=>contracts.canonicalJson(left)===contracts.canonicalJson(right);
const closed=(value,fields)=>{
 copy(value);
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!==[...fields].sort().join(','))fail('INVALID','OWNER_INFERENCE_SELECTION_FIELDS');
};

/** Explicit host inputs only. The registry and ledger must already contain the
 * owner-approved Task/route; selection never registers, edits or charges them.
 * Use selector.resolveRequest as createDshOwnerInferenceProducer's existing
 * resolveRequest callback. The genuine E/C reviewed-proof path is still required
 * before that producer can reserve/dispatch. No default or mock is supplied. */
export function createOwnerInferenceRequestSelector({context,ledger,route,taskRegistry}={}){
 const fixed=validateInferenceContext(context),fixedRoute=freeze(copy(validateRoute(route)));
 if(typeof ledger?.task!=='function'||typeof ledger?.route!=='function'||typeof taskRegistry?.getOwned!=='function')
  fail('UNAVAILABLE','OWNER_INFERENCE_REGISTERED_HOST_REQUIRED');
 const readTask=ledger.task.bind(ledger),readRoute=ledger.route.bind(ledger),getOwned=taskRegistry.getOwned.bind(taskRegistry);
 let active=true;
 function currentTask(){
  if(!active)fail('UNAVAILABLE','OWNER_INFERENCE_SELECTOR_WITHDRAWN');
  const entry=getOwned(fixed.task_id,fixed.owner_id);
  if(!entry||entry.task.owner_id!==fixed.owner_id||entry.task.task_id!==fixed.task_id
   ||entry.task.conversation_id!==fixed.conversation_id||!['pending','running'].includes(entry.task.status))
   fail('UNAUTHORIZED','OWNER_INFERENCE_ACTIVE_TASK_REQUIRED');
  contracts.validateContract('Task',entry.task);
  const actualRoute=copy(validateRoute(readRoute(fixed.owner_id,fixed.task_id)));
  if(!same(actualRoute,fixedRoute))fail('UNAVAILABLE','OWNER_INFERENCE_REGISTERED_ROUTE_CHANGED');
  const task=copy(validateTask(readTask(fixed.owner_id,fixed.task_id)));
  const expected=fromPrimeTask(entry.task,fixedRoute,{max_total_tokens:task.max_tokens});
  if(!same(task,expected))fail('UNAUTHORIZED','OWNER_INFERENCE_REGISTERED_TASK_CHANGED');
  return task;
 }
 // Reject a missing/different registered policy before exposing a selector.
 const registered=freeze(copy(currentTask()));
 return Object.freeze({context:fixed,
  resolveRequest(input,{signal}={}){
   const selected=copy(input);closed(selected,['draft','context','owner']);
   if(signal?.aborted)fail('UNAVAILABLE','OWNER_INFERENCE_SELECTION_ABORTED');
   if(!same(selected.context,fixed)||selected.owner?.owner_id!==fixed.owner_id
    ||typeof selected.owner.expiry!=='string'||!Number.isFinite(Date.parse(selected.owner.expiry))
    ||Date.parse(selected.owner.expiry)<=Date.now())fail('UNAUTHORIZED','OWNER_INFERENCE_SELECTION_OWNER_REQUIRED');
   const task=currentTask();
   if(!same(task,registered))fail('UNAVAILABLE','OWNER_INFERENCE_REGISTERED_TASK_CHANGED');
   const draft=validateInferenceDraft(selected.draft);
   const request={...fixed,request_uuid:draft.request_uuid,
    max_output_tokens:Math.min(task.max_output_tokens,fixedRoute.max_output_tokens),
    fragments:[{...fixed,data_class:'conversation',role:'user',text:draft.text}]};
   // Existing E checks classes, scope, pasted credential forms, UTF-8/token
   // bounds and exact body/citations. This neither reserves nor approves work.
   prepareRequest(task,fixedRoute,request);
   const options={provider:'externalDeepSeek',model:fixedRoute.model,sessionId:fixed.conversation_id,
    maxTokens:request.max_output_tokens,tools:[],
    messages:[{role:'user',source:{kind:'user'},content:[{type:'text',text:draft.text}]}]};
   return freeze({request,options});
  },
  dispose(){active=false;},
 });
}
