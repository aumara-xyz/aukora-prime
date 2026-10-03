// SPDX-License-Identifier: AGPL-3.0-or-later
// Existing E dispatch binding only. H owns protected connections; this module opens no channel.
import { canonicalJson, operationDigest, validateContract } from '../../contracts/src/runtime.mjs';
import { canonical, hash, id, integer, refuse, InferenceRefusal } from './policy.mjs';

const BINDING=['owner_id','task_id','conversation_id','request_uuid','body_sha256','binding_hash',
  'citations_sha256','config_digest','reserved_tokens','reserved_cost_microusd','credential_generation','total_budget_id'];
const REQUEST=[...BINDING,'route_id','endpoint','body','citations','headers','admission'];
const REPLY=['text','source_ids','input_tokens','output_tokens'];
const closed=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const same=(a,b)=>canonicalJson(a)===canonicalJson(b);
function bounds(milliseconds,bytes) {
  if (!integer(milliseconds,1)||milliseconds>60000||!integer(bytes,1)||bytes>2*1024*1024)
    refuse('PRIVATE_TRANSPORT_BOUNDS_REQUIRED');
}
function signalRequired(signal) {
  if (!(signal instanceof AbortSignal)) refuse('PRIVATE_CANCEL_SCOPE_REQUIRED');
}

/** Detached existing envelope. These binding checks authenticate no owner, peer, policy or grant. */
function snapshotRequest(value,maxBytes) {
  try {
    if (Buffer.byteLength(canonicalJson(value))>maxBytes||!closed(value,REQUEST)) throw new Error();
    const request=structuredClone(value),admission=request.admission;
    if (!closed(admission,[...BINDING,'operation','consumed_grant','request_digest'])
        ||BINDING.some(key=>request[key]!==admission[key])
        ||request.route_id!=='externalDeepSeek'||request.endpoint!=='https://api.deepseek.com'
        ||![request.owner_id,request.task_id,request.conversation_id,request.total_budget_id].every(id)
        ||!/^([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/iu.test(request.request_uuid)
        ||!integer(request.reserved_tokens,1)||!integer(request.reserved_cost_microusd,1)
        ||!integer(request.credential_generation,1)
        ||![request.body_sha256,request.binding_hash,request.citations_sha256].every(d=>typeof d==='string'&&/^[a-f0-9]{64}$/u.test(d))
        ||typeof request.config_digest!=='string'||!/^sha256:[a-f0-9]{64}$/u.test(request.config_digest)
        ||!closed(request.body,['model','messages','max_tokens','stream','response_format','thinking'])
        ||!id(request.body.model)||!integer(request.body.max_tokens,1)||request.body.stream!==false
        ||!Array.isArray(request.body.messages)||request.body.messages.length<2||request.body.messages.length>129
        ||request.body.messages.some(m=>!closed(m,['role','content'])||!['system','user','assistant'].includes(m.role)||typeof m.content!=='string')
        ||!closed(request.body.response_format,['type'])||request.body.response_format.type!=='json_object'
        ||!closed(request.body.thinking,['type'])||request.body.thinking.type!=='disabled'
        ||!closed(request.headers,['user-agent'])||typeof request.headers['user-agent']!=='string'
        ||!request.headers['user-agent'].length||Buffer.byteLength(request.headers['user-agent'])>2048||/[\r\n]/u.test(request.headers['user-agent'])
        ||!Array.isArray(request.citations)||request.citations.length>128
        ||hash(JSON.stringify(request.body))!==request.body_sha256
        ||hash(canonical(request.citations))!==request.citations_sha256) throw new Error();
    for (const citation of request.citations) {
      if (!closed(citation,['source_id','url','span_sha256','captured_at'])||!id(citation.source_id)
          ||typeof citation.span_sha256!=='string'||!/^[a-f0-9]{64}$/u.test(citation.span_sha256)
          ||typeof citation.captured_at!=='string'||!Number.isFinite(Date.parse(citation.captured_at))) throw new Error();
      const url=new URL(citation.url);
      if (!['http:','https:'].includes(url.protocol)||url.username||url.password) throw new Error();
    }
    validateContract('OperationProposal',admission.operation);validateContract('ConsumedGrant',admission.consumed_grant);
    const operation=admission.operation,grant=admission.consumed_grant;
    const binding=Object.fromEntries(BINDING.map(key=>[key,request[key]]));
    const digest='sha256:'+hash('aukora-prime.inference-request.v1\0'+canonicalJson(binding));
    if (operation.owner_id!==request.owner_id||operation.task_id!==request.task_id
        ||operation.audience!=='aukora-prime.inference'||operation.action_type!=='inference.generate'
        ||!same(operation.canonical_parameters?.binding,binding)
        ||operation.canonical_parameters?.request_digest!==digest||admission.request_digest!==digest
        ||grant.operation_id!==operation.operation_id||grant.operation_digest!==operationDigest(operation)
        ||grant.owner_id!==operation.owner_id||grant.audience!==operation.audience
        ||grant.authorization_epoch!==operation.authorization_epoch) throw new Error();
    return request;
  } catch { refuse('INVALID_PRIVATE_DISPATCH'); }
}
function snapshotReply(value,request) {
  try {
    canonicalJson(value);
    const inputBound=Buffer.byteLength(JSON.stringify(request.body))+request.body.messages.length*64;
    if (!closed(value,REPLY)||typeof value.text!=='string'||!integer(value.input_tokens)||!integer(value.output_tokens)
        ||value.input_tokens>inputBound||value.output_tokens>request.body.max_tokens
        ||BigInt(Buffer.byteLength(value.text))>BigInt(request.body.max_tokens)*16n
        ||!Array.isArray(value.source_ids)||value.source_ids.some(source=>typeof source!=='string'
          ||!request.citations.some(citation=>citation.source_id===source))) throw new Error();
    return structuredClone(value);
  } catch { refuse('INVALID_PROVIDER_RESULT'); }
}

/** Application callback for RemoteDeepSeekProvider. No retry, reconnect, credentials or inferred success. */
export function createPrivateInferenceDispatch({send,max_request_ms,max_request_bytes}={}) {
  bounds(max_request_ms,max_request_bytes);
  if (typeof send!=='function') refuse('PRIVATE_CREDENTIAL_TRANSPORT_REQUIRED');
  return async (envelope,{signal}={})=>{
    if (typeof send!=='function') refuse('PRIVATE_CREDENTIAL_TRANSPORT_REQUIRED');
    signalRequired(signal);
    if (signal.aborted) refuse('CANCELLED_BEFORE_DISPATCH');
    const request=snapshotRequest(envelope,max_request_bytes),controller=new AbortController();
    let timer,abortListener,submitted=false,interruptionCode;
    const interrupted=new Promise((_,reject)=>{
      const stop=code=>{
        if (interruptionCode) return;
        interruptionCode=code;controller.abort();reject(new InferenceRefusal(code));
      };
      abortListener=()=>stop(submitted?'CANCELLED_AFTER_DISPATCH':'CANCELLED_BEFORE_DISPATCH');
      signal.addEventListener('abort',abortListener,{once:true});
      timer=setTimeout(()=>stop('PROVIDER_OUTCOME_UNKNOWN'),max_request_ms);
      if (signal.aborted) abortListener();
    });
    const flight=Promise.resolve().then(()=>{
      if (controller.signal.aborted) refuse('CANCELLED_BEFORE_DISPATCH');
      submitted=true;
      return send(structuredClone(request),{signal:controller.signal});
    }).then(reply=>{
      if (controller.signal.aborted) refuse('PROVIDER_OUTCOME_UNKNOWN');
      return snapshotReply(reply,request);
    });
    try { return await Promise.race([flight,interrupted]); }
    catch {
      controller.abort();
      if (interruptionCode) refuse(interruptionCode);
      // A submitted request may already be consumed/charged. No raw channel/service error reaches the planner.
      refuse('PROVIDER_OUTCOME_UNKNOWN');
    } finally { clearTimeout(timer);signal.removeEventListener('abort',abortListener); }
  };
}

/** Bind only behind H's protected receiver. signal is receiver-owned, never decoded from the wire. */
export function createPrivateInferenceReceiver({service,max_request_bytes}={}) {
  bounds(1,max_request_bytes);
  if (typeof service?.dispatch!=='function') refuse('PRIVATE_CREDENTIAL_TRANSPORT_REQUIRED');
  return async (envelope,{signal}={})=>{
    if (typeof service?.dispatch!=='function') refuse('PRIVATE_CREDENTIAL_TRANSPORT_REQUIRED');
    signalRequired(signal);
    if (signal.aborted) refuse('CANCELLED_BEFORE_DISPATCH');
    const request=snapshotRequest(envelope,max_request_bytes);
    try {
      const reply=await service.dispatch(structuredClone(request),{signal});
      if (signal.aborted) refuse('PROVIDER_OUTCOME_UNKNOWN');
      return snapshotReply(reply,request);
    } catch { refuse('PROVIDER_OUTCOME_UNKNOWN'); }
  };
}
