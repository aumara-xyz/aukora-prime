// SPDX-License-Identifier: AGPL-3.0-or-later
// Private source mapper. Structural consistency never establishes authority.
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData,detachContract,deepFreeze,dollars,operationDigest} from './operation.mjs'

export const INFERENCE_BINDING_FIELDS=Object.freeze(['owner_id','task_id','conversation_id','request_uuid',
  'body_sha256','binding_hash','citations_sha256','config_digest','reserved_tokens',
  'reserved_cost_microusd','credential_generation','total_budget_id'])
const TARGET=['version','kind','owner_subject','route_id','provider','endpoint','model','region',
  'config_digest','credential_generation','total_budget_id']
const PARAMETERS=['version','kind','binding','request_digest','limits','total_budget']
const LIMITS=['max_requests','max_input_tokens','max_output_tokens','max_total_tokens','max_request_ms','task_spend_ceiling']
const BUDGET=['budget_id','ceiling','policy_digest']
const ADMISSION=[...INFERENCE_BINDING_FIELDS,'operation','consumed_grant','request_digest']
const HEX=/^[a-f0-9]{64}$/
const DIGEST=/^sha256:[a-f0-9]{64}$/
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
const SUBJECT=/^aukora:1:[a-f0-9]{64}$/
const invalid=reason=>{throw new TypeError('INVALID: '+reason)}
const id=value=>typeof value==='string'&&value.length>0&&value.length<=256
const positive=value=>Number.isSafeInteger(value)&&value>0

function closed(input,fields) {
  assertData(input)
  const json=canonicalJson(input)
  if(!input||Array.isArray(input)||typeof input!=='object'||
     Object.keys(input).sort().join(',')!==[...fields].sort().join(','))invalid('closed inference fields')
  return JSON.parse(json)
}
function cost(input) {
  const value=closed(input,['currency','amount'])
  if(value.currency!=='USD'||typeof value.amount!=='string'||
     !/^(?:0|[1-9]\d*)(?:\.\d{1,8})?$/.test(value.amount)||dollars(value)<=0n)invalid('positive inference USD ceiling')
  return value
}

export function parseInferenceBinding(input) {
  const b=closed(input,INFERENCE_BINDING_FIELDS)
  if(![b.owner_id,b.task_id,b.conversation_id,b.total_budget_id].every(id)||
     typeof b.request_uuid!=='string'||!UUID.test(b.request_uuid)||
     ![b.body_sha256,b.binding_hash,b.citations_sha256].every(value=>typeof value==='string'&&HEX.test(value))||
     typeof b.config_digest!=='string'||!DIGEST.test(b.config_digest)||
     ![b.reserved_tokens,b.reserved_cost_microusd,b.credential_generation].every(positive))invalid('inference binding syntax')
  return deepFreeze(b)
}
export function inferenceRequestDigest(input) {
  const b=parseInferenceBinding(input)
  return 'sha256:'+createHash('sha256').update('aukora-prime.inference-request.v1\0'+canonicalJson(b)).digest('hex')
}

export function parseInferenceOperation(input) {
  const op=detachContract('OperationProposal',input),t=closed(op.target_identity,TARGET),
    p=closed(op.canonical_parameters,PARAMETERS),b=parseInferenceBinding(p.binding),
    limits=closed(p.limits,LIMITS),budget=closed(p.total_budget,BUDGET)
  if(op.audience!=='aukora-prime.inference'||op.action_type!=='inference.generate'||
     canonicalJson(op.data_scope)!=='["conversation"]'||t.version!==1||t.kind!=='prime-inference-route/v1'||
     t.route_id!=='externalDeepSeek'||t.provider!=='deepseek'||t.endpoint!=='https://api.deepseek.com'||
     ![t.model,t.region].every(id)||typeof t.owner_subject!=='string'||!SUBJECT.test(t.owner_subject)||
     p.version!==1||p.kind!=='prime-inference-request/v1')invalid('inference operation profile')
  if(b.owner_id!==op.owner_id||b.task_id!==op.task_id||t.config_digest!==b.config_digest||
     t.credential_generation!==b.credential_generation||t.total_budget_id!==b.total_budget_id||
     budget.budget_id!==b.total_budget_id||op.provider_and_region.provider!==t.provider||
     op.provider_and_region.region!==t.region||p.request_digest!==inferenceRequestDigest(b))invalid('inference operation binding')
  if(!LIMITS.filter(field=>field!=='task_spend_ceiling').every(field=>positive(limits[field]))||
     limits.max_request_ms>60000||b.reserved_tokens>limits.max_total_tokens||
     typeof budget.policy_digest!=='string'||!DIGEST.test(budget.policy_digest))invalid('inference limit syntax')
  const reserved=BigInt(b.reserved_cost_microusd)*100n
  cost(op.maximum_cost);cost(limits.task_spend_ceiling);cost(budget.ceiling)
  if(reserved>dollars(op.maximum_cost)||reserved>dollars(limits.task_spend_ceiling)||
     reserved>dollars(budget.ceiling)||dollars(op.maximum_cost)>dollars(limits.task_spend_ceiling))invalid('inference declared cost bound')
  // Signed decimal bytes and all operation fields remain exactly as received.
  // Budget policy/state version, Task conversation, full body and original rates
  // require independent trusted verification; this function cannot supply it.
  return deepFreeze(op)
}

export function parseInferenceAdmission(input) {
  const admission=closed(input,ADMISSION),op=parseInferenceOperation(admission.operation),
    grant=detachContract('ConsumedGrant',admission.consumed_grant),b=op.canonical_parameters.binding
  if(INFERENCE_BINDING_FIELDS.some(field=>admission[field]!==b[field])||
     admission.request_digest!==op.canonical_parameters.request_digest||
     grant.operation_id!==op.operation_id||grant.operation_digest!==operationDigest(op)||
     grant.owner_id!==op.owner_id||grant.audience!==op.audience||
     grant.authorization_epoch!==op.authorization_epoch)invalid('inference admission binding')
  // A matching envelope is not a durable grant. Original C store/kernel lookup,
  // owner approval and one-use claim remain mandatory.
  return deepFreeze(admission)
}

const unavailable=()=>({ok:false,error_code:'UNAVAILABLE',reason:'INFERENCE_AUTHORITY_JOIN_UNAVAILABLE'})
const errorResult=error=>({ok:false,error_code:error.error_code??(error instanceof TypeError?'INVALID':'UNAVAILABLE'),reason:error.message})
const refused=reason=>Object.assign(new Error(reason),{error_code:'RECONCILIATION_REQUIRED'})
const same=(a,b)=>canonicalJson(a)===canonicalJson(b)
const ERRORS=['UNAVAILABLE','INVALID','UNAUTHORIZED','STALE','REVOKED','REPLAYED','EXPIRED',
  'TARGET_MISMATCH','SCOPE_MISMATCH','CANCELLED','OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED']
function authorityReply(result) {
  assertData(result)
  if(!result||typeof result!=='object'||Array.isArray(result))throw refused('STRUCTURED_INFERENCE_AUTHORITY_REPLY_REQUIRED')
  if(result.ok===true)return result
  if(result.ok!==false||Object.keys(result).some(k=>!['ok','error_code','reason','detail'].includes(k))||
     !ERRORS.includes(result.error_code)||typeof result.reason!=='string'||
     (result.detail!==undefined&&typeof result.detail!=='string'))throw refused('STRUCTURED_INFERENCE_AUTHORITY_REFUSAL_REQUIRED')
  return {ok:false,error_code:result.error_code,reason:result.reason,
    ...(result.detail===undefined?{}:{detail:result.detail})}
}
function checkedGrant(result,op,status) {
  result=authorityReply(result)
  if(result.ok===false)return result
  const reply=closed(result,status==='PREPARED'?['ok','status','consumed_grant','kernel_receipt','profile']:
    ['ok','status','consumed_grant','request_id','request_digest'])
  const grant=detachContract('ConsumedGrant',reply.consumed_grant)
  if(reply.status!==status||grant.operation_id!==op.operation_id||grant.operation_digest!==operationDigest(op)||
     grant.owner_id!==op.owner_id||grant.audience!==op.audience||grant.authorization_epoch!==op.authorization_epoch)throw refused('EXACT_INFERENCE_GRANT_REPLY_REQUIRED')
  return deepFreeze({...reply,consumed_grant:grant})
}
/** Source-only adapter to the real protected C service/private proxy. The
 * dependency is supplied by trusted composition, never guest input. Its service
 * enforces the immutable inference profile, owner review/kernel, target observer
 * and original durable dispatch. This factory does not create a store, worker,
 * private role, key, HTTP request or atomic budget reservation. */
export function createInferenceAuthorityJoin(options) {
  if(options===undefined)return Object.freeze({reserve:unavailable,authorizeDispatch:unavailable,
    claimDispatch:unavailable,settleInference:unavailable,reconcileInferenceSettlement:unavailable})
  if(!options||Object.getPrototypeOf(options)!==Object.prototype||
     Reflect.ownKeys(options).some(k=>!['authority','resolveReviewedOperation'].includes(k))||!Object.hasOwn(options,'authority')||
     Reflect.ownKeys(options).some(k=>!Object.hasOwn(Object.getOwnPropertyDescriptor(options,k),'value'))||
     (Object.hasOwn(options,'resolveReviewedOperation')&&typeof options.resolveReviewedOperation!=='function'))invalid('trusted inference authority dependency')
  const authority=options.authority,names=['reserve','claimDispatch','settleInference','reconcileInferenceSettlement']
  const methods={}
  for(const name of names) {
    const descriptor=authority&&Object.getOwnPropertyDescriptor(authority,name)
    if(!descriptor||!Object.hasOwn(descriptor,'value')||typeof descriptor.value!=='function')invalid('inference authority methods unavailable')
    methods[name]=descriptor.value.bind(authority)
  }
  const attempt=async fn=>{try{return await fn()}catch(error){return errorResult(error)}}
  const reserve=input=>attempt(async()=>{
    const v=closed(input,['operation','approval_proof']),op=parseInferenceOperation(v.operation),
      proof=detachContract('ApprovalProof',v.approval_proof)
    if(proof.operation_id!==op.operation_id||proof.operation_digest!==operationDigest(op)||
       proof.owner_id!==op.owner_id||proof.audience!==op.audience||proof.authorization_epoch!==op.authorization_epoch)invalid('inference approval envelope')
    // Exactly one original C reserve call. Ambiguous replies are never retried.
    return checkedGrant(await methods.reserve({operation:op,approval_proof:proof}),op,'PREPARED')
  })
  const resolveReviewedOperation=options.resolveReviewedOperation
  const authorizeDispatch=input=>attempt(async()=>{
    const binding=parseInferenceBinding(input)
    if(!resolveReviewedOperation)return unavailable()
    // Matches E's authorize_dispatch(binding) seam. Resolution is trusted,
    // read-only composition from the existing exact owner-reviewed operation;
    // it never invents another proof, UUID or approval nonce.
    const v=closed(await resolveReviewedOperation(binding),['operation','approval_proof']),op=parseInferenceOperation(v.operation)
    if(!same(binding,op.canonical_parameters.binding))invalid('reviewed inference binding changed')
    const result=await reserve(v)
    if(!result||result.ok!==true)return result
    // App-side authorize_dispatch returns the closed flat fifteen-field tuple;
    // it never claims dispatch and cannot grant HTTP permission.
    return parseInferenceAdmission({...op.canonical_parameters.binding,operation:op,
      consumed_grant:result.consumed_grant,request_digest:op.canonical_parameters.request_digest})
  })
  const claimDispatch=input=>attempt(async()=>{
    const admission=parseInferenceAdmission(input),op=admission.operation,
      request_id=admission.request_uuid,request_digest=admission.request_digest
    // Worker-only call AFTER E atomically records intent and worst allowance.
    // E independently reconstructs body/citations/route/vault/budget before this.
    const result=checkedGrant(await methods.claimDispatch({operation:op,consumed_grant:admission.consumed_grant,
      request_id,request_digest}),op,'DISPATCHED')
    if(!result||result.ok!==true)return result
    const reply=closed(result,['ok','status','consumed_grant','request_id','request_digest'])
    if(reply.request_id!==request_id||reply.request_digest!==request_digest||
       !same(reply.consumed_grant,admission.consumed_grant))throw refused('EXACT_INFERENCE_DISPATCH_REPLY_REQUIRED')
    return deepFreeze(reply)
  })
  const settlement=(input,method)=>attempt(async()=>{
    const v=closed(input,['operation','consumed_grant','request_id','request_digest','receipt','receipt_digest']),
      op=parseInferenceOperation(v.operation),grant=detachContract('ConsumedGrant',v.consumed_grant)
    if(v.request_id!==op.canonical_parameters.binding.request_uuid||v.request_digest!==op.canonical_parameters.request_digest||
       typeof v.receipt_digest!=='string'||!DIGEST.test(v.receipt_digest))invalid('inference factual envelope')
    const result=authorityReply(await methods[method]({...v,operation:op,consumed_grant:grant}))
    if(result.ok===false)return result
    const reply=closed(result,['ok','status','request_id','request_digest','receipt_digest','idempotent','reconciliation_required'])
    if(!['COMPLETED','OUTCOME_UNKNOWN'].includes(reply.status)||reply.request_id!==v.request_id||
       reply.request_digest!==v.request_digest||reply.receipt_digest!==v.receipt_digest||
       typeof reply.idempotent!=='boolean'||reply.reconciliation_required!==(reply.status==='OUTCOME_UNKNOWN')||
       reply.status!==(v.receipt?.outcome==='completed'?'COMPLETED':v.receipt?.outcome==='outcome_unknown'?'OUTCOME_UNKNOWN':null))throw refused('EXACT_INFERENCE_SETTLEMENT_REPLY_REQUIRED')
    return deepFreeze(reply)
  })
  return Object.freeze({reserve,authorizeDispatch,claimDispatch,
    settleInference:input=>settlement(input,'settleInference'),
    reconcileInferenceSettlement:input=>settlement(input,'reconcileInferenceSettlement')})
}
