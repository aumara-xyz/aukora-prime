// SPDX-License-Identifier: AGPL-3.0-or-later
// Factual private-worker evidence. Recognition never authorizes a model request.
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData,detachContract,deepFreeze,operationDigest} from './operation.mjs'
import {parseInferenceOperation} from './inference-admission.mjs'

const RECEIPT_FIELDS=Object.freeze(['version','kind','operation_id','operation_digest','grant_id',
  'request_id','request_digest','owner_subject','task_id','conversation_id','route_id',
  'config_digest','credential_generation','total_budget_id','body_sha256','outcome',
  'result_digest','usage','reservation_retained','observed_at'])
const USAGE_FIELDS=Object.freeze(['input_tokens','output_tokens','cost_microusd'])
const CONTEXT_FIELDS=Object.freeze(['operation','consumed_grant','request_id','request_digest','owner_subject','rates'])
const RATE_FIELDS=Object.freeze(['input_microusd_per_token','output_microusd_per_token'])
const DIGEST=/^sha256:[a-f0-9]{64}$/
const HEX=/^[a-f0-9]{64}$/
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
const SUBJECT=/^aukora:1:[a-f0-9]{64}$/
const UTC_ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const invalid=reason=>{throw new TypeError('INVALID: '+reason)}
const integer=(value,min=0)=>Number.isSafeInteger(value)&&value>=min
const id=value=>typeof value==='string'&&value.length>0&&value.length<=1024
const matches=(value,pattern)=>typeof value==='string'&&pattern.test(value)

function closed(input,fields) {
  assertData(input)
  if(!input||typeof input!=='object'||Array.isArray(input)||
     Object.keys(input).sort().join(',')!==[...fields].sort().join(','))invalid('closed inference evidence fields')
  return JSON.parse(canonicalJson(input))
}
function observedAt(value) {
  if(!matches(value,UTC_ISO))return false
  const stamp=new Date(value)
  return Number.isFinite(stamp.getTime())&&stamp.toISOString()===value
}

/** Detached exact receipt recognition only. The caller must authenticate its
 * credential-worker source and bind it to the real durable dispatch below. */
export function inferenceEffectReceipt(input) {
  const r=closed(input,RECEIPT_FIELDS)
  if(r.version!==1||r.kind!=='prime-inference-effect/v1'||
     ![r.operation_id,r.grant_id,r.task_id,r.conversation_id,r.total_budget_id].every(id)||
     !matches(r.operation_digest,DIGEST)||!matches(r.request_id,UUID)||
     !matches(r.request_digest,DIGEST)||!matches(r.owner_subject,SUBJECT)||
     r.route_id!=='externalDeepSeek'||!matches(r.config_digest,DIGEST)||
     !integer(r.credential_generation,1)||!matches(r.body_sha256,HEX)||
     !observedAt(r.observed_at)||Buffer.byteLength(canonicalJson(r))>65536)invalid('exact inference effect receipt')
  if(r.outcome==='completed') {
    if(!matches(r.result_digest,DIGEST)||r.reservation_retained!==false)invalid('completed inference evidence')
    const usage=closed(r.usage,USAGE_FIELDS)
    if(!USAGE_FIELDS.every(field=>integer(usage[field])))invalid('bounded inference usage')
    r.usage=usage
  } else if(r.outcome==='outcome_unknown') {
    if(r.result_digest!==null||r.usage!==null||r.reservation_retained!==true)invalid('unknown inference evidence')
  } else invalid('inference evidence outcome')
  return deepFreeze(r)
}

export function inferenceEffectReceiptDigest(input) {
  const receipt=inferenceEffectReceipt(input)
  return 'sha256:'+createHash('sha256').update('aukora-prime.inference-receipt.v1\0'+canonicalJson(receipt)).digest('hex')
}

/** Pure consistency validation for an already authenticated factual source.
 * The service still requires its original stored grant/kernel preparation and
 * dispatch. rates must come from the original durable approved context, never
 * the receipt, app input or a replacement configuration. Task/route/budget
 * authentication and raw response/result-digest verification remain duties of
 * the trusted admission/evidence writer, not consequences of this function. */
export function validateInferenceReceiptBinding(input,context) {
  const v=closed(context,CONTEXT_FIELDS),op=parseInferenceOperation(v.operation),
    grant=detachContract('ConsumedGrant',v.consumed_grant),receipt=inferenceEffectReceipt(input),
    target=op.target_identity,p=op.canonical_parameters,b=p.binding,
    rates=closed(v.rates,RATE_FIELDS)
  if(!RATE_FIELDS.every(field=>integer(rates[field],1)))invalid('original approved inference rates')
  if(v.owner_subject!==target.owner_subject||v.request_id!==b.request_uuid||
     v.request_digest!==p.request_digest||grant.operation_id!==op.operation_id||
     grant.operation_digest!==operationDigest(op)||grant.owner_id!==op.owner_id||
     grant.audience!==op.audience||grant.authorization_epoch!==op.authorization_epoch)invalid('inference grant/request context binding')
  const expected={operation_id:op.operation_id,operation_digest:grant.operation_digest,
    grant_id:grant.grant_id,request_id:v.request_id,request_digest:v.request_digest,
    owner_subject:v.owner_subject,task_id:op.task_id,conversation_id:b.conversation_id,
    route_id:target.route_id,config_digest:b.config_digest,
    credential_generation:b.credential_generation,total_budget_id:b.total_budget_id,
    body_sha256:b.body_sha256}
  if(Object.entries(expected).some(([field,value])=>receipt[field]!==value))invalid('inference receipt operation binding')
  if(receipt.outcome==='completed') {
    const usage=receipt.usage,total=BigInt(usage.input_tokens)+BigInt(usage.output_tokens),
      cost=BigInt(usage.input_tokens)*BigInt(rates.input_microusd_per_token)+
        BigInt(usage.output_tokens)*BigInt(rates.output_microusd_per_token)
    if(usage.input_tokens>p.limits.max_input_tokens||usage.output_tokens>p.limits.max_output_tokens||
       total>BigInt(p.limits.max_total_tokens)||total>BigInt(b.reserved_tokens)||
       usage.cost_microusd>b.reserved_cost_microusd||cost!==BigInt(usage.cost_microusd))invalid('original bounded inference usage/cost')
  }
  return receipt
}
