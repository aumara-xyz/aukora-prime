// SPDX-License-Identifier: AGPL-3.0-or-later
// Provisioner-only immutable registry. No wire field can configure this profile.
import {createRequire} from 'node:module'
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {assertData,detachContract,deepFreeze,dollars} from './operation.mjs'
import {parseInferenceOperation} from './inference-admission.mjs'

const LOCAL_TASK=['owner_id','task_id','conversation_id','route_id','allowed_data_classes',
  'max_requests','max_tokens','max_input_tokens','max_output_tokens','spend_cap_microusd']
const ROUTE=['route_id','provider','endpoint','model','allowed_data_classes','max_input_tokens',
  'max_output_tokens','max_request_ms','mode','input_microusd_per_token','output_microusd_per_token',
  'max_requests','spend_cap_microusd','region','transport_status','pricing_evidence_id',
  'terms_evidence_id','served_version','credential_generation','config_digest','total_budget_id']
const PRICING=['input_microusd_per_token','output_microusd_per_token','max_request_ms',
  'pricing_evidence_id','terms_evidence_id','served_version']
const invalid=reason=>{throw new TypeError('INVALID: '+reason)}
const equal=(a,b)=>canonicalJson(a)===canonicalJson(b)
const positive=value=>Number.isSafeInteger(value)&&value>0
const helpers=new WeakMap()
const exact=(v,fields)=>v&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).sort().join(',')===[...fields].sort().join(',')
const amount=micros=>({currency:'USD',amount:`${BigInt(micros)/1000000n}.${String(BigInt(micros)%1000000n).padStart(6,'0')}`})
export const inferenceOperation=op=>op.audience==='aukora-prime.inference'||
  op.action_type.startsWith('inference.')||op.target_identity?.kind==='prime-inference-route/v1'

function originalConfiguration(context) {
  const config=context.original_config
  if(!exact(config,['route','pricing'])||!exact(config.pricing,PRICING))invalid('original inference configuration')
  const route=detachContract('ModelRoute',config.route),pricing=config.pricing,qualified=context.route
  const digest='sha256:'+createHash('sha256').update('aukora-prime.inference-config.v1\0'+canonicalJson(config)).digest('hex')
  // E's original settings payload is unavailable. Only the independently
  // qualified LocalRoute is promoted; never rehash that promoted payload.
  if(digest!==qualified.config_digest||route.status!=='unavailable'||route.allowed_tools.length||
     !['input_microusd_per_token','output_microusd_per_token','max_request_ms'].every(k=>positive(pricing[k]))||
     !['pricing_evidence_id','terms_evidence_id','served_version'].every(k=>typeof pricing[k]==='string'&&pricing[k].length>0&&pricing[k].length<=256)||
     ['route_id','provider','endpoint','model','region','max_input_tokens','max_output_tokens','max_requests'].some(k=>route[k]!==qualified[k])||
     !equal(route.allowed_data_classes,qualified.allowed_data_classes)||
     BigInt(qualified.spend_cap_microusd)!==dollars(route.task_spend_ceiling)/100n||
     PRICING.some(k=>pricing[k]!==qualified[k]))invalid('approved inference configuration bytes/rates mismatch')
}

/** Data comes from protected host qualification/configuration, never a guest callback.
 * C checks exact original {route,pricing} bytes against the configuration digest
 * and qualified route. Authentic approval and actual rates/terms qualification
 * must still be independently verified by the protected provisioner.
 * The live private worker observer remains mandatory at approval/reserve/claim. */
export function configureInferenceProfile(input,registeredOwners) {
  if(input===undefined)return null
  assertData(input)
  const profile=JSON.parse(canonicalJson(input))
  if(!exact(profile,['contexts'])||!Array.isArray(profile.contexts)||!profile.contexts.length||
     profile.contexts.length>256)invalid('immutable inference contexts')
  let binding
  try {binding=createRequire(import.meta.url)('@aukora-prime/inference/budget-binding')}
  catch {throw Object.assign(new Error('INFERENCE_BUDGET_HELPER_UNAVAILABLE'),{error_code:'UNAVAILABLE'})}
  const {inferenceBudgetState,totalBudgetPolicyDigest}=binding
  if(typeof inferenceBudgetState!=='function'||typeof totalBudgetPolicyDigest!=='function')invalid('inference shared helper exports')
  const seen=new Set()
  for(const context of profile.contexts) {
    if(!exact(context,['route','local_task','total_budget','original_config'])||!exact(context.route,ROUTE)||
       !exact(context.local_task,LOCAL_TASK))invalid('closed inference context')
    const {route,local_task:task,total_budget}=context
    const key=canonicalJson([task.owner_id,task.task_id])
    if(seen.has(key))invalid('duplicate inference context')
    seen.add(key)
    if(![task.owner_id,task.task_id,task.conversation_id].every(v=>typeof v==='string'&&v.length>0&&v.length<=256)||
       task.route_id!=='externalDeepSeek'||![task.max_requests,task.max_tokens,task.max_input_tokens,
       task.max_output_tokens,task.spend_cap_microusd].every(positive)||
       !Array.isArray(task.allowed_data_classes)||!equal(task.allowed_data_classes,['conversation'])||
       ![route.input_microusd_per_token,route.output_microusd_per_token].every(positive)||
       !Array.isArray(route.allowed_data_classes)||!route.allowed_data_classes.includes('conversation'))invalid('inference effective task/rates')
    // This invokes the one accepted E derivation, including exact normalized
    // stored seven-field budget syntax. No C copy of budget normalization exists.
    totalBudgetPolicyDigest(total_budget)
    const owner=registeredOwners?.get(task.owner_id)
    if(!owner)invalid('registered inference owner required')
    inferenceBudgetState({owner:{owner_id:owner.owner_id,subject:owner.subject},
      route,total_budget,credential_generation:route.credential_generation})
    originalConfiguration(context)
  }
  helpers.set(profile,{inferenceBudgetState})
  return deepFreeze(profile)
}

/** Original snapshot suitable for durable factual settlement, with no result text. */
export function inferencePolicyContext(profile,operation,{owner,task}) {
  const op=parseInferenceOperation(operation),p=op.canonical_parameters,b=p.binding
  if(!profile)throw Object.assign(new Error('INFERENCE_PROFILE_UNAVAILABLE'),{error_code:'UNAVAILABLE'})
  const {inferenceBudgetState}=helpers.get(profile)??{}
  if(typeof inferenceBudgetState!=='function')invalid('configured inference profile required')
  const context=profile.contexts.find(c=>c.local_task.owner_id===op.owner_id&&c.local_task.task_id===op.task_id)
  if(!context)throw Object.assign(new Error('INFERENCE_CONTEXT_UNAVAILABLE'),{error_code:'UNAVAILABLE'})
  const {local_task:local,route,total_budget}=context
  const budgetState=inferenceBudgetState({owner:{owner_id:owner.owner_id,subject:owner.subject},
    route,total_budget,credential_generation:route.credential_generation})
  const derivedRequests=Math.min(task.max_requests,route.max_requests)
  const aggregate=(task.max_input_tokens+task.max_output_tokens)*derivedRequests
  if(![task.max_input_tokens,task.max_output_tokens,task.max_requests,aggregate].every(positive)||task.route_id!==local.route_id||task.owner_id!==local.owner_id||
     task.task_id!==local.task_id||task.conversation_id!==local.conversation_id||b.conversation_id!==task.conversation_id||
     local.max_requests!==derivedRequests||local.max_tokens>aggregate||
     local.max_input_tokens!==Math.min(task.max_input_tokens,route.max_input_tokens)||
     local.max_output_tokens!==Math.min(task.max_output_tokens,route.max_output_tokens)||
     BigInt(local.spend_cap_microusd)!==(dollars(task.task_spend_ceiling)/100n<BigInt(route.spend_cap_microusd)
       ?dollars(task.task_spend_ceiling)/100n:BigInt(route.spend_cap_microusd))||
     !equal(local.allowed_data_classes,task.allowed_data_classes.filter(c=>route.allowed_data_classes.includes(c))))invalid('registered inference Task/context mismatch')
  const limits={max_requests:local.max_requests,max_input_tokens:local.max_input_tokens,
    max_output_tokens:local.max_output_tokens,max_total_tokens:local.max_tokens,
    max_request_ms:route.max_request_ms,task_spend_ceiling:amount(local.spend_cap_microusd)}
  if(!equal(op.target_identity,budgetState.target_identity)||op.expected_state_version!==budgetState.state_version||
     !equal(p.total_budget,budgetState.total_budget)||!equal(p.limits,limits)||
     b.reserved_tokens>local.max_tokens||b.reserved_cost_microusd>local.spend_cap_microusd)invalid('inference policy/state binding mismatch')
  return deepFreeze({local_task:structuredClone(local),route:structuredClone(route),
    total_budget:structuredClone(total_budget),original_config:structuredClone(context.original_config),rates:{input_microusd_per_token:route.input_microusd_per_token,
      output_microusd_per_token:route.output_microusd_per_token}})
}
