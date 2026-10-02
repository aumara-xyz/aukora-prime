// SPDX-License-Identifier: AGPL-3.0-or-later
import {validateContract} from '../../contracts/src/runtime.mjs'
import {dollars} from '../../authority/src/operation.mjs'
// Prime-local source for the owner-exported @aukora-prime/inference/budget-binding.
// Reuse its exact stored descriptor, policy and state derivations.
import {inferenceBudgetState,totalBudgetBinding} from '../../inference/src/budget-binding.mjs'
import {canonical as configurationJson,hash,integer,id,validateRoute,validateTask} from '../../inference/src/policy.mjs'
import {fromQualifiedPrimeRoute,fromPrimeTask} from '../../inference/src/prime-contracts.mjs'
import {createTrustedTaskRegistry} from './registry.mjs'
import {canonicalJson,operationDigest,closed,configRecord,data,inferenceOperation,ownerMappings,
  requireOwnedOperation,refusal,unavailableStatus} from './inference-support.mjs'

const usd = micros => ({currency:'USD',amount:`${BigInt(micros)/1000000n}.${String(BigInt(micros)%1000000n).padStart(6,'0')}`})
function qualifiedState(input,owner,registered) {
  const facts=closed(data(input),['route','configuration','local_task','total_budget','credential_generation'])
  const configuration=closed(facts.configuration,['digest','payload','operation_id'])
  closed(configuration.payload,['route','pricing'])
  const frozenRoute=configuration.payload.route,pricing=configuration.payload.pricing
  validateContract('ModelRoute',frozenRoute)
  closed(pricing,['input_microusd_per_token','output_microusd_per_token','max_request_ms',
    'pricing_evidence_id','terms_evidence_id','served_version'])
  if(frozenRoute.status!=='unavailable'||!id(configuration.operation_id)
    ||!integer(facts.credential_generation,1)||!integer(pricing.input_microusd_per_token,1)
    ||!integer(pricing.output_microusd_per_token,1)||!integer(pricing.max_request_ms,1)
    ||![pricing.pricing_evidence_id,pricing.terms_evidence_id,pricing.served_version].every(id))
    throw refusal('UNAUTHORIZED','INFERENCE_APPROVED_CONFIGURATION_REQUIRED')
  const digest='sha256:'+hash('aukora-prime.inference-config.v1\0'+configurationJson(configuration.payload))
  if(configuration.digest!==digest)throw refusal('UNAUTHORIZED','INFERENCE_CONFIGURATION_PREIMAGE_MISMATCH')
  const budget=totalBudgetBinding(facts.total_budget)
  const route=validateRoute(facts.route)
  const expectedRoute=fromQualifiedPrimeRoute({...frozenRoute,status:'approved'},
    {...pricing,credential_generation:facts.credential_generation,config_digest:digest,total_budget_id:budget.budget_id})
  if(canonicalJson(route)!==canonicalJson(expectedRoute))throw refusal('UNAUTHORIZED','INFERENCE_QUALIFIED_ROUTE_MISMATCH')
  const localTask=validateTask(facts.local_task)
  const expectedTask=fromPrimeTask(registered.task,route,{max_total_tokens:localTask.max_tokens})
  if(canonicalJson(localTask)!==canonicalJson(expectedTask)||localTask.owner_id!==owner.owner_id
    ||localTask.route_id!==route.route_id||!localTask.allowed_data_classes.includes('conversation')||!integer(localTask.spend_cap_microusd,1))
    throw refusal('UNAUTHORIZED','INFERENCE_EFFECTIVE_LOCAL_TASK_MISMATCH')
  const state=inferenceBudgetState({owner,route,total_budget:facts.total_budget,credential_generation:facts.credential_generation})
  return {state,limits:{max_requests:localTask.max_requests,max_input_tokens:localTask.max_input_tokens,
    max_output_tokens:localTask.max_output_tokens,max_total_tokens:localTask.max_tokens,
    max_request_ms:route.max_request_ms,task_spend_ceiling:usd(localTask.spend_cap_microusd)}}
}

/** Trusted private E host seam, not a guest callback or a qualification verifier.
 * withQualifiedState must read qualified route/config, E's stored seven-field
 * budget and live vault status independently, then await consume while holding
 * their change fence. It must remain held through actual HTTP dispatch too.
 * No bridge method reads secrets, normalizes a signed budget or creates allowance. */
export function createTrustedInferenceObserver(config) {
  configRecord(config,['registryEntries','ownerMappings'],['withQualifiedState'])
  const registry=createTrustedTaskRegistry(config.registryEntries),owners=ownerMappings(config.ownerMappings)
  if(config.withQualifiedState!==undefined&&typeof config.withQualifiedState!=='function')
    throw refusal('INVALID','INFERENCE_TRUSTED_STATE_ADAPTER_INVALID')
  const withState=config.withQualifiedState
  let active=false
  return Object.freeze({status:unavailableStatus,
    async withObservation(input,consume) {
      const detached=data(input)
      if(typeof withState!=='function')throw refusal('UNAVAILABLE','INFERENCE_TRUSTED_STATE_ADAPTER_UNMOUNTED')
      if(typeof consume!=='function')throw refusal('INVALID','INFERENCE_OBSERVATION_CONSUMER_REQUIRED')
      if(active)throw refusal('UNAVAILABLE','INFERENCE_OBSERVATION_REENTRANT')
      active=true
      let entered=false,completed=false,open=true,result,flight
      try {
        const operation=await inferenceOperation(detached),owner=requireOwnedOperation(operation,registry,owners)
        const registered=registry.getOwned(operation.task_id,owner.owner_id),json=canonicalJson(operation),digest=operationDigest(operation)
        await withState(data({owner_id:owner.owner_id,task_id:operation.task_id}),facts=>{
          if(!open||entered)throw refusal('UNAUTHORIZED','INFERENCE_STATE_SCOPE_REUSED')
          entered=true
          flight=(async()=>{
            const {state,limits}=qualifiedState(facts,owner,registered)
            if(canonicalJson(operation.target_identity)!==canonicalJson(state.target_identity)
              ||operation.expected_state_version!==state.state_version
              ||canonicalJson(operation.canonical_parameters.total_budget)!==canonicalJson(state.total_budget)
              ||canonicalJson(operation.canonical_parameters.limits)!==canonicalJson(limits)
              ||dollars(operation.maximum_cost)>dollars(limits.task_spend_ceiling))
              throw refusal('TARGET_MISMATCH','INFERENCE_TRUSTED_STATE_MISMATCH')
            const observation=data({target_identity:state.target_identity,state_version:state.state_version})
            const assertScope=()=>{
              if(!open||operationDigest(operation)!==digest||canonicalJson(operation)!==json)
                throw refusal('UNAUTHORIZED','INFERENCE_OBSERVATION_SCOPE_CLOSED')
            }
            assertScope();result=await consume(observation,assertScope);assertScope();completed=true
            return result
          })()
          return flight
        })
        if(!entered||!completed)throw refusal('OUTCOME_UNKNOWN','INFERENCE_STATE_FENCE_NOT_AWAITED')
        return result
      } finally {
        open=false
        // A faulty host callback cannot release reentry while an already sent
        // mutation is unresolved. Its result stays uncertain, never retried.
        try {await flight} catch {/* Preserve the original refusal/uncertainty. */} finally {active=false}
      }
    },
  })
}
