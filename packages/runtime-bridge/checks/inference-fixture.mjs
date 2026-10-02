// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
// TEST_ONLY synthetic policy and structural material, never runtime qualification.
import {operationDigest} from '../../contracts/src/runtime.mjs'
import {inferenceRequestDigest,parseInferenceAdmission} from '../../authority/src/inference-admission.mjs'
import {inferenceBudgetState} from '../../inference/src/budget-binding.mjs'
import {canonical,hash,prepareRequest} from '../../inference/src/policy.mjs'
import {fromQualifiedPrimeRoute,fromPrimeTask} from '../../inference/src/prime-contracts.mjs'
import {createTrustedInferenceObserver} from '../src/inference.mjs'
const clone=structuredClone

export function fixture({owner={owner_id:'keyless-source-owner',subject:'aukora:1:'+'a'.repeat(64)}}={}) {
  const task={version:1,task_id:'source-task',owner_id:owner.owner_id,agent_id:'source-agent',conversation_id:'source-conversation',
    status:'running',created_at:'2026-10-02T00:00:00.000Z',route_id:'externalDeepSeek',allowed_data_classes:['conversation'],
    max_input_tokens:4096,max_output_tokens:256,max_requests:1,task_spend_ceiling:{currency:'USD',amount:'0.010000'}}
  const storedRoute={version:1,route_id:'externalDeepSeek',provider:'deepseek',endpoint:'https://api.deepseek.com',model:'source-test-model',
    region:'source-region',allowed_data_classes:['conversation'],allowed_tools:[],max_input_tokens:4096,max_output_tokens:256,
    max_requests:1,task_spend_ceiling:{currency:'USD',amount:'0.010000'},status:'unavailable'}
  const pricing={input_microusd_per_token:1,output_microusd_per_token:1,max_request_ms:15000,
    pricing_evidence_id:'source-pricing',terms_evidence_id:'source-terms',served_version:'source-test-version'}
  const payload={route:storedRoute,pricing},configuration={payload,operation_id:'TEST_ONLY-config-approval',
    digest:'sha256:'+hash('aukora-prime.inference-config.v1\0'+canonical(payload))}
  const total_budget={version:1,budget_id:'source-budget',owner_id:owner.owner_id,provider:'deepseek',route_id:'externalDeepSeek',
    ceiling:{currency:'USD',amount:'10.000000'},approval_reference:'TEST_ONLY-budget-approval'}
  const route=fromQualifiedPrimeRoute({...storedRoute,status:'approved'},{...pricing,credential_generation:1,
    config_digest:configuration.digest,total_budget_id:total_budget.budget_id})
  const local_task=fromPrimeTask(task,route,{max_total_tokens:4352})
  const prepared=prepareRequest(local_task,route,{owner_id:owner.owner_id,task_id:task.task_id,conversation_id:task.conversation_id,
    request_uuid:'11111111-1111-4111-8111-111111111111',max_output_tokens:256,
    fragments:[{owner_id:owner.owner_id,task_id:task.task_id,conversation_id:task.conversation_id,data_class:'conversation',role:'user',text:'Public synthetic source check.'}]})
  const binding={owner_id:owner.owner_id,task_id:task.task_id,conversation_id:task.conversation_id,request_uuid:'11111111-1111-4111-8111-111111111111',
    body_sha256:prepared.body_hash,binding_hash:prepared.binding_hash,citations_sha256:hash(canonical(prepared.citations)),
    config_digest:route.config_digest,reserved_tokens:prepared.token_reservation,reserved_cost_microusd:prepared.cost_reservation,
    credential_generation:1,total_budget_id:total_budget.budget_id}
  const state=inferenceBudgetState({owner,route,total_budget,credential_generation:1})
  const operation={version:1,operation_id:'source-operation',task_id:task.task_id,owner_id:owner.owner_id,agent_id:task.agent_id,
    audience:'aukora-prime.inference',action_type:'inference.generate',target_identity:state.target_identity,
    canonical_parameters:{version:1,kind:'prime-inference-request/v1',binding,request_digest:inferenceRequestDigest(binding),
      limits:{max_requests:1,max_input_tokens:4096,max_output_tokens:256,max_total_tokens:4352,max_request_ms:15000,
        task_spend_ceiling:{currency:'USD',amount:'0.010000'}},total_budget:state.total_budget},data_scope:['conversation'],
    expected_state_version:state.state_version,provider_and_region:{provider:'deepseek',region:'source-region'},
    maximum_cost:{currency:'USD',amount:'0.010000'},expiry:'2040-01-01T00:00:00.000Z',nonce:'source-nonce',policy_version:'source-policy',authorization_epoch:0}
  const grant={version:1,grant_id:'TEST_ONLY-NOT-A-C-GRANT',operation_id:operation.operation_id,operation_digest:operationDigest(operation),
    owner_id:owner.owner_id,audience:operation.audience,authorization_epoch:0,prepared_at:'2026-10-02T00:00:00.000Z',reservation_id:'TEST_ONLY-not-kernel-prepared'}
  const proof={version:1,operation_id:operation.operation_id,operation_digest:operationDigest(operation),owner_id:owner.owner_id,
    audience:operation.audience,authorization_epoch:0,expiry:operation.expiry,nonce:'source-proof-nonce',material:{kind:'owner_key',signature:'0'.repeat(128),
      request:{domain:'aukora:owner-approval-request:v1',subject:owner.subject,activeControlDigest:'2'.repeat(64),
        operationDigest:operationDigest(operation).slice(7),challenge:'3'.repeat(64),issuedAt:1790899200,expiresAt:1790899260}}}
  const facts={route,configuration,local_task,total_budget,credential_generation:1}
  const registryEntries=[{task,provider_and_region:operation.provider_and_region,audience:operation.audience,
    policy_version:operation.policy_version,data_scope:['conversation']}]
  let held=0,reads=0
  const observer=createTrustedInferenceObserver({registryEntries,ownerMappings:[owner],async withQualifiedState(lookup,consume){
    assert.deepEqual(lookup,{owner_id:owner.owner_id,task_id:task.task_id});reads++;held++
    try{return await consume(clone(facts))}finally{held--}
  }})
  const admission=()=>parseInferenceAdmission({...binding,operation,consumed_grant:grant,request_digest:inferenceRequestDigest(binding)})
  const claim=()=>({operation,consumed_grant:grant,request_id:binding.request_uuid,request_digest:inferenceRequestDigest(binding)})
  return {owner,task,operation,grant,proof,binding,facts,registryEntries,observer,admission,claim,get held(){return held},get reads(){return reads}}
}
