#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Focused keyless local checks. Modelled replies are NOT kernel, approval or IPC proof.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {canonicalJson} from '../contracts/src/runtime.mjs'
import {operationDigest} from './src/operation.mjs'
import {createInferenceAuthorityJoin,parseInferenceAdmission,parseInferenceBinding,
  parseInferenceOperation,inferenceRequestDigest,INFERENCE_BINDING_FIELDS} from './src/inference-admission.mjs'
import {configureInferenceProfile,inferencePolicyContext} from './src/inference-profile.mjs'
import {inferenceEffectReceiptDigest} from './src/inference-effect.mjs'
import {inferenceBudgetState,totalBudgetPolicyDigest,normalizeTotalBudget} from '@aukora-prime/inference/budget-binding'

const copy=value=>structuredClone(value)
const digest=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value)).digest('hex')
const hex=character=>character.repeat(64)

export function inferenceFixture() {
  const owner={owner_id:'synthetic-mapper-owner',subject:'aukora:1:'+hex('a')}
  const ownerMap=new Map([[owner.owner_id,owner]])
  const original_config={route:{version:1,route_id:'externalDeepSeek',provider:'deepseek',
    endpoint:'https://api.deepseek.com',model:'synthetic-reviewed-model',region:'synthetic-region',
    allowed_data_classes:['conversation'],allowed_tools:[],max_input_tokens:4096,max_output_tokens:256,
    max_requests:1,task_spend_ceiling:{currency:'USD',amount:'0.010000'},status:'unavailable'},
    pricing:{input_microusd_per_token:1,output_microusd_per_token:20,max_request_ms:15000,
      pricing_evidence_id:'synthetic-public-pricing',terms_evidence_id:'synthetic-public-terms',
      served_version:'synthetic-served-version'}}
  const config_digest=digest('aukora-prime.inference-config.v1',original_config)
  const route={route_id:'externalDeepSeek',provider:'deepseek',endpoint:'https://api.deepseek.com',
    model:'synthetic-reviewed-model',allowed_data_classes:['conversation'],max_input_tokens:4096,
    max_output_tokens:256,max_request_ms:15000,mode:'production',input_microusd_per_token:1,
    output_microusd_per_token:20,max_requests:1,spend_cap_microusd:10000,region:'synthetic-region',
    transport_status:'approved',pricing_evidence_id:'synthetic-public-pricing',
    terms_evidence_id:'synthetic-public-terms',served_version:'synthetic-served-version',
    credential_generation:1,config_digest,total_budget_id:'synthetic-total-budget'}
  const total_budget={version:1,budget_id:'synthetic-total-budget',owner_id:owner.owner_id,
    provider:'deepseek',route_id:'externalDeepSeek',ceiling:{currency:'USD',amount:'10.000000'},
    approval_reference:'synthetic-public-approval-reference'}
  const local_task={owner_id:owner.owner_id,task_id:'synthetic-mapper-task',
    conversation_id:'synthetic-mapper-conversation',route_id:'externalDeepSeek',
    allowed_data_classes:['conversation'],max_requests:1,max_tokens:4352,max_input_tokens:4096,
    max_output_tokens:256,spend_cap_microusd:10000}
  const task={version:1,task_id:local_task.task_id,owner_id:owner.owner_id,agent_id:'synthetic-agent',
    conversation_id:local_task.conversation_id,status:'running',created_at:'2026-10-01T00:00:00.000Z',
    route_id:'externalDeepSeek',allowed_data_classes:['conversation'],max_input_tokens:4096,
    max_output_tokens:256,max_requests:1,task_spend_ceiling:{currency:'USD',amount:'0.010000'}}
  const state=inferenceBudgetState({owner,route,total_budget,credential_generation:1})
  const binding={owner_id:owner.owner_id,task_id:task.task_id,conversation_id:task.conversation_id,
    request_uuid:'11111111-2222-4333-8444-555555555555',body_sha256:hex('1'),binding_hash:hex('2'),
    citations_sha256:hex('3'),config_digest,reserved_tokens:150,reserved_cost_microusd:1000,
    credential_generation:1,total_budget_id:total_budget.budget_id}
  const operation={version:1,operation_id:'synthetic-inference-operation',task_id:task.task_id,
    owner_id:owner.owner_id,agent_id:task.agent_id,audience:'aukora-prime.inference',
    action_type:'inference.generate',target_identity:state.target_identity,
    canonical_parameters:{version:1,kind:'prime-inference-request/v1',binding,
      request_digest:inferenceRequestDigest(binding),limits:{max_requests:1,max_input_tokens:4096,
        max_output_tokens:256,max_total_tokens:4352,max_request_ms:15000,
        task_spend_ceiling:{currency:'USD',amount:'0.010000'}},total_budget:state.total_budget},
    data_scope:['conversation'],expected_state_version:state.state_version,
    provider_and_region:{provider:'deepseek',region:'synthetic-region'},
    maximum_cost:{currency:'USD',amount:'0.001000'},expiry:'2099-01-01T00:00:00.000Z',
    nonce:hex('4'),policy_version:'synthetic-policy-v1',authorization_epoch:7}
  // Constant non-verifying syntax bytes only. There is no signer, key or credential.
  const proof={version:1,operation_id:operation.operation_id,operation_digest:operationDigest(operation),
    owner_id:owner.owner_id,audience:operation.audience,authorization_epoch:7,
    expiry:'2098-12-31T23:59:00.000Z',nonce:hex('5'),material:{kind:'owner_key',
      request:{domain:'aukora:owner-approval-request:v1',subject:owner.subject,activeControlDigest:hex('6'),
        operationDigest:operationDigest(operation).slice(7),challenge:hex('5'),issuedAt:2000000000,
        expiresAt:2000000030},signature:'7'.repeat(128)}}
  const grant={version:1,grant_id:'grant:'+proof.nonce,operation_id:operation.operation_id,
    operation_digest:operationDigest(operation),owner_id:owner.owner_id,audience:operation.audience,
    authorization_epoch:7,prepared_at:'2026-10-01T00:00:01.000Z',reservation_id:'prepared:'+hex('8')}
  const context={route,local_task,total_budget,original_config}
  const profileInput={contexts:[context]}
  const admission={...binding,operation,consumed_grant:grant,
    request_digest:operation.canonical_parameters.request_digest}
  const receipt={version:1,kind:'prime-inference-effect/v1',operation_id:operation.operation_id,
    operation_digest:operationDigest(operation),grant_id:grant.grant_id,request_id:binding.request_uuid,
    request_digest:admission.request_digest,owner_subject:owner.subject,task_id:task.task_id,
    conversation_id:task.conversation_id,route_id:'externalDeepSeek',config_digest,
    credential_generation:1,total_budget_id:total_budget.budget_id,body_sha256:binding.body_sha256,
    outcome:'completed',result_digest:'sha256:'+hex('9'),usage:{input_tokens:90,output_tokens:10,cost_microusd:290},
    reservation_retained:false,observed_at:'2026-10-01T00:00:02.000Z'}
  const settlement={operation,consumed_grant:grant,request_id:binding.request_uuid,
    request_digest:admission.request_digest,receipt,receipt_digest:inferenceEffectReceiptDigest(receipt)}
  return {owner,ownerMap,context,profileInput,task,binding,operation,proof,grant,admission,settlement,
    original_config,route,total_budget}
}

function modelledAuthority(f,overrides={}) {
  const calls={reserve:[],claimDispatch:[],settleInference:[],reconcileInferenceSettlement:[]}
  const authority={}
  for(const name of Object.keys(calls))authority[name]=async input=>{
    calls[name].push(copy(input))
    if(overrides[name])return overrides[name](input)
    if(name==='reserve')return {ok:true,status:'PREPARED',consumed_grant:copy(f.grant),
      kernel_receipt:{fixture:'MODELLED_NO_KERNEL_PROOF'},profile:'MODELLED_NO_EFFECT_AUTHORITY'}
    if(name==='claimDispatch')return {ok:true,status:'DISPATCHED',consumed_grant:copy(input.consumed_grant),
      request_id:input.request_id,request_digest:input.request_digest}
    const status=input.receipt.outcome==='completed'?'COMPLETED':'OUTCOME_UNKNOWN'
    return {ok:true,status,request_id:input.request_id,request_digest:input.request_digest,
      receipt_digest:input.receipt_digest,idempotent:false,reconciliation_required:status==='OUTCOME_UNKNOWN'}
  }
  return {authority,calls}
}

export async function runInferenceMapperChecks() {
  let assertions=0
  const groups=[]
  const equal=(a,b,message)=>{assert.deepEqual(a,b,message);assertions++}
  const check=(value,message)=>{assert(value,message);assertions++}
  const rejects=(fn,pattern=/INVALID|UNAVAILABLE/)=>{assert.throws(fn,pattern);assertions++}
  const refusal=(result,code)=>{equal(result.ok,false,JSON.stringify(result));if(code)equal(result.error_code,code,JSON.stringify(result))}
  const test=async(name,fn)=>{await fn();groups.push(name)}
  const f=inferenceFixture()
  const reserveInput={operation:f.operation,approval_proof:f.proof}

  await test('default join and missing reviewed resolver remain unavailable',async()=>{
    const empty=createInferenceAuthorityJoin()
    for(const method of Object.keys(empty))refusal(await empty[method](), 'UNAVAILABLE')
    const m=modelledAuthority(f),join=createInferenceAuthorityJoin({authority:m.authority})
    refusal(await join.authorizeDispatch(f.binding),'UNAVAILABLE');equal(m.calls.reserve.length,0)
  })
  await test('binding rejects UUID array/coercion and unsafe or hidden fields',()=>{
    rejects(()=>parseInferenceBinding({...f.binding,request_uuid:[f.binding.request_uuid]}))
    rejects(()=>parseInferenceBinding({...f.binding,reserved_tokens:Number.MAX_SAFE_INTEGER+1}))
    rejects(()=>parseInferenceBinding({...f.binding,secret:'synthetic-rejected-extra'}))
    let reads=0;const accessor=copy(f.binding)
    Object.defineProperty(accessor,'owner_id',{enumerable:true,get(){reads++;return f.owner.owner_id}})
    rejects(()=>parseInferenceBinding(accessor));equal(reads,0)
    equal(Object.keys(parseInferenceBinding(f.binding)).sort(),[...INFERENCE_BINDING_FIELDS].sort())
  })
  await test('request and total-policy digests use accepted canonical domains',()=>{
    equal(inferenceRequestDigest(f.binding),digest('aukora-prime.inference-request.v1',f.binding))
    equal(totalBudgetPolicyDigest(f.context.total_budget),digest('aukora-prime.inference-budget-policy.v1',f.context.total_budget))
    equal(parseInferenceOperation(f.operation).canonical_parameters.total_budget.ceiling.amount,'10.000000')
    const changed=copy(f.operation);changed.canonical_parameters.limits.task_spend_ceiling.amount='00.010000'
    rejects(()=>parseInferenceOperation(changed))
  })
  await test('original reserve receives exact detached envelope once and returns frozen copied reply',async()=>{
    let shared
    const m=modelledAuthority(f,{reserve:()=>shared={ok:true,status:'PREPARED',consumed_grant:copy(f.grant),
      kernel_receipt:{fixture:'MODELLED_NO_KERNEL_PROOF'},profile:'MODELLED_NO_EFFECT_AUTHORITY'}})
    const reply=await createInferenceAuthorityJoin({authority:m.authority}).reserve(reserveInput)
    equal(reply.ok,true);equal(m.calls.reserve,[reserveInput]);check(Object.isFrozen(reply));check(Object.isFrozen(reply.consumed_grant))
    shared.status='changed';shared.consumed_grant.owner_id='changed';shared.kernel_receipt.fixture='changed'
    equal(reply.status,'PREPARED');equal(reply.consumed_grant.owner_id,f.owner.owner_id)
    equal(reply.kernel_receipt.fixture,'MODELLED_NO_KERNEL_PROOF')
  })
  await test('reserve refuses Boolean/malformed replies without a second call',async()=>{
    for(const response of [true,false,null,{ok:false},{ok:false,error_code:'INVALID',reason:'synthetic',extra:true}]){
      const m=modelledAuthority(f,{reserve:()=>response})
      refusal(await createInferenceAuthorityJoin({authority:m.authority}).reserve(reserveInput))
      equal(m.calls.reserve.length,1)
    }
  })
  await test('reserve refuses altered grant, status or success fields',async()=>{
    for(const change of [r=>r.consumed_grant.owner_id='other-owner',r=>r.consumed_grant.operation_digest='sha256:'+hex('b'),
      r=>r.status='DISPATCHED',r=>r.extra=true]){
      const m=modelledAuthority(f,{reserve:()=>{const r={ok:true,status:'PREPARED',consumed_grant:copy(f.grant),
        kernel_receipt:{fixture:'MODELLED_NO_KERNEL_PROOF'},profile:'MODELLED_NO_EFFECT_AUTHORITY'};change(r);return r}})
      refusal(await createInferenceAuthorityJoin({authority:m.authority}).reserve(reserveInput));equal(m.calls.reserve.length,1)
    }
  })
  await test('flat twelve-field resolver returns closed fifteen-field admission after one reserve',async()=>{
    const m=modelledAuthority(f);let resolved=0
    const join=createInferenceAuthorityJoin({authority:m.authority,resolveReviewedOperation:binding=>{
      resolved++;equal(binding,f.binding);check(Object.isFrozen(binding));return copy(reserveInput)}})
    const admission=await join.authorizeDispatch(f.binding)
    equal(Object.keys(admission).sort(),[...INFERENCE_BINDING_FIELDS,'operation','consumed_grant','request_digest'].sort())
    equal(parseInferenceAdmission(admission),f.admission);equal(resolved,1);equal(m.calls.reserve.length,1)
    equal(m.calls.claimDispatch.length,0)
  })
  await test('reviewed binding mismatch refuses before reserve',async()=>{
    const m=modelledAuthority(f)
    const join=createInferenceAuthorityJoin({authority:m.authority,resolveReviewedOperation:()=>copy(reserveInput)})
    refusal(await join.authorizeDispatch({...f.binding,conversation_id:'other-conversation'}),'INVALID')
    equal(m.calls.reserve.length,0)
  })
  await test('lost reserve reply is surfaced without retry or admission',async()=>{
    const m=modelledAuthority(f,{reserve:()=>{throw Object.assign(new Error('synthetic lost reply'),{error_code:'OUTCOME_UNKNOWN'})}})
    const join=createInferenceAuthorityJoin({authority:m.authority,resolveReviewedOperation:()=>copy(reserveInput)})
    refusal(await join.authorizeDispatch(f.binding),'OUTCOME_UNKNOWN');equal(m.calls.reserve.length,1);equal(m.calls.claimDispatch.length,0)
  })
  await test('claim maps exact operation/grant/UUID/digest once',async()=>{
    const m=modelledAuthority(f),reply=await createInferenceAuthorityJoin({authority:m.authority}).claimDispatch(f.admission)
    equal(reply.status,'DISPATCHED');equal(m.calls.claimDispatch,[{operation:f.operation,consumed_grant:f.grant,
      request_id:f.binding.request_uuid,request_digest:f.admission.request_digest}]);check(Object.isFrozen(reply))
    equal(m.calls.reserve.length,0)
  })
  await test('claim refuses mismatched admission before authority call',async()=>{
    const m=modelledAuthority(f),join=createInferenceAuthorityJoin({authority:m.authority})
    refusal(await join.claimDispatch({...f.admission,body_sha256:hex('c')}),'INVALID')
    equal(m.calls.claimDispatch.length,0)
  })
  await test('claim refuses Boolean, wrong grant, UUID, digest and extra reply fields',async()=>{
    for(const change of [()=>true,r=>({...r,consumed_grant:{...r.consumed_grant,reservation_id:'different'}}),
      r=>({...r,request_id:'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'}),r=>({...r,request_digest:'sha256:'+hex('d')}),
      r=>({...r,extra:true})]){
      const m=modelledAuthority(f,{claimDispatch:input=>change({ok:true,status:'DISPATCHED',
        consumed_grant:copy(input.consumed_grant),request_id:input.request_id,request_digest:input.request_digest})})
      refusal(await createInferenceAuthorityJoin({authority:m.authority}).claimDispatch(f.admission));equal(m.calls.claimDispatch.length,1)
    }
  })
  await test('lost claim reply is fenced without a repeated call',async()=>{
    const m=modelledAuthority(f,{claimDispatch:()=>{throw Object.assign(new Error('synthetic lost claim reply'),{error_code:'OUTCOME_UNKNOWN'})}})
    refusal(await createInferenceAuthorityJoin({authority:m.authority}).claimDispatch(f.admission),'OUTCOME_UNKNOWN')
    equal(m.calls.claimDispatch.length,1);equal(m.calls.reserve.length,0)
  })
  await test('factual settlement forwards exact envelope and enforces submitted outcome',async()=>{
    const m=modelledAuthority(f),join=createInferenceAuthorityJoin({authority:m.authority})
    const reply=await join.settleInference(f.settlement)
    equal(reply.status,'COMPLETED');equal(reply.reconciliation_required,false);equal(m.calls.settleInference,[f.settlement])
    equal(m.calls.reserve.length,0);equal(m.calls.claimDispatch.length,0)
    const bad=modelledAuthority(f,{settleInference:input=>({ok:true,status:'OUTCOME_UNKNOWN',request_id:input.request_id,
      request_digest:input.request_digest,receipt_digest:input.receipt_digest,idempotent:false,reconciliation_required:true})})
    refusal(await createInferenceAuthorityJoin({authority:bad.authority}).settleInference(f.settlement),'RECONCILIATION_REQUIRED')
  })
  await test('historical unknown acknowledgement stays unknown without modelling a current-row rollback',async()=>{
    const currentStatus='COMPLETED',unknown=copy(f.settlement)
    Object.assign(unknown.receipt,{outcome:'outcome_unknown',result_digest:null,usage:null,reservation_retained:true})
    unknown.receipt_digest=inferenceEffectReceiptDigest(unknown.receipt)
    const m=modelledAuthority(f,{reconcileInferenceSettlement:input=>({ok:true,status:'OUTCOME_UNKNOWN',
      request_id:input.request_id,request_digest:input.request_digest,receipt_digest:input.receipt_digest,
      idempotent:true,reconciliation_required:true})})
    const reply=await createInferenceAuthorityJoin({authority:m.authority}).reconcileInferenceSettlement(unknown)
    equal(reply.status,'OUTCOME_UNKNOWN');equal(reply.receipt_digest,unknown.receipt_digest);equal(reply.idempotent,true)
    equal(currentStatus,'COMPLETED');equal(m.calls.reconcileInferenceSettlement,[unknown]);equal(m.calls.claimDispatch.length,0)
  })
  await test('settlement refuses primitive/malformed and changed digest acknowledgements',async()=>{
    for(const response of [true,{ok:true,status:'COMPLETED',request_id:f.binding.request_uuid,
      request_digest:f.admission.request_digest,receipt_digest:'sha256:'+hex('e'),idempotent:false,reconciliation_required:false},
      {ok:false,error_code:'INVALID',reason:'synthetic',detail:{unexpected:true}}]){
      const m=modelledAuthority(f,{settleInference:()=>response})
      refusal(await createInferenceAuthorityJoin({authority:m.authority}).settleInference(f.settlement));equal(m.calls.settleInference.length,1)
    }
  })
  await test('profile binds public pinned owner, registered Task and exact original config bytes',()=>{
    const source=copy(f.profileInput),profile=configureInferenceProfile(source,f.ownerMap)
    check(Object.isFrozen(profile));check(Object.isFrozen(profile.contexts[0].original_config))
    const context=inferencePolicyContext(profile,f.operation,{owner:f.owner,task:f.task})
    equal(context.original_config,f.context.original_config);equal(context.rates,{input_microusd_per_token:1,output_microusd_per_token:20})
    equal(context.local_task,f.context.local_task);equal(context.route.config_digest,f.binding.config_digest)
    equal(context.original_config.route.status,'unavailable');equal(context.route.transport_status,'approved')
    source.contexts[0].local_task.conversation_id='changed-after-configure'
    equal(profile.contexts[0].local_task.conversation_id,f.task.conversation_id)
  })
  await test('profile refuses absent owner, duplicate contexts and non-normalized signed budget',()=>{
    rejects(()=>configureInferenceProfile(f.profileInput,new Map()))
    rejects(()=>configureInferenceProfile({contexts:[copy(f.context),copy(f.context)]},f.ownerMap))
    const changed=copy(f.profileInput);changed.contexts[0].total_budget.ceiling.amount='10'
    rejects(()=>configureInferenceProfile(changed,f.ownerMap),/TOTAL_BUDGET_NOT_NORMALIZED/)
    rejects(()=>totalBudgetPolicyDigest({...f.context.total_budget,ceiling_microusd:10000000}),/INVALID_TOTAL_BUDGET/)
    equal(normalizeTotalBudget({...f.context.total_budget,ceiling:{currency:'USD',amount:'10.00000099'}}).ceiling.amount,'10.000000')
  })
  await test('profile rejects promoted original bytes and wrong config digest/rates',()=>{
    for(const change of [c=>c.original_config.route.status='approved',c=>c.route.config_digest='sha256:'+hex('f'),
      c=>c.original_config.pricing.output_microusd_per_token=21,c=>c.original_config.route.max_output_tokens=257]){
      const changed=copy(f.profileInput);change(changed.contexts[0])
      if(changed.contexts[0].route.config_digest===f.context.route.config_digest)
        changed.contexts[0].route.config_digest=digest('aukora-prime.inference-config.v1',changed.contexts[0].original_config)
      rejects(()=>configureInferenceProfile(changed,f.ownerMap))
    }
  })
  await test('policy context refuses registered conversation, owner, cap or state changes',()=>{
    const profile=configureInferenceProfile(f.profileInput,f.ownerMap)
    for(const change of [t=>t.conversation_id='other-conversation',t=>t.owner_id='other-owner',
      t=>t.max_output_tokens=128,t=>t.task_spend_ceiling.amount='0.009000']){
      const task=copy(f.task);change(task)
      rejects(()=>inferencePolicyContext(profile,f.operation,{owner:f.owner,task}))
    }
    const operation=copy(f.operation);operation.expected_state_version='sha256:'+hex('c')
    rejects(()=>inferencePolicyContext(profile,operation,{owner:f.owner,task:f.task}))
    assert.throws(()=>inferencePolicyContext(null,f.operation,{owner:f.owner,task:f.task}),e=>e.error_code==='UNAVAILABLE');assertions++
    const changed=copy(f.profileInput);changed.contexts[0].route.credential_generation=2
    const newProfile=configureInferenceProfile(changed,f.ownerMap)
    rejects(()=>inferencePolicyContext(newProfile,f.operation,{owner:f.owner,task:f.task}))
  })
  return {status:'PASS',cases:groups.length,assertions,groups,
    scope:'Keyless local mapper/profile + exact owned E pure helper. Public synthetic data and constant non-verifying proof syntax; modelled authority replies only, NOT kernel approval, durable state, IPC, worker ledger, owner enrollment or runtime/provider qualification. No keys, services, credentials, network or provider calls.'}
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {console.log(JSON.stringify(await runInferenceMapperChecks()))}
  catch(error){console.log(JSON.stringify({status:'FAIL',error:error.message,stack:error.stack}));process.exitCode=1}
}
