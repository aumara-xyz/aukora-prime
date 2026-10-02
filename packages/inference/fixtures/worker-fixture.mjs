import { canonicalJson, operationDigest } from '../../contracts/src/runtime.mjs';
import { canonical, hash, prepareRequest } from '../src/policy.mjs';
import { inferenceBudgetState, normalizeTotalBudget } from '../src/budget-binding.mjs';
import { verifyPrivateDispatch } from '../src/dispatch-policy.mjs';

const money = micros => ({currency:'USD',amount:`${BigInt(micros) / 1000000n}.${String(BigInt(micros) % 1000000n).padStart(6,'0')}`});

/** Synthetic data only: these structurally valid operations/grants carry no real authority. */
export function makeWorkerFixture(options = {}) {
  const owner_id = options.owner_id ?? 'synthetic-owner';
  const task_id = options.task_id ?? 'synthetic-task';
  const conversation_id = options.conversation_id ?? 'synthetic-conversation';
  const request_uuid = options.request_uuid ?? '11111111-1111-4111-8111-111111111111';
  const route = {
    route_id:'externalDeepSeek',provider:'deepseek',endpoint:'https://api.deepseek.com',model:'synthetic-model',
    region:'synthetic-region',allowed_data_classes:['conversation','public_source'],max_input_tokens:4096,max_output_tokens:256,
    max_request_ms:1000,mode:'production',max_requests:1,spend_cap_microusd:10000,input_microusd_per_token:1,
    output_microusd_per_token:2,transport_status:'approved',pricing_evidence_id:'synthetic-price',terms_evidence_id:'synthetic-terms',
    served_version:'synthetic-version',credential_generation:options.credential_generation ?? 1,
    config_digest:'sha256:'+hash('synthetic-config'),total_budget_id:'synthetic-total-testing',...options.route
  };
  const task = {
    owner_id,task_id,conversation_id,route_id:route.route_id,allowed_data_classes:[...route.allowed_data_classes],
    max_requests:route.max_requests,max_tokens:route.max_input_tokens+route.max_output_tokens,
    max_input_tokens:route.max_input_tokens,max_output_tokens:route.max_output_tokens,
    spend_cap_microusd:route.spend_cap_microusd,...options.task
  };
  const total_budget = normalizeTotalBudget({version:1,budget_id:route.total_budget_id,owner_id:task.owner_id,
    provider:'deepseek',route_id:'externalDeepSeek',ceiling:{currency:'USD',amount:'10.000000'},
    approval_reference:'synthetic-budget-approval',...options.total_budget});
  const observation = {owner:{owner_id:task.owner_id,subject:'aukora:1:'+hash('synthetic-subject:'+task.owner_id)},
    total_budget,credential_generation:route.credential_generation};
  const scoped = {owner_id:task.owner_id,task_id:task.task_id,conversation_id:task.conversation_id};
  const text = options.text ?? 'Synthetic selected public source.';
  const fragment = task.allowed_data_classes.includes('public_source')
    ? {...scoped,data_class:'public_source',role:'user',text,citation:{source_id:'fixture-source',url:'https://example.com/docs',
      span_sha256:hash(text),captured_at:'2026-10-01T00:00:00.000Z'}}
    : {...scoped,data_class:'conversation',role:'user',text};
  const selected = {...scoped,request_uuid,max_output_tokens:options.max_output_tokens ?? task.max_output_tokens,fragments:[fragment]};
  const prepared = prepareRequest(task,route,selected);
  const binding = {...scoped,request_uuid,body_sha256:prepared.body_hash,binding_hash:prepared.binding_hash,
    citations_sha256:hash(canonical(prepared.citations)),config_digest:route.config_digest,
    reserved_tokens:prepared.token_reservation,reserved_cost_microusd:prepared.cost_reservation,
    credential_generation:route.credential_generation,total_budget_id:route.total_budget_id};
  const request_digest = 'sha256:'+hash('aukora-prime.inference-request.v1\0'+canonicalJson(binding));
  const state = inferenceBudgetState({...observation,route});
  const operation = {
    version:1,operation_id:'synthetic-operation:'+request_uuid,owner_id:task.owner_id,task_id:task.task_id,agent_id:'synthetic-agent',
    audience:'aukora-prime.inference',action_type:'inference.generate',target_identity:state.target_identity,
    canonical_parameters:{version:1,kind:'prime-inference-request/v1',binding:structuredClone(binding),request_digest,
      limits:{max_requests:task.max_requests,max_input_tokens:Math.min(task.max_input_tokens,route.max_input_tokens),
        max_output_tokens:Math.min(task.max_output_tokens,route.max_output_tokens),max_total_tokens:task.max_tokens,
        max_request_ms:route.max_request_ms,task_spend_ceiling:money(task.spend_cap_microusd)},total_budget:state.total_budget},
    data_scope:[...task.allowed_data_classes],expected_state_version:state.state_version,
    provider_and_region:{provider:route.provider,region:route.region},maximum_cost:money(task.spend_cap_microusd),
    expiry:'2099-01-01T00:00:00.000Z',nonce:'synthetic-nonce:'+request_uuid,policy_version:'synthetic-policy-v1',authorization_epoch:1
  };
  const consumed_grant = {version:1,grant_id:'grant:synthetic:'+request_uuid,operation_id:operation.operation_id,
    operation_digest:operationDigest(operation),owner_id:task.owner_id,audience:operation.audience,authorization_epoch:1,
    prepared_at:'2026-10-01T00:00:00.000Z',reservation_id:'prepared:synthetic:'+request_uuid};
  const request = {...binding,route_id:route.route_id,endpoint:route.endpoint,body:prepared.body,citations:prepared.citations,
    headers:{'user-agent':'aukora-prime/synthetic-fixture'},admission:{...binding,operation,consumed_grant,request_digest}};
  const {intent} = verifyPrivateDispatch(request,route,task,observation);
  return {route,task,observation,request,prepared,binding,operation,consumed_grant,intent};
}
