// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJson, operationDigest, validateContract } from '../../contracts/src/runtime.mjs';
import { hash, id, integer, refuse, validateRoute, validateTask } from './policy.mjs';
import { inferenceBudgetState } from './budget-binding.mjs';

const BINDING_FIELDS = ['owner_id','task_id','conversation_id','request_uuid','body_sha256','binding_hash',
  'citations_sha256','config_digest','reserved_tokens','reserved_cost_microusd','credential_generation','total_budget_id'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RAW_DIGEST = /^[a-f0-9]{64}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const money = micros => ({currency:'USD',amount:`${BigInt(micros) / 1000000n}.${String(BigInt(micros) % 1000000n).padStart(6,'0')}`});

/** This validates the reviewed metadata, not a proof, body, live credential or C owner mapping. */
export function reserveAttemptRecord(binding, operation, taskInput, routeInput, total_budget) {
  try {
    canonicalJson({binding,operation,task:taskInput,route:routeInput,total_budget});
    if (!binding || Array.isArray(binding)
      || Object.keys(binding).sort().join(',') !== [...BINDING_FIELDS].sort().join(',')
      || ![binding.owner_id,binding.task_id,binding.conversation_id,binding.total_budget_id].every(id)
      || typeof binding.request_uuid !== 'string' || !UUID.test(binding.request_uuid)
      || ![binding.body_sha256,binding.binding_hash,binding.citations_sha256].every(value => typeof value === 'string' && RAW_DIGEST.test(value))
      || typeof binding.config_digest !== 'string' || !DIGEST.test(binding.config_digest)
      || !integer(binding.reserved_tokens,1) || !integer(binding.reserved_cost_microusd,1)
      || !integer(binding.credential_generation,1)) refuse('INVALID_RESERVE_ATTEMPT');
    validateContract('OperationProposal',operation);
    const task = validateTask(taskInput), route = validateRoute(routeInput);
    // The adapter independently verifies C's owner mapping before entering the ledger.
    const state = inferenceBudgetState({owner:{owner_id:task.owner_id,subject:operation.target_identity?.owner_subject},
      route,total_budget,credential_generation:binding.credential_generation});
    const request_digest = 'sha256:' + hash('aukora-prime.inference-request.v1\0' + canonicalJson(binding));
    const limits = {max_requests:task.max_requests,max_input_tokens:Math.min(task.max_input_tokens,route.max_input_tokens),
      max_output_tokens:Math.min(task.max_output_tokens,route.max_output_tokens),max_total_tokens:task.max_tokens,
      max_request_ms:route.max_request_ms,task_spend_ceiling:money(task.spend_cap_microusd)};
    const parameters = {version:1,kind:'prime-inference-request/v1',binding,request_digest,limits,total_budget:state.total_budget};
    const [whole,fraction=''] = operation.maximum_cost.amount.split('.');
    const maximum = BigInt(whole) * 100000000n + BigInt(fraction.padEnd(8,'0'));
    if (task.owner_id !== binding.owner_id || task.task_id !== binding.task_id || task.conversation_id !== binding.conversation_id
      || task.route_id !== route.route_id || task.max_requests > route.max_requests
      || task.spend_cap_microusd > route.spend_cap_microusd
      || task.allowed_data_classes.some(value => !route.allowed_data_classes.includes(value))
      || binding.config_digest !== route.config_digest || binding.total_budget_id !== route.total_budget_id
      || binding.reserved_tokens > task.max_tokens
      || BigInt(binding.reserved_tokens) > BigInt(limits.max_input_tokens) + BigInt(limits.max_output_tokens)
      || binding.reserved_cost_microusd > task.spend_cap_microusd
      || operation.owner_id !== binding.owner_id || operation.task_id !== binding.task_id
      || operation.audience !== 'aukora-prime.inference' || operation.action_type !== 'inference.generate'
      || canonicalJson(operation.target_identity) !== canonicalJson(state.target_identity)
      || operation.expected_state_version !== state.state_version
      || canonicalJson(operation.canonical_parameters) !== canonicalJson(parameters)
      || canonicalJson(operation.provider_and_region) !== canonicalJson({provider:route.provider,region:route.region})
      || canonicalJson(operation.data_scope) !== canonicalJson(task.allowed_data_classes)
      || maximum < BigInt(binding.reserved_cost_microusd) * 100n
      || maximum > BigInt(task.spend_cap_microusd) * 100n) refuse('INVALID_RESERVE_ATTEMPT');
    return JSON.parse(canonicalJson({binding,operation_id:operation.operation_id,
      operation_digest:operationDigest(operation),request_digest}));
  } catch { refuse('INVALID_RESERVE_ATTEMPT'); }
}
