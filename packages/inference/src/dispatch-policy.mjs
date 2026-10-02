import { canonical, hash, id, integer, refuse, validateRoute, validateTask, assertDispatchExpiry } from './policy.mjs';
import { canonicalJson, operationDigest, validateContract } from '../../contracts/src/runtime.mjs';
import { inferenceBudgetState } from './budget-binding.mjs';

export const PRIVATE_NOTE_SYSTEM_TEXT = 'Return a JSON object with text (a concise sourced note) and source_ids (only supplied source_id values). The text is a proposal and never authorizes effects.';
const FIELDS = ['admission','binding_hash','body','body_sha256','citations','citations_sha256','config_digest',
  'conversation_id','credential_generation','endpoint','headers','owner_id','request_uuid',
  'reserved_cost_microusd','reserved_tokens','route_id','task_id','total_budget_id'];
const BINDING_FIELDS = ['owner_id','task_id','conversation_id','request_uuid','body_sha256','binding_hash',
  'citations_sha256','config_digest','reserved_tokens','reserved_cost_microusd','credential_generation','total_budget_id'];
const ADMISSION_FIELDS = [...BINDING_FIELDS,'operation','consumed_grant','request_digest'];
const SHA256 = /^[a-f0-9]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function closed(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
}

/** Shared post-claim continuation: the trusted observation can outlive an otherwise valid approval. */
export async function verifyWorkerContinuation(intent, observe, signal) {
  const current = await observe();
  if (canonicalJson(current.intent) !== canonicalJson(intent)) refuse('DISPATCH_POLICY_CHANGED');
  if (signal?.aborted) refuse('CANCELLED_AFTER_CLAIM');
  assertDispatchExpiry(intent.operation.expiry);
}

/** Pure policy/binding validation. C still verifies the actual consumed grant at claim. */
export function verifyPrivateDispatch(request, routeInput, taskInput, observation) {
  try { canonicalJson(request); } catch { refuse('INVALID_PRIVATE_DISPATCH'); }
  const route = validateRoute(routeInput), task = validateTask(taskInput);
  if (!closed(request,FIELDS) || !closed(request.body,['model','messages','max_tokens','stream','response_format','thinking'])
      || !closed(request.body.response_format,['type']) || request.body.response_format.type !== 'json_object'
      || !closed(request.body.thinking,['type']) || request.body.thinking.type !== 'disabled'
      || request.body.stream !== false || !closed(request.headers,['user-agent'])
      || typeof request.headers['user-agent'] !== 'string' || !request.headers['user-agent'].length
      || Buffer.byteLength(request.headers['user-agent']) > 2048 || /[\r\n]/u.test(request.headers['user-agent'])
      || !Array.isArray(request.body.messages) || request.body.messages.length < 2 || request.body.messages.length > 129
      || request.body.messages.some((message,index) => !closed(message,['role','content'])
        || typeof message.content !== 'string' || (index === 0
          ? message.role !== 'system' || message.content !== PRIVATE_NOTE_SYSTEM_TEXT
          : !['user','assistant'].includes(message.role)))
      || !Array.isArray(request.citations) || request.citations.length > 128) refuse('INVALID_PRIVATE_DISPATCH');
  for (const citation of request.citations) {
    let url; try { url = new URL(citation?.url); } catch { refuse('INVALID_PRIVATE_DISPATCH'); }
    if (!closed(citation,['source_id','url','span_sha256','captured_at']) || !id(citation.source_id)
        || !['https:','http:'].includes(url.protocol) || url.username || url.password
        || typeof citation.span_sha256 !== 'string' || !SHA256.test(citation.span_sha256)
        || typeof citation.captured_at !== 'string' || !Number.isFinite(Date.parse(citation.captured_at))) refuse('INVALID_PRIVATE_DISPATCH');
  }
  if (route.mode !== 'production' || route.config_digest !== request.config_digest
      || request.endpoint !== route.endpoint || request.body.model !== route.model
      || request.credential_generation !== route.credential_generation || !UUID.test(request.request_uuid)
      || request.total_budget_id !== route.total_budget_id
      || request.route_id !== route.route_id || !integer(request.body.max_tokens,1)
      || !SHA256.test(request.body_sha256) || !SHA256.test(request.citations_sha256) || !SHA256.test(request.binding_hash)
      || hash(JSON.stringify(request.body)) !== request.body_sha256 || hash(canonical(request.citations)) !== request.citations_sha256
      || task.max_requests > route.max_requests || task.spend_cap_microusd > route.spend_cap_microusd
      || task.allowed_data_classes.some(c => !route.allowed_data_classes.includes(c))
      || (request.citations.length && !task.allowed_data_classes.includes('public_source'))
      || task.owner_id !== request.owner_id || task.task_id !== request.task_id || task.conversation_id !== request.conversation_id) refuse('PRIVATE_DISPATCH_SCOPE_MISMATCH');
  const bindingHash = hash(canonical({ owner_id: task.owner_id, task_id: task.task_id, conversation_id: task.conversation_id,
    request_uuid: request.request_uuid, route, body_hash: request.body_sha256, citations: request.citations }));
  if (bindingHash !== request.binding_hash || !closed(request.admission,ADMISSION_FIELDS)
      || BINDING_FIELDS.some(field => request.admission[field] !== request[field])) refuse('PRIVATE_DISPATCH_SCOPE_MISMATCH');
  const input_bound = Buffer.byteLength(JSON.stringify(request.body)) + request.body.messages.length * 64;
  const token_reservation = input_bound + request.body.max_tokens;
  const cost_reservation = input_bound * route.input_microusd_per_token + request.body.max_tokens * route.output_microusd_per_token;
  if (!integer(input_bound,1) || !integer(token_reservation,1) || !integer(cost_reservation,1)
      || input_bound > Math.min(route.max_input_tokens,task.max_input_tokens)
      || request.body.max_tokens > Math.min(route.max_output_tokens,task.max_output_tokens)
      || token_reservation > task.max_tokens || cost_reservation > Math.min(route.spend_cap_microusd,task.spend_cap_microusd)
      || token_reservation !== request.reserved_tokens || cost_reservation !== request.reserved_cost_microusd) refuse('PRIVATE_DISPATCH_BUDGET_MISMATCH');
  const binding = { owner_id:task.owner_id,task_id:task.task_id,conversation_id:task.conversation_id,
    request_uuid:request.request_uuid,body_sha256:hash(JSON.stringify(request.body)),binding_hash:bindingHash,
    citations_sha256:hash(canonical(request.citations)),config_digest:route.config_digest,
    reserved_tokens:token_reservation,reserved_cost_microusd:cost_reservation,
    credential_generation:route.credential_generation,total_budget_id:route.total_budget_id };
  const request_digest = 'sha256:' + hash('aukora-prime.inference-request.v1\0' + canonicalJson(binding));
  const { operation,consumed_grant } = request.admission;
  try { validateContract('OperationProposal',operation); validateContract('ConsumedGrant',consumed_grant); }
  catch { refuse('INVALID_DISPATCH_ADMISSION'); }
  const state = inferenceBudgetState({ ...observation,route });
  const cap = BigInt(task.spend_cap_microusd);
  const limits = { max_requests:task.max_requests,max_input_tokens:Math.min(task.max_input_tokens,route.max_input_tokens),
    max_output_tokens:Math.min(task.max_output_tokens,route.max_output_tokens),max_total_tokens:task.max_tokens,
    max_request_ms:route.max_request_ms,task_spend_ceiling:{currency:'USD',amount:`${cap / 1000000n}.${String(cap % 1000000n).padStart(6,'0')}`} };
  const parameters = { version:1,kind:'prime-inference-request/v1',binding,request_digest,limits,total_budget:state.total_budget };
  const [whole,fraction=''] = operation.maximum_cost.amount.split('.');
  const maximum = BigInt(whole) * 100000000n + BigInt(fraction.padEnd(8,'0'));
  if (observation?.owner?.owner_id !== task.owner_id || operation.owner_id !== task.owner_id || operation.task_id !== task.task_id
      || operation.audience !== 'aukora-prime.inference' || operation.action_type !== 'inference.generate'
      || canonicalJson(operation.target_identity) !== canonicalJson(state.target_identity)
      || operation.expected_state_version !== state.state_version
      || canonicalJson(operation.canonical_parameters) !== canonicalJson(parameters)
      || canonicalJson(operation.provider_and_region) !== canonicalJson({provider:route.provider,region:route.region})
      || canonicalJson(operation.data_scope) !== canonicalJson(task.allowed_data_classes)
      || maximum < BigInt(cost_reservation) * 100n || maximum > BigInt(task.spend_cap_microusd) * 100n
      || request.admission.request_digest !== request_digest
      || consumed_grant.operation_id !== operation.operation_id || consumed_grant.owner_id !== operation.owner_id
      || consumed_grant.audience !== operation.audience || consumed_grant.authorization_epoch !== operation.authorization_epoch
      || consumed_grant.operation_digest !== operationDigest(operation)) refuse('DISPATCH_ADMISSION_MISMATCH');
  // C additionally binds agent_id and nested scope to its independently registered Task.
  const intent = { operation,consumed_grant,request_id:request.request_uuid,request_digest,binding,task,route,
    total_budget:observation.total_budget,input_bound,max_output_tokens:request.body.max_tokens,citations:request.citations };
  return { route,task,input_bound,token_reservation,cost_reservation,intent:structuredClone(intent) };
}
