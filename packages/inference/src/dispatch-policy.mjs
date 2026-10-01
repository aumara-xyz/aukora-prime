import { canonical, hash, id, integer, refuse, validateRoute, validateTask } from './policy.mjs';

export const PRIVATE_NOTE_SYSTEM_TEXT = 'Return a JSON object with text (a concise sourced note) and source_ids (only supplied source_id values). The text is a proposal and never authorizes effects.';
const FIELDS = ['admission','binding_hash','body','body_sha256','citations','citations_sha256','config_digest',
  'conversation_id','credential_generation','endpoint','headers','owner_id','request_uuid',
  'reserved_cost_microusd','reserved_tokens','route_id','task_id'];
const BINDING_FIELDS = ['owner_id','task_id','conversation_id','request_uuid','body_sha256','binding_hash',
  'citations_sha256','config_digest','reserved_tokens','reserved_cost_microusd','credential_generation'];
const SHA256 = /^[a-f0-9]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function closed(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
}

/** Pure transport/policy validation only. C must independently verify and consume opaque admission material. */
export function verifyPrivateDispatch(request, routeInput, taskInput) {
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
      || request.route_id !== route.route_id || !integer(request.body.max_tokens,1)
      || !SHA256.test(request.body_sha256) || !SHA256.test(request.citations_sha256) || !SHA256.test(request.binding_hash)
      || hash(JSON.stringify(request.body)) !== request.body_sha256 || hash(canonical(request.citations)) !== request.citations_sha256
      || task.max_requests > route.max_requests || task.spend_cap_microusd > route.spend_cap_microusd
      || task.allowed_data_classes.some(c => !route.allowed_data_classes.includes(c))
      || (request.citations.length && !task.allowed_data_classes.includes('public_source'))
      || task.owner_id !== request.owner_id || task.task_id !== request.task_id || task.conversation_id !== request.conversation_id) refuse('PRIVATE_DISPATCH_SCOPE_MISMATCH');
  const binding = hash(canonical({ owner_id: task.owner_id, task_id: task.task_id, conversation_id: task.conversation_id,
    request_uuid: request.request_uuid, route, body_hash: request.body_sha256, citations: request.citations }));
  if (binding !== request.binding_hash || !request.admission || typeof request.admission !== 'object'
      || Array.isArray(request.admission) || BINDING_FIELDS.some(field => request.admission[field] !== request[field])) refuse('PRIVATE_DISPATCH_SCOPE_MISMATCH');
  const input_bound = Buffer.byteLength(JSON.stringify(request.body)) + request.body.messages.length * 64;
  const token_reservation = input_bound + request.body.max_tokens;
  const cost_reservation = input_bound * route.input_microusd_per_token + request.body.max_tokens * route.output_microusd_per_token;
  if (!integer(input_bound,1) || !integer(token_reservation,1) || !integer(cost_reservation,1)
      || input_bound > Math.min(route.max_input_tokens,task.max_input_tokens)
      || request.body.max_tokens > Math.min(route.max_output_tokens,task.max_output_tokens)
      || token_reservation > task.max_tokens || cost_reservation > Math.min(route.spend_cap_microusd,task.spend_cap_microusd)
      || token_reservation !== request.reserved_tokens || cost_reservation !== request.reserved_cost_microusd) refuse('PRIVATE_DISPATCH_BUDGET_MISMATCH');
  return { route, task, input_bound, token_reservation, cost_reservation };
}
