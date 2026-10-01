import { createHash } from 'node:crypto';

export class InferenceRefusal extends Error {
  constructor(code) { super(code); this.name = 'InferenceRefusal'; this.code = code; }
}
export const refuse = code => { throw new InferenceRefusal(code); };
export const hash = value => createHash('sha256').update(value).digest('hex');
export const integer = (value, min = 0) => Number.isSafeInteger(value) && value >= min;
export const id = value => typeof value === 'string' && value.length > 0 && value.length <= 256;
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  const out = JSON.stringify(value);
  if (out === undefined) refuse('INVALID_REQUEST');
  return out;
}

export function validateRoute(route) {
  if (route?.route_id !== 'externalDeepSeek' || route.provider !== 'deepseek'
      || route.endpoint !== 'https://api.deepseek.com' || !id(route.model)
      || !Array.isArray(route.allowed_data_classes) || !route.allowed_data_classes.length
      || route.allowed_data_classes.some(c => !['conversation', 'public_source'].includes(c))
      || !integer(route.max_input_tokens, 1) || !integer(route.max_output_tokens, 1)
      || !integer(route.max_requests,1) || !integer(route.spend_cap_microusd) || !id(route.region)
      || !integer(route.max_request_ms, 1) || route.max_request_ms > 60000
      || !['mock', 'unavailable','production'].includes(route.mode)
      || !integer(route.input_microusd_per_token) || !integer(route.output_microusd_per_token)) refuse('INVALID_ROUTE');
  if (route.mode === 'production' && (route.transport_status !== 'approved'
      || !integer(route.spend_cap_microusd,1)
      || !integer(route.input_microusd_per_token,1) || !integer(route.output_microusd_per_token,1)
      || !id(route.pricing_evidence_id) || !id(route.terms_evidence_id) || !id(route.served_version)
      || !integer(route.credential_generation,1) || !/^sha256:[a-f0-9]{64}$/u.test(route.config_digest))) refuse('PRODUCTION_ROUTE_NOT_QUALIFIED');
  // Mock rates are synthetic. Production rates require separately qualified evidence and owner approval.
  return structuredClone(route);
}

export function validateTask(task) {
  if (![task?.owner_id, task?.task_id, task?.conversation_id].every(id)
      || !integer(task.max_requests, 1) || !integer(task.max_tokens, 1)
      || !integer(task.spend_cap_microusd) || task.route_id !== 'externalDeepSeek'
      || !integer(task.max_input_tokens,1) || !integer(task.max_output_tokens,1)
      || !Array.isArray(task.allowed_data_classes)
      || task.allowed_data_classes.some(c => !['conversation','public_source'].includes(c))) refuse('INVALID_TASK');
  return structuredClone(task);
}

// Inputs are selected by the host. Unlisted classes are omitted; scope violations refuse the whole request.
export function prepareRequest(task, route, request) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(request?.request_uuid)
      || request.owner_id !== task.owner_id || request.task_id !== task.task_id
      || request.conversation_id !== task.conversation_id || !Array.isArray(request.fragments)
      || request.fragments.length > 128 || !integer(request.max_output_tokens, 1)
      || request.max_output_tokens > Math.min(route.max_output_tokens,task.max_output_tokens)) refuse('INVALID_REQUEST_SCOPE');
  const messages = [], citations = [], omitted = [];
  for (const fragment of request.fragments) {
    if (fragment?.owner_id !== task.owner_id || fragment.task_id !== task.task_id
        || fragment.conversation_id !== task.conversation_id) refuse('SCOPE_MISMATCH');
    if (!route.allowed_data_classes.includes(fragment.data_class) || !task.allowed_data_classes.includes(fragment.data_class)) {
      omitted.push({ reason: 'DATA_CLASS_NOT_ALLOWED' }); continue;
    }
    if (typeof fragment.text !== 'string' || Buffer.byteLength(fragment.text) > 1024 * 1024
        || !['user', 'assistant'].includes(fragment.role)) refuse('INVALID_FRAGMENT');
    // Classification is the primary boundary. This also rejects common accidentally pasted credential forms.
    if (/\b(?:sk-[A-Za-z0-9_-]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._~-]{16,})/u.test(fragment.text)) refuse('SECRET_DETECTED');
    if (fragment.data_class === 'public_source') {
      const cite = fragment.citation;
      let url; try { url = new URL(cite?.url); } catch { refuse('INVALID_CITATION'); }
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password
          || !id(cite.source_id) || cite.span_sha256 !== hash(fragment.text)
          || !Number.isFinite(Date.parse(cite.captured_at))) refuse('INVALID_CITATION');
      citations.push({ source_id: cite.source_id, url: url.href, span_sha256: cite.span_sha256, captured_at: cite.captured_at });
    }
    messages.push({ role: fragment.role, content: fragment.data_class === 'public_source'
      ? `[source_id:${fragment.citation.source_id}]\n${fragment.text}` : fragment.text });
  }
  if (!messages.length) refuse('NO_ALLOWED_INPUT');
  const body = { model: route.model, messages: [{ role: 'system', content: 'Return a JSON object with text (a concise sourced note) and source_ids (only supplied source_id values). The text is a proposal and never authorizes effects.' },...messages],
    max_tokens: request.max_output_tokens, stream: false, response_format: { type: 'json_object' }, thinking: { type: 'disabled' } };
  // UTF-8 bytes plus message framing is a deliberately conservative admission bound; no chars/4 estimate.
  const input_bound = Buffer.byteLength(JSON.stringify(body)) + body.messages.length * 64;
  const token_reservation = input_bound + request.max_output_tokens;
  const cost_reservation = input_bound * route.input_microusd_per_token + request.max_output_tokens * route.output_microusd_per_token;
  if (input_bound > Math.min(route.max_input_tokens,task.max_input_tokens) || !integer(token_reservation) || !integer(cost_reservation)) refuse('TOKEN_CAP');
  const body_hash = hash(JSON.stringify(body));
  const binding_hash = hash(canonical({ owner_id: task.owner_id, task_id: task.task_id, conversation_id: task.conversation_id,
    request_uuid: request.request_uuid, route, body_hash, citations }));
  return { body, body_hash, binding_hash, citations, omitted, input_bound, token_reservation, cost_reservation };
}
