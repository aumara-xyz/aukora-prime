import { validateRoute, validateTask, integer, refuse } from './policy.mjs';

/** Exact decimal conversion: API billing is separate from ChatGPT/Codex credits. */
export function usdMicros(limit) {
  if (limit?.currency !== 'USD' || typeof limit.amount !== 'string' || !/^\d+(?:\.\d{1,8})?$/u.test(limit.amount)) refuse('INVALID_SPEND_CAP');
  const [whole, fraction = ''] = limit.amount.split('.');
  // Freeze permits eight decimals. Round the ceiling DOWN to our microusd unit, never enlarge it.
  const n = BigInt(whole) * 1000000n + BigInt(fraction.padEnd(8,'0')) / 100n;
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) refuse('INVALID_SPEND_CAP');
  return Number(n);
}

/** Local mock accounting is explicit host config; the frozen transport route stays unavailable for paid use. */
export function fromPrimeRoute(route, mock) {
  if (route?.version !== 1 || !['unavailable','approved'].includes(route.status)
      || !Array.isArray(route.allowed_tools) || route.allowed_tools.length || !integer(route.max_requests,1)) refuse('INVALID_ROUTE');
  return validateRoute({ route_id: route.route_id, provider: route.provider, endpoint: route.endpoint, model: route.model,
    allowed_data_classes: route.allowed_data_classes, max_input_tokens: route.max_input_tokens,
    max_output_tokens: route.max_output_tokens, max_request_ms: mock.max_request_ms,
    mode: mock.mode, input_microusd_per_token: mock.input_microusd_per_token,
    output_microusd_per_token: mock.output_microusd_per_token,
    max_requests: route.max_requests, spend_cap_microusd: usdMicros(route.task_spend_ceiling),
    region: route.region, transport_status: route.status });
}

/** Trusted owner/credential host only: callers must independently verify approval and qualification. */
export function fromQualifiedPrimeRoute(route, qualification) {
  if (route?.status !== 'approved') refuse('PRODUCTION_ROUTE_NOT_QUALIFIED');
  const base = fromPrimeRoute(route,{ ...qualification, mode: 'unavailable' });
  return validateRoute({ ...base, mode: 'production', pricing_evidence_id: qualification.pricing_evidence_id,
    terms_evidence_id: qualification.terms_evidence_id, served_version: qualification.served_version,
    credential_generation: qualification.credential_generation, config_digest: qualification.config_digest,
    total_budget_id: qualification.total_budget_id });
}

export function fromPrimeTask(task, route, { max_total_tokens } = {}) {
  if (task?.version !== 1 || !['pending','running'].includes(task.status)
      || !Array.isArray(task.allowed_data_classes) || !integer(task.max_input_tokens,1)
      || !integer(task.max_output_tokens,1)) refuse('INVALID_TASK');
  const max_requests = Math.min(task.max_requests,route.max_requests);
  const derived = (task.max_input_tokens + task.max_output_tokens) * max_requests;
  if (!integer(derived,1) || (max_total_tokens !== undefined && (!integer(max_total_tokens,1) || max_total_tokens > derived))) refuse('INVALID_TASK');
  return validateTask({ owner_id: task.owner_id, task_id: task.task_id, conversation_id: task.conversation_id,
    route_id: task.route_id, max_requests, max_tokens: max_total_tokens ?? derived,
    max_input_tokens: Math.min(task.max_input_tokens,route.max_input_tokens),
    max_output_tokens: Math.min(task.max_output_tokens,route.max_output_tokens),
    allowed_data_classes: task.allowed_data_classes.filter(c => route.allowed_data_classes.includes(c)),
    spend_cap_microusd: Math.min(usdMicros(task.task_spend_ceiling),route.spend_cap_microusd) });
}
