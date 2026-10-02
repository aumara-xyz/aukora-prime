import { resolve, join } from 'node:path';
import { createRequire } from 'node:module';
import { recordOrRefuse, modelRequestReceiptMatches, readRecordedModelRequest } from './owned/model-request-store.ts';
import { validateRoute, prepareRequest, hash, canonical, refuse, integer, InferenceRefusal } from './policy.mjs';

const { version } = createRequire(import.meta.url)('../package.json');
export const mockAttributionHeaders = () => ({ 'user-agent': `aukora-prime/${version} (+https://github.com/aumara-xyz/aukora-prime)` });

export class ExternalDeepSeekGateway {
  constructor({ route, ledger, request_home, provider, authorize_dispatch }) {
    this.route = Object.freeze(validateRoute(route));
    if (!request_home || !request_home.startsWith('/')) refuse('REQUEST_STORE_REQUIRED');
    this.ledger = ledger;
    this.request_home = resolve(request_home);
    this.provider = provider;
    this.authorize_dispatch = authorize_dispatch;
  }
  status() {
    return { route_id: 'externalDeepSeek', mode: this.route.mode, provider: 'deepseek', model: this.route.model,
      available: (this.route.mode === 'mock' && this.provider?.mode === 'mock')
        || (this.route.mode === 'production' && this.provider?.mode === 'production' && typeof this.authorize_dispatch === 'function'),
      pending: ['approved_api_credentials', 'approved_spend_cap', 'approved_data_scope', 'qualified_provider_terms_and_served_version'] };
  }
  async generate(request, { signal, attribution_headers = mockAttributionHeaders() } = {}) {
    if (!attribution_headers || Object.keys(attribution_headers).join(',') !== 'user-agent'
        || typeof attribution_headers['user-agent'] !== 'string' || /[\r\n]/u.test(attribution_headers['user-agent'])) refuse('INVALID_ATTRIBUTION');
    const task = this.ledger.task(request.owner_id,request.task_id);
    if (canonical(this.ledger.route(request.owner_id,request.task_id)) !== canonical(this.route)) refuse('TASK_ROUTE_CHANGED');
    const prepared = prepareRequest(task,this.route,request);
    const production = this.route.mode === 'production' && this.provider?.mode === 'production';
    if ((!production && (this.route.mode !== 'mock' || this.provider?.mode !== 'mock'))
        || (production && typeof this.authorize_dispatch !== 'function')) refuse('CREDENTIALS_AND_SPEND_APPROVAL_PENDING');
    if (signal?.aborted) refuse('CANCELLED_BEFORE_DISPATCH');
    let admission;
    if (production) {
      this.ledger.requireTotalBudget(task.owner_id,this.route.total_budget_id);
      // This is a trusted C-backed host hook, never model-authored policy or a frontend boolean.
      admission = await this.authorize_dispatch({ owner_id: task.owner_id, task_id: task.task_id,
        conversation_id: task.conversation_id, request_uuid: request.request_uuid, body_sha256: prepared.body_hash,
        binding_hash: prepared.binding_hash, citations_sha256: hash(canonical(prepared.citations)),
        config_digest: this.route.config_digest, reserved_tokens: prepared.token_reservation,
        reserved_cost_microusd: prepared.cost_reservation, credential_generation: this.route.credential_generation,
        total_budget_id: this.route.total_budget_id });
      if (!admission || admission.request_uuid !== request.request_uuid || admission.body_sha256 !== prepared.body_hash
          || admission.owner_id !== task.owner_id || admission.task_id !== task.task_id || admission.conversation_id !== task.conversation_id
          || admission.config_digest !== this.route.config_digest || admission.binding_hash !== prepared.binding_hash
          || admission.citations_sha256 !== hash(canonical(prepared.citations))
          || admission.credential_generation !== this.route.credential_generation
          || admission.total_budget_id !== this.route.total_budget_id
          || admission.reserved_tokens !== prepared.token_reservation
          || admission.reserved_cost_microusd !== prepared.cost_reservation) refuse('DISPATCH_APPROVAL_REQUIRED');
    }
    const home = join(this.request_home,hash(JSON.stringify([task.owner_id,task.task_id,task.conversation_id])));
    const sessionId = task.conversation_id;
    const receipt = this.ledger.reserve(task,request.request_uuid,prepared,() => {
      const receipt = recordOrRefuse({ dshHome: home, sessionId, request: { sessionId, body: prepared.body } });
      if (!modelRequestReceiptMatches(receipt,{ sessionId, body: prepared.body })
          || !readRecordedModelRequest({ dshHome: home, sessionId, receipt })) refuse('BODY_RECEIPT_MISMATCH');
      return { ...receipt, request_uuid: request.request_uuid, body_sha256: prepared.body_hash,
        source_citation: { sessionId, turn: receipt.turn, sha256: hash(receipt.line), requestId: JSON.parse(receipt.line).requestId },
        citations: prepared.citations };
    });
    // Freeze exact wire bytes. The private JSONL/ledger receipt above retains plaintext request content.
    // Console/planner errors remain fixed codes; completed ledger results also retain the reply text.
    const body = JSON.parse(JSON.stringify(prepared.body));
    if (hash(JSON.stringify(body)) !== receipt.body_sha256) refuse('BODY_RECEIPT_MISMATCH');
    this.ledger.transition(task.owner_id,task.task_id,request.request_uuid,'reserved','dispatched');
    const controller = new AbortController();
    let timer, abortListener;
    const interruption = new Promise((_, reject) => {
      const abort = code => { controller.abort(); reject(new InferenceRefusal(code)); };
      timer = setTimeout(() => abort('PROVIDER_TIMEOUT'),this.route.max_request_ms);
      abortListener = () => abort('CANCELLED_AFTER_DISPATCH');
      signal?.addEventListener('abort',abortListener,{ once: true });
      if (signal?.aborted) abortListener();
    });
    try {
      const reply = await Promise.race([interruption, Promise.resolve().then(() => this.provider.generate({
        route_id: 'externalDeepSeek', endpoint: this.route.endpoint, body, request_uuid: request.request_uuid,
        body_sha256: receipt.body_sha256, citations: structuredClone(prepared.citations), signal: controller.signal,
        headers: { ...attribution_headers },
        owner_id: task.owner_id, task_id: task.task_id, conversation_id: task.conversation_id,
        config_digest: this.route.config_digest ?? null, credential_generation: this.route.credential_generation ?? null,
        total_budget_id: this.route.total_budget_id ?? null,
        admission, reserved_tokens: prepared.token_reservation, reserved_cost_microusd: prepared.cost_reservation,
        binding_hash: prepared.binding_hash, citations_sha256: hash(canonical(prepared.citations)),
      }))]);
      if (!reply || typeof reply.text !== 'string' || !integer(reply.input_tokens) || !integer(reply.output_tokens)
          || reply.input_tokens > prepared.input_bound || reply.output_tokens > request.max_output_tokens
          || Buffer.byteLength(reply.text) > request.max_output_tokens * 16
          || !Array.isArray(reply.source_ids) || reply.source_ids.some(id => !prepared.citations.some(c => c.source_id === id))) refuse('INVALID_PROVIDER_RESULT');
      const cost = reply.input_tokens * this.route.input_microusd_per_token + reply.output_tokens * this.route.output_microusd_per_token;
      const result = { outcome: 'completed', request_uuid: request.request_uuid, route_id: 'externalDeepSeek', mode: this.route.mode,
        proposal: { text: reply.text, source_ids: reply.source_ids, grantsAuthority: false },
        usage: { input_tokens: reply.input_tokens, output_tokens: reply.output_tokens, cost_microusd: cost },
        receipt, omitted: prepared.omitted };
      this.ledger.settle(task.owner_id,task.task_id,request.request_uuid,reply.input_tokens + reply.output_tokens,cost,result);
      return result;
    } catch (error) {
      // Error text can contain credentials or request content. Only fixed codes cross the planner boundary.
      this.ledger.transition(task.owner_id,task.task_id,request.request_uuid,'dispatched','outcome_unknown');
      return { outcome: 'outcome_unknown', request_uuid: request.request_uuid, receipt,
        error: error instanceof InferenceRefusal && ['PROVIDER_TIMEOUT','CANCELLED_AFTER_DISPATCH','INVALID_PROVIDER_RESULT'].includes(error.code)
          ? error.code : 'PROVIDER_UNAVAILABLE', reservation_retained: true };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort',abortListener);
    }
  }
}

/** No fetch, credentials, socket or secondary orchestration loop. */
export class MockDeepSeekProvider {
  mode = 'mock';
  async generate({ body, citations, signal }) {
    if (signal.aborted) throw new Error('mock cancelled');
    return { text: 'Mock sourced note.', input_tokens: Buffer.byteLength(JSON.stringify(body)), output_tokens: 18,
      source_ids: citations.map(c => c.source_id) };
  }
}
