import { refuse } from './policy.mjs';

/** Supply the pinned DSH LlmAdapter class; preserves its stream contract without a new agent loop. */
export function createDshAdapter(LlmAdapter, { gateway, bindRequest, attributionHeaders }) {
  if (typeof LlmAdapter !== 'function' || typeof bindRequest !== 'function' || typeof attributionHeaders !== 'function') refuse('DSH_HOST_BINDING_REQUIRED');
  return new class extends LlmAdapter {
    providerInfo(provider) { return { id: provider, name: 'DeepSeek' }; }
    async listModels(provider) {
      if (provider !== 'externalDeepSeek') refuse('ROUTE_UNAVAILABLE');
      return [{ provider, id: gateway.route.model, name: gateway.route.model }];
    }
    providerRetryPolicy() {
      return Object.freeze({ mode: 'normal', maxRetries: 0, retryableCodes: Object.freeze(['TRANSPORT']),
        initialDelayMs: 500, maxDelayMs: 10000, jitterRatio: 0 });
    }
    async resolveModel(provider, model) {
      if (provider !== 'externalDeepSeek' || model !== gateway.route.model) refuse('ROUTE_UNAVAILABLE');
      return { provider, id: model, name: model };
    }
    async *stream(options) {
      if (options.provider !== 'externalDeepSeek' || options.model !== gateway.route.model) refuse('ROUTE_UNAVAILABLE');
      if (options.tools?.length) refuse('TOOL_PROPOSALS_UNQUALIFIED');
      // This callback belongs to the authenticated host, never the model. It selects task-bound spans.
      const request = await bindRequest(options);
      if ((options.sessionId !== undefined && request.conversation_id !== options.sessionId)
          || (options.maxTokens !== undefined && request.max_output_tokens > options.maxTokens)) refuse('DSH_REQUEST_BINDING_MISMATCH');
      const result = await gateway.generate(request,{ signal: options.signal, attribution_headers: attributionHeaders() });
      if (result.outcome !== 'completed') refuse(result.error);
      const text = result.proposal.text;
      yield { type: 'block-start', index: 0, blockType: 'text' };
      yield { type: 'text-delta', index: 0, text };
      yield { type: 'block-end', index: 0, block: { type: 'text', text } };
      yield { type: 'usage', usage: { inputTokens: result.usage.input_tokens, outputTokens: result.usage.output_tokens } };
      yield { type: 'finish', reason: { kind: 'stop' }, replayState: { response: { aukora_prime: {
        request_uuid: result.request_uuid, body_sha256: result.receipt.body_sha256,
        source_citation: result.receipt.source_citation, citations: result.receipt.citations,
      } } } };
    }
  };
}

export function mountDshInference(ctx, LlmAdapter, bindings) {
  const adapter = createDshAdapter(LlmAdapter,bindings);
  ctx.llm.registerAdapter(['externalDeepSeek'],adapter);
  return adapter;
}
