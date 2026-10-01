// Server-only module. Never import into the renderer, planner or the generic application host.
import { hash, integer, refuse } from './policy.mjs';

const CHAT_COMPLETIONS = 'https://api.deepseek.com/chat/completions';
const MAX_RESPONSE_BYTES = 1024 * 1024;

async function boundedJson(response, maxBytes) {
  if (!response.body || (response.headers.get('content-length') && Number(response.headers.get('content-length')) > maxBytes)) refuse('PROVIDER_RESPONSE_LIMIT');
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { await reader.cancel(); refuse('PROVIDER_RESPONSE_LIMIT'); }
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch { refuse('INVALID_PROVIDER_RESPONSE'); }
  finally { reader.releaseLock(); }
}

/** Native HTTPS wire code runs only where useCredential is available: the separated credential process. */
export class DeepSeekHttpProvider {
  constructor({ useCredential, transport = globalThis.fetch }) {
    if (typeof useCredential !== 'function' || typeof transport !== 'function') refuse('CREDENTIAL_SERVICE_UNAVAILABLE');
    this.useCredential = useCredential;
    this.transport = transport;
  }
  async generate(request) {
    if (request.endpoint !== 'https://api.deepseek.com' || request.route_id !== 'externalDeepSeek'
        || hash(JSON.stringify(request.body)) !== request.body_sha256
        || !request.body || Object.keys(request.body).some(k => !['model','messages','max_tokens','stream','response_format'].includes(k))
        || request.body.stream !== false || request.body.response_format?.type !== 'json_object'
        || !integer(request.body.max_tokens,1) || !Array.isArray(request.body.messages)
        || request.body.messages.some(m => !m || !['system','user','assistant'].includes(m.role) || typeof m.content !== 'string'
          || Object.keys(m).some(k => !['role','content'].includes(k)))) refuse('INVALID_PRIVATE_DISPATCH');
    if (request.signal?.aborted) refuse('CANCELLED_BEFORE_DISPATCH');
    return this.useCredential(request.owner_id,request.credential_generation,async secret => {
      if (typeof secret !== 'string' || secret.length < 8 || secret.length > 4096 || !/^[\x21-\x7e]+$/u.test(secret)) refuse('CREDENTIAL_INVALID');
      let response;
      try {
        response = await this.transport(CHAT_COMPLETIONS,{ method: 'POST', redirect: 'error', credentials: 'omit',
          headers: { 'content-type': 'application/json', 'user-agent': request.headers['user-agent'], authorization: 'Bearer ' + secret },
          body: JSON.stringify(request.body), signal: request.signal });
      } catch { refuse('PROVIDER_TRANSPORT_FAILED'); }
      // Error bodies may echo credentials/input. Never parse, log or return them.
      if (!response.ok || response.redirected || (response.url && response.url !== CHAT_COMPLETIONS)) {
        try { await response.body?.cancel(); } catch {}
        refuse('PROVIDER_REQUEST_FAILED');
      }
      const wire = await boundedJson(response,Math.min(MAX_RESPONSE_BYTES,request.body.max_tokens * 32 + 16384));
      if (!Array.isArray(wire.choices) || wire.choices.length !== 1 || wire.model !== (request.served_version ?? request.body.model)
          || !integer(wire.usage?.prompt_tokens) || !integer(wire.usage?.completion_tokens)
          || wire.usage.completion_tokens > request.body.max_tokens
          || wire.choices[0].message?.tool_calls?.length
          || !['stop','length'].includes(wire.choices[0].finish_reason)
          || typeof wire.choices[0].message?.content !== 'string') refuse('INVALID_PROVIDER_RESPONSE');
      let proposal; try { proposal = JSON.parse(wire.choices[0].message.content); } catch { refuse('INVALID_MODEL_PROPOSAL'); }
      if (!proposal || Object.keys(proposal).sort().join(',') !== 'source_ids,text' || typeof proposal.text !== 'string'
          || proposal.text.includes(secret) || !Array.isArray(proposal.source_ids)
          || proposal.source_ids.some(id => !request.citations.some(c => c.source_id === id))) refuse('INVALID_MODEL_PROPOSAL');
      return { text: proposal.text, source_ids: proposal.source_ids,
        input_tokens: wire.usage.prompt_tokens, output_tokens: wire.usage.completion_tokens };
    });
  }
}
