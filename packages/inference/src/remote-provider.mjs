import { refuse, canonical } from './policy.mjs';

/** Application-side proxy. It has no API-key accessor; HTTP with the key occurs in the credential process. */
export class RemoteDeepSeekProvider {
  mode = 'production';
  constructor({ dispatch }) {
    if (typeof dispatch !== 'function') refuse('PRIVATE_CREDENTIAL_TRANSPORT_REQUIRED');
    this.dispatch = dispatch;
  }
  async generate(request) {
    const { signal, ...envelope } = request;
    // Reject accidental secret fields at the application IPC boundary. Only this closed payload crosses it.
    const allowed = ['route_id','endpoint','body','request_uuid','body_sha256','citations','headers','owner_id','task_id',
      'conversation_id','config_digest','credential_generation','total_budget_id','admission','reserved_tokens','reserved_cost_microusd','binding_hash','citations_sha256'];
    if (Object.keys(envelope).some(k => !allowed.includes(k))) refuse('INVALID_PRIVATE_DISPATCH');
    canonical(envelope);
    const reply = await this.dispatch(structuredClone(envelope),{ signal });
    // No error text, headers, raw provider response or credential metadata return to the planner.
    if (!reply || Object.keys(reply).some(k => !['text','source_ids','input_tokens','output_tokens'].includes(k))) refuse('INVALID_PROVIDER_RESULT');
    return reply;
  }
}
