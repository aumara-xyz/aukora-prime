// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJson } from '../../contracts/src/json.mjs';
import { hash, integer, refuse } from './policy.mjs';

const RESULT_DOMAIN = 'aukora-prime.inference-result.v1\0';
const RECEIPT_DOMAIN = 'aukora-prime.inference-receipt.v1\0';
const CLAIM_FIELDS = ['ok','status','consumed_grant','request_id','request_digest'];
const SETTLEMENT_FIELDS = ['ok','status','request_id','request_digest','receipt_digest','idempotent','reconciliation_required'];
const REPLY_FIELDS = ['text','source_ids','input_tokens','output_tokens'];
const digest = (domain, value) => 'sha256:' + hash(domain + canonicalJson(value));
const detach = value => JSON.parse(canonicalJson(value));
function closed(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
}
function checked(code, action) {
  try { return action(); } catch { refuse(code); }
}
function requireValue(condition) {
  if (!condition) refuse('INVALID_WORKER_EVIDENCE');
}

/** Build factual evidence only from the worker's immutable verified intent and observed reply. */
export function createWorkerEvidence(intent, replyOrNull, observed_at) {
  return checked('INVALID_WORKER_EVIDENCE', () => {
    canonicalJson(intent);
    canonicalJson(replyOrNull);
    requireValue(typeof observed_at === 'string' && new Date(observed_at).toISOString() === observed_at);
    requireValue(integer(intent.input_bound,1) && integer(intent.max_output_tokens,1)
      && integer(intent.binding.reserved_tokens,1) && integer(intent.binding.reserved_cost_microusd)
      && integer(intent.route.input_microusd_per_token) && integer(intent.route.output_microusd_per_token));
    let result_digest = null, usage = null;
    const completed = replyOrNull !== null;
    if (completed) {
      const reply = replyOrNull;
      requireValue(closed(reply,REPLY_FIELDS) && typeof reply.text === 'string'
        && BigInt(Buffer.byteLength(reply.text,'utf8')) <= BigInt(intent.max_output_tokens) * 16n
        && Array.isArray(reply.source_ids) && Array.isArray(intent.citations)
        && integer(reply.input_tokens) && integer(reply.output_tokens)
        && reply.input_tokens <= intent.input_bound && reply.output_tokens <= intent.max_output_tokens);
      const allowedSources = new Set(intent.citations.map(citation => citation.source_id));
      requireValue(reply.source_ids.every(source => typeof source === 'string' && allowedSources.has(source)));
      const tokens = BigInt(reply.input_tokens) + BigInt(reply.output_tokens);
      const cost = BigInt(reply.input_tokens) * BigInt(intent.route.input_microusd_per_token)
        + BigInt(reply.output_tokens) * BigInt(intent.route.output_microusd_per_token);
      requireValue(tokens <= BigInt(intent.binding.reserved_tokens)
        && cost <= BigInt(intent.binding.reserved_cost_microusd));
      usage = { input_tokens:reply.input_tokens,output_tokens:reply.output_tokens,cost_microusd:Number(cost) };
      result_digest = digest(RESULT_DOMAIN,{
        text:reply.text,source_ids:reply.source_ids,input_tokens:reply.input_tokens,output_tokens:reply.output_tokens
      });
    }
    const receipt = {
      version:1,kind:'prime-inference-effect/v1',operation_id:intent.operation.operation_id,
      operation_digest:intent.consumed_grant.operation_digest,grant_id:intent.consumed_grant.grant_id,
      request_id:intent.request_id,request_digest:intent.request_digest,
      owner_subject:intent.operation.target_identity.owner_subject,
      task_id:intent.binding.task_id,conversation_id:intent.binding.conversation_id,route_id:intent.route.route_id,
      config_digest:intent.binding.config_digest,credential_generation:intent.binding.credential_generation,
      total_budget_id:intent.binding.total_budget_id,body_sha256:intent.binding.body_sha256,
      outcome:completed ? 'completed' : 'outcome_unknown',result_digest,usage,
      reservation_retained:!completed,observed_at
    };
    const payload = { operation:intent.operation,consumed_grant:intent.consumed_grant,
      request_id:intent.request_id,request_digest:intent.request_digest,
      receipt,receipt_digest:digest(RECEIPT_DOMAIN,receipt) };
    return detach({receipt,payload});
  });
}

/** A boolean, partial acknowledgement or different grant cannot make HTTP eligible. */
export function validateWorkerClaimReply(intent, reply) {
  return checked('INVALID_WORKER_CLAIM_REPLY', () => {
    canonicalJson(intent);
    canonicalJson(reply);
    if (!closed(reply,CLAIM_FIELDS) || reply.ok !== true || reply.status !== 'DISPATCHED'
      || reply.request_id !== intent.request_id || reply.request_digest !== intent.request_digest
      || canonicalJson(reply.consumed_grant) !== canonicalJson(intent.consumed_grant)) {
      refuse('INVALID_WORKER_CLAIM_REPLY');
    }
    return detach(reply);
  });
}

/** Acknowledge only the exact committed evidence; old acknowledgements cannot clear newer evidence. */
export function validateWorkerSettlementReply(payload, reply) {
  return checked('INVALID_WORKER_SETTLEMENT_REPLY', () => {
    canonicalJson(payload);
    canonicalJson(reply);
    const outcome = payload.receipt.outcome;
    if (!['completed','outcome_unknown'].includes(outcome)
      || payload.receipt_digest !== digest(RECEIPT_DOMAIN,payload.receipt)
      || !closed(reply,SETTLEMENT_FIELDS) || reply.ok !== true
      || reply.status !== (outcome === 'completed' ? 'COMPLETED' : 'OUTCOME_UNKNOWN')
      || reply.request_id !== payload.request_id || reply.request_digest !== payload.request_digest
      || reply.receipt_digest !== payload.receipt_digest || typeof reply.idempotent !== 'boolean'
      || reply.reconciliation_required !== (outcome === 'outcome_unknown')) {
      refuse('INVALID_WORKER_SETTLEMENT_REPLY');
    }
    return detach(reply);
  });
}
