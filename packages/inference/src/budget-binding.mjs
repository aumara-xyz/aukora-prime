// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJson } from '../../contracts/src/json.mjs';
import { hash, id, integer, refuse, validateRoute } from './policy.mjs';

const TOTAL_FIELDS = ['approval_reference','budget_id','ceiling','owner_id','provider','route_id','version'];
const POLICY_DOMAIN = 'aukora-prime.inference-budget-policy.v1\0';
const STATE_DOMAIN = 'aukora-prime.inference-state.v1\0';
const digest = (domain, value) => 'sha256:' + hash(domain + canonicalJson(value));
function closed(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
}
function jsonData(value, code) {
  try { return canonicalJson(value); } catch { refuse(code); }
}

/** Construction only, before review/signing. Preserves the ledger's existing microusd rounding. */
export function normalizeTotalBudget(value) {
  jsonData(value,'INVALID_TOTAL_BUDGET');
  if (!closed(value,TOTAL_FIELDS) || value.version !== 1
      || ![value.budget_id,value.owner_id,value.approval_reference].every(id)
      || value.provider !== 'deepseek' || value.route_id !== 'externalDeepSeek'
      || !closed(value.ceiling,['amount','currency']) || value.ceiling.currency !== 'USD'
      || typeof value.ceiling.amount !== 'string' || value.ceiling.amount.length > 32
      || !/^\d+(?:\.\d{1,8})?$/u.test(value.ceiling.amount)) refuse('INVALID_TOTAL_BUDGET');
  const [whole,fraction=''] = value.ceiling.amount.split('.');
  const precise = BigInt(whole) * 100000000n + BigInt(fraction.padEnd(8,'0'));
  const micros = precise / 100n;
  if (micros < 1n || micros > BigInt(Number.MAX_SAFE_INTEGER)) refuse('INVALID_TOTAL_BUDGET');
  return { ...value,ceiling:{currency:'USD',amount:`${micros / 1000000n}.${String(micros % 1000000n).padStart(6,'0')}`} };
}

function storedDescriptor(value) {
  const normalized = normalizeTotalBudget(value);
  // Signed/observed data must already contain the exact stored six-decimal amount.
  // In particular, never accept the eight-field requireTotalBudget accounting view.
  if (canonicalJson(value) !== canonicalJson(normalized)) refuse('TOTAL_BUDGET_NOT_NORMALIZED');
  return normalized;
}

/** Hash exactly the immutable stored seven fields, including approval_reference. */
export function totalBudgetPolicyDigest(descriptor) {
  return digest(POLICY_DOMAIN,storedDescriptor(descriptor));
}

/** Existing operation total_budget shape; not an available-spend observation or an approval. */
export function totalBudgetBinding(descriptor) {
  const stored = storedDescriptor(descriptor);
  return { budget_id:stored.budget_id,ceiling:stored.ceiling,policy_digest:digest(POLICY_DOMAIN,stored) };
}

/**
 * Pure derivation from trusted private observations, never from app operation fields.
 * owner is C's registered owner_id/subject pair; credential_generation is independently
 * read from the live vault. route must be qualified against the approved configuration.
 * This function performs no authentication, key read, I/O, approval or budget reservation.
 */
export function inferenceBudgetState({ owner, route:routeInput, total_budget, credential_generation }) {
  jsonData({owner,route:routeInput,total_budget,credential_generation},'INVALID_INFERENCE_BUDGET_STATE');
  if (!closed(owner,['owner_id','subject']) || !id(owner.owner_id)
      || typeof owner.subject !== 'string' || !/^aukora:1:[a-f0-9]{64}$/u.test(owner.subject)
      || !integer(credential_generation,1)) refuse('INVALID_INFERENCE_BUDGET_STATE');
  const route = validateRoute(routeInput), descriptor = storedDescriptor(total_budget);
  if (route.mode !== 'production' || route.credential_generation !== credential_generation
      || owner.owner_id !== descriptor.owner_id || route.total_budget_id !== descriptor.budget_id
      || route.provider !== descriptor.provider || route.route_id !== descriptor.route_id) refuse('INFERENCE_BUDGET_STATE_MISMATCH');
  const bound = totalBudgetBinding(descriptor);
  const target_identity = { version:1,kind:'prime-inference-route/v1',owner_subject:owner.subject,
    route_id:route.route_id,provider:route.provider,endpoint:route.endpoint,model:route.model,region:route.region,
    config_digest:route.config_digest,credential_generation,total_budget_id:descriptor.budget_id };
  const state_version = digest(STATE_DOMAIN,{target_identity,policy_digest:bound.policy_digest});
  return { target_identity,state_version,total_budget:bound };
}
