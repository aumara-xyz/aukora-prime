import type { LocalRoute, TotalTestingBudget } from './index.mjs';
import type { Digest } from '@aukora-prime/contracts';

/** Construct before owner review; signed/stored inputs must not be renormalized. */
export function normalizeTotalBudget(value:TotalTestingBudget):TotalTestingBudget;
/** Requires the exact seven-field descriptor with an already normalized six-decimal USD ceiling. */
export function totalBudgetPolicyDigest(descriptor:TotalTestingBudget):Digest;
export type TotalBudgetBinding = {budget_id:string;ceiling:{currency:'USD';amount:string};policy_digest:Digest};
export function totalBudgetBinding(descriptor:TotalTestingBudget):TotalBudgetBinding;
export type InferenceTargetIdentity = {
 version:1;kind:'prime-inference-route/v1';owner_subject:string;route_id:'externalDeepSeek';provider:'deepseek';
 endpoint:'https://api.deepseek.com';model:string;region:string;config_digest:Digest;credential_generation:number;total_budget_id:string;
};
export interface InferenceBudgetState {
 target_identity:InferenceTargetIdentity;state_version:Digest;total_budget:TotalBudgetBinding;
}
/** Pure data helper: caller supplies independent C, qualified-policy, protected-ledger and live-vault observations. */
export function inferenceBudgetState(input:{owner:{owner_id:string;subject:string};route:LocalRoute;
 total_budget:TotalTestingBudget;credential_generation:number}):InferenceBudgetState;
