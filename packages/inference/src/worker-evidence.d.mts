import type { OperationProposal, ConsumedGrant, Digest } from '@aukora-prime/contracts';
import type { DispatchBinding, LocalTask, LocalRoute, TotalTestingBudget, SourceCitation, ProviderReply } from './index.mjs';
export interface WorkerIntent {
 operation:OperationProposal;consumed_grant:ConsumedGrant;request_id:string;request_digest:Digest;
 binding:DispatchBinding;task:LocalTask;route:LocalRoute;total_budget:TotalTestingBudget;
 input_bound:number;max_output_tokens:number;citations:SourceCitation[];
}
export type WorkerPhase = 'intent_committed'|'claim_started'|'claimed'|'http_started'|'outcome_recorded';
export interface WorkerClaimReply {
 ok:true;status:'DISPATCHED';consumed_grant:ConsumedGrant;request_id:string;request_digest:Digest;
}
export interface WorkerReceipt {
 version:1;kind:'prime-inference-effect/v1';operation_id:string;operation_digest:Digest;grant_id:string;
 request_id:string;request_digest:Digest;owner_subject:string;task_id:string;conversation_id:string;route_id:'externalDeepSeek';
 config_digest:string;credential_generation:number;total_budget_id:string;body_sha256:string;
 outcome:'completed'|'outcome_unknown';result_digest:Digest|null;
 usage:{input_tokens:number;output_tokens:number;cost_microusd:number}|null;reservation_retained:boolean;observed_at:string;
}
export interface WorkerSettlementPayload {
 operation:OperationProposal;consumed_grant:ConsumedGrant;request_id:string;request_digest:Digest;
 receipt:WorkerReceipt;receipt_digest:Digest;
}
export interface WorkerSettlementReply {
 ok:true;status:'COMPLETED'|'OUTCOME_UNKNOWN';request_id:string;request_digest:Digest;receipt_digest:Digest;
 idempotent:boolean;reconciliation_required:boolean;
}
export interface PendingWorkerSettlement {
 sequence:number;method:'settleInference'|'reconcileInferenceSettlement';payload:WorkerSettlementPayload;
}
export function createWorkerEvidence(intent:WorkerIntent,reply:ProviderReply|null,observed_at:string):{receipt:WorkerReceipt;payload:WorkerSettlementPayload};
export function validateWorkerClaimReply(intent:WorkerIntent,reply:unknown):WorkerClaimReply;
export function validateWorkerSettlementReply(payload:WorkerSettlementPayload,reply:unknown):WorkerSettlementReply;
