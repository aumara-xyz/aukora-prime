/** Prime contracts v1. Integration-owned, frozen 2026-10-01. */
export type JsonValue = null | boolean | string | number | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type Digest = `sha256:${string}`;
export type PrimeErrorCode = 'UNAVAILABLE'|'INVALID'|'UNAUTHORIZED'|'STALE'|'REVOKED'|'REPLAYED'|'EXPIRED'|'TARGET_MISMATCH'|'SCOPE_MISMATCH'|'CANCELLED'|'OUTCOME_UNKNOWN'|'RECONCILIATION_REQUIRED';
export interface CostLimit { readonly currency: 'USD'; readonly amount: string }
export interface Task {
 readonly version: 1; readonly task_id: string; readonly owner_id: string; readonly agent_id: string; readonly conversation_id: string;
 readonly status: 'pending'|'running'|'paused'|'completed'|'failed'|'cancelled';
 readonly created_at: string; readonly route_id: string | null; readonly allowed_data_classes: readonly string[];
 readonly max_input_tokens: number; readonly max_output_tokens: number; readonly max_requests: number;
 readonly task_spend_ceiling: CostLimit;
}
export interface OperationProposal {
 readonly version: 1; readonly operation_id: string; readonly task_id: string; readonly owner_id: string; readonly agent_id: string;
 readonly audience: string; readonly action_type: string; readonly target_identity: JsonValue;
 readonly canonical_parameters: JsonValue; readonly data_scope: readonly string[];
 readonly expected_state_version: string; readonly provider_and_region: { readonly provider: string; readonly region: string };
 readonly maximum_cost: CostLimit; readonly expiry: string; readonly nonce: string; readonly policy_version: string; readonly authorization_epoch: number;
}
export interface ApprovalProof {
 readonly version: 1; readonly operation_id: string; readonly operation_digest: Digest; readonly owner_id: string;
 readonly audience: string; readonly authorization_epoch: number; readonly expiry: string; readonly nonce: string;
 readonly material: ApprovalMaterial;
}
export interface ApprovalRequest {
 readonly domain: 'aukora:owner-approval-request:v1'; readonly subject: string;
 readonly activeControlDigest: string; readonly operationDigest: string; readonly challenge: string;
 readonly issuedAt: number; readonly expiresAt: number;
}
export type ApprovalMaterial = { readonly kind: 'owner_key'; readonly request: ApprovalRequest; readonly signature: string }
 | { readonly kind: 'passkey'; readonly credential_id: string; readonly client_data_json: string;
     readonly authenticator_data: string; readonly signature: string; readonly user_handle: string | null };
/** Presentation only. Never a signed approval. */
export type ApprovalTemplate = Omit<ApprovalProof, 'material'> & { readonly material:
 { readonly kind: 'owner_key'; readonly request: ApprovalRequest; readonly signature: '' } | { readonly kind: 'passkey' } };
export interface ConsumedGrant {
 readonly version: 1; readonly grant_id: string; readonly operation_id: string; readonly operation_digest: Digest;
 readonly owner_id: string; readonly audience: string; readonly authorization_epoch: number;
 readonly prepared_at: string; readonly reservation_id: string;
}
export interface ExecutionReceipt {
 readonly version: 1; readonly receipt_id: string; readonly operation_id: string; readonly task_id: string; readonly owner_id: string;
 readonly operation_digest: Digest; readonly grant_id: string; readonly request_id: string;
 readonly status: 'completed'|'failed'|'cancelled'|'unavailable'|'outcome_unknown';
 readonly stdout: string; readonly stderr: string; readonly exit_code: number | null;
 readonly rpc_completion: 'complete'|'transport_failed'|'not_started'; readonly output_truncated: boolean;
 readonly sandbox: { readonly uid: string; readonly name: string; readonly identity: string; readonly image_digest: string; readonly policy_digest: Digest } | null;
 readonly cleanup: 'not_created'|'pending'|'confirmed_absent'|'unknown';
 readonly started_at: string | null; readonly finished_at: string; readonly error_code: PrimeErrorCode | null;
 readonly reconciliation_required: boolean;
}
export interface OwnedExecutorRequest {
 readonly operation: OperationProposal; readonly consumed_grant: ConsumedGrant; readonly request_id: string;
 readonly image_digest: string; readonly policy_digest: Digest; readonly wall_time_ms: number; readonly max_output_bytes: number;
 readonly signal?: AbortSignal;
}
export interface OwnedExecutor {
 readonly capability: 'unavailable'|'qualified';
 execute(request: OwnedExecutorRequest): Promise<ExecutionReceipt>;
 reconcileOwned(): Promise<readonly ExecutionReceipt[]>;
}
export interface BrowserSession {
 readonly version: 1; readonly session_id: string; readonly owner_id: string; readonly task_id: string;
 readonly state: 'queued'|'starting'|'agent_controlled'|'human_controlled'|'paused'|'completed'|'failed';
 readonly lease_id: string | null; readonly controller: 'agent'|'owner'|null;
 readonly worker_identity: string | null; readonly permitted_origins: readonly string[]; readonly expires_at: string;
}
export interface ModelRoute {
 readonly version: 1; readonly route_id: string; readonly provider: string; readonly endpoint: string; readonly model: string;
 readonly region: string; readonly allowed_data_classes: readonly string[]; readonly allowed_tools: readonly string[];
 readonly max_input_tokens: number; readonly max_output_tokens: number; readonly max_requests: number;
 readonly task_spend_ceiling: CostLimit; readonly status: 'unavailable'|'approved';
}
export interface MemoryRecord {
 readonly version: 1; readonly record_id: string; readonly owner_subject: string; readonly task_id: string;
 readonly scope: string; readonly privacy: string; readonly record_format: string; readonly canonicalizer: string;
 /** Exact original UTF-8 JSON string. Never recanonicalize this field or mint a new salt/ID. */
 readonly canonical_bytes: string; readonly revision: string; readonly grants_authority: false;
 readonly source_event_digest: string | null; readonly evidence: JsonValue;
 readonly chain_domain: 'remembered'|'approved'|'legacy-presplit'; readonly source_span: JsonValue;
 readonly storage_status: 'pending'|'saved'|'failed'; readonly index_status: 'pending'|'indexing'|'indexed'|'searchable'|'failed';
}

export interface StrictJsonOptions { readonly maxBytes?: number; readonly maxDepth?: number }
export interface ContractMap {
 Task: Task; OperationProposal: OperationProposal; ApprovalProof: ApprovalProof; ConsumedGrant: ConsumedGrant;
 ExecutionReceipt: ExecutionReceipt; BrowserSession: BrowserSession; ModelRoute: ModelRoute; MemoryRecord: MemoryRecord;
}
export type ContractKind = keyof ContractMap;
export declare class ContractValidationError extends TypeError {
 constructor(reason: string, path?: string);
 readonly code: 'INVALID'; readonly error_code: 'INVALID'; readonly reason: string; readonly path: string;
}
export declare const CONTRACT_VERSION: 1;
export declare const CONTRACT_FIELDS: Readonly<Record<ContractKind, readonly string[]>>;
export declare const ERROR_CODES: readonly PrimeErrorCode[];
export declare const MAX_JSON_BYTES: number;
export declare const MAX_JSON_DEPTH: number;
export declare function canonicalJson(value: unknown): string;
export declare function parseStrictJson(text: string, options?: StrictJsonOptions): JsonValue;
export declare function validateContract<K extends ContractKind>(kind: K, value: unknown): ContractMap[K];
export declare function validateApprovalTemplate(value: unknown): ApprovalTemplate;
export declare function parseContract<K extends ContractKind>(kind: K, text: string, options?: StrictJsonOptions): ContractMap[K];
export declare function operationBytes(proposal: OperationProposal): Uint8Array;
export declare function operationDigest(proposal: OperationProposal): Digest;
