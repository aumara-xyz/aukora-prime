// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only private Node subpath. Declarations establish no runtime qualification.
import type {ApprovalMaterial,ApprovalProof,ConsumedGrant,CostLimit,Digest,JsonValue,ModelRoute,
  OperationProposal,Task} from '@aukora-prime/contracts'
import type {DispatchBinding,LocalRoute,LocalTask,ProviderConfiguration,TotalTestingBudget} from '@aukora-prime/inference'
import type {InferenceTargetIdentity,TotalBudgetBinding} from '@aukora-prime/inference/budget-binding'

/** The twelve existing E fields; bare body/binding/citation hashes stay unchanged. */
export type InferenceBinding = Readonly<Omit<DispatchBinding,'config_digest'>> & {readonly config_digest:Digest}
export type InferenceLimits = {
  readonly max_requests:number;readonly max_input_tokens:number;readonly max_output_tokens:number
  readonly max_total_tokens:number;readonly max_request_ms:number;readonly task_spend_ceiling:Readonly<CostLimit>
}
export type InferenceParameters = {
  readonly version:1;readonly kind:'prime-inference-request/v1';readonly binding:InferenceBinding
  readonly request_digest:Digest;readonly limits:InferenceLimits;readonly total_budget:Readonly<TotalBudgetBinding>
}
/** Specializes existing frozen fields; introduces no OperationProposal fields. */
export type InferenceOperation = Omit<OperationProposal,'audience'|'action_type'|'target_identity'|
  'canonical_parameters'|'data_scope'|'expected_state_version'|'provider_and_region'> & {
  readonly audience:'aukora-prime.inference';readonly action_type:'inference.generate'
  readonly target_identity:Readonly<InferenceTargetIdentity>;readonly canonical_parameters:InferenceParameters
  readonly data_scope:readonly ['conversation'];readonly expected_state_version:Digest
  readonly provider_and_region:{readonly provider:'deepseek';readonly region:string}
}
/** Closed flat fifteen fields; never E's currently permissive DispatchAdmission. */
export type InferenceAdmission = InferenceBinding & {
  readonly operation:InferenceOperation;readonly consumed_grant:ConsumedGrant;readonly request_digest:Digest
}
export interface InferenceClaimInput {
  readonly operation:InferenceOperation;readonly consumed_grant:ConsumedGrant
  readonly request_id:string;readonly request_digest:Digest
}
export interface InferenceDispatchReply {
  readonly ok:true;readonly status:'DISPATCHED';readonly consumed_grant:ConsumedGrant
  readonly request_id:string;readonly request_digest:Digest
}
export type InferenceReceipt = {
  readonly version:1;readonly kind:'prime-inference-effect/v1'
  readonly operation_id:string;readonly operation_digest:Digest;readonly grant_id:string
  readonly request_id:string;readonly request_digest:Digest;readonly owner_subject:string
  readonly task_id:string;readonly conversation_id:string;readonly route_id:'externalDeepSeek'
  readonly config_digest:Digest;readonly credential_generation:number;readonly total_budget_id:string
  readonly body_sha256:string;readonly observed_at:string
} & ({
  readonly outcome:'completed';readonly result_digest:Digest
  readonly usage:{readonly input_tokens:number;readonly output_tokens:number;readonly cost_microusd:number}
  readonly reservation_retained:false
} | {
  readonly outcome:'outcome_unknown';readonly result_digest:null;readonly usage:null
  readonly reservation_retained:true
})
/** Exact six factual fields, read from E's genuine committed settlement outbox. */
export type InferenceSettlementInput = InferenceClaimInput & {
  readonly receipt:InferenceReceipt;readonly receipt_digest:Digest
}
/** Exact seven fields; unknown retains the reservation and requires reconciliation. */
export type InferenceSettlementReply = {
  readonly ok:true;readonly request_id:string;readonly request_digest:Digest;readonly receipt_digest:Digest
  readonly idempotent:boolean
} & ({readonly status:'COMPLETED';readonly reconciliation_required:false} |
  {readonly status:'OUTCOME_UNKNOWN';readonly reconciliation_required:true})
export type InferenceSettlementMethod = 'settleInference'|'reconcileInferenceSettlement'

export interface InferenceSourceStatus {
  readonly state:'unavailable';readonly qualification:'unqualified'
  readonly reason:'INFERENCE_HOST_AND_C_E_LIFECYCLE_JOIN_PENDING'
}
export interface InferenceOwnerMapping {readonly owner_id:string;readonly subject:string}
export interface InferenceRegistryEntry {
  readonly task:Task;readonly provider_and_region:OperationProposal['provider_and_region']
  readonly audience:'aukora-prime.inference';readonly policy_version:string;readonly data_scope:readonly string[]
}
export interface InferenceStateLookup {readonly owner_id:string;readonly task_id:string}
/** Exact five trusted host facts; configuration has exactly three fields. */
export interface TrustedInferenceFacts {
  readonly route:Readonly<LocalRoute>
  readonly configuration:{readonly digest:Digest;readonly operation_id:string
    readonly payload:{readonly route:ModelRoute & {readonly status:'unavailable'}
      readonly pricing:Readonly<ProviderConfiguration['pricing']>}}
  readonly local_task:Readonly<LocalTask>;readonly total_budget:Readonly<TotalTestingBudget>
  readonly credential_generation:number
}
export interface InferenceObservation {
  readonly target_identity:Readonly<InferenceTargetIdentity>;readonly state_version:Digest
}
/** Independently read E/C facts, then await consume once while holding the change fence.
 * This fence must remain held through C claim and dispatchCommitted's actual HTTP.
 * The stored seven-field budget is already normalized; state hashing creates no allowance. */
export type WithQualifiedInferenceState = <T>(lookup:InferenceStateLookup,
  consume:(facts:TrustedInferenceFacts)=>Promise<T>)=>Promise<unknown>
export interface TrustedInferenceObserver {
  status():InferenceSourceStatus
  withObservation<T>(operation:InferenceOperation,
    consume:(observation:InferenceObservation,assertScope:()=>void)=>T|Promise<T>):Promise<T>
}
export type InferenceObserverAdapter = Pick<TrustedInferenceObserver,'withObservation'> & {
  readonly status?:TrustedInferenceObserver['status']
}
export interface TrustedInferenceObserverConfig {
  readonly registryEntries:readonly InferenceRegistryEntry[];readonly ownerMappings:readonly InferenceOwnerMapping[]
  readonly withQualifiedState?:WithQualifiedInferenceState
}
export function createTrustedInferenceObserver(config:TrustedInferenceObserverConfig):TrustedInferenceObserver

export interface InferenceIntentLookup extends InferenceStateLookup {
  readonly operation_digest:Digest;readonly request_uuid:string;readonly request_digest:Digest
}
export interface InferenceSettlementLookup extends InferenceIntentLookup {readonly receipt_digest:Digest}
export interface InferenceReviewedApproval {
  readonly operation:InferenceOperation;readonly approval_proof:ApprovalProof
}
/** E must atomically commit immutable intent, original effective task/route/rates,
 * and worst-case allowance before invoking consume once; never invoke after an uncertain claim.
 * This adapter uses E's existing worker ledger, not a host evidence copy or new ledger. */
export type WithCommittedInferenceIntent = <T>(lookup:InferenceIntentLookup,
  consume:(admission:InferenceAdmission)=>Promise<T>)=>Promise<unknown>
/** Await consume once with the original exact-six outbox bytes and observed_at.
 * Redelivery is factual settlement only; it never repeats a claim or provider request. */
export type WithCommittedInferenceSettlement = <T>(method:InferenceSettlementMethod,
  lookup:InferenceSettlementLookup,consume:(settlement:InferenceSettlementInput)=>Promise<T>)=>Promise<unknown>
export interface InferenceIpcLimits {
  readonly maxFrameBytes?:number;readonly maxOutputBytes?:number;readonly maxConnections?:number
  readonly maxInflight?:number;readonly maxInflightPerConnection?:number;readonly handshakeTimeoutMs?:number
  readonly idleTimeoutMs?:number;readonly requestTimeoutMs?:number;readonly maxRequestsPerConnection?:number
}
export interface InferenceSocketAccess {readonly server_uid:number;readonly client_uid:number;readonly group_gid:number}
export interface InferenceAuthorityChannel {
  readonly socketPath:string;readonly credential:{readonly id:string;readonly secret:string}
  readonly limits?:InferenceIpcLimits;readonly socketAccess?:InferenceSocketAccess
}
export interface InferenceLoginChallenge {
  readonly version:1;readonly owner_id:string;readonly audience:'aukora-prime.inference';readonly challenge:string
  readonly issued_at:string;readonly expiry:string;readonly authorization_epoch:number
}
export type InferenceLoginMaterial = {readonly kind:'owner_key';readonly signature:string} |
  Extract<ApprovalMaterial,{readonly kind:'passkey'}>
/** Existing C owner replies remain opaque: C exports no declaration for those replies. */
export interface InferenceOwnerAuthority {
  loginChallenge(input:{readonly owner_id:string;readonly kind:'owner_key'|'passkey'}):Promise<unknown>
  loginComplete(input:{readonly challenge:InferenceLoginChallenge;readonly material:InferenceLoginMaterial}):Promise<unknown>
  authenticateSession(input:{readonly session_token:string}):Promise<unknown>
  logoutSession(input:{readonly session_token:string}):Promise<unknown>
  status(input:{readonly session_token:string;readonly operation_id:string}):Promise<unknown>
  propose(input:{readonly session_token:string;readonly operation:InferenceOperation}):Promise<unknown>
  approvalChallenge(input:{readonly session_token:string;readonly operation:InferenceOperation}):Promise<unknown>
  approvalComplete(input:{readonly session_token:string;readonly proof:ApprovalProof}):Promise<unknown>
  declineApproval(input:{readonly session_token:string;readonly operation_id:string}):Promise<unknown>
}
/** Internal host callbacks are not wire fields or production-readiness gates.
 * Omitted adapters refuse their respective paths; authority/channel custody stays private. */
export interface InferenceAuthorityConnectionConfig<DispatchResult=unknown> {
  readonly authorityChannel:InferenceAuthorityChannel;readonly observer:InferenceObserverAdapter
  /** E must durably fence this owner/request reserve attempt before returning the reviewed pair.
   * Reuse after an attempted or uncertain reserve must refuse. The bridge's bounded local
   * latches do not survive connection recreation or process restart, or replace E's ledger fence. */
  readonly getReviewedApproval?:(binding:InferenceBinding)=>InferenceReviewedApproval|Promise<InferenceReviewedApproval>
  readonly withCommittedIntent?:WithCommittedInferenceIntent
  readonly dispatchCommitted?:(admission:InferenceAdmission,claim:InferenceDispatchReply)=>DispatchResult|Promise<DispatchResult>
  readonly withCommittedSettlement?:WithCommittedInferenceSettlement
}
export interface InferenceAuthorityConnection<DispatchResult=unknown> {
  readonly authority:InferenceOwnerAuthority
  status():InferenceSourceStatus
  dispose():void
  /** Reserves PREPARED once; returns admission without claiming dispatch. */
  authorizeDispatch(binding:InferenceBinding):Promise<InferenceAdmission>
  /** E intent fence -> qualified-state fence -> exact C claim -> E dispatch callback. */
  withDispatch(input:InferenceClaimInput):Promise<DispatchResult>
  settleInference(input:InferenceSettlementInput):Promise<InferenceSettlementReply>
  reconcileInferenceSettlement(input:InferenceSettlementInput):Promise<InferenceSettlementReply>
}
export function createInferenceAuthorityConnection<DispatchResult=unknown>(
  config:InferenceAuthorityConnectionConfig<DispatchResult>):InferenceAuthorityConnection<DispatchResult>

export type InferenceAuthorityIdentity = {
  readonly owner_id:string;readonly subject:string;readonly approval_key_did:string
  readonly control_digest:string;readonly authorization_epoch:number
}
export type InferenceAuthorityProfile = {
  readonly contexts:readonly {
    readonly route:Readonly<LocalRoute>;readonly local_task:Readonly<LocalTask>
    readonly total_budget:Readonly<TotalTestingBudget>;readonly original_config:Readonly<ProviderConfiguration>
  }[]
}
/** C owns validation of its data-only configuration and existing protected state.
 * This entry point supplies no provisioning, state reset, signer or inference policy defaults. */
export type InferenceAuthorityConfig = Readonly<Record<string,JsonValue|InferenceAuthorityProfile>> & {
  readonly statePath:string;readonly stateRoot:string;readonly witnessDir:string
  readonly audience:'aukora-prime.inference';readonly identities:readonly InferenceAuthorityIdentity[]
  readonly policy:JsonValue;readonly retainedMemoryParticipant?:never
  readonly inferenceProfile:InferenceAuthorityProfile
}
export interface InferenceAuthorityWorkerConfig {
  readonly kind:'inference-authority';readonly registryEntries:readonly InferenceRegistryEntry[]
  readonly authorityConfig:InferenceAuthorityConfig
  /** Frozen JSON configuration: host secrets are lowercase hexadecimal strings. */
  readonly ipc:{readonly socketPath:string
    readonly credentials:readonly {readonly id:string;readonly role:'inference_effect';readonly secret:string}[]
    readonly limits?:InferenceIpcLimits;readonly socketAccess?:InferenceSocketAccess}
}
export interface InferenceAuthorityWorker {
  close():Promise<void>
  status():InferenceSourceStatus & {readonly kind:'inference-authority';readonly socket:string}
}
/** Requires the fixed C inference parser import and full accepted thirteen-method
 * service and explicit immutable inference profile before listening.
 * C parser/lifecycle are absent at base 6becb72; startup refuses. */
export function startInferenceAuthorityWorker(config:InferenceAuthorityWorkerConfig):Promise<InferenceAuthorityWorker>
