// SPDX-License-Identifier: AGPL-3.0-or-later
export interface ForgetResultContracts {
  canonicalJson(value:unknown):string
  parseStrictJson(text:string,options?:{maxBytes?:number;maxDepth?:number}):unknown
  validateContract(kind:string,value:unknown):unknown
  operationDigest(operation:unknown):string|Promise<string>
}
export interface ForgetRecordSummary {
  readonly record_id:string
  readonly revision:string
  readonly statement:string
  readonly attributed_to:string|null
}
export interface ForgetReview extends ForgetRecordSummary { readonly canonical_sha256:string }
export interface LogicalForgetResult {
  readonly record_id:string
  readonly state:'tombstoned'
  readonly canonical_payload_retained:true
  readonly physical_media_erasure:false
  readonly authority_approval_history_erased:false
  readonly backups_erased:false
  readonly wal_erased:false
  readonly grants_authority:false
}
export interface ForgetWorkflowSnapshot {
  readonly phase:'idle'|'proposal_pending'|'proposed'|'approval_pending'|'forget_pending'|'forgotten'|'refused'|'outcome_unknown'|'unavailable'
  readonly operation:Readonly<Record<string,unknown>>|null
  readonly record_summary:ForgetRecordSummary|null
  readonly operation_digest:string|null
  readonly approval:'not_requested'|'pending'|'approved'|'refused'|'unknown'
  readonly forget:'not_attempted'|'pending'|'forgotten'|'refused'|'unknown'
  readonly forgotten:boolean|null
  readonly result:LogicalForgetResult|null
  readonly receipt:Readonly<Record<string,unknown>>|null
  readonly receipt_digest:string|null
  readonly authority_settlement:'completed'|'pending'|null
  readonly reconciliation_required:boolean
  readonly error_code:string|null
  readonly recovery_status:'not_requested'|'pending'|'idle'|'known_unsent'|'saved'|'forgotten'|'unknown'|'refused'
  readonly recovery_operation_id:string|null
  readonly recovery_operation_digest:string|null
}
export interface ForgetPresentation {
  readonly operation:Readonly<Record<string,unknown>>
  readonly canonical_operation:string
  readonly operation_digest:string
  readonly forget_review:ForgetReview
}
export function validateForgetWorkflowSnapshot(value:unknown,contracts:ForgetResultContracts):ForgetWorkflowSnapshot
/** Presentation consistency only. Recheck the captured owner/revision after awaiting. */
export function validateForgetWorkflowResult(value:unknown,context:{presentation:ForgetPresentation;approved:boolean;proofNonce?:string;contracts:ForgetResultContracts}):Promise<ForgetWorkflowSnapshot>
/** Throws OUTCOME_UNKNOWN unless exact content-free unsent or completed facts. */
export function validateCancelledForgetWorkflow(value:unknown,contracts:ForgetResultContracts):ForgetWorkflowSnapshot
