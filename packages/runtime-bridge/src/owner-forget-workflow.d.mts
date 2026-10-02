// SPDX-License-Identifier: AGPL-3.0-or-later
export interface ForgetRecordSummary {
  readonly record_id:string
  readonly revision:string
  readonly statement:string
  readonly attributed_to:string|null
}
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
/** Authenticated, server-derived C/D facts; no operation or proof is rebuilt. */
export interface ForgetRecoveryReply {
  readonly ok:true
  readonly owner_id:string
  readonly owner_subject:string
  readonly task_id:string
  readonly operation_id:string|null
  readonly operation_digest:string|null
  readonly action_type:'memory.save'|'memory.forget'|null
  readonly state:'idle'|'known_unsent'|'saved'|'forgotten'|'unknown'
  readonly reconciliation_required:boolean
  readonly result:LogicalForgetResult|Readonly<Record<string,unknown>>|null
  readonly receipt:Readonly<Record<string,unknown>>|null
  readonly receipt_digest:string|null
  readonly authority_settlement:'completed'|null
  readonly citation:Readonly<Record<string,unknown>>|null
  readonly index:Readonly<Record<string,unknown>>|null
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
export interface OwnerForgetController {
  getSnapshot():{readonly owner:{readonly owner_id:string;readonly expiry:string}|null;readonly authority_available:boolean;readonly expired:boolean;
    readonly phase:string;readonly error_code:string|null;readonly presentation:unknown}
  subscribe(listener:()=>void):()=>void
  /** H prepares the controller's review after this exact operation is set. */
  setOperation(operation:unknown,options:{readonly recordSummary:ForgetRecordSummary}):void
  /** Raw approval API; B's submitApproval selects its separate forget hook. */
  approve():Promise<unknown>
}
export interface OwnerForgetWorkflow {
  getSnapshot():ForgetWorkflowSnapshot
  subscribe(listener:()=>void):()=>void
  proposeForget(input:{readonly record_id:string}):Promise<ForgetWorkflowSnapshot>
  approveAndForget():Promise<ForgetWorkflowSnapshot>
  /** Reads C/D durable facts and may deliver the retained settlement receipt;
   * never reconstructs an approval or repeats the forget effect. */
  recover(input?:{readonly operation_id:string|null}):Promise<ForgetWorkflowSnapshot>
  /** Local fences only; never cancels, reconciles or repeats a server mutation. */
  dispose():void
}
/** Use the same adapter instance's authority in the controller and memory here.
 * H/B hand off this separate result through the controller's forget hook. */
export function createOwnerForgetWorkflow(options:{controller:OwnerForgetController;memory:{
  proposeForget(input:{readonly record_id:string}):Promise<unknown>
  forget(input:{readonly operation:Readonly<Record<string,unknown>>;readonly approval_proof:Readonly<Record<string,unknown>>}):Promise<unknown>
  recover?(input:{readonly operation_id:string|null}):Promise<unknown>
};contracts:{operationDigest(operation:unknown):string|Promise<string>}}):OwnerForgetWorkflow
