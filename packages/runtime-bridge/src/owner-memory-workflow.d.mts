// SPDX-License-Identifier: AGPL-3.0-or-later
export interface CaptureMetadata {
  readonly profile:'prime-pilot-memory-capture/v1'
  readonly category:'fact'
  readonly valid_from:string
  readonly observed_at:string
  readonly confidence_percent:70
  readonly sensitivity:'none'
}
export interface MemoryCapture {
  readonly statement:string
  readonly attributed_to:string
  readonly capture_metadata:CaptureMetadata
  readonly evidence_quote:string
}
export interface MemoryDraft {readonly extraction_json:string;readonly idempotency_key:string}
/** Exact private callback and cancellation signal for one B-owned hook flight. */
export interface OwnerMemoryApprovalInvocation {readonly signal:AbortSignal;readonly approve:()=>Promise<unknown>}
export interface MemoryWorkflowSnapshot {
  readonly phase:'idle'|'proposal_pending'|'proposed'|'approval_pending'|'save_pending'|'saved'|'refused'|'outcome_unknown'|'unavailable'
  readonly operation:Readonly<Record<string,unknown>>|null
  readonly memory_capture:MemoryCapture|null
  readonly operation_digest:string|null
  readonly approval:'not_requested'|'pending'|'approved'|'refused'|'unknown'
  readonly save:'not_attempted'|'pending'|'saved'|'refused'|'unknown'
  readonly saved:boolean|null
  readonly record:Readonly<Record<string,unknown>>|null
  readonly receipt:Readonly<Record<string,unknown>>|null
  readonly receipt_digest:string|null
  readonly citation:Readonly<Record<string,unknown>>|null
  readonly citation_status:'not_requested'|'pending'|'verified'|'unverified'|'missing'|'unavailable'
  readonly index:Readonly<{status:string;indexed:boolean|null;searchable:boolean|null}>
  readonly authority_settlement:'completed'|'pending'|null
  readonly reconciliation_required:boolean
  readonly error_code:string|null
  readonly read_error_code:string|null
}
export interface OwnerMemoryController {
  getSnapshot():{readonly owner:{readonly owner_id:string;readonly expiry:string}|null;readonly authority_available:boolean;readonly expired:boolean;readonly phase:string;readonly error_code:string|null;readonly presentation:unknown}
  subscribe(listener:()=>void):()=>void
  setOperation(operation:unknown,options:{readonly memoryCapture:MemoryCapture;readonly captureMetadata:CaptureMetadata}):void
  approve():Promise<unknown>
  logout?():void|Promise<unknown>
}
export interface OwnerMemoryWorkflow {
  getSnapshot():MemoryWorkflowSnapshot
  /** Fixed metadata retained from the independently validated capture draft. */
  getCaptureMetadata():CaptureMetadata|null
  subscribe(listener:()=>void):()=>void
  proposeSave(draft:MemoryDraft):Promise<MemoryWorkflowSnapshot>
  /** Owned hooks must supply their invocation; no-options calls use raw approval. */
  approveAndSave(options?:OwnerMemoryApprovalInvocation):Promise<MemoryWorkflowSnapshot>
  /** Read only: refreshes known record status and retained-head citation. */
  refresh():Promise<MemoryWorkflowSnapshot>
  /** Reads durable C/D facts and resends retained settlement receipts only. */
  recover(input?:{operation_id:string|null}):Promise<MemoryWorkflowSnapshot>
  /** Revokes the adapter's actual C session after removing local owner access. */
  logout():Promise<unknown>
  /** Disposes this helper only, without cancelling or replaying any mutation. */
  dispose():void
}
export function createOwnerMemoryWorkflow(options:{controller:OwnerMemoryController;memory:{proposeSave(input:unknown):Promise<unknown>;save(input:unknown):Promise<unknown>;status(input:unknown):Promise<unknown>;cite(input:unknown):Promise<unknown>;recover?(input:unknown):Promise<unknown>;logout?():Promise<unknown>};contracts:{operationDigest(operation:unknown):string|Promise<string>}}):OwnerMemoryWorkflow
