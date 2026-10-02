import type { Buffer } from 'node:buffer';
import type { ApprovalProof, ConsumedGrant, Digest, OperationProposal } from '@aukora-prime/contracts';
import type { CredentialHandoff, CredentialStatus, DispatchAdmission, DispatchBinding, LocalRoute, LocalTask, ProviderRequest, ProviderReply, TotalTestingBudget, TotalBudgetUsage } from './index.mjs';
import type { WorkerIntent, WorkerPhase, WorkerClaimReply, WorkerSettlementPayload, WorkerSettlementReply } from './worker-evidence.mjs';
export type { WorkerIntent, WorkerClaimReply, WorkerSettlementPayload, WorkerSettlementReply } from './worker-evidence.mjs';
export interface WorkerSettlementStatus {
 request_id:string;phase:WorkerPhase;outcome:'reserved'|'dispatched'|'completed'|'outcome_unknown';
 claim_confirmed:boolean;receipt_digest:string|null;settlement_pending:boolean;
}
export interface WorkerRequestScope {owner_id:string;task_id:string;request_id:string}
export interface WorkerReviewedApproval {operation:OperationProposal;approval_proof:ApprovalProof}
export interface WorkerClaimInput {
 operation:OperationProposal;consumed_grant:ConsumedGrant;request_id:string;request_digest:Digest;
}
export interface WorkerIntentLookup {
 owner_id:string;task_id:string;operation_digest:Digest;request_uuid:string;request_digest:Digest;
}
export interface WorkerSettlementLookup extends WorkerIntentLookup {receipt_digest:Digest}
export type WorkerSettlementMethod = 'settleInference'|'reconcileInferenceSettlement';
/** Server-only stable key custody. Must provide a Node Buffer held only by the credential UID. */
export interface VaultOptions {path:string;withEncryptionKey:<T>(callback:(key:Buffer)=>T|Promise<T>)=>T|Promise<T>}
export class CredentialVault {
 constructor(options:VaultOptions);close():void;status(owner_id:string):CredentialStatus;
 createTicket(owner_id:string,expected_generation:number,expiry:number):string;
 submit(input:{owner_id:string;ticket:string;secret:string;now?:number}):Promise<{configured:true;generation:number}>;
 use<T>(owner_id:string,generation:number,callback:(secret:string)=>Promise<T>):Promise<T>;
}
export function assertSeparatedCredentialProcess(application_uid:number):void;
export interface SeparatedServiceOptions extends VaultOptions {
 application_uid:number;spend_path:string;total_budget:TotalTestingBudget;
 authenticateOwner:(context:unknown)=>Promise<{owner_id:string}|undefined>;
 approveCredentialEntry:(input:{owner_id:string;provider:'externalDeepSeek';expected_generation:number;approval_proof:unknown;context:unknown})=>Promise<{owner_id:string;provider:'externalDeepSeek';expected_generation:number;operation_id:string}>;
 /** Trusted reviewed pair; the service durably fences the original reserve attempt before returning it. */
 getReviewedApproval:(binding:DispatchBinding)=>Promise<WorkerReviewedApproval>;
 /** Hold the qualified-state scope through one C claim, actual HTTP and durable evidence. */
 withDispatch:(input:WorkerClaimInput)=>Promise<ProviderReply>;
 getQualifiedRoute:(owner_id:string)=>Promise<LocalRoute>;
 getAuthorizedTask:(owner_id:string,task_id:string)=>Promise<LocalTask>;
 getOwnerIdentity:(owner_id:string)=>Promise<{owner_id:string;subject:string}>;
 settleInference:(input:WorkerSettlementPayload)=>Promise<WorkerSettlementReply>;
 reconcileInferenceSettlement:(input:WorkerSettlementPayload)=>Promise<WorkerSettlementReply>;
 /** Trusted local evidence resolver only; never an app reply, fresh inference or current replacement pricing. */
 getReconciliationEvidence?:(input:{evidence_id:string;intent:WorkerIntent})=>Promise<ProviderReply>;
}
export class SeparatedCredentialService {
 constructor(options:SeparatedServiceOptions);close():void;
 createHandoff(input:{owner_id:string;expected_generation:number;approval_proof:unknown;context:unknown}):Promise<CredentialHandoff>;
 submitEntry(context:unknown,input:{ticket:string;secret:string}):Promise<{configured:true;generation:number}>;
 status(owner_id:string,context:unknown):Promise<CredentialStatus>;
 /** E retains broad frozen-contract data types. A host joining the narrower Bridge
  * inference types must validate at that boundary; these methods do not supply a
  * TypeScript narrowing assertion or authorize a cast to the Bridge contract. */
 getReviewedApproval(binding:DispatchBinding):Promise<WorkerReviewedApproval>;
 /** Await consume once, only inside the active original dispatch after durable intent commit. */
 withCommittedIntent<T>(lookup:WorkerIntentLookup,consume:(admission:DispatchAdmission)=>Promise<T>):Promise<T>;
 dispatchCommitted(admission:DispatchAdmission,claim:WorkerClaimReply):Promise<ProviderReply>;
 /** Replay the original committed outbox, including independent recovery delivery. */
 withCommittedSettlement<T>(method:WorkerSettlementMethod,lookup:WorkerSettlementLookup,
  consume:(payload:WorkerSettlementPayload)=>Promise<T>):Promise<T>;
 dispatch(request:Omit<ProviderRequest,'signal'>,options?:{signal?:AbortSignal}):Promise<ProviderReply>;
 settlementStatus(owner_id:string,task_id:string,request_id:string):WorkerSettlementStatus;
 pendingRequests(owner_id:string,options?:{after_request_id?:string;limit?:number}):(WorkerRequestScope & {phase:WorkerPhase;outcome:string})[];
 retrySettlement(owner_id:string,task_id:string,request_id:string):Promise<WorkerSettlementStatus>;
 recoverUnknown(context:unknown,scope:WorkerRequestScope):Promise<WorkerSettlementStatus>;
 reconcileEvidence(context:unknown,input:WorkerRequestScope & {evidence_id:string}):Promise<WorkerSettlementStatus>;
 totalUsage(owner_id:string,budget_id:string):TotalBudgetUsage;
}
