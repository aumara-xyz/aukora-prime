import type { OwnedExecutor, OwnedExecutorRequest, ExecutionReceipt, OperationProposal, ConsumedGrant } from '../../contracts/src/index.ts'
import type { SdkTransport } from './sdk-transport.ts'
export { SdkTransport, SDK_SOURCE_COMMIT, SDK_PACKAGE_VERSION } from './sdk-transport.ts'
export interface ExecutorSettings {
  workspace: string; logical_workspace_root: string; image_digest: string;
  control_timeout_ms: number; cleanup_timeout_ms: number; poll_ms: number;
}
export class OwnedLedger {
  constructor(root: string,options?:{initialize?:boolean;expected_identity?:string|null})
  readonly identity:string
  withLease<T>(work: () => Promise<T>): Promise<T>
  pending(): unknown[]
  recovery(): unknown[]
  close(): void
}
export class OpenShellOwnedExecutor implements OwnedExecutor {
  constructor(options: { settings: ExecutorSettings; transport: SdkTransport; ledger: OwnedLedger;
    broker: AuthorityExecutorBinding; qualification?: RuntimeQualification | null; runtimeBinding?:{host_profile_digest:string;gateway_identity:string;ledger_id:string}|null })
  readonly capability: 'unavailable' | 'qualified'
  execute(request: OwnedExecutorRequest): Promise<ExecutionReceipt>
  reconcileOwned(): Promise<readonly ExecutionReceipt[]>
  cancellationCause(requestId: string): 'timeout' | 'caller' | 'dispose' | null
  availability(): { backend: 'openshell-linux'; state: 'unavailable' | 'qualified'; cleanup: 'pending' | 'unprobed'; source:'pinned_source'; protocol:'unperformed'|'mocked'; runtime:'accepted'|'unavailable'; runtimeEnforcementVerified: boolean; qualification_id:string|null; host_profile:HostProfile|null; settlement:'pending'|'settled' }
  dispose(): Promise<void>
}
export function createDshOpenShellExecutor(options: {
  ShellExecutor: abstract new (...args: any[]) => any;
  resolveSpec: (request: any) => any;
  executor: OwnedExecutor;
  resolveOperation: (spec: any) => Promise<OwnedExecutorRequest>;
}): new (...args: any[]) => any
export function installOwnedBash(ctx: any, options: Parameters<typeof createDshOpenShellExecutor>[0]): Promise<any>
export function policyDigest(mode: 'read-only' | 'workspace-write'): `sha256:${string}`
export function wirePolicy(mode: 'read-only' | 'workspace-write'): import('./sdk-transport.ts').Policy
export function loadPinnedSdk(sdkRoot: string, connectOptions: { gateway: string; [key: string]: unknown }): Promise<{ client: unknown; transport: SdkTransport }>
export { validateSpec, guestEnvironment, guestPolicy, refused } from './policy.mjs'

export type ExecutorBinding = {operation:OperationProposal;consumed_grant:ConsumedGrant;request_id:string;request_digest:`sha256:${string}`}
export type SettlementBinding = ExecutorBinding & {receipt:ExecutionReceipt;receipt_digest:`sha256:${string}`}
export type BrokerRefusal = {ok:false;error_code:string;reason:string}
export type ClaimReply = {ok:true;status:'DISPATCHED';consumed_grant:ConsumedGrant;request_id:string;request_digest:string}
export type CancelReply = {ok:true;status:'CANCEL_REQUESTED'|'COMPLETED'|'FAILED'|'CANCELLED'|'UNAVAILABLE'|'OUTCOME_UNKNOWN';request_id:string;cancel_recorded:boolean}
export type SettlementReply = {ok:true;status:'COMPLETED'|'FAILED'|'CANCELLED'|'UNAVAILABLE'|'OUTCOME_UNKNOWN';request_id:string;request_digest:string;receipt_digest:string;idempotent:boolean;reconciliation_required:boolean}
export interface AuthorityExecutorBinding {
 claimDispatch(input:ExecutorBinding): ClaimReply|BrokerRefusal|Promise<ClaimReply|BrokerRefusal>;
 requestCancel(input:Omit<ExecutorBinding,'request_digest'> & {reason:'caller'|'timeout'|'dispose'}): CancelReply|BrokerRefusal|Promise<CancelReply|BrokerRefusal>;
 settle(input:SettlementBinding): SettlementReply|BrokerRefusal|Promise<SettlementReply|BrokerRefusal>;
 reconcileSettlement(input:SettlementBinding): SettlementReply|BrokerRefusal|Promise<SettlementReply|BrokerRefusal>;
}
export interface HostProfile {host_id:string;os:'linux';architecture:'amd64';kernel_release:string;landlock_abi:number;seccomp_notify:true;cgroup_version:2;docker_version:string}
export interface QualificationRecord {
 version:1;qualification_id:string;workspace:string;logical_workspace_root:string;image_digest:string;policy_digest:string;
 sdk_source_commit:string;sdk_package_version:'0.0.0';host_profile:HostProfile;gateway_identity:string;ledger_id:string;
 bounds:{cpu_millicores:number;memory_bytes:number;scratch_bytes:number;pids:number;wall_time_ms:number;max_output_bytes:number};
 evidence_digest:string;accepted_at:string;expires_at:string;
}
export interface QualificationEvidence {check:string;artifact_digest:string;observed_at:string;scope_digest:string;status:'passed'}
export interface QualificationProof {kind:'host_runtime_acceptance';record_digest:string;evidence_digest:string;host_profile_digest:string;accepted_by:string;material:unknown}
export interface RuntimeQualification {
 record:QualificationRecord;evidence:readonly QualificationEvidence[];proof:QualificationProof;
 verifyAcceptedProof(input:{record:QualificationRecord;evidence:readonly QualificationEvidence[];proof:QualificationProof}):
 {status:'ACCEPTED';record_digest:string;evidence_digest:string;host_profile_digest:string;accepted_by:string} | null;
}
export function executorRequestDigest(request:OwnedExecutorRequest):`sha256:${string}`
export function executionReceiptDigest(receipt:ExecutionReceipt):`sha256:${string}`
export function qualificationRecordDigest(record:QualificationRecord):`sha256:${string}`
export function qualificationEvidenceDigest(evidence:readonly QualificationEvidence[]):`sha256:${string}`
export function hostProfileDigest(profile:HostProfile):`sha256:${string}`
