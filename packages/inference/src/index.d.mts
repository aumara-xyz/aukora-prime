import type { Task, ModelRoute, OperationProposal, ConsumedGrant, Digest } from '@aukora-prime/contracts';
import type { TotalBudgetBinding } from './budget-binding.mjs';
import type { WorkerIntent, WorkerPhase, WorkerClaimReply, PendingWorkerSettlement } from './worker-evidence.mjs';
export { normalizeTotalBudget, totalBudgetPolicyDigest, totalBudgetBinding, inferenceBudgetState } from './budget-binding.mjs';
export type { TotalBudgetBinding, InferenceTargetIdentity, InferenceBudgetState } from './budget-binding.mjs';
export interface LocalRoute {
  route_id: 'externalDeepSeek'; provider: 'deepseek'; endpoint: 'https://api.deepseek.com'; model: string;
  allowed_data_classes: readonly string[]; max_input_tokens: number; max_output_tokens: number; max_request_ms: number;
  mode: 'mock'|'unavailable'|'production'; input_microusd_per_token: number; output_microusd_per_token: number;
  max_requests: number; spend_cap_microusd: number; region: string; transport_status: ModelRoute['status'];
  pricing_evidence_id?: string; terms_evidence_id?: string; served_version?: string;
  credential_generation?: number; config_digest?: string; total_budget_id?: string;
}
export interface LocalTask {
  owner_id: string; task_id: string; conversation_id: string; route_id: 'externalDeepSeek';
  allowed_data_classes: readonly string[]; max_requests: number; max_tokens: number;
  max_input_tokens: number; max_output_tokens: number; spend_cap_microusd: number;
}
export interface SourceCitation { source_id: string; url: string; captured_at: string; span_sha256: string }
export interface Fragment { owner_id: string; task_id: string; conversation_id: string; data_class: string;
  role: 'user'|'assistant'; text: string; citation?: SourceCitation }
export interface InferenceRequest { request_uuid: string; owner_id: string; task_id: string; conversation_id: string;
  max_output_tokens: number; fragments: readonly Fragment[] }
export interface BodyReceipt { sessionId: string; line: string; turn: number; spokenAt: number; request_uuid: string;
  body_sha256: string; source_citation: {sessionId: string; turn: number; sha256: string; requestId: string}; citations: readonly SourceCitation[] }
export type InferenceResult = { outcome: 'outcome_unknown'; request_uuid: string; receipt: BodyReceipt; error: string; reservation_retained: true }
 | { outcome: 'completed'; request_uuid: string; route_id: 'externalDeepSeek'; mode: 'mock'|'production';
     proposal: {text: string; source_ids: string[]; grantsAuthority: false}; usage: {input_tokens: number; output_tokens: number; cost_microusd: number};
     receipt: BodyReceipt; omitted: {reason: string}[] };
export class InferenceRefusal extends Error { readonly code: string; constructor(code: string) }
export function hash(value: string): string;
export function mockAttributionHeaders(): Record<string,string>;
export function usdMicros(limit: {currency: 'USD'; amount: string}): number;
export function fromPrimeRoute(route: ModelRoute, mock: {mode:'mock'|'unavailable'; max_request_ms: number;
  input_microusd_per_token: number; output_microusd_per_token: number}): LocalRoute;
export function fromPrimeTask(task: Task, route: LocalRoute, options?: {max_total_tokens?: number}): LocalTask;
export interface TotalTestingBudget {
 version:1;budget_id:string;owner_id:string;provider:'deepseek';route_id:'externalDeepSeek';
 ceiling:{currency:'USD';amount:string};approval_reference:string;
}
export interface TotalBudgetUsage {
 budget_id:string;ceiling_microusd:number;requests:number;tokens:number;cost_microusd:number;remaining_microusd:number;
}
/** Permanent pre-C-reserve fence; no approval proof, operation plaintext, prompt or credential is retained. */
export interface ReserveAttemptRecord {
 binding:DispatchBinding;operation_id:string;operation_digest:Digest;request_digest:Digest;
}
export class SpendLedger {
 constructor(path: string,options?:{total_budget?:TotalTestingBudget});
 requireTotalBudget(owner:string,budget_id:string):TotalTestingBudget & {ceiling_microusd:number};
 storedTotalBudget():TotalTestingBudget|undefined;
 totalBudgetBinding(owner:string,budget_id:string):TotalBudgetBinding;
 totalUsage(owner:string,budget_id:string):TotalBudgetUsage;
 register(task: LocalTask, route: LocalRoute): void;
 task(owner: string, task: string): LocalTask;
 route(owner: string, task: string): LocalRoute;
 usage(owner: string, task: string): {requests: number; tokens: number; cost_microusd: number};
 get(owner: string, task: string, uuid: string): {status: 'reserved'|'dispatched'|'outcome_unknown'|'completed';
   receipt: BodyReceipt; result?: InferenceResult; charged_cost: number; reserved_cost: number; charged_tokens: number; reserved_tokens: number} | undefined;
 /** Private synchronous guard: requires registered trusted task/route and commits before C reserve. Never retry a retained attempt. */
 beginReserveAttempt(binding:DispatchBinding,operation:OperationProposal):ReserveAttemptRecord;
 reserveAttempt(owner:string,task:string,uuid:string):ReserveAttemptRecord|undefined;
 reconcile(owner: string, task: string, uuid: string, usage: {tokens: number; cost_microusd: number; evidence_id: string}): void;
 /** Private worker methods. Recovered phases must never resume claim/HTTP. */
 reserveWorkerIntent(intent:WorkerIntent):WorkerIntent;
 workerIntent(owner:string,task:string,uuid:string):{intent:WorkerIntent;phase:WorkerPhase;claim_reply:WorkerClaimReply|null};
 beginWorkerClaim(owner:string,task:string,uuid:string):void;
 acceptWorkerClaim(owner:string,task:string,uuid:string,reply:unknown):void;
 beginWorkerHttp(owner:string,task:string,uuid:string):void;
 recordWorkerEvidence(owner:string,task:string,uuid:string,reply:ProviderReply|null,observed_at:string,options?:{reconciliation?:boolean}):PendingWorkerSettlement;
 pendingWorkerSettlement(owner:string,task:string,uuid:string):PendingWorkerSettlement|null;
 pendingWorkerRequests(owner:string,options?:{after_request_id?:string;limit?:number}):{owner_id:string;task_id:string;request_id:string;phase:WorkerPhase;outcome:string}[];
 acknowledgeWorkerSettlement(owner:string,task:string,uuid:string,receipt_digest:string,reply:unknown):void;
 close(): void;
}
export interface DispatchBinding {
 owner_id:string; task_id:string; conversation_id:string; request_uuid:string; body_sha256:string;
 binding_hash:string; citations_sha256:string; config_digest:string; reserved_tokens:number;
 reserved_cost_microusd:number; credential_generation:number;total_budget_id:string;
}
export type DispatchAdmission = DispatchBinding & {operation:OperationProposal;consumed_grant:ConsumedGrant;request_digest:Digest};
export interface ProviderRequest extends Omit<DispatchBinding,'config_digest'|'credential_generation'|'total_budget_id'> {
 route_id:'externalDeepSeek'; endpoint:'https://api.deepseek.com';
 body:{model:string; messages:{role:'system'|'user'|'assistant';content:string}[]; max_tokens:number; stream:false; response_format:{type:'json_object'};thinking:{type:'disabled'}};
 citations:SourceCitation[]; headers:Record<string,string>; config_digest:string|null; credential_generation:number|null;total_budget_id:string|null;
 admission?:DispatchAdmission; signal:AbortSignal;
}
export interface ProviderReply {text:string;input_tokens:number;output_tokens:number;source_ids:string[]}
export interface InferenceProvider {
 mode:'mock'|'production'; generate(request:ProviderRequest):Promise<ProviderReply>;
}
export interface MockProvider extends InferenceProvider {mode:'mock'}
export class MockDeepSeekProvider implements MockProvider {
 readonly mode: 'mock'; generate: MockProvider['generate'];
}
export class ExternalDeepSeekGateway {
 readonly route: LocalRoute;
 constructor(options: {route: LocalRoute; ledger: SpendLedger; request_home: string; provider: InferenceProvider;
   authorize_dispatch?:(binding:DispatchBinding)=>Promise<DispatchAdmission>});
 status(): {route_id:string;mode:string;provider:string;model:string;available:boolean;pending:string[]};
 generate(request: InferenceRequest, options?: {signal?: AbortSignal; attribution_headers?: Record<string,string>}): Promise<InferenceResult>;
}
export class RemoteDeepSeekProvider implements InferenceProvider {
 readonly mode:'production';
 constructor(options:{dispatch:(envelope:Omit<ProviderRequest,'signal'>,options:{signal:AbortSignal})=>Promise<ProviderReply>});
 generate(request:ProviderRequest):Promise<ProviderReply>;
}
export interface PricingQualification {
 input_microusd_per_token:number; output_microusd_per_token:number; max_request_ms:number;
 pricing_evidence_id:string; terms_evidence_id:string; served_version:string;
}
/** This helper constructs data; it does not verify an owner proof or enable network access. */
export function fromQualifiedPrimeRoute(route:ModelRoute,qualification:PricingQualification & {credential_generation:number;config_digest:string;total_budget_id:string}):LocalRoute;
export interface ProviderConfiguration {route:ModelRoute;pricing:PricingQualification}
export interface CredentialStatus {configured:boolean;generation:number|null}
export interface CredentialHandoff {provider:'externalDeepSeek';method:'POST';path:'/api/prime/inference/credential-entry';ticket:string;expires_at:string}
export interface ProviderNamespace {
 namespace:'prime-inference'; section:{providers:{externalDeepSeek:{endpoint:'https://api.deepseek.com';model:string;region:string;
 allowedDataClasses:readonly string[];maxInputTokens:number;maxOutputTokens:number;maxRequests:number;enabled:boolean;
 credentialConfigured:boolean;taskSpendCeiling:ModelRoute['task_spend_ceiling']|null}}};
}
export interface OwnerProviderStatus {
 version:1;provider:'externalDeepSeek';configured:boolean;config_digest:string|null;profile:ProviderConfiguration|null;
 credential:CredentialStatus;paid_requests_enabled:boolean;pending:string[];namespace:ProviderNamespace;
}
export const PROVIDER_DIRECTORY:{readonly provider:'externalDeepSeek';readonly displayName:'DeepSeek';readonly settingsNs:'prime-inference';readonly settingsPath:readonly ['providers','externalDeepSeek'];readonly declared:false};
export function mountDshCatalog(ctx:{llm:{registerConfigurableProviders(entries:readonly typeof PROVIDER_DIRECTORY[]):()=>void}}):()=>void;
export function providerNamespace(status?:{profile?:ProviderConfiguration|null;credential?:{configured:boolean};paid_requests_enabled?:boolean}):ProviderNamespace;
export const DEEPSEEK_FLASH_MODEL:{readonly id:'deepseek-flash';readonly name:'DeepSeek V4.1 Flash';readonly status:'unavailable';readonly qualification:'documentation_only';readonly source:'https://api-docs.deepseek.com/updates/';readonly documented_release:'2026-09-10'};
export function providerCatalog():{version:1;providers:(typeof PROVIDER_DIRECTORY & {active:false;endpoint:string;credential_entry:string;paid_requests_enabled:false;models:(typeof DEEPSEEK_FLASH_MODEL)[];credential_status:string;pending:string[]})[];namespace:ProviderNamespace};
export interface OwnerSettingsOptions {
 path:string;validateContract:(kind:'ModelRoute',value:unknown)=>unknown;
 authenticateOwner?:(context:unknown)=>Promise<{owner_id:string}|undefined>;
 approveConfiguration?:(input:{owner_id:string;config_digest:string;payload:ProviderConfiguration;approval_proof:unknown;context:unknown})=>Promise<{owner_id:string;config_digest:string;operation_id:string}>;
 credentials?:{
 status:(owner_id:string,context:unknown)=>Promise<CredentialStatus>;
 createHandoff:(input:{owner_id:string;expected_generation:number;approval_proof:unknown;context:unknown})=>Promise<CredentialHandoff>;
 };
 qualifiedDispatchStatus?:(owner_id:string,config_digest:string,credential_generation:number)=>Promise<{config_digest:string;credential_generation:number;ready:boolean}>;
}
export class OwnerProviderSettings {
 constructor(options:OwnerSettingsOptions);close():void;catalog:typeof providerCatalog;
 owner(context:unknown):Promise<string>;status(context:unknown):Promise<OwnerProviderStatus>;
 configure(context:unknown,input:ProviderConfiguration,approval_proof:unknown):Promise<{configured:true;config_digest:string;paid_requests_enabled:false}>;
 credentialHandoff(context:unknown,input:{expected_generation:number;approval_proof:unknown}):Promise<CredentialHandoff>;
 setCredential():never;
}
export interface HttpRequest extends AsyncIterable<Uint8Array> {url?:string;method?:string;headers:Record<string,string|string[]|undefined>}
export interface HttpResponse {writeHead(status:number,headers:Record<string,string>):unknown;end(body:string):unknown}
export type HttpHandler=(req:HttpRequest,res:HttpResponse)=>Promise<boolean>;
export function createProviderSettingsHandler(options:{settings:OwnerProviderSettings;owner_origin:string;ownerContext?:(req:HttpRequest)=>Promise<unknown>}):HttpHandler;
export interface AuthenticatedInferenceOwner {owner_id:string;subject:string;authorization_epoch:number;expiry:string}
export function createAuthorityOwnerAuthenticator(options:{authority:{authenticateSession(input:{session_token:string}):unknown|Promise<unknown>};sessionToken:(context:unknown)=>unknown|Promise<unknown>}):(context:unknown)=>Promise<AuthenticatedInferenceOwner>;
export {createDshAdapter, mountDshInference} from './dsh-adapter.mjs';
