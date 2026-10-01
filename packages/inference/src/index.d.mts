import type { Task, ModelRoute } from '@aukora-prime/contracts';
export interface LocalRoute {
  route_id: 'externalDeepSeek'; provider: 'deepseek'; endpoint: 'https://api.deepseek.com'; model: string;
  allowed_data_classes: readonly string[]; max_input_tokens: number; max_output_tokens: number; max_request_ms: number;
  mode: 'mock'|'unavailable'; input_microusd_per_token: number; output_microusd_per_token: number;
  max_requests: number; spend_cap_microusd: number; region: string; transport_status: ModelRoute['status'];
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
 | { outcome: 'completed'; request_uuid: string; route_id: 'externalDeepSeek'; mode: 'mock';
     proposal: {text: string; source_ids: string[]; grantsAuthority: false}; usage: {input_tokens: number; output_tokens: number; cost_microusd: number};
     receipt: BodyReceipt; omitted: {reason: string}[] };
export class InferenceRefusal extends Error { readonly code: string; constructor(code: string) }
export function hash(value: string): string;
export function mockAttributionHeaders(): Record<string,string>;
export function usdMicros(limit: {currency: 'USD'; amount: string}): number;
export function fromPrimeRoute(route: ModelRoute, mock: {mode:'mock'|'unavailable'; max_request_ms: number;
  input_microusd_per_token: number; output_microusd_per_token: number}): LocalRoute;
export function fromPrimeTask(task: Task, route: LocalRoute, options?: {max_total_tokens?: number}): LocalTask;
export class SpendLedger {
 constructor(path: string);
 register(task: LocalTask, route: LocalRoute): void;
 task(owner: string, task: string): LocalTask;
 route(owner: string, task: string): LocalRoute;
 usage(owner: string, task: string): {requests: number; tokens: number; cost_microusd: number};
 get(owner: string, task: string, uuid: string): {status: 'reserved'|'dispatched'|'outcome_unknown'|'completed';
   receipt: BodyReceipt; result?: InferenceResult; charged_cost: number; reserved_cost: number; charged_tokens: number; reserved_tokens: number} | undefined;
 reconcile(owner: string, task: string, uuid: string, usage: {tokens: number; cost_microusd: number; evidence_id: string}): void;
 close(): void;
}
export interface MockProvider {
 mode: 'mock'; generate(request: {route_id: string; endpoint: string; body: {model: string; messages: {role:string;content:string}[]; max_tokens: number; stream:false};
   request_uuid: string; body_sha256: string; citations: SourceCitation[]; signal: AbortSignal; headers: Record<string,string>}):
   Promise<{text:string;input_tokens:number;output_tokens:number;source_ids:string[]}>;
}
export class MockDeepSeekProvider implements MockProvider {
 readonly mode: 'mock'; generate: MockProvider['generate'];
}
export class ExternalDeepSeekGateway {
 readonly route: LocalRoute;
 constructor(options: {route: LocalRoute; ledger: SpendLedger; request_home: string; provider: MockProvider});
 status(): {route_id:string;mode:string;provider:string;model:string;available:boolean;pending:string[]};
 generate(request: InferenceRequest, options?: {signal?: AbortSignal; attribution_headers?: Record<string,string>}): Promise<InferenceResult>;
}
export {createDshAdapter, mountDshInference} from './dsh-adapter.mjs';
