import type { GenerateOptions, LlmAdapter } from '@deepseek-ai/dsh-llm';
import type { ExternalDeepSeekGateway, InferenceRequest } from './index.mjs';
export interface DshBindings {
 gateway: ExternalDeepSeekGateway;
 bindRequest(options: GenerateOptions): InferenceRequest | Promise<InferenceRequest>;
 attributionHeaders(): Record<string,string>;
}
export function createDshAdapter(base: typeof LlmAdapter, bindings: DshBindings): LlmAdapter;
export function mountDshInference(ctx: {llm: {registerAdapter(routes: string[], adapter: LlmAdapter): unknown}},
 base: typeof LlmAdapter, bindings: DshBindings): LlmAdapter;
