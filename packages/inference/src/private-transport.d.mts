import type {ProviderRequest,ProviderReply} from './index.mjs';
export type PrivateInferenceDispatch = (envelope:Omit<ProviderRequest,'signal'>,
  options:{signal:AbortSignal})=>Promise<ProviderReply>;
export interface PrivateInferenceDispatchOptions {
 /** H/Bridge-owned protected request submission, with cancellation of this authenticated invocation. */
 send?:PrivateInferenceDispatch;
 /** Bounded local wait from approved route policy; not an approval or spend allowance. */
 max_request_ms:number;max_request_bytes:number;
}
export function createPrivateInferenceDispatch(options:PrivateInferenceDispatchOptions):PrivateInferenceDispatch;
export function createPrivateInferenceReceiver(options:{
 /** Existing separated service only in production. No service is constructed or mounted here. */
 service?:{dispatch:PrivateInferenceDispatch};max_request_bytes:number;
}):PrivateInferenceDispatch;
