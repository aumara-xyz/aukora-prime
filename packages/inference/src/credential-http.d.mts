import type { ProviderRequest, ProviderReply } from './index.mjs';
/** Server-only. The callback and transport may access a key; never load in app host or renderer. */
export interface CredentialUse {
 <T>(owner_id:string,generation:number,callback:(secret:string)=>Promise<T>):Promise<T>;
}
export class DeepSeekHttpProvider {
 constructor(options:{useCredential:CredentialUse;transport?:typeof fetch});
 generate(request:ProviderRequest & {served_version?:string}):Promise<ProviderReply>;
}
