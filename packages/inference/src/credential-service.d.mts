import type { Buffer } from 'node:buffer';
import type { CredentialHandoff, CredentialStatus, LocalRoute, LocalTask, ProviderRequest, ProviderReply } from './index.mjs';
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
 application_uid:number;spend_path:string;
 authenticateOwner:(context:unknown)=>Promise<{owner_id:string}|undefined>;
 approveCredentialEntry:(input:{owner_id:string;provider:'externalDeepSeek';expected_generation:number;approval_proof:unknown;context:unknown})=>Promise<{owner_id:string;provider:'externalDeepSeek';expected_generation:number;operation_id:string}>;
 verifyDispatchAdmission:(request:Omit<ProviderRequest,'signal'>)=>Promise<boolean>;
 getQualifiedRoute:(owner_id:string)=>Promise<LocalRoute>;
 getAuthorizedTask:(owner_id:string,task_id:string)=>Promise<LocalTask>;
}
export class SeparatedCredentialService {
 constructor(options:SeparatedServiceOptions);close():void;
 createHandoff(input:{owner_id:string;expected_generation:number;approval_proof:unknown;context:unknown}):Promise<CredentialHandoff>;
 submitEntry(context:unknown,input:{ticket:string;secret:string}):Promise<{configured:true;generation:number}>;
 status(owner_id:string,context:unknown):Promise<CredentialStatus>;
 dispatch(request:Omit<ProviderRequest,'signal'>,options?:{signal?:AbortSignal}):Promise<ProviderReply>;
}
