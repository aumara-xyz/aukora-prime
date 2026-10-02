// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnedExecutorRequest } from '../../../contracts/src/index.ts'
import type { LocalLifetime } from '../lifetime-safety.mjs'
import type { CreateTemplate } from '../create-profile.mjs'
import type { SdkTransport } from '../sdk-transport.ts'
export interface GuardianScope {version:1;ledger_id:string;gateway_identity:string;deployment_digest:string;host_profile_digest:string;workspace:string;image_digest:string;logical_workspace_root:string}
export interface GuardianRegistration {version:1;request:Omit<OwnedExecutorRequest,'signal'>;request_digest:string;ledger_id:string;gateway_identity:string;deployment_digest:string;host_profile_digest:string;name:string;token:string;create_request_id:string;delete_request_id:string;create_template:CreateTemplate;create_profile_digest:string;guest_workdir:string;lifetime:LocalLifetime;lifetime_digest:string}
export interface GuardianResource {uid:string;name:string;workspace:string;owner_token:string|null;origin_request_id:string|null}
export interface GuardianRow {version:1;guardian_id:string;request_id:string;registration:GuardianRegistration;registration_digest:string;mode:'watching'|'cleanup_requested';cleanup_reason:string|null;sandbox_uid:string|null;observation:{state:'present'|'api_absent'|'unavailable'|'identity_mismatch';observed_at:string}|null;reclaim:{request_id:string;sandbox_uid:string;state:'attempted'|'reply_uncertain'|'replied';reply:{sandbox_uid:string;outcome:'reclaimed'|'already_absent'}|null}|null;effect_outcome:'unknown';runtime_qualified:false;terminal_fence:'unavailable';artifact_cleanup:'unverified';last_error:string|null}
/** Trusted guardian bootstrap only. Reclamation must be immutable-identity
 * conditioned and idempotent for request_id; this grants no runtime acceptance. */
export interface GuardianBackend {
 observe(registration:GuardianRegistration,options:{signal:AbortSignal}):Promise<{sandboxes:GuardianResource[];inventory_complete:true}>;
 reclaim(registration:GuardianRegistration,resource:GuardianResource,options:{request_id:string;signal:AbortSignal}):Promise<{sandbox_uid:string;outcome:'reclaimed'|'already_absent'}>;
}
export class GuardianStore {
 constructor(root:string,options:{initialize?:boolean;scope:GuardianScope});
 readonly root:string;readonly identity:string;readonly scope:GuardianScope;
 withOwner<T>(work:()=>Promise<T>):Promise<T>;
 lookup(requestId:string):GuardianRow|null;rows():GuardianRow[];
 register(registration:GuardianRegistration):GuardianRow;save(row:GuardianRow):void;
 observeClock(now?:number):boolean;close():void;
}
export function startGuardian(options:{store:GuardianStore;backend:GuardianBackend;socketPath:string;pollMs?:number;controlTimeoutMs?:number}):Promise<{close:()=>Promise<void>}>;
export function guardianCall(socketPath:string,method:'register',payload:GuardianRegistration,options?:{timeoutMs?:number}):Promise<GuardianRow>;
export function guardianCall(socketPath:string,method:'inspect',payload:{request_id:string;registration_digest:string},options?:{timeoutMs?:number}):Promise<GuardianRow>;
export function guardianCall(socketPath:string,method:'cancel',payload:{request_id:string;registration_digest:string;reason:'caller'|'timeout'|'dispose'},options?:{timeoutMs?:number}):Promise<GuardianRow>;
export function guardianRegistrationDigest(registration:GuardianRegistration):`sha256:${string}`;
export class PinnedGuardianBackend implements GuardianBackend {
 constructor(transport:SdkTransport,scope:GuardianScope);
 observe(registration:GuardianRegistration,options:{signal:AbortSignal}):ReturnType<GuardianBackend['observe']>;
 reclaim():Promise<never>;
}
