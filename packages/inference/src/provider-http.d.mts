import type { HttpHandler, HttpRequest } from './index.mjs';
export { createProviderSettingsHandler } from './index.mjs';
/** Server-only, direct HTTPS route to the credential UID. */
export function createCredentialEntryHandler(options:{owner_origin:string;ownerContext?:(req:HttpRequest)=>Promise<unknown>;
 service:{submitEntry(context:unknown,input:{ticket:string;secret:string}):Promise<{configured:true;generation:number}>}}):HttpHandler;
