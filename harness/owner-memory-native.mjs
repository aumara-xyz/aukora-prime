// SPDX-License-Identifier: AGPL-3.0-or-later
// Trusted browser composition. Importing alone creates no owner binding.
import {createOwnerMemoryClient} from './owner-memory-client.mjs';

/** Provide within the native composition's own lifetime. B's read-only exact
 * connection acknowledgement gates explicit attachment and each later use. */
export function createOwnerMemoryNativeBinding(scope,{contracts,ownerBinding,fetcher,passkeySigner,observeAuthorityCall,observeAuthorityReply}={}) {
 const controller=scope?.primeOwnerUi;
 const acknowledgement=scope?.primeOwnerNativeConnection;
 if(!controller||typeof scope?.reflect?.provide!=='function'||scope.primeAuthority!==undefined
  ||acknowledgement?.controller!==controller||typeof acknowledgement?.isConnected!=='function')
  throw new TypeError('UNAVAILABLE: unbound native owner UI scope required');
 const isCurrentConnection=binding=>scope.primeOwnerUi===controller
  &&scope.primeOwnerNativeConnection===acknowledgement&&scope.primeAuthority===binding
  &&acknowledgement.isConnected(binding)===true;
 const client=createOwnerMemoryClient({controller,contracts,ownerBinding,fetcher,passkeySigner,isCurrentConnection,observeAuthorityCall,observeAuthorityReply});
 let disposed=false,attached=false,attaching=false,disposing=false,removeAuthority;
 const current=()=>{
  if(disposed||scope.primeOwnerUi!==controller||scope.primeAuthority!==client.binding)
   throw new TypeError('UNAVAILABLE: native owner binding is no longer current');
 };
 const acknowledged=()=>{current();if(!isCurrentConnection(client.binding))throw new TypeError('UNAVAILABLE: exact native connection is not current');};
 const connected=()=>{current();if(!attached)throw new TypeError('UNAVAILABLE: native owner client is not attached');acknowledged();};
 const dispose=()=>{
  disposed=true;
  if(disposing)return;
  disposing=true;
  const failures=[];
  try {
   // The client fences work and removes the panel before the authority service.
   // Attempt both cleanups; a failed remover stays owned for a later retry.
   try{client.dispose();}catch{failures.push(new Error('OWNER_MEMORY_CLIENT_CLEANUP_FAILED'));}
   if(removeAuthority){try{removeAuthority();removeAuthority=undefined;}
    catch{failures.push(new Error('OWNER_MEMORY_AUTHORITY_CLEANUP_FAILED'));}}
  }finally{disposing=false;}
  if(failures.length)throw new AggregateError(failures,'OWNER_MEMORY_NATIVE_CLEANUP_FAILED');
 };
 const fail=error=>{
  try{dispose();}catch(cleanup){
   const failure=new AggregateError([error,cleanup],'OWNER_MEMORY_NATIVE_BINDING_FAILED');
   Object.defineProperty(failure,'dispose',{value:dispose});
   throw failure;
  }
  throw error;
 };
 try {
  const remover=scope.reflect.provide('primeAuthority',client.binding);
  if(typeof remover!=='function')throw new TypeError('UNAVAILABLE: owned authority disposer required');
  removeAuthority=remover;
  current();
 }catch(error){fail(error);}
 return Object.freeze({
  attachAfterNativeConnection(){
   acknowledged();
   if(attaching)throw new TypeError('UNAVAILABLE: native owner attachment in progress');
   if(attached)return client;
   attaching=true;
   try{
    // Do not call controller.connect here: B's native injection owns its
    // supplied flag and prevents the async fallback from replacing the hook.
    client.attach();acknowledged();attached=true;
    client.providePilotMemory(scope);
    acknowledged();
    return client;
   }catch(error){fail(error);}
   finally{attaching=false;}
  },
  get client(){connected();return client;},
  setCapabilities(value){connected();client.setCapabilities(value);},
  capabilitiesUnavailable(){connected();client.capabilitiesUnavailable();},
  dispose,
 });
}
