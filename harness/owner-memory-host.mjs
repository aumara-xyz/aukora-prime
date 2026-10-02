// SPDX-License-Identifier: AGPL-3.0-or-later
// Unmounted root assembly. Protected channel/release pins and the existing
// connection/origin guards are host inputs; no qualification is created here.
import {createOwnerMemoryIpcBoundary} from './owner-memory-ipc.mjs';
import {createOwnerMemoryHttpRoutes} from './owner-memory-transport.mjs';

export function createOwnerMemoryHost({connection,guardRequest,contracts,channel,deployment}={}) {
 const publicBoundary=createOwnerMemoryIpcBoundary({channel,deployment});
 const routes=createOwnerMemoryHttpRoutes({connection,guardRequest,contracts,publicBoundary});
 return Object.freeze({publicBoundary,routes:Object.freeze(routes)});
}

/** Trusted composition calls this inside its own Cordis effect. This function
 * registers existing exact routes; it starts no listener and creates no
 * deployment acceptance. The default preview does not call it. */
export function mountOwnerMemoryHost({webServer,connection,guardRequest,contracts,channel,deployment}={}) {
 if(typeof webServer?.register!=='function'||typeof connection?.requestRejection!=='function'
  ||typeof guardRequest!=='function'||typeof contracts?.parseStrictJson!=='function'
  ||typeof contracts?.canonicalJson!=='function'||!channel||!deployment)
  throw new TypeError('UNAVAILABLE: protected owner-memory composition required');
 let active=true;
 const boundary=createOwnerMemoryIpcBoundary({channel,deployment,isActive:()=>active});
 const disposers=[];
 const unavailable=()=>({ok:false,error_code:'UNAVAILABLE',reason:'OWNER_MEMORY_HOST_DISPOSED'});
 // Recheck after HTTP body collection, immediately before crossing to IPC.
 // Disposal never cancels or retries an effect already submitted to the worker.
 const publicBoundary=Object.freeze({handlePublic(method,input,context){
  return active?boundary.handlePublic(method,input,context):Promise.resolve(unavailable());
 }});
 const routes=createOwnerMemoryHttpRoutes({connection,guardRequest,contracts,publicBoundary});
 const dispose=()=>{
  active=false;
  const failures=[];
  // Retain failed cleanups so a later disposal can retry unregistering them.
  for(let index=disposers.length-1;index>=0;index--){
   try {disposers[index]();disposers.splice(index,1);}
   catch {failures.push(new Error('OWNER_MEMORY_ROUTE_CLEANUP_FAILED'));}
  }
  if(failures.length)throw new AggregateError(failures,'OWNER_MEMORY_HOST_CLEANUP_FAILED');
 };
 try {
  for(const route of routes){
   const remove=webServer.register({...route,handler(request,response){
    if(active)return route.handler(request,response);
    if(response.destroyed||response.writableEnded)return;
    response.writeHead(503,{'content-type':'application/json; charset=utf-8','cache-control':'no-store',
     'x-content-type-options':'nosniff','connection':'close'});
    response.end(contracts.canonicalJson(unavailable()));
   }});
   if(typeof remove!=='function')throw new TypeError('UNAVAILABLE: owned route disposer required');
   disposers.push(remove);
  }
 } catch(error){
  try {dispose();}catch(cleanup){
   const failure=new AggregateError([error,cleanup],'OWNER_MEMORY_HOST_REGISTRATION_FAILED');
   Object.defineProperty(failure,'dispose',{value:dispose});
   throw failure;
  }
  throw error;
 }
 return dispose;
}
