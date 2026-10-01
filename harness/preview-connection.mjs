// Preserve pinned DSH carrier semantics while validating actual HTTP JSON text before decoding.
// Composed beside the pinned connection bundle as lib/prime-host.mjs.
import {apply as applyPinned,HostConnectionService} from './index.js';
import {parseStrictJson} from '../../../../prime-packages/contracts/src/runtime.mjs';
import {parseIngressBytes,decodeStrictUtf8} from '../../../../harness/ingress.mjs';
export const inject=['credentials'];
const original=HostConnectionService.prototype.createSharedFetchHandler;
HostConnectionService.prototype.createSharedFetchHandler=function(channel) {
 const handler=original.call(this,channel);
 return {...handler,fetch:async request=>{
  if(request.method!=='POST')return handler.fetch(request);
  let text;
  try{const bytes=new Uint8Array(await request.arrayBuffer());parseIngressBytes(bytes,parseStrictJson);text=decodeStrictUtf8(bytes);}
  catch{return new Response(JSON.stringify({ok:false,error_code:'INVALID',reason:'Strict JSON ingress refused'}),{status:400,headers:{'content-type':'application/json'}});}
  return handler.fetch(new Request(request.url,{method:request.method,headers:request.headers,body:text,signal:request.signal}));
 }};
};
export const apply=applyPinned;
