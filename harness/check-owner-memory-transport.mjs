// SOURCE-ONLY scoped HTTP adapter check. Fake streams/dispatcher only; no
// listener, credentials, authority, memory, browser or production qualification.
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import * as contracts from '../packages/contracts/src/runtime.mjs';
import {createRuntimeBridge,PUBLIC_METHODS} from '../packages/runtime-bridge/src/index.mjs';
import {createLocalhostPilotGuard} from '../packages/runtime-bridge/src/pilot-origin.mjs';
import {createOwnerMemoryHttpRoutes} from './owner-memory-transport.mjs';
import {createOwnerMemoryHttpCall,OWNER_MEMORY_METHODS} from './owner-memory-browser.mjs';
import {createOwnerMemoryIpcBoundary} from './owner-memory-ipc.mjs';
const guardRequest=createLocalhostPilotGuard({profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'});
const connection={requestRejection:()=>undefined};
let checks=0,calls=[];
const boundary={async handlePublic(method,input,context){calls.push({method,input,context});return {ok:true,status:'SOURCE_ONLY_DISPATCH_FIXTURE'};}};
const options={connection,publicBoundary:boundary,guardRequest,contracts};
const routes=createOwnerMemoryHttpRoutes(options);
class Response {
 destroyed=false;writableEnded=false;status=0;headers={};body='';
 writeHead(status,headers){this.status=status;this.headers=headers;}
 end(body){this.writableEnded=true;this.body=body??'';}
}
async function invoke({method='memory.save',payload='{}',headers={},verb='POST',url,encoding,routes:given=routes,response}={}){
 const request=Readable.from([typeof payload==='string'?Buffer.from(payload):payload]);
 request.method=verb;request.url=url??'/api/prime/bridge/'+method;
 request.headers={host:'localhost:18731',origin:'http://localhost:18731','content-type':'application/json',...headers};
 if(encoding)request.setEncoding(encoding);
 const res=response??new Response();
 await given.find(x=>x.path==='/api/prime/bridge/'+method).handler(request,res);
 return res;
}
async function refuse(input,status,code){const count=calls.length;const res=await invoke(input);assert.equal(res.status,status);assert.equal(JSON.parse(res.body).error_code,code);assert.equal(calls.length,count);checks++;}
assert.deepEqual([...OWNER_MEMORY_METHODS].sort(),[...PUBLIC_METHODS].sort());checks++;
assert(!routes.some(route=>route.path.includes('reserve')||route.path.includes('settle')||route.path.includes('claim')));checks++;
let res=await invoke({payload:'{"role":"proposer","marker":"literal"}'});
assert.equal(res.status,200);assert.equal(calls.at(-1).context.role,'owner_control');
assert.equal(calls.at(-1).input.role,'proposer');assert.deepEqual(Object.keys(calls.at(-1).context.request).sort(),['host','origin','request_id','transport']);checks++;
res=await invoke({method:'memory.cite'});assert.equal(calls.at(-1).context.role,'read_only');assert.equal(res.headers['cache-control'],'no-store');checks++;
await refuse({routes:createOwnerMemoryHttpRoutes()},503,'UNAVAILABLE');
await refuse({routes:createOwnerMemoryHttpRoutes({...options,connection:{requestRejection:()=>401}})},401,'UNAUTHORIZED');
await refuse({routes:createOwnerMemoryHttpRoutes({...options,guardRequest:()=>true})},400,'INVALID');
await refuse({headers:{origin:'http://127.0.0.1:18731',host:'127.0.0.1:18731'}},400,'INVALID');
await refuse({headers:{origin:'http://localhost:18732',host:'localhost:18732'}},400,'INVALID');
await refuse({headers:{origin:undefined}},400,'INVALID');
await refuse({verb:'GET'},405,'INVALID');
await refuse({url:'/api/prime/bridge/a/../memory.save'},400,'INVALID');
await refuse({url:'/api/prime/bridge/memory.save?owner=guest'},400,'INVALID');
await refuse({headers:{'content-type':'text/plain'}},400,'INVALID');
await refuse({headers:{'content-length':'65537'}},400,'INVALID');
await refuse({payload:'{"value":1,"value":2}'},400,'INVALID');
await refuse({payload:Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d])},400,'INVALID');
await refuse({payload:'{}',encoding:'utf8'},400,'INVALID');
await refuse({payload:Buffer.alloc(65537,32)},400,'INVALID');
await refuse({payload:'[]'},400,'INVALID');
res=await invoke({routes:createOwnerMemoryHttpRoutes({...options,publicBoundary:createRuntimeBridge()})});
assert.equal(res.status,503);assert.equal(JSON.parse(res.body).error_code,'UNAVAILABLE');checks++;
for(const method of ['memory.save','memory.cite']){
 const thrownRoutes=createOwnerMemoryHttpRoutes({...options,publicBoundary:{async handlePublic(){throw new Error('synthetic-private-error-material');}}});
 res=await invoke({method,routes:thrownRoutes});assert.equal(JSON.parse(res.body).error_code,method==='memory.save'?'OUTCOME_UNKNOWN':'UNAVAILABLE');assert(!res.body.includes('private'));checks++;
}
const oversized=createOwnerMemoryHttpRoutes({...options,publicBoundary:{async handlePublic(){return {ok:true,value:'x'.repeat(65536)};}}});
res=await invoke({routes:oversized});assert.equal(JSON.parse(res.body).error_code,'OUTCOME_UNKNOWN');checks++;
const gone=new Response();gone.destroyed=true;const before=calls.length;await invoke({response:gone});assert.equal(calls.length,before+1);assert.equal(gone.status,0);checks++;
const reply=text=>new globalThis.Response(text,{status:200,headers:{'content-type':'application/json'}});
let fetches=0,last;
const call=createOwnerMemoryHttpCall({contracts,fetcher:async(url,input)=>{fetches++;last={url,input};return reply('{"ok":true,"status":"SOURCE_ONLY_HTTP_FIXTURE"}');}});
assert.equal((await call('memory.save',{})).ok,true);assert.equal(fetches,1);assert.equal(last.url,'/api/prime/bridge/memory.save');assert.equal(last.input.redirect,'error');assert.equal(last.input.credentials,'same-origin');checks++;
assert.equal((await call('authority.reserve',{})).error_code,'INVALID');assert.equal(fetches,1);checks++;
const abort=new AbortController();abort.abort();assert.equal((await call('memory.save',{}, {signal:abort.signal})).error_code,'UNAVAILABLE');assert.equal(fetches,1);checks++;
for(const text of ['{"ok":true,"ok":false}','{"ok":true,"blob":"'+'x'.repeat(65536)+'"}']){
 let attempts=0;const broken=createOwnerMemoryHttpCall({contracts,fetcher:async()=>{attempts++;return reply(text);}});
 assert.equal((await broken('memory.save',{})).error_code,'OUTCOME_UNKNOWN');assert.equal(attempts,1);checks++;
}
let attempts=0;const lost=createOwnerMemoryHttpCall({contracts,fetcher:async()=>{attempts++;throw new Error('reply lost');}});
assert.equal((await lost('memory.save',{})).error_code,'OUTCOME_UNKNOWN');assert.equal(attempts,1);checks++;
assert.equal((await lost('memory.cite',{})).error_code,'UNAVAILABLE');assert.equal(attempts,2);checks++;
// A timed-out/disconnected request is never retried; capacity remains charged
// until the actual dispatcher settles. Exercise only the finite inflight guard.
const finishes=[];const bounded=createOwnerMemoryHttpRoutes({...options,publicBoundary:{handlePublic(){return new Promise(resolve=>finishes.push(()=>resolve({ok:true})));}}});
const pending=Array.from({length:8},()=>invoke({routes:bounded}));
await new Promise(resolve=>setImmediate(resolve));assert.equal(finishes.length,8);
res=await invoke({routes:bounded});assert.equal(res.status,503);assert.equal(JSON.parse(res.body).reason,'HTTP_INFLIGHT_BOUND');
for(const finish of finishes)finish();await Promise.all(pending);checks++;
// Explicit fake IPC primitive only, to verify transport sequencing/profile
// refusal. This does not create or verify any production acceptance record.
const deployment={source_commit:'a'.repeat(40),release_digest:'sha256:'+'b'.repeat(64)};
const channel={socketPath:'/synthetic/not-opened.sock',credential:{id:'synthetic',secret:'c'.repeat(64)}};
assert.equal((await createOwnerMemoryIpcBoundary().handlePublic('memory.save',{})).error_code,'UNAVAILABLE');checks++;
const never=createOwnerMemoryIpcBoundary({channel,deployment,connect:async()=>{throw new Error('must not connect');}});
assert.equal((await never.handlePublic('capability.status',{guest:'override'})).error_code,'INVALID');
assert.equal((await never.handlePublic('memory.save',[])).error_code,'INVALID');checks++;
for(const capability of [true,{ok:true,available:false},
 {ok:true,available:true,public_routes:'available',qualification:deployment},
 {ok:true,available:true,public_routes:'available',public_dispatch:'qualified-owner-memory/v1',qualification:{...deployment,source_commit:'d'.repeat(40)}}]){
 const sent=[];let closed=0;
 const proxy=createOwnerMemoryIpcBoundary({channel,deployment,connect:async()=>({async request(method){sent.push(method);return capability;},async close(){closed++;}})});
 assert.equal((await proxy.handlePublic('memory.save',{})).error_code,'UNAVAILABLE');assert.deepEqual(sent,['capability.status']);assert.equal(closed,1);checks++;
}
for(const lost of [false,true]){
 const sent=[];let closed=0;
 const proxy=createOwnerMemoryIpcBoundary({channel,deployment,connect:async()=>({async request(method,input){
  sent.push({method,input});if(method==='capability.status')return {ok:true,available:true,public_routes:'available',public_dispatch:'qualified-owner-memory/v1',qualification:deployment};
  if(lost)throw new Error('synthetic lost reply');return {ok:true,status:'SOURCE_ONLY_IPC_FIXTURE'};
 },async close(){closed++;}})});
 const reply=await proxy.handlePublic('memory.save',{marker:'literal'},{request:{credential_id:'guest'},role:'guest'});
 assert.equal(reply.error_code,lost?'OUTCOME_UNKNOWN':undefined);assert.equal(sent.length,2);assert.deepEqual(sent[1],{method:'memory.save',input:{marker:'literal'}});assert.equal(closed,1);checks++;
}
console.log(JSON.stringify({status:'PASS',checks,scope:'source-only HTTP/browser adapters and guards',actual_authority_or_PG:false,listener_started:false,production_qualification:false}));
