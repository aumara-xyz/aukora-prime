// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only H join: current Prime factories, bounded fake HTTP streams and disposable
// same-UID IPC/SQLite. No accepted production qualifier or deployed C/PG/UID proof.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {mkdtemp,realpath,readFile,rm,lstat} from 'node:fs/promises'
import {join,resolve} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {Readable,Writable} from 'node:stream'
import {finished} from 'node:stream/promises'
import {createTrustedTaskRegistry} from '../src/registry.mjs'
import {startMemoryWorker,startPublicMemoryWorker} from '../src/worker.mjs'
import {createIpcClient} from '../src/ipc.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {authorityFixture} from './authority-fixture.mjs'
import {FixturePool} from './sql-fixture.mjs'
import {fixture as ownerFixture,draft,extraction,assertSaved} from './owner-memory-fixture.mjs'

const primeRoot=await realpath(fileURLToPath(new URL('../../../',import.meta.url)))
const hostRoot=process.env.PRIME_OWNER_MEMORY_HOST_ROOT??primeRoot
const helperExports={
  'owner-memory-browser.mjs':{OWNER_MEMORY_METHODS:'object',createOwnerMemoryHttpCall:'function'},
  'owner-memory-transport.mjs':{createOwnerMemoryHttpRoutes:'function'},
  'owner-memory-ipc.mjs':{createOwnerMemoryIpcBoundary:'function'},
  'owner-memory-context.mjs':{createOwnerMemoryContext:'function'},
}
// Selected static imports and explicit own-root dynamic imports of those four
// helpers. Compare an optional snapshot to the current checkout's source files,
// rather than treating an old standalone hash as the current H implementation.
const helperClosure=[
  ...Object.keys(helperExports).map(file=>'harness/'+file),
  'packages/contracts/src/runtime.mjs','packages/contracts/src/browser.mjs',
  'packages/contracts/src/shared.mjs','packages/contracts/src/json.mjs',
  'packages/runtime-bridge/src/ipc.mjs','packages/runtime-bridge/src/registry.mjs',
  'packages/memory/src/codecs.mjs','packages/memory/src/capture-review.mjs',
  ...['memory-forget.mjs','memory-tiers.mjs','memory-law.mjs','strict-read.mjs','record.mjs']
    .map(file=>'packages/memory/genesis/plugins/aukora-kira/lib/'+file),
  ...['envelope.js','ingestGate.js'].map(file=>'packages/memory/genesis/vendor/aukora-packages/lib/packages/memory/src/'+file),
  ...['canonical.js','errors.js'].map(file=>'packages/memory/genesis/vendor/authority/lib/'+file),
  ...['sha2.js','utils.js','_md.js','_u64.js'].map(file=>'packages/memory/genesis/vendor/authority/deps/@noble/hashes@2.2.0/'+file),
]
let hostModules
async function host(){
  if(!hostModules)hostModules=(async()=>{
    assert.equal(resolve(hostRoot),hostRoot,'host source must be absolute')
    const selectedRoot=await realpath(hostRoot)
    await assert.rejects(lstat(join(selectedRoot,'prime-release.json')),error=>error?.code==='ENOENT',
      'this source-only H join must reject a release layout before module import')
    for(const file of helperClosure){
      const source=join(selectedRoot,file),metadata=await lstat(source)
      assert(metadata.isFile()&&!metadata.isSymbolicLink(),'H closure must contain regular source: '+file)
      assert((await realpath(source)).startsWith(selectedRoot+'/'),'H closure must remain in its selected Prime root: '+file)
      const [bytes,current]=await Promise.all([readFile(source),readFile(join(primeRoot,file))])
      assert.equal(createHash('sha256').update(bytes).digest('hex'),createHash('sha256').update(current).digest('hex'),
        'H snapshot must match the current Prime helper closure: '+file)
    }
    const [browser,transport,ipc,context,contracts]=await Promise.all([
      ...Object.keys(helperExports).map(file=>import(pathToFileURL(join(selectedRoot,'harness',file)).href)),
      import(pathToFileURL(join(hostRoot,'packages/contracts/src/runtime.mjs')).href),
    ])
    for(const [index,[file,expected]] of Object.entries(helperExports).entries()){
      const module=[browser,transport,ipc,context][index]
      assert.deepEqual(Object.keys(module).sort(),Object.keys(expected).sort(),'exact H exported hooks: '+file)
      for(const [name,type] of Object.entries(expected))assert.equal(typeof module[name],type,'H export '+name)
    }
    assert(Array.isArray(browser.OWNER_MEMORY_METHODS)&&Object.isFrozen(browser.OWNER_MEMORY_METHODS))
    assert.equal(typeof contracts.parseStrictJson,'function');assert.equal(typeof contracts.canonicalJson,'function')
    return {...browser,...transport,...ipc,...context,contracts}
  })()
  return hostModules
}

const origin='https://prime.example.test',hostname='prime.example.test',at='2026-10-01T11:03:00Z'
const refusal={ok:false,error_code:'UNAVAILABLE',reason:'QUALIFIED_PUBLIC_WORKER_REQUIRED'}
class BoundedResponse extends Writable {
  constructor(){super({autoDestroy:false});this.statusCode=null;this.headers={};this.chunks=[];this.bytes=0;this.writes=0}
  writeHead(status,headers){this.statusCode=status;this.headers=headers;return this}
  _write(chunk,encoding,done){
    this.writes++;this.bytes+=chunk.length
    if(this.bytes>65536)return done(new Error('SYNTHETIC_HTTP_RESPONSE_BOUND'))
    this.chunks.push(Buffer.from(chunk));done()
  }
  body(){return Buffer.concat(this.chunks,this.bytes)}
}
function routes(h,publicBoundary){
  return h.createOwnerMemoryHttpRoutes({contracts:h.contracts,publicBoundary,
    connection:{requestRejection:()=>undefined},
    guardRequest:()=>({profile:'https',origin,rp_id:hostname}),
  })
}
async function http(routes,h,method,input,overrides={}){
  const bytes=overrides.body??Buffer.from(h.contracts.canonicalJson(input))
  const request=Readable.from([bytes]),response=new BoundedResponse()
  request.method=overrides.verb??'POST';request.url=overrides.url??'/api/prime/bridge/'+method
  request.headers={host:hostname,origin,'content-type':'application/json','content-length':String(bytes.length),...overrides.headers}
  try{
    await routes.find(route=>route.path==='/api/prime/bridge/'+method).handler(request,response)
    await finished(response)
    return {response,value:h.contracts.parseStrictJson(response.body().toString('utf8'))}
  }finally{request.destroy()}
}
function browserResponse(response){
  const bytes=new Uint8Array(response.body())
  return {ok:response.statusCode>=200&&response.statusCode<300,redirected:false,
    headers:new Headers(response.headers),body:new ReadableStream({start(controller){
      for(let offset=0;offset<bytes.length;offset+=1024)controller.enqueue(bytes.slice(offset,offset+1024))
      controller.close()
    }}),
  }
}

test('current H HTTP factories reject closed Host/Origin and malformed bounded input before dispatch',async()=>{
  const h=await host();let dispatched=0
  const endpoints=routes(h,{async handlePublic(){dispatched++;return refusal}})
  for(const changed of [
    {headers:{host:'guest.example.test'}},{headers:{origin:'https://guest.example.test'}},
    {headers:{origin:origin+'/path'}},{headers:{host:[hostname]}},{headers:{origin:undefined}},
    {url:'/api/prime/bridge/owner.loginChallenge?owner_id=guest'},
    {headers:{'content-type':'text/plain'}},{headers:{'content-length':'65537'}},
    {body:Buffer.from('{"owner_id":"guest","owner_id":"spoofed"}')},
    {body:Buffer.from([0xef,0xbb,0xbf,0x7b,0x7d])},{body:Buffer.from([0xc3,0x28])},
    {body:Buffer.alloc(65537,0x20),headers:{'content-length':undefined}},
  ]){
    const reply=await http(endpoints,h,'owner.loginChallenge',{owner_id:'guest',kind:'passkey'},changed)
    assert.equal(reply.response.statusCode,400)
    assert.equal(reply.value.ok,false)
    assert.equal(reply.value.error_code,'INVALID')
    assert.equal(dispatched,0,'invalid HTTP metadata/bytes must not reach a worker')
  }
  const get=await http(endpoints,h,'owner.loginChallenge',{}, {verb:'GET'})
  assert.equal(get.response.statusCode,405);assert.equal(dispatched,0)
})

test('current H browser performs one fetch and reports lost mutation replies as unknown without replay',async()=>{
  const h=await host()
  for(const method of ['memory.save','memory.status']){
    let fetches=0,dispatched=0
    const endpoints=routes(h,{async handlePublic(){dispatched++;return refusal}})
    const call=h.createOwnerMemoryHttpCall({contracts:h.contracts,fetcher:async(url,options)=>{
      fetches++;assert.equal(url,'/api/prime/bridge/'+method)
      assert.equal(options.method,'POST');assert.equal(options.credentials,'same-origin')
      assert.equal(options.mode,'same-origin');assert.equal(options.redirect,'error')
      await http(endpoints,h,method,h.contracts.parseStrictJson(options.body))
      throw new Error('SYNTHETIC_HTTP_REPLY_LOST')
    }})
    assert.deepEqual(await call(method,{}),{ok:false,error_code:method==='memory.save'?'OUTCOME_UNKNOWN':'UNAVAILABLE',reason:'BRIDGE_REPLY_UNAVAILABLE'})
    assert.equal(fetches,1);assert.equal(dispatched,1)
  }
  for(const kind of ['truncated','oversized']){
    let fetches=0,reads=0,cancels=0,releases=0
    const call=h.createOwnerMemoryHttpCall({contracts:h.contracts,fetcher:async()=>{
      fetches++;return {ok:true,redirected:false,headers:new Headers({'content-type':'application/json'}),
        body:{getReader:()=>({async read(){reads++;if(kind==='oversized')return {done:false,value:new Uint8Array(65537)};
          if(reads===1)return {done:false,value:new TextEncoder().encode('{"ok":')};throw new Error('SYNTHETIC_TRUNCATED_REPLY')},
          async cancel(){cancels++},releaseLock(){releases++}})}}
    }})
    assert.deepEqual(await call('memory.save',{}),{ok:false,error_code:'OUTCOME_UNKNOWN',reason:'BRIDGE_REPLY_UNAVAILABLE'})
    assert.equal(fetches,1);assert.equal(cancels,1);assert.equal(releases,1)
  }
})

test('current H HTTP disconnect does not abort or replay an already submitted call',async()=>{
  const h=await host();let dispatched=0,release,entered
  const ready=new Promise(resolve=>{entered=resolve}),reply=new Promise(resolve=>{release=resolve})
  const endpoints=routes(h,{async handlePublic(){dispatched++;entered();return reply}})
  const request=Readable.from([Buffer.from('{}')]),response=new BoundedResponse()
  request.method='POST';request.url='/api/prime/bridge/memory.save'
  request.headers={host:hostname,origin,'content-type':'application/json','content-length':'2'}
  const pending=endpoints.find(route=>route.path===request.url).handler(request,response)
  await ready;response.destroy();release(refusal);await pending
  assert.equal(dispatched,1);assert.equal(response.writes,0);assert.equal(response.statusCode,null)
  request.destroy()
})

async function captured(t,h){
  const root=await realpath(await mkdtemp('/tmp/prime-omh-c-'))
  t.after(()=>rm(root,{recursive:true,force:true}))
  const auth=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:()=>null,observeTarget:()=>null})
  const task={version:1,task_id:'synthetic-host-task',owner_id:auth.identity.owner_id,agent_id:'synthetic-agent',
    conversation_id:'synthetic-host-conversation',status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],
    max_input_tokens:100,max_output_tokens:100,max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}}
  const registry=createTrustedTaskRegistry([{task,provider_and_region:{provider:'local',region:'local'},audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']}])
  const bytes=Buffer.from(JSON.stringify({type:'turn',text:'Exact synthetic host source: Café.',seq:0,at})+'\n')
  const binding={credential_id:'synthetic-owner-control',owner_id:auth.identity.owner_id,task_id:task.task_id,
    memory_host:{owner_subject:auth.identity.subject,privacy:'local',scope:'owner',attributedTo:'owner',
      source:{sessionId:'synthetic-host-session',seq:0,at,sha256:sha256(bytes)},events:[bytes]}}
  let registryReads=0
  const resolver=h.createOwnerMemoryContext({taskRegistry:{getOwned(...args){registryReads++;return registry.getOwned(...args)},authorizeTask:registry.authorizeTask},bindings:[binding]})
  return {auth,registry,task,binding,bytes,resolver,registryReads:()=>registryReads,resetReads:()=>{registryReads=0}}
}

test('current H context derives immutable owner/task/source binding from its configured IPC credential',async t=>{
  const h=await host(),f=await captured(t,h)
  const challenge=f.auth.service.loginChallenge({owner_id:f.auth.identity.owner_id,kind:'passkey'})
  assert.equal(challenge.ok,true)
  const completed=f.auth.service.loginComplete({challenge:challenge.challenge,material:f.auth.assertion(challenge.public_key.challenge)})
  assert.equal(completed.ok,true)
  const session=f.auth.service.authenticateSession({session_token:completed.session_token})
  assert.equal(session.ok,true,'session identity comes from real disposable C verification')
  const request={transport:'ipc',credential_id:f.binding.credential_id}
  assert.deepEqual(f.resolver({request,session:null}),{login_owner_id:f.auth.identity.owner_id})
  const trusted=f.resolver({request,session})
  assert.equal(trusted.task_id,f.task.task_id);assert.equal(trusted.memory_host.owner_subject,f.auth.identity.subject)
  assert.ok(Buffer.from(trusted.memory_host.events[0]).equals(f.bytes))
  f.resetReads()
  for(const changed of [
    {...request,owner_id:'guest'},{...request,task_id:'guest'},{...request,source:{sessionId:'guest'}},
    {...request,role:'owner_control'}, {...request,headers:{owner_id:'guest'}},
    {transport:'http',credential_id:request.credential_id},{transport:'ipc',credential_id:'unbound-guest'},
  ])assert.throws(()=>f.resolver({request:changed,session}),error=>['INVALID','UNAUTHORIZED'].includes(error.error_code))
  assert.equal(f.registryReads(),0,'spoofed request fields refuse before trusted task lookup')
  assert.throws(()=>f.resolver({request,session,body:{owner_id:'guest',source:{sha256:'0'.repeat(64)}}}),error=>error.error_code==='INVALID')
  const original=Buffer.from(f.bytes)
  f.binding.memory_host.events[0].fill(0);trusted.memory_host.events[0].fill(1)
  const retained=f.resolver({request,session})
  assert.ok(Buffer.from(retained.memory_host.events[0]).equals(original))
  assert.equal(retained.memory_host.source.sha256,sha256(original))
  // Direct request objects exercise derivation/refusal only; this test does not
  // claim that the resolver itself authenticates a channel or owner session.
})

test('current B submitApproval and H byte factories carry one real C/D literal save through an explicit test-only boundary',async t=>{
  const h=await host()
  // Load B from the current selected Prime source. The injected
  // fixture boundary below is deliberately separate from the production IPC
  // boundary: it preserves the fixture's own trusted route and makes no claim
  // that HTTP request association is captured source or host qualification.
  const [{createPrimeOwnerController},uiContracts]=await Promise.all([
    import(pathToFileURL(join(hostRoot,'packages/ui/prime-authority/src/client/controller.mjs')).href),
    import(pathToFileURL(join(hostRoot,'packages/contracts/src/browser.mjs')).href),
  ])
  const fetchMethods=[],associations=[]
  const f=await ownerFixture(t,{uiContracts,controllerFactory:createPrimeOwnerController,wrapCall(bridgeCall){
    const testOnlyBoundary={async handlePublic(method,input,context){associations.push(context);return bridgeCall(method,input)}}
    const endpoints=routes(h,testOnlyBoundary)
    return h.createOwnerMemoryHttpCall({contracts:h.contracts,fetcher:async(url,options)=>{
      const method=url.slice('/api/prime/bridge/'.length);fetchMethods.push(method)
      const answer=await http(endpoints,h,method,h.contracts.parseStrictJson(options.body))
      return browserResponse(answer.response)
    }})
  }})
  await f.login();const operation=await f.prepare(draft('pinned-H-literal-save'))
  const review=f.controller.getSnapshot().presentation.memory_review
  assert.equal(review.statement,extraction.statement);assert.equal(review.attributed_to,'owner')
  f.controller.setApprovalAction(()=>f.workflow.approveAndSave())
  const first=f.controller.submitApproval(),second=f.controller.submitApproval()
  assert.equal(first,second,'B must coalesce the two submitted approval actions')
  const action=await first,saved=f.workflow.getSnapshot()
  assertSaved(saved);assert.equal(action.saved,true)
  assert.equal(saved.authority_settlement,'completed');assert.equal(saved.reconciliation_required,false)
  assert.equal(saved.citation.verdict,'VERIFIED');assert.equal(saved.citation.grants_authority,false)
  assert.equal(JSON.parse(saved.record.canonical_bytes).statement,extraction.statement)
  assert.equal(JSON.parse(saved.record.canonical_bytes).attributedTo,'owner')
  assert.equal(saved.record.source_event_digest,'sha256:'+sha256(f.host.events[0]))
  assert.deepEqual(saved.receipt,f.replies.find(reply=>reply.method==='memory.save').result.receipt)
  assert.equal(f.operationState(operation.operation_id).status,'COMPLETED')
  assert.equal(f.settlementCalls(),1);assert.equal(f.signerCalls(),2)
  assert.equal(f.count('owner.approvalComplete'),1);assert.equal(f.count('memory.save'),1)
  for(const table of ['records','intents','effects'])assert.equal(f.tableCount('prime_memory_'+table),1)
  assert.deepEqual(fetchMethods,f.calls.map(call=>call.method),'each genuine bridge call must use exactly one H browser fetch')
  for(const context of associations){
    assert.deepEqual(Object.keys(context).sort(),['request','role'])
    assert.deepEqual(Object.keys(context.request).sort(),['host','origin','request_id','transport'])
    assert.equal(context.request.transport,'http');assert.equal(context.request.host,hostname);assert.equal(context.request.origin,origin)
  }
  f.controller.setApprovalAction(null)
})

test('current H HTTP/IPC boundary refuses actual unqualified public and internal workers before C or SQL',async t=>{
  const h=await host(),f=await captured(t,h)
  for(const publicMode of [true,false]){
    const root=await realpath(await mkdtemp('/tmp/prime-omh-ipc-'))
    let worker,pool,poolClosed=false,contexts=0,privateReads=0,queries=0,verifications=0
    const socketPath=join(root,'memory.sock'),authoritySocket=join(root,'missing-authority.sock'),secret='d'.repeat(64)
    const config={kind:publicMode?'public-memory':'memory',ipc:{socketPath,credentials:[{id:f.binding.credential_id,role:'owner_control',secret}]},
      authorityChannel:{get socketPath(){privateReads++;return authoritySocket},credential:{id:'synthetic-memory',secret:'e'.repeat(64)}},
      registryEntries:f.registry.snapshot(),initializeSchema:true,
      resolveHostContext(input){contexts++;return f.resolver(input)},
      createPgPool(){pool=new FixturePool(join(root,'memory.sqlite'));const query=pool.query.bind(pool)
        pool.query=(...args)=>{queries++;return query(...args)};pool.end=async()=>{if(!poolClosed){pool.close();poolClosed=true}};return pool},
      ...(publicMode?{verifyHostQualification(){verifications++;return null}}:{}),
    }
    try{
      worker=await (publicMode?startPublicMemoryWorker:startMemoryWorker)(config)
      const direct=await createIpcClient({socketPath,credential:{id:f.binding.credential_id,secret}})
      try{const capability=await direct.request('capability.status',{});assert.equal(capability.available,false)
        assert.equal(Object.hasOwn(capability,'public_dispatch'),publicMode)
        if(publicMode)assert.equal(capability.public_dispatch,'qualified-owner-memory/v1')
      }finally{await direct.close()}
      const baseline=queries;let connections=0,httpDispatches=0,fetches=0
      const requested=[],deployment={source_commit:'0'.repeat(40),release_digest:'sha256:'+'0'.repeat(64)}
      const boundary=h.createOwnerMemoryIpcBoundary({channel:{socketPath,credential:{id:f.binding.credential_id,secret}},deployment,
        async connect(channel){connections++;const client=await createIpcClient(channel)
          return {async request(method,input){requested.push(method);return client.request(method,input)},close:()=>client.close()}}
      })
      const endpoints=routes(h,{handlePublic(...args){httpDispatches++;return boundary.handlePublic(...args)}})
      const browser=h.createOwnerMemoryHttpCall({contracts:h.contracts,fetcher:async(url,options)=>{
        fetches++;const method=url.slice('/api/prime/bridge/'.length)
        const result=await http(endpoints,h,method,h.contracts.parseStrictJson(options.body),{headers:{'x-owner-id':'guest','x-source-session':'guest'}})
        return browserResponse(result.response)
      }})
      for(const [method,input] of [
        ['owner.loginChallenge',{owner_id:f.auth.identity.owner_id,kind:'passkey'}],
        ['owner.loginChallenge',{owner_id:'guest',kind:'passkey',owner_subject:'guest',task_id:'guest',source:{sessionId:'guest'},role:'owner_control'}],
        ['memory.save',{session_token:'f'.repeat(64),owner_id:'guest',task_id:'guest',source:{sha256:'0'.repeat(64)}}],
      ])assert.deepEqual(await browser(method,input),refusal)
      assert.equal(fetches,3);assert.equal(httpDispatches,3);assert.equal(connections,3)
      assert.deepEqual(requested,['capability.status','capability.status','capability.status'])
      assert.equal(verifications,publicMode?4:0)
      assert.equal(contexts,0);assert.equal(privateReads,0);assert.equal(queries,baseline)
      for(const table of ['records','intents','effects','requests'])assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_'+table).get().n,0)
      await assert.rejects(lstat(authoritySocket),error=>error.code==='ENOENT')
    }finally{await worker?.close();if(pool&&!poolClosed)pool.close();await rm(root,{recursive:true,force:true})}
  }
})
