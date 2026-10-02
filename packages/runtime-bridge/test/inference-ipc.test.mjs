// SPDX-License-Identifier: AGPL-3.0-or-later
// KEYLESS LOCAL transport regressions. All handlers and inputs are TEST_ONLY.
// These real disposable Unix sockets exercise IPC routing and ingress only;
// they establish no C owner authentication, approval, settlement or UID isolation.
import assert from 'node:assert/strict'
import test from 'node:test'
import net from 'node:net'
import {createHmac,randomBytes} from 'node:crypto'
import {chmod,mkdtemp,realpath,rm,stat} from 'node:fs/promises'
import {join} from 'node:path'
import {setTimeout as delay} from 'node:timers/promises'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {createIpcServer,createIpcClient,createAuthorityIpcServer,createAuthorityIpcClient,
  createInferenceAuthorityIpcServer,createInferenceAuthorityIpcClient,
  PUBLIC_METHODS,IPC_METHOD_ROLES,PRIVATE_AUTHORITY_METHODS,INFERENCE_AUTHORITY_METHODS} from '../src/ipc.mjs'

const inferenceMethods=['authority.propose','authority.loginChallenge','authority.loginComplete',
  'authority.authenticateSession','authority.logoutSession','authority.approvalChallenge',
  'authority.approvalComplete','authority.declineApproval','authority.status','authority.reserve',
  'authority.claimDispatch','authority.settleInference','authority.reconcileInferenceSettlement']
const memoryMethods=['authority.propose','authority.loginChallenge','authority.loginComplete',
  'authority.authenticateSession','authority.logoutSession','authority.approvalChallenge',
  'authority.approvalComplete','authority.declineApproval','authority.status','authority.reserve',
  'authority.claimDispatch','authority.settleMemory','authority.markOutcomeUnknown']
const publicMethods=['capability.status','owner.status','memory.status','memory.cite','memory.recall',
  'memory.proposeSave','memory.proposeForget','owner.loginChallenge','owner.loginComplete','owner.logout',
  'owner.approvalChallenge','owner.approvalComplete','owner.declineApproval','memory.save','memory.forget','memory.recover']
const bounds={handshakeTimeoutMs:500,idleTimeoutMs:1000,requestTimeoutMs:500}
const sign=(key,domain,value)=>createHmac('sha256',key)
  .update('aukora-prime.ipc.v1\0'+domain+'\0'+canonicalJson(value)).digest('hex')
const unavailable=error=>error.code==='UNAVAILABLE'
const invalidMethod=error=>error.code==='INVALID'&&error.message==='IPC_METHOD_UNAVAILABLE'

async function fixture(t) {
  const directory=await realpath(await mkdtemp(join(await realpath('/tmp'),'inf-ipc-')))
  await chmod(directory,0o700)
  assert.equal((await stat(directory)).mode&0o777,0o700)
  const servers=[],clients=[],rawSockets=[],secrets=[]
  t.after(async()=>{
    for(const client of clients)await client.close()
    for(const socket of rawSockets)await new Promise(done=>{
      if(socket.closed)return done()
      socket.once('close',done);socket.destroy()
    })
    for(const server of servers)await server.close()
    for(const secret of secrets)secret.fill(0)
    await rm(directory,{recursive:true,force:true})
  })
  return {
    path(name) {
      const path=join(directory,name+'.sock')
      assert(Buffer.byteLength(path)<=103)
      return path
    },
    secret() {const secret=randomBytes(32);secrets.push(secret);return secret},
    async server(create,options) {
      const server=await create(options);servers.push(server);return server
    },
    async client(create,options) {
      const client=await create(options);clients.push(client);return client
    },
    rawSocket(socket) {rawSockets.push(socket)},
  }
}

// TEST_ONLY authenticated wire peer: bypasses the production client's local
// method and canonical-text checks so refusals must come from the listener.
async function rawPeer(f,path,credential) {
  const socket=net.createConnection(path),messages=[],waiters=[]
  f.rawSocket(socket)
  socket.on('error',()=>{})
  let buffer=Buffer.alloc(0),ended=false,sequence=0
  const rejectWaiters=error=>{
    for(const waiter of waiters.splice(0)){clearTimeout(waiter.timer);waiter.reject(error)}
  }
  socket.on('close',()=>{ended=true;rejectWaiters(new Error('TEST_ONLY raw peer closed'))})
  socket.on('data',chunk=>{
    try {
      buffer=Buffer.concat([buffer,chunk])
      while(buffer.length>=4&&buffer.length>=4+buffer.readUInt32BE()) {
        const length=buffer.readUInt32BE(),value=JSON.parse(buffer.subarray(4,4+length).toString('utf8'))
        buffer=buffer.subarray(4+length)
        const waiter=waiters.shift()
        if(waiter){clearTimeout(waiter.timer);waiter.resolve(value)}else messages.push(value)
      }
    } catch(error){rejectWaiters(error);socket.destroy()}
  })
  const next=()=>{
    if(messages.length)return Promise.resolve(messages.shift())
    if(ended)return Promise.reject(new Error('TEST_ONLY raw peer closed'))
    return new Promise((resolve,reject)=>{
      const waiter={resolve,reject,timer:setTimeout(()=>{
        const index=waiters.indexOf(waiter);if(index!==-1)waiters.splice(index,1)
        reject(new Error('TEST_ONLY raw reply timeout'))
      },750)}
      waiters.push(waiter)
    })
  }
  const sendText=text=>{
    const body=Buffer.from(text,'utf8'),header=Buffer.alloc(4)
    header.writeUInt32BE(body.length);socket.write(Buffer.concat([header,body]))
  }
  const hello=await next()
  assert.equal(hello.type,'hello')
  const binding={credential_id:credential.id,server_nonce:hello.server_nonce,client_nonce:randomBytes(32).toString('hex')}
  const key=Buffer.from(sign(credential.secret,'session',binding),'hex')
  sendText(canonicalJson({version:1,type:'auth',credential_id:credential.id,client_nonce:binding.client_nonce,
    mac:sign(credential.secret,'authenticate',binding)}))
  const authenticated=await next(),{mac:authMac,...authAnswer}=authenticated
  assert.equal(authenticated.type,'authenticated')
  assert.equal(authMac,sign(key,'authenticated',authAnswer))
  return {
    socket,role:authenticated.role,sendText,
    signed(method,input={}) {
      const request={version:1,type:'request',seq:++sequence,method,input}
      return {...request,mac:sign(key,'request',request)}
    },
    async request(method,input={}) {
      const request=this.signed(method,input);sendText(canonicalJson(request))
      const reply=await next(),{mac:replyMac,...answer}=reply
      assert.equal(reply.type,'response');assert.equal(reply.seq,request.seq)
      assert.equal(replyMac,sign(key,'response',answer))
      return reply.result
    },
    async closesAfter(send) {
      const closed=new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(new Error('TEST_ONLY rejected ingress did not close')),750)
        socket.once('close',()=>{clearTimeout(timer);resolve()})
      })
      send();await closed
    },
  }
}

test('TEST_ONLY inference profile has exactly thirteen methods and fixed role constructors',{timeout:5000},async t=>{
  const f=await fixture(t),secret=f.secret()
  assert.deepEqual(INFERENCE_AUTHORITY_METHODS,inferenceMethods)
  assert.deepEqual(PRIVATE_AUTHORITY_METHODS,memoryMethods)
  assert.deepEqual(PUBLIC_METHODS,publicMethods)
  assert(Object.isFrozen(INFERENCE_AUTHORITY_METHODS))
  assert(Object.isFrozen(PRIVATE_AUTHORITY_METHODS))
  assert(Object.isFrozen(PUBLIC_METHODS))
  assert.deepEqual(IPC_METHOD_ROLES['memory.save'],['owner_control'])
  assert(INFERENCE_AUTHORITY_METHODS.every(method=>!PUBLIC_METHODS.includes(method)))
  let handlerCalls=0
  const TEST_ONLY_handler=()=>{handlerCalls++;return {ok:true}}
  for(const [create,role,name] of [
    [createInferenceAuthorityIpcServer,'memory_effect','bad-inference-memory'],
    [createInferenceAuthorityIpcServer,'proposer','bad-inference-public'],
    [createAuthorityIpcServer,'inference_effect','bad-memory-inference'],
    [createIpcServer,'inference_effect','bad-public-inference'],
  ])await assert.rejects(create({socketPath:f.path(name),credentials:[{id:'TEST_ONLY_worker',role,secret}],
    handlePublic:TEST_ONLY_handler,limits:bounds}),TypeError)
  assert.equal(handlerCalls,0)
})

test('TEST_ONLY independent inference and memory listeners enforce both allowlists',{timeout:5000},async t=>{
  const f=await fixture(t),secret=f.secret(),id='TEST_ONLY_shared_worker'
  const credential={id,secret},inferencePath=f.path('inference'),memoryPath=f.path('memory'),calls=[]
  // Deliberately reuse only an ephemeral test channel credential to show that
  // a valid MAC cannot make the other profile's signed role acceptable.
  const TEST_ONLY_handler=(method,input,context)=>{
    calls.push({method,role:context.role})
    return {ok:true,method,input,role:context.role,request:context.request}
  }
  await f.server(createInferenceAuthorityIpcServer,{socketPath:inferencePath,
    credentials:[{id,role:'inference_effect',secret}],handlePublic:TEST_ONLY_handler,limits:bounds,
    allowedMethods:memoryMethods,roles:['memory_effect']})
  await f.server(createAuthorityIpcServer,{socketPath:memoryPath,
    credentials:[{id,role:'memory_effect',secret}],handlePublic:TEST_ONLY_handler,limits:bounds})
  const inference=await f.client(createInferenceAuthorityIpcClient,{socketPath:inferencePath,credential,limits:bounds,
    allowedMethods:memoryMethods,roles:['memory_effect']})
  const memory=await f.client(createAuthorityIpcClient,{socketPath:memoryPath,credential,limits:bounds})
  assert.equal(inference.role,'inference_effect');assert.equal(memory.role,'memory_effect')
  for(const method of inferenceMethods) {
    const result=await inference.request(method,{TEST_ONLY:true})
    assert.equal(result.ok,true);assert.equal(result.method,method);assert.equal(result.role,'inference_effect')
    assert.deepEqual(result.request,{transport:'ipc',credential_id:id})
    assert(!Object.hasOwn(result.request,'owner_id'));assert(!Object.hasOwn(result.request,'task_id'))
  }
  for(const method of ['authority.settleMemory','authority.markOutcomeUnknown'])
    assert.equal((await memory.request(method,{TEST_ONLY:true})).role,'memory_effect')
  const beforeRefusals=calls.length
  const forbidden=['authority.settleMemory','authority.markOutcomeUnknown','authority.settle',
    'authority.reconcileSettlement','authority.settleExecution','executor.execute','memory.save']
  const inferenceWire=await rawPeer(f,inferencePath,credential)
  assert.equal(inferenceWire.role,'inference_effect')
  for(const method of forbidden) {
    await assert.rejects(inference.request(method,{}),invalidMethod)
    assert.deepEqual(await inferenceWire.request(method),{
      ok:false,error_code:'UNAUTHORIZED',reason:'IPC_METHOD_ROLE_REFUSED'})
  }
  const memoryWire=await rawPeer(f,memoryPath,credential)
  for(const method of ['authority.settleInference','authority.reconcileInferenceSettlement']) {
    await assert.rejects(memory.request(method,{}),invalidMethod)
    assert.deepEqual(await memoryWire.request(method),{
      ok:false,error_code:'UNAUTHORIZED',reason:'IPC_METHOD_ROLE_REFUSED'})
  }
  await assert.rejects(createInferenceAuthorityIpcClient({socketPath:memoryPath,credential,limits:bounds}),unavailable)
  await assert.rejects(createAuthorityIpcClient({socketPath:inferencePath,credential,limits:bounds}),unavailable)
  await assert.rejects(createIpcClient({socketPath:inferencePath,credential,limits:bounds}),unavailable)
  assert.equal(calls.length,beforeRefusals)
})

test('TEST_ONLY correctly MACed BOM, noncanonical and duplicate text never reaches a handler',{timeout:5000},async t=>{
  const f=await fixture(t),secret=f.secret(),credential={id:'TEST_ONLY_ingress',secret}
  const profiles=[
    {name:'inference',create:createInferenceAuthorityIpcServer,role:'inference_effect',method:'authority.reserve'},
    {name:'memory',create:createAuthorityIpcServer,role:'memory_effect',method:'authority.reserve'},
    {name:'public',create:createIpcServer,role:'owner_control',method:'memory.save'},
  ]
  for(const profile of profiles) {
    const path=f.path(profile.name),handled=[]
    await f.server(profile.create,{socketPath:path,credentials:[{...credential,role:profile.role}],limits:bounds,
      handlePublic(method){handled.push(method);return {ok:true,TEST_ONLY:true}}})
    const canonicalPeer=await rawPeer(f,path,credential)
    assert.equal((await canonicalPeer.request(profile.method)).ok,true)
    assert.deepEqual(handled,[profile.method])
    for(const [name,alter] of [
      ['BOM',text=>'\uFEFF'+text],
      ['noncanonical whitespace',text=>' '+text],
      ['duplicate input key',text=>text.replace('"input":{},','"input":{},"input":{},')],
    ]) {
      const peer=await rawPeer(f,path,credential),signed=peer.signed(profile.method)
      const canonical=canonicalJson(signed),text=alter(canonical)
      assert.notEqual(text,canonical,name)
      // Each text preserves the exact signed semantic request; a bad MAC or
      // an unmounted method cannot explain the listener's rejection.
      assert.deepEqual(JSON.parse(text.replace(/^\uFEFF/,'')),signed,name)
      await peer.closesAfter(()=>peer.sendText(text))
      assert.deepEqual(handled,[profile.method],profile.name+' '+name+' must precede handler')
    }
  }
})

test('TEST_ONLY a lost inference mutation reply stays OUTCOME_UNKNOWN without retry',{timeout:5000},async t=>{
  const f=await fixture(t),path=f.path('lost-reply'),secret=f.secret(),credential={id:'TEST_ONLY_mutation',secret}
  let effects=0,finishHandler,markStarted,markFinished,started=false
  const held=new Promise(done=>{finishHandler=done})
  const handlerStarted=new Promise(done=>{markStarted=done})
  const handlerFinished=new Promise(done=>{markFinished=done})
  await f.server(createInferenceAuthorityIpcServer,{socketPath:path,
    credentials:[{...credential,role:'inference_effect'}],limits:bounds,
    async handlePublic(method) {
      if(method==='authority.reserve') {
        effects++;started=true;markStarted()
        await held;markFinished();return {ok:true,TEST_ONLY:true,effects}
      }
      return {ok:true,TEST_ONLY:true,effects}
    }})
  try {
    const client=await f.client(createInferenceAuthorityIpcClient,{socketPath:path,credential,
      limits:{...bounds,requestTimeoutMs:30}})
    const lost=assert.rejects(client.request('authority.reserve',{TEST_ONLY:true}),
      error=>error.code==='OUTCOME_UNKNOWN'&&error.message==='IPC_REPLY_TIMEOUT')
    await handlerStarted;await lost
    assert.equal(effects,1)
    await assert.rejects(client.request('authority.reserve',{TEST_ONLY:true}),unavailable)
    finishHandler();await handlerFinished
    await delay(90)
    const probe=await f.client(createInferenceAuthorityIpcClient,{socketPath:path,credential,limits:bounds})
    assert.equal((await probe.request('authority.status',{TEST_ONLY:true})).effects,1)
    assert.equal(effects,1)
  } finally {
    finishHandler()
    if(started)await handlerFinished
  }
})
