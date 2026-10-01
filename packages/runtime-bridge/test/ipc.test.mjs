// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable transport fixture only. The child runs under the same UID; these
// checks prove a process/socket boundary, not deployed UID or owner isolation.
import assert from 'node:assert/strict'
import net from 'node:net'
import { spawn } from 'node:child_process'
import { createHmac, randomBytes } from 'node:crypto'
import { mkdtemp, realpath, rm, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { once } from 'node:events'
import { canonicalJson } from '../../contracts/src/runtime.mjs'
import { createIpcServer, createIpcClient, PUBLIC_METHODS, IPC_METHOD_ROLES } from '../src/ipc.mjs'

const ownFile=fileURLToPath(import.meta.url)
const delay=ms=>new Promise(done=>setTimeout(done,ms))
const sign=(key,domain,value)=>createHmac('sha256',key).update('aukora-prime.ipc.v1\0'+domain+'\0'+canonicalJson(value)).digest('hex')
const fixtureToken='synthetic-verified-owner-session'
const closed=(value,keys)=>Object.keys(value).sort().join(',')===[...keys].sort().join(',')

if (process.argv[2] === '--ipc-child') {
  // No C verifier is mocked into production. This handler merely exercises the
  // IPC seam; the separate bridge integration fixture owns real C/D/F checks.
  let server
  process.on('message',async message=>{
    if (message.type === 'close') {await server?.close();process.send({type:'closed'});process.disconnect();return}
    if (message.type !== 'start') return
    let effects=0,active=0,maxActive=0
    try {
      server=await createIpcServer({socketPath:message.path,credentials:message.credentials,limits:message.limits,
        async handlePublic(method,input,context) {
          if (method === 'capability.status') {
            if (!closed(input,[])) return {ok:false,error_code:'INVALID',reason:'fixture closed capability grammar'}
            return {ok:true,pid:process.pid,role:context.role,request:context.request,effects,active,maxActive}
          }
          if (method === 'memory.status') {
            if (!closed(input,['session_token','record_id']) || input.session_token !== fixtureToken)
              return {ok:false,error_code:'UNAUTHORIZED',reason:'fixture session required'}
            if (input.record_id === 'slow') {active++;maxActive=Math.max(maxActive,active);await delay(350);active--}
            if (input.record_id === 'large') return {ok:true,value:'x'.repeat(5000)}
            return {ok:true,storage_status:'saved',index_status:'pending'}
          }
          if (method === 'memory.proposeSave') {
            if (!closed(input,['session_token','extraction']) || input.session_token !== fixtureToken)
              return {ok:false,error_code:'INVALID',reason:'fixture closed proposal grammar'}
            return {ok:true,proposal:'synthetic proposal',role:context.role}
          }
          if (method === 'memory.save') {
            if (!closed(input,['session_token','operation_id']) || input.session_token !== fixtureToken)
              return {ok:false,error_code:'UNAUTHORIZED',reason:'fixture session required'}
            effects++
            if (input.operation_id === 'slow') {active++;maxActive=Math.max(maxActive,active);await delay(350);active--}
            return {ok:true,effects}
          }
          return {ok:false,error_code:'UNAVAILABLE',reason:'fixture method unmounted'}
        }})
      process.send({type:'ready',pid:process.pid})
    } catch(error) {process.send({type:'error',message:error.message})}
  })
  process.on('disconnect',()=>{server?.close().finally(()=>process.exit(0))})
} else {
  let checks=0
  async function check(name,run) {await run();checks++;console.log('PASS '+name)}
  const root=await realpath(await mkdtemp('/tmp/prime-ipc-fixture-')),path=join(root,'broker.sock')
  const secrets={proposer:randomBytes(32),read_only:randomBytes(32),owner_control:randomBytes(32)}
  const credentials=Object.entries(secrets).map(([role,secret])=>({id:role,role,secret:secret.toString('hex')}))
  const serverLimits={maxFrameBytes:4096,maxOutputBytes:4096,maxConnections:8,maxInflight:3,maxInflightPerConnection:2,
    handshakeTimeoutMs:500,idleTimeoutMs:2000,requestTimeoutMs:100,maxRequestsPerConnection:30}
  const clientLimits={...serverLimits,requestTimeoutMs:1000}
  const child=spawn(process.execPath,[ownFile,'--ipc-child'],{stdio:['ignore','pipe','pipe','ipc']})
  let childOutput=''
  child.stdout.on('data',data=>{childOutput+=data});child.stderr.on('data',data=>{childOutput+=data})
  const clients=[]
  async function client(role,extra={}) {
    const value=await createIpcClient({socketPath:path,credential:{id:role,secret:secrets[role]},limits:{...clientLimits,...extra}})
    clients.push(value);return value
  }
  async function raw() {
    const socket=net.createConnection(path),messages=[],waiters=[]
    socket.on('error',()=>{})
    let buffer=Buffer.alloc(0)
    socket.on('data',chunk=>{
      buffer=Buffer.concat([buffer,chunk])
      while (buffer.length>=4 && buffer.length>=4+buffer.readUInt32BE()) {
        const length=buffer.readUInt32BE(),value=JSON.parse(buffer.subarray(4,4+length).toString('utf8'));buffer=buffer.subarray(4+length)
        const waiter=waiters.shift();if(waiter)waiter(value);else messages.push(value)
      }
    })
    const next=()=>messages.length?Promise.resolve(messages.shift()):new Promise((done,reject)=>{
      const timer=setTimeout(()=>reject(new Error('fixture raw reply timeout')),1000)
      waiters.push(value=>{clearTimeout(timer);done(value)})
    })
    const sendText=text=>{const body=Buffer.from(text),header=Buffer.alloc(4);header.writeUInt32BE(body.length);socket.write(Buffer.concat([header,body]))}
    const send=value=>sendText(canonicalJson(value))
    const hello=await next()
    return {socket,next,send,sendText,hello,async authenticate(role='proposer',override={}) {
      const binding={credential_id:role,server_nonce:hello.server_nonce,client_nonce:randomBytes(32).toString('hex')}
      const key=Buffer.from(sign(secrets[role],'session',binding),'hex')
      const auth={version:1,type:'auth',credential_id:role,client_nonce:binding.client_nonce,mac:sign(secrets[role],'authenticate',binding),...override}
      send(auth);await next();return {key,auth}
    }}
  }
  async function closes(socket,run) {
    const end=Promise.race([once(socket,'close'),delay(1500).then(()=>{throw new Error('fixture connection did not close')})])
    run();await end
  }
  try {
    const readyPromise=once(child,'message')
    child.send({type:'start',path,credentials,limits:serverLimits})
    const [ready]=await readyPromise
    assert.equal(ready.type,'ready',JSON.stringify(ready)+' '+childOutput)
    await check('actual child process and private socket',async()=>{
      const c=await client('read_only'),r=await c.request('capability.status',{})
      assert.equal(r.ok,true);assert.equal(r.pid,child.pid);assert.notEqual(r.pid,process.pid)
      assert.deepEqual(r.request,{transport:'ipc',credential_id:'read_only'});assert.equal(r.role,'read_only')
      assert.equal((await stat(path)).mode&0o777,0o600)
      assert(PUBLIC_METHODS.includes('memory.proposeSave'));assert(!PUBLIC_METHODS.includes('owner.reserve'));assert(!PUBLIC_METHODS.includes('executor.execute'))
      assert.deepEqual(IPC_METHOD_ROLES['memory.save'],['owner_control'])
      await c.close()
    })
    await check('proposer and read-only method fences precede handler effects',async()=>{
      const p=await client('proposer'),r=await client('read_only')
      assert.equal((await p.request('memory.proposeSave',{session_token:fixtureToken,extraction:{statement:'synthetic'}})).ok,true)
      for (const method of ['owner.loginChallenge','owner.loginComplete','owner.approvalChallenge','owner.approvalComplete','owner.declineApproval','memory.save'])
        assert.equal((await p.request(method,{})).error_code,'UNAUTHORIZED')
      assert.equal((await r.request('memory.proposeSave',{session_token:fixtureToken,extraction:{}})).error_code,'UNAUTHORIZED')
      assert.equal((await r.request('memory.save',{session_token:fixtureToken,operation_id:'never'})).error_code,'UNAUTHORIZED')
      assert.equal((await p.request('capability.status',{})).effects,0)
      await p.close();await r.close()
    })
    await check('role conveys no owner identity and service rejects claimed context',async()=>{
      const p=await client('proposer')
      for (const field of ['owner_id','task_id','provider_and_region','expected_state_version','state'])
        assert.equal((await p.request('memory.proposeSave',{session_token:fixtureToken,extraction:{},[field]:'guest-claim'})).error_code,'INVALID')
      assert.equal((await p.request('memory.status',{session_token:'forged',record_id:'synthetic'})).error_code,'UNAUTHORIZED')
      const status=await p.request('memory.status',{session_token:fixtureToken,record_id:'synthetic'})
      assert.equal(status.storage_status,'saved');assert.equal(status.index_status,'pending');await p.close()
    })
    await check('wrong host secret cannot authenticate',async()=>{
      await assert.rejects(createIpcClient({socketPath:path,credential:{id:'owner_control',secret:randomBytes(32)},limits:clientLimits}),e=>e.code==='UNAVAILABLE')
    })
    await check('authenticated input tamper and sequence replay close channel',async()=>{
      const a=await raw(),session=await a.authenticate()
      const request={version:1,type:'request',seq:1,method:'capability.status',input:{}}
      const signed={...request,mac:sign(session.key,'request',request)}
      a.send(signed);assert.equal((await a.next()).result.ok,true)
      await closes(a.socket,()=>a.send(signed))
      const b=await raw(),bs=await b.authenticate()
      await closes(b.socket,()=>b.send({...request,input:{owner_id:'altered'},mac:sign(bs.key,'request',request)}))
    })
    await check('authentication from another connection nonce cannot replay',async()=>{
      const a=await raw(),session=await a.authenticate();a.socket.destroy();await once(a.socket,'close')
      const b=await raw();assert.notEqual(b.hello.server_nonce,a.hello.server_nonce)
      await closes(b.socket,()=>b.send(session.auth))
    })
    await check('strict duplicate-key parser and oversized frame close channel',async()=>{
      const a=await raw();await a.authenticate()
      await closes(a.socket,()=>a.sendText('{"input":{},"input":{},"mac":"'+ '0'.repeat(64)+'","method":"capability.status","seq":1,"type":"request","version":1}'))
      const b=await raw();const header=Buffer.alloc(4);header.writeUInt32BE(serverLimits.maxFrameBytes+1)
      await closes(b.socket,()=>b.socket.write(header))
      const c=await raw();await closes(c.socket,()=>c.sendText('{"server_nonce":"'+ '0'.repeat(64)+'","type":"auth","version":1.00000000000000001}'))
    })
    await check('connection count and unauthenticated lifetime are bounded',async()=>{
      const sockets=[]
      try {
        for (let i=0;i<serverLimits.maxConnections;i++) sockets.push((await raw()).socket)
        const extra=net.createConnection(path);extra.on('error',()=>{})
        await closes(extra,()=>{})
      } finally {for (const socket of sockets)socket.destroy()}
      await delay(20)
      const unauthenticated=await raw();await closes(unauthenticated.socket,()=>{})
    })
    await check('unauthenticated partial-frame trickle cannot extend handshake deadline',async()=>{
      const channel=await raw(),started=Date.now(),header=Buffer.alloc(4)
      header.writeUInt32BE(serverLimits.maxFrameBytes)
      // Keep sending before any inactivity timeout could expire, without ever
      // completing the bounded frame or providing authentication material.
      let sent=0
      const trickle=setInterval(()=>{if(!channel.socket.destroyed){sent++;channel.socket.write(Buffer.from(' '))}},50)
      try {
        await closes(channel.socket,()=>channel.socket.write(header))
        assert(sent>=2,'fixture must send multiple keepalive bytes')
        assert(Date.now()-started<serverLimits.handshakeTimeoutMs*2,'authentication must have an absolute deadline')
      } finally {clearInterval(trickle);channel.socket.destroy()}
    })
    await check('inflight and output are bounded, mutation timeout retains uncertainty',async()=>{
      const c=await client('owner_control')
      const first=c.request('memory.save',{session_token:fixtureToken,operation_id:'slow'})
      const second=c.request('memory.status',{session_token:fixtureToken,record_id:'slow'})
      await assert.rejects(c.request('capability.status',{}),e=>e.code==='UNAVAILABLE')
      const [saved,status]=await Promise.all([first,second])
      assert.equal(saved.error_code,'OUTCOME_UNKNOWN');assert.equal(status.error_code,'UNAVAILABLE')
      // Timed-out handlers still consume their server-side slots.
      assert.equal((await c.request('memory.status',{session_token:fixtureToken,record_id:'synthetic'})).reason,'IPC_INFLIGHT_BOUND')
      await delay(300)
      const probe=await c.request('capability.status',{});assert.equal(probe.effects,1);assert.equal(probe.maxActive,2)
      assert.equal((await c.request('memory.status',{session_token:fixtureToken,record_id:'large'})).reason,'IPC_SERVICE_OUTPUT_UNAVAILABLE')
      await assert.rejects(c.request('memory.save',{session_token:fixtureToken,operation_id:'x'.repeat(5000)}),e=>e.code==='INVALID')
      await c.close()
    })
    await check('lost mutation reply is unknown and client never retries',async()=>{
      const c=await client('owner_control',{requestTimeoutMs:20})
      await assert.rejects(c.request('memory.save',{session_token:fixtureToken,operation_id:'slow'}),e=>e.code==='OUTCOME_UNKNOWN')
      await delay(400)
      const probe=await client('read_only');assert.equal((await probe.request('capability.status',{})).effects,2);await probe.close()
    })
    await check('existing socket is not removed or replaced',async()=>{
      await assert.rejects(createIpcServer({socketPath:path,credentials,handlePublic:()=>({ok:true})}),e=>e.code==='UNAVAILABLE')
      const c=await client('read_only');assert.equal((await c.request('capability.status',{})).ok,true);await c.close()
    })
    console.log(JSON.stringify({status:'PASS',checks,scope:'disposable authenticated Unix socket and distinct child process',limits:['same UID; no UID isolation proof','synthetic handler; real C/D/F integration checked separately','no enrollment, deployment, security settings, or live application changes']}))
  } finally {
    for (const c of clients) await c.close()
    if (child.connected) {
      const done=once(child,'exit');child.send({type:'close'});await Promise.race([done,delay(2000).then(()=>child.kill())])
    } else if (child.exitCode===null) child.kill()
    await rm(root,{recursive:true,force:true})
  }
}
