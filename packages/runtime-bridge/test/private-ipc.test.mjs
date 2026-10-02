// SPDX-License-Identifier: AGPL-3.0-or-later
// Transport fixture only: a distinct child process, same UID, synthetic handler.
// A private channel role is never an owner identity or approval proof. Real C
// verification remains the responsibility of the worker's closed service join.
import assert from 'node:assert/strict'
import {spawn} from 'node:child_process'
import {randomBytes} from 'node:crypto'
import {mkdtemp,realpath,rm,mkdir,chmod,stat} from 'node:fs/promises'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {once} from 'node:events'
import {createIpcServer,createIpcClient,createAuthorityIpcServer,createAuthorityIpcClient,
  PUBLIC_METHODS,PRIVATE_AUTHORITY_METHODS} from '../src/ipc.mjs'

const expected=['authority.propose','authority.loginChallenge','authority.loginComplete','authority.authenticateSession','authority.logoutSession',
  'authority.approvalChallenge','authority.approvalComplete','authority.declineApproval','authority.status','authority.reserve',
  'authority.claimDispatch','authority.settleMemory','authority.markOutcomeUnknown']
const ownFile=fileURLToPath(import.meta.url)
const delay=ms=>new Promise(done=>setTimeout(done,ms))
if(process.argv[2]==='--private-ipc-child') {
  let privateServer,publicServer,effects=0
  process.on('message',async message=>{
    if(message.type==='close') {await privateServer?.close();await publicServer?.close();process.disconnect();return}
    if(message.type!=='start')return
    try {
      privateServer=await createAuthorityIpcServer({socketPath:message.privatePath,
        credentials:[{id:'memory-worker',role:'memory_effect',secret:message.memorySecret}],limits:message.limits,
        // Fixture handler proves role/method routing only, not C authorization.
        handlePublic(method,input,context) {
          if(method==='authority.reserve')effects++
          return {ok:true,method,input,role:context.role,request:context.request,pid:process.pid,effects}
        }})
      publicServer=await createIpcServer({socketPath:message.publicPath,
        credentials:[{id:'app',role:'proposer',secret:message.appSecret}],limits:message.limits,
        handlePublic(method,input,context){return {ok:true,method,input,role:context.role,pid:process.pid}}})
      process.send({type:'ready',pid:process.pid})
    } catch(error){process.send({type:'error',message:error.message})}
  })
  process.on('disconnect',()=>Promise.all([privateServer?.close(),publicServer?.close()]).finally(()=>process.exit(0)))
} else {
  const root=await realpath(await mkdtemp('/tmp/prime-private-ipc-')),privatePath=join(root,'authority.sock'),publicPath=join(root,'public.sock')
  const memorySecret=randomBytes(32),appSecret=randomBytes(32)
  const limits={handshakeTimeoutMs:500,requestTimeoutMs:1000,idleTimeoutMs:2000}
  const child=spawn(process.execPath,[ownFile,'--private-ipc-child'],{stdio:['ignore','pipe','pipe','ipc']})
  let output='',checks=0
  child.stdout.on('data',data=>{output+=data});child.stderr.on('data',data=>{output+=data})
  const clients=[]
  async function check(label,run){await run();checks++;console.log('PASS '+label)}
  try {
    const readyPromise=once(child,'message')
    child.send({type:'start',privatePath,publicPath,memorySecret:memorySecret.toString('hex'),appSecret:appSecret.toString('hex'),limits})
    const [ready]=await readyPromise;assert.equal(ready.type,'ready',JSON.stringify(ready)+' '+output)
    await check('private authority method set is exact and disjoint from public API',async()=>{
      assert.deepEqual(PRIVATE_AUTHORITY_METHODS,expected)
      assert(PRIVATE_AUTHORITY_METHODS.every(method=>!PUBLIC_METHODS.includes(method)))
      assert(Object.isFrozen(PRIVATE_AUTHORITY_METHODS))
      await assert.rejects(createAuthorityIpcServer({socketPath:join(root,'bad-private.sock'),
        credentials:[{id:'app',role:'proposer',secret:appSecret}],handlePublic:()=>({ok:true})}),TypeError)
      await assert.rejects(createIpcServer({socketPath:join(root,'bad-public.sock'),
        credentials:[{id:'worker',role:'memory_effect',secret:memorySecret}],handlePublic:()=>({ok:true})}),TypeError)
    })
    await check('app public-role secret cannot authenticate to authority service plane',async()=>{
      await assert.rejects(createAuthorityIpcClient({socketPath:privatePath,credential:{id:'app',secret:appSecret},limits}),error=>error.code==='UNAVAILABLE')
      await assert.rejects(createAuthorityIpcClient({socketPath:privatePath,credential:{id:'memory-worker',secret:appSecret},limits}),error=>error.code==='UNAVAILABLE')
      const app=await createIpcClient({socketPath:publicPath,credential:{id:'app',secret:appSecret},limits});clients.push(app)
      await assert.rejects(app.request('authority.reserve',{}),error=>error.code==='INVALID')
      assert.equal((await app.request('capability.status',{})).role,'proposer')
    })
    await check('memory effect credential reaches fixed methods across real child process',async()=>{
      const worker=await createAuthorityIpcClient({socketPath:privatePath,credential:{id:'memory-worker',secret:memorySecret},limits,
        // Ignored input cannot customize the private client method allowlist.
        allowedMethods:['admin.secret'],roles:['owner_control']});clients.push(worker)
      assert.equal(worker.role,'memory_effect')
      for(const method of PRIVATE_AUTHORITY_METHODS) {
        const result=await worker.request(method,{fixture:'synthetic service envelope'})
        assert.equal(result.ok,true);assert.equal(result.method,method);assert.equal(result.role,'memory_effect')
        assert.equal(result.pid,child.pid);assert.notEqual(result.pid,process.pid)
        assert.deepEqual(result.request,{transport:'ipc',credential_id:'memory-worker'})
        assert(!Object.hasOwn(result.request,'owner_id'));assert(!Object.hasOwn(result.request,'task_id'))
      }
      const status=await worker.request('authority.status',{});assert.equal(status.effects,1)
      await assert.rejects(worker.request('admin.secret',{}),error=>error.code==='INVALID')
      await assert.rejects(worker.request('owner.approvalComplete',{}),error=>error.code==='INVALID')
      await assert.rejects(worker.request('memory.save',{}),error=>error.code==='INVALID')
      assert.equal((await worker.request('authority.status',{})).effects,1)
    })
    await check('public client cannot interpret private role even with deliberately shared test credential',async()=>{
      // This checks profile separation, not a recommendation to share secrets.
      await assert.rejects(createIpcClient({socketPath:privatePath,credential:{id:'memory-worker',secret:memorySecret},limits}),error=>error.code==='UNAVAILABLE')
      await assert.rejects(createAuthorityIpcClient({socketPath:publicPath,credential:{id:'app',secret:appSecret},limits}),error=>error.code==='UNAVAILABLE')
    })
    await check('provisioned socket policy is explicit and wrong or missing policy refuses',async()=>{
      // Same-UID fixture validates source policy checks only. G/H must later
      // provision and verify actual separate users and group membership.
      const parent=join(root,'provisioned');await mkdir(parent,{mode:0o710});await chmod(parent,0o710)
      const path=join(parent,'authority.sock'),parentStat=await stat(parent)
      const socketAccess={server_uid:process.getuid(),client_uid:process.getuid(),group_gid:parentStat.gid}
      const base={socketPath:path,credentials:[{id:'worker',role:'memory_effect',secret:memorySecret}],handlePublic:()=>({ok:true}),limits}
      await assert.rejects(createAuthorityIpcServer(base),error=>error.code==='UNAVAILABLE')
      await assert.rejects(createAuthorityIpcServer({...base,socketAccess:{...socketAccess,server_uid:socketAccess.server_uid+1}}),error=>error.code==='UNAVAILABLE')
      await assert.rejects(createAuthorityIpcServer({...base,socketAccess:{...socketAccess,group_gid:socketAccess.group_gid+1}}),error=>error.code==='UNAVAILABLE')
      await assert.rejects(createAuthorityIpcServer({...base,socketAccess:{...socketAccess,role:'owner_control'}}),TypeError)
      const server=await createAuthorityIpcServer({...base,socketAccess})
      try {
        const socketStat=await stat(path);assert.equal(socketStat.uid,socketAccess.server_uid)
        assert.equal(socketStat.gid,socketAccess.group_gid);assert.equal(socketStat.mode&0o7777,0o660)
        const config={socketPath:path,credential:{id:'worker',secret:memorySecret},limits}
        await assert.rejects(createAuthorityIpcClient(config),error=>error.code==='UNAVAILABLE')
        await assert.rejects(createAuthorityIpcClient({...config,socketAccess:{...socketAccess,client_uid:socketAccess.client_uid+1}}),error=>error.code==='UNAVAILABLE')
        await assert.rejects(createAuthorityIpcClient({...config,socketAccess:{...socketAccess,group_gid:socketAccess.group_gid+1}}),error=>error.code==='UNAVAILABLE')
        await chmod(path,0o600)
        await assert.rejects(createAuthorityIpcClient({...config,socketAccess}),error=>error.code==='UNAVAILABLE')
        await chmod(path,0o660)
        const client=await createAuthorityIpcClient({...config,socketAccess})
        assert.equal((await client.request('authority.status',{})).ok,true);await client.close()
      } finally {await server.close()}
    })
    console.log(JSON.stringify({status:'PASS',checks,scope:'fixed private authority role/method plane over real child-process IPC',
      limits:['synthetic handler only; owner tokens and proofs still require C','same UID; no deployment/isolation qualification','tamper and replay covered by shared engine IPC checks']}))
  } finally {
    for(const client of clients)await client.close()
    if(child.connected){const done=once(child,'exit');child.send({type:'close'});await Promise.race([done,delay(2000).then(()=>child.kill())])}
    else if(child.exitCode===null)child.kill()
    await rm(root,{recursive:true,force:true})
  }
}
