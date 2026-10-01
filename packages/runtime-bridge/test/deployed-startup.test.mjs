// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable same-UID Unix transport regression only. The synthetic handlers
// below prove startup/authenticated routing, not C proof, PostgreSQL or UID isolation.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,realpath,lstat,rm} from 'node:fs/promises'
import {join} from 'node:path'
import {createAuthorityIpcServer,createAuthorityIpcClient,createIpcServer,createIpcClient} from '../src/ipc.mjs'
import {credentialId,memoryCredentialId,validateCredential} from './deployed-profile.mjs'
import {fixtureStartupDiagnostic} from './deployed-bootstrap.mjs'

const profile={fixture:{run_id:'94d2bfebeeca4499b217092d'}}
const secret='a'.repeat(64)
const diagnostics=error=>JSON.stringify(fixtureStartupDiagnostic(error))

test('generated fixture IDs satisfy the unchanged private and app transport grammar',()=>{
  assert.equal(memoryCredentialId(profile),'fixture-memory-94d2bfebeeca4499b217092d')
  for(const owner of ['primary','secondary'])assert.equal(credentialId(profile,owner),'fixture-'+owner+'-94d2bfebeeca4499b217092d')
  for(const id of [memoryCredentialId(profile),credentialId(profile,'primary'),credentialId(profile,'secondary')]){
    assert.deepEqual(validateCredential({id,secret},id),{id,secret})
    const legacy=id.replace(/-([a-f0-9]{24})$/,':$1')
    assert.throws(()=>validateCredential({id:legacy,secret},legacy),/EXACT_FIXTURE_IPC_CREDENTIAL_REQUIRED/)
  }
})

test('both real server constructors refuse legacy colon IDs before binding; corrected fixture IDs authenticate',async t=>{
  const root=await realpath(await mkdtemp('/tmp/prime-startup-'))
  t.after(()=>rm(root,{recursive:true,force:true}))
  const cases=[
    {name:'authority',server:createAuthorityIpcServer,client:createAuthorityIpcClient,
      entries:[{id:memoryCredentialId(profile),role:'memory_effect',secret}],method:'authority.status'},
    {name:'memory',server:createIpcServer,client:createIpcClient,
      entries:['primary','secondary'].map(owner=>({id:credentialId(profile,owner),role:'owner_control',secret})),method:'capability.status'},
  ]
  for(const item of cases){
    const socketPath=join(root,item.name+'.sock')
    let calls=0
    const handlePublic=(method,input,context)=>{calls++;return {ok:true,method,role:context.role,credential_id:context.request.credential_id}}
    for(let index=0;index<item.entries.length;index++){
      const credentials=item.entries.map((entry,i)=>({...entry,id:i===index?entry.id.replace(/-([a-f0-9]{24})$/,':$1'):entry.id}))
      await assert.rejects(item.server({socketPath,credentials,handlePublic}),error=>{
        assert.ok(error instanceof TypeError)
        assert.deepEqual(fixtureStartupDiagnostic(error),{version:1,kind:'prime-private-cd-pg-startup-diagnostic/v1',name:'TypeError',code:'INVALID',reason:'IPC_CREDENTIAL_IDENTITY_OR_ROLE_INVALID'})
        return true
      })
      await assert.rejects(lstat(socketPath),error=>error.code==='ENOENT')
      assert.equal(calls,0)
    }
    const server=await item.server({socketPath,credentials:item.entries,handlePublic})
    try{
      assert.equal((await lstat(socketPath)).isSocket(),true)
      for(const entry of item.entries){
        const client=await item.client({socketPath,credential:{id:entry.id,secret}})
        try{assert.deepEqual(await client.request(item.method,{}),{ok:true,method:item.method,role:entry.role,credential_id:entry.id})}
        finally{await client.close()}
      }
      assert.equal(calls,item.entries.length)
    }finally{await server.close()}
    await assert.rejects(lstat(socketPath),error=>error.code==='ENOENT')
  }
})

test('startup diagnostics support IPC error_code and built-in TypeErrors using finite tokens',()=>{
  const error=Object.assign(new Error('IPC_PROVISIONED_SOCKET_ACCESS_REQUIRED'),{error_code:'UNAVAILABLE'})
  assert.deepEqual(fixtureStartupDiagnostic(error),{version:1,kind:'prime-private-cd-pg-startup-diagnostic/v1',name:'Error',code:'UNAVAILABLE',reason:'IPC_PROVISIONED_SOCKET_ACCESS_REQUIRED'})
  assert.equal(fixtureStartupDiagnostic(Object.assign(new Error('IPC_PRIVATE_HOST_SOCKET_DIRECTORY_REQUIRED'),{error_code:'UNAUTHORIZED'})).code,'UNAUTHORIZED')
  assert.equal(fixtureStartupDiagnostic(new TypeError('INVALID: IPC credential identity')).reason,'IPC_CREDENTIAL_IDENTITY_INVALID')
  assert.equal(fixtureStartupDiagnostic(Object.assign(new Error('unknown'),{code:'EACCES'})).code,'EACCES')
  assert.equal(fixtureStartupDiagnostic(Object.assign(new Error('unknown'),{code:'INVALID',error_code:'UNAVAILABLE'})).code,'INVALID')
  assert.ok(Object.isFrozen(fixtureStartupDiagnostic(error)))
})

test('startup diagnostics suppress raw secret/path/message/cause/stack fields and accessor values',()=>{
  const sentinel='SECRET-SENTINEL\n/private/fixture/config.json'
  const error={name:sentinel,code:sentinel,error_code:sentinel,message:sentinel,stack:sentinel,cause:{config:sentinel,secret:sentinel}}
  const expected={version:1,kind:'prime-private-cd-pg-startup-diagnostic/v1',name:'Error',code:'UNAVAILABLE',reason:'STARTUP_DETAIL_SUPPRESSED'}
  assert.deepEqual(fixtureStartupDiagnostic(error),expected)
  assert.equal(diagnostics(error).includes('SECRET-SENTINEL'),false)
  let reads=0
  const accessors=Object.defineProperties({},Object.fromEntries(['name','code','error_code','message'].map(key=>[key,{get(){reads++;throw new Error(sentinel)}}])))
  assert.deepEqual(fixtureStartupDiagnostic(accessors),expected)
  assert.equal(reads,0)
  const throwingProxy=new Proxy({},{getOwnPropertyDescriptor(){throw new Error(sentinel)}})
  const throwingPrototype=new Proxy({},{getPrototypeOf(){throw new Error(sentinel)}})
  const revoked=Proxy.revocable({},{});revoked.revoke()
  for(const value of [null,undefined,sentinel,1,{},new Error(sentinel),throwingProxy,throwingPrototype,revoked.proxy]){
    const text=diagnostics(value)
    assert.equal(text.includes('SECRET-SENTINEL'),false)
    assert.ok(Buffer.byteLength(text)<256)
  }
})
