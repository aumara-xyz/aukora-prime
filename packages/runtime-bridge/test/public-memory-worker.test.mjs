// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual worker factories and same-UID Unix IPC with D's SQLite dialect fixture.
// No production host qualification, real C owner join, PostgreSQL or UID proof.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,realpath,lstat,rm} from 'node:fs/promises'
import {join} from 'node:path'
import {startMemoryWorker,startPublicMemoryWorker,startWorker} from '../src/worker.mjs'
import {createIpcClient,PUBLIC_METHODS} from '../src/ipc.mjs'
import {FixturePool} from './sql-fixture.mjs'

const marker='qualified-owner-memory/v1',secret='a'.repeat(64)
const at='2026-10-01T11:03:00Z'
const task={version:1,task_id:'synthetic-public-worker-task',owner_id:'synthetic-owner',agent_id:'synthetic-agent',
  conversation_id:'synthetic-conversation',status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],
  max_input_tokens:100,max_output_tokens:100,max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}}
const registryEntries=[{task,provider_and_region:{provider:'local',region:'local'},audience:'aukora-prime.memory',
  policy_version:'synthetic-policy',data_scope:['synthetic']}]
const unmountedSynthetic={profile:'synthetic-unmounted-public-worker/v1',environment:'synthetic',accepted:false,
  app_uid:0,broker_uid:0,transport:'authenticated-ipc',owner_enrollment:'unperformed',postgres_runtime:'unperformed',
  source_commit:'0'.repeat(40),release_digest:'sha256:'+'0'.repeat(64)}

async function fixture(t,kind){
  const root=await realpath(await mkdtemp('/tmp/prime-pmw-')),socketPath=join(root,'memory.sock')
  const authoritySocket=join(root,'missing-authority.sock')
  let worker,pool,poolClosed=false,poolOpens=0,queries=0,contextCalls=0,authorityChannelReads=0
  const clients=[]
  t.after(async()=>{
    for(const client of clients)await client.close()
    await worker?.close()
    if(pool&&!poolClosed){pool.close();poolClosed=true}
    await rm(root,{recursive:true,force:true})
  })
  const config={kind,ipc:{socketPath,credentials:[{id:'synthetic-app',role:'owner_control',secret}]},
    // This test-only accessor observes attempted private client construction.
    // The endpoint is absent; qualification must prevent even reading its path.
    authorityChannel:{get socketPath(){authorityChannelReads++;return authoritySocket},credential:{id:'synthetic-memory',secret:'b'.repeat(64)}},
    registryEntries,initializeSchema:true,
    createPgPool(){
      poolOpens++;pool=new FixturePool(join(root,'memory.sqlite'))
      const query=pool.query.bind(pool)
      pool.query=(...args)=>{queries++;return query(...args)}
      pool.end=async()=>{if(!poolClosed){pool.close();poolClosed=true}}
      return pool
    },
    resolveHostContext(){contextCalls++;throw new Error('SYNTHETIC_CONTEXT_MUST_NOT_BE_REACHED')},
  }
  return {config,socketPath,authoritySocket,
    async start(factory,settings=config){worker=await factory(settings);return worker},
    async connect(){const client=await createIpcClient({socketPath,credential:{id:'synthetic-app',secret}});clients.push(client);return client},
    counts:()=>({poolOpens,queries,contextCalls,authorityChannelReads}),
    effects:()=>Object.fromEntries(['records','intents','effects','requests'].map(name=>[name,pool.db.prepare('SELECT count(*) AS n FROM prime_memory_'+name).get().n])),
  }
}

test('public memory factory gates every authenticated IPC method on rejected qualification; synthetic SQL only',async t=>{
  const f=await fixture(t,'public-memory')
  let qualification=null,verifications=0
  f.config.verifyHostQualification=()=>{verifications++;return qualification}
  const worker=await f.start(startPublicMemoryWorker),client=await f.connect()
  assert.equal(worker.status().kind,'public-memory')
  assert.equal(worker.status().qualification,'per-request')
  assert.equal(worker.status().public_dispatch,marker)
  assert.equal(verifications,0,'startup must not cache a qualification decision')
  const baseline=f.counts()
  assert.equal(baseline.poolOpens,1)
  assert.deepEqual(f.effects(),{records:0,intents:0,effects:0,requests:0})
  await assert.rejects(lstat(f.authoritySocket),error=>error.code==='ENOENT')
  const methods=['capability.status','owner.loginChallenge','memory.save',...PUBLIC_METHODS.filter(method=>!['capability.status','owner.loginChallenge','memory.save'].includes(method))]
  for(const value of [null,true,unmountedSynthetic]){
    qualification=value
    for(const method of methods){
      const before=verifications
      const input=method==='owner.loginChallenge'?{owner_id:task.owner_id,kind:'passkey'}:
        method==='memory.save'?{session_token:'c'.repeat(64),idempotency_key:'synthetic-public-worker-save'}:{}
      const result=await client.request(method,input)
      assert.equal(verifications,before+1,method+' must recheck qualification')
      if(method==='capability.status'){
        assert.equal(result.ok,true)
        assert.equal(result.public_dispatch,marker)
        assert.equal(result.state,'unqualified')
        assert.equal(result.available,false)
        assert.equal(result.public_routes,'unavailable')
        assert.equal(result.qualification,null)
        assert.equal(result.postgres_runtime,'unperformed')
        assert.equal(result.runtime_isolation,'unverified')
      }else assert.deepEqual(result,{ok:false,error_code:'UNAVAILABLE',reason:'SEPARATED_HOST_QUALIFICATION_REQUIRED'},method)
      assert.deepEqual(f.counts(),baseline,'refused calls must reach no context, private channel or SQL')
      assert.deepEqual(f.effects(),{records:0,intents:0,effects:0,requests:0})
    }
  }
  await assert.rejects(lstat(f.authoritySocket),error=>error.code==='ENOENT')
})

test('internal memory factory capability omits the public dispatch marker',async t=>{
  const f=await fixture(t,'memory'),worker=await f.start(startMemoryWorker),client=await f.connect()
  assert.equal(worker.status().kind,'memory')
  assert.equal(worker.status().qualification,'unqualified')
  assert.equal(Object.hasOwn(worker.status(),'public_dispatch'),false)
  const baseline=f.counts(),result=await client.request('capability.status',{})
  assert.equal(result.ok,true)
  assert.equal(result.available,false)
  assert.equal(result.public_routes,'unavailable')
  assert.equal(Object.hasOwn(result,'public_dispatch'),false)
  assert.deepEqual(f.counts(),baseline)
  assert.deepEqual(f.effects(),{records:0,intents:0,effects:0,requests:0})
})

test('public memory verifier and dispatch mode are closed constructor inputs before pool creation',async t=>{
  const f=await fixture(t,'public-memory')
  for(const factory of [startPublicMemoryWorker,startWorker]){
    await assert.rejects(factory(f.config),TypeError)
    for(const verifyHostQualification of [null,true,unmountedSynthetic])
      await assert.rejects(factory({...f.config,verifyHostQualification}),TypeError)
  }
  await assert.rejects(startPublicMemoryWorker({...f.config,kind:'memory',verifyHostQualification:()=>null}),TypeError)
  await assert.rejects(startPublicMemoryWorker({...f.config,verifyHostQualification:()=>null,public_dispatch:marker}),TypeError)
  const internal={...f.config,kind:'memory'}
  await assert.rejects(startMemoryWorker({...internal,verifyHostQualification:()=>null}),TypeError)
  await assert.rejects(startMemoryWorker({...internal,public_dispatch:marker}),TypeError)
  await assert.rejects(startMemoryWorker(f.config),TypeError)
  assert.deepEqual(f.counts(),{poolOpens:0,queries:0,contextCalls:0,authorityChannelReads:0})
  await assert.rejects(lstat(f.socketPath),error=>error.code==='ENOENT')
})
