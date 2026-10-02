// SPDX-License-Identifier: AGPL-3.0-or-later
// Keyless local process-mechanism evidence only. Same-UID Mac children cannot
// qualify Linux cross-UID supervision, a real gateway or all-artifact cleanup.
import assert from 'node:assert/strict'
import { fork } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { chmod,mkdir,mkdtemp,realpath,rm,writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { request,settings } from './harness.mjs'
import { fixtureBackendCall } from './guardian-fixture-worker.mjs'
import { createLocalLifetime,localLifetimeDigest } from '../src/lifetime-safety.mjs'
import { executorRequestDigest } from '../src/binding.mjs'
import { createTemplate,createProfileDigest,GUEST_WORKDIR } from '../src/create-profile.mjs'
import { operationDigest } from '../../contracts/src/runtime.mjs'
import { guardianCall } from '../src/guardian/ipc.mjs'

const worker=fileURLToPath(new URL('./guardian-fixture-worker.mjs',import.meta.url))
const copy=value=>structuredClone(value)
const digest=character=>'sha256:'+character.repeat(64)
const children=new Set()
const safeWrite=(file,value)=>writeFile(file,JSON.stringify(value),{mode:0o600})

function launch(args,wanted='ready') {
  const child=fork(worker,args,{stdio:['ignore','pipe','pipe','ipc'],execArgv:[]})
  children.add(child)
  let output=''
  child.stdout.on('data',data=>{output+=data.toString()})
  child.stderr.on('data',data=>{output+=data.toString()})
  const exit=new Promise(resolve=>child.once('exit',(code,signal)=>{children.delete(child);resolve({code,signal,output})}))
  const ready=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error(`fixture ${args[0]} startup timed out: ${output}`)),3000)
    const finish=(failure,value)=>{clearTimeout(timer);child.removeListener('message',message);if(failure)reject(failure);else resolve(value)}
    const message=value=>{
      if(value?.type==='error')finish(Object.assign(new Error(value.message),{code:value.code}))
      else if(value?.type===wanted)finish(null,value)
    }
    child.on('message',message)
    child.once('exit',(code,signal)=>finish(new Error(`fixture ${args[0]} exited before readiness (${code??signal}): ${output}`)))
  })
  return {child,ready,exit,get output(){return output}}
}

async function stop(process,{crash=false}={}) {
  if(process.child.exitCode!==null||process.child.signalCode!==null)return process.exit
  if(crash)process.child.kill('SIGKILL')
  else process.child.send({type:'close'})
  return Promise.race([process.exit,delay(1000).then(async()=>{process.child.kill('SIGKILL');return process.exit})])
}

async function until(description,inspect,{timeoutMs=3000}={}) {
  const deadline=Date.now()+timeoutMs
  while(Date.now()<deadline) {
    const value=await inspect()
    if(value)return value
    await delay(15)
  }
  assert.fail(description+' did not occur within the disposable bound')
}

function registration(scope,wall=250) {
  const r=request({wall_time_ms:wall})
  r.operation.canonical_parameters.timeout_ms=wall
  r.consumed_grant.operation_digest=operationDigest(r.operation)
  const job={request:r,request_id:r.request_id,request_digest:executorRequestDigest(r)}
  const token=randomUUID(),lifetime=createLocalLifetime(job)
  return {version:1,request:r,request_digest:job.request_digest,ledger_id:scope.ledger_id,
    gateway_identity:scope.gateway_identity,deployment_digest:scope.deployment_digest,host_profile_digest:scope.host_profile_digest,
    name:`prime-bash-${token}`,token,create_request_id:randomUUID(),delete_request_id:randomUUID(),
    create_template:createTemplate(settings.image_digest),create_profile_digest:createProfileDigest(settings.image_digest),
    guest_workdir:GUEST_WORKDIR,lifetime,lifetime_digest:localLifetimeDigest(lifetime)}
}

function resource(reg,overrides={}) {
  return {uid:randomUUID(),name:reg.name,workspace:settings.workspace,owner_token:reg.token,
    origin_request_id:reg.create_request_id,...overrides}
}
function assertUnqualified(row) {
  assert.equal(row.effect_outcome,'unknown')
  assert.equal(row.runtime_qualified,false)
  assert.equal(row.terminal_fence,'unavailable')
  assert.equal(row.artifact_cleanup,'unverified')
}

async function fixture(work) {
  // realpath avoids Mac's /tmp symlink; short paths fit Darwin Unix sockets.
  const root=await mkdtemp(join(await realpath('/tmp'),'auk-g-'))
  await chmod(root,0o700)
  const guardianRoot=join(root,'g');await mkdir(guardianRoot,{mode:0o700})
  const socketPath=join(guardianRoot,'guardian.sock'),backendPath=join(root,'backend.sock'),scopeFile=join(root,'scope.json')
  const scope={version:1,ledger_id:randomUUID(),gateway_identity:'https://synthetic.invalid:19443/',
    deployment_digest:digest('b'),host_profile_digest:digest('c'),workspace:settings.workspace,
    image_digest:settings.image_digest,logical_workspace_root:settings.logical_workspace_root}
  await safeWrite(scopeFile,scope)
  const backend=launch(['fixture-backend',root,backendPath])
  let guardian=null
  const context={root,guardianRoot,socketPath,backendPath,scope,scopeFile,
    backendCall:(method,payload)=>fixtureBackendCall(backendPath,method,payload),
    async start(initialize=true) {guardian=launch(['fixture-guardian',guardianRoot,socketPath,backendPath,scopeFile,initialize?'initialize':'reopen']);return guardian.ready},
    async stopGuardian(crash=false) {const current=guardian;guardian=null;return stop(current,{crash})},
    async inspect(reg,row) {return guardianCall(socketPath,'inspect',{request_id:reg.request.request_id,registration_digest:row.registration_digest})},
    async register(reg) {return guardianCall(socketPath,'register',reg)},
    async cancel(reg,row,reason='caller') {return guardianCall(socketPath,'cancel',{request_id:reg.request.request_id,registration_digest:row.registration_digest,reason})},
    async registerOwner(reg) {
      const file=join(root,'owner-registration.json');await safeWrite(file,reg)
      const owner=launch(['fixture-owner',socketPath,file],'registered'),reply=await owner.ready
      const exited=await owner.exit;assert.equal(exited.code,0,exited.output)
      return {row:reply.value,owner_pid:reply.pid}
    },
    get guardian(){return guardian},
  }
  try {await backend.ready;await work(context)}
  finally {if(guardian)await stop(guardian);await stop(backend);await rm(root,{recursive:true,force:true})}
}

const cases={
  async owner_exit_and_late_resource_cleanup() {
    await fixture(async f=>{
      const ready=await f.start(),reg=registration(f.scope,180),{row,owner_pid}=await f.registerOwner(reg)
      assert.notEqual(owner_pid,ready.pid)
      assert.notEqual(owner_pid,process.pid)
      const originalDeadline=row.registration.lifetime.deadline_at
      await until('guardian observes original deadline after owner exit',async()=>{
        const current=await f.inspect(reg,row)
        return current.mode==='cleanup_requested'&&current.observation?.state==='api_absent'&&current
      })
      const unrelated=resource(reg,{name:'unrelated-disposable',owner_token:randomUUID(),origin_request_id:randomUUID()}),owned=resource(reg)
      await f.backendCall('add',{resource:unrelated})
      await f.backendCall('add',{resource:owned})
      const state=await until('late owned resource reclaimed',async()=>{
        const value=await f.backendCall('read');return !value.resources[owned.uid]&&value.events.some(event=>event.action==='reclaimed'&&event.uid===owned.uid)&&value
      })
      assert.deepEqual(state.resources[unrelated.uid],unrelated)
      const current=await f.inspect(reg,row)
      assert.equal(current.registration.lifetime.deadline_at,originalDeadline)
      assert.equal(current.mode,'cleanup_requested');assertUnqualified(current)
    })
  },
  async guardian_restart_preserves_original_deadline() {
    await fixture(async f=>{
      const ready=await f.start(),reg=registration(f.scope,350),row=await f.register(reg)
      const deadline=row.registration.lifetime.deadline_at
      // The SQLite owner lock must prevent an overlapping guardian from serving.
      const duplicate=launch(['fixture-guardian',f.guardianRoot,f.socketPath,f.backendPath,f.scopeFile,'reopen'])
      await assert.rejects(duplicate.ready)
      await duplicate.exit
      await f.stopGuardian(true)
      await until('original deadline passes during guardian absence',()=>Date.now()>Date.parse(deadline)+25)
      const owned=resource(reg);await f.backendCall('add',{resource:owned})
      const restarted=await f.start(false)
      assert.equal(restarted.guardian_id,ready.guardian_id)
      await until('restart reconciles expired original job',async()=>{
        const value=await f.backendCall('read');return !value.resources[owned.uid]&&value.events.some(event=>event.action==='reclaimed'&&event.uid===owned.uid)
      })
      const current=await f.inspect(reg,row)
      assert.equal(current.registration.lifetime.deadline_at,deadline)
      assert.equal(current.registration.lifetime.accepted_at,row.registration.lifetime.accepted_at)
      assert.equal(current.mode,'cleanup_requested');assertUnqualified(current)
    })
  },
  async duplicate_registration_cannot_extend_or_rebind() {
    await fixture(async f=>{
      await f.start();const reg=registration(f.scope,1500),row=await f.register(reg),duplicate=await f.register(copy(reg))
      assert.equal(duplicate.registration_digest,row.registration_digest)
      assert.equal(duplicate.guardian_id,row.guardian_id)
      assert.equal(duplicate.registration.lifetime.deadline_at,row.registration.lifetime.deadline_at)
      const extended=copy(reg)
      extended.lifetime.deadline_at=new Date(Date.parse(extended.lifetime.deadline_at)+100).toISOString()
      extended.lifetime_digest=localLifetimeDigest(extended.lifetime)
      await assert.rejects(f.register(extended))
      const rebound=copy(reg);rebound.token=randomUUID();rebound.name=`prime-bash-${rebound.token}`
      await assert.rejects(f.register(rebound))
      const current=await f.inspect(reg,row)
      assert.equal(current.registration_digest,row.registration_digest)
      assert.deepEqual(current.registration,reg);assertUnqualified(current)
    })
  },
  async identity_substitution_refuses_delete() {
    await fixture(async f=>{
      await f.start();const reg=registration(f.scope,1500),row=await f.register(reg),owned=resource(reg),replacement=resource(reg)
      await f.backendCall('add',{resource:owned})
      await f.backendCall('configure',{replace_on_reclaim:replacement})
      await f.cancel(reg,row)
      await until('conditional backend refuses UID replacement',async()=>{
        const value=await f.backendCall('read');return value.events.some(event=>event.action==='reclaim_refused')&&value
      })
      await delay(90)
      const state=await f.backendCall('read')
      assert.deepEqual(state.resources[replacement.uid],replacement)
      assert.equal(state.events.filter(event=>event.action==='reclaimed').length,0)
      assert.equal(state.events.filter(event=>event.action==='reclaim_attempt'&&event.resource.uid===replacement.uid).length,0)
      assertUnqualified(await f.inspect(reg,row))
    })
  },
  async exact_name_owner_and_origin_are_required() {
    await fixture(async f=>{
      await f.start();const reg=registration(f.scope,1500),row=await f.register(reg)
      const wrongOwner=resource(reg,{owner_token:randomUUID()})
      await f.backendCall('add',{resource:wrongOwner});await f.cancel(reg,row)
      await until('matching name with foreign owner is refused',async()=>{
        const current=await f.inspect(reg,row);return current.observation?.state==='identity_mismatch'
      })
      const first=await f.backendCall('read')
      assert.deepEqual(first.resources[wrongOwner.uid],wrongOwner)
      assert.equal(first.events.filter(event=>event.action==='reclaim_attempt').length,0)
      await f.backendCall('remove',{uid:wrongOwner.uid})
      const wrongOrigin=resource(reg,{origin_request_id:randomUUID()})
      await f.backendCall('add',{resource:wrongOrigin})
      await until('matching name and owner with foreign origin is refused',async()=>{
        const current=await f.inspect(reg,row),state=await f.backendCall('read')
        return current.observation?.state==='identity_mismatch'&&state.observations>first.observations+1
      })
      const second=await f.backendCall('read')
      assert.deepEqual(second.resources[wrongOrigin.uid],wrongOrigin)
      assert.equal(second.events.filter(event=>event.action==='reclaim_attempt').length,0)
      assertUnqualified(await f.inspect(reg,row))
    })
  },
  async outage_preserves_watch_then_recovers() {
    await fixture(async f=>{
      await f.start();const reg=registration(f.scope,180),row=await f.register(reg),owned=resource(reg)
      await f.backendCall('add',{resource:owned})
      await f.backendCall('configure',{outage:true})
      await until('independent observer records API outage',async()=>{
        const state=await f.backendCall('read'),current=await f.inspect(reg,row)
        return state.failed_observations>=2&&current.mode==='cleanup_requested'
      })
      const unavailable=await f.backendCall('read')
      assert.deepEqual(unavailable.resources[owned.uid],owned)
      assert.equal(unavailable.events.filter(event=>event.action==='reclaimed').length,0)
      assertUnqualified(await f.inspect(reg,row))
      await f.backendCall('configure',{outage:false})
      await until('same watch cleans after API recovery',async()=>{
        const value=await f.backendCall('read');return !value.resources[owned.uid]&&value.events.some(event=>event.action==='reclaimed'&&event.uid===owned.uid)
      })
      assertUnqualified(await f.inspect(reg,row))
    })
  },
  async lost_reply_reuses_exact_attempt_for_same_resource() {
    await fixture(async f=>{
      await f.start();const reg=registration(f.scope,1500),row=await f.register(reg),owned=resource(reg)
      await f.backendCall('add',{resource:owned})
      await f.backendCall('configure',{lost_reclaims:1})
      await f.cancel(reg,row)
      const state=await until('cleanup reobserves immutable resource after reply loss',async()=>{
        const value=await f.backendCall('read');return value.events.some(event=>event.action==='reclaimed'&&event.uid===owned.uid)&&value
      })
      const attempts=state.events.filter(event=>event.action==='reclaim_attempt')
      assert.equal(attempts.length,2)
      assert.equal(attempts[0].request_id,attempts[1].request_id)
      assert.deepEqual(attempts[0].resource,attempts[1].resource)
      const replacement=resource(reg);await f.backendCall('add',{resource:replacement})
      await delay(90)
      const final=await f.backendCall('read')
      assert.deepEqual(final.resources[replacement.uid],replacement)
      assert.equal(final.events.filter(event=>event.action==='reclaim_attempt').length,2)
      assertUnqualified(await f.inspect(reg,row))
    })
  },
}

const selected=process.argv.slice(2)
for(const name of selected)if(!Object.hasOwn(cases,name))throw new Error('unknown guardian process case: '+name)
let passed=0
try {
  for(const name of selected.length?selected:Object.keys(cases)) {await cases[name]();passed++;console.log(JSON.stringify({case:name,status:'PASS'}))}
  console.log(JSON.stringify({check:'guardian-process',passed,runtime_qualified:false,evidence:'keyless local separate processes with authored conditional backend; no real gateway, credentials, guest or host changes'}))
} finally {
  // Only child processes created by this fixture are eligible for cleanup.
  for(const child of children)child.kill('SIGKILL')
}
