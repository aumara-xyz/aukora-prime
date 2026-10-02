// SPDX-License-Identifier: AGPL-3.0-or-later
// SOURCE-FIXTURE ONLY: actual worker handler body with an injected delayed C
// service and inert listener. No C proof/store, IPC/MAC, PG, UID or runtime claim.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createTrustedTaskRegistry,closed,copy} from '../src/registry.mjs'
import {PRIVATE_AUTHORITY_METHODS} from '../src/ipc.mjs'

const source=readFileSync(new URL('../src/worker.mjs',import.meta.url),'utf8')
const begin=source.indexOf('const METHODS=')
const end=source.indexOf('export async function startMemoryWorker(')
assert(begin>=0&&end>begin,'fixture must use the actual authority worker body')
const load=new Function('contracts','createAuthorityService','createAuthorityIpcServer',
  'PRIVATE_AUTHORITY_METHODS','createTrustedTaskRegistry','closed','copy',
  source.slice(begin,end).replace('export async function startAuthorityWorker(',
    'async function startAuthorityWorker(')+';return startAuthorityWorker')
const owner='scope-fixture-owner',subject='aukora:1:'+'a'.repeat(64)
const task={version:1,task_id:'scope-fixture-task',owner_id:owner,agent_id:'scope-fixture-agent',
  conversation_id:'scope-fixture-conversation',status:'running',created_at:'2026-10-01T00:00:00Z',
  route_id:null,allowed_data_classes:['synthetic'],max_input_tokens:1,max_output_tokens:1,
  max_requests:1,task_spend_ceiling:{currency:'USD',amount:'0'}}
const operation={version:1,operation_id:'scope-fixture-operation',task_id:task.task_id,owner_id:owner,
  agent_id:task.agent_id,audience:'aukora-prime.memory',action_type:'memory.save',
  target_identity:{kind:'prime-memory',owner_subject:subject},canonical_parameters:{fixture:'synthetic'},
  data_scope:['synthetic'],expected_state_version:'fixture-state-1',
  provider_and_region:{provider:'local',region:'local'},maximum_cost:{currency:'USD',amount:'0'},
  expiry:'2030-01-01T00:00:00Z',nonce:'scope-fixture-nonce',policy_version:'scope-fixture-policy',authorization_epoch:0}
const context={role:'memory_effect'}
const deferred=()=>{let resolve,reject;const promise=new Promise((done,fail)=>{resolve=done;reject=fail});return {promise,resolve,reject}}
function wrapper(input={},op=operation,observe=true) {
  return {input,operation:op,operation_digest:op?contracts.operationDigest(op):null,
    observation:observe?{target_identity:op.target_identity,state_version:op.expected_state_version}:null}
}
async function fixture(methods) {
  let handler,authorityOptions
  const start=load(contracts,options=>{authorityOptions=options;return methods(()=>authorityOptions)},
    async options=>{handler=options.handlePublic;return {address:'synthetic-inert-listener',close:async()=>{}}},
    PRIVATE_AUTHORITY_METHODS,createTrustedTaskRegistry,closed,copy)
  const worker=await start({kind:'authority',ipc:{},registryEntries:[{task,provider_and_region:operation.provider_and_region,
    audience:operation.audience,policy_version:operation.policy_version,data_scope:operation.data_scope}],
    authorityConfig:{identities:[{owner_id:owner,subject}]}})
  assert.equal(worker.status().qualification,'unqualified')
  return {call(method,input,role=context){try{return Promise.resolve(handler(method,input,role))}catch(error){return Promise.reject(error)}},
    observe:op=>authorityOptions.observeTarget(op)}
}
const reentrant=error=>error.error_code==='UNAUTHORIZED'&&error.message==='WORKER_TARGET_SCOPE_REENTRANT'
const missing=error=>error.error_code==='UNAUTHORIZED'&&error.message==='WORKER_TARGET_SCOPE_REQUIRED'

test('C recheck after a microtask retains the exact scoped observation',async()=>{
  const f=await fixture(options=>({async reserve({operation:op}) {
    const before=options().observeTarget(op)
    await Promise.resolve()
    assert.deepEqual(options().observeTarget(op),before)
    return {ok:true}
  }}))
  assert.equal((await f.call('authority.reserve',wrapper({operation}))).ok,true)
  assert.throws(()=>f.observe(operation),missing)
})

test('observation survives delayed C call, remains detached/exact, and refuses overlap',async()=>{
  const gate=deferred();let enters=0,readCalls=0
  const f=await fixture(options=>({
    async reserve({operation:op}) {
      enters++;const before=options().observeTarget(op)
      await gate.promise
      const after=options().observeTarget(op)
      assert.deepEqual(after,before);assert.equal(Object.isFrozen(after),true)
      assert.throws(()=>options().observeTarget({...op,operation_id:'another-operation'}),missing)
      return {ok:true,fixture:'delayed-C'}
    },authenticateSession(){readCalls++;return {ok:true}}
  }))
  const input=wrapper({operation}),pending=f.call('authority.reserve',input)
  input.observation.state_version='changed-after-dispatch'
  assert.deepEqual(f.observe(operation),{target_identity:operation.target_identity,state_version:'fixture-state-1'})
  await assert.rejects(f.call('authority.reserve',wrapper({operation})),reentrant)
  const other={...operation,operation_id:'scope-fixture-other-operation'}
  await assert.rejects(f.call('authority.reserve',wrapper({operation:other},other)),reentrant)
  await assert.rejects(f.call('authority.authenticateSession',wrapper({},null,false)),reentrant)
  assert.equal(enters,1);assert.equal(readCalls,0)
  gate.resolve();assert.deepEqual(await pending,{ok:true,fixture:'delayed-C'})
  assert.throws(()=>f.observe(operation),missing)
  assert.deepEqual(await f.call('authority.authenticateSession',wrapper({},null,false)),{ok:true})
  assert.equal(readCalls,1)
})

test('pending rejection clears observation only after settlement, and later call is admitted',async()=>{
  const gate=deferred();let mode='reject',enters=0
  const f=await fixture(()=>({async reserve(){enters++;if(mode==='reject')await gate.promise;return {ok:true}}}))
  const pending=f.call('authority.reserve',wrapper({operation}))
  assert.equal(f.observe(operation).state_version,operation.expected_state_version)
  const rejected=assert.rejects(pending,/synthetic-C-rejected/)
  gate.reject(new Error('synthetic-C-rejected'));await rejected
  assert.throws(()=>f.observe(operation),missing)
  mode='complete';assert.equal((await f.call('authority.reserve',wrapper({operation}))).ok,true)
  assert.equal(enters,2)
})

test('synchronous completion and throw both release the scope without leaking it',async()=>{
  let throwing=true
  const f=await fixture(options=>({reserve({operation:op}){options().observeTarget(op);if(throwing)throw new Error('synthetic-sync-throw');return {ok:true}}}))
  await assert.rejects(f.call('authority.reserve',wrapper({operation})),/synthetic-sync-throw/)
  assert.throws(()=>f.observe(operation),missing)
  throwing=false;assert.equal((await f.call('authority.reserve',wrapper({operation}))).ok,true)
  assert.throws(()=>f.observe(operation),missing)
})

test('pending non-live C call fences later scope installation',async()=>{
  const gate=deferred();let reserves=0
  const f=await fixture(()=>({async authenticateSession(){await gate.promise;return {ok:true}},reserve(){reserves++;return {ok:true}}}))
  const pending=f.call('authority.authenticateSession',wrapper({},null,false))
  await assert.rejects(f.call('authority.reserve',wrapper({operation})),reentrant)
  assert.throws(()=>f.observe(operation),missing);assert.equal(reserves,0)
  gate.resolve();await pending
  assert.equal((await f.call('authority.reserve',wrapper({operation}))).ok,true);assert.equal(reserves,1)
})

test('private ACL, default unmounted refusal, and closed observation checks remain intact',async()=>{
  let calls=0
  const f=await fixture(()=>({reserve(){calls++;return {ok:true}}}))
  for(const role of ['owner_control','proposer','read_only'])
    await assert.rejects(f.call('authority.reserve',wrapper({operation}),{role}),/WORKER_PRIVATE_ROLE_REQUIRED/)
  await assert.rejects(f.call('authority.reserveRetained',wrapper({operation})),/WORKER_PRIVATE_ROLE_REQUIRED/)
  assert.deepEqual(await f.call('authority.claimDispatch',wrapper({operation})),
    {ok:false,error_code:'UNAVAILABLE',reason:'WORKER_AUTHORITY_SERVICE_UNMOUNTED:claimDispatch'})
  const bad=wrapper({operation});bad.observation.state_version='changed'
  await assert.rejects(f.call('authority.reserve',bad),/WORKER_TARGET_STATE_MISMATCH/)
  const extra=wrapper({operation});extra.observation.extra='guest-field'
  await assert.rejects(f.call('authority.reserve',extra),TypeError)
  assert.equal(calls,0);assert.throws(()=>f.observe(operation),missing)
})
