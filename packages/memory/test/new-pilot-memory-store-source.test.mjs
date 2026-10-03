// SPDX-License-Identifier: AGPL-3.0-or-later
// PURE source-entry checks. No SQL, guard installer, filesystem fixture or PG is run.
import test from 'node:test'
import assert from 'node:assert/strict'
import {prepareNewPilotMemoryStore,verifyNewPilotMemoryStore,NEW_PILOT_MEMORY_TABLE_NAMES}
  from '../src/new-pilot-memory-store.mjs'

const entrypoints=[prepareNewPilotMemoryStore,verifyNewPilotMemoryStore]
const host=Object.freeze({owner_id:'synthetic-owner-id',owner_subject:'synthetic-owner-subject',
  task_id:'synthetic-task',authorization_epoch:0})
const profile=Object.freeze({version:2,kind:'prime-private-unsent-closure/v2',
  expected_authority_store_id:'a'.repeat(64),expected_memory_store_id:'b'.repeat(64),retention_profile:'required-retained/v2'})
const contracts=Object.freeze({validateContract(){throw Error('not invoked')},operationDigest(){throw Error('not invoked')},
  canonicalJson(){throw Error('not invoked')}})
const configuration=()=>({host,profile,contracts,expected_schema:'prime_pilot_123456781234423489ab123456789abc'})
let queries=0
const noQuery=Object.freeze({query(){queries++;throw Error('SQL forbidden by PURE check')}})
async function refuses(input,code,client=noQuery) {
  const before=queries
  for(const entrypoint of entrypoints) await assert.rejects(entrypoint(client,input),error=>error.code===code)
  assert.equal(queries,before)
}

test('fixed census contains every existing physical/control/journal table and sole new logical table',()=>{
  assert.deepEqual([...NEW_PILOT_MEMORY_TABLE_NAMES],[
    'prime_memory_chain','prime_memory_controls','prime_memory_effects','prime_memory_events','prime_memory_fts',
    'prime_memory_heads','prime_memory_intents','prime_memory_logical_store','prime_memory_originals',
    'prime_memory_outbox','prime_memory_purges','prime_memory_quarantine','prime_memory_records',
    'prime_memory_redactions','prime_memory_replay_fences','prime_memory_requests','prime_memory_snapshots',
    'prime_memory_tombstones','prime_memory_unsent_closures','prime_runtime_workflow_closure_progress_v2','prime_runtime_workflows',
  ])
  assert.equal(Object.isFrozen(NEW_PILOT_MEMORY_TABLE_NAMES),true)
})
test('only fresh lowercase raw UUIDv4 pilot schema grammar is accepted before client inspection',async()=>{
  await refuses(configuration(),'memory:new-pilot-store-client-required',null)
  for(const expected_schema of ['prime_memory','public','prime_pilot_'+'a'.repeat(32),
    'prime_pilot_123456781234123489ab123456789abc','prime_pilot_123456781234423479ab123456789abc',
    'prime_pilot_123456781234423489ab123456789abc;DROP TABLE x',
    ['prime_pilot_123456781234423489ab123456789abc']])
    await refuses({...configuration(),expected_schema},'memory:new-pilot-store-schema-required')
})
test('configuration is closed inert data; getters and proxies do not execute',async()=>{
  let traps=0
  const getter={...configuration()}
  Object.defineProperty(getter,'expected_schema',{get(){traps++;throw Error('getter forbidden')},enumerable:true})
  await refuses(getter,'memory:new-pilot-store-configuration-required')
  await refuses(new Proxy(configuration(),{ownKeys(){traps++;throw Error('proxy forbidden')}}),
    'memory:new-pilot-store-configuration-required')
  await refuses({...configuration(),allow_existing:true},'memory:new-pilot-store-configuration-required')
  const missing=configuration();delete missing.profile
  await refuses(missing,'memory:new-pilot-store-configuration-required')
  assert.equal(traps,0)
})
test('host and profile accessors/proxies are rejected without running traps',async()=>{
  let traps=0
  const dangerous=new Proxy(profile,{ownKeys(){traps++;throw Error('proxy forbidden')}})
  for(const entrypoint of entrypoints) await assert.rejects(entrypoint(noQuery,{...configuration(),profile:dangerous}))
  const dangerousHost={...host}
  Object.defineProperty(dangerousHost,'owner_subject',{get(){traps++;throw Error('getter forbidden')},enumerable:true})
  for(const entrypoint of entrypoints) await assert.rejects(entrypoint(noQuery,{...configuration(),host:dangerousHost}))
  assert.equal(traps,0);assert.equal(queries,0)
})
test('contract methods are captured own data and Proxy functions are refused',async()=>{
  let traps=0
  const getter={...contracts}
  Object.defineProperty(getter,'canonicalJson',{get(){traps++;throw Error('getter forbidden')},enumerable:true})
  await refuses({...configuration(),contracts:getter},'memory:new-pilot-store-contracts-required')
  await refuses({...configuration(),contracts:{...contracts,operationDigest:new Proxy(contracts.operationDigest,
    {apply(){traps++;throw Error('proxy forbidden')}})}},'memory:new-pilot-store-contracts-required')
  assert.equal(traps,0)
})
test('client getters and proxy clients/prototypes refuse before guard imports or SQL',async()=>{
  let traps=0
  const getter={get query(){traps++;throw Error('getter forbidden')}}
  await refuses(configuration(),'memory:new-pilot-store-client-required',getter)
  await refuses(configuration(),'memory:new-pilot-store-client-required',new Proxy({},
    {getOwnPropertyDescriptor(){traps++;throw Error('proxy forbidden')}}))
  await refuses(configuration(),'memory:new-pilot-store-client-required',Object.create(new Proxy({},
    {getOwnPropertyDescriptor(){traps++;throw Error('proxy forbidden')}})))
  assert.equal(traps,0)
})
test('supplied IDs/profile remain unchanged and no generated ID or query occurs on validation refusal',async()=>{
  const before=JSON.stringify(profile)
  await refuses(configuration(),'memory:new-pilot-store-client-required',null)
  assert.equal(JSON.stringify(profile),before)
  assert.equal(profile.expected_authority_store_id,'a'.repeat(64))
  assert.equal(profile.expected_memory_store_id,'b'.repeat(64))
  assert.equal(queries,0)
})
