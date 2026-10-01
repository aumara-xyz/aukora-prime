// SPDX-License-Identifier: AGPL-3.0-or-later
// TEST ONLY: actual C passkey verification and D capture bindings, disposable
// SQLite SQL fixture. This is not PostgreSQL durability/advisory-lock evidence.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {randomBytes,randomUUID} from 'node:crypto'
import {mkdtempSync,realpathSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {createTrustedTaskRegistry} from '../src/registry.mjs'
import {createPostgresWorkflowStore,isWorkflowStore} from '../src/workflow-store.mjs'
import {authorityFixture} from './authority-fixture.mjs'
import {FixturePool} from './sql-fixture.mjs'

const at='2026-10-01T11:03:00Z'
const ownerId='synthetic-owner'
const taskFor=task_id=>({version:1,task_id,owner_id:ownerId,agent_id:'synthetic-agent',conversation_id:'synthetic-conversation',status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],max_input_tokens:100,max_output_tokens:100,max_requests:16,task_spend_ceiling:{currency:'USD',amount:'0'}})
const ok=result=>{assert.equal(result.ok,true,JSON.stringify(result));return result}
const refusal=error_code=>error=>error.error_code===error_code

async function fixture(t) {
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-workflow-journal-'))
  let pool
  t.after(()=>{pool?.close();rmSync(root,{recursive:true,force:true})})
  pool=new FixturePool(join(root,'synthetic.sqlite'))
  const tasks=['synthetic-task-one','synthetic-task-two'].map(taskFor)
  const registry=createTrustedTaskRegistry(tasks.map(task=>({task,provider_and_region:{provider:'local',region:'local'},audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']})))
  let memory
  const auth=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:registry.authorizeTask,observeTarget:operation=>memory.authorityTargetObservation(operation)})
  memory=createPostgresMemory({pool,authority:auth.service,contracts})
  await memory.migrate()
  const store=createPostgresWorkflowStore({pool})
  await store.migrate()
  const login=ok(auth.service.loginChallenge({owner_id:ownerId,kind:'passkey'}))
  const sessionToken=ok(auth.service.loginComplete({challenge:login.challenge,material:auth.assertion(login.public_key.challenge)})).session_token
  const event=Buffer.from(JSON.stringify({type:'turn',text:'Synthetic owner remembers a banana.',seq:0,at})+'\n')
  const hostFor=task_id=>({owner_subject:auth.identity.subject,owner_id:ownerId,task_id,privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(event)},events:[event]})
  async function proposal(task_id,key) {
    const host=hostFor(task_id),task=registry.getOwned(task_id,ownerId).task
    const input={category:'fact',statement:'Synthetic owner remembers a banana.',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}
    const binding=await memory.prepareCaptureBinding(host,input,key)
    const operation={version:1,operation_id:randomUUID(),task_id,owner_id:ownerId,agent_id:task.agent_id,audience:'aukora-prime.memory',action_type:'memory.save',target_identity:binding.target_identity,canonical_parameters:binding.canonical_parameters,data_scope:['synthetic'],expected_state_version:binding.state_version,provider_and_region:{provider:'local',region:'local'},maximum_cost:{currency:'USD',amount:'0'},expiry:new Date(Date.now()+120_000).toISOString(),nonce:randomBytes(32).toString('hex'),policy_version:'synthetic-policy',authorization_epoch:auth.identity.authorization_epoch}
    const admitted=ok(auth.service.propose({session_token:sessionToken,operation}))
    assert.equal(admitted.operation_digest,contracts.operationDigest(operation))
    return {host,input:{operation:admitted.operation,idempotency_key_sha256:binding.canonical_parameters.idempotency_key_sha256,record_id:null}}
  }
  const assertNoEffects=()=>assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,0)
  const authorityStatus=operation_id=>ok(auth.service.status({session_token:sessionToken,operation_id})).status
  return {pool,store,hostFor,proposal,assertNoEffects,authorityStatus}
}

test('workflow references migrate explicitly and survive a new store instance without retaining payloads',async t=>{
  const f=await fixture(t),p=await f.proposal('synthetic-task-one','synthetic-key-one')
  const inserted=await f.store.insert(p.host,p.input)
  assert.equal(inserted.phase,'proposed')
  assert.equal(inserted.operation_digest,contracts.operationDigest(p.input.operation))
  assert.equal(Object.isFrozen(inserted),true)
  assert.equal(isWorkflowStore(f.store),true)
  assert.equal(isWorkflowStore({...f.store}),false)
  assert.deepEqual(await f.store.insert(p.host,p.input),inserted)
  const reopened=createPostgresWorkflowStore({pool:f.pool})
  assert.deepEqual(await reopened.get(p.host,p.input.operation.operation_id),inserted)
  assert.deepEqual((await reopened.list(p.host,{active:true})).items,[inserted])
  const columns=f.pool.db.prepare('PRAGMA table_info(prime_runtime_workflows)').all().map(row=>row.name)
  assert.deepEqual(columns,['owner_subject','owner_id','task_id','operation_id','operation_digest','action_type','idempotency_key_sha256','record_id','phase','request_id','request_digest','receipt_digest','created_at'])
  assert.equal(f.authorityStatus(p.input.operation.operation_id),'PROPOSED')
  f.assertNoEffects()
})

test('owner attempt admission spans tasks and known-unsent closes the retained proposal',async t=>{
  const f=await fixture(t)
  const one=await f.proposal('synthetic-task-one','synthetic-key-one'),two=await f.proposal('synthetic-task-two','synthetic-key-two')
  await f.store.insert(one.host,one.input);await f.store.insert(two.host,two.input)
  const attempt=()=>f.store.attempt(one.host,one.input.operation.operation_id,contracts.operationDigest(one.input.operation))
  assert.equal((await attempt()).phase,'attempted')
  await assert.rejects(attempt(),refusal('REPLAYED'))
  await assert.rejects(f.store.attempt(two.host,two.input.operation.operation_id,contracts.operationDigest(two.input.operation)),refusal('RECONCILIATION_REQUIRED'))
  assert.equal((await f.store.get(two.host,two.input.operation.operation_id)).phase,'proposed')
  assert.equal((await f.store.mark(one.host,one.input.operation.operation_id,'known_unsent')).phase,'known_unsent')
  await assert.rejects(attempt(),refusal('REPLAYED'))
  assert.deepEqual((await f.store.list(one.host,{active:true})).items,[])
  assert.equal((await f.store.attempt(two.host,two.input.operation.operation_id,contracts.operationDigest(two.input.operation))).phase,'attempted')
  const neverSent=await f.proposal('synthetic-task-one','synthetic-key-three')
  await f.store.insert(neverSent.host,neverSent.input)
  assert.equal((await f.store.mark(neverSent.host,neverSent.input.operation.operation_id,'known_unsent')).phase,'known_unsent')
  assert.equal(f.authorityStatus(one.input.operation.operation_id),'PROPOSED')
  assert.equal(f.authorityStatus(two.input.operation.operation_id),'PROPOSED')
  f.assertNoEffects()
})

test('active references refuse overflow while recent history is bounded and exact lookup stays available',async t=>{
  const f=await fixture(t),references=[]
  for(let index=0;index<3;index++) {
    const p=await f.proposal('synthetic-task-one','synthetic-history-'+index)
    references.push(await f.store.insert(p.host,p.input))
  }
  const host=f.hostFor('synthetic-task-one')
  await assert.rejects(f.store.list(host,{active:true,limit:2}),error=>error.error_code==='UNAVAILABLE'&&error.overflow===true)
  const history=await f.store.list(host,{active:false,limit:2})
  const descending=[...references].sort((a,b)=>b.created_at.localeCompare(a.created_at)||b.operation_id.localeCompare(a.operation_id))
  assert.equal(history.overflow,true)
  assert.deepEqual(history.items,descending.slice(0,2))
  assert.deepEqual(await f.store.get(host,descending[2].operation_id),descending[2])
  assert.deepEqual((await f.store.list(f.hostFor('synthetic-task-two'),{active:false})).items,[])
  f.assertNoEffects()
})
