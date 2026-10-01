// SPDX-License-Identifier: AGPL-3.0-or-later
// Real C verification/stores and D APIs; synthetic P-256 keys and SQLite dialect
// fixture only. The invented host acceptance record below exercises public
// ingress, never qualifies PostgreSQL, UID isolation or a deployed application.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {existsSync,mkdtempSync,readFileSync,realpathSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {createRuntimeBridge,createTrustedTaskRegistry} from '../src/index.mjs'
import {authorityFixture} from './authority-fixture.mjs'
import {FixturePool} from './sql-fixture.mjs'
import {createPostgresWorkflowStore} from '../src/workflow-store.mjs'

const ownerId='synthetic-owner',at='2026-10-01T11:03:00Z'
const extraction={category:'fact',statement:'banana',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}
const task={version:1,task_id:'synthetic-task',owner_id:ownerId,agent_id:'synthetic-agent',conversation_id:'synthetic-conversation',
  status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],max_input_tokens:100,max_output_tokens:100,
  max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}}
const context=role=>({role,request:{route:'negative-fixture'}})
const accepted=result=>{assert.equal(result.ok,true,JSON.stringify(result));return result}
const rejected=(result,code)=>{assert.equal(result.ok,false,JSON.stringify(result));if(code)assert.equal(result.error_code,code,JSON.stringify(result));return result}
const draft=key=>({extraction_json:JSON.stringify(extraction),idempotency_key:key})
async function fixture(t) {
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-public-negative-')),pool=new FixturePool(join(root,'memory.sqlite'))
  t.after(()=>{pool.close();rmSync(root,{recursive:true,force:true})})
  const registry=createTrustedTaskRegistry([{task,provider_and_region:{provider:'local',region:'local'},
    audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']}])
  let memory
  const auth=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:registry.authorizeTask,
    observeTarget:operation=>memory.authorityTargetObservation(operation)})
  const event=Buffer.from(JSON.stringify({type:'turn',text:'Synthetic owner likes banana.',seq:0,at})+'\n')
  const host={privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(event)},events:[event]}
  memory=createPostgresMemory({pool,authority:auth.service,contracts});await memory.migrate()
  const workflowStore=createPostgresWorkflowStore({pool});await workflowStore.migrate()
  const resolveHostContext=({request,session})=>{
    if(request?.route!=='negative-fixture')throw new Error('test-only trusted request association missing')
    return session?{task_id:task.task_id,memory_host:host}:{login_owner_id:ownerId}
  }
  const base={authority:auth.service,memory,workflowStore,taskRegistry:registry,resolveHostContext}
  const bridge=createRuntimeBridge({...base,verifyHostQualification:()=>({
    profile:'prime-separated-runtime-host/v1',environment:'production',accepted:true,app_uid:101,broker_uid:102,
    transport:'authenticated-ipc',owner_enrollment:'qualified',postgres_runtime:'qualified',
    source_commit:'0'.repeat(40),release_digest:'sha256:'+'0'.repeat(64)})})
  const unqualified=createRuntimeBridge(base)
  const call=(method,input,role='owner_control')=>bridge.handlePublic(method,input,context(role))
  async function login() {
    const challenge=accepted(await call('owner.loginChallenge',{owner_id:ownerId,kind:'passkey'}))
    return accepted(await call('owner.loginComplete',{challenge:challenge.challenge,material:auth.assertion(challenge.public_key.challenge)})).session_token
  }
  const evidence=()=>{
    const state=existsSync(auth.config.statePath)?JSON.parse(readFileSync(auth.config.statePath,'utf8')):null
    const count=table=>pool.db.prepare('SELECT count(*) AS n FROM '+table).get().n
    return {operations:Object.keys(state?.broker?.operations??{}).length,consumed:[...(state?.state?.consumedIds??[])],prepared:state?.prepared?.length??0,
      records:count('prime_memory_records'),events:count('prime_memory_events'),effects:count('prime_memory_effects'),chain:count('prime_memory_chain'),
      requests:count('prime_memory_requests'),outbox:count('prime_memory_outbox'),intents:count('prime_memory_intents'),
      controls:count('prime_memory_controls'),tombstones:count('prime_memory_tombstones'),snapshots:count('prime_memory_snapshots')}
  }
  return {auth,memory,pool,bridge,unqualified,call,login,evidence}
}

test('public method grammar exposes no raw capture, tombstone, import, reservation or dispatch path; synthetic SQLite only',async t=>{
  const f=await fixture(t),session_token=await f.login(),before=f.evidence()
  const hidden=['memory.captureRemembered','captureRemembered','memory.captureAuthorizedRemembered',
    'memory.tombstoneRecord','memory.eraseOwnerPayloads','memory.importSnapshot','memory.restoreSnapshot','memory.exportBackup',
    'authority.propose','authority.reserve','authority.claimDispatch','authority.settleMemory','authority.markOutcomeUnknown',
    'owner.reserve','owner.claimDispatch','claimDispatch','reserve','admin.import']
  for(const method of hidden)for(const role of ['owner_control','proposer','read_only'])
    rejected(await f.call(method,{session_token,owner_id:ownerId,owner_subject:f.auth.identity.subject,task_id:task.task_id},role),'INVALID')
  assert.deepEqual(f.evidence(),before,'unknown public methods must reach neither authority effects nor D storage')
  // Empty mounts and source-only/unqualified hosts also remain closed.
  for(const method of ['memory.proposeSave','memory.save','owner.approvalComplete'])
    rejected(await f.unqualified.handlePublic(method,{session_token},context('owner_control')),'UNAVAILABLE')
  assert.deepEqual(f.evidence(),before)
})

test('missing and forged C owner sessions cannot read, propose, approve or save through public ingress',async t=>{
  const f=await fixture(t),before=f.evidence()
  for(const method of ['memory.proposeSave','memory.save','memory.status','memory.cite','memory.recall',
    'owner.approvalChallenge','owner.approvalComplete','owner.declineApproval','owner.status']) {
    rejected(await f.call(method,{}),'UNAUTHORIZED')
    rejected(await f.call(method,{session_token:'0'.repeat(64)}),'UNAUTHORIZED')
  }
  assert.deepEqual(f.evidence(),before)
  // A typed passkey label or valid synthetic signature for another challenge
  // never replaces actual C challenge/origin/assertion verification.
  const challenge=accepted(await f.call('owner.loginChallenge',{owner_id:ownerId,kind:'passkey'}))
  rejected(await f.call('owner.loginComplete',{challenge:challenge.challenge,material:{kind:'passkey',valid:true}}))
  rejected(await f.call('owner.loginComplete',{challenge:challenge.challenge,material:f.auth.assertion('wrong-challenge')}),'UNAUTHORIZED')
  const valid=accepted(await f.call('owner.loginComplete',{challenge:challenge.challenge,material:f.auth.assertion(challenge.public_key.challenge)}))
  assert.match(valid.session_token,/^[a-f0-9]{64}$/)
  assert.deepEqual(f.evidence(),before)
})

test('129 unauthenticated proposals do not consume admission; authenticated proposer has no owner mutation power',async t=>{
  const f=await fixture(t),before=f.evidence()
  for(let index=0;index<129;index++)rejected(await f.call('memory.proposeSave',draft('guest-'+index),'proposer'),'UNAUTHORIZED')
  assert.deepEqual(f.evidence(),before)
  const session_token=await f.login()
  const proposed=accepted(await f.call('memory.proposeSave',{session_token,...draft('authenticated-after-129')},'proposer'))
  const operation=proposed.operation,afterProposal=f.evidence()
  assert.equal(afterProposal.operations,1);assert.equal(afterProposal.prepared,0)
  assert.deepEqual(afterProposal.consumed,[]);assert.equal(afterProposal.records,0)
  assert.equal(accepted(await f.call('owner.status',{session_token,operation_id:operation.operation_id},'proposer')).status,'PROPOSED')
  for(const role of ['proposer','read_only'])for(const [method,input] of [
    ['owner.loginChallenge',{owner_id:ownerId,kind:'passkey'}],['owner.loginComplete',{}],
    ['owner.approvalChallenge',{session_token,operation}],['owner.approvalComplete',{session_token,operation,proof:{}}],
    ['owner.declineApproval',{session_token,operation_id:operation.operation_id}],['memory.save',{session_token,operation}],
  ])rejected(await f.call(method,input,role),'UNAUTHORIZED')
  rejected(await f.call('memory.proposeSave',{session_token,...draft('read-only-denied')},'read_only'),'UNAUTHORIZED')
  assert.equal(accepted(await f.call('owner.status',{session_token,operation_id:operation.operation_id})).status,'PROPOSED')
  assert.deepEqual(f.evidence(),afterProposal)
})

test('guest owner/task/provider/state or raw record bytes cannot enter the trusted public proposal binding',async t=>{
  const f=await fixture(t),session_token=await f.login(),before=f.evidence()
  const base={session_token,...draft('smuggled-host')}
  for(const [field,value] of Object.entries({owner_id:'guest',owner_subject:'guest',task_id:'guest',agent_id:'guest',
    provider_and_region:{provider:'guest',region:'guest'},expected_state_version:'guest',state:'guest',
    canonical_bytes:'{"statement":"unsigned"}',record:{statement:'unsigned'},operation:{action_type:'memory.save'}}))
    rejected(await f.call('memory.proposeSave',{...base,[field]:value},'proposer'),'INVALID')
  for(const field of ['owner_id','owner_subject','task_id','provider_and_region','expected_state_version','canonical_bytes'])
    rejected(await f.call('memory.proposeSave',{...base,extraction_json:JSON.stringify({...extraction,[field]:'guest'})},'proposer'))
  assert.deepEqual(f.evidence(),before)
})
