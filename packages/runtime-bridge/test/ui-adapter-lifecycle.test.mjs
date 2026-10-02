// SPDX-License-Identifier: AGPL-3.0-or-later
// Test ONLY: real C authentication/admission and D APIs, synthetic P-256 keys,
// SQLite dialect fixture. Delivery gates hold real replies without replacing
// auth, storage or effects. This proves neither PostgreSQL nor UID isolation.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtempSync,readFileSync,realpathSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {createRuntimeBridge,createTrustedTaskRegistry} from '../src/index.mjs'
import {createPostgresWorkflowStore} from '../src/workflow-store.mjs'
import {createUiAdapters} from '../src/ui-adapter.mjs'
import {authorityFixture} from './authority-fixture.mjs'
import {FixturePool} from './sql-fixture.mjs'

const ownerId='synthetic-owner',at='2026-10-01T11:03:00Z'
const extraction={category:'fact',statement:'banana',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}
const draft=key=>({extraction_json:JSON.stringify(extraction),idempotency_key:key})
const ok=result=>{assert.equal(result.ok,true,JSON.stringify(result));return result}
const observe=promise=>Promise.resolve(promise).then(value=>({value}),error=>({error}))
function refused(outcome) {
  if(outcome.error)assert.match(outcome.error.message,/UNAUTHORIZED|UI_SESSION|login required|session changed/i)
  else assert.equal(outcome.value?.ok,false,JSON.stringify(outcome.value))
}
async function expectRefusal(action){refused(await observe(Promise.resolve().then(action)))}
function deniedSession(authority,session_token){
  const result=authority.authenticateSession({session_token})
  assert.equal(result.ok,false);assert.equal(result.error_code,'UNAUTHORIZED')
}

function deliveryGate() {
  const entries=[],waiters=[]
  let released=false
  return {
    entries,
    hold(result,input) {
      if(released)return Promise.resolve(result)
      return new Promise(resolve=>{
        entries.push({result,input,resolve})
        for(let index=waiters.length-1;index>=0;index--)if(entries.length>=waiters[index].count){
          const [waiter]=waiters.splice(index,1);clearTimeout(waiter.timer);waiter.resolve()
        }
      })
    },
    entered(count) {
      if(entries.length>=count)return Promise.resolve()
      return new Promise((resolve,reject)=>{
        const waiter={count,resolve,timer:setTimeout(()=>reject(new Error('real reply gate did not receive '+count+' replies')),5000)}
        waiters.push(waiter)
      })
    },
    release() {
      released=true;for(const entry of entries)entry.resolve(entry.result)
      for(const waiter of waiters){clearTimeout(waiter.timer);waiter.resolve()}
      waiters.length=0
    },
  }
}

async function fixture(t) {
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-ui-lifecycle-')),pool=new FixturePool(join(root,'memory.sqlite'))
  const gates=new Map(),allGates=[],calls=[],task={version:1,task_id:'synthetic-task',owner_id:ownerId,agent_id:'synthetic-agent',
    conversation_id:'synthetic-conversation',status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],
    max_input_tokens:100,max_output_tokens:100,max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}}
  let queue=Promise.resolve(),memory
  t.after(async()=>{for(const gate of allGates)gate.release();await queue;pool.close();rmSync(root,{recursive:true,force:true})})
  const taskRegistry=createTrustedTaskRegistry([{task,provider_and_region:{provider:'local',region:'local'},
    audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']}])
  const auth=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:taskRegistry.authorizeTask,
    observeTarget:operation=>memory.authorityTargetObservation(operation)})
  const event=Buffer.from(JSON.stringify({type:'turn',text:'Synthetic owner likes banana.',seq:0,at})+'\n')
  const host={privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(event)},events:[event]}
  memory=createPostgresMemory({pool,authority:auth.service,contracts});await memory.migrate()
  const workflowStore=createPostgresWorkflowStore({pool});await workflowStore.migrate()
  const bridge=createRuntimeBridge({authority:auth.service,memory,workflowStore,taskRegistry,
    resolveHostContext:({request,session})=>{
      if(request?.route!=='lifecycle-fixture')throw new Error('synthetic trusted request association missing')
      return session?{task_id:task.task_id,memory_host:host}:{login_owner_id:ownerId}
    }})
  const adapters=createUiAdapters({call:async(method,input)=>{
    calls.push({method,input})
    const gate=gates.get(method)
    // FixturePool owns one SQLite connection, so execute real bridge requests
    // serially. Reply delivery is outside that queue: all adapter calls remain
    // pending together, without pretending to test PostgreSQL concurrency.
    const work=queue.then(()=>bridge.handleTrusted(method,input,{role:'owner_control',request:{route:'lifecycle-fixture'}}))
    queue=work.then(()=>undefined,()=>undefined)
    const result=await work
    return gate?gate.hold(result,input):result
  }})
  const gate=method=>{const value=deliveryGate();gates.set(method,value);allGates.push(value);return value}
  const ungate=method=>gates.delete(method)
  const unhold=(method,value)=>{gates.delete(method);value.release()}
  const count=method=>calls.filter(call=>call.method===method).length
  const state=()=>JSON.parse(readFileSync(auth.config.statePath,'utf8'))
  const operations=()=>Object.values(state().broker.operations)
  const noMemoryEffects=()=>{
    for(const table of ['prime_memory_records','prime_memory_events','prime_memory_effects','prime_memory_intents'])
      assert.equal(pool.db.prepare('SELECT count(*) AS n FROM '+table).get().n,0,table)
  }
  const challenge=()=>adapters.authority.loginChallenge({owner_id:ownerId,kind:'passkey'}).then(ok)
  const complete=answer=>adapters.authority.loginComplete({challenge:answer.challenge,material:auth.assertion(answer.public_key.challenge)})
  const login=async()=>ok(await complete(await challenge()))
  return {auth,adapters,calls,gate,ungate,unhold,count,operations,noMemoryEffects,challenge,complete,login}
}

test('a real successful login reply arriving after logout cannot restore the adapter token',async t=>{
  const f=await fixture(t),challenge=await f.challenge(),gate=f.gate('owner.loginComplete')
  const pending=observe(f.complete(challenge));await gate.entered(1)
  const completed=ok(gate.entries[0].result)
  ok(f.auth.service.authenticateSession({session_token:completed.session_token}))
  await f.adapters.logout();f.unhold('owner.loginComplete',gate)
  refused(await pending)
  await expectRefusal(()=>f.adapters.memory.proposeSave(draft('after-logout')))
  assert.equal(f.count('memory.proposeSave'),0);assert.equal(f.operations().length,0);f.noMemoryEffects()
})

test('an older real login reply cannot replace the token from a newer completed login',async t=>{
  const f=await fixture(t),challenge=await f.challenge(),gate=f.gate('owner.loginComplete')
  const pending=observe(f.complete(challenge));await gate.entered(1)
  const old=ok(gate.entries[0].result)
  // Keep the old reply held, but let the new login use the actual C service.
  f.ungate('owner.loginComplete')
  const current=await f.login();assert.notEqual(current.session_token,old.session_token)
  gate.release();refused(await pending)
  ok(await f.adapters.memory.proposeSave(draft('new-session-only')))
  const dispatched=f.calls.filter(call=>call.method==='memory.proposeSave')
  assert.equal(dispatched.length,1);assert.equal(dispatched[0].input.session_token,current.session_token)
  assert.equal(f.operations().length,1);f.noMemoryEffects()
})

for(const nextLogin of [false,true]) {
  test('an old decline token cannot mutate a real proposal after '+(nextLogin?'a new login':'logout'),async t=>{
    const f=await fixture(t),session=await f.login(),proposed=ok(await f.adapters.memory.proposeSave(draft('stale-decline')))
    assert.equal(ok(await f.adapters.logout()).status,'LOGGED_OUT')
    deniedSession(f.auth.service,session.session_token)
    if(nextLogin)await f.login()
    const persisted=structuredClone(f.operations())
    await expectRefusal(()=>f.adapters.authority.declineApproval({session_token:session.session_token,operation_id:proposed.operation.operation_id}))
    assert.equal(f.count('owner.declineApproval'),0)
    deniedSession(f.auth.service,session.session_token)
    assert.deepEqual(f.operations(),persisted,'the rejected old decline changes no actual persisted C operation')
    assert.equal(f.operations().length,1);f.noMemoryEffects()
  })

  test('a delayed real proposal cannot retain a capture after '+(nextLogin?'a new login':'logout'),async t=>{
    const f=await fixture(t),session=await f.login(),gate=f.gate('memory.proposeSave'),input=draft('stale-proposal')
    const pending=observe(f.adapters.memory.proposeSave(input));await gate.entered(1)
    const proposed=ok(gate.entries[0].result)
    assert.equal(ok(await f.adapters.logout()).status,'LOGGED_OUT')
    deniedSession(f.auth.service,session.session_token)
    const current=nextLogin?await f.login():null,persisted=structuredClone(f.operations())
    f.unhold('memory.proposeSave',gate);refused(await pending)
    const refusedReview=await f.adapters.authority.approvalChallenge({session_token:current?.session_token??session.session_token,operation:proposed.operation})
    assert.equal(refusedReview.ok,false)
    assert.equal(refusedReview.reason,nextLogin?'UI_EXACT_CAPTURE_REQUIRED':'UI_SESSION_CHANGED')
    assert.equal(f.count('owner.approvalChallenge'),0);assert.equal(f.count('memory.save'),0)
    assert.deepEqual(f.operations(),persisted,'late proposal delivery changes no actual persisted C operation')
    assert.equal(f.operations().length,1);f.noMemoryEffects()
  })

  test('a delayed real review cannot be completed after '+(nextLogin?'a new login':'logout'),async t=>{
    const f=await fixture(t),session=await f.login(),proposed=ok(await f.adapters.memory.proposeSave(draft('stale-review')))
    const gate=f.gate('owner.approvalChallenge')
    const pending=observe(f.adapters.authority.approvalChallenge({session_token:session.session_token,operation:proposed.operation}))
    await gate.entered(1);const review=ok(gate.entries[0].result)
    assert.equal(ok(await f.adapters.logout()).status,'LOGGED_OUT')
    deniedSession(f.auth.service,session.session_token)
    if(nextLogin)await f.login()
    const persisted=structuredClone(f.operations())
    const proof={...review.proof_template,material:f.auth.assertion(review.public_key.challenge)}
    contracts.validateContract('ApprovalProof',proof)
    f.unhold('owner.approvalChallenge',gate);refused(await pending)
    await expectRefusal(()=>f.adapters.authority.approvalComplete({session_token:session.session_token,proof}))
    assert.equal(f.count('owner.approvalComplete'),0)
    assert.deepEqual(f.operations(),persisted,'the rejected old review changes no actual persisted C operation')
    f.noMemoryEffects()
  })
}

test('16 pending real proposal replies reserve adapter capacity and a decline releases a slot',async t=>{
  const f=await fixture(t),session=await f.login(),gate=f.gate('memory.proposeSave')
  const pending=Promise.allSettled(Array.from({length:40},(_,index)=>f.adapters.memory.proposeSave(draft('parallel-'+index))))
  await gate.entered(16)
  assert.equal(f.count('memory.proposeSave'),16,'only reserved calls reach actual C/D')
  for(const entry of gate.entries)ok(entry.result)
  assert.equal(f.operations().length,16);f.noMemoryEffects()
  f.unhold('memory.proposeSave',gate)
  const replies=await pending
  assert.equal(replies.filter(reply=>reply.status==='fulfilled'&&reply.value.ok===true).length,16)
  for(const reply of replies.filter(reply=>reply.status!=='fulfilled'||reply.value.ok!==true)) {
    assert.equal(reply.status,'fulfilled');assert.equal(reply.value.error_code,'UNAVAILABLE');assert.match(reply.value.reason,/UI_CAPTURE_QUOTA/)
  }
  const denied=await f.adapters.memory.proposeSave(draft('at-capacity'))
  assert.equal(denied.ok,false);assert.equal(f.count('memory.proposeSave'),16)
  const first=gate.entries[0].result.operation
  ok(await f.adapters.authority.declineApproval({session_token:session.session_token,operation_id:first.operation_id}))
  assert.equal(ok(f.auth.service.status({session_token:session.session_token,operation_id:first.operation_id})).status,'DENIED')
  const fresh=ok(await f.adapters.memory.proposeSave(draft('released-capacity')))
  assert.equal(f.count('memory.proposeSave'),17)
  assert.equal(ok(f.auth.service.status({session_token:session.session_token,operation_id:fresh.operation.operation_id})).status,'PROPOSED')
  f.noMemoryEffects()
})

test('16 pending real reviews of one live proposal reserve capacity and delivery releases their reservations',async t=>{
  const f=await fixture(t),session=await f.login()
  const proposal=ok(await f.adapters.memory.proposeSave(draft('review-live-proposal'))).operation
  const gate=f.gate('owner.approvalChallenge')
  const input={session_token:session.session_token,operation:proposal}
  const pending=Promise.allSettled(Array.from({length:40},()=>f.adapters.authority.approvalChallenge(input)))
  await gate.entered(16)
  assert.equal(f.count('owner.approvalChallenge'),16,'only reserved calls create actual C challenges')
  for(const entry of gate.entries)assert.deepEqual(ok(entry.result).operation,proposal)
  assert.equal(f.operations().length,1);f.noMemoryEffects()
  f.unhold('owner.approvalChallenge',gate)
  const replies=await pending
  assert.equal(replies.filter(reply=>reply.status==='fulfilled'&&reply.value.ok===true).length,16)
  const denied=replies.filter(reply=>reply.status!=='fulfilled'||reply.value.ok!==true)
  assert.equal(denied.length,24)
  for(const reply of denied) {
    assert.equal(reply.status,'fulfilled');assert.equal(reply.value.error_code,'UNAVAILABLE');assert.equal(reply.value.reason,'UI_REVIEW_QUOTA')
  }
  assert.deepEqual(ok(await f.adapters.authority.approvalChallenge(input)).operation,proposal)
  assert.equal(f.count('owner.approvalChallenge'),17,'completed delivery releases the pending reservations')
  assert.equal(f.operations().length,1);f.noMemoryEffects()
})
