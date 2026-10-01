// SPDX-License-Identifier: AGPL-3.0-or-later
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtempSync,rmSync,realpathSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import * as contracts from '../../contracts/src/runtime.mjs'
import {createPostgresMemory} from '../../memory/src/index.mjs'
import {sha256} from '../../memory/src/codecs.mjs'
import {createPrimeTransport} from '../../ui/adapters/transport.mjs'
import {createRuntimeBridge,createTrustedTaskRegistry} from '../src/index.mjs'
import {createPostgresWorkflowStore} from '../src/workflow-store.mjs'
import {createUiAdapters} from '../src/ui-adapter.mjs'
import {createLocalhostPilotGuard} from '../src/pilot-origin.mjs'
import {authorityFixture} from './authority-fixture.mjs'
import {FixturePool} from './sql-fixture.mjs'

const at='2026-10-01T11:03:00Z',ownerId='synthetic-owner'
const task={version:1,task_id:'synthetic-task',owner_id:ownerId,agent_id:'synthetic-agent',conversation_id:'synthetic-conversation',status:'running',created_at:at,route_id:null,allowed_data_classes:['synthetic'],max_input_tokens:100,max_output_tokens:100,max_requests:5,task_spend_ceiling:{currency:'USD',amount:'0'}}
const registry=()=>createTrustedTaskRegistry([{task,provider_and_region:{provider:'local',region:'local'},audience:'aukora-prime.memory',policy_version:'synthetic-policy',data_scope:['synthetic']}])
const ok=result=>{assert.equal(result.ok,true,JSON.stringify(result));return result}
const refused=result=>{assert.equal(result.ok,false,JSON.stringify(result));return result}
const input={category:'fact',statement:'  banana <tag>&\n\t🍌  ',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}

test('real C passkey + D save/index/cite/restart via existing injected B transport; SQLite fixture is not PostgreSQL acceptance',async()=>{
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-bridge-cd-')),taskRegistry=registry()
  let pool=new FixturePool(join(root,'memory.sqlite')),memory,workflowStore
  const auth=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:taskRegistry.authorizeTask,observeTarget:op=>memory.authorityTargetObservation(op)})
  let authority=auth.service
  const event=Buffer.from(JSON.stringify({type:'turn',text:'Synthetic owner likes banana.',seq:0,at})+'\n')
  const host={privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(event)},events:[event]}
  const resolveHostContext=({request,session})=>{
    if(request?.route!=='trusted-test')throw new Error('synthetic trusted request association missing')
    return session?{task_id:task.task_id,memory_host:host}:{login_owner_id:ownerId}
  }
  const makeMemory=()=>createPostgresMemory({pool,authority,contracts})
  const makeBridge=()=>createRuntimeBridge({authority,memory,workflowStore,taskRegistry,resolveHostContext})
  const trusted={request:{route:'trusted-test'},role:'owner_control'}
  let bridge
  try {
    memory=makeMemory();await memory.migrate()
    workflowStore=createPostgresWorkflowStore({pool});await workflowStore.migrate();bridge=makeBridge()
    assert.equal((await bridge.capability()).state,'unqualified')
    refused(await bridge.handlePublic('memory.proposeSave',{}))
    const booleanGate=createRuntimeBridge({authority,memory,workflowStore,taskRegistry,resolveHostContext,verifyHostQualification:()=>true})
    assert.equal((await booleanGate.capability()).available,false)
    refused(await bridge.handleTrusted('claimDispatch',{},trusted))
    refused(await bridge.handleTrusted('owner.loginChallenge',{owner_id:'guest-owner',kind:'passkey'},trusted))
    refused(await bridge.handleTrusted('owner.loginChallenge',{owner_id:ownerId,kind:'owner_key'},trusted))
    refused(await bridge.handleTrusted('owner.loginChallenge',{owner_id:ownerId,kind:'passkey'}))
    refused(await bridge.handleTrusted('owner.loginChallenge',{owner_id:ownerId,kind:'passkey'},{...trusted,role:'proposer'}))
    const pilot=createLocalhostPilotGuard({profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'})
    assert.equal(pilot({host:'localhost:18731',origin:'http://localhost:18731'}).rp_id,'localhost')
    for(const wrong of [{host:'127.0.0.1:18731',origin:'http://127.0.0.1:18731'},{host:'localhost:18731',origin:'http://localhost:18732'},{host:'localhost.:18731',origin:'http://localhost:18731'}])assert.throws(()=>pilot(wrong),/PILOT_HOST_ORIGIN_REFUSED/)
    let sessionToken
    const adapters=createUiAdapters({call:async(method,value)=>{const result=await bridge.handleTrusted(method,value,trusted);if(method==='owner.loginComplete'&&result.ok)sessionToken=result.session_token;return result}})
    let signerCalls=0
    const ui=createPrimeTransport({authority:adapters.authority,contracts,passkeySigner:({public_key})=>{signerCalls++;return auth.assertion(public_key.challenge)}})
    await ui.login({owner_id:ownerId})
    const draft={extraction_json:JSON.stringify(input),idempotency_key:'synthetic-save-one'}
    const proposed=ok(await adapters.memory.proposeSave(draft)),operation=proposed.operation
    assert.equal(operation.owner_id,ownerId);assert.equal(operation.target_identity.owner_subject,auth.identity.subject)
    assert.equal(taskRegistry.authorizeTask({...operation,provider_and_region:{provider:'guest',region:'elsewhere'}}).authenticated,false)
    // TEST ONLY verifier record: exercises ingress snapshot around an async
    // acceptance call. It is no evidence of these invented UIDs or deployment.
    const callInput={session_token:sessionToken,operation_id:operation.operation_id},callContext=structuredClone(trusted)
    const ingress=createRuntimeBridge({authority,memory,workflowStore,taskRegistry,resolveHostContext,verifyHostQualification:async()=>{
      await Promise.resolve();callInput.session_token='0'.repeat(64);callContext.request.route='guest';callContext.role='read_only'
      return {profile:'prime-separated-runtime-host/v1',environment:'production',accepted:true,app_uid:101,broker_uid:102,transport:'authenticated-ipc',owner_enrollment:'qualified',postgres_runtime:'qualified',source_commit:'0'.repeat(40),release_digest:'sha256:'+'0'.repeat(64)}
    }})
    assert.equal(ok(await ingress.handlePublic('owner.status',callInput,callContext)).status,'PROPOSED')
    assert.deepEqual(proposed.memory_capture,{statement:input.statement,attributed_to:'owner'})
    assert.equal(operation.canonical_parameters.statement,input.statement)
    assert.equal(operation.canonical_parameters.attributed_to,'owner')
    await assert.rejects(ui.prepareApproval(operation),error=>error.code==='TARGET_MISMATCH')
    await assert.rejects(ui.prepareApproval(operation,{memoryCapture:{statement:'changed display',attributed_to:'owner'}}),error=>error.code==='TARGET_MISMATCH')
    await assert.rejects(ui.prepareApproval(operation,{memoryCapture:{statement:input.statement,attributed_to:'agent'}}),error=>error.code==='TARGET_MISMATCH')
    assert.equal(signerCalls,1,'missing/altered review draft must never reach the signer after login')
    const review=await ui.prepareApproval(operation,{memoryCapture:proposed.memory_capture}),approved=await ui.approve(review)
    assert.equal(signerCalls,2)
    assert.deepEqual({statement:review.memory_review.statement,attributed_to:review.memory_review.attributed_to},proposed.memory_capture)
    assert.notEqual(approved.approval_proof.nonce,operation.nonce)
    const modified=await adapters.memory.save({...draft,operation:{...operation,canonical_parameters:{...operation.canonical_parameters,capture_sha256:'f'.repeat(64)}},approval_proof:approved.approval_proof})
    refused(modified)
    refused(await adapters.memory.save({...draft,extraction_json:JSON.stringify({...input,statement:'changed'}),operation,approval_proof:approved.approval_proof}))
    // Bypass the browser adapter to exercise real D's under-lock literal checks.
    for(const changed of [{statement:'changed displayed text'},{attributed_to:'agent'}]) {
      refused(await bridge.handleTrusted('memory.save',{session_token:sessionToken,...draft,
        operation:{...operation,canonical_parameters:{...operation.canonical_parameters,...changed}},approval_proof:approved.approval_proof},trusted))
      assert.equal(ok(authority.status({session_token:sessionToken,operation_id:operation.operation_id})).status,'APPROVED')
      assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,0)
    }
    const saved=ok(await adapters.memory.save({...draft,operation,approval_proof:approved.approval_proof}))
    const exactSaved=JSON.parse(saved.record.canonical_bytes)
    assert.equal(exactSaved.statement,review.memory_review.statement)
    assert.equal(exactSaved.attributedTo,review.memory_review.attributed_to)
    assert.equal(saved.record.storage_status,'saved');assert.equal(saved.record.index_status,'pending')
    assert.equal(saved.authority_settlement,'completed');assert.equal(saved.reconciliation_required,false)
    const statusInput={record_id:saved.record.record_id,revision:null}
    const pending=ok(await adapters.memory.status(statusInput));assert.equal(pending.saved,true);assert.equal(pending.indexed,false);assert.equal(pending.searchable,false)
    const citation=ok(await adapters.memory.cite({...statusInput,retained_head:null})).citation
    assert.equal(citation.verdict,'VERIFIED');assert.equal(citation.grants_authority,false)
    const retainedHead=citation.verified_head
    const replay=ok(await adapters.memory.save({...draft,operation,approval_proof:approved.approval_proof}))
    assert.equal(replay.record.record_id,saved.record.record_id)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_effects').get().n,1)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,1)
    // Cold reopen the real C file stores and D fixture database; retain UI token only in memory.
    pool.close();pool=new FixturePool(join(root,'memory.sqlite'));authority=auth.restart();memory=makeMemory();await memory.migrate()
    workflowStore=createPostgresWorkflowStore({pool});await workflowStore.migrate();bridge=makeBridge()
    const reopened=ok(await adapters.memory.status(statusInput));assert.equal(reopened.record.canonical_bytes,saved.record.canonical_bytes)
    assert.equal(ok(await adapters.memory.cite({...statusInput,retained_head:retainedHead})).citation.verdict,'VERIFIED')
    pool.failIndex=true
    const hostBound={...host,owner_subject:auth.identity.subject,owner_id:ownerId,task_id:task.task_id}
    assert.equal((await memory.drainOutbox(hostBound)).failed,1)
    assert.equal(ok(await adapters.memory.status(statusInput)).saved,true)
    pool.failIndex=false;assert.equal((await memory.drainOutbox(hostBound)).indexed,1)
    assert.equal(ok(await adapters.memory.status(statusInput)).searchable,true)
    assert.equal(ok(await adapters.memory.recall({query:'banana',limit:10})).records.length,1)
    // Injected host/source event change cannot reuse an approval to save different bytes.
    const badSource=Buffer.from(JSON.stringify({type:'turn',text:'Changed source',seq:0,at})+'\n')
    host.events=[badSource];host.source={...host.source,sha256:sha256(badSource)}
    refused(await adapters.memory.save({...draft,operation,approval_proof:approved.approval_proof}))
    host.events=[event];host.source={...host.source,sha256:sha256(event)}
    // The grammar refuses owner/task/provider/state smuggling before any service effect.
    refused(await adapters.memory.proposeSave({...draft,owner_id:'guest',task_id:'guest',provider:'guest',expected_state_version:'guest'}))
    refused(await bridge.handleTrusted('memory.proposeSave',{session_token:'0'.repeat(64),...draft},trusted))
    const guestRequest=createUiAdapters({call:(method,value)=>bridge.handleTrusted(method,value,{request:{route:'guest'},role:'owner_control'})})
    refused(await guestRequest.authority.loginChallenge({owner_id:ownerId,kind:'passkey'}))
    // Ordinary create/source tests never qualify the deployed application.
    assert.equal((await bridge.capability()).public_routes,'unavailable')
  } finally {pool.close();rmSync(root,{recursive:true,force:true})}
})

test('real C/D post-dispatch interruption stays consumed and reconciles receipts without saving twice',async()=>{
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-bridge-unknown-')),taskRegistry=registry()
  const pool=new FixturePool(join(root,'memory.sqlite'));let memory
  const auth=authorityFixture({root,audience:'aukora-prime.memory',authorizeTask:taskRegistry.authorizeTask,observeTarget:op=>memory.authorityTargetObservation(op)})
  const event=Buffer.from(JSON.stringify({type:'turn',text:'Synthetic owner likes banana.',seq:0,at})+'\n')
  const host={privacy:'local',scope:'owner',attributedTo:'owner',source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(event)},events:[event]}
  try {
    memory=createPostgresMemory({pool,authority:auth.service,contracts});await memory.migrate()
    const workflowStore=createPostgresWorkflowStore({pool});await workflowStore.migrate()
    const bridge=createRuntimeBridge({authority:auth.service,memory,workflowStore,taskRegistry,resolveHostContext:({session})=>session?{task_id:task.task_id,memory_host:host}:{login_owner_id:ownerId}})
    let sessionToken
    const adapters=createUiAdapters({call:async(method,value)=>{const result=await bridge.handleTrusted(method,value,{role:'owner_control'});if(method==='owner.loginComplete'&&result.ok)sessionToken=result.session_token;return result}})
    const ui=createPrimeTransport({authority:adapters.authority,contracts,passkeySigner:({public_key})=>auth.assertion(public_key.challenge)})
    await ui.login({owner_id:ownerId})
    const approve=async key=>{const draft={extraction_json:JSON.stringify(input),idempotency_key:key};const proposed=ok(await adapters.memory.proposeSave(draft)),operation=proposed.operation;const proof=(await ui.approve(await ui.prepareApproval(operation,{memoryCapture:proposed.memory_capture}))).approval_proof;return {...draft,operation,approval_proof:proof}}
    const first=await approve('commit-reply-lost');pool.commitAfterEffect=true
    const unknown=refused(await adapters.memory.save(first));assert.equal(unknown.error_code,'OUTCOME_UNKNOWN');assert.equal(unknown.reconciliation_required,true)
    const state=ok(auth.service.status({session_token:sessionToken,operation_id:first.operation.operation_id}));assert.equal(state.status,'OUTCOME_UNKNOWN')
    const bound={...host,owner_id:ownerId,owner_subject:auth.identity.subject,task_id:task.task_id}
    const reconciled=await memory.reconcileEffect(bound,first.operation.operation_id);assert.equal(reconciled.authority_settlement,'completed')
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,1)
    assert.equal(ok(auth.service.status({session_token:sessionToken,operation_id:first.operation.operation_id})).status,'COMPLETED')
    const second=await approve('effect-write-failed');pool.failAfterDispatch=true
    assert.equal(refused(await adapters.memory.save(second)).error_code,'OUTCOME_UNKNOWN')
    pool.failAfterDispatch=false
    const unresolved=await memory.reconcileEffect(bound,second.operation.operation_id)
    assert.equal(unresolved.status,'unresolved');assert.equal(unresolved.automatic_retry,false)
    refused(await adapters.memory.save(second))
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,1)
    assert.equal(ok(auth.service.status({session_token:sessionToken,operation_id:second.operation.operation_id})).status,'OUTCOME_UNKNOWN')
  } finally {pool.close();rmSync(root,{recursive:true,force:true})}
})
