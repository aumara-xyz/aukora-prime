// SPDX-License-Identifier: AGPL-3.0-or-later
// TEST ONLY: bounded Bridge contract doubles, no PostgreSQL/C/D service setup.
// These refusal checks do not establish retained publication or authentication.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {canonicalJSON as donorJSON} from '../../memory/genesis/plugins/aukora-kira/lib/record.mjs'
import {createTrustedTaskRegistry} from '../src/registry.mjs'
import {createRetainedWorkflowStore} from '../src/retained-workflow-store.mjs'
import {createRetainedRecovery} from '../src/retained-recovery.mjs'
import {createRetainedRuntimeBridge,createRuntimeBridge} from '../src/index.mjs'
import {closureAttemptId,progressDigest,workflowDigest,normalTransitionDigest,journalTransitionDigest,REFERENCE_FIELDS} from '../src/closure-v2.mjs'
import {validateRetainedPendingMarker,retainedUnknown,retainedUnknownReference} from '../src/retained-pending.mjs'

const h='1'.repeat(64),digest='sha256:'+h
const host={owner_id:'synthetic-owner',owner_subject:'aukora:1:'+h,task_id:'task-one',authorization_epoch:0}
const profile={version:2,kind:'prime-private-unsent-closure/v2',expected_authority_store_id:'2'.repeat(64),
  expected_memory_store_id:'3'.repeat(64),retention_profile:'required-retained/v2'}
const checkpoint={checkpoint_sha256:'4'.repeat(64),control_sha256:'5'.repeat(64),authorization_epoch:0}
const registry=createTrustedTaskRegistry(['task-one','task-two'].map(task_id=>({task:{version:1,task_id,owner_id:host.owner_id,
  agent_id:'synthetic-agent',conversation_id:'synthetic-conversation',status:'running',created_at:'2026-10-01T11:03:00Z',route_id:null,
  allowed_data_classes:['synthetic'],max_input_tokens:100,max_output_tokens:100,max_requests:16,
  task_spend_ceiling:{currency:'USD',amount:'0'}},provider_and_region:{provider:'local',region:'local'},audience:'aukora-prime.memory',
  policy_version:'synthetic-policy',data_scope:['synthetic']})))
const row=(operation_id,task_id=host.task_id,phase='proposed')=>({owner_subject:host.owner_subject,owner_id:host.owner_id,task_id,
  operation_id,operation_digest:digest,action_type:'memory.save',idempotency_key_sha256:h,record_id:null,phase,
  request_id:null,request_digest:null,receipt_digest:null,created_at:'2026-10-01T11:03:00.000Z'})
function fixture(initial=[]) {
  let value={workflow_references:initial,closure_progress:[],checkpoint},mutations=0,queries=0
  const memory={async readRetainedWorkflowJournal(h,input){assert.deepEqual(input,{reference:null});assert.equal(h.owner_id,host.owner_id);queries++;return value},
    async withRetainedWorkflowMutation(){mutations++;throw Error('TEST_DOUBLE_HAS_NO_RETENTION')},
    async withRetainedJournalTransition(){mutations++;throw Error('TEST_DOUBLE_HAS_NO_RETENTION')}}
  const store=createRetainedWorkflowStore({memory,closureProfile:profile,taskRegistry:registry})
  return {memory,store,set:v=>{value=v},stats:()=>({mutations,queries})}
}

test('retained factory has no absent-participant, downgrade or legacy qualification fallback',async()=>{
  assert.throws(()=>createRetainedWorkflowStore({closureProfile:profile,taskRegistry:registry}),/PARTICIPANT_UNMOUNTED/)
  const f=fixture(),names=['authenticateSession','logoutSession','propose','loginChallenge','loginComplete','approvalChallenge','approvalComplete',
    'declineApproval','status','reserve','claimDispatch','settleMemory','markOutcomeUnknown','closeUnconsumedOperation','readUnconsumedClosure']
  const authority=Object.fromEntries(names.map(n=>[n,()=>{throw Error('NO_SERVICE_CALL_EXPECTED')}]))
  for(const n of ['prepareCaptureBinding','captureAuthorizedRemembered','withAuthorityTargetObservation','status','cite','recall',
    'prepareRecordMutationBinding','forgetRecord','reconcileEffect','closeUnsentOperation','readUnsentClosure'])f.memory[n]=()=>{throw Error('NO_SERVICE_CALL_EXPECTED')}
  const bridge=createRetainedRuntimeBridge({authority,memory:f.memory,closureProfile:profile,taskRegistry:registry,
    resolveHostContext:()=>{throw Error('NO_CONTEXT_CALL_EXPECTED')}})
  assert.equal((await bridge.capability()).available,false)
  assert.equal((await bridge.capability()).state,'unqualified')
  assert.equal((await bridge.handlePublic('memory.save',{},{})).error_code,'UNAVAILABLE')
  assert.throws(()=>createRuntimeBridge({workflowStore:f.store,knownUnsentProfile:{version:1,environment:'source-only',retention:'non-retained'}}),/DOWNGRADE_REFUSED/)
  let qualificationCalls=0
  const legacyRecord={profile:'prime-separated-runtime-host/v1',environment:'production',accepted:true,app_uid:1,broker_uid:2,
    transport:'authenticated-ipc',owner_enrollment:'qualified',postgres_runtime:'qualified',source_commit:'a'.repeat(40),release_digest:digest}
  const legacyQualifier=createRuntimeBridge({authority,memory:f.memory,workflowStore:f.store,taskRegistry:registry,
    resolveHostContext:()=>{throw Error('NO_CONTEXT_CALL_EXPECTED')},verifyHostQualification:()=>{qualificationCalls++;return legacyRecord}})
  assert.equal((await legacyQualifier.capability()).available,false);assert.equal(qualificationCalls,0)
  assert.deepEqual(f.stats(),{mutations:0,queries:0})
})

test('owner census discovers all registered tasks and refuses partial or alien metadata',async()=>{
  const f=fixture([row('one'),row('two','task-two')])
  assert.equal((await f.store.admissionCandidates(host)).items.length,2)
  assert.equal((await f.store.list(host,{active:true})).items.length,1)
  f.set({workflow_references:[],closure_progress:[],checkpoint})
  assert.deepEqual((await f.store.ownerCensus(host)).workflow_references,[])
  for(const bad of [{workflow_references:[],closure_progress:[],checkpoint:null},
    {workflow_references:[{...row('other'),owner_id:'other'}],closure_progress:[],checkpoint},
    {workflow_references:[row('z'),row('a')],closure_progress:[],checkpoint},
    {workflow_references:[row('known',host.task_id,'known_unsent')],closure_progress:[],checkpoint},
    {workflow_references:[],closure_progress:[],checkpoint,overflow:false}]) {
    f.set(bad);await assert.rejects(f.store.ownerCensus(host),error=>error.error_code==='OUTCOME_UNKNOWN'
      &&error.reconciliation_required===true&&error.automatic_retry===false)
  }
  assert.equal(f.stats().mutations,0)
})

test('proposed recovery never manufactures an interrupted attempt or calls closure commands',async()=>{
  const f=fixture([row('one')]);let serviceCalls=0
  const call=()=>{serviceCalls++;throw Error('NO_CLOSURE_CALL_EXPECTED')}
  const recovery=createRetainedRecovery({workflowStore:f.store,authority:{closeUnconsumedOperation:call,readUnconsumedClosure:call},
    memory:{closeUnsentOperation:call,readUnsentClosure:call,reconcileEffect:call},inFlight:new Set(),authorizeTask:call})
  assert.equal((await recovery.recover(host,'test-token','one')).state,'unknown')
  assert.equal((await recovery.recover(host,'test-token',null)).state,'idle')
  assert.equal(serviceCalls,0);assert.equal(f.stats().mutations,0)
})

test('identical published stages return factual postimages only with current exact digest',async()=>{
  const f=fixture(),workflow=row('one',host.task_id,'attempted')
  const reference=Object.fromEntries(REFERENCE_FIELDS.map(k=>[k,workflow[k]]))
  const hash=(domain,value,encode=canonicalJson)=>'sha256:'+createHash('sha256').update(domain+'\0'+encode(value)).digest('hex')
  const c={version:1,kind:'prime-authority-never-consumed/v1',store_id:profile.expected_authority_store_id,
    owner_id:host.owner_id,owner_subject:host.owner_subject,task_id:host.task_id,operation_id:'one',operation_digest:digest,
    authorization_epoch:0,closed_at:'2026-10-01T11:03:00.000Z',broker_revision:1,kernel_receipt_count:0,kernel_receipt_head:null}
  const authority={closure:c,closure_digest:hash('aukora-prime.authority-never-consumed.v1',c)}
  const immutable={reference,idempotency_key_sha256:h,expected_authority_store_id:profile.expected_authority_store_id,
    expected_memory_store_id:profile.expected_memory_store_id,closing_authorization_epoch:0}
  const progress={version:2,kind:'prime-runtime-unsent-closure-progress/v2',...immutable,
    closure_attempt_id:closureAttemptId(immutable),stage:'authority_confirmed',authority,memory:null}
  let pair={progress,progress_digest:progressDigest(progress)}
  f.set({workflow_references:[workflow],closure_progress:[pair],checkpoint})
  assert.deepEqual(await f.store.saveAuthorityClosure(host,{reference,progress_digest:pair.progress_digest,authority}),pair)
  await assert.rejects(f.store.saveAuthorityClosure(host,{reference,progress_digest:'sha256:'+'0'.repeat(64),authority}))
  await assert.rejects(f.store.saveAuthorityClosure(host,{reference,progress_digest:pair.progress_digest,authority:{...authority,extra:true}}))
  const d={version:2,kind:'prime-memory-writer-closure/v2',store_id:profile.expected_memory_store_id,...reference,authorization_epoch:0,
    closure_id:'00000000-0000-4000-8000-000000000000',writer_closed:true,intent_absent:true,effect_absent:true,grants_authority:false}
  const closure_digest=hash('aukora-prime.memory-writer-closure.v2',d,donorJSON)
  const completion={version:2,kind:'prime-memory-writer-completion/v2',store_id:profile.expected_memory_store_id,closure_digest,
    retention:{version:2,kind:'prime-memory-writer-retention/v2',...checkpoint}}
  progress.stage='complete';progress.memory={closure:d,closure_digest,completion,
    completion_digest:hash('aukora-prime.memory-writer-completion.v2',completion,donorJSON)}
  pair={progress,progress_digest:progressDigest(progress)}
  const closed={...workflow,phase:'known_unsent'}
  f.set({workflow_references:[closed],closure_progress:[pair],checkpoint})
  assert.deepEqual(await f.store.completeClosure(host,{reference,progress_digest:pair.progress_digest}),{workflow_reference:closed,...pair})
  assert.equal(f.stats().mutations,0)
})

test('unavailable factual C settlement cannot promote retained attempted history',async()=>{
  const f=fixture([row('one',host.task_id,'attempted')])
  await assert.rejects(f.store.mark(host,'one','saved',{record_id:'rem:'+h,request_id:'test-request',request_digest:digest,
    receipt_digest:digest},{authority_status:{ok:false,error_code:'UNAUTHORIZED'},effect:{authority_settlement:'completed'}}),
    error=>error.error_code==='OUTCOME_UNKNOWN'&&error.reconciliation_required===true&&error.automatic_retry===false)
  assert.equal((await f.store.get(host,'one')).phase,'attempted');assert.equal(f.stats().mutations,0)
})

test('private normal and journal failures preserve their original immutable transition identity',async()=>{
  const f=fixture([row('one')]),target=row('one',host.task_id,'attempted')
  let normal
  try{await f.store.attemptForAdmission(host,'one',digest)}catch(error){normal=error}
  assert(normal);assert.equal(normal.error_code,'OUTCOME_UNKNOWN')
  assert.match(normal.transition_id,/^[a-f0-9-]{36}$/)
  const reference=Object.fromEntries(REFERENCE_FIELDS.map(k=>[k,target[k]]))
  assert.equal(normal.transition_digest,normalTransitionDigest({version:3,kind:'prime-runtime-workflow-mutation/v3',
    memory_store_id:profile.expected_memory_store_id,reference,idempotency_key_sha256:h,
    expected_checkpoint_sha256:checkpoint.checkpoint_sha256,
    previous_workflow_digest:workflowDigest(row('one')),
    target_workflow:target}))
  assert.equal(normal.operation_id,'one');assert.equal(normal.operation_digest,digest)
  assert.equal(normal.reconciliation_required,true);assert.equal(normal.automatic_retry,false)
  f.set({workflow_references:[target],closure_progress:[],checkpoint})
  let journal
  try{await f.store.beginClosure(host,{reference,expected_authority_store_id:profile.expected_authority_store_id,
    expected_memory_store_id:profile.expected_memory_store_id,closing_authorization_epoch:0})}catch(error){journal=error}
  const immutable={reference,idempotency_key_sha256:h,expected_authority_store_id:profile.expected_authority_store_id,
    expected_memory_store_id:profile.expected_memory_store_id,closing_authorization_epoch:0}
  const progress={version:2,kind:'prime-runtime-unsent-closure-progress/v2',...immutable,
    closure_attempt_id:closureAttemptId(immutable),stage:'started',authority:null,memory:null}
  assert(journal);assert.equal(journal.error_code,'OUTCOME_UNKNOWN')
  assert.equal(journal.transition_digest,journalTransitionDigest({version:3,kind:'prime-runtime-unsent-journal-transition/v3',
    memory_store_id:profile.expected_memory_store_id,reference,idempotency_key_sha256:h,
    expected_checkpoint_sha256:checkpoint.checkpoint_sha256,previous_progress_digest:null,target_stage:'started',target_progress:progress}))
  assert.notEqual(normal.transition_id,journal.transition_id)
  assert.equal(journal.operation_id,'one');assert.equal(journal.operation_digest,digest)
  assert.equal(journal.reconciliation_required,true);assert.equal(journal.automatic_retry,false)
  assert.equal(f.stats().mutations,2)
  assert.deepEqual(retainedUnknownReference(normal),reference)
  assert.deepEqual(retainedUnknownReference(retainedUnknown(journal)),reference)
  assert.equal(retainedUnknownReference({...normal,reference}),null)
  // The existing wire fields stay operation-bound if a later census fails.
  // This is a private error-context double, not a genuine D recovery fixture.
  const memory={...f.memory,async readRetainedWorkflowJournal(){throw retainedUnknown(normal)}}
  const store=createRetainedWorkflowStore({memory,closureProfile:profile,taskRegistry:registry})
  let serviceCalls=0
  const call=()=>{serviceCalls++;throw Error('NO_SERVICE_CALL_EXPECTED')}
  const recovery=createRetainedRecovery({workflowStore:store,authority:{closeUnconsumedOperation:call,readUnconsumedClosure:call},
    memory:{closeUnsentOperation:call,readUnsentClosure:call,reconcileEffect:call},inFlight:new Set(),authorizeTask:call})
  const outcome=await recovery.recover(host,'test-token',null)
  assert.equal(outcome.state,'unknown');assert.equal(outcome.operation_id,'one')
  assert.equal(outcome.operation_digest,digest);assert.equal(outcome.action_type,'memory.save')
  assert.equal(outcome.reconciliation_required,true);assert.equal(serviceCalls,0)
})

test('pure pending binding checks refuse changed owner task epoch purpose and original identity',()=>{
  const target=row('one'),reference=Object.fromEntries(REFERENCE_FIELDS.map(k=>[k,target[k]]))
  const transition={version:3,kind:'prime-runtime-workflow-mutation/v3',memory_store_id:profile.expected_memory_store_id,
    reference,idempotency_key_sha256:h,expected_checkpoint_sha256:checkpoint.checkpoint_sha256,
    previous_workflow_digest:null,target_workflow:target}
  const marker={schema:'aukora-prime-memory-retention-workflow-pending/v3',owner_id:host.owner_id,
    owner_subject:host.owner_subject,authorization_epoch:0,transition_id:'00000000-0000-4000-8000-000000000001',
    transition,transition_digest:normalTransitionDigest(transition),prepared_checkpoint_sha256:'6'.repeat(64),
    prepared_generation_file:'synthetic.'+'6'.repeat(64)+'.json'}
  const identity=validateRetainedPendingMarker(marker,host,profile,'one')
  assert.equal(identity.transition_id,marker.transition_id);assert.equal(identity.transition_digest,marker.transition_digest)
  assert.equal(identity.reference.operation_id,'one');assert(Object.isFrozen(identity))
  for(const changed of [{...marker,owner_id:'other'},{...marker,authorization_epoch:1},
    {...marker,schema:'aukora-prime-memory-retention-restore-pending/v3'},
    {...marker,transition_digest:'sha256:'+'0'.repeat(64)},
    {...marker,prepared_checkpoint_sha256:null,prepared_generation_file:null},
    {...marker,transition:{...transition,kind:'prime-memory-authorized-effect/v3'}},
    {...marker,extra:true}])assert.throws(()=>validateRetainedPendingMarker(changed,host,profile,'one'))
  assert.throws(()=>validateRetainedPendingMarker(marker,{...host,task_id:'task-two'},profile,'one'))
  assert.throws(()=>validateRetainedPendingMarker(marker,host,profile,'other'))
  assert.throws(()=>validateRetainedPendingMarker(marker,host,{...profile,expected_memory_store_id:'7'.repeat(64)},'one'))
  // Pure typed binding is deliberately no genuine reader/brand/custody proof.
})

test('private uncertainty keeps bounded D pending identity without evaluating error accessors',async()=>{
  let reads=0
  const pending=Object.assign(Error('TEST_ONLY_PENDING'),{retention_transition_id:'00000000-0000-4000-8000-000000000001',
    retention_transition_digest:digest,operation_id:'one',operation_digest:digest})
  Object.defineProperty(pending,'retention_phase',{get(){reads++;throw Error('ACCESSOR')}})
  const f=fixture(),memory={...f.memory,async readRetainedWorkflowJournal(){throw pending}}
  const store=createRetainedWorkflowStore({memory,closureProfile:profile,taskRegistry:registry})
  await assert.rejects(store.ownerCensus(host),error=>error.retention_transition_id===pending.retention_transition_id
    &&error.retention_transition_digest===digest&&error.operation_id==='one'&&error.operation_digest===digest
    &&error.reconciliation_required===true&&error.automatic_retry===false)
  assert.equal(reads,0)
  const malformed=retainedUnknown(Object.assign(Error('BAD_IDENTITY'),{transition_id:'not-uuid',
    transition_digest:'not-digest',retention_phase:'unsafe\nvalue'}))
  assert.equal(Object.hasOwn(malformed,'transition_id'),false)
  assert.equal(Object.hasOwn(malformed,'transition_digest'),false)
  assert.equal(Object.hasOwn(malformed,'retention_phase'),false)
  assert.equal(Object.hasOwn(retainedUnknown({retention_phase:'other'}),'retention_phase'),false)
  assert.equal(retainedUnknown({retention_phase:'intent'}).retention_phase,'intent')
  assert.equal(retainedUnknown({retention_phase:'applied'}).retention_phase,'applied')
})
