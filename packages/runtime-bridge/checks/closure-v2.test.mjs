// SPDX-License-Identifier: AGPL-3.0-or-later
// PURE SOURCE CHECKS: synthetic metadata for frozen private-v2 decision v004
// (SHA256 95fcc9d4fb4420e2dbc13ba28b8332968b4b36e71f069a233847c23932a1c3b9).
// No store, owner enrollment, retained publication, PG fence or runtime custody
// is established by these checks. No service/provider/configuration is used.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {canonicalJson,operationDigest} from '../../contracts/src/runtime.mjs'
import {canonicalJSON as memoryCanonicalJSON} from '../../memory/genesis/plugins/aukora-kira/lib/record.mjs'
import {
  validateClosureProfile,validateClosureHost,validateWorkflowRow,workflowDigest,
  validateClosureProgress,progressDigest,closureAttemptId,
  validateNormalTransition,normalTransitionDigest,
  validateJournalTransition,journalTransitionDigest,
  validateAuthorityProjection,validateMemoryProjection,
  validateMemoryClosureReply,validateAuthorityClosureReply,
  validateWorkflowAdvance,validateProgressAdvance,parseClosureProgressBytes,
} from '../src/closure-v2.mjs'

const clone=structuredClone
const raw=character=>character.repeat(64)
const digest=(domain,value,encode=canonicalJson)=>'sha256:'+createHash('sha256').update(domain,'utf8').update(encode(value),'utf8').digest('hex')
const authorityDomain='aukora-prime.authority-never-consumed.v1\0'
const memoryDomain='aukora-prime.memory-writer-closure.v2\0'
const completionDomain='aukora-prime.memory-writer-completion.v2\0'
const attemptDomain='aukora-prime.runtime-unsent-closure-attempt.v2\0'
const progressDomain='aukora-prime.runtime-unsent-closure-progress.v2\0'
const rowDomain='aukora-prime.runtime-workflow-row.v3\0'
const normalDomain='aukora-prime.runtime-workflow-mutation.v3\0'
const journalDomain='aukora-prime.runtime-unsent-journal-transition.v3\0'

function fixture() {
  const profile={version:2,kind:'prime-private-unsent-closure/v2',expected_authority_store_id:raw('a'),
    expected_memory_store_id:raw('b'),retention_profile:'required-retained/v2'}
  const host={owner_id:'synthetic-owner',owner_subject:'aukora:1:'+raw('c'),task_id:'synthetic-task',authorization_epoch:7}
  const operation={version:1,operation_id:'11111111-1111-4111-8111-111111111111',task_id:host.task_id,
    owner_id:host.owner_id,agent_id:'synthetic-agent',audience:'aukora-prime.memory',action_type:'memory.save',
    target_identity:{kind:'prime-memory',owner_subject:host.owner_subject},canonical_parameters:{},
    data_scope:['synthetic'],expected_state_version:'synthetic-state',provider_and_region:{provider:'local',region:'local'},
    maximum_cost:{currency:'USD',amount:'0'},expiry:'2030-01-01T00:00:00.000Z',nonce:raw('d'),
    policy_version:'synthetic-policy',authorization_epoch:3}
  const reference={owner_id:host.owner_id,owner_subject:host.owner_subject,task_id:host.task_id,
    operation_id:operation.operation_id,operation_digest:operationDigest(operation),action_type:operation.action_type}
  const row={owner_subject:host.owner_subject,owner_id:host.owner_id,task_id:host.task_id,
    operation_id:reference.operation_id,operation_digest:reference.operation_digest,action_type:reference.action_type,
    idempotency_key_sha256:raw('e'),record_id:null,phase:'proposed',request_id:null,request_digest:null,
    receipt_digest:null,created_at:'2026-10-02T12:00:00.000Z'}
  const authorityMarker={version:1,kind:'prime-authority-never-consumed/v1',store_id:profile.expected_authority_store_id,
    owner_id:host.owner_id,owner_subject:host.owner_subject,task_id:host.task_id,operation_id:reference.operation_id,
    operation_digest:reference.operation_digest,authorization_epoch:operation.authorization_epoch,
    closed_at:'2026-10-02T12:01:00.000Z',broker_revision:1,kernel_receipt_count:0,kernel_receipt_head:null}
  const authority={closure:authorityMarker,closure_digest:digest(authorityDomain,authorityMarker)}
  const marker={version:2,kind:'prime-memory-writer-closure/v2',store_id:profile.expected_memory_store_id,...reference,
    authorization_epoch:host.authorization_epoch,closure_id:'22222222-2222-4222-8222-222222222222',
    writer_closed:true,intent_absent:true,effect_absent:true,grants_authority:false}
  const markerDigest=digest(memoryDomain,marker,memoryCanonicalJSON)
  const completion={version:2,kind:'prime-memory-writer-completion/v2',store_id:profile.expected_memory_store_id,
    closure_digest:markerDigest,retention:{version:2,kind:'prime-memory-writer-retention/v2',checkpoint_sha256:raw('f'),
      control_sha256:raw('0'),authorization_epoch:host.authorization_epoch}}
  const memory={closure:marker,closure_digest:markerDigest,completion,
    completion_digest:digest(completionDomain,completion,memoryCanonicalJSON)}
  const attempt={reference,idempotency_key_sha256:row.idempotency_key_sha256,
    expected_authority_store_id:profile.expected_authority_store_id,expected_memory_store_id:profile.expected_memory_store_id,
    closing_authorization_epoch:host.authorization_epoch}
  const started={version:2,kind:'prime-runtime-unsent-closure-progress/v2',...attempt,
    closure_attempt_id:digest(attemptDomain,attempt),stage:'started',authority:null,memory:null}
  const authorityConfirmed={...started,stage:'authority_confirmed',authority}
  const memoryConfirmed={...authorityConfirmed,stage:'memory_confirmed',memory}
  const complete={...memoryConfirmed,stage:'complete'}
  const normal={version:3,kind:'prime-runtime-workflow-mutation/v3',memory_store_id:profile.expected_memory_store_id,
    reference,idempotency_key_sha256:row.idempotency_key_sha256,expected_checkpoint_sha256:raw('1'),
    previous_workflow_digest:null,target_workflow:row}
  const journal={version:3,kind:'prime-runtime-unsent-journal-transition/v3',memory_store_id:profile.expected_memory_store_id,
    reference,idempotency_key_sha256:row.idempotency_key_sha256,expected_checkpoint_sha256:raw('1'),
    previous_progress_digest:null,target_stage:'started',target_progress:started}
  return {profile,host,operation,reference,row,authority,memory,attempt,started,authorityConfirmed,memoryConfirmed,complete,normal,journal}
}

function assertDetachedFrozen(output,input) {
  assert.deepEqual(output,input)
  assert.notEqual(output,input)
  const visit=value=>{
    if(value===null||typeof value!=='object')return
    assert.equal(Object.isFrozen(value),true)
    for(const child of Object.values(value))visit(child)
  }
  visit(output)
}

test('closed metadata validators detach, freeze and refuse accessors/proxies before evaluating them',()=>{
  const f=fixture()
  assertDetachedFrozen(validateClosureProfile(f.profile),f.profile)
  assertDetachedFrozen(validateClosureHost(f.host),f.host)
  assertDetachedFrozen(validateWorkflowRow(f.row,f.host),f.row)
  const retained=validateClosureProgress(f.started,f.profile,f.host)
  assertDetachedFrozen(retained,f.started)
  assert.notEqual(retained.reference,f.started.reference)
  f.started.reference.task_id='caller-altered'
  assert.equal(retained.reference.task_id,'synthetic-task')
  let getters=0,traps=0
  const accessor=clone(f.profile)
  Object.defineProperty(accessor,'kind',{enumerable:true,get(){getters++;throw new Error('getter evaluated')}})
  assert.throws(()=>validateClosureProfile(accessor))
  const nested=clone(f.memoryConfirmed)
  Object.defineProperty(nested.memory.closure,'store_id',{enumerable:true,get(){getters++;throw new Error('nested getter evaluated')}})
  assert.throws(()=>validateClosureProgress(nested,f.profile,f.host))
  const proxy=new Proxy(clone(f.profile),{
    get(){traps++;throw new Error('get trap evaluated')},ownKeys(){traps++;throw new Error('ownKeys trap evaluated')},
    getPrototypeOf(){traps++;throw new Error('prototype trap evaluated')},
    getOwnPropertyDescriptor(){traps++;throw new Error('descriptor trap evaluated')},
  })
  assert.throws(()=>validateClosureProfile(proxy))
  assert.equal(getters,0);assert.equal(traps,0)
  assert.throws(()=>validateClosureHost({...f.host,source:'unexpected'}))
  assert.throws(()=>validateClosureProfile({...f.profile,expected_retention_store_id:raw('2')}))
  assert.throws(()=>validateWorkflowRow({...f.row,created_at:'2026-02-30T12:00:00.000Z'}))
  assert.throws(()=>validateWorkflowRow({...f.row,receipt_digest:'sha256:'+raw('4')}))
  assert.throws(()=>validateWorkflowRow({...f.row,request_id:'33333333-3333-4333-8333-333333333333',
    request_digest:'sha256:'+raw('3'),receipt_digest:'sha256:'+raw('4')}))
})

test('C original epoch and current D closing epoch stay distinct and both store pins bind',()=>{
  const f=fixture()
  assertDetachedFrozen(validateAuthorityProjection(f.authority,f.reference,f.profile),f.authority)
  assertDetachedFrozen(validateMemoryProjection(f.memory,f.reference,f.profile,f.host.authorization_epoch),f.memory)
  const cReply={ok:true,status:'CLOSED_UNCONSUMED',operation:f.operation,...f.authority,idempotent:true}
  assertDetachedFrozen(validateAuthorityClosureReply(cReply,f.reference,f.profile),cReply)
  const dReply={status:'closed-unsent',...f.memory,idempotent:true,grants_authority:false}
  assertDetachedFrozen(validateMemoryClosureReply(dReply,f.reference,f.profile,f.host.authorization_epoch),dReply)
  assert.throws(()=>validateMemoryProjection(f.memory,f.reference,f.profile,f.operation.authorization_epoch))
  assert.throws(()=>validateAuthorityProjection(f.authority,f.reference,{...f.profile,expected_authority_store_id:raw('2')}))
  assert.throws(()=>validateMemoryProjection(f.memory,f.reference,{...f.profile,expected_memory_store_id:raw('2')},7))
  const wrongOriginal=clone(cReply)
  wrongOriginal.closure.authorization_epoch=7
  wrongOriginal.closure_digest=digest(authorityDomain,wrongOriginal.closure)
  assert.throws(()=>validateAuthorityClosureReply(wrongOriginal,f.reference,f.profile))
  const changedRetention=clone(f.memory)
  changedRetention.completion.retention.authorization_epoch=3
  changedRetention.completion_digest=digest(completionDomain,changedRetention.completion,memoryCanonicalJSON)
  assert.throws(()=>validateMemoryProjection(changedRetention,f.reference,f.profile,7))
  assert.throws(()=>validateMemoryClosureReply({...dReply,completion:null,completion_digest:null},f.reference,f.profile,7))
})

test('proof hashes use the selected donor encoding, exact v2 domain and one actual NUL',()=>{
  const f=fixture()
  assert.notEqual(f.memory.closure_digest,digest('aukora-prime.memory-writer-closure.v2\\0',f.memory.closure,memoryCanonicalJSON))
  assert.notEqual(f.memory.closure_digest,digest(memoryDomain,f.memory.closure,JSON.stringify))
  for(const wrong of [
    digest('aukora-prime.memory-writer-closure.v1\0',f.memory.closure,memoryCanonicalJSON),
    digest('aukora-prime.memory-writer-closure.v2\\0',f.memory.closure,memoryCanonicalJSON),
    digest(memoryDomain,f.memory.closure,JSON.stringify),
  ])assert.throws(()=>validateMemoryProjection({...f.memory,closure_digest:wrong},f.reference,f.profile,7))
  const completion=clone(f.memory)
  completion.completion_digest=digest('aukora-prime.memory-writer-completion.v1\0',completion.completion,memoryCanonicalJSON)
  assert.throws(()=>validateMemoryProjection(completion,f.reference,f.profile,7))
  assert.equal(workflowDigest(f.row),digest(rowDomain,f.row))
  assert.equal(closureAttemptId(f.attempt),digest(attemptDomain,f.attempt))
  assert.equal(closureAttemptId(f.started),digest(attemptDomain,f.attempt))
  assert.equal(progressDigest(f.started),digest(progressDomain,f.started))
  assert.equal(normalTransitionDigest(f.normal),digest(normalDomain,f.normal))
  assert.equal(journalTransitionDigest(f.journal),digest(journalDomain,f.journal))
})

test('original journal identity/key/time and established receipt bytes cannot be rewritten',()=>{
  const f=fixture(),attempted={...f.row,phase:'attempted'}
  assert.doesNotThrow(()=>validateWorkflowAdvance(null,f.row))
  assert.doesNotThrow(()=>validateWorkflowAdvance(f.row,attempted))
  for(const change of [{idempotency_key_sha256:raw('2')},{created_at:'2026-10-02T12:00:01.000Z'},
    {operation_digest:'sha256:'+raw('2')},{task_id:'other-task'}]) {
    assert.throws(()=>validateWorkflowAdvance(f.row,{...attempted,...change}))
  }
  assert.throws(()=>validateWorkflowAdvance(attempted,f.row))
  assert.throws(()=>validateWorkflowAdvance(null,attempted))
  const malformedProposed={...f.row,request_id:'33333333-3333-4333-8333-333333333333',
    request_digest:'sha256:'+raw('3'),receipt_digest:'sha256:'+raw('4')}
  assert.throws(()=>validateWorkflowAdvance(malformedProposed,{...malformedProposed,phase:'attempted'}))
  const saved={...attempted,phase:'saved',record_id:'synthetic-record',request_id:'33333333-3333-4333-8333-333333333333',
    request_digest:'sha256:'+raw('3'),receipt_digest:'sha256:'+raw('4')}
  assert.doesNotThrow(()=>validateWorkflowAdvance(attempted,saved))
  assert.doesNotThrow(()=>validateWorkflowAdvance(saved,clone(saved)))
  assert.throws(()=>validateWorkflowAdvance(saved,{...saved,receipt_digest:'sha256:'+raw('5')}))
})

test('typed normal and closure transitions reject cross-purpose promotion and binding changes',()=>{
  const f=fixture()
  assertDetachedFrozen(validateNormalTransition(f.normal,f.profile),f.normal)
  assertDetachedFrozen(validateJournalTransition(f.journal,f.profile),f.journal)
  const attempted={...f.normal,previous_workflow_digest:workflowDigest(f.row),target_workflow:{...f.row,phase:'attempted'}}
  assert.doesNotThrow(()=>validateNormalTransition(attempted,f.profile))
  assert.throws(()=>validateNormalTransition({...attempted,target_workflow:{...f.row,phase:'known_unsent'}},f.profile))
  assert.throws(()=>validateNormalTransition({...attempted,previous_workflow_digest:null},f.profile))
  assert.throws(()=>validateNormalTransition({...f.normal,memory_store_id:raw('2')},f.profile))
  assert.throws(()=>validateNormalTransition({...f.normal,idempotency_key_sha256:raw('2')},f.profile))
  assert.throws(()=>validateJournalTransition({...f.journal,target_stage:'authority_confirmed'},f.profile))
  assert.throws(()=>validateJournalTransition({...f.journal,target_progress:f.authorityConfirmed,target_stage:'authority_confirmed'},f.profile))
  assert.throws(()=>validateJournalTransition({...f.journal,reference:{...f.reference,operation_digest:'sha256:'+raw('2')}},f.profile))
})

test('progress advances one retained stage at a time with immutable bindings/proofs and exact prior digest',()=>{
  const f=fixture()
  assert.doesNotThrow(()=>validateProgressAdvance(null,f.started,f.profile,f.host))
  assert.throws(()=>validateProgressAdvance(null,f.started))
  for(const [before,after] of [[f.started,f.authorityConfirmed],[f.authorityConfirmed,f.memoryConfirmed],[f.memoryConfirmed,f.complete]]) {
    assert.doesNotThrow(()=>validateProgressAdvance(before,after,f.profile,f.host,progressDigest(before)))
  }
  assert.doesNotThrow(()=>validateProgressAdvance(f.complete,clone(f.complete),f.profile,f.host,progressDigest(f.complete)))
  assert.throws(()=>validateProgressAdvance(f.complete,clone(f.complete),f.profile,f.host,'sha256:'+raw('2')))
  assert.throws(()=>validateProgressAdvance(f.started,f.memoryConfirmed,f.profile,f.host,progressDigest(f.started)))
  assert.throws(()=>validateProgressAdvance(f.memoryConfirmed,f.authorityConfirmed,f.profile,f.host,progressDigest(f.memoryConfirmed)))
  assert.throws(()=>validateProgressAdvance(f.started,f.authorityConfirmed,f.profile,f.host,'sha256:'+raw('2')))
  const changedKey=clone(f.authorityConfirmed)
  changedKey.idempotency_key_sha256=raw('2')
  changedKey.closure_attempt_id=closureAttemptId({reference:changedKey.reference,idempotency_key_sha256:changedKey.idempotency_key_sha256,
    expected_authority_store_id:changedKey.expected_authority_store_id,expected_memory_store_id:changedKey.expected_memory_store_id,
    closing_authorization_epoch:changedKey.closing_authorization_epoch})
  assert.throws(()=>validateProgressAdvance(f.started,changedKey,f.profile,f.host,progressDigest(f.started)))
  const changedProof=clone(f.memoryConfirmed)
  changedProof.authority.closure.closed_at='2026-10-02T12:01:01.000Z'
  changedProof.authority.closure_digest=digest(authorityDomain,changedProof.authority.closure)
  assert.throws(()=>validateProgressAdvance(f.authorityConfirmed,changedProof,f.profile,f.host,progressDigest(f.authorityConfirmed)))
  assert.throws(()=>validateClosureProgress(f.complete,f.profile,{...f.host,authorization_epoch:8}))
})

test('progress byte ingress requires exact canonical UTF8 with no BOM, duplicates or alternate JSON spelling',()=>{
  const f=fixture(),canonical=canonicalJson(f.memoryConfirmed),bytes=Buffer.from(canonical,'utf8')
  assertDetachedFrozen(parseClosureProgressBytes(bytes,f.profile,f.host),f.memoryConfirmed)
  const duplicate=canonical.replace('"version":2','"version":2,"version":2')
  assert.notEqual(duplicate,canonical)
  for(const malformed of [Buffer.concat([Buffer.from([0xff]),bytes]),Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),bytes]),
    Buffer.from(duplicate,'utf8'),Buffer.from(' '+canonical,'utf8'),Buffer.from(canonical+'\n','utf8'),
    Buffer.from(JSON.stringify(f.memoryConfirmed),'utf8')]) {
    assert.throws(()=>parseClosureProgressBytes(malformed,f.profile,f.host))
  }
})
