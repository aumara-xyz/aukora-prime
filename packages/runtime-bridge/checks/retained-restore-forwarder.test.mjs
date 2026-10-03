// SPDX-License-Identifier: AGPL-3.0-or-later
// PURE SOURCE CHECKS: TEST_ONLY data and inert unmounted constructor inputs.
// Actual C/D digest helpers are used; these checks establish no genuine source
// participant, owner approval, store/ancestry proof, PG guard or runtime custody.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {operationDigest} from '../../contracts/src/runtime.mjs'
import {validateRetainedRestoreOperation,validateRetainedRestoreResult,
  retainedRestoreRequestDigest} from '../../authority/src/retained-restore.mjs'
import {memoryResultDigest,memoryReceiptDigest} from '../../memory/src/authorization.mjs'
import {createRetainedRestoreForwarder,validateRestoreEffect} from '../src/retained-restore-forwarder.mjs'
import {PUBLIC_METHODS,IPC_METHOD_ROLES} from '../src/ipc.mjs'
import {validateWorkflowRow} from '../src/closure-v2.mjs'

const clone=structuredClone
const raw=character=>character.repeat(64)
function fixture() {
  const host={owner_id:'TEST_ONLY-owner',owner_subject:'aukora:1:'+raw('a'),
    task_id:'TEST_ONLY-task',authorization_epoch:7}
  const heads={remembered:'aukora:aura-record:v1',approved:raw('b')}
  const operation={version:1,operation_id:'11111111-1111-4111-8111-111111111111',
    task_id:host.task_id,owner_id:host.owner_id,agent_id:'TEST_ONLY-agent',audience:'aukora-prime.memory',
    action_type:'memory.restore',target_identity:{kind:'prime-memory',owner_subject:host.owner_subject},
    canonical_parameters:{manifest_sha256:raw('c'),mode:'prime-restore',heads,retained_heads:clone(heads),
      control_anchor_sha256:raw('d'),retention_checkpoint_sha256:raw('e'),retention_epoch:host.authorization_epoch},
    data_scope:['public'],expected_state_version:'sha256:'+raw('f'),
    provider_and_region:{provider:'none',region:'local'},maximum_cost:{currency:'USD',amount:'0'},
    expiry:'2040-01-01T00:00:00.000Z',nonce:'TEST_ONLY-nonce',policy_version:'TEST_ONLY-policy',
    authorization_epoch:host.authorization_epoch}
  validateRetainedRestoreOperation(operation)
  const result=validateRetainedRestoreResult({state:'restored',manifest_sha256:operation.canonical_parameters.manifest_sha256,
    heads:clone(heads),restored_records:2,grants_authority:false},operation)
  const receipt={version:1,kind:'prime-memory-effect/v1',operation_id:operation.operation_id,
    operation_digest:operationDigest(operation),grant_id:'TEST_ONLY-grant',
    request_id:'22222222-2222-4222-8222-222222222222',request_digest:retainedRestoreRequestDigest(operation),
    owner_subject:host.owner_subject,action_type:'memory.restore',status:'applied',
    result_digest:memoryResultDigest(result),result:clone(result)}
  const completed={result:clone(result),receipt,authority_settlement:'completed',
    receipt_digest:memoryReceiptDigest(receipt),reconciliation_required:false}
  const pending={result:clone(result),receipt:clone(receipt),authority_settlement:'pending',
    reconciliation_required:true,settlement_reason:'TEST_ONLY-settlement-unavailable'}
  return {host,operation,completed,pending}
}

test('pure completed restore reply binds actual C request and D result/receipt digests',()=>{
  const {host,operation,completed}=fixture()
  const checked=validateRestoreEffect(completed,operation,host)
  assert.deepEqual(checked,completed)
  assert.notEqual(checked,completed)
  assert.notEqual(checked.receipt,completed.receipt)
  assert.notEqual(checked.result,completed.result)
  assert.equal(checked.receipt.request_digest,retainedRestoreRequestDigest(operation))
  assert.equal(checked.receipt.result_digest,memoryResultDigest(checked.result))
  assert.equal(checked.receipt_digest,memoryReceiptDigest(checked.receipt))
  completed.result.heads.remembered=raw('0')
  assert.equal(checked.result.heads.remembered,'aukora:aura-record:v1')
})

test('pure pending restore reply retains reconciliation without inventing completion',()=>{
  const {host,operation,pending}=fixture()
  const checked=validateRestoreEffect(pending,operation,host)
  assert.deepEqual(checked,pending)
  assert.notEqual(checked.receipt,pending.receipt)
  assert.equal(checked.authority_settlement,'pending')
  assert.equal(checked.reconciliation_required,true)
  assert.equal(Object.hasOwn(checked,'receipt_digest'),false)
  assert.equal(checked.result.grants_authority,false)
})

test('pure restore reply refuses changed receipt and settlement bindings',()=>{
  const {host,operation,completed,pending}=fixture()
  const mutations=[
    ['operation id',v=>v.receipt.operation_id='TEST_ONLY-other-operation'],
    ['operation digest',v=>v.receipt.operation_digest='sha256:'+raw('0')],
    ['owner subject',v=>v.receipt.owner_subject='aukora:1:'+raw('0')],
    ['action',v=>v.receipt.action_type='memory.save'],
    ['status',v=>v.receipt.status='unresolved'],
    ['grant id',v=>v.receipt.grant_id=''],
    ['request id',v=>v.receipt.request_id='TEST_ONLY-not-a-UUID'],
    ['request digest',v=>v.receipt.request_digest='sha256:'+raw('0')],
    ['result digest',v=>v.receipt.result_digest='sha256:'+raw('0')],
    ['receipt result',v=>v.receipt.result.restored_records=3],
    ['receipt digest',v=>v.receipt_digest='sha256:'+raw('0')],
    ['receipt extra field',v=>v.receipt.grants_authority=true],
    ['completed reconciliation',v=>v.reconciliation_required=true],
    ['settlement status',v=>v.authority_settlement='unknown'],
    ['reply extra field',v=>v.known_unsent=true],
  ]
  for(const [label,mutate] of mutations) {
    const changed=clone(completed);mutate(changed)
    assert.throws(()=>validateRestoreEffect(changed,operation,host),label)
  }
  for(const [label,mutate] of [
    ['pending reconciliation',v=>v.reconciliation_required=false],
    ['pending reason',v=>v.settlement_reason=''],
    ['pending completion digest',v=>v.receipt_digest=memoryReceiptDigest(v.receipt)],
  ]) {
    const changed=clone(pending);mutate(changed)
    assert.throws(()=>validateRestoreEffect(changed,operation,host),label)
  }
})

test('pure restore result refuses changed operation-bound data even with recomputed D digests',()=>{
  const {host,operation,completed}=fixture()
  for(const [label,mutate] of [
    ['manifest',v=>v.manifest_sha256=raw('0')],
    ['heads',v=>v.heads.remembered=raw('0')],
    ['state',v=>v.state='imported'],
    ['authority grant',v=>v.grants_authority=true],
    ['negative record count',v=>v.restored_records=-1],
    ['oversized record count',v=>v.restored_records=10001],
    ['result extra field',v=>v.authorization_epoch=host.authorization_epoch],
  ]) {
    const changed=clone(completed);mutate(changed.result)
    changed.receipt.result=clone(changed.result)
    changed.receipt.result_digest=memoryResultDigest(changed.result)
    changed.receipt_digest=memoryReceiptDigest(changed.receipt)
    assert.throws(()=>validateRestoreEffect(changed,operation,host),label)
  }
})

test('pure restore reply refuses a different authenticated host binding',()=>{
  const {host,operation,completed}=fixture()
  for(const [field,value] of [
    ['owner_id','TEST_ONLY-other-owner'],['owner_subject','aukora:1:'+raw('0')],
    ['task_id','TEST_ONLY-other-task'],['authorization_epoch',host.authorization_epoch+1],
  ]) assert.throws(()=>validateRestoreEffect(completed,operation,{...host,[field]:value}),field)
})

test('inert unmounted local restore facade refuses before any source context call',async()=>{
  const {operation}=fixture()
  let contextCalls=0
  const forwarder=createRetainedRestoreForwarder({authority:{},memory:{},
    profile:{version:2,kind:'prime-private-unsent-closure/v2',expected_authority_store_id:raw('a'),
      expected_memory_store_id:raw('b'),retention_profile:'required-retained/v2'},
    taskRegistry:{},sourceContext:()=>{contextCalls++;throw Error('TEST_ONLY context must not run')},inFlight:new Set()})
  const context={request:{},role:'owner_control'},session_token='TEST_ONLY-no-session'
  for(const call of [
    ()=>forwarder.propose({session_token},{},context),
    ()=>forwarder.approvalChallenge({session_token,operation},context),
    ()=>forwarder.approvalComplete({session_token,operation,proof:{}},context),
    ()=>forwarder.apply({session_token,operation,approval_proof:{}},{},context),
    ()=>forwarder.reconcile({session_token,operation},context),
  ]) await assert.rejects(call,{error_code:'UNAVAILABLE',message:'RETAINED_RESTORE_SOURCE_UNMOUNTED'})
  await assert.rejects(()=>forwarder.propose({session_token},{},{request:{},role:'read_only'}),
    {error_code:'UNAUTHORIZED',message:'RETAINED_RESTORE_OWNER_CONTROL_REQUIRED'})
  assert.equal(contextCalls,0)
})

test('local restore checks leave public method grammar and original13 action scope closed',()=>{
  const {host,operation}=fixture()
  assert.equal(PUBLIC_METHODS.some(method=>/restore/i.test(method)),false)
  assert.equal(Object.keys(IPC_METHOD_ROLES).some(method=>/restore/i.test(method)),false)
  const row={owner_subject:host.owner_subject,owner_id:host.owner_id,task_id:host.task_id,
    operation_id:operation.operation_id,operation_digest:operationDigest(operation),action_type:'memory.restore',
    idempotency_key_sha256:raw('0'),record_id:null,phase:'proposed',request_id:null,request_digest:null,
    receipt_digest:null,created_at:'2026-10-02T12:00:00.000Z'}
  assert.throws(()=>validateWorkflowRow(row,host))
})
