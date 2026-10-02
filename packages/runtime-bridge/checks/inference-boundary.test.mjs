// SPDX-License-Identifier: AGPL-3.0-or-later
// KEYLESS SOURCE CHECK. Real C structural parser + E policy/budget helpers +
// actual authenticated Unix IPC; TEST_ONLY C replies and E ledger/dispatch
// adapters. No real C grant, durable E intent, provider, owner enrollment or UID
// separation is established. Run only in a snapshot with the accepted C parser.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {mkdtemp,realpath,rm} from 'node:fs/promises'
import {join} from 'node:path'
import {canonicalJson,operationDigest} from '../../contracts/src/runtime.mjs'
import {inferenceRequestDigest} from '../../authority/src/inference-admission.mjs'
import {createInferenceAuthorityIpcServer} from '../src/ipc.mjs'
import {createInferenceAuthorityConnection} from '../src/inference.mjs'
import {fixture} from './inference-fixture.mjs'
const clone=structuredClone
const digest=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value)).digest('hex')
const rejected=code=>error=>error.error_code===code


async function rpc(f,handler,adapters={},limits={}) {
  const root=await realpath(await mkdtemp('/tmp/prime-inference-boundary-')),socketPath=join(root,'c.sock'),secret='5'.repeat(64)
  const server=await createInferenceAuthorityIpcServer({socketPath,credentials:[{id:'source',role:'inference_effect',secret}],handlePublic:handler})
  const connection=createInferenceAuthorityConnection({observer:f.observer,authorityChannel:{socketPath,credential:{id:'source',secret},limits},...adapters})
  return {connection,async close(){connection.dispose();await server.close();await rm(root,{recursive:true,force:true})}}
}
const preparedReply=f=>({ok:true,status:'PREPARED',consumed_grant:f.grant,kernel_receipt:{TEST_ONLY:true},profile:'TEST_ONLY'})
const dispatchedReply=f=>({ok:true,status:'DISPATCHED',consumed_grant:f.grant,request_id:f.binding.request_uuid,request_digest:inferenceRequestDigest(f.binding)})

test('actual E preparation + shared budget/state + C parser map exact limits/operation',async()=>{
  const f=fixture()
  await f.observer.withObservation(f.operation,(observation,assertScope)=>{
    assert.equal(f.held,1);assertScope();assert.deepEqual(observation,{target_identity:f.operation.target_identity,state_version:f.operation.expected_state_version})
  })
  assert.equal(f.held,0);assert.equal(f.reads,1);assert.equal(f.observer.status().state,'unavailable')
  assert.equal(Object.keys(f.admission()).length,15)
})

test('altered nested conversation, configuration preimage, budget amount, generation and limits refuse',async()=>{
  const f=fixture(),wrong=clone(f.operation)
  wrong.canonical_parameters.binding.conversation_id='guest-conversation'
  wrong.canonical_parameters.request_digest=inferenceRequestDigest(wrong.canonical_parameters.binding)
  await assert.rejects(f.observer.withObservation(wrong,()=>assert.fail('no use')),rejected('UNAUTHORIZED'))
  assert.equal(f.reads,0)
  for(const mutate of [x=>{x.facts.configuration.payload.pricing.input_microusd_per_token++},x=>{x.facts.total_budget.ceiling.amount='10'},
    x=>{x.facts.credential_generation++},x=>{x.operation.canonical_parameters.limits.max_total_tokens++}]) {
    const altered=fixture();mutate(altered)
    await assert.rejects(altered.observer.withObservation(altered.operation,()=>assert.fail('no use')))
    assert.equal(altered.held,0)
  }
})

test('observation detaches caller operation before await and rejects reentry',async()=>{
  const f=fixture(),entered=Promise.withResolvers(),release=Promise.withResolvers(),original=clone(f.operation)
  const flight=f.observer.withObservation(f.operation,async observation=>{entered.resolve();await release.promise;assert.deepEqual(observation.target_identity,original.target_identity)})
  f.operation.target_identity.model='guest-altered-after-call'
  await entered.promise
  await assert.rejects(f.observer.withObservation(original,()=>{}),rejected('UNAVAILABLE'))
  release.resolve();await flight;assert.equal(f.held,0)
})

test('reserve returns flat15, never claims, and repeated/altered UUID context is latched',async()=>{
  const f=fixture();let reserves=0,reviews=0
  const r=await rpc(f,(method,wrapper)=>{assert.equal(method,'authority.reserve');assert.equal(f.held,1);reserves++
    assert.deepEqual(wrapper.input,{operation:f.operation,approval_proof:f.proof});return preparedReply(f)},
    {getReviewedApproval:()=>{reviews++;return {operation:f.operation,approval_proof:f.proof}}})
  try {
    assert.deepEqual(await r.connection.authorizeDispatch(f.binding),f.admission())
    await assert.rejects(r.connection.authorizeDispatch(f.binding),rejected('RECONCILIATION_REQUIRED'))
    await assert.rejects(r.connection.authorizeDispatch({...f.binding,body_sha256:'f'.repeat(64)}),rejected('RECONCILIATION_REQUIRED'))
    assert.equal(reserves,1);assert.equal(reviews,1)
  } finally {await r.close()}
})

test('lost reserve reply retains local fence: no reserve replay',async()=>{
  const f=fixture(),release=Promise.withResolvers();let reserves=0
  const r=await rpc(f,async()=>{reserves++;await release.promise;return preparedReply(f)},
    {getReviewedApproval:()=>({operation:f.operation,approval_proof:f.proof})},{requestTimeoutMs:30})
  try {
    await assert.rejects(r.connection.authorizeDispatch(f.binding),rejected('OUTCOME_UNKNOWN'))
    await assert.rejects(r.connection.authorizeDispatch(f.binding),rejected('RECONCILIATION_REQUIRED'))
    assert.equal(reserves,1)
  } finally {release.resolve();await r.close()}
})

test('lost claim or malformed positive reply never dispatches or repeats claim',async()=>{
  for(const lost of [false,true]) {
    const f=fixture(),release=Promise.withResolvers();let claims=0,dispatches=0,intents=0
    const r=await rpc(f,async()=>{claims++;if(lost)await release.promise;return {...dispatchedReply(f),request_digest:'sha256:'+'f'.repeat(64)}},
      {withCommittedIntent:async(_lookup,consume)=>{intents++;return await consume(f.admission())},dispatchCommitted:()=>{dispatches++}},
      {requestTimeoutMs:30})
    try {
      await assert.rejects(r.connection.withDispatch(f.claim()),rejected('OUTCOME_UNKNOWN'))
      await assert.rejects(r.connection.withDispatch(f.claim()),rejected('RECONCILIATION_REQUIRED'))
      assert.equal(claims,1);assert.equal(dispatches,0);assert.equal(intents,1)
    } finally {release.resolve();await r.close()}
  }
})

test('claim waits for committed exact intent and fence covers actual E dispatch callback',async()=>{
  const f=fixture();let claims=0,dispatches=0
  const r=await rpc(f,method=>{assert.equal(method,'authority.claimDispatch');assert.equal(f.held,1);claims++;return dispatchedReply(f)},
    {withCommittedIntent:async(_lookup,consume)=>{assert.equal(claims,0);return await consume(f.admission())},
      dispatchCommitted:()=>{assert.equal(f.held,1);assert.equal(claims,1);dispatches++;return {TEST_ONLY:true,grantsAuthority:false}}})
  try {assert.deepEqual(await r.connection.withDispatch(f.claim()),{TEST_ONLY:true,grantsAuthority:false});assert.equal(dispatches,1);assert.equal(f.held,0)}
  finally {await r.close()}
})

test('factual delivery uses exact committed outbox after live policy change; repeats only settlement',async()=>{
  const f=fixture(),receipt={version:1,kind:'prime-inference-effect/v1',operation_id:f.operation.operation_id,operation_digest:operationDigest(f.operation),
    grant_id:f.grant.grant_id,request_id:f.binding.request_uuid,request_digest:inferenceRequestDigest(f.binding),owner_subject:f.owner.subject,
    task_id:f.task.task_id,conversation_id:f.task.conversation_id,route_id:'externalDeepSeek',config_digest:f.binding.config_digest,
    credential_generation:1,total_budget_id:f.binding.total_budget_id,body_sha256:f.binding.body_sha256,outcome:'outcome_unknown',
    result_digest:null,usage:null,reservation_retained:true,observed_at:'2026-10-02T00:00:00.000Z'}
  const input={...f.claim(),receipt,receipt_digest:digest('aukora-prime.inference-receipt.v1',receipt)}
  let settlements=0
  const r=await rpc(f,(method,wrapper)=>{assert.equal(method,'authority.settleInference');assert.equal(wrapper.observation,null)
    assert.deepEqual(wrapper.input,input);settlements++;return {ok:true,status:'OUTCOME_UNKNOWN',request_id:input.request_id,
      request_digest:input.request_digest,receipt_digest:input.receipt_digest,idempotent:settlements>1,reconciliation_required:true}},
    {withCommittedSettlement:async(_method,_lookup,consume)=>await consume(input)})
  try {
    await assert.rejects(r.connection.settleInference({...input,receipt:{...receipt,observed_at:'2026-10-03T00:00:00.000Z'}}),rejected('UNAUTHORIZED'))
    assert.equal(settlements,0);f.facts.credential_generation=2;f.facts.total_budget.ceiling.amount='1'
    assert.equal((await r.connection.settleInference(input)).idempotent,false)
    assert.equal((await r.connection.settleInference(input)).idempotent,true)
    assert.equal(f.reads,0);assert.equal(settlements,2)
  } finally {await r.close()}
})
