// SPDX-License-Identifier: AGPL-3.0-or-later
// LOCAL SOURCE CHECK: genuine C verification, kernel/store/witness and private
// IPC worker; normal explicit disposable provisioning and synthetic passkeys.
// E intent, dispatch, result and settlement outbox below are TEST_ONLY adapters.
// No provider HTTP, durable E ledger, real owner enrollment, PG or UID isolation
// is established. Run in the isolated snapshot with the accepted live C source.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {createHash,randomBytes} from 'node:crypto'
import {chmod,mkdtemp,readFile,realpath,rm,stat} from 'node:fs/promises'
import {join} from 'node:path'
import {canonicalJson,operationDigest} from '../../contracts/src/runtime.mjs'
import {inferenceRequestDigest} from '../../authority/src/inference-admission.mjs'
import {inferenceEffectReceiptDigest} from '../../authority/src/inference-effect.mjs'
import {inferenceBudgetState} from '../../inference/src/budget-binding.mjs'
import {authorityFixture} from '../test/authority-fixture.mjs'
import {createTrustedTaskRegistry} from '../src/registry.mjs'
import {createInferenceAuthorityIpcClient} from '../src/ipc.mjs'
import {startInferenceAuthorityWorker,createInferenceAuthorityConnection} from '../src/inference.mjs'
import {fixture} from './inference-fixture.mjs'

const clone=structuredClone
const accepted=reply=>{assert.equal(reply?.ok,true,JSON.stringify(reply));return reply}
const rejected=code=>error=>error.error_code===code||error.code===code
const digest=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value)).digest('hex')
const limits={handshakeTimeoutMs:1000,idleTimeoutMs:5000,requestTimeoutMs:3000}
const contextOf=f=>({route:clone(f.facts.route),local_task:clone(f.facts.local_task),
  total_budget:clone(f.facts.total_budget),original_config:clone(f.facts.configuration.payload)})
const observationOf=f=>({target_identity:clone(f.operation.target_identity),state_version:f.operation.expected_state_version})
const claimOf=admission=>({operation:clone(admission.operation),consumed_grant:clone(admission.consumed_grant),
  request_id:admission.request_uuid,request_digest:admission.request_digest})

function receiptOf(f,admission,outcome) {
  const claim=claimOf(admission),completed=outcome==='completed'
  // A synthetic worker result only. C authenticates/binds factual receipt
  // metadata; this fabricated result does not establish an actual inference.
  const TEST_ONLY_result={text:'TEST_ONLY synthetic inference evidence',source_ids:[],input_tokens:3,output_tokens:2}
  const receipt={version:1,kind:'prime-inference-effect/v1',operation_id:claim.operation.operation_id,
    operation_digest:operationDigest(claim.operation),grant_id:claim.consumed_grant.grant_id,
    request_id:claim.request_id,request_digest:claim.request_digest,owner_subject:f.owner.subject,
    task_id:f.task.task_id,conversation_id:f.task.conversation_id,route_id:'externalDeepSeek',
    config_digest:admission.config_digest,credential_generation:admission.credential_generation,
    total_budget_id:admission.total_budget_id,body_sha256:admission.body_sha256,outcome,
    result_digest:completed?digest('aukora-prime.inference-result.v1',TEST_ONLY_result):null,
    usage:completed?{input_tokens:3,output_tokens:2,cost_microusd:5}:null,
    reservation_retained:!completed,observed_at:completed?'2026-10-02T00:00:00.001Z':'2026-10-02T00:00:00.000Z'}
  return {...claim,receipt,receipt_digest:inferenceEffectReceiptDigest(receipt)}
}

test('genuine C inference lifecycle over private IPC survives a C-only restart',{timeout:20000},async t=>{
  const root=await realpath(await mkdtemp(join(await realpath('/tmp'),'inf-real-c-')))
  await chmod(root,0o700)
  assert.equal((await stat(root)).mode&0o777,0o700)
  const socketPath=join(root,'c.sock');assert(Buffer.byteLength(socketPath)<=103)
  const channelSecret=randomBytes(32),credential={id:'TEST_ONLY_inference_peer',secret:channelSecret.toString('hex')}
  const authorityChannel={socketPath,credential,limits},workers=[],connections=[]
  t.after(async()=>{
    for(const connection of connections)connection.dispose()
    for(const worker of workers)await worker.close()
    channelSecret.fill(0);await rm(root,{recursive:true,force:true})
  })
  const f=fixture({owner:{owner_id:'synthetic-owner',subject:'aukora:1:'+'a'.repeat(64)}})
  const registry=createTrustedTaskRegistry(f.registryEntries),originalContext=contextOf(f)
  const independentState=inferenceBudgetState({owner:f.owner,route:f.facts.route,
    total_budget:f.facts.total_budget,credential_generation:f.facts.credential_generation})
  const auth=authorityFixture({root,audience:'aukora-prime.inference',authorizeTask:registry.authorizeTask,
    observeTarget:()=>clone({target_identity:independentState.target_identity,state_version:independentState.state_version}),
    policy:{version:f.operation.policy_version,actions:['inference.generate'],agents:[f.task.agent_id],
      data_scope:['conversation'],maximum_cost:{currency:'USD',amount:'0.010000'}},
    inferenceProfile:{contexts:[originalContext]}})
  assert.equal(auth.identity.owner_id,f.owner.owner_id);assert.equal(auth.identity.subject,f.owner.subject)
  // Function seams are supplied by startInferenceAuthorityWorker itself; only
  // immutable provisioner data crosses its closed authorityConfig constructor.
  const {authorizeTask:_authorizeTask,observeTarget:_observeTarget,...configured}=auth.config
  const authorityConfig={...configured,provisionTrustedState:false}
  const workerConfig=(config,registryEntries=f.registryEntries)=>({kind:'inference-authority',registryEntries,
    authorityConfig:config,ipc:{socketPath,credentials:[{...credential,role:'inference_effect'}],limits}})
  const persisted=async()=>({state:await readFile(auth.config.statePath,'utf8'),
    witness:await readFile(join(auth.config.witnessDir,'kernel-high-water.json'),'utf8')})
  const record=async()=>JSON.parse((await persisted()).state)
  const onlyRow=state=>{
    const rows=Object.values(state.broker.operations);assert.equal(rows.length,1);return rows[0]
  }
  async function direct(name,input,operation=null,observation=null) {
    const client=await createInferenceAuthorityIpcClient(authorityChannel)
    try{return await client.request('authority.'+name,{input,operation,
      operation_digest:operation?operationDigest(operation):null,observation})}
    finally{await client.close()}
  }
  let reviewed,approved,TEST_ONLY_committedAdmission,TEST_ONLY_committedSettlement
  let reviewReads=0,intentReads=0,dispatches=0,settlementReads=0
  const connectionConfig={authorityChannel,observer:f.observer,
    getReviewedApproval(binding) {
      reviewReads++;assert.deepEqual(binding,f.binding);assert.equal(approved?.ok,true)
      // The only accepted proof comes from genuine C approvalComplete below.
      return {operation:clone(reviewed.operation),approval_proof:clone(approved.approval_proof)}
    },
    async withCommittedIntent(lookup,consume) {
      intentReads++;assert.deepEqual(lookup,{owner_id:f.owner.owner_id,task_id:f.task.task_id,
        operation_digest:operationDigest(f.operation),request_uuid:f.binding.request_uuid,
        request_digest:inferenceRequestDigest(f.binding)})
      return await consume(clone(TEST_ONLY_committedAdmission))
    },
    dispatchCommitted(admission,claimed) {
      assert.equal(f.held,1);assert.deepEqual(admission,TEST_ONLY_committedAdmission)
      assert.deepEqual(claimed,{ok:true,status:'DISPATCHED',consumed_grant:admission.consumed_grant,
        request_id:admission.request_uuid,request_digest:admission.request_digest})
      dispatches++;return {TEST_ONLY:true,provider_http:false}
    },
    async withCommittedSettlement(_method,lookup,consume) {
      settlementReads++;assert.equal(lookup.receipt_digest,TEST_ONLY_committedSettlement.receipt_digest)
      return await consume(clone(TEST_ONLY_committedSettlement))
    }}
  const connect=()=>{
    const connection=createInferenceAuthorityConnection(connectionConfig);connections.push(connection);return connection
  }

  // A changed original configuration preimage is rejected before any listener
  // or C authority consumption; the genuine store and witness stay untouched.
  const beforeBadConfig=await persisted(),badConfig=clone(authorityConfig)
  badConfig.inferenceProfile.contexts[0].original_config.pricing.input_microusd_per_token++
  await assert.rejects(startInferenceAuthorityWorker(workerConfig(badConfig)),
    error=>error instanceof TypeError&&error.message.includes('approved inference configuration bytes/rates mismatch'))
  assert.deepEqual(await persisted(),beforeBadConfig)

  const workerA=await startInferenceAuthorityWorker(workerConfig(authorityConfig));workers.push(workerA)
  const connectionA=connect()
  const challenge=accepted(await connectionA.authority.loginChallenge({owner_id:f.owner.owner_id,kind:'passkey'}))
  const session=accepted(await connectionA.authority.loginComplete({challenge:challenge.challenge,
    material:auth.assertion(challenge.public_key.challenge)})).session_token
  assert.equal(accepted(await connectionA.authority.authenticateSession({session_token:session})).subject,f.owner.subject)

  const beforeInvalid=await persisted(),nested=clone(f.operation)
  nested.operation_id='TEST_ONLY-wrong-nested-task'
  nested.canonical_parameters.binding.conversation_id='TEST_ONLY-unregistered-conversation'
  nested.canonical_parameters.request_digest=inferenceRequestDigest(nested.canonical_parameters.binding)
  const nestedRefusal=await direct('propose',{session_token:session,operation:nested},nested)
  assert.equal(nestedRefusal.ok,false)
  assert.deepEqual(await persisted(),beforeInvalid)
  const differentGeneration=clone(f.operation),changedRoute={...clone(f.facts.route),credential_generation:2}
  const changedState=inferenceBudgetState({owner:f.owner,route:changedRoute,total_budget:f.facts.total_budget,credential_generation:2})
  differentGeneration.operation_id='TEST_ONLY-wrong-protected-target'
  differentGeneration.target_identity=clone(changedState.target_identity)
  differentGeneration.expected_state_version=changedState.state_version
  differentGeneration.canonical_parameters.binding.credential_generation=2
  differentGeneration.canonical_parameters.request_digest=inferenceRequestDigest(differentGeneration.canonical_parameters.binding)
  const targetRefusal=await direct('propose',{session_token:session,operation:differentGeneration},differentGeneration)
  assert.equal(targetRefusal.ok,false);assert.equal(targetRefusal.error_code,'INVALID')
  assert.match(targetRefusal.reason,/inference policy\/state binding mismatch/)
  assert.deepEqual(await persisted(),beforeInvalid)

  assert.equal(accepted(await connectionA.authority.propose({session_token:session,operation:f.operation})).status,'PROPOSED')
  reviewed=accepted(await connectionA.authority.approvalChallenge({session_token:session,operation:f.operation}))
  approved=accepted(await connectionA.authority.approvalComplete({session_token:session,
    proof:{...reviewed.proof_template,material:auth.assertion(reviewed.public_key.challenge)}}))
  assert.equal(approved.status,'APPROVED');assert.equal(approved.approval_proof.material.kind,'passkey')
  const admission=await connectionA.authorizeDispatch(f.binding)
  assert.equal(Object.keys(admission).length,15);assert.equal(reviewReads,1)
  assert.notEqual(admission.consumed_grant.grant_id,f.grant.grant_id)
  assert.equal(admission.consumed_grant.grant_id,'grant:'+approved.approval_proof.nonce)
  const prepared=await record(),preparedRow=onlyRow(prepared)
  assert.equal(preparedRow.status,'PREPARED')
  assert.deepEqual(preparedRow.inference_context.original_config,originalContext.original_config)
  assert.deepEqual(preparedRow.grant,admission.consumed_grant)
  assert.deepEqual(prepared.state.consumedIds,['approval:'+approved.approval_proof.nonce])
  assert.equal(prepared.prepared.length,1)
  assert.equal(prepared.prepared[0].consumptionId,'approval:'+approved.approval_proof.nonce)
  assert.equal(prepared.prepared[0].effectId,admission.consumed_grant.reservation_id.slice('prepared:'.length))
  assert.equal(prepared.prepared[0].contentHash,operationDigest(f.operation).slice(7))
  assert(prepared.state.receiptHead.count>0)
  await assert.rejects(connectionA.authorizeDispatch(f.binding),rejected('RECONCILIATION_REQUIRED'))
  assert.equal(reviewReads,1)

  TEST_ONLY_committedAdmission=clone(admission)
  const claim=claimOf(admission),forgedClaim={...clone(claim),consumed_grant:{...clone(claim.consumed_grant),grant_id:'TEST_ONLY-forged-grant'}}
  const beforeForgedClaim=await persisted()
  assert.equal((await direct('claimDispatch',forgedClaim,f.operation,observationOf(f))).ok,false)
  assert.deepEqual(await persisted(),beforeForgedClaim);assert.equal(dispatches,0)
  assert.deepEqual(await connectionA.withDispatch(claim),{TEST_ONLY:true,provider_http:false})
  assert.equal(dispatches,1);assert.equal(intentReads,1);assert.equal(f.held,0)
  await assert.rejects(connectionA.withDispatch(claim),rejected('RECONCILIATION_REQUIRED'))
  const duplicateClaim=await direct('claimDispatch',claim,f.operation,observationOf(f))
  assert.equal(duplicateClaim.ok,false);assert.equal(duplicateClaim.error_code,'REPLAYED')
  assert.equal(dispatches,1);assert.equal(intentReads,1)
  const dispatched=await record()
  assert.equal(onlyRow(dispatched).status,'DISPATCHED')
  assert.deepEqual(dispatched.state.consumedIds,prepared.state.consumedIds)
  assert.deepEqual(dispatched.state.receiptHead,prepared.state.receiptHead)

  accepted(await connectionA.authority.logoutSession({session_token:session}))
  assert.equal((await connectionA.authority.authenticateSession({session_token:session})).ok,false)
  const unknown=receiptOf(f,admission,'outcome_unknown'),completed=receiptOf(f,admission,'completed')
  // Genuine C, rather than the TEST_ONLY outbox adapter, rejects altered receipt
  // identities and wrong actual cost while preserving dispatch/kernel history.
  for(const alter of [x=>{x.receipt.body_sha256='f'.repeat(64)},x=>{x.receipt.usage.cost_microusd++}]) {
    const wrong=clone(completed);alter(wrong);wrong.receipt_digest=inferenceEffectReceiptDigest(wrong.receipt)
    const beforeWrongReceipt=await persisted()
    const refusal=await direct('settleInference',wrong,f.operation)
    assert.equal(refusal.ok,false);assert.equal(refusal.error_code,'INVALID')
    assert.deepEqual(await persisted(),beforeWrongReceipt)
  }
  const readsBeforeFacts=f.reads
  f.facts.credential_generation=2;f.facts.total_budget.ceiling.amount='1'
  TEST_ONLY_committedSettlement=clone(unknown)
  const unknownReply=await connectionA.settleInference(unknown)
  assert.equal(unknownReply.status,'OUTCOME_UNKNOWN');assert.equal(unknownReply.idempotent,false)
  assert.equal(unknownReply.reconciliation_required,true);assert.equal(f.reads,readsBeforeFacts)
  const heldUnknown=await record(),unknownRow=onlyRow(heldUnknown)
  assert.equal(unknownRow.status,'OUTCOME_UNKNOWN')
  assert.deepEqual(unknownRow.operation,f.operation);assert.deepEqual(unknownRow.grant,admission.consumed_grant)
  assert.deepEqual(unknownRow.dispatch.receipt,unknown.receipt)
  assert.deepEqual(unknownRow.inference_context.original_config,originalContext.original_config)

  // Restart C only, with the same state/witness and no current Task admission.
  // Its current valid profile has changed generation/budget; factual evidence
  // must still use the original durable approved context, without live reads.
  connectionA.dispose();await workerA.close()
  const changedConfig=clone(authorityConfig)
  changedConfig.inferenceProfile.contexts[0].route.credential_generation=2
  changedConfig.inferenceProfile.contexts[0].total_budget.ceiling.amount='1.000000'
  const beforeRestart=await persisted()
  const workerB=await startInferenceAuthorityWorker(workerConfig(changedConfig,[]));workers.push(workerB)
  assert.deepEqual(await persisted(),beforeRestart)
  const connectionB=connect(),duplicateUnknown=await connectionB.settleInference(unknown)
  assert.equal(duplicateUnknown.status,'OUTCOME_UNKNOWN');assert.equal(duplicateUnknown.idempotent,true)
  assert.deepEqual(await persisted(),beforeRestart)
  TEST_ONLY_committedSettlement=clone(completed)
  await assert.rejects(connectionB.settleInference(completed),rejected('STALE'))
  assert.deepEqual(await persisted(),beforeRestart)
  const completion=await connectionB.reconcileInferenceSettlement(completed)
  assert.equal(completion.status,'COMPLETED');assert.equal(completion.idempotent,false)
  assert.equal(completion.reconciliation_required,false);assert.equal(completion.receipt_digest,completed.receipt_digest)
  const terminal=await record(),terminalRow=onlyRow(terminal)
  assert.equal(terminalRow.status,'COMPLETED')
  assert.equal(terminalRow.schema,'prime-terminal-operation-v1')
  assert.equal(terminalRow.dispatch.evidence_kind,'inference')
  assert.equal(terminalRow.dispatch.result_digest,completed.receipt.result_digest)
  assert.deepEqual(terminalRow.dispatch.settlement_digests,[unknown.receipt_digest,completed.receipt_digest])
  assert(!Object.hasOwn(terminalRow,'operation'));assert(!Object.hasOwn(terminalRow,'inference_context'))
  assert.deepEqual(terminal.state.consumedIds,prepared.state.consumedIds)
  assert.deepEqual(terminal.state.receiptHead,prepared.state.receiptHead)
  assert.deepEqual(terminal.prepared,prepared.prepared)
  assert.equal(terminal.broker.store_id,prepared.broker.store_id)
  const beforeDuplicates=await persisted()
  assert.equal((await connectionB.reconcileInferenceSettlement(completed)).idempotent,true)
  TEST_ONLY_committedSettlement=clone(unknown)
  const oldUnknown=await connectionB.settleInference(unknown)
  assert.equal(oldUnknown.status,'OUTCOME_UNKNOWN');assert.equal(oldUnknown.idempotent,true)
  assert.equal(onlyRow(await record()).status,'COMPLETED')
  assert.deepEqual(await persisted(),beforeDuplicates)
  assert.equal(f.reads,readsBeforeFacts);assert.equal(dispatches,1);assert.equal(settlementReads,6)
})
