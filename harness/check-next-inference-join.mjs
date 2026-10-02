// SPDX-License-Identifier: AGPL-3.0-or-later
// ONE TEST_ONLY source smoke: genuine C synthetic-passkey approval/private IPC,
// actual E reserve fence/continuation/outbox and pinned DSH stream, with one
// explicitly mock provider reply. Production-shaped admission is NOT a paid call.
// Same-UID local IPC is not isolation or runtime qualification. No provider
// network, real owner credentials, vault, public route or installed app is used.
// SeparatedCredentialService is unsupported on Mac and is not bypassed here.
// Trusted policy/observation remain fixtures and custody is unexercised. The E
// lifecycle is shared with that service; no native UI or installed join is mounted.
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {randomBytes} from 'node:crypto'
import {chmod,mkdtemp,readFile,realpath,rm,writeFile} from 'node:fs/promises'
import {createRequire} from 'node:module'
import {isAbsolute,join,resolve} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {operationDigest} from '../packages/contracts/src/runtime.mjs'
import {parseInferenceOperation,parseInferenceAdmission} from '../packages/authority/src/inference-admission.mjs'
import {authorityFixture} from '../packages/runtime-bridge/test/authority-fixture.mjs'
import {fixture as policyFixture} from '../packages/runtime-bridge/checks/inference-fixture.mjs'
import {createTrustedTaskRegistry} from '../packages/runtime-bridge/src/registry.mjs'
import {createTrustedInferenceObserver,createInferenceAuthorityConnection,
  startInferenceAuthorityWorker} from '../packages/runtime-bridge/src/inference.mjs'
import {SpendLedger} from '../packages/inference/src/ledger.mjs'
import {ExternalDeepSeekGateway,MockDeepSeekProvider} from '../packages/inference/src/gateway.mjs'
import {RemoteDeepSeekProvider} from '../packages/inference/src/remote-provider.mjs'
import {mountDshInference} from '../packages/inference/src/dsh-adapter.mjs'
import {verifyPrivateDispatch} from '../packages/inference/src/dispatch-policy.mjs'
import {WorkerDispatchContinuation,reviewedReserveAttempt,
  withCommittedWorkerSettlement} from '../packages/inference/src/worker-continuation.mjs'

const accepted=reply=>{assert.equal(reply?.ok,true,JSON.stringify(reply));return reply}
const refused=code=>error=>error.code===code||error.error_code===code
const flat=intent=>({...intent.binding,operation:intent.operation,
  consumed_grant:intent.consumed_grant,request_digest:intent.request_digest})
const lookupOf=intent=>({owner_id:intent.task.owner_id,task_id:intent.task.task_id,
  operation_digest:operationDigest(intent.operation),request_uuid:intent.request_id,request_digest:intent.request_digest})

test('NEXT pinned DSH mock reply uses genuine C approval, Bridge and E continuation across dropped acknowledgement and reopen',
  {timeout:30000},async t=>{
  const resultFile=process.env.PRIME_NEXT_PILOT_RESULT_FILE
  if(resultFile!==undefined)assert(isAbsolute(resultFile)&&resolve(resultFile)===resultFile,
    'PRIME_NEXT_PILOT_RESULT_FILE must be an absolute normalized new file path')
  const dshRoot=process.env.PRIME_PINNED_DSH_DIR??fileURLToPath(new URL('../vendor/dsh',import.meta.url))
  assert(isAbsolute(dshRoot),'PRIME_PINNED_DSH_DIR must name the verified absolute pinned harness')
  const dshEntry=join(dshRoot,'packages/llm/llm/lib/index.js'),requireDsh=createRequire(dshEntry)
  const dshPackage=JSON.parse(await readFile(join(dshRoot,'packages/llm/llm/package.json'),'utf8'))
  assert.equal(dshPackage.name,'@deepseek-ai/dsh-llm');assert.equal(dshPackage.version,'0.1.6-alpha.1')
  assert.equal(JSON.parse(await readFile(join(dshRoot,'vendor/cordis/package.json'),'utf8')).version,'4.0.2')
  const dsh=await import(pathToFileURL(dshEntry).href)
  const {Context}=await import(pathToFileURL(requireDsh.resolve('@deepseek-ai/cordis')).href)
  const root=await realpath(await mkdtemp(join(await realpath('/tmp'),'prime-join-')))
  await chmod(root,0o700)
  const channelSecret=randomBytes(32),socketPath=join(root,'c.sock')
  assert(Buffer.byteLength(socketPath)<=103)
  let ledger,appLedger,worker,connection,continuation,dshContext
  t.after(async()=>{
    connection?.dispose()
    try{await dshContext?.fiber.dispose()}finally{
      try{await worker?.close()}finally{
        try{ledger?.close()}finally{
          try{appLedger?.close()}finally{
            channelSecret.fill(0);await rm(root,{recursive:true,force:true})
          }
        }
      }
    }
  })
  // Select only policy material. Never use this fixture's fake proof/grant.
  const {owner,task,operation,binding,facts,registryEntries}=policyFixture({
    owner:{owner_id:'synthetic-owner',subject:'aukora:1:'+'a'.repeat(64)}})
  const ledgerPath=join(root,'worker-spend.sqlite'),appLedgerPath=join(root,'app-spend.sqlite')
  const scope=[owner.owner_id,task.task_id,binding.request_uuid]
  ledger=new SpendLedger(ledgerPath,{total_budget:facts.total_budget})
  appLedger=new SpendLedger(appLedgerPath,{total_budget:facts.total_budget})
  // Distinct app/worker stores account for the same request, never two provider calls.
  ledger.register(facts.local_task,facts.route);appLedger.register(facts.local_task,facts.route)
  const registry=createTrustedTaskRegistry(registryEntries)
  const auth=authorityFixture({root,audience:operation.audience,authorizeTask:registry.authorizeTask,
    observeTarget:()=>({target_identity:operation.target_identity,state_version:operation.expected_state_version}),
    policy:{version:operation.policy_version,actions:['inference.generate'],agents:[task.agent_id],
      data_scope:['conversation'],maximum_cost:{currency:'USD',amount:'0.010000'}},
    inferenceProfile:{contexts:[{route:facts.route,local_task:facts.local_task,
      total_budget:facts.total_budget,original_config:facts.configuration.payload}]}})
  assert.deepEqual({owner_id:auth.identity.owner_id,subject:auth.identity.subject},owner)
  const {authorizeTask:_task,observeTarget:_target,...configured}=auth.config
  const authorityConfig={...configured,provisionTrustedState:false}
  const credential={id:'TEST_ONLY_next_inference',secret:channelSecret.toString('hex')}
  const limits={handshakeTimeoutMs:1000,idleTimeoutMs:5000,requestTimeoutMs:3000}
  const authorityChannel={socketPath,credential,limits}
  const start=entries=>startInferenceAuthorityWorker({kind:'inference-authority',registryEntries:entries,
    authorityConfig,ipc:{socketPath,credentials:[{...credential,role:'inference_effect'}],limits}})
  const record=async()=>JSON.parse(await readFile(auth.config.statePath,'utf8'))
  const persisted=async()=>({state:await readFile(auth.config.statePath,'utf8'),
    witness:await readFile(join(auth.config.witnessDir,'kernel-high-water.json'),'utf8')})
  const onlyRow=state=>{const rows=Object.values(state.broker.operations);assert.equal(rows.length,1);return rows[0]}
  let held=0,observations=0,reviewReads=0,reservePairs=0,claims=0,providerCalls=0,settlementCalls=0
  let reviewed,approved,privateRequest,admission,preparedState,firstAck,rawReply
  const observer=createTrustedInferenceObserver({registryEntries,ownerMappings:[owner],
    async withQualifiedState(lookup,consume){
      assert.deepEqual(lookup,{owner_id:owner.owner_id,task_id:task.task_id})
      observations++;held++
      try{return await consume({...structuredClone(facts),total_budget:ledger.storedTotalBudget()})}
      finally{held--}
    }})
  const verify=snapshot=>verifyPrivateDispatch(snapshot,facts.route,facts.local_task,
    {owner,total_budget:ledger.storedTotalBudget(),credential_generation:facts.credential_generation})
  const mock=new MockDeepSeekProvider(),signal=new AbortController().signal
  const createContinuation=()=>new WorkerDispatchContinuation({ledger,observe:verify,
    async generate(request){
      assert.equal(held,1);assert.equal(ledger.workerIntent(...scope).phase,'http_started')
      providerCalls++;rawReply=await mock.generate(request)
      assert.equal(held,1);return rawReply
    },
    withDispatch:claim=>connection.withDispatch(claim),
    async retrySettlement(ownerId,taskId,uuid){
      assert.equal(held,0);assert.deepEqual([ownerId,taskId,uuid],scope)
      const pending=ledger.pendingWorkerSettlement(...scope);assert(pending)
      const reads=observations
      firstAck=await connection[pending.method](pending.payload);settlementCalls++
      assert.equal(observations,reads,'factual delivery must not reobserve current policy')
      // Simulate a reply received but lost before E commits its acknowledgement.
      // This is deliberately not an IPC transport-failure or process-crash test.
    }})
  const connectionConfig={authorityChannel,observer,
    async getReviewedApproval(candidate){
      const pair=await reviewedReserveAttempt(ledger,candidate,async checked=>{
        assert.deepEqual(checked,binding);assert.equal(approved?.ok,true);reviewReads++
        // Use the real C narrower parser, never a broad-type cast or fake proof.
        return {operation:parseInferenceOperation(reviewed.operation),approval_proof:approved.approval_proof}
      })
      assert(ledger.reserveAttempt(...scope),'attempt must commit before Bridge receives the reviewed pair')
      reservePairs++;return pair
    },
    async withCommittedIntent(lookup,consume){
      const stored=ledger.workerIntent(...scope)
      assert.deepEqual(lookup,lookupOf(stored.intent))
      assert.equal(stored.phase,'intent_committed')
      assert.equal(ledger.get(...scope).charged_cost,binding.reserved_cost_microusd)
      assert.equal(ledger.get(...scope).charged_tokens,binding.reserved_tokens)
      return continuation.withCommittedIntent(lookup,value=>{
        assert.equal(ledger.workerIntent(...scope).phase,'claim_started')
        return consume(parseInferenceAdmission(value))
      })
    },
    async dispatchCommitted(admission,claim){
      assert.equal(held,1);assert.deepEqual(admission,flat(ledger.workerIntent(...scope).intent))
      claims++
      const reply=await continuation.dispatchCommitted(parseInferenceAdmission(admission),claim)
      assert.equal(held,1);assert.equal(ledger.workerIntent(...scope).phase,'outcome_recorded')
      assert(ledger.pendingWorkerSettlement(...scope),'evidence/outbox commits before the observation releases')
      return reply
    },
    withCommittedSettlement:(method,lookup,consume)=>withCommittedWorkerSettlement(ledger,method,lookup,consume)}
  continuation=createContinuation()
  worker=await start(registryEntries)
  connection=createInferenceAuthorityConnection(connectionConfig)
  const challenge=accepted(await connection.authority.loginChallenge({owner_id:owner.owner_id,kind:'passkey'}))
  const session=accepted(await connection.authority.loginComplete({challenge:challenge.challenge,
    material:auth.assertion(challenge.public_key.challenge)})).session_token
  assert.equal(accepted(await connection.authority.authenticateSession({session_token:session})).subject,owner.subject)
  accepted(await connection.authority.propose({session_token:session,operation}))
  reviewed=accepted(await connection.authority.approvalChallenge({session_token:session,operation}))
  approved=accepted(await connection.authority.approvalComplete({session_token:session,
    proof:{...reviewed.proof_template,material:auth.assertion(reviewed.public_key.challenge)}}))
  const sourceRequest={owner_id:owner.owner_id,task_id:task.task_id,
    conversation_id:task.conversation_id,request_uuid:binding.request_uuid,max_output_tokens:256,
    fragments:[{owner_id:owner.owner_id,task_id:task.task_id,conversation_id:task.conversation_id,
      data_class:'conversation',role:'user',text:'Public synthetic source check.'}]}
  const proxy=new RemoteDeepSeekProvider({dispatch:(request,options)=>{
    privateRequest=structuredClone(request)
    return continuation.dispatch(request,options)
  }})
  const gateway=new ExternalDeepSeekGateway({route:facts.route,ledger:appLedger,request_home:join(root,'app-requests'),
    provider:proxy,authorize_dispatch:async candidate=>{
      admission=parseInferenceAdmission(await connection.authorizeDispatch(candidate))
      assert.equal(admission.consumed_grant.grant_id,'grant:'+approved.approval_proof.nonce)
      preparedState=await record()
      assert.equal(onlyRow(preparedState).status,'PREPARED')
      assert.deepEqual(preparedState.state.consumedIds,['approval:'+approved.approval_proof.nonce])
      assert.equal(preparedState.prepared.length,1);assert.equal(reviewReads,1);assert.equal(reservePairs,1)
      assert.equal(preparedState.prepared[0].effectId,admission.consumed_grant.reservation_id.slice(9))
      assert.equal(ledger.get(...scope),undefined,'reserve attempt must not charge worker allowance')
      return admission
    }})
  dshContext=new Context();await dshContext.plugin(dsh.default)
  const adapter=mountDshInference(dshContext,dsh.LlmAdapter,{gateway,
    bindRequest:()=>structuredClone(sourceRequest),attributionHeaders:dsh.attributionHeaders})
  assert(adapter instanceof dsh.LlmAdapter);assert.equal(adapter.providerRetryPolicy('externalDeepSeek').maxRetries,0)
  const chunks=[]
  for await(const chunk of dshContext.llm.stream({provider:'externalDeepSeek',model:facts.route.model,
    messages:[],tools:[],sessionId:task.conversation_id,maxTokens:256,signal}))chunks.push(chunk)
  assert.deepEqual(chunks.map(chunk=>chunk.type),['block-start','text-delta','block-end','usage','finish'])
  assert.equal(chunks[1].text,'Mock sourced note.')
  const result=appLedger.get(...scope).result
  assert.equal(result.outcome,'completed');assert.equal(result.proposal.grantsAuthority,false)
  // Preserve the actual gateway metadata; this fixture's provider remains MockDeepSeekProvider.
  assert.equal(result.mode,'production');assert.equal(result.receipt.body_sha256,binding.body_sha256)
  const finish=chunks.at(-1).replayState.response.aukora_prime
  assert.equal(finish.mode,result.mode);assert.equal(finish.request_uuid,binding.request_uuid)
  assert.equal(finish.body_sha256,binding.body_sha256);assert.equal(finish.owner_id,owner.owner_id)
  assert.equal(finish.task_id,task.task_id);assert.equal(finish.conversation_id,task.conversation_id)
  assert.equal(finish.config_digest,binding.config_digest);assert.equal(finish.total_budget_id,binding.total_budget_id)
  assert.equal(finish.grants_authority,false);assert.deepEqual(finish.usage,result.usage)
  assert.equal(JSON.stringify(chunks.at(-1).replayState).includes(sourceRequest.fragments[0].text),false)
  const claim={operation,consumed_grant:admission.consumed_grant,request_id:binding.request_uuid,request_digest:admission.request_digest}
  assert.equal(held,0);assert.equal(claims,1);assert.equal(providerCalls,1);assert.equal(continuation.activeCount,0)
  assert.deepEqual(ledger.workerIntent(...scope).claim_reply,{ok:true,status:'DISPATCHED',
    consumed_grant:claim.consumed_grant,request_id:claim.request_id,request_digest:claim.request_digest})
  const completed=ledger.get(...scope),pending=ledger.pendingWorkerSettlement(...scope)
  const actualCost=rawReply.input_tokens*facts.route.input_microusd_per_token+rawReply.output_tokens*facts.route.output_microusd_per_token
  assert.equal(completed.status,'completed');assert.equal(completed.charged_cost,actualCost)
  assert.equal(completed.charged_tokens,rawReply.input_tokens+rawReply.output_tokens)
  assert.equal(completed.reserved_cost,binding.reserved_cost_microusd);assert(actualCost<completed.reserved_cost)
  assert.equal(ledger.totalUsage(owner.owner_id,facts.total_budget.budget_id).cost_microusd,actualCost)
  assert.equal(ledger.totalUsage(owner.owner_id,facts.total_budget.budget_id).requests,1)
  assert.equal(pending.payload.receipt.usage.cost_microusd,actualCost)
  assert.equal(pending.payload.receipt.reservation_retained,false)
  assert.equal(completed.result.receipt_digest,pending.payload.receipt_digest)
  assert.equal(appLedger.get(...scope).charged_cost,actualCost);assert.deepEqual(result.usage,pending.payload.receipt.usage)
  assert.equal(appLedger.totalUsage(owner.owner_id,facts.total_budget.budget_id).requests,1)
  await assert.rejects(connection.authorizeDispatch(binding),refused('RECONCILIATION_REQUIRED'))
  await assert.rejects(connection.withDispatch(claim),refused('RECONCILIATION_REQUIRED'))
  await assert.rejects(continuation.dispatch(privateRequest),refused('REQUEST_ALREADY_RESERVED'))
  const readsBeforeSettlement=observations
  assert.equal(settlementCalls,1)
  assert.equal(firstAck.status,'COMPLETED');assert.equal(firstAck.idempotent,false)
  assert.equal(firstAck.receipt_digest,pending.payload.receipt_digest)
  const terminal=await record(),terminalRow=onlyRow(terminal)
  assert.equal(terminalRow.status,'COMPLETED');assert.equal(terminalRow.dispatch.evidence_kind,'inference')
  assert.equal(terminalRow.dispatch.receipt_digest,pending.payload.receipt_digest)
  assert.equal(terminalRow.dispatch.result_digest,pending.payload.receipt.result_digest)
  assert.deepEqual(terminal.state,preparedState.state);assert.deepEqual(terminal.prepared,preparedState.prepared)
  const attempt=ledger.reserveAttempt(...scope)
  assert.deepEqual(Object.keys(attempt).sort(),['binding','operation_digest','operation_id','request_digest'])
  assert.equal(attempt.operation_digest,operationDigest(operation));assert.deepEqual(attempt.binding,binding)
  // Gracefully close/reopen C, the connection and E ledgers in this process.
  accepted(await connection.authority.logoutSession({session_token:session}))
  const beforeRestart=await persisted()
  connection.dispose();connection=null;await worker.close();worker=null
  ledger.close();ledger=null;ledger=new SpendLedger(ledgerPath)
  appLedger.close();appLedger=null;appLedger=new SpendLedger(appLedgerPath)
  continuation=createContinuation()
  worker=await start([]);connection=createInferenceAuthorityConnection(connectionConfig)
  assert.equal((await connection.authority.authenticateSession({session_token:session})).ok,false)
  assert.deepEqual(ledger.pendingWorkerSettlement(...scope),pending)
  assert.deepEqual(ledger.reserveAttempt(...scope),attempt)
  const repeated=await connection.settleInference(ledger.pendingWorkerSettlement(...scope).payload)
  assert.equal(repeated.status,'COMPLETED');assert.equal(repeated.idempotent,true)
  assert.equal(repeated.receipt_digest,pending.payload.receipt_digest)
  ledger.acknowledgeWorkerSettlement(...scope,pending.payload.receipt_digest,repeated)
  assert.equal(ledger.pendingWorkerSettlement(...scope),null)
  assert.deepEqual(await persisted(),beforeRestart)
  assert.deepEqual(ledger.get(...scope),completed)
  assert.deepEqual(appLedger.get(...scope).result,result)
  // Fresh Bridge latches cannot repeat either reserve or the durable completed dispatch.
  await assert.rejects(connection.authorizeDispatch(binding),refused('RESERVE_ATTEMPT_RETAINED'))
  await assert.rejects(continuation.dispatch(privateRequest),refused('REQUEST_ALREADY_RESERVED'))
  assert.deepEqual(await persisted(),beforeRestart)
  assert.equal(observations,readsBeforeSettlement)
  assert.equal(reviewReads,2);assert.equal(reservePairs,1);assert.equal(claims,1);assert.equal(providerCalls,1)
  assert.equal(continuation.activeCount,0)
  if(resultFile!==undefined)await writeFile(resultFile,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600})
  t.diagnostic('Pinned DSH/Cordis, actual C synthetic approval/IPC, and E shared reserve fence/continuation/accounting/outbox; one MockDeepSeekProvider reply. Production-shaped metadata is unchanged, not real inference. Acknowledgement commit omitted; graceful same-process reopen only. No separated service, custody, enrollment, native UI or runtime qualification.')
})
