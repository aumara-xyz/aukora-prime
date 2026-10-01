// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual C owner proof/kernel/store and F lifecycle join in disposable state.
// Only F's explicitly test-only admission subclass and SDK protocol are mocked.
// No live gateway, guest, owner enrollment, UID isolation or runtime qualification.
import assert from 'node:assert/strict'
import {generateKeyPairSync,sign} from 'node:crypto'
import {mkdtempSync,mkdirSync,readFileSync,realpathSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {createAuthorityService,provisionNewAuthorityStore,loginSigningBytes,approvalSigningBytes} from '../../authority/src/index.mjs'
import {didKeyFromEd25519PublicKey} from '../../authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import {operationDigest} from '../../contracts/src/runtime.mjs'
import {OwnedLedger,executorRequestDigest} from '../../execution/src/index.mjs'
import {settings,request,fixture,MockedProtocolExecutor} from '../../execution/checks/harness.mjs'
import {createTrustedTaskRegistry} from '../src/registry.mjs'

const roots=[],ledgers=new Set()
let checks=0
const clone=structuredClone
const accepted=value=>{assert.equal(value.ok,true,JSON.stringify(value));return value}
const count=(f,name)=>f.protocol.calls.filter(([method])=>method===name).length
async function check(label,run){await run();checks++;console.log('PASS '+label)}
function closeLedger(ledger){ledger.close();ledgers.delete(ledger)}

function authorityFixture() {
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-bridge-execution-c-'));roots.push(root)
  const stateRoot=join(root,'state');mkdirSync(stateRoot,{mode:0o700})
  const r=request(),keys=generateKeyPairSync('ed25519')
  const publicHex=Buffer.from(keys.publicKey.export({format:'jwk'}).x,'base64url').toString('hex')
  const identity={owner_id:r.operation.owner_id,subject:'aukora:1:'+'1'.repeat(64),
    approval_key_did:didKeyFromEd25519PublicKey(publicHex),control_digest:'2'.repeat(64),authorization_epoch:r.operation.authorization_epoch}
  const task={version:1,task_id:r.operation.task_id,owner_id:identity.owner_id,agent_id:r.operation.agent_id,
    conversation_id:'synthetic-conversation',status:'running',created_at:new Date().toISOString(),route_id:null,
    allowed_data_classes:['public'],max_input_tokens:0,max_output_tokens:0,max_requests:0,
    task_spend_ceiling:{currency:'USD',amount:'0'}}
  const registry=createTrustedTaskRegistry([{task,provider_and_region:r.operation.provider_and_region,
    audience:r.operation.audience,policy_version:r.operation.policy_version,data_scope:['public']}])
  const target=clone(r.operation.target_identity),stateVersion=r.operation.expected_state_version
  const config={stateRoot,statePath:join(stateRoot,'authority.json'),witnessDir:join(root,'witness'),
    audience:r.operation.audience,identities:[identity],loginKinds:['owner_key'],provisionTrustedState:true,
    policy:{version:r.operation.policy_version,actions:['shell.bash.foreground'],agents:[task.agent_id],
      data_scope:['public'],maximum_cost:{currency:'USD',amount:'0'}},
    authorizeTask:registry.authorizeTask,
    observeTarget:()=>({target_identity:clone(target),state_version:stateVersion})}
  accepted(provisionNewAuthorityStore(config))
  const service=createAuthorityService(config)
  const challenge=accepted(service.loginChallenge({owner_id:identity.owner_id,kind:'owner_key'})).challenge
  const token=accepted(service.loginComplete({challenge,
    material:{kind:'owner_key',signature:sign(null,loginSigningBytes(challenge),keys.privateKey).toString('hex')}})).session_token
  accepted(service.propose({session_token:token,operation:r.operation}))
  const review=accepted(service.approvalChallenge({session_token:token,operation:r.operation}))
  const proof={...review.proof_template,material:{kind:'owner_key',request:review.approval_request,
    signature:sign(null,approvalSigningBytes(review.approval_request),keys.privateKey).toString('hex')}}
  accepted(service.approvalComplete({session_token:token,proof}))
  const reserved=accepted(service.reserve({operation:r.operation,approval_proof:proof}))
  assert.equal(reserved.status,'PREPARED');r.consumed_grant=reserved.consumed_grant
  const state=JSON.parse(readFileSync(config.statePath,'utf8'))
  assert(state.state.consumedIds.includes('approval:'+proof.nonce))
  assert(state.prepared.some(row=>row.consumptionId==='approval:'+proof.nonce))
  // Private signing keys stay in this helper and are never passed to F.
  return {r,service,token,config,
    status:(current=service)=>accepted(current.status({session_token:token,operation_id:r.operation.operation_id})),
    restart:()=>createAuthorityService({...config,provisionTrustedState:false})}
}
function tracedBroker(service,calls,hooks={}) {
  return Object.fromEntries(['claimDispatch','requestCancel','settle','reconcileSettlement'].map(method=>[method,async input=>{
    const value=service[method](input)
    calls.push({method,input:clone(input),value:clone(value)})
    await hooks[method]?.(value,input)
    return value
  }]))
}
async function joined(options={},hooks={}) {
  const authority=authorityFixture(),calls=[]
  const f=await fixture(options,{broker:tracedBroker(authority.service,calls,hooks)})
  roots.push(f.root);ledgers.add(f.ledger)
  return {...f,authority,calls}
}
const claimBinding=r=>({operation:r.operation,consumed_grant:r.consumed_grant,
  request_id:r.request_id,request_digest:executorRequestDigest(r)})

try {
  await check('real approved C reservation is claimed once by F and settles C COMPLETED',async()=>{
    const f=await joined(),r=f.authority.r
    assert.equal(f.authority.status().status,'PREPARED')
    const receipt=await f.executor.execute(r)
    assert.equal(receipt.status,'completed');assert.equal(receipt.exit_code,0)
    assert.equal(receipt.rpc_completion,'complete');assert.equal(receipt.cleanup,'confirmed_absent')
    assert.deepEqual(f.calls.map(row=>row.method),['claimDispatch','settle'])
    assert.equal(f.calls[0].value.status,'DISPATCHED');assert.equal(f.calls[1].value.status,'COMPLETED')
    assert.equal(f.authority.status().status,'COMPLETED')
    assert.equal(count(f,'create'),1);assert.equal(count(f,'exec'),1)
    assert.equal(f.executor.availability().runtimeEnforcementVerified,false)
    assert.equal(f.executor.availability().protocol,'mocked')
    assert.equal(f.executor.availability().runtime,'unavailable')
  })

  await check('altered operation and changed grant are refused before mocked SDK creation',async()=>{
    const f=await joined(),altered=clone(f.authority.r)
    altered.operation.canonical_parameters.command='different synthetic inert command'
    await assert.rejects(f.executor.execute(altered),error=>error.code==='UNAUTHORIZED')
    assert.equal(f.calls.length,0);assert.equal(count(f,'create'),0)
    // An internally consistent new digest still cannot replace C's exact review.
    altered.consumed_grant.operation_digest=operationDigest(altered.operation)
    await assert.rejects(f.executor.execute(altered),error=>['TARGET_MISMATCH','INVALID','UNAUTHORIZED'].includes(error.code))
    assert.equal(f.calls.length,1);assert.equal(f.calls[0].method,'claimDispatch')
    assert.equal(f.calls[0].value.ok,false);assert.equal(f.authority.status().status,'PREPARED')
    assert.equal(count(f,'create'),0);assert.equal(count(f,'exec'),0)
    const g=await joined(),changed=clone(g.authority.r)
    changed.consumed_grant.prepared_at=new Date(Date.now()-10_000).toISOString()
    await assert.rejects(g.executor.execute(changed),error=>error.code==='UNAUTHORIZED')
    assert.equal(g.calls[0].value.reason,'EXACT_CONSUMED_GRANT_REQUIRED')
    assert.equal(g.authority.status().status,'PREPARED');assert.equal(count(g,'create'),0)
  })

  await check('grant replay across the same and fresh F ledger never launches twice',async()=>{
    const f=await joined(),r=f.authority.r
    await f.executor.execute(r)
    const replay=f.authority.service.claimDispatch(claimBinding(r))
    assert.equal(replay.ok,false);assert.equal(replay.error_code,'REPLAYED')
    await assert.rejects(f.executor.execute(r),error=>error.code==='REPLAYED')
    assert.equal(count(f,'exec'),1)
    const fresh=await fixture({},{broker:tracedBroker(f.authority.restart(),f.calls)})
    roots.push(fresh.root);ledgers.add(fresh.ledger)
    await assert.rejects(fresh.executor.execute(r),error=>error.code==='REPLAYED')
    assert.equal(count(fresh,'create'),0);assert.equal(count(fresh,'exec'),0)
    assert.equal(f.authority.status().status,'COMPLETED')
  })

  await check('lost RPC trailers remain C OUTCOME_UNKNOWN across C/F restart without relaunch',async()=>{
    const f=await joined({exit:1,trailerFailure:true}),r=f.authority.r
    const receipt=await f.executor.execute(r)
    assert.equal(receipt.status,'outcome_unknown');assert.equal(receipt.exit_code,1)
    assert.equal(receipt.stdout,'retained synthetic output');assert.equal(receipt.rpc_completion,'transport_failed')
    assert.equal(receipt.cleanup,'confirmed_absent');assert.equal(f.authority.status().status,'OUTCOME_UNKNOWN')
    closeLedger(f.ledger)
    const restartedC=f.authority.restart(),ledger=new OwnedLedger(f.root);ledgers.add(ledger)
    const executor=new MockedProtocolExecutor({settings,transport:f.transport,ledger,broker:tracedBroker(restartedC,f.calls)})
    const [reconciled]=await executor.reconcileOwned()
    assert.equal(reconciled.receipt_id,receipt.receipt_id);assert.equal(reconciled.stdout,receipt.stdout)
    assert.equal(reconciled.exit_code,1);assert.equal(reconciled.status,'outcome_unknown')
    assert.equal(f.authority.status(restartedC).status,'OUTCOME_UNKNOWN')
    await assert.rejects(executor.execute(r),error=>error.code==='RECONCILIATION_REQUIRED')
    assert.equal(f.calls.filter(row=>row.method==='claimDispatch').length,1)
    assert.equal(count(f,'create'),1);assert.equal(count(f,'exec'),1)
  })

  await check('lost C settlement reply is reconciled idempotently without a second dispatch',async()=>{
    let lost=false
    const f=await joined({},{settle:value=>{
      assert.equal(value.ok,true)
      if(!lost){lost=true;throw new Error('synthetic reply loss after durable C settlement')}
    }}),r=f.authority.r
    await assert.rejects(f.executor.execute(r),error=>error.code==='RECONCILIATION_REQUIRED'&&error.executionReceipt?.status==='completed')
    assert.equal(f.authority.status().status,'COMPLETED')
    assert.equal(f.ledger.lookup(r.request_id).outbox[0].state,'pending')
    closeLedger(f.ledger)
    const restartedC=f.authority.restart(),ledger=new OwnedLedger(f.root);ledgers.add(ledger)
    const executor=new MockedProtocolExecutor({settings,transport:f.transport,ledger,broker:tracedBroker(restartedC,f.calls)})
    const [receipt]=await executor.reconcileOwned();assert.equal(receipt.status,'completed')
    assert.equal(ledger.lookup(r.request_id).outbox[0].state,'acked')
    assert.equal(ledger.recovery().length,0)
    const settlements=f.calls.filter(row=>row.method==='settle')
    assert.equal(settlements.length,2);assert.equal(settlements[1].value.idempotent,true)
    assert.equal(settlements[0].input.receipt_digest,settlements[1].input.receipt_digest)
    assert.equal(f.calls.filter(row=>row.method==='claimDispatch').length,1)
    assert.equal(count(f,'create'),1);assert.equal(count(f,'exec'),1)
    assert.equal(f.authority.status(restartedC).status,'COMPLETED')
  })
  console.log(JSON.stringify({status:'PASS',checks,scope:'actual C cryptographic proof/kernel/store and F dispatch/settlement join',
    limits:['mocked SDK and explicit test-only F admission','no real gateway or guest','no runtime qualification or UID isolation','ephemeral owner-key fixture only; no enrollment or signer passed to F']}))
} finally {
  for(const ledger of ledgers){try{ledger.close()}catch{}}
  for(const root of roots)rmSync(root,{recursive:true,force:true})
}
