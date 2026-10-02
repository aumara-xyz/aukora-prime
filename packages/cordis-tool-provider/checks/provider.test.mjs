// SPDX-License-Identifier: AGPL-3.0-or-later
// Keyless checks: synthetic proof only, actual C/F code, MOCKED SDK/admission.
// Context below is a lifecycle stub; cordis.test.mjs covers the actual DSH pin.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import { createCordisToolProvider, createProbeOperation, PROBE_COMMAND } from '../src/index.mjs'
import { executorRequestDigest } from '../../authority/src/index.mjs'
import { OpenShellOwnedExecutor } from '../../execution/src/index.mjs'
import { gate, mounted, providerFixture } from './provider-fixture.mjs'

const count=(f,name)=>f.protocol.calls.filter(([method])=>method===name).length
const setup=t=>{const f=providerFixture();t.after(()=>f.cleanup());return f}
const ready=f=>{f.propose();f.approve();return mounted(f.makePlugin())}

test('default registration grants nothing; explicit inputs cannot set command or child policy',async()=>{
  const p=mounted(createCordisToolProvider())
  assert.equal(p.service.availability().state,'unavailable')
  await assert.rejects(p.service.invoke(),{code:'UNAVAILABLE'})
  await assert.rejects(p.service.invoke({command:'id'}),{code:'INVALID'})
  await assert.rejects(p.tool.execute({parent:{allow:true}},{signal:new AbortController().signal}),{code:'INVALID'})
  await p.dispose()
})

test('fixed proposal binds exact operation, code meaning, policy, image and zero cost',t=>{
  const f=setup(t),op=f.operation
  assert.equal(op.canonical_parameters.command,PROBE_COMMAND)
  assert.equal(op.canonical_parameters.timeout_ms,1000);assert.equal(op.canonical_parameters.max_output_bytes,1024)
  assert.match(op.expected_state_version,/^prime\.cordis\.read-only-printf\.v1@sha256:[a-f0-9]{64}$/)
  assert(Object.isFrozen(op.canonical_parameters));assert.deepEqual(op.maximum_cost,{currency:'USD',amount:'0'})
  for(const change of [op=>{op.canonical_parameters.command='id'},op=>{op.canonical_parameters.sandbox_mode='workspace-write'},
    op=>{op.target_identity.policy_digest='sha256:'+'b'.repeat(64)},op=>{op.expected_state_version='invented-parent'}]) {
    const changed=structuredClone(op);change(changed)
    assert.throws(()=>createCordisToolProvider({operation:changed}))
  }
  assert.throws(()=>createProbeOperation({parent:op}),{code:'INVALID'})
})

test('actual C proposal/review/reservation -> actual F -> MOCKED SDK -> actual C settlement',async t=>{
  const f=setup(t)
  assert.equal(f.propose().status,'PROPOSED');assert.equal(count(f,'create'),0)
  f.approve();const p=mounted(f.makePlugin()),receipt=await p.service.invoke({})
  assert.equal(receipt.status,'completed');assert.equal(receipt.rpc_completion,'complete');assert.equal(receipt.cleanup,'confirmed_absent')
  assert.equal(f.status().status,'COMPLETED')
  assert.deepEqual(f.calls.map(row=>row.method),['reserve','claimDispatch','settle'])
  const [reserved,claim,settle]=f.calls
  assert.equal(reserved.result.status,'PREPARED');assert.equal(claim.result.status,'DISPATCHED')
  assert.deepEqual(reserved.input.operation,claim.input.operation)
  assert.equal(claim.input.request_digest,executorRequestDigest({operation:f.operation,consumed_grant:reserved.result.consumed_grant,
    request_id:receipt.request_id,image_digest:f.operation.target_identity.image_digest,policy_digest:f.operation.target_identity.policy_digest,
    wall_time_ms:1000,max_output_bytes:1024}))
  assert.equal(settle.result.status,'COMPLETED');assert.equal(count(f,'create'),1);assert.equal(count(f,'exec'),1)
  const state=JSON.parse(readFileSync(f.root+'/state/authority.json','utf8'))
  assert(state.state.consumedIds.length>0)
  assert.equal(p.service.availability().executor.protocol,'mocked')
  assert.equal(p.service.availability().executor.runtimeEnforcementVerified,false)
  await assert.rejects(p.service.invoke(),{code:'REPLAYED'})
  await p.dispose()
})

test('absent/altered owner proof never reaches SDK; composition cannot approve',async t=>{
  const f=setup(t);f.propose();const p=mounted(f.makePlugin())
  await assert.rejects(p.service.invoke());assert.equal(count(f,'create'),0)
  f.approve();f.alterProof(proof=>({...proof,operation_digest:'sha256:'+'b'.repeat(64)}))
  await assert.rejects(p.service.invoke(),{code:'TARGET_MISMATCH'})
  assert.equal(f.calls.length,0);assert.equal(f.status().status,'APPROVED')
  await p.dispose()
})

test('qualified executor bound to another broker refuses',async t=>{
  const f=setup(t);f.propose();f.approve()
  const p=mounted(createCordisToolProvider({operation:f.operation,authority:{...f.authority},executor:f.executor,readApproval:f.readApproval}))
  await assert.rejects(p.service.invoke(),{code:'UNAVAILABLE'});assert.equal(count(f,'create'),0)
  await p.dispose()
})

test('actual production F without accepted qualification stays unavailable and consumes no approval',async t=>{
  const f=setup(t);f.propose();f.approve()
  const executor=new OpenShellOwnedExecutor({settings:f.executor.settings,transport:f.transport,ledger:f.ledger,broker:f.authority})
  const p=mounted(createCordisToolProvider({operation:f.operation,authority:f.authority,executor,readApproval:f.readApproval}))
  assert.equal(p.service.availability().state,'unavailable')
  assert.equal(p.service.availability().executor.runtimeEnforcementVerified,false)
  await assert.rejects(p.service.invoke(),{code:'UNAVAILABLE'})
  assert.equal(f.status().status,'APPROVED');assert.equal(f.calls.length,0);assert.equal(count(f,'create'),0)
  await p.dispose()
})

test('retained service/tool references refuse after disposal; cleanup requested once',async t=>{
  const f=setup(t),p=ready(f),invoke=p.service.invoke,execute=p.tool.execute
  let disposals=0;const dispose=f.executor.dispose.bind(f.executor)
  f.executor.dispose=()=>{disposals++;return dispose()}
  await Promise.all([p.dispose(),p.dispose()]);assert.equal(disposals,1)
  await assert.rejects(invoke(),{code:'REVOKED'})
  await assert.rejects(execute({},{}),{code:'REVOKED'})
  assert.equal(f.calls.length,0);assert.equal(count(f,'create'),0)
})

test('revoked qualification refuses a captured invocation before reading approval',async t=>{
  const f=setup(t),p=ready(f);f.qualify(false)
  await assert.rejects(p.service.invoke(),{code:'UNAVAILABLE'})
  assert.equal(f.calls.length,0);assert.equal(count(f,'create'),0);await p.dispose()
})

for(const action of ['dispose','revoke','cancel']) test(`${action} during approval retrieval refuses at post-await checkpoint`,async t=>{
  const g=gate(),f=providerFixture({readApproval:g.wait});t.after(()=>f.cleanup())
  const p=ready(f),controller=new AbortController(),running=p.service.invoke({},controller.signal)
  const rejected=assert.rejects(running,{code:{dispose:'REVOKED',revoke:'UNAVAILABLE',cancel:'CANCELLED'}[action]})
  await g.entered
  if(action==='dispose')await p.dispose();else if(action==='revoke')f.qualify(false);else controller.abort()
  g.release();await rejected;assert.equal(f.calls.length,0);assert.equal(count(f,'create'),0);await p.dispose()
})

test('disposal after C reservation preserves PREPARED but refuses F dispatch',async t=>{
  const g=gate(),f=providerFixture({afterreserve:g.wait});t.after(()=>f.cleanup())
  const p=ready(f),running=p.service.invoke(),rejected=assert.rejects(running,{code:'REVOKED'})
  await g.entered;assert.equal(f.status().status,'PREPARED');await p.dispose();g.release();await rejected
  assert.deepEqual(f.calls.map(row=>row.method),['reserve']);assert.equal(count(f,'create'),0)
  assert.equal(f.status().reconciliation_required,true)
})

for(const mutation of ['session','task','image','policy','meaning']) test(`C dispatch checkpoint refuses changed ${mutation} after reservation`,async t=>{
  let f
  f=providerFixture({afterreserve:()=>{
    if(mutation==='session')f.logout()
    if(mutation==='task')f.taskActive(false)
    if(mutation==='image')f.changeTarget(target=>({...target,image_digest:'sha256:'+'c'.repeat(64)}))
    if(mutation==='policy')f.changeTarget(target=>({...target,policy_digest:'sha256:'+'c'.repeat(64)}))
    if(mutation==='meaning')f.changeState('different-provider-build')
  }});t.after(()=>f.cleanup())
  const p=ready(f)
  await assert.rejects(p.service.invoke(),error=>['UNAUTHORIZED','TARGET_MISMATCH'].includes(error.code))
  assert.deepEqual(f.calls.map(row=>row.method),['reserve','claimDispatch'])
  assert.equal(f.calls[1].result.ok,false);assert.equal(count(f,'create'),0);assert.equal(count(f,'exec'),0)
  await p.dispose()
})

test('concurrent invocation does not multiply approval retrieval or reservation',async t=>{
  const g=gate(),f=providerFixture({readApproval:g.wait});t.after(()=>f.cleanup())
  const p=ready(f),running=p.service.invoke();await g.entered
  await assert.rejects(p.service.invoke(),{code:'REPLAYED'});g.release();await running
  assert.equal(count(f,'create'),1);assert.equal(f.calls.filter(row=>row.method==='reserve').length,1);await p.dispose()
})

test('MOCKED RPC uncertainty remains actual C OUTCOME_UNKNOWN and rejects the tool with exact receipt',async t=>{
  const f=providerFixture({protocol:{trailerFailure:true}});t.after(()=>f.cleanup({allowPending:true}))
  const p=ready(f)
  await assert.rejects(p.tool.execute({},{}),error=>{
    assert.equal(error.executionReceipt.status,'outcome_unknown')
    assert.equal(error.executionReceipt.rpc_completion,'transport_failed')
    assert.equal(error.executionReceipt.reconciliation_required,true);return true
  })
  assert.equal(f.status().status,'OUTCOME_UNKNOWN')
  await assert.rejects(p.service.invoke(),{code:'REPLAYED'})
  await assert.rejects(p.dispose(),{code:'RECONCILIATION_REQUIRED'})
})

for(const [field,value] of [['workspace','another-private-workspace'],
  ['image_digest','sha256:'+'d'.repeat(64)],['logical_workspace_root','/logical/another-project']]) {
  test(`qualified executor with mismatched ${field} refuses before approval retrieval or reservation`,async t=>{
    let approvalReads=0
    const f=providerFixture({readApproval:()=>{approvalReads++}});t.after(()=>f.cleanup())
    const p=ready(f)
    // Explicit test-only host configuration change after capturing the service.
    f.executor.settings=Object.freeze({...f.executor.settings,[field]:value})
    assert.equal(f.executor.capability,'qualified')
    assert.equal(p.service.availability().state,'unavailable')
    await assert.rejects(p.service.invoke(),{code:'UNAVAILABLE'})
    assert.equal(approvalReads,0);assert.deepEqual(f.calls,[])
    assert.equal(count(f,'create'),0);assert.equal(count(f,'exec'),0)
    assert.equal(f.status().status,'APPROVED');await p.dispose()
  })
}

test('MOCKED request-specific admission refusal checks exact policy and bounds before reading approval',async t=>{
  let approvalReads=0
  const f=providerFixture({readApproval:()=>{approvalReads++}});t.after(()=>f.cleanup())
  const p=ready(f),admissions=[]
  // Generic qualification stays true; this explicit mock denies the exact scope.
  f.executor.admission=request=>{admissions.push(structuredClone(request));return false}
  assert.equal(f.executor.capability,'qualified')
  await assert.rejects(p.service.invoke(),{code:'UNAVAILABLE'})
  assert.deepEqual(admissions,[{policy_digest:f.operation.target_identity.policy_digest,
    wall_time_ms:1000,max_output_bytes:1024}])
  assert.equal(approvalReads,0);assert.deepEqual(f.calls,[])
  assert.equal(count(f,'create'),0);assert.equal(count(f,'exec'),0)
  assert.equal(f.status().status,'APPROVED');await p.dispose()
})

test('unchanged operation digest with altered owner signature is rejected by actual C before dispatch',async t=>{
  const f=setup(t),p=ready(f)
  const before=JSON.parse(readFileSync(f.root+'/state/authority.json','utf8'))
  f.alterProof(proof=>({...proof,material:{...proof.material,
    signature:(proof.material.signature[0]==='0'?'1':'0')+proof.material.signature.slice(1)}}))
  await assert.rejects(p.service.invoke())
  assert.deepEqual(f.calls.map(row=>row.method),['reserve'])
  assert.equal(f.calls[0].input.approval_proof.operation_digest,
    Object.values(before.broker.operations)[0].operation_digest)
  assert.equal(f.calls[0].result.ok,false)
  assert.equal(f.status().status,'APPROVED')
  const after=JSON.parse(readFileSync(f.root+'/state/authority.json','utf8'))
  assert.deepEqual(after.state.consumedIds,before.state.consumedIds)
  assert.deepEqual(after.prepared,before.prepared)
  assert.equal(count(f,'create'),0);assert.equal(count(f,'exec'),0);await p.dispose()
})

test('lost actual C reserve reply preserves consumed PREPARED state and permanently fences provider retry',async t=>{
  let approvalReads=0
  const f=providerFixture({readApproval:()=>{approvalReads++},afterreserve:result=>{
    assert.equal(result.ok,true);assert.equal(result.status,'PREPARED')
    throw new Error('synthetic reserve reply loss after durable C preparation')
  }});t.after(()=>f.cleanup())
  const p=ready(f)
  await assert.rejects(p.service.invoke(),{message:'synthetic reserve reply loss after durable C preparation'})
  assert.equal(f.status().status,'PREPARED');assert.equal(f.status().reconciliation_required,true)
  const beforeRetry=JSON.parse(readFileSync(f.root+'/state/authority.json','utf8'))
  const nonce=f.calls[0].input.approval_proof.nonce
  assert(beforeRetry.state.consumedIds.includes('approval:'+nonce))
  assert.equal(beforeRetry.prepared.filter(row=>row.consumptionId==='approval:'+nonce).length,1)
  await assert.rejects(p.service.invoke(),{code:'REPLAYED'})
  assert.equal(approvalReads,1);assert.deepEqual(f.calls.map(row=>row.method),['reserve'])
  assert.equal(count(f,'create'),0);assert.equal(count(f,'exec'),0)
  const afterRetry=JSON.parse(readFileSync(f.root+'/state/authority.json','utf8'))
  assert.deepEqual(afterRetry.state.consumedIds,beforeRetry.state.consumedIds)
  assert.deepEqual(afterRetry.prepared,beforeRetry.prepared)
  await p.dispose()
})
