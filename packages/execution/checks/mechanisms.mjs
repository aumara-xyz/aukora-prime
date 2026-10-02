// SPDX-License-Identifier: AGPL-3.0-or-later
// Each selectable case reaches one lifecycle guard with all other bindings valid.
// All authority/gateway responses below are disposable mocks, never runtime proof.
import assert from 'node:assert/strict'
import { existsSync,readFileSync } from 'node:fs'
import { rm } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { createDshOpenShellExecutor } from '../src/index.mjs'
import { operationDigest } from '../../contracts/src/runtime.mjs'
import { fixture,request } from './harness.mjs'

const fixtures=[]
const make=async(...args)=>{const f=await fixture(...args);fixtures.push(f);return f}
const clone=value=>JSON.parse(JSON.stringify(value))
const calls=(f,name)=>f.protocol.calls.filter(([kind])=>kind===name)
const brokerCalls=(f,name)=>f.broker.read().calls.filter(([kind])=>kind===name)
const noExec=f=>assert.equal(calls(f,'exec').length,0,'no execution may follow refused evidence')
const durableBytes=ledger=>Object.fromEntries(['ledger.json','jobs.sqlite','jobs.sqlite-wal'].map(name=>{
  const path=join(ledger.root,name);return [name,existsSync(path)?readFileSync(path):null]
}))
const inertJob=()=>{const r=request();return {request_id:r.request_id,reservation_id:r.consumed_grant.reservation_id,
  stage:'prepared',receipt:{operation_id:r.operation.operation_id,grant_id:r.consumed_grant.grant_id,cleanup:'pending'}}}
function assertUnstarted(receipt,cleanup) {
  assert.equal(receipt.status,'outcome_unknown')
  assert.equal(receipt.cleanup,cleanup)
  assert.equal(receipt.started_at,null)
  assert.equal(receipt.exit_code,null)
  assert.equal(receipt.rpc_completion,'not_started')
  assert.equal(receipt.reconciliation_required,true)
}

const cases={
  async lease_reserve() {
    const f=await make(),job=inertJob(),before=durableBytes(f.ledger)
    assert.equal(f.ledger.lookup(job.request_id),null)
    assert.throws(()=>f.ledger.reserve(job),error=>error.code==='RECONCILIATION_REQUIRED')
    assert.deepEqual(durableBytes(f.ledger),before,'an unleased reserve must not write durable bytes')
    assert.equal(f.ledger.lookup(job.request_id),null)
    assert.equal(f.protocol.calls.length,0)
    assert.equal(f.broker.read().calls.length,0)
  },
  async lease_save() {
    const f=await make(),job=inertJob()
    await f.ledger.withLease(async()=>f.ledger.reserve(job))
    const stored=f.ledger.lookup(job.request_id),before=durableBytes(f.ledger),changed=clone(stored)
    changed.stage='synthetic_changed';changed.receipt.cleanup='confirmed_absent'
    assert.throws(()=>f.ledger.save(changed),error=>error.code==='RECONCILIATION_REQUIRED')
    assert.deepEqual(durableBytes(f.ledger),before,'an unleased save must not write durable bytes')
    assert.deepEqual(f.ledger.lookup(job.request_id),stored,'the prior owned checkpoint must remain exact')
    assert.equal(f.protocol.calls.length,0)
    assert.equal(f.broker.read().calls.length,0)
  },
  async bash_parameters() {
    const f=await make(),r=request(),p=r.operation.canonical_parameters
    let resolves=0,executions=0
    const execute=f.executor.execute.bind(f.executor)
    f.executor.execute=async input=>{executions++;return execute(input)}
    class ShellExecutor {constructor(ctx){this.ctx=ctx}}
    const Executor=createDshOpenShellExecutor({ShellExecutor,executor:f.executor,
      resolveSpec:input=>input,resolveOperation:async()=>{resolves++;return r}})
    const shell=new Executor({effect(){},sandboxPolicy:{defaultMode:'read-only',resolve:()=>({mode:p.sandbox_mode,workspaceRoot:p.workdir})}})
    const spec=shell.resolve({command:p.command+' changed',workdir:p.workdir,stdin:p.stdin,env:p.env,dshEnv:p.dsh_env,
      timeoutMs:p.timeout_ms,stdoutMaxBytes:p.max_output_bytes})
    await assert.rejects(shell.run(spec),error=>error.code==='TARGET_MISMATCH')
    assert.equal(resolves,1)
    assert.equal(executions,0,'the factory must reject the mismatch before calling OwnedExecutor')
    assert.equal(f.broker.read().calls.length,0)
    assert.equal(f.protocol.calls.length,0)
    assert.equal(f.ledger.lookup(r.request_id),null)
  },
  async pre_exec_qualification() {
    let admitted=true
    const f=await make({}, {protocolAdmission:()=>admitted}),r=request()
    const get=f.protocol.raw.getSandbox
    f.protocol.raw.getSandbox=async(...args)=>{const reply=await get(...args);admitted=false;return reply}
    const receipt=await f.executor.execute(r)
    assert.equal(calls(f,'create').length,1)
    assert(calls(f,'get').length>0,'revocation must occur only after the readiness observation')
    assert.equal(brokerCalls(f,'claimDispatch').length,1)
    noExec(f)
    assertUnstarted(receipt,'confirmed_absent')
    assert.equal(f.broker.read().rows[r.operation.operation_id].status,'OUTCOME_UNKNOWN')
  },
  async pre_exec_expiry() {
    const f=await make(),r=request(),now=Date.now
    r.operation.expiry=new Date(now()+60_000).toISOString()
    r.consumed_grant.operation_digest=operationDigest(r.operation)
    const get=f.protocol.raw.getSandbox
    // Move only this test's logical clock after a ready response. No timing race,
    // expiry mutation of the frozen request, or timer/abort can hide the guard.
    f.protocol.raw.getSandbox=async(...args)=>{const reply=await get(...args);Date.now=()=>Date.parse(r.operation.expiry)+1;return reply}
    try {
      const receipt=await f.executor.execute(r)
      assert.equal(calls(f,'create').length,1)
      assert(calls(f,'get').length>0)
      assert.equal(brokerCalls(f,'claimDispatch').length,1)
      noExec(f)
      assertUnstarted(receipt,'confirmed_absent')
    } finally {Date.now=now}
  },
  async admitted_image() {
    let f
    const foreign='example.invalid/workload@sha256:'+'b'.repeat(64)
    f=await make({afterCreate(){f.protocol.getSandbox().spec.template.image=foreign}})
    const receipt=await f.executor.execute(request())
    assert.equal(calls(f,'create').length,1)
    assert(calls(f,'get').length>0)
    noExec(f)
    assertUnstarted(receipt,'confirmed_absent')
    assert.equal(calls(f,'delete').length,1,'the unchanged ownership token still permits scoped cleanup')
  },
  async claim_grant_reply() {
    const f=await make(),r=request(),claim=f.executor.broker.claimDispatch
    f.executor.broker.claimDispatch=async input=>{const reply=await claim(input);return {...reply,
      consumed_grant:{...reply.consumed_grant,grant_id:randomUUID()}}}
    const receipt=await f.executor.execute(r),job=f.ledger.lookup(r.request_id)
    assert.equal(brokerCalls(f,'claimDispatch').length,1)
    assert.equal(calls(f,'create').length,0)
    noExec(f)
    assertUnstarted(receipt,'not_created')
    assert.equal(job.claim_state,'unknown','a successful reply with a different grant is never accepted')
    assert.equal(job.claim_reply,null)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status,'OUTCOME_UNKNOWN')
  },
  async claim_digest_reply() {
    const f=await make(),r=request(),claim=f.executor.broker.claimDispatch
    f.executor.broker.claimDispatch=async input=>({...await claim(input),request_digest:'sha256:'+'b'.repeat(64)})
    const receipt=await f.executor.execute(r),job=f.ledger.lookup(r.request_id)
    assert.equal(brokerCalls(f,'claimDispatch').length,1)
    assert.equal(calls(f,'create').length,0)
    noExec(f)
    assertUnstarted(receipt,'not_created')
    assert.equal(job.claim_state,'unknown','a successful reply with a different request digest is never accepted')
    assert.equal(job.claim_reply,null)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status,'OUTCOME_UNKNOWN')
  },
  async settlement_status_reply() {
    const f=await make(),r=request(),settle=f.executor.broker.settle
    f.executor.broker.settle=async input=>({...await settle(input),status:'FAILED'})
    await assert.rejects(f.executor.execute(r),error=>error.code==='RECONCILIATION_REQUIRED'
      &&error.executionReceipt.status==='completed')
    const job=f.ledger.lookup(r.request_id)
    assert.equal(job.receipt.status,'completed')
    assert.equal(job.receipt.exit_code,0)
    assert.equal(job.receipt.rpc_completion,'complete')
    assert.equal(job.receipt.cleanup,'confirmed_absent')
    assert.equal(job.outbox.length,1)
    assert.equal(job.outbox[0].state,'pending','a mismatched settlement outcome must leave delivery pending')
    assert.equal(job.outbox[0].reply,null)
    assert.equal(f.ledger.recovery().length,1)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status,'COMPLETED')
    // A subsequent matching, idempotent authority reply can acknowledge the
    // same retained evidence without another claim, create, or execution.
    f.executor.broker.settle=settle
    const receipts=await f.executor.reconcileOwned()
    assert.equal(receipts[0].status,'completed')
    assert.equal(f.ledger.recovery().length,0)
    assert.equal(f.ledger.lookup(r.request_id).outbox[0].reply.idempotent,true)
    assert.equal(brokerCalls(f,'claimDispatch').length,1)
    assert.equal(calls(f,'create').length,1)
    assert.equal(calls(f,'exec').length,1)
  },
  async owner_label() {
    let f
    const foreign=randomUUID()
    f=await make({afterCreate(){f.protocol.getSandbox().metadata.labels['aukora.openshell/owner']=foreign}})
    const r=request(),receipt=await f.executor.execute(r)
    assert.equal(calls(f,'create').length,1)
    noExec(f)
    assert.equal(calls(f,'delete').length,0,'a matching name/workspace/ID never substitutes for the owner label')
    assertUnstarted(receipt,'unknown')
    assert.equal(receipt.sandbox,null)
    assert.equal(f.protocol.getSandbox().metadata.labels['aukora.openshell/owner'],foreign)
    const reconciled=await f.executor.reconcileOwned()
    assertUnstarted(reconciled[0],'unknown')
    noExec(f)
    assert.equal(calls(f,'delete').length,0)
    assert.equal(f.ledger.recovery().length,1)
    assert.equal(brokerCalls(f,'claimDispatch').length,1)
  },
}

try {
  const selected=process.argv[2]
  if(selected&&!Object.hasOwn(cases,selected))throw new Error('unknown mechanism case: '+selected)
  for(const [name,run] of Object.entries(cases)) {
    if(selected&&selected!==name)continue
    await run();console.log('PASS '+name)
  }
} finally {
  for(const f of fixtures) {
    try {f.ledger.close()}finally {await rm(f.root,{recursive:true,force:true})}
  }
}
