// SPDX-License-Identifier: AGPL-3.0-or-later
// Keyless local accounting and refusal fixtures. No client, guest, credentials
// or real authority enrollment. Public absence below is synthetic observation.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { rm } from 'node:fs/promises'
import { once } from 'node:events'
import { OpenShellOwnedExecutor,OwnedLedger,SDK_SOURCE_COMMIT,SDK_PACKAGE_VERSION,executorRequestDigest,wirePolicy } from '../src/index.mjs'
import { createLocalLifetime,localLifetimeDigest,inspectLocalLifetime,PINNED_EXECUTION_SAFETY } from '../src/lifetime-safety.mjs'
import { assertEffectiveConfiguration,expectedConfigIdentity } from '../src/effective-policy.mjs'
import { operationDigest } from '../../contracts/src/runtime.mjs'
import { request,settings,fixture,MockedProtocolExecutor } from './harness.mjs'

const ACCEPTED=Date.UTC(2026,9,3,12)
const iso=ms=>new Date(ms).toISOString()
const freeze=value=>{
  for(const child of Object.values(value))if(child&&typeof child==='object')freeze(child)
  return Object.freeze(value)
}
function localJob({wall=500,expiry=ACCEPTED+60_000}={}) {
  const r=request({wall_time_ms:wall})
  r.operation.expiry=iso(expiry)
  r.operation.canonical_parameters.timeout_ms=wall
  r.consumed_grant.operation_digest=operationDigest(r.operation)
  freeze(r)
  const job={request:r,request_id:r.request_id,request_digest:executorRequestDigest(r)}
  job.lifetime=createLocalLifetime(job,ACCEPTED)
  job.lifetime_digest=localLifetimeDigest(job.lifetime)
  return job
}
const copy=value=>structuredClone(value)
const rejects=(fn,code)=>assert.rejects(async()=>fn(),error=>error.code===code)

// Returning accepted evidence only models qualification inspection. It must not
// override the production launch, independent lifetime or cleanup requirements.
class EvidenceOnlyExecutor extends OpenShellOwnedExecutor {
  acceptedQualification(){return {qualification_id:'synthetic-record',host_profile:{os:'linux'}}}
}
function unavailableExecutor(Executor=EvidenceOnlyExecutor) {
  const calls=[]
  const touched=method=>()=>{calls.push(method);throw new Error('unexpected side effect: '+method)}
  const ledger={identity:randomUUID(),pending:()=>[],recovery:()=>[],withLease:touched('ledger.withLease'),save:touched('ledger.save'),reserve:touched('ledger.reserve')}
  const transport={sourceCommit:SDK_SOURCE_COMMIT,packageVersion:SDK_PACKAGE_VERSION,gatewayIdentity:'https://synthetic.invalid:19443/',
    create:touched('sdk.create'),get:touched('sdk.get'),configuration:touched('sdk.configuration'),inventory:touched('sdk.inventory'),delete:touched('sdk.delete'),execStream:touched('sdk.execStream')}
  const broker=Object.fromEntries(['claimDispatch','requestCancel','settle','reconcileSettlement'].map(method=>[method,touched('broker.'+method)]))
  return {executor:new Executor({settings,ledger,transport,broker}),calls}
}
function configurationFixture() {
  const policy=wirePolicy('read-only'),identity=expectedConfigIdentity(policy),instance=randomUUID(),attachment=randomUUID()
  const config={policy:copy(policy),version:1,policyHash:identity.policy_hash,
    settings:Object.fromEntries(['ocsf_json_enabled','ocsf_schema_version','agent_policy_proposals_enabled','proposal_approval_mode'].map(key=>[key,{scope:0}])),
    configRevision:BigInt(identity.config_revision),policySource:1,globalPolicyVersion:0,providerEnvRevision:BigInt(identity.provider_env_revision),
    supervisorMiddlewareServices:[],workspace:settings.workspace,policyValidationFailureMode:'fail_closed',extensionAuthenticationEnabled:false,
    providerAttachmentEpoch:attachment,configurationAdmitted:true,configurationError:'',configurationInstanceId:instance}
  const sandbox={metadata:{id:randomUUID(),workspace:settings.workspace},spec:{policy:copy(policy),providers:[],providerAttachmentEpoch:attachment},
    status:{configurationAdmission:{instanceId:instance,state:2,policyVersion:1,policyHash:identity.policy_hash,
      configRevision:config.configRevision,providerEnvRevision:config.providerEnvRevision,error:''}}}
  return {sandbox,config,policy,workspace:settings.workspace}
}

const cases={
  exact_deadline_and_original_expiry() {
    const wall=localJob(),earlierApproval=localJob({expiry:ACCEPTED+80})
    assert.equal(wall.lifetime.accepted_at,iso(ACCEPTED))
    assert.equal(wall.lifetime.deadline_at,iso(ACCEPTED+500))
    assert.equal(earlierApproval.lifetime.deadline_at,iso(ACCEPTED+500))
    assert.equal(inspectLocalLifetime(earlierApproval,ACCEPTED+100).status,'active')
    assert.equal(earlierApproval.lifetime.enforcement,'local_accounting_only')
    assert.deepEqual(Object.keys(earlierApproval.lifetime).sort(),['version','request_id','request_digest','accepted_at','deadline_at','last_observed_at','wall_time_ms','enforcement'].sort())
    const expired={...wall,request:copy(wall.request)}
    expired.request.operation.expiry=iso(ACCEPTED)
    expired.request.consumed_grant.operation_digest=operationDigest(expired.request.operation)
    freeze(expired.request);expired.request_digest=executorRequestDigest(expired.request)
    assert.throws(()=>createLocalLifetime(expired,ACCEPTED),error=>error.code==='EXPIRED')
  },
  inspection_does_not_renew() {
    const job=localJob(),original=copy(job.lifetime),digest=job.lifetime_digest
    const first=inspectLocalLifetime(job,ACCEPTED+100)
    assert.equal(first.status,'active');assert.equal(first.remaining_ms,400)
    assert.equal(first.lifetime.deadline_at,original.deadline_at)
    assert.equal(first.lifetime.last_observed_at,iso(ACCEPTED+100))
    assert.equal(localLifetimeDigest(first.lifetime),digest)
    assert.deepEqual(job.lifetime,original)
    job.lifetime=first.lifetime
    const second=inspectLocalLifetime(job,ACCEPTED+350)
    assert.equal(second.status,'active');assert.equal(second.remaining_ms,150)
    assert.equal(second.lifetime.accepted_at,original.accepted_at)
    assert.equal(second.lifetime.deadline_at,original.deadline_at)
    assert.equal(localLifetimeDigest(second.lifetime),digest)
  },
  expiry_and_clock_rollback() {
    const job=localJob({wall:80})
    const atDeadline=inspectLocalLifetime(job,ACCEPTED+80)
    assert.equal(atDeadline.status,'expired');assert.equal(atDeadline.remaining_ms,0)
    job.lifetime=atDeadline.lifetime
    const restarted=inspectLocalLifetime(job,ACCEPTED+1000)
    assert.equal(restarted.status,'expired');assert.equal(restarted.remaining_ms,0)
    assert.equal(restarted.lifetime.deadline_at,iso(ACCEPTED+80))
    const rollback=inspectLocalLifetime(job,ACCEPTED+79)
    assert.equal(rollback.status,'clock_uncertain');assert.equal(rollback.remaining_ms,null)
    assert.equal(rollback.lifetime.last_observed_at,iso(ACCEPTED+80))
    assert.equal(rollback.lifetime.deadline_at,iso(ACCEPTED+80))
    assert.equal(inspectLocalLifetime(localJob(),ACCEPTED-1).status,'clock_uncertain')
  },
  altered_binding_and_extension_invalid() {
    for(const change of [job=>{job.request_id=randomUUID()},job=>{job.request_digest='sha256:'+'b'.repeat(64)},
      job=>{job.lifetime.deadline_at=iso(ACCEPTED+501)},job=>{job.lifetime.request_id=randomUUID()},
      job=>{job.lifetime.request_digest='sha256:'+'b'.repeat(64)}]) {
      const job=localJob();change(job)
      const observed=inspectLocalLifetime(job,ACCEPTED+1)
      assert.deepEqual(observed,{status:'invalid',remaining_ms:null,lifetime:null})
    }
    // Even a recalculated local digest cannot extend the approved wall bound.
    for(const options of [{},{expiry:ACCEPTED+80}]) {
      const job=localJob(options)
      job.lifetime.deadline_at=iso(Date.parse(job.lifetime.deadline_at)+1)
      job.lifetime_digest=localLifetimeDigest(job.lifetime)
      assert.equal(inspectLocalLifetime(job,ACCEPTED+1).status,'invalid')
    }
    const original=localJob(),foreign=localJob()
    foreign.lifetime=copy(original.lifetime);foreign.lifetime_digest=original.lifetime_digest
    assert.equal(inspectLocalLifetime(foreign,ACCEPTED+1).status,'invalid')
  },
  malformed_accounting_is_not_proof() {
    for(const change of [job=>{delete job.lifetime_digest},job=>{delete job.lifetime},
      job=>{job.lifetime.enforcement='independent'},job=>{job.lifetime.extra=true},
      job=>{job.lifetime.last_observed_at=iso(ACCEPTED-1)},job=>{job.lifetime.last_observed_at='not-a-time'},
      job=>{job.lifetime.version=2}]) {
      const job=localJob();change(job)
      assert.deepEqual(inspectLocalLifetime(job,ACCEPTED+1),{status:'invalid',remaining_ms:null,lifetime:null})
    }
    assert.equal(inspectLocalLifetime(localJob(),Number.NaN).status,'invalid')
  },
  async claim_wait_spends_original_wall_budget() {
    let f,original
    f=await fixture({}, {beforeClaim:async()=>{
      const job=f.ledger.lookup(f.executor.active.job.request_id)
      original=copy(job.lifetime)
      assert.equal(job.claim_state,'attempted')
      assert.equal(job.lifetime_digest,localLifetimeDigest(original))
      assert.equal(Date.parse(original.deadline_at)-Date.parse(original.accepted_at),50)
      const signal=f.executor.active.controller.signal
      if(!signal.aborted)await once(signal,'abort')
      assert(Date.now()>=Date.parse(original.deadline_at))
      return true
    }})
    try {
      const r=request({wall_time_ms:50});r.operation.canonical_parameters.timeout_ms=50
      r.consumed_grant.operation_digest=operationDigest(r.operation)
      const receipt=await f.executor.execute(r),job=f.ledger.lookup(r.request_id)
      assert.equal(receipt.status,'cancelled');assert.equal(receipt.cleanup,'not_created')
      assert.equal(receipt.started_at,null);assert.equal(job.cancel_cause,'timeout')
      assert.equal(job.lifetime.accepted_at,original.accepted_at)
      assert.equal(job.lifetime.deadline_at,original.deadline_at)
      assert.equal(f.broker.read().calls.filter(([name])=>name==='claimDispatch').length,1)
      assert.equal(f.protocol.calls.length,0)
      for(const change of [j=>{j.receipt.started_at=iso(Date.now())},j=>{j.receipt.exit_code=0},
        j=>{j.id=randomUUID()},j=>{j.create_confirmed=true},j=>{j.receipt.rpc_completion='complete'}]) {
        const contradictory=copy(job);change(contradictory)
        await rejects(()=>f.executor.cleanup(contradictory),'RECONCILIATION_REQUIRED')
      }
      assert.equal(f.protocol.calls.length,0)
    } finally {f.ledger.close();await rm(f.root,{recursive:true,force:true})}
  },
  async restart_preserves_deadline_and_typed_uncertainty() {
    const f=await fixture({exit:1,trailerFailure:true})
    let ledger=f.ledger
    try {
      const r=request(),first=await f.executor.execute(r),original=copy(ledger.lookup(r.request_id).lifetime)
      assert.equal(first.status,'outcome_unknown');assert.equal(first.exit_code,1)
      ledger.close();ledger=null
      ledger=new OwnedLedger(f.root)
      const executor=new MockedProtocolExecutor({settings,transport:f.transport,ledger,broker:f.broker})
      const [receipt]=await executor.reconcileOwned(),job=ledger.lookup(r.request_id)
      assert.equal(job.lifetime.accepted_at,original.accepted_at)
      assert.equal(job.lifetime.deadline_at,original.deadline_at)
      assert.equal(job.lifetime_digest,localLifetimeDigest(original))
      assert.equal(receipt.status,'outcome_unknown');assert.equal(receipt.exit_code,1)
      assert.equal(receipt.rpc_completion,'transport_failed');assert.equal(receipt.stdout,'retained synthetic output')
      assert.equal(f.protocol.calls.filter(([name])=>name==='create').length,1)
      assert.equal(f.protocol.calls.filter(([name])=>name==='exec').length,1)
      assert.equal(f.broker.read().calls.filter(([name])=>name==='claimDispatch').length,1)
    } finally {ledger?.close();await rm(f.root,{recursive:true,force:true})}
  },
  async uncertain_clock_never_becomes_timeout_intent() {
    const f=await fixture()
    try {
      f.executor.observeLifetime=job=>{
        const observed=inspectLocalLifetime(job,Date.parse(job.lifetime.accepted_at)-1)
        job.local_lifetime_status=observed.status;f.ledger.save(job);return observed
      }
      const r=request()
      await rejects(()=>f.executor.execute(r),'RECONCILIATION_REQUIRED')
      const job=f.ledger.lookup(r.request_id)
      assert.equal(job.local_lifetime_status,'clock_uncertain');assert.equal(job.claim_state,'refused')
      assert.equal(job.receipt.cleanup,'not_created');assert.equal(job.receipt.status,'unavailable')
      assert.equal(job.cancel_cause,undefined);assert.equal(job.cancel_state,null)
      assert.deepEqual(job.outbox,[]);assert.deepEqual(f.broker.read().calls,[])
      assert.equal(f.broker.read().rows[r.operation.operation_id].status,'PREPARED')
      assert.equal(f.protocol.calls.length,0)
    } finally {f.ledger.close();await rm(f.root,{recursive:true,force:true})}
  },
  async accepted_evidence_cannot_enable_production() {
    assert.deepEqual(PINNED_EXECUTION_SAFETY,{independent_expiry:'unavailable',late_create_fence:'unavailable',atomic_configuration:'unavailable',owned_artifact_cleanup:'unavailable'})
    assert.equal(Object.isFrozen(PINNED_EXECUTION_SAFETY),true)
    const {executor,calls}=unavailableExecutor(),r=request()
    assert.equal(executor.executionSafeguardsAvailable(),false)
    assert.equal(executor.capability,'unavailable');assert.equal(executor.admission(r),false)
    const available=executor.availability()
    assert.equal(available.state,'unavailable');assert.equal(available.runtime,'unavailable')
    assert.equal(available.runtimeEnforcementVerified,false)
    await rejects(()=>executor.requireIndependentLifetime(localJob()),'UNAVAILABLE')
    await rejects(()=>executor.execute(r),'UNAVAILABLE')
    assert.deepEqual(calls,[])
  },
  async stable_readbacks_are_not_atomic_authorization() {
    const snapshot=configurationFixture(),before=assertEffectiveConfiguration(snapshot),after=assertEffectiveConfiguration(copy(snapshot))
    assert.deepEqual(after,before)
    const {executor,calls}=unavailableExecutor(),job=localJob()
    job.effective_configuration=before;job.configuration_verification='verified'
    await rejects(()=>executor.requireAtomicConfiguration(job),'UNAVAILABLE')
    assert.deepEqual(calls,[])
  },
  async public_absence_cannot_confirm_owned_cleanup() {
    const {executor,calls}=unavailableExecutor(),job=localJob()
    job.stage='delete_attempted';job.create_confirmed=true
    job.receipt={cleanup:'pending'}
    job.public_absence_observed_at=iso(ACCEPTED+1000)
    job.public_inventory={sandboxes:[],nextPageToken:''}
    await rejects(()=>executor.requireIndependentCleanup(job),'RECONCILIATION_REQUIRED')
    await rejects(()=>executor.confirmOwnedCleanup(job),'RECONCILIATION_REQUIRED')
    assert.equal(job.receipt.cleanup,'pending');assert.equal(job.stage,'delete_attempted')
    assert.deepEqual(calls,[])
  },
  mocked_protocol_never_reports_runtime_qualification() {
    const {executor}=unavailableExecutor(MockedProtocolExecutor),available=executor.availability()
    assert.equal(available.protocol,'mocked');assert.equal(available.state,'unavailable')
    assert.equal(available.runtime,'unavailable');assert.equal(available.runtimeEnforcementVerified,false)
  },
}
const selected=process.argv[2]
if(selected&&!Object.hasOwn(cases,selected))throw new Error('unknown scoped lifetime-safety check')
for(const [name,check] of Object.entries(cases))if(!selected||selected===name){await check();console.log(`PASS ${name}`)}
console.log(`PASS lifetime-safety ${selected?1:Object.keys(cases).length} scoped cases; local accounting only, runtime unavailable`)
