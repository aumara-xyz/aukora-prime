#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Keyless post-dispatch checks. Prior owner review/dispatch metadata is MODELLED.
// The unchanged kernel/store really prepares/consumes public fixture IDs, and
// actual C factual settlement/compaction/reopen use disposable journal/witness.
// This is NOT authenticated owner login/reserve/dispatch or private IPC proof.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {cpSync,mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {dirname,join,resolve} from 'node:path'
import {spawnSync} from 'node:child_process'
import {fileURLToPath} from 'node:url'
import {canonicalJson} from '../contracts/src/runtime.mjs'
import {canonicalBytes} from './upstream/vendor/authority/lib/index.js'
import {KERNEL_ACTION,KERNEL_RESOURCE_NAMESPACE,KERNEL_RING,KERNEL_POLICY} from './upstream/scripts/aukora/decide.mjs'
import {didKeyFromEd25519PublicKey} from './upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import {createAuthorityService,provisionNewAuthorityStore,operationDigest,
  inferenceEffectReceiptDigest,memoryResultDigest,executionReceiptDigest} from './src/index.mjs'
import {PrimeApprovalStateStore,EMPTY_KERNEL_STATE} from './src/state-store.mjs'
import {configureInferenceProfile,inferencePolicyContext} from './src/inference-profile.mjs'
import {inferenceFixture} from './check-inference-mapper.mjs'

const sha=value=>createHash('sha256').update(value).digest('hex')
const keyOf=op=>sha(canonicalJson([op.owner_id,op.operation_id]))
const snapshot=f=>({state:readFileSync(f.config.statePath),witness:readFileSync(join(f.config.witnessDir,'kernel-high-water.json'))})
const read=f=>JSON.parse(readFileSync(f.config.statePath,'utf8'))
const kernel=record=>({state:record.state,prepared:record.prepared})
const row=f=>read(f).broker.operations[keyOf(f.operation)]

export function runInferenceServiceChecks() {
  const root=mkdtempSync(join(realpathSync(tmpdir()),'prime-inference-keyless-'))
  let assertions=0
  const groups=[]
  const equal=(a,b,message)=>{assert.deepEqual(a,b,message);assertions++}
  const check=(value,message)=>{assert(value,message);assertions++}
  const ok=result=>{check(result.ok===true,JSON.stringify(result));return result}
  const no=(result,code)=>{equal(result.ok,false,JSON.stringify(result));if(code)equal(result.error_code,code,JSON.stringify(result));return result}
  const unchanged=(f,fn)=>{const before=snapshot(f),result=fn();equal(snapshot(f),before,'refusal/duplicate changed durable bytes');return result}
  const fixture=(name,{expired=false}={})=>{
    const base=inferenceFixture(),directory=join(root,name),state=join(directory,'state')
    mkdirSync(state,{recursive:true,mode:0o700})
    // Constant public syntax only; no private key exists or is read/generated.
    const identity={...base.owner,approval_key_did:didKeyFromEd25519PublicKey('b'.repeat(64)),
      control_digest:base.proof.material.request.activeControlDigest,authorization_epoch:7}
    const config={statePath:join(state,'authority.json'),stateRoot:state,witnessDir:join(directory,'witness'),
      audience:'aukora-prime.inference',identities:[identity],loginKinds:['owner_key'],provisionTrustedState:true,
      policy:{version:base.operation.policy_version,actions:['inference.generate'],agents:[base.task.agent_id],
        data_scope:['conversation'],maximum_cost:{currency:'USD',amount:'0.010000'}},
      inferenceProfile:base.profileInput,authorizeTask:()=>({authenticated:true,task:structuredClone(base.task)}),
      observeTarget:()=>({target_identity:structuredClone(base.operation.target_identity),state_version:base.operation.expected_state_version})}
    const op=structuredClone(base.operation)
    if(expired)op.expiry='2000-01-01T00:00:00.000Z'
    const proof=structuredClone(base.proof),grant=structuredClone(base.grant)
    proof.operation_digest=operationDigest(op);proof.material.request.operationDigest=proof.operation_digest.slice(7)
    if(expired)proof.expiry='1999-12-31T23:59:59.000Z'
    grant.operation_digest=proof.operation_digest
    const profile=configureInferenceProfile(config.inferenceProfile,new Map([[identity.owner_id,identity]])),
      context=inferencePolicyContext(profile,op,{owner:identity,task:base.task})
    ok(provisionNewAuthorityStore(config))
    const binding={operation:op,consumed_grant:grant,request_id:base.binding.request_uuid,
      request_digest:op.canonical_parameters.request_digest}
    const store=new PrimeApprovalStateStore({statePath:config.statePath,stateRoot:config.stateRoot,
      witnessDir:config.witnessDir,createConsumedIds:false})
    try {
      store.open()
      // Model ONLY the previously authenticated broker metadata. Actual kernel
      // decision/consumption/prepared receipt and fsynced commit are not mocked.
      store.primeBeforeKernel=()=>{
        store.broker.operations[keyOf(op)]={operation:structuredClone(op),operation_digest:operationDigest(op),
          status:'DISPATCHED',review:null,approval:{proof:structuredClone(proof),receipt:null},grant:structuredClone(grant),
          inference_context:structuredClone(context),dispatch:{request_id:binding.request_id,
            request_digest:binding.request_digest,cancel_requested:false,cancel_reason:null,
            receipt:null,receipt_digest:null,settlement_digests:[]}}
      }
      const prepared=store.authorizeAndPrepare({genesis:structuredClone(EMPTY_KERNEL_STATE),
        request:{schema:'aukora-kernel-request-v1',requestId:'keyless-post-dispatch-fixture',
          action:{...KERNEL_ACTION},resource:{namespace:KERNEL_RESOURCE_NAMESPACE,id:identity.subject},
          ring:KERNEL_RING,payloadHash:operationDigest(op).slice(7),consumptionId:'approval:'+proof.nonce,
          humanClearance:false,authorization:null,evidenceRefs:['modelled-prior-owner-review-and-dispatch']},
        policyBytes:canonicalBytes(KERNEL_POLICY),nowMs:Date.now(),effect:{effectId:grant.reservation_id.slice(9),
          descriptorKind:'keyless-modelled-prior-dispatch',targetPath:identity.subject,contentHash:operationDigest(op).slice(7)}})
      check(prepared.ok===true,'unchanged kernel failed to prepare public fixture')
    } finally {store.close()}
    const receipt={...structuredClone(base.settlement.receipt),operation_digest:operationDigest(op)}
    return {...base,config,operation:op,proof,grant,binding,receipt,service:createAuthorityService(config)}
  }
  const input=(f,receipt)=>({...f.binding,receipt,receipt_digest:inferenceEffectReceiptDigest(receipt)})
  const unknown=f=>({...structuredClone(f.receipt),outcome:'outcome_unknown',result_digest:null,usage:null,
    reservation_retained:true,observed_at:'2026-10-01T00:00:01.000Z'})
  try {
    const complete=fixture('complete'),before=read(complete),stamp=complete.receipt.observed_at
    // Drop the first acknowledgement and reopen instead of retrying any effect.
    ok(complete.service.settleInference(input(complete,complete.receipt)))
    const settled=row(complete)
    equal(settled.status,'COMPLETED');equal(settled.dispatch.evidence_kind,'inference')
    check(!Object.hasOwn(settled,'operation')&&!Object.hasOwn(settled,'inference_context'),'terminal payload survived')
    equal(kernel(read(complete)),kernel(before),'settlement changed kernel history')
    equal(unchanged(complete,()=>ok(createAuthorityService({...complete.config,inferenceProfile:undefined})
      .settleInference(input(complete,complete.receipt)))).idempotent,true)
    equal(stamp,complete.receipt.observed_at,'retry changed original observed_at')
    const witness=JSON.parse(snapshot(complete).witness)
    equal(witness.heads[sha('aukora-prime.kernel-history.v1\0'+read(complete).broker.store_id)],before.state.receiptHead.count)
    equal(witness.heads[sha('aukora-prime.broker-history.v1\0'+read(complete).broker.store_id)],read(complete).broker.revision)
    groups.push('real C terminal commit/reopen/lost-ack idempotence preserves unchanged kernel and witnesses')

    const uncertain=fixture('unknown'),uncertainReceipt=unknown(uncertain)
    equal(ok(uncertain.service.settleInference(input(uncertain,uncertainReceipt))).status,'OUTCOME_UNKNOWN')
    const retained=row(uncertain),unknownHistory=kernel(read(uncertain))
    check(retained.operation&&retained.approval&&retained.inference_context&&!retained.schema,'unknown lost full payload')
    equal(retained.dispatch.receipt,uncertainReceipt)
    unchanged(uncertain,()=>no(uncertain.service.settleInference(input(uncertain,uncertain.receipt)),'STALE'))
    const stale={...uncertain.receipt,observed_at:'2026-10-01T00:00:00.000Z'}
    unchanged(uncertain,()=>no(uncertain.service.reconcileInferenceSettlement(input(uncertain,stale)),'INVALID'))
    equal(ok(uncertain.service.reconcileInferenceSettlement(input(uncertain,uncertain.receipt))).status,'COMPLETED')
    equal(kernel(read(uncertain)),unknownHistory)
    const historical=unchanged(uncertain,()=>ok(createAuthorityService({...uncertain.config,inferenceProfile:undefined})
      .settleInference(input(uncertain,uncertainReceipt))))
    equal(historical.status,'OUTCOME_UNKNOWN');equal(historical.receipt_digest,inferenceEffectReceiptDigest(uncertainReceipt))
    equal(historical.idempotent,true);equal(historical.reconciliation_required,true);equal(row(uncertain).status,'COMPLETED')
    equal(row(uncertain).dispatch.settlement_digests,[inferenceEffectReceiptDigest(uncertainReceipt),inferenceEffectReceiptDigest(uncertain.receipt)])
    groups.push('unknown remains full; explicit new facts complete; historical unknown acknowledgement never rolls terminal row back')

    const expired=fixture('expired',{expired:true}),expiredHistory=kernel(read(expired))
    const epochStore=new PrimeApprovalStateStore({statePath:expired.config.statePath,stateRoot:expired.config.stateRoot,
      witnessDir:expired.config.witnessDir,createConsumedIds:false})
    try {epochStore.open();epochStore.load(structuredClone(EMPTY_KERNEL_STATE))
      epochStore.broker.owners[sha(expired.operation.owner_id)].authorization_epoch=8
      epochStore.broker.owners[sha(expired.operation.owner_id)].revoked=true
      epochStore.commitBroker()
    } finally {epochStore.close()}
    equal(ok(createAuthorityService({...expired.config,inferenceProfile:undefined})
      .settleInference(input(expired,expired.receipt))).status,'COMPLETED')
    equal(kernel(read(expired)),expiredHistory)
    groups.push('factual settlement works with expired operation/proof, changed synthetic epoch and missing current inference profile')

    const closed=fixture('bindings'),badReceipt={...closed.receipt,body_sha256:'c'.repeat(64)}
    unchanged(closed,()=>no(closed.service.settleInference(input(closed,badReceipt)),'INVALID'))
    unchanged(closed,()=>no(closed.service.settleInference({...input(closed,closed.receipt),
      consumed_grant:{...closed.grant,reservation_id:'prepared:'+'d'.repeat(64)}}),'UNAUTHORIZED'))
    unchanged(closed,()=>no(closed.service.settleInference({...input(closed,closed.receipt),
      request_digest:'sha256:'+'e'.repeat(64)}),'UNAUTHORIZED'))
    const rpc={version:1,receipt_id:'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',operation_id:closed.operation.operation_id,
      task_id:closed.operation.task_id,owner_id:closed.operation.owner_id,operation_digest:operationDigest(closed.operation),
      grant_id:closed.grant.grant_id,request_id:closed.binding.request_id,status:'completed',stdout:'',stderr:'',exit_code:0,
      rpc_completion:'complete',output_truncated:false,sandbox:{uid:'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        name:'synthetic-sandbox',identity:'synthetic-sandbox/bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',image_digest:'sha256:'+'a'.repeat(64),
        policy_digest:'sha256:'+'b'.repeat(64)},cleanup:'confirmed_absent',started_at:'2026-10-01T00:00:01.000Z',
      finished_at:'2026-10-01T00:00:02.000Z',error_code:null,reconciliation_required:false}
    unchanged(closed,()=>no(closed.service.settle({...closed.binding,receipt:rpc,
      receipt_digest:executionReceiptDigest(rpc)}),'INVALID'))
    const memory={version:1,kind:'prime-memory-effect/v1',operation_id:closed.operation.operation_id,
      operation_digest:operationDigest(closed.operation),grant_id:closed.grant.grant_id,request_id:closed.binding.request_id,
      request_digest:closed.binding.request_digest,owner_subject:closed.owner.subject,action_type:closed.operation.action_type,
      status:'applied',result_digest:memoryResultDigest({fixture:'modelled-incompatible-evidence'}),result:{fixture:'modelled-incompatible-evidence'}}
    unchanged(closed,()=>no(closed.service.settleMemory({...closed.binding,receipt:memory}),'INVALID'))
    groups.push('actual C grant/request/body and cross-kind settlement refusals leave durable state/witness unchanged')

    // One disposable source copy resolves optional dependency loading behavior
    // without renaming a shared peer or editing another checkout.
    const isolated=join(root,'no-peer'),repo=resolve(dirname(fileURLToPath(import.meta.url)),'..','..')
    for(const name of ['authority','contracts'])cpSync(join(repo,'packages',name),join(isolated,'packages',name),{recursive:true,verbatimSymlinks:true})
    const child=spawnSync(process.execPath,['--input-type=module','-e',
      "import assert from 'node:assert/strict';import * as c from './packages/authority/src/index.mjs';import {configureInferenceProfile} from './packages/authority/src/inference-profile.mjs';assert.equal(typeof c.createAuthorityService,'function');assert.equal(configureInferenceProfile(undefined),null);assert.throws(()=>configureInferenceProfile({contexts:[{}]},new Map()),e=>e.error_code==='UNAVAILABLE'&&e.message==='INFERENCE_BUDGET_HELPER_UNAVAILABLE');"],
      {cwd:isolated,encoding:'utf8',timeout:10000})
    equal(child.status,0,child.stderr)
    groups.push('disposable no-peer child loads default C and refuses configured inference before store open')
    return {status:'PASS',cases:groups.length,assertions,groups,
      limits:'Keyless public data only. Prior owner review/dispatch rows are modelled; unchanged kernel/local journal/witness preparation and C factual settlement are real. No signed C owner admission, private IPC, E allowance/outbox, provider, runtime containment or physical power-loss proof.'}
  } finally {rmSync(root,{recursive:true,force:true})}
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {process.stdout.write(JSON.stringify(runInferenceServiceChecks())+'\n')}
  catch(error){process.stderr.write(error.stack+'\n');process.exitCode=1}
}
