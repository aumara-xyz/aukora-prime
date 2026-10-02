import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {operationDigest} from '../contracts/src/runtime.mjs';
import {makeWorkerFixture} from './fixtures/worker-fixture.mjs';
import {SpendLedger} from './src/ledger.mjs';
import {verifyPrivateDispatch} from './src/dispatch-policy.mjs';
import {WorkerDispatchContinuation,reviewedReserveAttempt,withCommittedWorkerSettlement} from './src/worker-continuation.mjs';
import {DeepSeekHttpProvider} from './src/credential-http.mjs';
import {assertSeparatedCredentialProcess} from './src/credential-service.mjs';

const lookup=f=>({owner_id:f.task.owner_id,task_id:f.task.task_id,operation_digest:operationDigest(f.operation),
  request_uuid:f.intent.request_id,request_digest:f.intent.request_digest});
const claim=f=>({ok:true,status:'DISPATCHED',consumed_grant:f.consumed_grant,request_id:f.intent.request_id,request_digest:f.intent.request_digest});
const reply={text:'Synthetic continuation reply.',source_ids:[],input_tokens:12,output_tokens:6};
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
function fixture(t,options={}) {
  const f=makeWorkerFixture(options);
  const dir=mkdtempSync(join(tmpdir(),'prime-continuation-')),path=join(dir,'ledger.sqlite');
  let ledger=new SpendLedger(path,{total_budget:f.observation.total_budget});
  ledger.register(f.task,f.route);
  const scope=[f.task.owner_id,f.task.task_id,f.intent.request_id];
  t.after(()=>{ledger.close();rmSync(dir,{recursive:true,force:true});});
  return {...f,scope,path,get ledger(){return ledger;},restart(){ledger.close();ledger=new SpendLedger(path);return ledger;}};
}
function fenced(f) { f.ledger.beginReserveAttempt(f.binding,f.operation); }
function continuation(f,overrides={}) {
  const counters={held:0,claims:0,http:0,settlement:0,observations:0};let worker;
  const verify=()=>verifyPrivateDispatch(f.request,f.route,f.task,f.observation);
  worker=new WorkerDispatchContinuation({ledger:f.ledger,
    observe:async()=>{counters.observations++;return verify();},
    generate:async()=>{assert.equal(counters.held,1);counters.http++;return reply;},
    withDispatch:async input=>{
      assert.equal(input.request_id,f.intent.request_id);
      counters.flight=worker.withCommittedIntent(lookup(f),async admission=>{
        assert.equal(f.ledger.workerIntent(...f.scope).phase,'claim_started');
        counters.held++;
        try {
          counters.claims++;
          return await worker.dispatchCommitted(admission,claim(f));
        } finally {
          assert.equal(f.ledger.workerIntent(...f.scope).phase,'outcome_recorded');
          counters.held--;
        }
      });
      return await counters.flight;
    },
    retrySettlement:async()=>{counters.settlement++;assert.equal(counters.held,0);},...overrides});
  return {worker,counters,verify};
}

test('Private continuation holds observation through exact claim, HTTP and durable evidence; outbox survives restart',async t=>{
  const f=fixture(t);fenced(f);const {worker,counters}=continuation(f);
  await assert.rejects(worker.dispatchCommitted(f.request.admission,claim(f)),{code:'WORKER_CONTINUATION_REQUIRED'});
  assert.deepEqual(await worker.dispatch(f.request),reply);
  assert.equal(counters.claims,1);assert.equal(counters.http,1);assert.equal(counters.held,0);
  assert.equal(f.ledger.usage(f.task.owner_id,f.task.task_id).requests,1);
  assert.equal(f.ledger.get(...f.scope).status,'completed');
  const pending=f.ledger.pendingWorkerSettlement(...f.scope);assert(pending);
  f.restart();
  const matched={...lookup(f),receipt_digest:pending.payload.receipt_digest};
  assert.deepEqual(await withCommittedWorkerSettlement(f.ledger,pending.method,matched,async p=>p),pending.payload);
  await assert.rejects(withCommittedWorkerSettlement(f.ledger,'reconcileInferenceSettlement',matched,async()=>assert.fail()),{code:'WORKER_SETTLEMENT_SCOPE_MISMATCH'});
  const after=continuation(f);
  await assert.rejects(after.worker.dispatch(f.request),{code:'REQUEST_ALREADY_RESERVED'});
  assert.equal(after.counters.claims,0);assert.equal(after.counters.http,0);
  if (process.platform==='darwin') assert.throws(()=>assertSeparatedCredentialProcess(501),{code:'SEPARATE_CREDENTIAL_UID_REQUIRED'});
});

test('Dispatch requires the original durable pre-reserve attempt; a caller mutation cannot rebind the continuation',async t=>{
  const f=fixture(t);const gate=deferred(),seen=deferred();
  let worker,calls=0;
  worker=new WorkerDispatchContinuation({ledger:f.ledger,observe:async request=>{
    seen.resolve();await gate.promise;return verifyPrivateDispatch(request,f.route,f.task,f.observation);
  },generate:async()=>{calls++;return reply;},withDispatch:async()=>assert.fail('unfenced attempt reached C'),retrySettlement:async()=>{}});
  const request=structuredClone(f.request),pending=worker.dispatch(request);
  await seen.promise;request.body.messages[1].content='caller mutation';gate.resolve();
  await assert.rejects(pending,{code:'RESERVE_ATTEMPT_REQUIRED'});
  assert.equal(calls,0);assert.equal(f.ledger.get(...f.scope),undefined);
});

test('Duplicate and mismatched committed callbacks refuse; factual uncertainty commits before observation releases',async t=>{
  const f=fixture(t);fenced(f);let worker,held=0,http=0;
  worker=continuation(f,{withDispatch:async()=>worker.withCommittedIntent(lookup(f),async admission=>{
    held++;
    try {
      await assert.rejects(worker.withCommittedIntent(lookup(f),async()=>{}),{code:'WORKER_CONTINUATION_SCOPE_MISMATCH'});
      return await worker.dispatchCommitted(admission,{...claim(f),request_id:'wrong'});
    } finally {assert.equal(f.ledger.workerIntent(...f.scope).phase,'outcome_recorded');held--;}
  }),generate:async()=>{http++;return reply;},retrySettlement:async()=>assert.equal(held,0)}).worker;
  await assert.rejects(worker.dispatch(f.request),{code:'PROVIDER_OUTCOME_UNKNOWN'});
  assert.equal(http,0);assert.equal(f.ledger.get(...f.scope).charged_cost,f.binding.reserved_cost_microusd);
  assert.equal(f.ledger.pendingWorkerSettlement(...f.scope).payload.receipt.reservation_retained,true);
  await assert.rejects(worker.dispatchCommitted(f.request.admission,claim(f)),{code:'WORKER_CONTINUATION_REQUIRED'});
});

test('Timed-out claim cannot continue later, and original reservation stays held',async t=>{
  const f=fixture(t,{route:{max_request_ms:20}});fenced(f);
  const gate=deferred(),done=deferred();let worker,http=0;
  worker=continuation(f,{withDispatch:async()=>worker.withCommittedIntent(lookup(f),async admission=>{
    await gate.promise;
    try {return await worker.dispatchCommitted(admission,claim(f));} finally {done.resolve();}
  }),generate:async()=>{http++;return reply;}}).worker;
  await assert.rejects(worker.dispatch(f.request),{code:'PROVIDER_OUTCOME_UNKNOWN'});
  assert.equal(worker.activeCount,1);assert.equal(worker.hasOwner(f.task.owner_id),true);
  const pending=f.ledger.pendingWorkerSettlement(...f.scope);gate.resolve();await done.promise;
  await new Promise(resolve=>setImmediate(resolve));assert.equal(worker.activeCount,0);
  assert.equal(http,0);assert.deepEqual(f.ledger.pendingWorkerSettlement(...f.scope),pending);
  assert.equal(f.ledger.get(...f.scope).charged_cost,f.binding.reserved_cost_microusd);
});

test('Timeout during asynchronous custody aborts before transport and cannot overwrite durable uncertainty',async t=>{
  const f=fixture(t,{route:{max_request_ms:25}});fenced(f);
  const gate=deferred(),entered=deferred(),done=deferred();let transports=0;
  const provider=new DeepSeekHttpProvider({useCredential:async(_o,_g,consume)=>{
    entered.resolve();await gate.promise;
    try {return await consume('INERT_SYNTHETIC_PLACEHOLDER');} finally {done.resolve();}
  },transport:async()=>{transports++;assert.fail('revoked custody reached transport');}});
  const {worker,counters}=continuation(f,{generate:r=>provider.generate(r),retrySettlement:async()=>{}});
  const running=worker.dispatch(f.request);await entered.promise;
  await assert.rejects(running,{code:'PROVIDER_OUTCOME_UNKNOWN'});
  assert.equal(worker.activeCount,1);assert.equal(worker.hasRequest(f.intent.request_id),true);
  const pending=f.ledger.pendingWorkerSettlement(...f.scope);gate.resolve();await done.promise;
  await assert.rejects(counters.flight);
  await new Promise(resolve=>setImmediate(resolve));assert.equal(worker.activeCount,0);
  assert.equal(transports,0);assert.deepEqual(f.ledger.pendingWorkerSettlement(...f.scope),pending);
  assert.equal(f.ledger.get(...f.scope).charged_tokens,f.binding.reserved_tokens);
});

test('Reviewed approval is returned only after a durable attempt; lost reserve result refuses after restart',async t=>{
  const f=fixture(t);let reserveCalls=0;
  const proof={version:1,operation_id:f.operation.operation_id,operation_digest:operationDigest(f.operation),
    owner_id:f.operation.owner_id,audience:f.operation.audience,authorization_epoch:1,expiry:f.operation.expiry,
    nonce:'synthetic-approval',material:{kind:'passkey',credential_id:'c3ludGhldGlj',client_data_json:'c3ludGhldGlj',
      authenticator_data:'c3ludGhldGlj',signature:'c3ludGhldGlj',user_handle:null}};
  const approval=async()=>({operation:f.operation,approval_proof:proof});
  async function reserve() {
    const pair=await reviewedReserveAttempt(f.ledger,f.binding,approval);
    assert.deepEqual(pair.approval_proof,proof);assert(f.ledger.reserveAttempt(...f.scope));
    reserveCalls++;throw new Error('synthetic lost reserve reply');
  }
  await assert.rejects(reserve(),/synthetic lost reserve reply/);f.restart();
  await assert.rejects(reserve(),{code:'RESERVE_ATTEMPT_RETAINED'});
  assert.equal(reserveCalls,1);assert.equal(f.ledger.usage(f.task.owner_id,f.task.task_id).requests,0);
  assert.equal(JSON.stringify(f.ledger.reserveAttempt(...f.scope)).includes('signature'),false);
});
