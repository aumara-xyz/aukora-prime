import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { operationDigest } from '../contracts/src/runtime.mjs';
import { makeWorkerFixture } from './fixtures/worker-fixture.mjs';
import { verifyPrivateDispatch, verifyWorkerContinuation } from './src/dispatch-policy.mjs';
import { DeepSeekHttpProvider } from './src/credential-http.mjs';
import { SpendLedger } from './src/ledger.mjs';

const now=Date.parse('2026-10-02T12:00:00.000Z');
function fixture(t) {
  t.mock.timers.enable({apis:['Date'],now});
  const f=makeWorkerFixture();
  f.operation.expiry=new Date(now+10).toISOString();
  f.consumed_grant.operation_digest=operationDigest(f.operation);
  f.intent=verifyPrivateDispatch(f.request,f.route,f.task,f.observation).intent;
  const dir=mkdtempSync(join(tmpdir(),'prime-expiry-'));
  const ledger=new SpendLedger(join(dir,'ledger.sqlite'),{total_budget:f.observation.total_budget});
  const scope=[f.task.owner_id,f.task.task_id,f.request.request_uuid];
  ledger.reserveWorkerIntent(f.intent);ledger.beginWorkerClaim(...scope);
  ledger.acceptWorkerClaim(...scope,{ok:true,status:'DISPATCHED',consumed_grant:f.consumed_grant,
    request_id:f.intent.request_id,request_digest:f.intent.request_digest});
  t.after(()=>{ledger.close();rmSync(dir,{recursive:true,force:true});t.mock.timers.reset();});
  return {...f,ledger,scope};
}
function heldAfterRefusal(f) {
  const evidence=f.ledger.recordWorkerEvidence(...f.scope,null,new Date().toISOString());
  assert.equal(f.ledger.get(...f.scope).charged_cost,f.binding.reserved_cost_microusd);
  assert.equal(f.ledger.get(...f.scope).charged_tokens,f.binding.reserved_tokens);
  assert.equal(f.ledger.usage(f.task.owner_id,f.task.task_id).requests,1);
  assert.deepEqual(evidence.payload.consumed_grant,f.consumed_grant);
  assert.equal(evidence.payload.receipt.reservation_retained,true);
  assert.equal(evidence.payload.receipt.result_digest,null);
  assert.throws(()=>f.ledger.reserveWorkerIntent(f.intent),{code:'REQUEST_ALREADY_RESERVED'});
}

test('Approval expiring during awaited post-claim observation refuses before HTTP fence',async t=>{
  const f=fixture(t);let finishObservation,httpAttempts=0;
  const observed=new Promise(resolve=>{finishObservation=resolve;});
  const continuation=verifyWorkerContinuation(f.intent,()=>observed).then(()=>{
    f.ledger.beginWorkerHttp(...f.scope);httpAttempts++;
  });
  const rejected=assert.rejects(continuation,{code:'DISPATCH_APPROVAL_EXPIRED'});
  await Promise.resolve();t.mock.timers.setTime(now+10);finishObservation({intent:f.intent});
  await rejected;
  assert.equal(httpAttempts,0);assert.equal(f.ledger.workerIntent(...f.scope).phase,'claimed');
  heldAfterRefusal(f);
});

test('Approval expiring during asynchronous custody refuses at transport boundary without a paid request',async t=>{
  const f=fixture(t);let releaseCustody,transportCalls=0,custodyStarted;
  const entered=new Promise(resolve=>{custodyStarted=resolve;});
  const custody=new Promise(resolve=>{releaseCustody=resolve;});
  const http=new DeepSeekHttpProvider({
    useCredential:async (_owner,_generation,callback)=>{custodyStarted();await custody;return callback('INERT_SYNTHETIC_PLACEHOLDER');},
    transport:async()=>{transportCalls++;assert.fail('expired authority must not reach even mocked transport');},
  });
  await verifyWorkerContinuation(f.intent,async()=>({intent:f.intent}));
  f.ledger.beginWorkerHttp(...f.scope);
  const pending=http.generate({...f.request,served_version:f.route.served_version,signal:new AbortController().signal});
  const rejected=assert.rejects(pending,{code:'DISPATCH_APPROVAL_EXPIRED'});
  await entered;t.mock.timers.setTime(now+11);releaseCustody();await rejected;
  assert.equal(transportCalls,0);assert.equal(f.ledger.workerIntent(...f.scope).phase,'http_started');
  heldAfterRefusal(f);
});
