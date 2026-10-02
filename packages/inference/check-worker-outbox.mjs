import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { SpendLedger } from './src/ledger.mjs';
import { totalBudgetPolicyDigest, totalBudgetBinding, inferenceBudgetState } from './src/budget-binding.mjs';
import { makeWorkerFixture } from './fixtures/worker-fixture.mjs';

const observed = '2026-10-02T12:00:00.000Z';
const reply = {text:'SYNTHETIC_RESULT_TEXT_NOT_FOR_WORKER_STORAGE',source_ids:['fixture-source'],input_tokens:4,output_tokens:3};
const scope = f => [f.task.owner_id,f.task.task_id,f.request.request_uuid];
const claim = f => ({ok:true,status:'DISPATCHED',consumed_grant:f.consumed_grant,
  request_id:f.intent.request_id,request_digest:f.intent.request_digest});
const ack = payload => ({ok:true,status:payload.receipt.outcome === 'completed' ? 'COMPLETED' : 'OUTCOME_UNKNOWN',
  request_id:payload.request_id,request_digest:payload.request_digest,receipt_digest:payload.receipt_digest,
  idempotent:false,reconciliation_required:payload.receipt.outcome === 'outcome_unknown'});
const amount = micros => `${BigInt(micros)/1000000n}.${String(BigInt(micros)%1000000n).padStart(6,'0')}`;
function store(f) {
  const directory=mkdtempSync(join(tmpdir(),'prime-worker-outbox-')),path=join(directory,'ledger.sqlite');
  let ledger=new SpendLedger(path,{total_budget:f.observation.total_budget});
  return {path,get ledger(){return ledger;},restart(){ledger.close();ledger=new SpendLedger(path);},
    close(){ledger.close();rmSync(directory,{recursive:true,force:true});}};
}
function startHttp(ledger,f) {
  ledger.reserveWorkerIntent(f.intent);ledger.beginWorkerClaim(...scope(f));
  ledger.acceptWorkerClaim(...scope(f),claim(f));ledger.beginWorkerHttp(...scope(f));
}

test('Stored budget digest rejects accounting views/renormalization and stays independent of mutable usage',()=>{
  const f=makeWorkerFixture(),s=store(f);
  try {
    const digest=totalBudgetPolicyDigest(f.observation.total_budget);
    assert.equal(totalBudgetBinding(f.observation.total_budget).policy_digest,digest);
    assert.throws(()=>totalBudgetPolicyDigest({...f.observation.total_budget,ceiling:{currency:'USD',amount:'10'}}),{code:'TOTAL_BUDGET_NOT_NORMALIZED'});
    assert.throws(()=>totalBudgetPolicyDigest(s.ledger.requireTotalBudget(f.task.owner_id,f.route.total_budget_id)),{code:'INVALID_TOTAL_BUDGET'});
    assert.notEqual(totalBudgetPolicyDigest({...f.observation.total_budget,approval_reference:'different-synthetic-approval'}),digest);
    const state=inferenceBudgetState({...f.observation,route:f.route});
    s.ledger.reserveWorkerIntent(f.intent);
    assert.equal(s.ledger.totalBudgetBinding(f.task.owner_id,f.route.total_budget_id).policy_digest,digest);
    assert.equal(inferenceBudgetState({...f.observation,route:f.route,total_budget:s.ledger.storedTotalBudget()}).state_version,state.state_version);
    assert.notEqual(inferenceBudgetState({...f.observation,route:{...f.route,credential_generation:2},credential_generation:2}).state_version,state.state_version);
  } finally {s.close();}
});

test('Intent and worst-case charge commit atomically; capacity refusal creates no orphan task or intent',()=>{
  const sample=makeWorkerFixture();
  const total={...sample.observation.total_budget,ceiling:{currency:'USD',amount:amount(sample.binding.reserved_cost_microusd)}};
  const f=makeWorkerFixture({total_budget:total}),s=store(f);
  try {
    s.ledger.db.exec("CREATE TEMP TRIGGER injected_intent_failure BEFORE INSERT ON worker_intents BEGIN SELECT RAISE(ABORT,'synthetic-intent-failure'); END;");
    assert.throws(()=>s.ledger.reserveWorkerIntent(f.intent),/synthetic-intent-failure/);
    assert.equal(s.ledger.get(...scope(f)),undefined);
    assert.equal(s.ledger.db.prepare('SELECT COUNT(*) AS n FROM tasks').get().n,0);
    assert.equal(s.ledger.totalUsage(f.task.owner_id,f.route.total_budget_id).cost_microusd,0);
    s.ledger.db.exec('DROP TRIGGER injected_intent_failure');
    s.ledger.reserveWorkerIntent(f.intent);
    assert.equal(s.ledger.workerIntent(...scope(f)).phase,'intent_committed');
    assert.equal(s.ledger.get(...scope(f)).charged_cost,f.binding.reserved_cost_microusd);
    const another=makeWorkerFixture({task_id:'second-synthetic-task',request_uuid:randomUUID(),total_budget:total});
    assert.throws(()=>s.ledger.reserveWorkerIntent(another.intent),{code:'TOTAL_SPEND_CAP'});
    assert.equal(s.ledger.get(...scope(another)),undefined);
    assert.throws(()=>s.ledger.task(another.task.owner_id,another.task.task_id),{code:'TASK_NOT_REGISTERED'});
    assert.equal(s.ledger.db.prepare('SELECT COUNT(*) AS n FROM worker_intents').get().n,1);
    assert.equal(s.ledger.db.prepare('SELECT intent FROM worker_intents').get().intent.includes('Synthetic selected public source.'),false);
  } finally {s.close();}
});

test('Interrupted worker phases survive restart with held allowance and cannot replay after unknown recovery',()=>{
  for (const phase of ['intent_committed','claim_started','claimed','http_started']) {
    const f=makeWorkerFixture({task_id:'interrupted-'+phase,request_uuid:randomUUID()}),s=store(f);
    try {
      s.ledger.reserveWorkerIntent(f.intent);
      if (phase!=='intent_committed') s.ledger.beginWorkerClaim(...scope(f));
      if (phase==='claimed'||phase==='http_started') s.ledger.acceptWorkerClaim(...scope(f),claim(f));
      if (phase==='http_started') s.ledger.beginWorkerHttp(...scope(f));
      s.restart();
      assert.equal(s.ledger.workerIntent(...scope(f)).phase,phase);
      assert.equal(s.ledger.get(...scope(f)).charged_cost,f.binding.reserved_cost_microusd);
      assert.throws(()=>s.ledger.reserveWorkerIntent(f.intent),{code:'REQUEST_ALREADY_RESERVED'});
      const evidence=s.ledger.recordWorkerEvidence(...scope(f),null,observed);
      assert.equal(evidence.payload.receipt.reservation_retained,true);
      assert.equal(evidence.payload.receipt.result_digest,null);assert.equal(evidence.payload.receipt.usage,null);
      assert.throws(()=>s.ledger.beginWorkerClaim(...scope(f)),{code:'WORKER_PHASE_CONFLICT'});
      assert.throws(()=>s.ledger.beginWorkerHttp(...scope(f)),{code:'WORKER_PHASE_CONFLICT'});
      assert.equal(s.ledger.usage(f.task.owner_id,f.task.task_id).requests,1);
      assert.equal(s.ledger.pendingWorkerRequests(f.task.owner_id)[0].request_id,f.request.request_uuid);
    } finally {s.close();}
  }
});

test('Only an exact claim reply permits one HTTP phase',()=>{
  const f=makeWorkerFixture(),s=store(f);
  try {
    s.ledger.reserveWorkerIntent(f.intent);s.ledger.beginWorkerClaim(...scope(f));
    for (const malformed of [true,{...claim(f),extra:true},{...claim(f),request_id:randomUUID()},
      {...claim(f),consumed_grant:{...f.consumed_grant,grant_id:'different-grant'}}]) {
      assert.throws(()=>s.ledger.acceptWorkerClaim(...scope(f),malformed),{code:'INVALID_WORKER_CLAIM_REPLY'});
      assert.equal(s.ledger.workerIntent(...scope(f)).phase,'claim_started');
      assert.throws(()=>s.ledger.beginWorkerHttp(...scope(f)),{code:'WORKER_PHASE_CONFLICT'});
    }
    s.ledger.acceptWorkerClaim(...scope(f),claim(f));s.ledger.beginWorkerHttp(...scope(f));
    assert.throws(()=>s.ledger.beginWorkerHttp(...scope(f)),{code:'WORKER_PHASE_CONFLICT'});
    assert.throws(()=>s.ledger.beginWorkerClaim(...scope(f)),{code:'WORKER_PHASE_CONFLICT'});
  } finally {s.close();}
});

test('Evidence, actual charge and outbox roll back together; completed evidence survives lost delivery/restart',()=>{
  const f=makeWorkerFixture(),s=store(f);
  try {
    startHttp(s.ledger,f);
    s.ledger.db.exec("CREATE TEMP TRIGGER injected_evidence_failure BEFORE INSERT ON worker_evidence BEGIN SELECT RAISE(ABORT,'synthetic-evidence-failure'); END;");
    assert.throws(()=>s.ledger.recordWorkerEvidence(...scope(f),reply,observed),/synthetic-evidence-failure/);
    assert.equal(s.ledger.get(...scope(f)).status,'dispatched');
    assert.equal(s.ledger.get(...scope(f)).charged_cost,f.binding.reserved_cost_microusd);
    assert.equal(s.ledger.workerIntent(...scope(f)).phase,'http_started');
    assert.equal(s.ledger.pendingWorkerSettlement(...scope(f)),null);
    s.ledger.db.exec('DROP TRIGGER injected_evidence_failure');
    f.route.output_microusd_per_token=9999; // Caller mutation cannot reinterpret stored rates.
    const evidence=s.ledger.recordWorkerEvidence(...scope(f),reply,observed);
    assert.equal(evidence.payload.receipt.usage.cost_microusd,10);
    assert.equal(s.ledger.get(...scope(f)).charged_cost,10);
    assert.equal(s.ledger.usage(f.task.owner_id,f.task.task_id).requests,1);
    assert.equal(evidence.payload.receipt.reservation_retained,false);
    assert.equal(JSON.stringify(evidence).includes(reply.text),false);
    assert.equal(s.ledger.db.prepare('SELECT payload FROM worker_evidence').get().payload.includes(reply.text),false);
    s.restart();
    assert.deepEqual(s.ledger.pendingWorkerSettlement(...scope(f)),evidence);
    assert.equal(s.ledger.get(...scope(f)).status,'completed');
    assert.throws(()=>s.ledger.acknowledgeWorkerSettlement(...scope(f),evidence.payload.receipt_digest,{...ack(evidence.payload),receipt_digest:'sha256:'+'0'.repeat(64)}),{code:'INVALID_WORKER_SETTLEMENT_REPLY'});
    assert.deepEqual(s.ledger.pendingWorkerSettlement(...scope(f)),evidence);
    s.ledger.acknowledgeWorkerSettlement(...scope(f),evidence.payload.receipt_digest,ack(evidence.payload));
    assert.equal(s.ledger.pendingWorkerSettlement(...scope(f)),null);
    assert.equal(s.ledger.get(...scope(f)).charged_cost,10);
  } finally {s.close();}
});

test('Unknown holds require ordered factual reconciliation; generic setters and stale acknowledgements cannot clear them',()=>{
  const f=makeWorkerFixture(),s=store(f);
  try {
    startHttp(s.ledger,f);
    const unknown=s.ledger.recordWorkerEvidence(...scope(f),null,observed);
    assert.throws(()=>s.ledger.settle(...scope(f),0,0,{}),{code:'WORKER_EVIDENCE_REQUIRED'});
    assert.throws(()=>s.ledger.reconcile(...scope(f),{tokens:0,cost_microusd:0,evidence_id:'untrusted-label'}),{code:'WORKER_EVIDENCE_REQUIRED'});
    assert.throws(()=>s.ledger.transition(...scope(f),'outcome_unknown','completed'),{code:'WORKER_EVIDENCE_REQUIRED'});
    assert.throws(()=>s.ledger.recordWorkerEvidence(...scope(f),reply,observed,{reconciliation:true}),{code:'WORKER_RECONCILIATION_REQUIRED'});
    assert.equal(s.ledger.get(...scope(f)).charged_cost,f.binding.reserved_cost_microusd);
    s.ledger.acknowledgeWorkerSettlement(...scope(f),unknown.payload.receipt_digest,ack(unknown.payload));
    assert.equal(s.ledger.pendingWorkerRequests(f.task.owner_id).length,1); // Acknowledged uncertainty still needs facts.
    assert.throws(()=>s.ledger.recordWorkerEvidence(...scope(f),{...reply,output_tokens:100000},observed,{reconciliation:true}),{code:'INVALID_WORKER_EVIDENCE'});
    const completed=s.ledger.recordWorkerEvidence(...scope(f),reply,'2026-10-02T12:01:00.000Z',{reconciliation:true});
    assert.equal(completed.method,'reconcileInferenceSettlement');
    assert.equal(s.ledger.db.prepare('SELECT COUNT(*) AS n FROM worker_evidence').get().n,2);
    s.ledger.acknowledgeWorkerSettlement(...scope(f),unknown.payload.receipt_digest,{...ack(unknown.payload),idempotent:true});
    assert.equal(s.ledger.pendingWorkerSettlement(...scope(f)).payload.receipt_digest,completed.payload.receipt_digest);
    s.ledger.acknowledgeWorkerSettlement(...scope(f),completed.payload.receipt_digest,ack(completed.payload));
    assert.equal(s.ledger.pendingWorkerRequests(f.task.owner_id).length,0);
    assert.equal(s.ledger.get(...scope(f)).charged_cost,10);
    assert.equal(s.ledger.usage(f.task.owner_id,f.task.task_id).requests,1);
  } finally {s.close();}
});

test('Two local processes cannot each commit worker intent under one-call total allowance',async()=>{
  const sample=makeWorkerFixture(),ceiling={currency:'USD',amount:amount(sample.binding.reserved_cost_microusd)};
  const fixtures=[0,1].map(i=>makeWorkerFixture({task_id:'worker-race-'+i,request_uuid:randomUUID(),total_budget:{ceiling}}));
  const s=store(fixtures[0]),children=[];
  try {
    const workers=fixtures.map(f=>{
      const code=`import {SpendLedger} from ${JSON.stringify(new URL('./src/ledger.mjs',import.meta.url).href)};
        const ledger=new SpendLedger(${JSON.stringify(s.path)}),intent=${JSON.stringify(f.intent)};
        process.stdout.write('READY\\n');await new Promise(r=>process.stdin.once('data',r));
        try{ledger.reserveWorkerIntent(intent);process.stdout.write('reserved\\n');}
        catch(e){process.stdout.write(e.code+'\\n');}finally{ledger.close();}`;
      const child=spawn(process.execPath,['--input-type=module','-e',code],{stdio:['pipe','pipe','pipe']});children.push(child);
      let output='',stderr='';let readyResolve,readyReject;
      const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
      const timer=setTimeout(()=>readyReject(new Error('synthetic worker startup timed out')),5000);
      ready.then(()=>clearTimeout(timer),()=>clearTimeout(timer));
      child.stdout.on('data',data=>{output+=data;if(output.includes('READY\n'))readyResolve();});
      child.stderr.on('data',data=>{stderr+=data;});child.once('error',readyReject);
      const done=once(child,'close').then(([code])=>{if(!output.includes('READY\n'))readyReject(new Error(stderr));assert.equal(code,0,stderr);return output.trim().split('\n').at(-1);});
      done.catch(()=>{});return {child,ready,done};
    });
    await Promise.all(workers.map(w=>w.ready));for(const w of workers)w.child.stdin.end('GO\n');
    const results=await Promise.all(workers.map(w=>w.done));
    assert.deepEqual(results.sort(),['TOTAL_SPEND_CAP','reserved'].sort());
    assert.equal(s.ledger.db.prepare('SELECT COUNT(*) AS n FROM worker_intents').get().n,1);
    assert.equal(s.ledger.db.prepare('SELECT COUNT(*) AS n FROM tasks').get().n,1);
    assert.equal(s.ledger.totalUsage(fixtures[0].task.owner_id,fixtures[0].route.total_budget_id).cost_microusd,sample.binding.reserved_cost_microusd);
  } finally {for(const child of children)if(child.exitCode===null)child.kill();s.close();}
});
