import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { SpendLedger } from './src/ledger.mjs';
import { hash } from './src/policy.mjs';

const OWNER = 'synthetic-total-budget-owner';
const budget = { version:1,budget_id:'synthetic-deepseek-testing-total',owner_id:OWNER,provider:'deepseek',
  route_id:'externalDeepSeek',ceiling:{currency:'USD',amount:'10.000000'},approval_reference:'synthetic-usd10-total-approval' };
const route = { route_id:'externalDeepSeek',provider:'deepseek',endpoint:'https://api.deepseek.com',model:'synthetic-mock-model',
  region:'synthetic-region',allowed_data_classes:['conversation'],max_input_tokens:10000,max_output_tokens:1000,
  max_request_ms:1000,mode:'mock',max_requests:1,spend_cap_microusd:10000000,input_microusd_per_token:1,
  output_microusd_per_token:2,total_budget_id:budget.budget_id };
const task = task_id => ({ owner_id:OWNER,task_id,conversation_id:'synthetic-'+task_id,route_id:'externalDeepSeek',
  allowed_data_classes:['conversation'],max_requests:1,max_tokens:11000,max_input_tokens:10000,max_output_tokens:1000,
  spend_cap_microusd:10000000 });
const prepared = cost => ({ binding_hash:hash('synthetic-binding'),body_hash:hash('synthetic-body'),
  token_reservation:200,cost_reservation:cost });
const receipt = uuid => ({ request_uuid:uuid,body_sha256:hash('synthetic-body') });

test('One USD 10 total ceiling spans tasks and keeps uncertain spend across restart', () => {
  const dir=mkdtempSync(join(tmpdir(),'prime-total-budget-')); const path=join(dir,'ledger.sqlite');
  let ledger;
  try {
    ledger=new SpendLedger(path,{total_budget:budget});
    assert.equal(ledger.requireTotalBudget(OWNER,budget.budget_id).ceiling_microusd,10000000);
    assert.deepEqual(ledger.totalUsage(OWNER,budget.budget_id),{budget_id:budget.budget_id,ceiling_microusd:10000000,
      requests:0,tokens:0,cost_microusd:0,remaining_microusd:10000000});
    const first=task('first-task'),second=task('second-task'),third=task('third-task');
    for (const value of [first,second,third]) ledger.register(value,route);
    const uuid1=randomUUID(),uuid2=randomUUID();
    ledger.reserve(first,uuid1,prepared(6000000),()=>receipt(uuid1));
    ledger.transition(OWNER,first.task_id,uuid1,'reserved','dispatched');
    ledger.transition(OWNER,first.task_id,uuid1,'dispatched','outcome_unknown');
    let rejectedReceipts=0;
    const over=randomUUID();
    assert.throws(()=>ledger.reserve(second,over,prepared(5000000),()=>{rejectedReceipts++;return receipt(over);}),{code:'TOTAL_SPEND_CAP'});
    assert.equal(rejectedReceipts,0); assert.equal(ledger.get(OWNER,second.task_id,over),undefined);
    ledger.reserve(second,uuid2,prepared(4000000),()=>receipt(uuid2));
    assert.equal(ledger.get(OWNER,second.task_id,uuid2).status,'reserved');
    assert.deepEqual(ledger.totalUsage(OWNER,budget.budget_id),{budget_id:budget.budget_id,ceiling_microusd:10000000,
      requests:2,tokens:400,cost_microusd:10000000,remaining_microusd:0});
    ledger.close(); ledger=new SpendLedger(path);
    assert.equal(ledger.requireTotalBudget(OWNER,budget.budget_id).ceiling_microusd,10000000);
    assert.equal(ledger.get(OWNER,first.task_id,uuid1).status,'outcome_unknown');
    assert.equal(ledger.get(OWNER,second.task_id,uuid2).status,'reserved');
    assert.equal(ledger.totalUsage(OWNER,budget.budget_id).remaining_microusd,0);
    assert.throws(()=>ledger.reserve(third,randomUUID(),prepared(1),()=>assert.fail('receipt must follow budget admission')),{code:'TOTAL_SPEND_CAP'});
    assert.throws(()=>ledger.reserve(first,uuid1,prepared(6000000),()=>assert.fail('duplicate must never record')),{code:'REQUEST_ALREADY_RESERVED'});
    assert.throws(()=>ledger.reconcile(OWNER,first.task_id,uuid1,{tokens:50,cost_microusd:1000000,evidence_id:''}),{code:'RECONCILIATION_EVIDENCE_REQUIRED'});
    assert.equal(ledger.totalUsage(OWNER,budget.budget_id).remaining_microusd,0);
    ledger.reconcile(OWNER,first.task_id,uuid1,{tokens:50,cost_microusd:1000000,evidence_id:'synthetic-provider-charge-evidence'});
    assert.deepEqual(ledger.totalUsage(OWNER,budget.budget_id),{budget_id:budget.budget_id,ceiling_microusd:10000000,
      requests:2,tokens:250,cost_microusd:5000000,remaining_microusd:5000000});
    assert.equal(ledger.usage(OWNER,first.task_id).requests,1);
    assert.throws(()=>ledger.reserve(first,randomUUID(),prepared(1),()=>assert.fail('reconciliation cannot restore a slot')),{code:'REQUEST_CAP'});
    const uuid3=randomUUID(); ledger.reserve(third,uuid3,prepared(5000000),()=>receipt(uuid3));
    ledger.transition(OWNER,third.task_id,uuid3,'reserved','dispatched');
    assert.deepEqual(ledger.totalUsage(OWNER,budget.budget_id),{budget_id:budget.budget_id,ceiling_microusd:10000000,
      requests:3,tokens:450,cost_microusd:10000000,remaining_microusd:0});
    ledger.close(); ledger=new SpendLedger(path,{total_budget:budget});
    assert.equal(ledger.get(OWNER,third.task_id,uuid3).status,'dispatched');
    assert.equal(ledger.totalUsage(OWNER,budget.budget_id).cost_microusd,10000000);
  } finally {ledger?.close();rmSync(dir,{recursive:true,force:true});}
});

test('Testing budget identity is immutable; omitted options and another owner cannot reset it', () => {
  const dir=mkdtempSync(join(tmpdir(),'prime-total-budget-scope-')); const path=join(dir,'ledger.sqlite');
  let ledger;
  try {
    ledger=new SpendLedger(path,{total_budget:budget});
    const value=task('identity-task');ledger.register(value,route);const uuid=randomUUID();
    ledger.reserve(value,uuid,prepared(6000000),()=>receipt(uuid));ledger.close();ledger=undefined;
    for (const changed of [{...budget,budget_id:'replacement-budget'}, {...budget,approval_reference:'different-approval'},
      {...budget,ceiling:{currency:'USD',amount:'9.000000'}}, {...budget,owner_id:'other-owner'}]) {
      assert.throws(()=>new SpendLedger(path,{total_budget:changed}),{code:'TOTAL_BUDGET_CONFIG_CHANGED'});
    }
    ledger=new SpendLedger(path);
    assert.equal(ledger.totalUsage(OWNER,budget.budget_id).cost_microusd,6000000);
    assert.throws(()=>ledger.requireTotalBudget('other-owner',budget.budget_id),{code:'TOTAL_BUDGET_SCOPE_MISMATCH'});
    assert.throws(()=>ledger.requireTotalBudget(OWNER,'replacement-budget'),{code:'TOTAL_BUDGET_SCOPE_MISMATCH'});
    assert.throws(()=>ledger.totalUsage('other-owner',budget.budget_id),{code:'TOTAL_BUDGET_SCOPE_MISMATCH'});
    assert.throws(()=>ledger.register({...task('other-owner-task'),owner_id:'other-owner'},route),{code:'TOTAL_BUDGET_SCOPE_MISMATCH'});
    assert.throws(()=>ledger.register(task('wrong-budget-task'),{...route,total_budget_id:'replacement-budget'}),{code:'TOTAL_BUDGET_SCOPE_MISMATCH'});
    const noRouteId={...route};delete noRouteId.total_budget_id;
    const omitted=task('mock-route-without-id');ledger.register(omitted,noRouteId);
    assert.throws(()=>ledger.reserve(omitted,randomUUID(),prepared(5000000),()=>assert.fail('mock route cannot bypass stored total')),{code:'TOTAL_SPEND_CAP'});
    ledger.close();ledger=new SpendLedger(join(dir,'unconfigured.sqlite'));
    assert.throws(()=>ledger.requireTotalBudget(OWNER,budget.budget_id),{code:'TOTAL_BUDGET_REQUIRED'});
    const productionRoute={...route,mode:'production',transport_status:'approved',pricing_evidence_id:'synthetic-price-evidence',
      terms_evidence_id:'synthetic-terms-evidence',served_version:'synthetic-served-version',credential_generation:1,
      config_digest:'sha256:'+hash('synthetic-config')};
    assert.throws(()=>ledger.register(task('unconfigured-production-task'),productionRoute),{code:'TOTAL_BUDGET_REQUIRED'});
    const invalidDescriptors=[
      {...budget,ceiling:{currency:'USD',amount:'0.000000'}}, {...budget,ceiling:{currency:'USD',amount:'9007199254.740992'}},
      {...budget,ceiling:{currency:'USD',amount:'-1'}}, {...budget,ceiling:{currency:'EUR',amount:'10.000000'}},
      {...budget,ceiling:{...budget.ceiling,unexpected:true}}, {...budget,unexpected:true}, {...budget,version:2},
      {...budget,provider:'other-provider'}, {...budget,route_id:'other-route'}, {...budget,approval_reference:''}, {...budget,budget_id:''},
    ];
    for (const [index,descriptor] of invalidDescriptors.entries()) {
      assert.throws(()=>new SpendLedger(join(dir,'invalid-'+index+'.sqlite'),{total_budget:descriptor}),{code:'INVALID_TOTAL_BUDGET'});
    }
  } finally {ledger?.close();rmSync(dir,{recursive:true,force:true});}
});

test('An independently configured other-owner USD 12 fixture has no universal USD 10 limit', () => {
  const dir=mkdtempSync(join(tmpdir(),'prime-configured-budget-'));let ledger;
  try {
    const otherBudget={...budget,owner_id:'synthetic-other-budget-owner',budget_id:'synthetic-configured-usd12-budget',
      approval_reference:'synthetic-other-owner-approval',ceiling:{currency:'USD',amount:'12.000000'}};
    const otherRoute={...route,total_budget_id:otherBudget.budget_id,spend_cap_microusd:12000000};
    const otherTask={...task('other-budget-task'),owner_id:otherBudget.owner_id,spend_cap_microusd:12000000};
    ledger=new SpendLedger(join(dir,'ledger.sqlite'),{total_budget:otherBudget});ledger.register(otherTask,otherRoute);
    assert.equal(ledger.requireTotalBudget(otherBudget.owner_id,otherBudget.budget_id).ceiling_microusd,12000000);
    const uuid=randomUUID();ledger.reserve(otherTask,uuid,prepared(11000000),()=>receipt(uuid));
    assert.deepEqual(ledger.totalUsage(otherBudget.owner_id,otherBudget.budget_id),{budget_id:otherBudget.budget_id,ceiling_microusd:12000000,
      requests:1,tokens:200,cost_microusd:11000000,remaining_microusd:1000000});
  } finally {ledger?.close();rmSync(dir,{recursive:true,force:true});}
});

test('Installing the approved total preserves existing held reservations in the same database', () => {
  const dir=mkdtempSync(join(tmpdir(),'prime-total-budget-existing-'));const path=join(dir,'ledger.sqlite');let ledger;
  try {
    ledger=new SpendLedger(path);const oldRoute={...route};delete oldRoute.total_budget_id;
    const oldTask=task('existing-mock-task'),uuid=randomUUID();ledger.register(oldTask,oldRoute);
    ledger.reserve(oldTask,uuid,prepared(6000000),()=>receipt(uuid));ledger.close();
    ledger=new SpendLedger(path,{total_budget:budget});
    assert.equal(ledger.totalUsage(OWNER,budget.budget_id).cost_microusd,6000000);
    const newTask=task('new-budget-task');ledger.register(newTask,route);
    assert.throws(()=>ledger.reserve(newTask,randomUUID(),prepared(5000000),()=>assert.fail('existing holds cannot be discarded')),{code:'TOTAL_SPEND_CAP'});
    assert.equal(ledger.totalUsage(OWNER,budget.budget_id).requests,1);
  } finally {ledger?.close();rmSync(dir,{recursive:true,force:true});}
});

test('Two OS processes racing different tasks cannot each reserve USD 6 under one USD 10 total', async () => {
  const dir=mkdtempSync(join(tmpdir(),'prime-total-budget-race-'));const path=join(dir,'ledger.sqlite');
  const racers=[task('racer-a'),task('racer-b')];let ledger;const children=[];
  try {
    ledger=new SpendLedger(path,{total_budget:budget});for(const value of racers)ledger.register(value,route);ledger.close();ledger=undefined;
    const moduleUrl=new URL('./src/ledger.mjs',import.meta.url).href;
    const start=value=>{
      const uuid=randomUUID();
      const source=`import {SpendLedger} from ${JSON.stringify(moduleUrl)};
        const ledger=new SpendLedger(${JSON.stringify(path)});
        const task=${JSON.stringify(value)},uuid=${JSON.stringify(uuid)};
        process.stdout.write('READY\\n');
        await new Promise(resolve=>process.stdin.once('data',resolve));
        let receiptCalls=0;
        try {ledger.reserve(task,uuid,${JSON.stringify(prepared(6000000))},()=>{receiptCalls++;return ${JSON.stringify(receipt(uuid))};});
          process.stdout.write(JSON.stringify({outcome:'reserved',receiptCalls})+'\\n');}
        catch(error){process.stdout.write(JSON.stringify({outcome:error.code,receiptCalls})+'\\n');}
        finally {ledger.close();}`;
      const child=spawn(process.execPath,['--input-type=module','-e',source],{stdio:['pipe','pipe','pipe']});children.push(child);
      let stdout='',stderr='';let resolveReady,rejectReady;
      const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject;});
      const startupTimeout=setTimeout(()=>rejectReady(new Error('Fixture worker did not become ready')),5000);
      ready.then(()=>clearTimeout(startupTimeout),()=>clearTimeout(startupTimeout));
      child.stdout.on('data',chunk=>{stdout+=chunk;if(stdout.includes('READY\n'))resolveReady();});
      child.stderr.on('data',chunk=>{stderr+=chunk;});
      child.once('error',rejectReady);
      child.once('close',()=>{if(!stdout.includes('READY\n'))rejectReady(new Error('Fixture worker exited before ready: '+stderr));});
      const completed=once(child,'close').then(([code])=>{
        assert.equal(code,0,stderr);return JSON.parse(stdout.trim().split('\n').at(-1));
      });
      completed.catch(()=>{});
      return {child,ready,completed};
    };
    const workers=racers.map(start);
    await Promise.all(workers.map(worker=>worker.ready));
    for(const worker of workers)worker.child.stdin.end('GO\n');
    const results=await Promise.all(workers.map(worker=>worker.completed));
    assert.equal(results.filter(value=>value.outcome==='reserved').length,1);
    assert.equal(results.filter(value=>value.outcome==='TOTAL_SPEND_CAP').length,1);
    assert.equal(results.find(value=>value.outcome==='reserved').receiptCalls,1);
    assert.equal(results.find(value=>value.outcome==='TOTAL_SPEND_CAP').receiptCalls,0);
    ledger=new SpendLedger(path);
    assert.deepEqual(ledger.totalUsage(OWNER,budget.budget_id),{budget_id:budget.budget_id,ceiling_microusd:10000000,
      requests:1,tokens:200,cost_microusd:6000000,remaining_microusd:4000000});
    assert.equal(racers.reduce((count,value)=>count+ledger.usage(OWNER,value.task_id).requests,0),1);
  } finally {for(const child of children){if(child.exitCode===null)child.kill();}ledger?.close();rmSync(dir,{recursive:true,force:true});}
});
