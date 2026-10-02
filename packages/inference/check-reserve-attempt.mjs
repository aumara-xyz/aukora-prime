import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { operationDigest } from '../contracts/src/runtime.mjs';
import { SpendLedger } from './src/ledger.mjs';
import { hash } from './src/policy.mjs';
import { makeWorkerFixture } from './fixtures/worker-fixture.mjs';

const ORIGINAL_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NEXT_UUID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const expected = fixture => ({binding:fixture.binding,operation_id:fixture.operation.operation_id,
  operation_digest:operationDigest(fixture.operation),request_digest:fixture.request.admission.request_digest});

function environment(t, options = {}) {
  const fixture = makeWorkerFixture({request_uuid:ORIGINAL_UUID,...options});
  const home = mkdtempSync(join(tmpdir(),'inference-reserve-attempt-'));
  const path = join(home,'spend.sqlite'), opened = new Set();
  const open = () => {
    const ledger = new SpendLedger(path,{total_budget:fixture.observation.total_budget});
    opened.add(ledger);return ledger;
  };
  const close = ledger => { ledger.close();opened.delete(ledger); };
  t.after(() => {for (const ledger of opened) ledger.close();rmSync(home,{recursive:true,force:true});});
  const ledger = open();ledger.register(fixture.task,fixture.route);
  return {fixture,ledger,open,close};
}

test('Reserve attempt survives an uncertain reply and reopening without retaining reviewed content or charging allowance', t => {
  const {fixture,ledger,open,close} = environment(t,{text:'SYNTHETIC_PROMPT_MUST_NOT_BE_STORED'});
  fixture.operation.nonce='SYNTHETIC_REVIEW_NONCE_MUST_NOT_BE_STORED';
  const usage = ledger.totalUsage(fixture.task.owner_id,fixture.route.total_budget_id);
  let calls = 0;
  const reserveAfterGuard = store => {
    const record = store.beginReserveAttempt(fixture.binding,fixture.operation);
    assert.deepEqual(record,expected(fixture));
    calls++;
    throw new Error('synthetic lost C reserve reply');
  };
  assert.throws(() => reserveAfterGuard(ledger),/synthetic lost C reserve reply/u);
  assert.equal(calls,1);
  const retained = ledger.reserveAttempt(fixture.task.owner_id,fixture.task.task_id,ORIGINAL_UUID);
  assert.deepEqual(retained,expected(fixture));
  assert.deepEqual(Object.keys(retained).sort(),['binding','operation_digest','operation_id','request_digest']);
  assert.equal(JSON.stringify(retained).includes('MUST_NOT_BE_STORED'),false);
  assert.equal(ledger.reserveAttempt('another-owner',fixture.task.task_id,ORIGINAL_UUID),undefined);
  retained.binding.body_sha256=hash('mutating returned inspection');
  retained.operation_id='mutating returned inspection';
  assert.deepEqual(ledger.reserveAttempt(fixture.task.owner_id,fixture.task.task_id,ORIGINAL_UUID),expected(fixture));
  assert.deepEqual(ledger.totalUsage(fixture.task.owner_id,fixture.route.total_budget_id),usage);
  assert.equal(ledger.get(fixture.task.owner_id,fixture.task.task_id,ORIGINAL_UUID),undefined);
  close(ledger);
  const reopened = open();
  assert.throws(() => reserveAfterGuard(reopened),{code:'RESERVE_ATTEMPT_RETAINED'});
  assert.equal(calls,1);
  assert.deepEqual(reopened.reserveAttempt(fixture.task.owner_id,fixture.task.task_id,ORIGINAL_UUID),expected(fixture));
  assert.deepEqual(reopened.totalUsage(fixture.task.owner_id,fixture.route.total_budget_id),usage);
});

test('Original UUID and operation ID remain global fences despite coherent mutation and UUID case changes', t => {
  const {fixture,ledger} = environment(t);
  ledger.beginReserveAttempt(fixture.binding,fixture.operation);
  const changedBody = makeWorkerFixture({request_uuid:ORIGINAL_UUID,text:'Different synthetic request content.'});
  changedBody.operation.operation_id='new-operation-for-old-uuid';
  assert.throws(() => ledger.beginReserveAttempt(changedBody.binding,changedBody.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
  const newUuid = makeWorkerFixture({request_uuid:NEXT_UUID});
  newUuid.operation.operation_id=fixture.operation.operation_id;
  assert.throws(() => ledger.beginReserveAttempt(newUuid.binding,newUuid.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
  const uppercase = makeWorkerFixture({request_uuid:ORIGINAL_UUID.toUpperCase()});
  assert.throws(() => ledger.beginReserveAttempt(uppercase.binding,uppercase.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
  const anotherOwner = makeWorkerFixture({owner_id:'another-owner',task_id:'another-task',request_uuid:ORIGINAL_UUID});
  assert.throws(() => ledger.beginReserveAttempt(anotherOwner.binding,anotherOwner.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
  assert.deepEqual(ledger.reserveAttempt(fixture.task.owner_id,fixture.task.task_id,ORIGINAL_UUID),expected(fixture));
  const separate = makeWorkerFixture({request_uuid:NEXT_UUID});
  assert.deepEqual(ledger.beginReserveAttempt(separate.binding,separate.operation),expected(separate));
  assert.equal(ledger.usage(fixture.task.owner_id,fixture.task.task_id).requests,0);
});

test('Guard rejects altered nested scope, request digest, policy and hidden content before writing an attempt', t => {
  const {fixture,ledger} = environment(t);
  const refuseChanged = edit => {
    const binding = structuredClone(fixture.binding), operation = structuredClone(fixture.operation);
    edit(binding,operation);
    assert.throws(() => ledger.beginReserveAttempt(binding,operation),{code:'INVALID_RESERVE_ATTEMPT'});
    assert.equal(ledger.reserveAttempt(fixture.task.owner_id,fixture.task.task_id,ORIGINAL_UUID),undefined);
  };
  for (const field of ['owner_id','task_id','conversation_id']) {
    refuseChanged((_,operation) => {operation.canonical_parameters.binding[field]='different-'+field;});
  }
  refuseChanged(binding => {binding.body_sha256=hash('different-body');});
  refuseChanged((_,operation) => {operation.canonical_parameters.request_digest='sha256:'+hash('different-request');});
  refuseChanged((_,operation) => {operation.canonical_parameters.total_budget.policy_digest='sha256:'+hash('different-policy');});
  refuseChanged((_,operation) => {operation.canonical_parameters.total_budget.ceiling.amount='9.000000';});
  refuseChanged((_,operation) => {operation.canonical_parameters.limits.max_requests++;});
  refuseChanged((_,operation) => {operation.expected_state_version='sha256:'+hash('different-state');});
  refuseChanged((_,operation) => {operation.target_identity.credential_generation++;});
  refuseChanged((_,operation) => {operation.maximum_cost.amount='0.01000001';});
  refuseChanged(binding => {binding.approval_proof='synthetic forbidden proof';});
  refuseChanged((_,operation) => {operation.canonical_parameters.prompt='synthetic forbidden prompt';});
  refuseChanged((_,operation) => {operation.approval_proof='synthetic forbidden proof';});
  assert.deepEqual(ledger.beginReserveAttempt(fixture.binding,fixture.operation),expected(fixture));
});

test('Failed SQLite commit cannot return a guard or reach C reserve and rolls back the attempt', t => {
  const {fixture,ledger} = environment(t);
  ledger.db.exec(`PRAGMA foreign_keys=ON;
    CREATE TABLE synthetic_commit_parent(id INTEGER PRIMARY KEY);
    CREATE TABLE synthetic_commit_child(parent_id INTEGER REFERENCES synthetic_commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
    CREATE TRIGGER synthetic_commit_failure AFTER INSERT ON reserve_attempts
      BEGIN INSERT INTO synthetic_commit_child VALUES(1); END;`);
  let calls = 0;
  const guardThenCall = () => {ledger.beginReserveAttempt(fixture.binding,fixture.operation);calls++;};
  assert.throws(guardThenCall,/FOREIGN KEY constraint failed/u);
  assert.equal(calls,0);
  assert.equal(ledger.reserveAttempt(fixture.task.owner_id,fixture.task.task_id,ORIGINAL_UUID),undefined);
  assert.equal(ledger.db.prepare('SELECT COUNT(*) AS count FROM synthetic_commit_child').get().count,0);
  assert.equal(ledger.usage(fixture.task.owner_id,fixture.task.task_id).requests,0);
  ledger.db.exec('DROP TRIGGER synthetic_commit_failure');
  guardThenCall();
  assert.equal(calls,1);
});

test('Two independent SQLite handles share the same original request and operation fences', t => {
  const {fixture,ledger,open} = environment(t);
  const second = open();
  const record = ledger.beginReserveAttempt(fixture.binding,fixture.operation);
  assert.deepEqual(second.reserveAttempt(fixture.task.owner_id,fixture.task.task_id,ORIGINAL_UUID),record);
  assert.throws(() => second.beginReserveAttempt(fixture.binding,fixture.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
  const mutated = makeWorkerFixture({request_uuid:NEXT_UUID});
  mutated.operation.operation_id=fixture.operation.operation_id;
  assert.throws(() => second.beginReserveAttempt(mutated.binding,mutated.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
  const separate = makeWorkerFixture({request_uuid:NEXT_UUID});
  second.beginReserveAttempt(separate.binding,separate.operation);
  assert.throws(() => ledger.beginReserveAttempt(separate.binding,separate.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
});

test('Existing worker requests also fence legacy UUIDs and original operation IDs without changing held spend', t => {
  const {fixture,ledger} = environment(t);
  ledger.reserveWorkerIntent(fixture.intent);
  const usage = ledger.totalUsage(fixture.task.owner_id,fixture.route.total_budget_id);
  assert.throws(() => ledger.beginReserveAttempt(fixture.binding,fixture.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
  const differentUuid = makeWorkerFixture({request_uuid:NEXT_UUID});
  differentUuid.operation.operation_id=fixture.operation.operation_id;
  assert.throws(() => ledger.beginReserveAttempt(differentUuid.binding,differentUuid.operation),{code:'RESERVE_ATTEMPT_RETAINED'});
  assert.deepEqual(ledger.totalUsage(fixture.task.owner_id,fixture.route.total_budget_id),usage);
});
