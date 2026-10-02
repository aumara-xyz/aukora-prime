import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hash, canonical } from './src/policy.mjs';
import { operationDigest } from '../contracts/src/runtime.mjs';
import { verifyPrivateDispatch } from './src/dispatch-policy.mjs';
import { makeWorkerFixture } from './fixtures/worker-fixture.mjs';

test('Private dispatch pure verifier: closed scope, admission binding and conservative caps', () => {
  const {route,task,request,prepared,observation} = makeWorkerFixture();
  const scoped = { owner_id:task.owner_id,task_id:task.task_id,conversation_id:task.conversation_id };
  const verify = (value=request,r=route,t=task) => verifyPrivateDispatch(value,r,t,observation);
  const result = verify();
  assert.equal(result.input_bound,prepared.input_bound);
  assert.equal(result.token_reservation,prepared.token_reservation);
  assert.equal(result.cost_reservation,prepared.cost_reservation);
  assert.deepEqual(result.route,route); assert.deepEqual(result.task,task);
  const tamper = (edit,code='PRIVATE_DISPATCH_SCOPE_MISMATCH') => {
    const changed=structuredClone(request); edit(changed); assert.throws(()=>verify(changed),{code});
  };
  tamper(r=>r.request_uuid='22222222-2222-4222-8222-222222222222');
  tamper(r=>r.body.messages[1].content='Changed selected body');
  tamper(r=>r.citations[0].span_sha256=hash('Changed source'));
  tamper(r=>r.binding_hash=hash('wrong binding'));
  tamper(r=>r.admission.conversation_id='other-conversation');
  tamper(r=>r.credential_generation=2);
  tamper(r=>r.total_budget_id='other-total-budget');
  tamper(r=>r.admission.total_budget_id='other-total-budget');
  tamper(r=>r.config_digest='sha256:'+hash('other-config'));
  tamper(r=>r.request_uuid='not-a-uuid');
  for (const field of ['reserved_tokens','reserved_cost_microusd']) tamper(r=>{r[field]++;r.admission[field]++;},'PRIVATE_DISPATCH_BUDGET_MISMATCH');
  tamper(r=>r.secret='SYNTHETIC-SECRET-FIELD','INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.body.tools=[],'INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.body.messages[0].content='Different system policy','INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.body.messages[1].role='system','INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.body.response_format.extra=true,'INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.body.thinking.type='enabled','INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.headers.authorization='SYNTHETIC-FORBIDDEN-HEADER','INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.headers['user-agent']='fixture\r\ninjected','INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.citations[0].secret='SYNTHETIC-FORBIDDEN-CITATION','INVALID_PRIVATE_DISPATCH');
  tamper(r=>r.citations[0].url='https://fixture-user:fixture-password@example.com/docs','INVALID_PRIVATE_DISPATCH');
  const rebind = (r,t=task) => {
    const envelope=structuredClone(request);
    envelope.binding_hash=hash(canonical({...scoped,request_uuid:envelope.request_uuid,route:r,body_hash:envelope.body_sha256,citations:envelope.citations}));
    envelope.admission.binding_hash=envelope.binding_hash;
    return () => verify(envelope,r,t);
  };
  assert.throws(rebind({...route,max_input_tokens:prepared.input_bound-1}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
  assert.throws(rebind({...route,max_output_tokens:request.body.max_tokens-1}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
  assert.throws(rebind(route,{...task,max_tokens:prepared.token_reservation-1}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
  assert.throws(rebind(route,{...task,spend_cap_microusd:prepared.cost_reservation-1}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
  assert.throws(rebind(route,{...task,max_requests:2}),{code:'PRIVATE_DISPATCH_SCOPE_MISMATCH'});
  assert.throws(rebind(route,{...task,allowed_data_classes:['conversation']}),{code:'PRIVATE_DISPATCH_SCOPE_MISMATCH'});
  assert.throws(rebind({...route,input_microusd_per_token:Number.MAX_SAFE_INTEGER}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
});

test('Private admission is exactly fifteen flat fields and validates frozen grant bytes', () => {
  const {route,task,request,observation} = makeWorkerFixture();
  assert.equal(Object.keys(request.admission).length,15);
  const reject = (edit,code='PRIVATE_DISPATCH_SCOPE_MISMATCH') => {
    const changed = structuredClone(request); edit(changed.admission);
    assert.throws(() => verifyPrivateDispatch(changed,route,task,observation),{code});
  };
  reject(admission => {admission.opaque_material={fixture:true};});
  reject(admission => {delete admission.request_digest;});
  reject(admission => {admission.wrapper={operation:admission.operation,consumed_grant:admission.consumed_grant};delete admission.operation;delete admission.consumed_grant;});
  reject(admission => {admission.consumed_grant.extra=true;},'INVALID_DISPATCH_ADMISSION');
  reject(admission => {admission.consumed_grant.operation_digest='sha256:'+hash('different-operation');},'DISPATCH_ADMISSION_MISMATCH');
  reject(admission => {admission.request_digest='sha256:'+hash('different-request');},'DISPATCH_ADMISSION_MISMATCH');
});

test('Nested operation scope and policy changes refuse even with a matching operation digest', () => {
  const {route,task,request,observation} = makeWorkerFixture();
  const rejectOperation = edit => {
    const changed = structuredClone(request);
    edit(changed.admission.operation);
    // Recompute the synthetic grant digest so the changed operation must fail its independent E binding.
    changed.admission.consumed_grant.operation_digest=operationDigest(changed.admission.operation);
    assert.throws(() => verifyPrivateDispatch(changed,route,task,observation),{code:'DISPATCH_ADMISSION_MISMATCH'});
  };
  for (const field of ['owner_id','task_id','conversation_id']) {
    rejectOperation(operation => {operation.canonical_parameters.binding[field]='different-'+field;});
  }
  rejectOperation(operation => {operation.target_identity.model='different-model';});
  rejectOperation(operation => {operation.target_identity.credential_generation=2;});
  rejectOperation(operation => {operation.expected_state_version='sha256:'+hash('different-state');});
  rejectOperation(operation => {operation.canonical_parameters.total_budget.policy_digest='sha256:'+hash('different-budget-policy');});
  rejectOperation(operation => {operation.canonical_parameters.total_budget.ceiling.amount='9.000000';});
  rejectOperation(operation => {operation.canonical_parameters.limits.max_total_tokens++;});
  rejectOperation(operation => {operation.maximum_cost.amount='0.01000001';});
  rejectOperation(operation => {operation.maximum_cost.amount='0.00000001';});
  const changedObservation = structuredClone(observation);
  changedObservation.credential_generation++;
  assert.throws(() => verifyPrivateDispatch(request,route,task,changedObservation),{code:'INFERENCE_BUDGET_STATE_MISMATCH'});
  const changedBudget = structuredClone(observation);
  changedBudget.total_budget.approval_reference='different-reviewed-policy';
  assert.throws(() => verifyPrivateDispatch(request,route,task,changedBudget),{code:'DISPATCH_ADMISSION_MISMATCH'});
  const changedOwner = structuredClone(observation);
  changedOwner.owner.subject='aukora:1:'+hash('different-owner-subject');
  assert.throws(() => verifyPrivateDispatch(request,route,task,changedOwner),{code:'DISPATCH_ADMISSION_MISMATCH'});
});
