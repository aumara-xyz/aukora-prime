import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { hash, canonical, prepareRequest } from './src/policy.mjs';
import { verifyPrivateDispatch } from './src/dispatch-policy.mjs';

test('Private dispatch pure verifier: closed scope, admission binding and conservative caps', () => {
  const route = { route_id:'externalDeepSeek',provider:'deepseek',endpoint:'https://api.deepseek.com',model:'synthetic-model',
    region:'synthetic-region',allowed_data_classes:['conversation','public_source'],max_input_tokens:10000,max_output_tokens:200,
    max_request_ms:1000,mode:'production',max_requests:1,spend_cap_microusd:30000,input_microusd_per_token:1,
    output_microusd_per_token:2,transport_status:'approved',pricing_evidence_id:'synthetic-price',terms_evidence_id:'synthetic-terms',
    served_version:'synthetic-version',credential_generation:1,config_digest:'sha256:'+hash('synthetic-config') };
  const task = { owner_id:'synthetic-owner',task_id:'synthetic-task',conversation_id:'synthetic-conversation',route_id:'externalDeepSeek',
    allowed_data_classes:['conversation','public_source'],max_requests:1,max_tokens:10200,max_input_tokens:10000,max_output_tokens:200,spend_cap_microusd:30000 };
  const scoped = { owner_id:task.owner_id,task_id:task.task_id,conversation_id:task.conversation_id };
  const text = 'Synthetic selected public source.';
  const selected = { ...scoped,request_uuid:randomUUID(),max_output_tokens:200,fragments:[{ ...scoped,data_class:'public_source',role:'user',text,
    citation:{source_id:'fixture-source',url:'https://example.com/docs',span_sha256:hash(text),captured_at:'2026-10-01T00:00:00Z'} }] };
  const prepared = prepareRequest(task,route,selected);
  const binding = { ...scoped,request_uuid:selected.request_uuid,body_sha256:prepared.body_hash,binding_hash:prepared.binding_hash,
    citations_sha256:hash(canonical(prepared.citations)),config_digest:route.config_digest,credential_generation:1,
    reserved_tokens:prepared.token_reservation,reserved_cost_microusd:prepared.cost_reservation };
  const request = { ...binding,route_id:'externalDeepSeek',endpoint:route.endpoint,body:prepared.body,citations:prepared.citations,
    headers:{'user-agent':'aukora-prime/synthetic-fixture'},admission:{...binding,operation_id:'synthetic-operation',opaque_material:{fixture:true}} };
  const verify = (value=request,r=route,t=task) => verifyPrivateDispatch(value,r,t);
  const result = verify();
  assert.equal(result.input_bound,prepared.input_bound);
  assert.equal(result.token_reservation,prepared.token_reservation);
  assert.equal(result.cost_reservation,prepared.cost_reservation);
  assert.deepEqual(result.route,route); assert.deepEqual(result.task,task);
  const tamper = (edit,code='PRIVATE_DISPATCH_SCOPE_MISMATCH') => {
    const changed=structuredClone(request); edit(changed); assert.throws(()=>verify(changed),{code});
  };
  tamper(r=>r.request_uuid=randomUUID());
  tamper(r=>r.body.messages[1].content='Changed selected body');
  tamper(r=>r.citations[0].span_sha256=hash('Changed source'));
  tamper(r=>r.binding_hash=hash('wrong binding'));
  tamper(r=>r.admission.conversation_id='other-conversation');
  tamper(r=>r.credential_generation=2);
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
  assert.throws(rebind({...route,max_output_tokens:199}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
  assert.throws(rebind(route,{...task,max_tokens:prepared.token_reservation-1}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
  assert.throws(rebind(route,{...task,spend_cap_microusd:prepared.cost_reservation-1}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
  assert.throws(rebind(route,{...task,max_requests:2}),{code:'PRIVATE_DISPATCH_SCOPE_MISMATCH'});
  assert.throws(rebind(route,{...task,allowed_data_classes:['conversation']}),{code:'PRIVATE_DISPATCH_SCOPE_MISMATCH'});
  assert.throws(rebind({...route,input_microusd_per_token:Number.MAX_SAFE_INTEGER}),{code:'PRIVATE_DISPATCH_BUDGET_MISMATCH'});
});
