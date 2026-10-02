import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeWorkerFixture} from './fixtures/worker-fixture.mjs';
import {createPrivateInferenceDispatch,createPrivateInferenceReceiver} from './src/private-transport.mjs';
import {InferenceRefusal} from './src/policy.mjs';

const caps={max_request_ms:1000,max_request_bytes:2*1024*1024};
const reply={text:'Synthetic transport reply.',source_ids:[],input_tokens:12,output_tokens:6};
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};

test('Existing envelope is detached at both ends; UUID, digest, body bytes and four-field reply are preserved',async()=>{
  const {request}=makeWorkerFixture(),original=structuredClone(request),gate=deferred();let received,calls=0;
  const receive=createPrivateInferenceReceiver({max_request_bytes:caps.max_request_bytes,service:{
    async dispatch(envelope,{signal}) {received=envelope;assert(signal instanceof AbortSignal);calls++;await gate.promise;return reply;}
  }});
  const dispatch=createPrivateInferenceDispatch({...caps,send:receive});
  const running=dispatch(request,{signal:new AbortController().signal});
  request.body.messages[1].content='caller mutated after submission';
  await Promise.resolve();gate.resolve();
  assert.deepEqual(await running,reply);assert.deepEqual(received,original);assert.equal(calls,1);
  assert.equal(received.admission.consumed_grant.operation_digest,original.admission.consumed_grant.operation_digest);
});

test('Missing runtime, pre-abort, secret fields, changed body and grant binding refuse without submission',async()=>{
  const {request}=makeWorkerFixture();let calls=0;
  assert.throws(()=>createPrivateInferenceDispatch(caps),{code:'PRIVATE_CREDENTIAL_TRANSPORT_REQUIRED'});
  assert.throws(()=>createPrivateInferenceReceiver({max_request_bytes:caps.max_request_bytes}),{code:'PRIVATE_CREDENTIAL_TRANSPORT_REQUIRED'});
  const dispatch=createPrivateInferenceDispatch({...caps,send:async()=>{calls++;return reply;}});
  await assert.rejects(dispatch(request,{signal:AbortSignal.abort()}),{code:'CANCELLED_BEFORE_DISPATCH'});
  await assert.rejects(dispatch(request,{}),{code:'PRIVATE_CANCEL_SCOPE_REQUIRED'});
  for (const mutate of [
    r=>{r.api_key='INERT_PLACEHOLDER';},r=>{r.body.messages[1].content='changed wire body';},
    r=>{r.admission.consumed_grant.operation_digest='sha256:'+'0'.repeat(64);},
    r=>{r.admission.conversation_id='wrong-conversation';},
  ]) {
    const changed=structuredClone(request);mutate(changed);
    await assert.rejects(dispatch(changed,{signal:new AbortController().signal}),{code:'INVALID_PRIVATE_DISPATCH'});
  }
  assert.equal(calls,0);
});

test('Cancellation propagates to a distinct receiver-owned signal; late completion never retries or claims quiescence',async()=>{
  const {request}=makeWorkerFixture(),gate=deferred(),entered=deferred();let calls=0,remoteFlight,received,remoteSignal;
  const receive=createPrivateInferenceReceiver({max_request_bytes:caps.max_request_bytes,service:{
    async dispatch(envelope,{signal}) {calls++;received=structuredClone(envelope);remoteSignal=signal;entered.resolve();await gate.promise;return reply;}
  }});
  const controller=new AbortController();
  const dispatch=createPrivateInferenceDispatch({...caps,send:(envelope,{signal})=>{
    const receiver=new AbortController();signal.addEventListener('abort',()=>receiver.abort(),{once:true});
    remoteFlight=receive(envelope,{signal:receiver.signal});return remoteFlight;
  }});
  const running=dispatch(request,{signal:controller.signal});await entered.promise;controller.abort();
  await assert.rejects(running,{code:'CANCELLED_AFTER_DISPATCH'});
  assert.notEqual(remoteSignal,controller.signal);assert.equal(remoteSignal.aborted,true);
  assert.equal(received.request_uuid,request.request_uuid);assert.equal(calls,1);
  gate.resolve();await assert.rejects(remoteFlight,{code:'PROVIDER_OUTCOME_UNKNOWN'});
  assert.equal(calls,1);
});

test('Timeout and malformed/channel error responses retain unknown outcome without exposing raw error or metadata',async()=>{
  const {request}=makeWorkerFixture(),gate=deferred(),entered=deferred();let calls=0,observedSignal;
  const dispatch=createPrivateInferenceDispatch({...caps,max_request_ms:15,send:async(_request,{signal})=>{
    calls++;observedSignal=signal;entered.resolve();await gate.promise;return reply;
  }});
  const running=dispatch(request,{signal:new AbortController().signal});await entered.promise;
  await assert.rejects(running,{code:'PROVIDER_OUTCOME_UNKNOWN'});assert.equal(observedSignal.aborted,true);
  gate.resolve();await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,1);
  for (const send of [async()=>{throw new Error('INERT_SECRET_ERROR_PLACEHOLDER');},async()=>{
    const error=new InferenceRefusal('CANCELLED_BEFORE_DISPATCH');error.message='INERT_DIAGNOSTIC_PLACEHOLDER';throw error;
  },async()=>({...reply,headers:{authorization:'INERT_PLACEHOLDER'}})]) {
    const malformed=createPrivateInferenceDispatch({...caps,send});
    await assert.rejects(malformed(request,{signal:new AbortController().signal}),error=>{
      assert.equal(error.code,'PROVIDER_OUTCOME_UNKNOWN');assert.equal(error.message,'PROVIDER_OUTCOME_UNKNOWN');return true;
    });
  }
});
