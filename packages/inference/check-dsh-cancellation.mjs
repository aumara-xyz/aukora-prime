// SPDX-License-Identifier: AGPL-3.0-or-later
// Attached adapter regression fixtures only: no provider, custody, authority or mounted pilot.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {getEventListeners} from 'node:events';
import {createRequire} from 'node:module';
import {createDshAdapter} from './src/dsh-adapter.mjs';

const deferred=()=>{
  let resolve,reject;
  const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});
  return {promise,resolve,reject};
};
const options=signal=>({provider:'externalDeepSeek',model:'fixture-model',messages:[],tools:[],
  sessionId:'fixture-conversation',maxTokens:32,...(signal?{signal}:{})});
const request=()=>({owner_id:'fixture-owner',task_id:'fixture-task',conversation_id:'fixture-conversation',
  request_uuid:'fixture-request',max_output_tokens:32,fragments:[]});
function fixture(bind,Base=class {}) {
  let binderCalls=0,gatewayCalls=0;
  const result={outcome:'completed',request_uuid:'fixture-request',route_id:'externalDeepSeek',mode:'mock',
    proposal:{text:'Attached fixture response.',source_ids:[],grantsAuthority:false},
    usage:{input_tokens:12,output_tokens:4,cost_microusd:16},
    receipt:{body_sha256:'a'.repeat(64),source_citation:{sessionId:'fixture-conversation',turn:1,
      sha256:'b'.repeat(64),requestId:'fixture-body'},citations:[]},omitted:[]};
  const original=structuredClone(result);
  const adapter=createDshAdapter(Base,{
    gateway:{route:{model:'fixture-model'},async generate(){gatewayCalls++;return result;}},
    bindRequest:async value=>{binderCalls++;return bind?await bind(value):request();},
    attributionHeaders:()=>({'user-agent':'attached-regression-fixture'}),
  });
  return {adapter,result,original,counts:()=>({binderCalls,gatewayCalls})};
}
const cancellation=code=>error=>{
  assert.equal(error.code,code);assert.equal(error.message,code);return true;
};

test('Pre-aborted DSH request never enters host binding or gateway',{timeout:1000},async()=>{
  const f=fixture();
  const iterator=f.adapter.stream(options(AbortSignal.abort('private cancellation detail')));
  await assert.rejects(iterator.next(),cancellation('CANCELLED_BEFORE_DISPATCH'));
  assert.deepEqual(f.counts(),{binderCalls:0,gatewayCalls:0});
});

test('Pinned DSH runtime converts cancelled pending binding into one aborted finish',{
  timeout:5000,
  skip:process.env.PRIME_DSH_LLM_ENTRY?false:'PRIME_DSH_LLM_ENTRY not supplied; actual pinned DSH runtime case skipped',
},async t=>{
  const entry=process.env.PRIME_DSH_LLM_ENTRY;
  const dsh=await import(entry),requireDsh=createRequire(entry);
  const {Context}=await import(requireDsh.resolve('@deepseek-ai/cordis'));
  const context=new Context();
  t.after(async()=>{await context.fiber.dispose();});
  await context.plugin(dsh.default);
  const controller=new AbortController(),entered=deferred(),binding=deferred();
  const f=fixture(()=>{entered.resolve();return binding.promise;},dsh.LlmAdapter);
  context.llm.registerAdapter(['externalDeepSeek'],f.adapter);
  const iterator=context.llm.stream(options(controller.signal))[Symbol.asyncIterator]();
  const next=iterator.next();
  await entered.promise;
  controller.abort('private cancellation detail');
  const terminal=await next;
  assert.equal(terminal.done,false);
  assert.equal(terminal.value.type,'finish');
  assert.equal(terminal.value.reason.kind,'aborted');
  assert.equal(terminal.value.reason.failure.message,'CANCELLED_BEFORE_DISPATCH');
  assert.equal(terminal.value.replayState,undefined);
  assert.deepEqual(f.counts(),{binderCalls:1,gatewayCalls:0});
  assert.deepEqual(await iterator.next(),{value:undefined,done:true});
  binding.resolve(request());
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(f.counts(),{binderCalls:1,gatewayCalls:0});
  assert.equal(getEventListeners(controller.signal,'abort').length,0);
});

test('Abort abandons pending binding, detaches listener and consumes late completion or rejection',
  {timeout:1000},async()=>{
  for (const late of ['resolve','reject']) {
    const controller=new AbortController(),entered=deferred(),binding=deferred();
    const f=fixture(()=>{entered.resolve();return binding.promise;});
    const baseline=getEventListeners(controller.signal,'abort').length;
    const iterator=f.adapter.stream(options(controller.signal)),next=iterator.next();
    await entered.promise;
    assert.equal(getEventListeners(controller.signal,'abort').length,baseline+1);
    controller.abort('private cancellation detail');
    await assert.rejects(next,cancellation('CANCELLED_BEFORE_DISPATCH'));
    assert.equal(getEventListeners(controller.signal,'abort').length,baseline);
    if (late==='resolve') binding.resolve(request());
    else binding.reject(new Error('private late binding detail'));
    // Let late promise reactions run; node:test reports unhandled rejections as failures.
    await new Promise(resolve=>setImmediate(resolve));
    assert.deepEqual(await iterator.next(),{value:undefined,done:true});
    assert.deepEqual(f.counts(),{binderCalls:1,gatewayCalls:0});
  }
});

test('Abort at each response resume suppresses further chunks without changing completed result',
  {timeout:1000},async()=>{
  for (const emitted of [1,2,3,4]) {
    const controller=new AbortController(),f=fixture();
    const iterator=f.adapter.stream(options(controller.signal));
    for (let i=0;i<emitted;i++) assert.equal((await iterator.next()).done,false);
    assert.deepEqual(f.counts(),{binderCalls:1,gatewayCalls:1});
    controller.abort('private cancellation detail');
    await assert.rejects(iterator.next(),cancellation('CANCELLED_AFTER_DISPATCH'));
    assert.deepEqual(await iterator.next(),{value:undefined,done:true});
    assert.deepEqual(f.result,f.original);
    assert.deepEqual(f.counts(),{binderCalls:1,gatewayCalls:1});
  }
});

test('Ordinary response keeps exact five chunks and receipt metadata with or without a signal',
  {timeout:1000},async()=>{
  for (const signal of [undefined,new AbortController().signal]) {
    const f=fixture(),chunks=[];
    for await (const chunk of f.adapter.stream(options(signal))) chunks.push(chunk);
    const text=f.result.proposal.text;
    assert.deepEqual(chunks,[
      {type:'block-start',index:0,blockType:'text'},
      {type:'text-delta',index:0,text},
      {type:'block-end',index:0,block:{type:'text',text}},
      {type:'usage',usage:{inputTokens:12,outputTokens:4}},
      {type:'finish',reason:{kind:'stop'},replayState:{response:{aukora_prime:{
        request_uuid:'fixture-request',body_sha256:f.result.receipt.body_sha256,
        source_citation:f.result.receipt.source_citation,citations:[],mode:'mock',provider:'deepseek',
        route_id:'externalDeepSeek',model:'fixture-model',owner_id:'fixture-owner',task_id:'fixture-task',
        conversation_id:'fixture-conversation',config_digest:null,total_budget_id:null,
        usage:{input_tokens:12,output_tokens:4,cost_microusd:16},grants_authority:false,
      }}}},
    ]);
    assert.deepEqual(f.counts(),{binderCalls:1,gatewayCalls:1});
    assert.deepEqual(f.result,f.original);
    if (signal) assert.equal(getEventListeners(signal,'abort').length,0);
  }
});
