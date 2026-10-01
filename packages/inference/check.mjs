import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { ExternalDeepSeekGateway, MockDeepSeekProvider, SpendLedger, createDshAdapter, fromPrimeRoute, fromPrimeTask, hash, usdMicros, mockAttributionHeaders } from './src/index.mjs';

test('Lane E disposable mock acceptance: exact body, scope, durable caps, uncertainty and DSH stream', async () => {
  const dir = mkdtempSync(join(tmpdir(),'prime-inference-'));
  const dbPath = join(dir,'ledger.sqlite');
  const routeEnvelope = { version: 1, route_id: 'externalDeepSeek', provider: 'deepseek', endpoint: 'https://api.deepseek.com',
    model: 'deepseek-mock-v1', region: 'unqualified-mock', allowed_data_classes: ['conversation','public_source'], allowed_tools: [],
    max_input_tokens: 10000, max_output_tokens: 200, max_requests: 3, task_spend_ceiling: { currency: 'USD', amount: '0.030000' }, status: 'unavailable' };
  const route = fromPrimeRoute(routeEnvelope,{ mode: 'mock', max_request_ms: 100, input_microusd_per_token: 1, output_microusd_per_token: 2 });
  const envelope = { version: 1, owner_id: 'synthetic-owner', agent_id: 'synthetic-agent', task_id: 'synthetic-task', conversation_id: 'synthetic-conversation',
    created_at: '2026-10-01T00:00:00Z', status: 'running', route_id: 'externalDeepSeek', allowed_data_classes: ['conversation','public_source'],
    max_input_tokens: 10000, max_output_tokens: 200, max_requests: 3, task_spend_ceiling: { currency: 'USD', amount: '0.030000' } };
  const task = fromPrimeTask(envelope,route);
  let ledger = new SpendLedger(dbPath);
  const scoped = { owner_id: task.owner_id, task_id: task.task_id, conversation_id: task.conversation_id };
  const text = 'Synthetic public documentation span.';
  const request = () => ({ ...scoped, request_uuid: randomUUID(), max_output_tokens: 200, fragments: [
    { ...scoped, data_class: 'public_source', role: 'user', text,
      citation: { source_id: 'synthetic-source', url: 'https://example.com/docs', captured_at: '2026-10-01T00:00:00Z', span_sha256: hash(text) } },
    { ...scoped, data_class: 'memory', role: 'user', text: 'OMIT_MEMORY_SENTINEL' },
    { ...scoped, data_class: 'screen', role: 'user', text: 'OMIT_SCREEN_SENTINEL' },
    { ...scoped, data_class: 'repo', role: 'user', text: 'OMIT_REPO_SENTINEL' },
    { ...scoped, data_class: 'secret', role: 'user', text: 'OMIT_SECRET_SENTINEL' },
  ] });
  try {
    ledger.register(task,route);
    let observed, calls = 0;
    const mock = new MockDeepSeekProvider();
    const provider = { mode: 'mock', async generate(input) {
      calls++; observed = input;
      const row = ledger.get(task.owner_id,task.task_id,input.request_uuid);
      assert.equal(row.status,'dispatched');
      assert.ok(row.charged_cost > 0);
      return mock.generate(input);
    } };
    let gateway = new ExternalDeepSeekGateway({ route, ledger, request_home: join(dir,'requests'), provider });
    const firstRequest = request();
    const first = await gateway.generate(firstRequest);
    assert.equal(first.outcome,'completed');
    assert.equal(calls,1);
    assert.equal(first.proposal.grantsAuthority,false);
    assert.equal(first.omitted.length,4);
    assert.equal(JSON.stringify(observed.body).includes('OMIT_'),false);
    assert.equal(hash(JSON.stringify(observed.body)),first.receipt.body_sha256);
    assert.ok(observed.headers['user-agent'].startsWith('aukora-prime/'));
    assert.equal(first.receipt.request_uuid,firstRequest.request_uuid);
    assert.equal(first.receipt.source_citation.sha256,hash(first.receipt.line));
    assert.equal(first.receipt.source_citation.requestId,JSON.parse(first.receipt.line).requestId);
    assert.deepEqual(first.receipt.citations,observed.citations);
    await assert.rejects(gateway.generate(firstRequest),{ code: 'REQUEST_ALREADY_RESERVED' });
    const crossed = request(); crossed.fragments[0].conversation_id = 'other-conversation';
    await assert.rejects(gateway.generate(crossed),{ code: 'SCOPE_MISMATCH' });
    const badCite = request(); badCite.fragments[0].citation.span_sha256 = hash('changed');
    await assert.rejects(gateway.generate(badCite),{ code: 'INVALID_CITATION' });
    const secret = request(); secret.fragments[0] = { ...scoped, data_class: 'conversation', role: 'user', text: 'Bearer SYNTHETIC_TOKEN_1234567890' };
    await assert.rejects(gateway.generate(secret),{ code: 'SECRET_DETECTED' });
    const large = request(); large.fragments[0] = { ...scoped, data_class: 'conversation', role: 'user', text: 'x'.repeat(20000) };
    await assert.rejects(gateway.generate(large),{ code: 'TOKEN_CAP' });
    for (const [taskId, changes, code] of [
      ['tight-spend',{ spend_cap_microusd: 1 },'SPEND_CAP'],
      ['tight-tokens',{ max_tokens: 1 },'TASK_TOKEN_CAP'],
    ]) {
      const tight = { ...task, ...changes, task_id: taskId }; ledger.register(tight,route);
      const tightRequest = request(); tightRequest.task_id = taskId;
      tightRequest.fragments = tightRequest.fragments.map(f => ({ ...f, task_id: taskId }));
      await assert.rejects(gateway.generate(tightRequest),{ code });
      assert.equal(ledger.usage(task.owner_id,taskId).requests,0);
    }
    assert.equal(calls,1);
    // Simulate provider outage; its sensitive error must never appear in planner state.
    const failureRequest = request();
    gateway = new ExternalDeepSeekGateway({ route, ledger, request_home: join(dir,'requests'), provider: { mode: 'mock', generate() { throw new Error('SECRET_PROVIDER_ERROR'); } } });
    const failed = await gateway.generate(failureRequest);
    assert.equal(failed.outcome,'outcome_unknown');
    assert.equal(failed.reservation_retained,true);
    assert.equal(JSON.stringify(failed).includes('SECRET_PROVIDER_ERROR'),false);
    const held = ledger.get(task.owner_id,task.task_id,failureRequest.request_uuid);
    assert.equal(held.charged_cost,held.reserved_cost);
    ledger.close(); ledger = new SpendLedger(dbPath);
    assert.equal(ledger.get(task.owner_id,task.task_id,failureRequest.request_uuid).status,'outcome_unknown');
    gateway = new ExternalDeepSeekGateway({ route, ledger, request_home: join(dir,'requests'), provider: mock });
    await assert.rejects(gateway.generate(failureRequest),{ code: 'REQUEST_ALREADY_RESERVED' });
    // Owner cancellation after durable dispatch remains uncertain and held.
    const controller = new AbortController();
    const cancelRequest = request();
    const slow = new ExternalDeepSeekGateway({ route, ledger, request_home: join(dir,'requests'), provider: { mode: 'mock', generate() { controller.abort(); return new Promise(() => {}); } } });
    const cancelled = await slow.generate(cancelRequest,{ signal: controller.signal });
    assert.equal(cancelled.error,'CANCELLED_AFTER_DISPATCH');
    assert.equal(cancelled.reservation_retained,true);
    await assert.rejects(gateway.generate(request()),{ code: 'REQUEST_CAP' });
    ledger.reconcile(task.owner_id,task.task_id,failureRequest.request_uuid,{ tokens: 0, cost_microusd: 0, evidence_id: 'synthetic-provider-no-charge-receipt' });
    assert.equal(ledger.get(task.owner_id,task.task_id,failureRequest.request_uuid).charged_cost,0);
    // Known charges can be reconciled, but request admission slots are never reset by reconciliation.
    await assert.rejects(gateway.generate(request()),{ code: 'REQUEST_CAP' });
    const dshTask = { ...task, task_id: 'dsh-task', max_requests: 1 };
    ledger.register(dshTask,route);
    const dshRequest = request(); dshRequest.task_id = dshTask.task_id;
    dshRequest.fragments = dshRequest.fragments.map(f => ({ ...f, task_id: dshTask.task_id }));
    const realDsh = process.env.PRIME_DSH_LLM_ENTRY ? await import(process.env.PRIME_DSH_LLM_ENTRY) : undefined;
    const adapter = createDshAdapter(realDsh?.LlmAdapter ?? class {},{ gateway, bindRequest: () => dshRequest,
      attributionHeaders: realDsh?.attributionHeaders ?? mockAttributionHeaders });
    assert.equal(adapter.providerRetryPolicy('externalDeepSeek').maxRetries,0);
    assert.deepEqual(await adapter.resolveModel('externalDeepSeek',route.model),{ provider: 'externalDeepSeek', id: route.model, name: route.model });
    let context;
    let stream = options => adapter.stream(options);
    if (realDsh) {
      const requireDsh = createRequire(process.env.PRIME_DSH_LLM_ENTRY);
      const { Context } = await import(requireDsh.resolve('@deepseek-ai/cordis'));
      context = new Context(); await context.plugin(realDsh.default);
      context.llm.registerAdapter(['externalDeepSeek'],adapter);
      stream = options => context.llm.stream(options);
    }
    const chunks = []; for await (const chunk of stream({ provider: 'externalDeepSeek', model: route.model, messages: [], tools: [],
      sessionId: dshTask.conversation_id, maxTokens: 200 })) chunks.push(chunk);
    assert.deepEqual(chunks.map(c => c.type),['block-start','text-delta','block-end','usage','finish']);
    assert.equal(chunks.at(-1).replayState.response.aukora_prime.request_uuid,dshRequest.request_uuid);
    assert.equal(JSON.stringify(chunks.at(-1).replayState).includes(text),false);
    if (context) await context.fiber.dispose();
    const unavailable = new ExternalDeepSeekGateway({ route, ledger, request_home: join(dir,'requests'), provider: { mode: 'network', generate() { assert.fail('never dispatch network'); } } });
    await assert.rejects(unavailable.generate(request()),{ code: 'CREDENTIALS_AND_SPEND_APPROVAL_PENDING' });
    assert.equal(usdMicros({ currency: 'USD', amount: '0.000001' }),1);
    assert.throws(() => usdMicros({ currency: 'USD', amount: 'NaN' }),{ code: 'INVALID_SPEND_CAP' });

    // Two independent processes compete for one admission slot; BEGIN IMMEDIATE must choose exactly one.
    const concurrent = { ...task, task_id: 'concurrent-task', max_requests: 1 };
    ledger.register(concurrent,route);
    const moduleUrl = new URL('./src/index.mjs',import.meta.url).href;
    const worker = `import {randomUUID} from 'node:crypto';
      import {SpendLedger,ExternalDeepSeekGateway,MockDeepSeekProvider} from ${JSON.stringify(moduleUrl)};
      const ledger=new SpendLedger(${JSON.stringify(dbPath)});
      const gateway=new ExternalDeepSeekGateway({route:${JSON.stringify(route)},ledger,request_home:${JSON.stringify(join(dir,'requests'))},provider:new MockDeepSeekProvider()});
      const request=${JSON.stringify({ ...request(), task_id: concurrent.task_id })};
      request.request_uuid=randomUUID();
      request.fragments=request.fragments.map(f=>({...f,task_id:request.task_id}));
      try { console.log((await gateway.generate(request)).outcome); } catch(e) { console.log(e.code); } finally { ledger.close(); }`;
    const runWorker = async () => {
      const child = spawn(process.execPath,['--input-type=module','-e',worker],{ stdio: ['ignore','pipe','pipe'] });
      let output = ''; child.stdout.on('data',chunk => { output += chunk; });
      const [code] = await once(child,'close'); assert.equal(code,0); return output.trim();
    };
    // Each worker needs a different UUID to exercise cap admission, rather than duplicate fencing.
    const results = await Promise.all([runWorker(),runWorker()]);
    assert.equal(results.filter(r => r === 'completed').length,1);
    assert.equal(results.filter(r => r === 'REQUEST_CAP').length,1);
    console.log('PASS mock receipt/scope/filter/caps/restart/outage/cancel/reconcile/concurrent admission/DSH stream; paid calls=0');
  } finally { ledger.close(); rmSync(dir,{ recursive: true, force: true }); }
});
