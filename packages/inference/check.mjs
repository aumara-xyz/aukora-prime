import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { ExternalDeepSeekGateway, MockDeepSeekProvider, SpendLedger, createDshAdapter, fromPrimeRoute, fromQualifiedPrimeRoute, fromPrimeTask, hash, usdMicros, mockAttributionHeaders,
  OwnerProviderSettings, providerCatalog, mountDshCatalog, RemoteDeepSeekProvider, createProviderSettingsHandler, createAuthorityOwnerAuthenticator } from './src/index.mjs';
import { CredentialVault, assertSeparatedCredentialProcess } from './src/credential-service.mjs';
import { DeepSeekHttpProvider } from './src/credential-http.mjs';
import { createCredentialEntryHandler } from './src/provider-http.mjs';

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
      const disposeCatalog = mountDshCatalog(context);
      assert.equal(context.llm.listConfigurableProviders()[0].provider,'externalDeepSeek');
      disposeCatalog();
      context.llm.registerAdapter(['externalDeepSeek'],adapter);
      stream = options => context.llm.stream(options);
    }
    const chunks = []; for await (const chunk of stream({ provider: 'externalDeepSeek', model: route.model, messages: [], tools: [],
      sessionId: dshTask.conversation_id, maxTokens: 200 })) chunks.push(chunk);
    assert.deepEqual(chunks.map(c => c.type),['block-start','text-delta','block-end','usage','finish']);
    assert.equal(chunks.at(-1).replayState.response.aukora_prime.request_uuid,dshRequest.request_uuid);
    assert.equal(chunks.at(-1).replayState.response.aukora_prime.mode,'mock');
    assert.equal(chunks.at(-1).replayState.response.aukora_prime.conversation_id,dshTask.conversation_id);
    assert.equal(chunks.at(-1).replayState.response.aukora_prime.task_id,dshTask.task_id);
    assert.equal(chunks.at(-1).replayState.response.aukora_prime.grants_authority,false);
    assert.ok(chunks.at(-1).replayState.response.aukora_prime.usage.cost_microusd>0);
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

    // Synthetic key only: test the server-only wire path and encrypted storage without any network call.
    const fixtureSecret = 'SYNTHETIC-KEY-FIXTURE-ONLY';
    const vaultPath = join(dir,'vault.sqlite'), fixtureKey = Buffer.alloc(32,42);
    let vault = new CredentialVault({ path: vaultPath, withEncryptionKey: callback => callback(fixtureKey) });
    const ticket = vault.createTicket(task.owner_id,0,Date.now()+60000);
    assert.deepEqual(await vault.submit({ owner_id: task.owner_id, ticket, secret: fixtureSecret }),{configured:true,generation:1});
    await assert.rejects(vault.submit({ owner_id: task.owner_id, ticket, secret: fixtureSecret }),{code:'CREDENTIAL_TICKET_INVALID'});
    const otherTicket = vault.createTicket(task.owner_id,1,Date.now()+60000);
    await assert.rejects(vault.submit({ owner_id:'other-owner', ticket:otherTicket, secret:fixtureSecret }),{code:'CREDENTIAL_TICKET_INVALID'});
    for (const path of [vaultPath,vaultPath+'-wal']) if (existsSync(path)) assert.equal(readFileSync(path).includes(Buffer.from(fixtureSecret)),false);
    vault.close(); vault = new CredentialVault({ path:vaultPath, withEncryptionKey:callback=>callback(fixtureKey) });
    assert.deepEqual(vault.status(task.owner_id),{configured:true,generation:1});
    assert.throws(() => assertSeparatedCredentialProcess(process.getuid?.() ?? 1000),{code:'SEPARATE_CREDENTIAL_UID_REQUIRED'});
    const prodRoute = fromQualifiedPrimeRoute({ ...routeEnvelope, status:'approved' },{ ...route, pricing_evidence_id:'synthetic-pricing-proof',
      terms_evidence_id:'synthetic-terms-proof', served_version:'synthetic-served-version', credential_generation:1,
      config_digest:'sha256:'+hash('synthetic-approved-route') });
    assert.throws(()=>fromQualifiedPrimeRoute(routeEnvelope,{}),{code:'PRODUCTION_ROUTE_NOT_QUALIFIED'});
    const prodTask = { ...task, task_id:'production-fixture' }; ledger.register(prodTask,prodRoute);
    const prodRequest = () => { const r=request(); r.task_id=prodTask.task_id; r.fragments=r.fragments.map(f=>({...f,task_id:prodTask.task_id}));return r; };
    let wireCalls=0, failWire=false, echoSecret=false;
    const http = new DeepSeekHttpProvider({ useCredential:(owner,generation,callback)=>vault.use(owner,generation,callback),
      transport:async (url,options) => {
        wireCalls++;
        assert.equal(url,'https://api.deepseek.com/chat/completions'); assert.equal(options.redirect,'error');
        assert.equal(options.credentials,'omit'); assert.equal(options.headers.authorization,'Bearer '+fixtureSecret);
        const body=JSON.parse(options.body); assert.equal(body.stream,false); assert.equal(body.response_format.type,'json_object');
        assert.deepEqual(body.thinking,{type:'disabled'});
        assert.equal(JSON.stringify(body).includes('OMIT_'),false);
        if(failWire) return new Response('sensitive provider error '+fixtureSecret,{status:401});
        return new Response(JSON.stringify({model:prodRoute.served_version,usage:{prompt_tokens:8,completion_tokens:25},
          choices:[{finish_reason:'stop',message:{content:JSON.stringify({text:echoSecret?fixtureSecret:'Fixture sourced note.',source_ids:['synthetic-source']})}}]}),{status:200});
      } });
    const proxy = new RemoteDeepSeekProvider({dispatch:(envelope,{signal}) => {
      assert.equal(JSON.stringify(envelope).includes(fixtureSecret),false);
      return http.generate({...envelope,served_version:prodRoute.served_version,signal});
    }});
    const paidGateway = new ExternalDeepSeekGateway({route:prodRoute,ledger,request_home:join(dir,'requests'),provider:proxy,
      authorize_dispatch:async admission => ({...admission,operation_id:'synthetic-consumed-admission'})});
    const wired = await paidGateway.generate(prodRequest());
    assert.equal(wired.outcome,'completed'); assert.equal(wired.mode,'production'); assert.equal(wireCalls,1);
    assert.equal(JSON.stringify(wired).includes(fixtureSecret),false);
    failWire=true; const failedWireRequest=prodRequest(); const failedWire=await paidGateway.generate(failedWireRequest);
    assert.equal(failedWire.outcome,'outcome_unknown'); assert.equal(failedWire.reservation_retained,true);
    assert.equal(JSON.stringify(failedWire).includes(fixtureSecret),false);
    await assert.rejects(paidGateway.generate(failedWireRequest),{code:'REQUEST_ALREADY_RESERVED'});
    assert.equal(wireCalls,2);
    const noGrant = new ExternalDeepSeekGateway({route:prodRoute,ledger,request_home:join(dir,'requests'),provider:proxy});
    await assert.rejects(noGrant.generate(prodRequest()),{code:'CREDENTIALS_AND_SPEND_APPROVAL_PENDING'});
    failWire=false;echoSecret=true;
    const echoed=await paidGateway.generate(prodRequest());
    assert.equal(echoed.outcome,'outcome_unknown');assert.equal(JSON.stringify(echoed).includes(fixtureSecret),false);
    assert.equal(wireCalls,3);

    let approvedCalls=0,qualifiedGeneration;
    const structuralValidator = process.env.PRIME_CONTRACTS_ENTRY
      ? (await import(process.env.PRIME_CONTRACTS_ENTRY)).validateContract
      : (kind,value) => {assert.equal(kind,'ModelRoute'); assert.equal(value.version,1);};
    const settings = new OwnerProviderSettings({path:join(dir,'provider-settings.sqlite'),validateContract:structuralValidator,
      authenticateOwner:async context => context?.fixtureOwner === task.owner_id ? {owner_id:task.owner_id} : undefined,
      approveConfiguration:async input => {approvedCalls++;return{owner_id:input.owner_id,config_digest:input.config_digest,operation_id:'synthetic-config-grant'};},
      qualifiedDispatchStatus:async(owner,digest,generation)=>{assert.equal(owner,task.owner_id);assert.ok(generation>0);return{config_digest:digest,credential_generation:qualifiedGeneration,ready:true};},
      credentials:{status:async owner=>vault.status(owner),createHandoff:async input=>({provider:'externalDeepSeek',method:'POST',path:'/api/prime/inference/credential-entry',
        ticket:vault.createTicket(input.owner_id,input.expected_generation,Date.now()+60000),expires_at:new Date(Date.now()+60000).toISOString()})}});
    const contextOwner={fixtureOwner:task.owner_id};
    const config={route:routeEnvelope,pricing:{input_microusd_per_token:1,output_microusd_per_token:2,max_request_ms:100,
      pricing_evidence_id:'synthetic-pricing-proof',terms_evidence_id:'synthetic-terms-proof',served_version:'synthetic-served-version'}};
    assert.equal(providerCatalog().providers[0].provider,'externalDeepSeek');
    assert.equal(providerCatalog().providers[0].models[0].id,'deepseek-flash');
    assert.equal(providerCatalog().providers[0].models[0].status,'unavailable');
    await assert.rejects(settings.configure({},config,{}),{code:'OWNER_AUTH_REQUIRED'});
    const savedConfig=await settings.configure(contextOwner,config,{synthetic:true});
    assert.equal(savedConfig.paid_requests_enabled,false); assert.equal(approvedCalls,1);
    const configuredStatus=await settings.status(contextOwner);
    assert.equal(configuredStatus.paid_requests_enabled,false);
    assert.equal(configuredStatus.namespace.section.providers.externalDeepSeek.model,route.model);
    assert.equal(configuredStatus.namespace.section.providers.externalDeepSeek.credentialConfigured,true);
    assert.equal(configuredStatus.namespace.section.providers.externalDeepSeek.enabled,false);
    qualifiedGeneration=0;assert.equal((await settings.status(contextOwner)).paid_requests_enabled,false);
    qualifiedGeneration=1;assert.equal((await settings.status(contextOwner)).paid_requests_enabled,true);
    qualifiedGeneration=undefined;assert.equal((await settings.status(contextOwner)).paid_requests_enabled,false);
    assert.throws(()=>settings.setCredential(fixtureSecret),{code:'SECRET_REQUIRES_SEPARATED_OWNER_ENTRY'});
    const handoff=await settings.credentialHandoff(contextOwner,{expected_generation:1,approval_proof:{synthetic:true}});
    assert.equal(JSON.stringify(handoff).includes(fixtureSecret),false);
    const httpCall=async(handler,{method,url,body,origin='https://owner.example',context=contextOwner})=>{
      const req=Readable.from(body===undefined?[]:[Buffer.from(JSON.stringify(body))]);
      Object.assign(req,{method,url,fixtureContext:context,headers:{'content-type':'application/json',origin,'sec-fetch-site':'same-origin'}});
      const response={status:null,body:null,writeHead(status){this.status=status;},end(text){this.body=JSON.parse(text);}};
      const handled=await handler(req,response); assert.equal(handled,true); return response;
    };
    const appHandler=createProviderSettingsHandler({settings,owner_origin:'https://owner.example',ownerContext:async req=>req.fixtureContext});
    const catalogResponse=await httpCall(appHandler,{method:'GET',url:'/api/prime/inference/catalog'});assert.equal(catalogResponse.status,200);
    const wrongOrigin=await httpCall(appHandler,{method:'POST',url:'/api/prime/inference/credential-handoff',body:{expected_generation:1,approval_proof:{synthetic:true}},origin:'https://other.example'});assert.equal(wrongOrigin.status,401);
    const secretToApp=await httpCall(appHandler,{method:'POST',url:'/api/prime/inference/credential-entry',body:{ticket:handoff.ticket,secret:fixtureSecret}});
    assert.equal(secretToApp.status,503);assert.equal(JSON.stringify(secretToApp.body).includes(fixtureSecret),false);
    const entryHandler=createCredentialEntryHandler({owner_origin:'https://owner.example',ownerContext:async req=>req.fixtureContext,
      service:{submitEntry:async(ctx,input)=>{assert.equal(ctx.fixtureOwner,task.owner_id);return{...await vault.submit({owner_id:task.owner_id,...input}),accidental_extra:fixtureSecret};}}});
    const entered=await httpCall(entryHandler,{method:'POST',url:handoff.path,body:{ticket:handoff.ticket,secret:fixtureSecret}});
    assert.equal(entered.status,200);assert.deepEqual(entered.body,{configured:true,generation:2});
    assert.equal(JSON.stringify(entered.body).includes(fixtureSecret),false);
    qualifiedGeneration=1;assert.equal((await settings.status(contextOwner)).paid_requests_enabled,false);
    qualifiedGeneration=2;assert.equal((await settings.status(contextOwner)).paid_requests_enabled,true);

    // Match current C's read interface. This is a fake facade contract check, not genuine owner authentication.
    const sessionFixture='a'.repeat(64);let acceptedCalls=0;
    const actor={ok:true,owner_id:task.owner_id,subject:'aukora:1:'+'b'.repeat(64),authorization_epoch:0,expiry:new Date(Date.now()+60000).toISOString()};
    const ownerAuth=createAuthorityOwnerAuthenticator({authority:{authenticateSession:async input=>{assert.deepEqual(input,{session_token:sessionFixture});acceptedCalls++;return actor;}},
      sessionToken:context=>context?.ownerSession});
    await assert.rejects(ownerAuth({dshCookie:sessionFixture}),{code:'OWNER_AUTH_REQUIRED'});assert.equal(acceptedCalls,0);
    const authenticated=await ownerAuth({ownerSession:sessionFixture});assert.equal(authenticated.owner_id,task.owner_id);
    assert.equal(JSON.stringify(authenticated).includes(sessionFixture),false);
    actor.expiry='2000-01-01T00:00:00Z';await assert.rejects(ownerAuth({ownerSession:sessionFixture}),{code:'OWNER_AUTH_REQUIRED'});
    const failedAuth=createAuthorityOwnerAuthenticator({authority:{authenticateSession:async()=>{throw new Error(sessionFixture);}},sessionToken:()=>sessionFixture});
    try{await failedAuth({});assert.fail('must refuse');}catch(error){assert.equal(error.code,'OWNER_AUTH_REQUIRED');assert.equal(error.message.includes(sessionFixture),false);}
    settings.close();vault.close();fixtureKey.fill(0);
    console.log('PASS mock scope/caps/restart/DSH; fixture-only production HTTPS/proxy/vault/owner settings/entry; external API calls=0');
  } finally { ledger.close(); rmSync(dir,{ recursive: true, force: true }); }
});
