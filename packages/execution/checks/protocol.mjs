// SPDX-License-Identifier: AGPL-3.0-or-later
// One disposable protocol check. No guest, live gateway, credential or host command execution.
import assert from 'node:assert/strict'
import { mkdtemp, rm, realpath } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { OpenShellOwnedExecutor, OwnedLedger, SdkTransport, policyDigest, wirePolicy, createDshOpenShellExecutor } from '../src/index.mjs'
import { operationDigest } from '../../contracts/src/runtime.mjs'

import {settings,request,mock,fixture as makeFixture,MockedProtocolExecutor,MockedDurableBroker} from './harness.mjs'
const roots=[]
async function fixture(options={},hooks={}){const f=await makeFixture(options,hooks);roots.push(f.root);return f}
async function check(label,fn){await fn();console.log('PASS '+label)}

if(process.argv[2]==='lease-child'){
  const ledger=new OwnedLedger(process.argv[3]);await ledger.withLease(async()=>{process.stdout.write('OWNED\n');await new Promise(resolve=>process.stdin.once('data',resolve))});ledger.close();process.exit(0)
}
if(process.argv[2]==='crash-child'){
  const ledger=new OwnedLedger(process.argv[3]);await ledger.withLease(async()=>{process.stdout.write('OWNED\n');process.exit(0)})
}

if(process.argv[2]==='exec-crash-child'){
  const ledger=new OwnedLedger(process.argv[3]),protocol=mock({exit:1,crashAfterExit:true})
  const executor=new MockedProtocolExecutor({settings,transport:new SdkTransport(protocol.raw,{gatewayIdentity:'https://synthetic.invalid:19443/'}),ledger,broker:new MockedDurableBroker(process.argv[3])})
  await executor.execute(request());throw new Error('crash child unexpectedly returned')
}

try {
  await check('typed exit 1 output and final trailers are drained before owned absence',async()=>{
    const f=await fixture({exit:1,afterDelete:3});const r=request();const receipt=await f.executor.execute(r)
    assert.equal(receipt.status,'failed');assert.equal(receipt.exit_code,1);assert.equal(receipt.stdout,'retained synthetic output');assert.equal(receipt.stderr,'retained error');assert.equal(receipt.rpc_completion,'complete');assert.equal(receipt.cleanup,'confirmed_absent')
    const exec=f.protocol.calls.find(([name])=>name==='exec')[1];assert.equal(exec.requestId,r.request_id);assert.deepEqual(exec.command,['bash','-c',r.operation.canonical_parameters.command]);assert.equal(exec.tty,false);assert.equal(exec.noLoginShell,true)
    assert.equal(f.protocol.calls.find(([name])=>name==='create')[1].spec.providers.length,0)
    await assert.rejects(f.executor.execute(r),e=>e.code==='REPLAYED');assert.equal(f.protocol.calls.filter(([name])=>name==='exec').length,1);f.ledger.close()
  })
  await check('local immutable Docker image ID works and mutable image tags refuse',async()=>{
    const f=await fixture(),localSettings={...settings,image_digest:'sha256:'+'c'.repeat(64)}
    const executor=new MockedProtocolExecutor({settings:localSettings,transport:f.transport,ledger:f.ledger,broker:f.broker})
    const r=request();r.image_digest=localSettings.image_digest;r.operation.target_identity.image_digest=localSettings.image_digest;r.consumed_grant.operation_digest=operationDigest(r.operation)
    assert.equal((await executor.execute(r)).status,'completed');assert.equal(f.protocol.calls.find(([name])=>name==='create')[1].spec.template.image,localSettings.image_digest)
    assert.throws(()=>new MockedProtocolExecutor({settings:{...settings,image_digest:'example.invalid/workload:latest'},transport:f.transport,ledger:f.ledger,broker:f.broker}),e=>e.code==='UNAVAILABLE');f.ledger.close()
  })
  await check('typed exit survives trailing SdkError with completion uncertainty',async()=>{
    const f=await fixture({exit:1,trailerFailure:true});const receipt=await f.executor.execute(request())
    assert.equal(receipt.exit_code,1);assert.equal(receipt.stdout,'retained synthetic output');assert.equal(receipt.status,'outcome_unknown');assert.equal(receipt.rpc_completion,'transport_failed');assert.equal(receipt.cleanup,'confirmed_absent');f.ledger.close()
  })
  await check('stdout text cannot forge typed success and no exit never becomes exit 1',async()=>{
    const f=await fixture({events:[{payload:{case:'stdout',value:{data:Buffer.from('{"exitCode":0,"type":"exit"}')}}}]});const receipt=await f.executor.execute(request())
    assert.equal(receipt.status,'outcome_unknown');assert.equal(receipt.exit_code,null);assert.equal(receipt.rpc_completion,'transport_failed');f.ledger.close()
  })
  await check('exact broker refusal and unqualified runtime do not create',async()=>{
    const a=await fixture({}, {beforeClaim:async()=>false});await assert.rejects(a.executor.execute(request()),e=>e.code==='UNAUTHORIZED');assert.equal(a.protocol.calls.length,0);a.ledger.close()
    const b=await fixture({}, {protocolAdmission:()=>false});await assert.rejects(b.executor.execute(request()),e=>e.code==='UNAVAILABLE');assert.equal(b.protocol.calls.length,0);b.ledger.close()
  })
  await check('dispose during broker await and asynchronous qualification cannot dispatch',async()=>{
    let release;const pause=new Promise(resolve=>{release=resolve})
    const f=await fixture({}, {beforeClaim:async()=>{await pause;return true}}),run=f.executor.execute(request())
    await new Promise(resolve=>setImmediate(resolve));const disposing=f.executor.dispose();release();assert.equal((await run).status,'cancelled');await disposing;assert.equal(f.protocol.calls.length,0);f.ledger.close()
    const asyncQualification=await fixture({}, {protocolAdmission:async()=>true});await assert.rejects(asyncQualification.executor.execute(request()),e=>e.code==='UNAVAILABLE');asyncQualification.ledger.close()
  })
  await check('caller mutation cannot replace command or grant during awaited broker confirmation',async()=>{
    let release;const blocked=new Promise(r=>{release=r});const f=await fixture({}, {beforeClaim:async(op)=>{assert.equal(op.canonical_parameters.command,'synthetic inert command');await blocked;return true}})
    const r=request(),run=f.executor.execute(r);await new Promise(resolve=>setImmediate(resolve));r.operation.canonical_parameters.command='mutated';r.consumed_grant.operation_digest='sha256:'+'b'.repeat(64);release();await run
    assert.equal(f.protocol.calls.find(([name])=>name==='exec')[1].command[2],'synthetic inert command');f.ledger.close()
  })
  await check('abort and wall timeout require remote cleanup independent of canceled RPC',async()=>{
    const f=await fixture({waitAbort:true});const controller=new AbortController(),r=request({signal:controller.signal});const run=f.executor.execute(r)
    while(!f.protocol.calls.some(([name])=>name==='exec'))await new Promise(resolve=>setImmediate(resolve));controller.abort();const receipt=await run
    assert.equal(receipt.status,'outcome_unknown');assert.equal(receipt.cleanup,'confirmed_absent');assert.equal(f.executor.cancellationCause(r.request_id),'caller');f.ledger.close()
    const t=await fixture({waitAbort:true}),req=request();req.wall_time_ms=5;req.operation.canonical_parameters.timeout_ms=5;req.consumed_grant.operation_digest=operationDigest(req.operation)
    const timeout=await t.executor.execute(req);assert.equal(timeout.status,'outcome_unknown');assert.equal(t.executor.cancellationCause(req.request_id),'timeout');assert.equal(timeout.cleanup,'confirmed_absent');t.ledger.close()
  })
  await check('unknown create with empty inventory blocks new work; late owned creation reconciles',async()=>{
    const f=await fixture({createFailure:true,invisibleCreate:true});const r=request();const receipt=await f.executor.execute(r)
    assert.equal(receipt.cleanup,'unknown');assert.equal(receipt.reconciliation_required,true);await assert.rejects(f.executor.execute(request()),e=>e.code==='RECONCILIATION_REQUIRED');assert.equal(f.protocol.calls.filter(([name])=>name==='create').length,1)
    // Only original owned resource later becomes visible; no launch replay.
    f.transport.raw.listSandboxes=async()=>({sandboxes:[f.protocol.getSandbox()],nextPageToken:''})
    const oldDelete=f.transport.raw.deleteSandbox;f.transport.raw.deleteSandbox=async(...args)=>{const result=await oldDelete(...args);f.transport.raw.listSandboxes=async()=>({sandboxes:[],nextPageToken:''});return result}
    const result=await f.executor.reconcileOwned();assert.equal(result[0].cleanup,'confirmed_absent');assert.equal(result[0].status,'outcome_unknown');f.ledger.close()
  })
  await check('restart keeps partial output/fence and retries only observed owned cleanup',async()=>{
    const f=await fixture({exit:1,trailerFailure:true,cleanupFailure:true});const r=request();const first=await f.executor.execute(r);assert.equal(first.cleanup,'unknown');f.ledger.close();f.protocol.setCleanup(false)
    const ledger=new OwnedLedger(f.root),executor=new MockedProtocolExecutor({settings,transport:f.transport,ledger,broker:f.broker})
    const receipts=await executor.reconcileOwned();assert.equal(receipts[0].stdout,'retained synthetic output');assert.equal(receipts[0].exit_code,1);assert.equal(receipts[0].rpc_completion,'transport_failed');assert.equal(receipts[0].cleanup,'confirmed_absent');assert.equal(f.protocol.calls.filter(([name])=>name==='exec').length,1)
    await assert.rejects(executor.execute(r),e=>e.code==='RECONCILIATION_REQUIRED');ledger.close()
  })
  await check('actual child death after typed exit keeps durable output and fences restart',async()=>{
    const f=await fixture(),file=fileURLToPath(import.meta.url)
    const child=spawn(process.execPath,[file,'exec-crash-child',f.root],{stdio:['ignore','pipe','pipe']})
    const [code]=await once(child,'close');assert.equal(code,0)
    const [job]=f.ledger.pending();assert.equal(job.receipt.exit_code,1);assert.equal(Buffer.from(job.stdout_b64,'base64').toString(),'retained synthetic output')
    let present=true
    const sandbox={metadata:{id:job.id,name:job.name,workspace:settings.workspace,labels:{'aukora.openshell/owner':job.token}}}
    f.transport.raw.listSandboxes=async()=>({sandboxes:present?[sandbox]:[],nextPageToken:''})
    f.transport.raw.getSandbox=async()=>({sandbox})
    f.transport.raw.deleteSandbox=async()=>{present=false;return {outcome:1,sandboxId:job.id}}
    const [receipt]=await f.executor.reconcileOwned();assert.equal(receipt.cleanup,'confirmed_absent');assert.equal(receipt.stdout,'retained synthetic output');assert.equal(receipt.exit_code,1);assert.equal(receipt.status,'outcome_unknown');assert.equal(receipt.rpc_completion,'transport_failed');assert.equal(f.protocol.calls.filter(([name])=>name==='exec').length,0)
    f.ledger.close()
  })
  await check('identity replacement refuses deletion and retained uncertainty',async()=>{
    const f=await fixture({identityMismatch:true});const receipt=await f.executor.execute(request());assert.equal(receipt.cleanup,'unknown');assert.equal(f.protocol.calls.filter(([name])=>name==='delete').length,0);f.ledger.close()
  })
  await check('cross-process lease excludes live owner and OS releases it on child death',async()=>{
    const f=await fixture(),file=fileURLToPath(import.meta.url)
    const child=spawn(process.execPath,[file,'lease-child',f.root],{stdio:['pipe','pipe','pipe']});await once(child.stdout,'data')
    await assert.rejects(f.ledger.withLease(async()=>{}),e=>e.code==='RECONCILIATION_REQUIRED');const closed=once(child,'close');child.stdin.write('release');await closed
    await f.ledger.withLease(async()=>{})
    const crash=spawn(process.execPath,[file,'crash-child',f.root],{stdio:['ignore','pipe','pipe']});await once(crash,'close');await f.ledger.withLease(async()=>{});f.ledger.close()
  })
  await check('DSH foreground seam resolves exit 1 and refuses infrastructure/background/G1',async()=>{
    class ShellExecutor{constructor(ctx){this.ctx=ctx}}
    const ctx={sandboxPolicy:{defaultMode:'read-only',resolve:()=>({mode:'read-only',workspaceRoot:settings.logical_workspace_root})}}
    const f=await fixture({exit:1}),resolveSpec=r=>({command:r.command,workdir:settings.logical_workspace_root,timeoutMs:500,stdoutMaxBytes:128})
    const make=options=>createDshOpenShellExecutor({ShellExecutor,resolveSpec,executor:f.executor,resolveOperation:async spec=>{const r=request();r.operation.canonical_parameters.command=spec.command;r.consumed_grant.operation_digest=operationDigest(r.operation);return r},...options})
    const klass=make(),shell=new klass(ctx),result=await shell.run(shell.resolve({command:'synthetic inert command'}));assert.equal(result.exitCode,1);assert.equal(result.stdout.text,'retained synthetic output');await assert.rejects(shell.start({}),e=>e.code==='UNAVAILABLE')
    let approved=false;const unqualified=make({executor:{capability:'unavailable',execute(){}},resolveOperation:async()=>{approved=true}}),unqualifiedShell=new unqualified(ctx);await assert.rejects(unqualifiedShell.run(unqualifiedShell.resolve({command:'synthetic'})),e=>e.code==='UNAVAILABLE');assert.equal(approved,false)
    const broken=await fixture({trailerFailure:true}),failureClass=make({executor:broken.executor}),failureShell=new failureClass(ctx);await assert.rejects(failureShell.run(failureShell.resolve({command:'synthetic'})),e=>e.executionReceipt?.rpc_completion==='transport_failed');broken.ledger.close();f.ledger.close()
  })
  console.log('PASS disposable protocol check (mocked gateway; real local SQLite/process lease only)')
} finally {for(const root of roots)await rm(root,{recursive:true,force:true})}
