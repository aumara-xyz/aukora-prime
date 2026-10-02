// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable Cordis ownership checks only. No SDK, gateway, guest or OS setup.
// Optional argument: an existing pinned DSH build root, used read-only for the
// actual Cordis/ShellExecutor cases; there is no production donor dependency.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve,join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createDshOpenShellExecutor,installOwnedBash } from '../src/bash.mjs'

const label='owned OpenShell lifecycle'
const policy={mode:'read-only',workspaceRoot:'/sandbox'}
const spec={command:'synthetic inert command',workdir:'/sandbox',timeoutMs:1000,stdoutMaxBytes:128,sandboxPolicy:policy}
const unavailable=()=>{throw Object.assign(new Error('synthetic unavailable'),{code:'UNAVAILABLE'})}
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no});return {promise,resolve,reject}}
let passed=0
const check=async(name,work)=>{await work();passed++;console.log('PASS '+name)}
const refusal=error=>error.code==='UNAVAILABLE'
const make=(executor,ShellExecutor=FaithfulShellExecutor)=>createDshOpenShellExecutor({
  ShellExecutor,executor,resolveSpec:request=>({...spec,...request}),resolveOperation:unavailable,
})

// Faithful to the pinned effect API: the body registers a disposer immediately;
// its wrapper is single-use, and fiber teardown awaits it but logs failures.
class FaithfulContext {
  effects=[];services=new Map();errors=[];onCalls=0
  sandboxPolicy={defaultMode:'read-only',resolve:()=>policy}
  effect(body,label) {
    const raw=body();assert.equal(typeof raw,'function')
    let cleanup
    const dispose=()=>cleanup??=Promise.resolve().then(raw)
    this.effects.push({label,raw,dispose})
    return dispose
  }
  provide(name,value) {
    assert(!this.services.has(name),'duplicate service')
    this.services.set(name,value)
    return this.effect(()=>()=>{this.services.delete(name)},'ctx.provide('+JSON.stringify(name)+')')
  }
  on(){this.onCalls++;throw new Error('event listener is not a teardown hook')}
  async plugin(Executor){return new Executor(this)}
  async dispose(){await Promise.all([...this.effects].reverse().map(async effect=>{
    try{await effect.dispose()}catch(error){this.errors.push(error)}
  }))}
}
class FaithfulShellExecutor {
  constructor(ctx){this.ctx=ctx;ctx.provide('shell',this)}
}
const ownedEffect=ctx=>{
  const effects=ctx.effects.filter(effect=>effect.label===label)
  assert.equal(effects.length,1,'the actual factory must register exactly one ownership effect')
  return effects[0]
}

await check('qualified executor without dispose is refused before mounting',async()=>{
  assert.throws(()=>make({capability:'qualified',execute:unavailable}),refusal)
})
await check('only the immutable unavailable data stub may omit dispose',async()=>{
  assert.throws(()=>make({capability:'unavailable',execute:unavailable}),refusal)
  assert.throws(()=>make(Object.freeze({get capability(){return 'unavailable'},execute:unavailable})),refusal)
  assert.throws(()=>make(Object.freeze({capability:'unavailable',execute:unavailable,transport:{}})),refusal)
  assert.throws(()=>make(Object.freeze(Object.assign(Object.create({transport:{}}),{capability:'unavailable',execute:unavailable}))),refusal)
})
await check('missing Cordis effect refuses before shell registration',async()=>{
  let registered=false
  const Executor=make({capability:'qualified',execute:unavailable,dispose(){}})
  assert.throws(()=>new Executor({provide(){registered=true}}),refusal)
  assert.equal(registered,false)
})
await check('frozen G1 stub mounts and refuses before broker or execution',async()=>{
  let calls=0
  const executor=Object.freeze({capability:'unavailable',execute(){calls++}})
  const Executor=createDshOpenShellExecutor({ShellExecutor:FaithfulShellExecutor,executor,
    resolveSpec:request=>({...spec,...request}),resolveOperation(){calls++;throw new Error('must not resolve')}})
  const ctx=new FaithfulContext(),shell=new Executor(ctx)
  ownedEffect(ctx)
  await assert.rejects(shell.run(shell.resolve({command:spec.command})),refusal)
  await assert.rejects(shell.start(spec),refusal)
  await ctx.dispose();assert.equal(calls,0);assert.equal(ctx.errors.length,0)
})
await check('factory cleanup captures one promise and awaits concurrent teardown',async()=>{
  const barrier=deferred();let calls=0,finished=false
  const executor={capability:'qualified',execute:unavailable,dispose(){assert.equal(this,executor);calls++;return barrier.promise}}
  const ctx=new FaithfulContext(),Executor=make(executor)
  new Executor(ctx)
  const effect=ownedEffect(ctx),first=effect.raw(),second=effect.raw()
  assert.equal(first,second,'the factory itself must share one cleanup promise')
  const unloading=ctx.dispose().then(()=>{finished=true})
  await Promise.resolve();await Promise.resolve()
  assert.equal(calls,1);assert.equal(finished,false)
  barrier.resolve();await Promise.all([first,second,unloading]);await ctx.dispose()
  assert.equal(calls,1);assert.equal(finished,true)
})
await check('synchronous cleanup error becomes a shared rejected promise',async()=>{
  const uncertainty=Object.assign(new Error('synthetic reconciliation pending'),{code:'RECONCILIATION_REQUIRED'})
  let calls=0
  const ctx=new FaithfulContext(),Executor=make({capability:'qualified',execute:unavailable,dispose(){calls++;throw uncertainty}})
  new Executor(ctx)
  const first=ownedEffect(ctx).raw(),second=ownedEffect(ctx).raw()
  assert.equal(first,second);await assert.rejects(first,error=>error===uncertainty)
  await assert.rejects(second,error=>error===uncertainty);assert.equal(calls,1)
})
await check('fiber teardown reports uncertainty without claiming guest absence',async()=>{
  const receipt=Object.freeze({status:'outcome_unknown',cleanup:'unknown',reconciliation_required:true})
  const uncertainty=Object.assign(new Error('synthetic cleanup uncertain'),{code:'RECONCILIATION_REQUIRED',executionReceipt:receipt})
  const ctx=new FaithfulContext(),Executor=make({capability:'qualified',execute:unavailable,dispose(){return Promise.reject(uncertainty)}})
  new Executor(ctx);await ctx.dispose()
  assert.deepEqual(ctx.errors,[uncertainty]);assert.equal(ctx.errors[0].executionReceipt,receipt)
  assert.equal(receipt.cleanup,'unknown');assert.equal(receipt.reconciliation_required,true)
})
await check('installer delegates one lifecycle owner to the mounted factory',async()=>{
  let calls=0
  const executor={capability:'qualified',execute:unavailable,availability:()=>({state:'unavailable'}),dispose(){calls++}}
  const ctx=new FaithfulContext()
  const service=await installOwnedBash(ctx,{ShellExecutor:FaithfulShellExecutor,executor,
    resolveSpec:request=>({...spec,...request}),resolveOperation:unavailable})
  ownedEffect(ctx);assert.equal(ctx.onCalls,0)
  assert.equal(ctx.services.get('aukoraConfinement'),service)
  await assert.rejects(service.confine(),refusal)
  await ctx.dispose();assert.equal(calls,1)
})

if(process.argv[2]) {
  const root=resolve(process.argv[2])
  assert.equal(JSON.parse(readFileSync(join(root,'vendor/cordis/package.json'),'utf8')).version,'4.0.2')
  const {Context}=await import(pathToFileURL(join(root,'vendor/cordis/lib/index.js')))
  const {ShellExecutor}=await import(pathToFileURL(join(root,'packages/shell/shell/lib/index.js')))
  const mount=async executor=>{
    const ctx=new Context()
    ctx.provide('sandboxPolicy',{defaultMode:'read-only',resolve:()=>policy})
    const Executor=make(executor,ShellExecutor),fiber=await ctx.plugin(Executor)
    assert(ctx.get('shell') instanceof Executor)
    assert.equal(fiber.getEffects().filter(effect=>effect.label===label).length,1)
    return {ctx,fiber}
  }
  await check('pinned Cordis 4.0.2 unload awaits factory cleanup once',async()=>{
    const entered=deferred(),barrier=deferred();let calls=0,finished=false
    const {ctx,fiber}=await mount({capability:'qualified',execute:unavailable,dispose(){calls++;entered.resolve();return barrier.promise}})
    const unloading=fiber.dispose().then(()=>{finished=true})
    await entered.promise;assert.equal(finished,false);assert.equal(calls,1)
    barrier.resolve();await unloading;await ctx.fiber.dispose();assert.equal(calls,1)
    assert.equal(ctx.get('shell'),undefined)
  })
  await check('pinned Cordis logs disposer refusal and preserves receipt uncertainty',async()=>{
    const receipt=Object.freeze({status:'outcome_unknown',cleanup:'unknown',reconciliation_required:true})
    const uncertainty=Object.assign(new Error('synthetic cleanup uncertain'),{code:'RECONCILIATION_REQUIRED',executionReceipt:receipt})
    const {ctx,fiber}=await mount({capability:'qualified',execute:unavailable,dispose(){throw uncertainty}})
    const errors=[]
    ctx.logger.exporter({export:message=>{if(message.type==='error')errors.push(...message.args)}})
    await fiber.dispose()
    assert(errors.some(error=>error===uncertainty||error.cause===uncertainty||error.message?.includes(uncertainty.message)))
    assert.equal(receipt.cleanup,'unknown');assert.equal(receipt.reconciliation_required,true)
    await ctx.fiber.dispose()
  })
  await check('pinned Cordis mounts frozen unavailable G1 with no backend call',async()=>{
    let calls=0
    const {ctx,fiber}=await mount(Object.freeze({capability:'unavailable',execute(){calls++}}))
    const shell=ctx.get('shell')
    await assert.rejects(shell.run(shell.resolve({command:spec.command})),refusal)
    await fiber.dispose();await ctx.fiber.dispose();assert.equal(calls,0)
  })
}
console.log('PASS '+passed+' disposable lifecycle checks; no runtime qualification or guest cleanup proof')
