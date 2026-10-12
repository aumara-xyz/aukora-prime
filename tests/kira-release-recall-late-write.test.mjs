// Refused and timed-out probe writes settle before two absence observations release the journal.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { EventEmitter } from 'node:events'
import fs from 'node:fs'
import { createRequire, syncBuiltinESMExports } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const probeFile = join(root, 'scripts/kira/release-recall-probe.mjs')
const source = fs.readFileSync(probeFile, 'utf8'), mask = process.umask(0o002)
const work = fs.mkdtempSync(join(root, 'tests/.probe-late-write-'))
fs.chmodSync(work, 0o700)
const put = (path, bytes) => { fs.mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); fs.writeFileSync(path, bytes, { mode: 0o600 }) }
let passed = 0, killed = 0, sequence = 0
const check = async (name, action) => { await action(); passed++; console.log(`PASS ${name}`) }
const copy = (name, target, replacement) => {
  let bytes = source.replace("'../lib/is-main.mjs'", JSON.stringify(pathToFileURL(join(root, 'scripts/lib/is-main.mjs')).href))
  if (target) { assert.equal(bytes.split(target).length, 2, `mutation target: ${name}`); bytes = bytes.replace(target, replacement) }
  // Exercise orchestration with synthetic transports on macOS; the shipped CLI remains Linux-only.
  bytes = bytes.replace("if (process.platform !== 'linux') return", 'if (false) return')
  const path = join(work, `${name}.mjs`); put(path, bytes); return path
}
const load = async (...args) => import(pathToFileURL(copy(...args)).href)
const run = (script, scratch, cleanup = true) => spawnSync(process.execPath, [script, ...(cleanup ? ['--cleanup', scratch] : [join(work, 'release'), '--scratch-state', scratch])],
  { encoding: 'utf8', timeout: 5000, env: Object.fromEntries(Object.entries(process.env).filter(([name]) => name !== 'NODE_OPTIONS')) })

try {
  const probe = await load('baseline')
  const native = createRequire(import.meta.url)('node:child_process'), originalFork = native.fork
  const stopped = async (module, timeout = false) => {
    const events = [], child = new EventEmitter()
    child.pid = 123; child.send = () => { if (!timeout) queueMicrotask(() => child.emit('error', Error('synthetic child failure'))) }
    child.kill = signal => { events.push(signal); setTimeout(() => { events.push('closed'); child.emit('close', 1) }, 30); return true }
    native.fork = () => child; syncBuiltinESMExports()
    try {
      await assert.rejects(module.fresh({ action: 'cleanup', release: root }, work, 0))
      assert.equal(events.at(-1), 'closed', 'step rejected while the write child was still running')
      assert.equal(events[0], 'SIGTERM', 'request abortion was skipped')
    } finally { native.fork = originalFork; syncBuiltinESMExports() }
  }
  await check('child failure waits for request abortion and child close', async () => {
    await stopped(probe)
    const mutant = await load('early-error', "child.once('error', () => { childFailed = true; stop() })",
      "child.once('error', () => { childFailed = true; stop(); reject(new Error('child-failed')) })")
    await assert.rejects(stopped(mutant), /still running/u); killed++
  })
  await check('child timeout waits for child close', async () => {
    const short = copy('short-timeout', '120_000', '10')
    await stopped(await import(pathToFileURL(short).href), true)
    const mutant = copy('early-timeout', 'timedOut = true; stop()', "timedOut = true; stop(); reject(new Error('child-timeout'))")
    put(mutant, fs.readFileSync(mutant, 'utf8').replace('120_000', '10'))
    await assert.rejects(stopped(await import(pathToFileURL(mutant).href), true), /still running/u); killed++
  })
  await check('transport abortion waits for in-flight request settlement', async () => {
    const exercise = async module => {
      let settled = false, signal
      const transport = module.probeTransport({ user: 'owner', url: 'http://synthetic.invalid' }, 'run', (_url, options) => new Promise((_resolve, reject) => {
        signal = options.signal
        const complete = () => { settled = true; reject(Error('finished')) }
        const completion = setTimeout(complete, 80)
        signal.addEventListener('abort', () => { clearTimeout(completion); setTimeout(complete, 30) }, { once: true })
      }))
      const request = transport('http://synthetic.invalid/write').catch(() => {})
      await new Promise(resolve => setImmediate(resolve))
      await transport.close()
      assert.equal(signal.aborted, true, 'in-flight request was not aborted')
      assert.equal(settled, true, 'request was still in flight after close')
      await request
    }
    await exercise(probe)
    const mutant = await load('no-drain', 'await Promise.allSettled([...pending])', 'void 0')
    await assert.rejects(exercise(mutant), /still in flight/u); killed++
    const noAbort = await load('no-abort', 'fetch.abort(); await Promise.allSettled([...pending])', 'await Promise.allSettled([...pending])')
    await assert.rejects(exercise(noAbort), /not aborted/u); killed++
  })

  const release = join(work, 'release'), provider = join(work, 'provider.json')
  const config = { openVikingHome: provider, memoryOwner: { stateDir: join(work, 'real-state') } }
  put(join(release, 'package.json'), '{"type":"module"}')
  put(join(release, 'vendor/include/lib/index.js'), 'export const entryListSchema={};export const applyEntryPatches=(_,x)=>x')
  put(join(release, 'vendor/include/lib/node_modules/js-yaml/index.cjs'), 'exports.load=JSON.parse')
  put(join(release, 'vendor/include/lib/node_modules/js-yaml/package.json'), '{"main":"index.cjs"}')
  put(join(release, 'vendor/loader/lib/index.js'), 'export const interpolate=(_,x)=>x')
  put(join(release, 'packages/util/home-paths/lib/index.js'), 'export const dshHomePath="unused"')
  put(join(release, 'plugins/aukora-kira/lib/index.js'), `
import fs from 'node:fs'
export const readConfig=x=>x
export const apply=async(ctx)=>{
 ctx.tools.register({name:'kira_remember',execute:async()=>{
  const pending=fetch('http://synthetic.invalid/api/v1/content/write',{signal:AbortSignal.timeout(5000)})
  pending.catch(()=>{})
  if(JSON.parse(fs.readFileSync(${JSON.stringify(provider)},'utf8')).waitWrite)await pending
  await Promise.resolve();throw Error('write refused')
 }})
 ctx.tools.register({name:'kira_recall',execute:async({lexical})=>({remembered:{method:lexical?'lexical-bm25-bigram':'openviking-semantic',degraded:false,state:'empty'},snippets:[]})})
 ctx.inject([],web=>web.get('webServer').register({path:'/api/kira/memories/forget',handler:async(_req,res)=>res.end(JSON.stringify({forgotten:false,openviking:{removed:false}}))}))
}
`)
  put(join(release, 'plugins/aukora-kira/lib/gate-capture-host.mjs'), 'export const createGateCaptureHostPlugin=options=>({apply:async ctx=>(await options.loadKira()).apply(ctx)})')
  put(join(release, 'aukora-composition.patch.yml'), JSON.stringify([{ id: 'aukora-kira', name: './plugins/aukora-kira/lib/gate-capture-host.mjs', config }]))
  put(join(release, 'plugins/aukora-kira/lib/recall-openviking.mjs'), `
import fs from 'node:fs'
export const readBridgeConfig=()=>{
 globalThis.fetch=async(url,options={})=>{
  const state=JSON.parse(fs.readFileSync(${JSON.stringify(provider)},'utf8')),path=new URL(url).pathname
  if(path==='/api/v1/content/write'){
   state.started=true;fs.writeFileSync(${JSON.stringify(provider)},JSON.stringify(state))
   return new Promise((_resolve,reject)=>{
    const keepalive=state.waitWrite?setInterval(()=>{},1000):undefined
    if(state.resistAbort)return
    options.signal.addEventListener('abort',()=>{
     clearInterval(keepalive)
     const current=JSON.parse(fs.readFileSync(${JSON.stringify(provider)},'utf8'));current.aborted=true;fs.writeFileSync(${JSON.stringify(provider)},JSON.stringify(current))
     setTimeout(()=>{const current=JSON.parse(fs.readFileSync(${JSON.stringify(provider)},'utf8'));current.finished=true;fs.writeFileSync(${JSON.stringify(provider)},JSON.stringify(current));reject(Error('aborted'))},30)
    },{once:true})
   })
  }
  if(state.acceptAt&&Date.now()>=state.acceptAt){state.present=true;delete state.acceptAt}
  let status=200,result={memories:[],resources:[]}
  if(options.method==='DELETE'){state.present=false;state.deletes++}
  if(path==='/api/v1/content/read'){state.reads++;status=state.present?200:404}
  if(path==='/api/v1/search/find'){
   if(state.present)result.memories=[{uri:state.uri}]
   if(state.late&&!state.acceptAt&&!state.present){state.late=false;state.acceptAt=Date.now()+50}
   if(state.failSecond&&state.reads===2)status=500
  }
  fs.writeFileSync(${JSON.stringify(provider)},JSON.stringify(state))
  return {status,ok:status===200,json:async()=>({status:status===200?'ok':'error',result})}
 }
 return {configured:true,url:'http://synthetic.invalid',user:'owner',account:'aukora',key:'fixture',timeoutMs:1000}
}
export const createOpenVikingRecall=()=>({available:async()=>({ok:true})})
`)
  const fixture = (name, controls = {}) => {
    const scratch = join(work, name); fs.mkdirSync(scratch, { mode: 0o700 })
    const run = '00000000-0000-4000-8000-000000000000', sentence = `Scarlet bicycle ${run} parked beneath maple foliage.`
    const hash = createHash('sha256').update(sentence).digest('hex')
    const saved = { release, run, sentence, user: 'owner', account: 'aukora', url: 'http://synthetic.invalid',
      uri: `viking://user/owner/memories/kira-release-probe/${run}/content/${hash}.md` }
    put(join(scratch, 'release-probe.json'), JSON.stringify(saved))
    put(provider, JSON.stringify({ uri: saved.uri, deletes: 0, reads: 0, present: false, ...controls }))
    return { scratch, saved }
  }
  const script = copy('cleanup')
  await check('failed child aborts and drains its actual transport before acknowledging completion', async () => {
    const exercise = async module => {
      const { scratch, saved } = fixture(`child-drain-${sequence++}`)
      const input = { ...await module.readReleaseConfig(release), ...saved, action: 'remember', config }
      const held = fs.openSync(scratch, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
      try {
        await assert.rejects(module.fresh(input, scratch, held), error => error.operationFinished === true)
        const state = JSON.parse(fs.readFileSync(provider))
        assert.equal(state.started, true)
        assert.equal(state.aborted, true, 'child did not abort its request')
        assert.equal(state.finished, true, 'child acknowledged completion before request settlement')
      } finally { fs.closeSync(held) }
    }
    await exercise(probe)
    const mutant = await load('child-no-drain', 'await transport.close()', 'void 0')
    await assert.rejects(exercise(mutant), /did not abort/u); killed++
    const noMarker = await load('child-no-marker', 'response?.finished === true', 'false')
    await assert.rejects(exercise(noMarker), error => error.code === 'ERR_ASSERTION'); killed++
  })
  await check('timeout aborts a request with its own signal and observes drained completion', async () => {
    const exercise = async module => {
      const { scratch, saved } = fixture(`timeout-drain-${sequence++}`, { waitWrite: true })
      const input = { ...await module.readReleaseConfig(release), ...saved, action: 'remember', config }
      const held = fs.openSync(scratch, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY)
      try {
        await assert.rejects(module.fresh(input, scratch, held), error => error.code === 'kira.release-probe:child-timeout' && error.operationFinished === true)
        const state = JSON.parse(fs.readFileSync(provider)); assert.equal(state.aborted, true); assert.equal(state.finished, true)
      } finally { fs.closeSync(held) }
    }
    const short = await load('timeout-drain', '120_000', '1000')
    await exercise(short)
    const mutant = copy('no-signal-join', 'AbortSignal.any([options.signal, controller.signal])', 'options.signal')
    put(mutant, fs.readFileSync(mutant, 'utf8').replace('120_000', '1000'))
    await assert.rejects(exercise(await import(pathToFileURL(mutant).href)), error => error.code === 'ERR_ASSERTION'); killed++
  })
  await check('force-killed write remains ambiguous after both absence checks', async () => {
    const exercise = async module => {
      const scratch = join(work, `force-killed-${sequence++}`); fs.mkdirSync(scratch, { mode: 0o700 })
      put(provider, JSON.stringify({ reads: 0, deletes: 0, waitWrite: true, resistAbort: true }))
      const report = await module.probeRelease({ release, scratch })
      assert.ok(report.cleanupIncomplete, 'force-killed write lost its recovery target')
      assert.ok(fs.existsSync(join(scratch, 'release-probe.json')))
      const state = JSON.parse(fs.readFileSync(provider)); assert.equal(state.started, true); assert.equal(state.reads, 2)
    }
    const short = await load('force-kill', '120_000', "input.action === 'remember' ? 1000 : 5000")
    await exercise(short)
    const mutant = copy('forget-ambiguity', "if (action.action === 'remember') ambiguousWrite = error.operationFinished !== true", 'void 0')
    put(mutant, fs.readFileSync(mutant, 'utf8').replace('120_000', "input.action === 'remember' ? 1000 : 5000"))
    await assert.rejects(exercise(await import(pathToFileURL(mutant).href)), /lost its recovery/u); killed++
  })
  await check('late acceptance after first absence retains journal and exits 3; cleanup later recovers', async () => {
    const { scratch, saved } = fixture('late', { late: true })
    const result = run(script, scratch)
    assert.equal(result.status, 3, result.stdout + result.stderr)
    assert.equal(result.stderr.trim(), `CLEANUP INCOMPLETE: ${saved.uri}`)
    assert.ok(fs.existsSync(join(scratch, 'release-probe.json')))
    const state = JSON.parse(fs.readFileSync(provider)); assert.equal(state.present, true); assert.equal(state.deletes, 1)
    const recovered = run(script, scratch)
    assert.equal(recovered.status, 0, recovered.stdout + recovered.stderr)
    assert.equal(fs.existsSync(join(scratch, 'release-probe.json')), false)
    assert.equal(JSON.parse(fs.readFileSync(provider)).present, false)
    for (const [name, target, replacement] of [
      ['one-observation', 'observation < 2', 'observation < 1'],
      ['no-delay', 'if (observation) await new Promise(resolveDelay => setTimeout(resolveDelay, 250))', 'void 0'],
    ]) {
      const mutant = copy(name, target, replacement), next = fixture(name, { late: true })
      const bad = run(mutant, next.scratch)
      assert.equal(bad.status, 0, bad.stdout + bad.stderr)
      assert.equal(fs.existsSync(join(next.scratch, 'release-probe.json')), false, `${name} did not reproduce journal loss`)
      const state = JSON.parse(fs.readFileSync(provider)); assert.ok(state.acceptAt, `${name} did not leave a late accepted write`)
      await new Promise(resolve => setTimeout(resolve, 80))
      assert.ok(Date.now() >= state.acceptAt)
      state.present = true; delete state.acceptAt; put(provider, JSON.stringify(state))
      assert.equal(JSON.parse(fs.readFileSync(provider)).present, true, 'late accepted note did not survive cleanup')
      killed++
    }
  })
  await check('failed write through a normal probe retains its late accepted note recovery target', async () => {
    const scratch = join(work, 'normal-late'); fs.mkdirSync(scratch, { mode: 0o700 })
    put(provider, JSON.stringify({ reads: 0, deletes: 0, late: true }))
    const result = run(script, scratch, false)
    assert.equal(result.status, 3, result.stdout + result.stderr)
    const saved = JSON.parse(fs.readFileSync(join(scratch, 'release-probe.json')))
    assert.equal(result.stderr.trim(), `CLEANUP INCOMPLETE: ${saved.uri}`)
    const state = JSON.parse(fs.readFileSync(provider))
    assert.equal(state.started, true); assert.equal(state.aborted, true); assert.equal(state.finished, true)
    assert.equal(state.reads, 2); assert.equal(state.present, true)
  })
  await check('failed second absence keeps the recovery journal', async () => {
    const { scratch, saved } = fixture('second-refused', { failSecond: true })
    const result = run(script, scratch)
    assert.equal(result.status, 3, result.stdout + result.stderr)
    assert.equal(result.stderr.trim(), `CLEANUP INCOMPLETE: ${saved.uri}`)
    assert.ok(fs.existsSync(join(scratch, 'release-probe.json')))
  })
  console.log(`kira-release-recall-late-write-test: ${passed} passed, 0 failed; ${killed} mutants killed`)
} finally { process.umask(mask); fs.rmSync(work, { recursive: true, force: true }) }
