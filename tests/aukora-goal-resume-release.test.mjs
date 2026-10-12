// Release goal rows use declared services and contain failures without re-arming ineligible goals.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import * as plugin from '../plugins/aukora-goal-resume/lib/index.mjs'
import { generated, root, rows, source } from './helpers/release-composition.mjs'
import { strictContext } from './helpers/release-context.mjs'

const overlay = readFileSync(new URL('../overlays/goal-resume.patch.yml', import.meta.url), 'utf8')
const pluginPath = join(root, 'plugins/aukora-goal-resume/lib/index.mjs')
const original = readFileSync(pluginPath, 'utf8')
const previousUmask = process.umask(0o002)
const home = mkdtempSync(join(root, '.goal-release-'))
assert.equal(statSync(home).mode & 0o777, 0o700)
test.after(() => { rmSync(home, { recursive: true, force: true }); process.umask(previousUmask) })
const render = (input = source) => generated(input, { home, includeUpstream: false }).patches['aukora-composition.patch.yml']
const composition = render()
const settle = () => new Promise(resolve => setImmediate(resolve))

function configFor(patch, deploymentHome) {
  const selected = rows(patch, 'goal-release', { home: deploymentHome, dshHome: deploymentHome })
    .filter(row => row.id === 'aukora-goal-resume')
  assert.equal(selected.length, 1)
  assert.equal(selected[0].name, './plugins/aukora-goal-resume/lib/index.mjs')
  assert.equal(selected[0].config.stateDir, join(deploymentHome, 'goal-resume-state'), 'goal-resume row must supply config.stateDir')
  return selected[0].config
}

function services() {
  const agent = { sessionId: 'active' }, resumed = []
  return { resumed, values: {
    agents: { roots: () => [agent], get: () => agent },
    goals: { get: () => ({ id: 'goal-active', revision: 7, phase: 'active', activation: 'armed' }),
      resume: (selected, ref) => resumed.push([selected.sessionId, ref]) },
  } }
}

function warnings(recorder) {
  return recorder.logs.filter(line => line.includes('INERT'))
}

async function checkFailure(selected, failure) {
  const fixture = services()
  if (failure === 'services') fixture.values.goals = undefined
  const recorder = strictContext(selected.inject, fixture.values)
  const config = { ...configFor(composition, home), stateDir: join(home, `failure-${failure}`) }
  if (failure === 'state-dir') delete config.stateDir
  if (failure === 'effect') recorder.ctx.effect = () => { throw new Error('effect-fault') }
  if (failure === 'roots') {
    fixture.values.agents.roots = () => { throw new Error('roots-fault') }
    recorder.ctx.effect = create => create()
  }
  if (failure === 'boot') fixture.values.goals.get = () => { throw new Error('boot-fault') }
  if (failure === 'warn') recorder.ctx.logger = { warn() { throw new Error('logger-warn-fault') } }
  const captured = [], oldWarn = console.warn
  console.warn = line => captured.push(String(line))
  try {
    assert.doesNotThrow(() => selected.apply(recorder.ctx, failure === 'warn' ? {} : config))
    await settle()
    const lines = [...warnings(recorder), ...captured]
    if (failure === 'warn') assert.deepEqual(lines, [])
    else {
      assert.equal(lines.length, 1, `${failure}: one inert diagnostic`)
      assert.match(lines[0], new RegExp(`${failure === 'state-dir' ? 'state-dir-missing' : failure === 'services' ? 'services-unavailable' : failure === 'boot' ? 'boot-failed' : 'apply-failed'}.*INERT`, 'u'))
    }
    assert.deepEqual(fixture.resumed, [])
    assert.deepEqual(recorder.refusals, [])
  } finally {
    console.warn = oldWarn
    await recorder.dispose()
  }
}

async function checkLogger(selected, absent) {
  const fixture = services(), recorder = strictContext(selected.inject, fixture.values)
  let summarized = false
  recorder.ctx.logger = absent ? undefined : { info(line) { summarized ||= line.includes('unclean start'); throw new Error('logger-info-fault') }, warn() { throw new Error('logger-warn-fault') } }
  const captured = [], oldWarn = console.warn
  console.warn = line => captured.push(String(line))
  try {
    assert.doesNotThrow(() => selected.apply(recorder.ctx, { stateDir: join(home, `logger-${absent}`) }))
    await settle()
    assert.deepEqual(fixture.resumed, [['active', { id: 'goal-active', revision: 7 }]])
    assert.deepEqual(captured, [])
    if (!absent) assert.equal(summarized, true, 'throwing logger must not abort the boot summary')
    assert.deepEqual(recorder.refusals, [])
    assert.equal(existsSync(selected.markerFor(join(home, `logger-${absent}`))), false)
  } finally {
    console.warn = oldWarn
    await recorder.dispose()
    rmSync(join(home, `logger-${absent}`), { recursive: true, force: true })
  }
}

async function mutant(from, to) {
  assert.equal(original.split(from).length, 2, 'unique goal-resume mutation target')
  const resume = pathToFileURL(join(root, 'plugins/aukora-goal-resume/lib/resume.mjs')).href
  const code = original.replace(from, to).replace("'./resume.mjs'", JSON.stringify(resume))
  return import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
}

test('default composition and optional overlay derive goal state from the deployment home', () => {
  for (const deploymentHome of ['/var/lib/aukora-host/home', '/Users/synthetic/Library/Application Support/AUKORA/state/home']) {
    configFor(composition, deploymentHome)
    configFor(overlay, deploymentHome)
  }
})

test('mounted generated config re-arms eligible goals and consumes only clean-stop markers', async t => {
  const config = configFor(composition, home)
  const agents = ['active', 'paused', 'complete', 'disarmed', 'armed'].map(sessionId => ({ sessionId }))
  const views = new Map(agents.map(agent => [agent, { id: `goal-${agent.sessionId}`, revision: 7,
    phase: agent.sessionId === 'paused' || agent.sessionId === 'complete' ? agent.sessionId : 'active',
    activation: agent.sessionId === 'disarmed' ? 'disarmed' : 'armed', alreadyArmed: agent.sessionId === 'armed' }]))
  const resumed = [], recorders = []
  t.after(async () => { for (const recorder of recorders) await recorder.dispose() })
  const mount = async () => {
    const recorder = strictContext(plugin.inject, {
      agents: { roots: () => agents, get: id => agents.find(agent => agent.sessionId === id) },
      goals: { get: agent => views.get(agent), resume: (agent, ref) => resumed.push([agent.sessionId, ref]) },
    })
    recorders.push(recorder)
    plugin.apply(recorder.ctx, config)
    await settle()
    assert.deepEqual(recorder.refusals, [])
    assert.deepEqual(warnings(recorder), [])
    return recorder
  }
  const first = await mount()
  assert.deepEqual(resumed, [['active', { id: 'goal-active', revision: 7 }]])
  assert.ok(first.logs.some(line => line.includes('unclean start')))
  assert.equal(existsSync(plugin.markerFor(config.stateDir)), false, 'boot must not mark a subsequent crash clean')
  await first.dispose()
  assert.equal(existsSync(plugin.markerFor(config.stateDir)), true, 'clean disposal writes a usable state directory')
  resumed.length = 0
  await mount()
  assert.deepEqual(resumed, [], 'clean stop must not re-arm')
  assert.equal(existsSync(plugin.markerFor(config.stateDir)), false, 'clean marker is consumed')
  await mount()
  assert.deepEqual(resumed, [['active', { id: 'goal-active', revision: 7 }]], 'unclean restart re-arms again')
})

test('missing state or services and synchronous or asynchronous boot failures stay inert', async () => {
  for (const failure of ['state-dir', 'services', 'effect', 'roots', 'boot', 'warn']) await checkFailure(plugin, failure)
  await checkLogger(plugin, true)
  await checkLogger(plugin, false)
})

test('failure containment mutations fail the same release-context controls', async () => {
  await assert.rejects(checkFailure(await mutant('    if (stateDir === null) {', '    if (false) {'), 'state-dir'), { code: 'ERR_ASSERTION' })
  const guard = "    if (typeof goals?.get !== 'function' || typeof goals?.resume !== 'function'\n        || typeof agents?.roots !== 'function' || typeof agents?.get !== 'function') {"
  await assert.rejects(checkFailure(await mutant(guard, '    if (false) {'), 'services'), { code: 'ERR_ASSERTION' })
  const warning = "    try { (logger?.warn ? logger : console).warn(`aukora-goal-resume: ${reason} — INERT`); } catch { /* logging cannot abort mount */ }"
  await assert.rejects(checkFailure(await mutant(warning, warning.replace('try { ', '').replace(' } catch { /* logging cannot abort mount */ }', '')), 'warn'), { code: 'ERR_ASSERTION' })
  const info = 'log: (line) => { try { logger?.info?.(line); } catch { /* logging cannot abort boot */ } },'
  await assert.rejects(checkLogger(await mutant(info, 'log: (line) => { logger.info(line); },'), true), { code: 'ERR_ASSERTION' })
  await assert.rejects(checkLogger(await mutant(info, 'log: (line) => { logger?.info?.(line); },'), false), { code: 'ERR_ASSERTION' })
  await assert.rejects(checkFailure(await mutant("  } catch { warn('apply-failed'); }", '  } catch (error) { throw error; }'), 'effect'), { code: 'ERR_ASSERTION' })
  await assert.rejects(checkFailure(await mutant("}).catch(() => warn('boot-failed'));", '}).catch(() => {});'), 'boot'), { code: 'ERR_ASSERTION' })
  const resume = pathToFileURL(join(root, 'plugins/aukora-goal-resume/lib/resume.mjs')).href
  const child = sourceCode => spawnSync(process.execPath, ['--input-type=module', '-'], { encoding: 'utf8', timeout: 5000,
    input: `const selected = await import('data:text/javascript;base64,' + ${JSON.stringify(Buffer.from(sourceCode.replace("'./resume.mjs'", JSON.stringify(resume))).toString('base64'))});\n`
      + `const {strictContext} = await import(${JSON.stringify(pathToFileURL(join(root, 'tests/helpers/release-context.mjs')).href)});\n`
      + `const agent={sessionId:'active'}, recorder=strictContext(selected.inject,{agents:{roots:()=>[agent],get:()=>agent},goals:{get(){throw new Error('boot-mutant-fault')},resume(){}}});\n`
      + `selected.apply(recorder.ctx,{stateDir:${JSON.stringify(join(home, 'async-control'))}}); await new Promise(resolve=>setImmediate(resolve)); console.log(recorder.logs.length);\n` })
  assert.equal(child(original).status, 0, 'async catch control')
  const uncaught = child(original.replace("}).catch(() => warn('boot-failed'));", '});'))
  assert.notEqual(uncaught.status, 0, 'removed async catch must fail')
  assert.match(uncaught.stderr, /boot-mutant-fault/u)
})

test('removing either config or stateDir wiring fails the same configuration check', () => {
  const from = "        '      config:\\n'\n        \"        stateDir: !!js dshHomePath('goal-resume-state')\\n\"\n"
  assert.equal(source.split(from).length, 2, 'unique builder mutation target')
  assert.throws(() => configFor(render(source.replace(from, '')), home), { code: 'ERR_ASSERTION' })
  assert.throws(() => configFor(render(source.replace(from, from.replace("        '      config:\\n'\n", ''))), home), { code: 'ERR_ASSERTION' })
  const line = "        stateDir: !!js dshHomePath('goal-resume-state')\n"
  assert.equal(overlay.split(line).length, 2, 'unique overlay mutation target')
  assert.throws(() => configFor(overlay.replace(line, ''), home), { code: 'ERR_ASSERTION' })
  assert.throws(() => configFor(overlay.replace('      config:\n', ''), home), { code: 'ERR_ASSERTION' })
})
