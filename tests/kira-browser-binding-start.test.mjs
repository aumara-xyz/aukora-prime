// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify binding starts one owned Kira mount and refuses mismatched identities.
import assert from 'node:assert/strict'
import test from 'node:test'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { createRequire, registerHooks } from 'node:module'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createBrowserBinding } from '../plugins/aukora-aumlok/lib/browser-binding.mjs'
import { createGateCaptureHostPlugin, waitForBrowserMemory, BROWSER_MEMORY } from '../plugins/aukora-kira/lib/gate-capture-host.mjs'
import { createTrackedMemory } from '../plugins/aukora-kira/lib/tracked-memory.mjs'

const root = join(import.meta.dirname, '..')
const harness = [process.env.AUKORA_PINNED_DSH, join(root, 'vendor/dsh'), join(homedir(), 'aukora-genesis/vendor/dsh')]
  .filter(Boolean).find(path => existsSync(join(path, 'vendor/cordis/lib/index.js')))
if (!harness) { console.log('UNPERFORMED: built pinned Cordis required'); process.exit(2) }
const archive = join(root, 'vendor/dsh-source.tar.gz'), sha = value => createHash('sha256').update(value).digest('hex')
assert.equal(sha(readFileSync(archive)), JSON.parse(readFileSync(join(root, 'upstream-dsh.json'))).archiveSha256)
const prefix = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }).split('\n')[0]
for (const file of ['vendor/cordis/src/registry.ts', 'vendor/cordis/src/fiber.ts']) {
  assert.equal(sha(readFileSync(join(harness, file))), sha(execFileSync('tar', ['-xOf', archive, prefix + file])))
}
const { Context } = createRequire(join(harness, 'package.json'))(join(harness, 'vendor/cordis/lib/index.js'))
const subject = 'aukora:1:' + 'a'.repeat(64)
const config = { retrieval: 'lexical', browserBinding: { directory: '/fixture/binding', supportRoot: '/fixture/support', stateRoot: '/fixture/home' },
  memoryOwner: { subject: 'aumlok:subject:owner', stateDir: '/fixture/home/kira-memory', permittedPrivacy: ['local'] } }
const source = readFileSync(join(root, 'plugins/aukora-kira/lib/gate-capture-host.mjs'), 'utf8')
const face = readFileSync(join(root, 'plugins/aukora-face/settings/lib/index.js'), 'utf8')
const snapshotStart = face.indexOf('//#region lib/types/aura/snapshot.js')
const snapshotEnd = face.indexOf('//#endregion', face.indexOf('//#region lib/types/aura/snapshot-reader.js'))
assert.ok(snapshotStart > 0 && snapshotEnd > snapshotStart)
const { readAuraSnapshot } = await import(`data:text/javascript;base64,${Buffer.from(
  "import { createHash } from 'node:crypto'; import { constants } from 'node:fs'; import { open } from 'node:fs/promises'; import { isAbsolute, join, normalize } from 'node:path';\n"
  + face.slice(snapshotStart, snapshotEnd) + '\nexport { readAuraSnapshot };').toString('base64')}`)
const pause = ms => new Promise(resolve => setTimeout(resolve, ms))
const waitingHead = value => ({ ...value, browserMemory: { active: false, reason: BROWSER_MEMORY.WAITING } })
const activeHead = value => ({ ...value, browserMemory: { active: true, reason: BROWSER_MEMORY.ACTIVE } })

function fixture(overrides = {}) {
  let binding = null, owner = { subject, stateDir: config.memoryOwner.stateDir }, scheduled, dispose, mounts = 0
  const messages = [], warnings = []
  const ctx = { logger: { info: message => messages.push(message), warn: message => warnings.push(message) },
    effect: make => { dispose = make() },
    plugin: plugin => { mounts++; return Object.assign(Promise.resolve().then(() => plugin.apply(ctx)), { dispose: async () => {} }) } }
  const deps = { readBinding: async () => binding, readOverlay: async () => owner,
    schedule: check => { scheduled = check; return () => {} }, ...overrides }
  return { ctx, deps, messages, warnings, setBinding: value => { binding = value }, setOwner: value => { owner = value },
    tick: async () => { scheduled?.(); await pause(0) }, dispose: () => dispose(), mounts: () => mounts }
}
async function run(checker, state, selected = config, startMemory = async () => {}) {
  await checker(state.ctx, selected, startMemory, state.deps)
}
async function mutated(before, after, additionally = []) {
  assert.equal(source.split(before).length, 2, `mutation matches once: ${before}`)
  let text = source.replace(before, after)
  for (const [guard, replacement] of additionally) {
    assert.equal(text.split(guard).length, 2, `mutation matches once: ${guard}`)
    text = text.replace(guard, replacement)
  }
  const local = text.replace("'./continuity-head.mjs'", JSON.stringify(
    pathToFileURL(join(root, 'plugins/aukora-kira/lib/continuity-head.mjs')).href))
  return (await import(`data:text/javascript;base64,${Buffer.from(local).toString('base64')}`)).waitForBrowserMemory
}

let indexMutation = 0
async function mutatedKira(before, after) {
  const target = `${pathToFileURL(join(root, 'plugins/aukora-kira/lib/index.js')).href}?browser-readiness=${++indexMutation}`
  let applied = 0
  const hook = registerHooks({ load(url, context, next) {
    const loaded = next(url, context)
    if (url !== target) return loaded
    const text = String(loaded.source)
    assert.equal(text.split(before).length, 2, `index mutation matches once: ${before}`)
    applied++
    return { ...loaded, source: text.replace(before, after) }
  } })
  try {
    const module = await import(target)
    assert.equal(applied, 1)
    return module
  } finally { hook.deregister() }
}

async function mountNativeReadiness(kira, readiness) {
  const directory = mkdtempSync(join(root, '.browser-readiness-'))
  const ctx = new Context(), tools = new Map()
  ctx.provide('tools', { register: definition => { tools.set(definition.name, definition); return () => tools.delete(definition.name) } })
  ctx.provide('sessions', { get: () => undefined })
  ctx.provide('webServer', { register: () => () => {} })
  ctx.provide('connection', { requestRejection: () => undefined })
  try {
    await kira.apply(ctx, { retrieval: 'lexical', memoryOwner: { subject, stateDir: join(directory, 'memory'),
      permittedPrivacy: ['local'] } }, undefined, readiness)
    return ctx.get('kira.head')?.readHead()
  } finally {
    await ctx.fiber.dispose()
    rmSync(directory, { recursive: true, force: true })
  }
}

test('real binding starts native memory without restarting the Cordis host', async t => {
  const directory = mkdtempSync(join(root, '.browser-memory-'))
  const supportRoot = join(directory, 'support'), stateRoot = join(directory, 'home'), bindingDir = join(directory, 'binding')
  mkdirSync(supportRoot); mkdirSync(stateRoot)
  let ceremony
  const ctx = new Context(), tools = new Map(), routes = new Map(), messages = []
  ctx.provide('tools', { register: definition => { tools.set(definition.name, definition); return () => tools.delete(definition.name) } })
  ctx.provide('sessions', { get: () => undefined })
  ctx.provide('webServer', { register: ({ path, handler }) => { routes.set(path, handler); return () => routes.delete(path) } })
  ctx.provide('connection', { requestRejection: () => undefined })
  const plugin = createGateCaptureHostPlugin({ platform: 'fixture', preflight: async () => true,
    loadKira: () => import('../plugins/aukora-kira/lib/index.js'), loadAura: async () => {}, loadCapture: async () => {}, gateCall: async () => {} })
  const host = ctx.plugin({ name: plugin.name, inject: plugin.inject, apply: (child, selected) => {
    child.logger.info = message => messages.push(String(message))
    child.logger.warn = message => messages.push(String(message))
    return plugin.apply(child, selected)
  } }, { ...config, browserBinding: { directory: bindingDir, supportRoot, stateRoot },
    memoryOwner: { ...config.memoryOwner, stateDir: join(stateRoot, 'kira-memory') } })
  try {
    await host
    assert.equal(tools.size, 0)
    const waitingHead = ctx.get('kira.head')
    assert.equal(Object.isFrozen(waitingHead), true)
    assert.deepEqual(Object.keys(waitingHead), ['readHead'])
    assert.deepEqual(waitingHead.readHead(), { head: null, entries: 0, absence: 'kira-ledger-missing',
      browserMemory: { active: false, reason: BROWSER_MEMORY.WAITING } })
    assert.deepEqual((await readAuraSnapshot(root, null, () => waitingHead.readHead())).sources[1],
      { name: 'kira-chain', head: null, entries: 0, absence: 'kira-ledger-missing',
        browserMemory: { active: false, reason: BROWSER_MEMORY.WAITING } })
    assert.equal(existsSync(join(stateRoot, 'kira-memory')), false, 'waiting head never creates memory state')
    assert.ok(messages.some(message => message.includes(BROWSER_MEMORY.WAITING)))
    assert.equal(messages.some(message => message.includes('MemoryIdentityError')), false)
    ceremony = createBrowserBinding({ dir: bindingDir, supportRoot, stateRoot })
    const prepared = ceremony.prepare({ handle: 'rehearsal-fixture' })
    assert.equal(prepared.ok, true)
    const bound = await ceremony.bind({ ceremonyId: prepared.draw.ceremonyId, typedPhrase: prepared.draw.words.join(' '), acknowledged: true })
    assert.equal(bound.reason, 'aumlok:ceremony-verified')
    for (let retry = 0; retry < 40 && !tools.has('kira_remember'); retry++) await pause(50)
    assert.equal(tools.has('kira_remember'), true, 'same host acquires native remember after binding')
    assert.ok(messages.some(message => message.includes(BROWSER_MEMORY.ACTIVE)))
    assert.notEqual(ctx.get('kira.head'), waitingHead)
    assert.deepEqual(waitingHead.readHead(), { head: null, entries: null, absence: 'kira-ledger-unavailable',
      browserMemory: { active: true, reason: BROWSER_MEMORY.ACTIVE } })
    const note = await tools.get('kira_remember').execute({ text: 'Harmless browser binding cohesion fixture note.' }, {})
    assert.equal(note.remembered, 1)
    assert.equal(ctx.get('kira.head').readHead().entries, 1)
    const auraKira = (await readAuraSnapshot(root, null, () => ctx.get('kira.head').readHead())).sources[1]
    assert.equal(auraKira.entries, 1); assert.match(auraKira.head, /^[0-9a-f]{64}$/u); assert.equal(auraKira.absence, null)
    assert.deepEqual(auraKira.browserMemory, { active: true, reason: BROWSER_MEMORY.ACTIVE })
    assert.equal(routes.has('/api/kira/memories'), true)
    await host.dispose()
    assert.equal(ctx.get('kira.head'), undefined); assert.equal(routes.size, 0)
    t.diagnostic('PASS same Cordis invocation: waiting -> bound -> native kira_remember -> Kira head present; owned child disposed')
  } finally {
    ceremony?.close(); await ctx.fiber.dispose()
    await pause(250)
    rmSync(directory, { recursive: true, force: true })
  }
})

test('real pinned Cordis projects a named reason for a mismatched browser identity', async t => {
  const directory = mkdtempSync(join(root, '.browser-memory-mismatch-'))
  const supportRoot = join(directory, 'support'), stateRoot = join(directory, 'home'), bindingDir = join(directory, 'binding')
  mkdirSync(supportRoot); mkdirSync(stateRoot)
  const ceremony = createBrowserBinding({ dir: bindingDir, supportRoot, stateRoot })
  const prepared = ceremony.prepare({ handle: 'mismatch-fixture' })
  assert.equal(prepared.ok, true)
  assert.equal((await ceremony.bind({ ceremonyId: prepared.draw.ceremonyId,
    typedPhrase: prepared.draw.words.join(' '), acknowledged: true })).reason, 'aumlok:ceremony-verified')
  const overlay = join(supportRoot, 'kira-deployment-overlay.patch.yml')
  writeFileSync(overlay, readFileSync(overlay, 'utf8').replace(ceremony.status().subject, 'aukora:1:' + 'b'.repeat(64)), { mode: 0o600 })
  const ctx = new Context(), tools = new Map()
  ctx.provide('tools', { register: definition => { tools.set(definition.name, definition); return () => tools.delete(definition.name) } })
  ctx.provide('sessions', { get: () => undefined })
  const plugin = createGateCaptureHostPlugin({ platform: 'fixture', preflight: async () => true,
    loadKira: () => import('../plugins/aukora-kira/lib/index.js'), loadAura: async () => {}, loadCapture: async () => {}, gateCall: async () => {} })
  const host = ctx.plugin(plugin, { ...config, browserBinding: { directory: bindingDir, supportRoot, stateRoot },
    memoryOwner: { ...config.memoryOwner, stateDir: join(stateRoot, 'kira-memory') } })
  try {
    await host
    assert.deepEqual(ctx.get('kira.head').readHead().browserMemory,
      { active: false, reason: BROWSER_MEMORY.MISMATCH })
    assert.equal(tools.size, 0)
    t.diagnostic('PASS real pinned Cordis: mismatched public binding/overlay projects kira.memory:browser-identity-mismatch')
  } finally {
    await host.dispose(); ceremony.close(); await ctx.fiber.dispose()
    rmSync(directory, { recursive: true, force: true })
  }
})

test('native Kira accepts only the trusted active readiness projection', async t => {
  const linked = { active: true, reason: BROWSER_MEMORY.ACTIVE }
  const invalid = { active: false, reason: BROWSER_MEMORY.ACTIVE }
  const native = await import(`../plugins/aukora-kira/lib/index.js?browser-readiness=control`)
  await assert.rejects(() => mountNativeReadiness(native, invalid), error => error?.code === 'kira.memory:readiness-invalid')
  assert.deepEqual((await mountNativeReadiness(native, linked)).browserMemory, linked)
  const mutations = [
    ["browserMemory.active !== true || browserMemory.reason !== 'kira.memory:aumlok-linked'",
      "browserMemory.reason !== 'kira.memory:aumlok-linked'",
      async kira => assert.rejects(() => mountNativeReadiness(kira, invalid), error => error?.code === 'kira.memory:readiness-invalid')],
    ["...(readiness === undefined ? {} : { browserMemory: readiness })",
      "...(readiness === undefined ? {} : {})",
      async kira => assert.deepEqual((await mountNativeReadiness(kira, linked)).browserMemory, linked)],
  ]
  let killed = 0
  for (const [before, after, court] of mutations) {
    const kira = await mutatedKira(before, after)
    try { await court(kira); assert.fail('readiness mutation survived') } catch (error) {
      assert.match(error.message, /readiness mutation survived|Missing expected rejection|Expected values to be strictly deep-equal/u)
      killed++
    }
  }
  assert.equal(killed, mutations.length)
  t.diagnostic(`PASS native readiness mutations CAUGHT: ${killed}/${mutations.length} (active linked validation and head projection)`)
})

test('waiting, identity equality, path checks, single mount and disposal have executable negative controls', async t => {
  const waiting = async checker => {
    const f = fixture(); await run(checker, f)
    assert.equal(f.mounts(), 0); assert.deepEqual(f.warnings, [])
    assert.match(f.messages[0], /waiting \(kira.memory:aumlok-not-linked\)/u)
  }
  await waiting(waitForBrowserMemory)
  const quietMutant = await mutated('if (publicBinding === null)', 'if (false)')
  await assert.rejects(() => waiting(quietMutant), { name: 'AssertionError' })
  const namedMismatch = async checker => {
    const f = fixture(), services = new Map()
    f.ctx.provide = (name, service) => { services.set(name, service); return async () => services.delete(name) }
    f.setBinding({ subject }); f.setOwner({ subject: 'aukora:1:' + 'b'.repeat(64), stateDir: config.memoryOwner.stateDir })
    await run(checker, f)
    assert.deepEqual(services.get('kira.head').readHead().browserMemory,
      { active: false, reason: BROWSER_MEMORY.MISMATCH })
  }
  await namedMismatch(waitForBrowserMemory)
  const readiness = async checker => {
    const f = fixture(); f.setBinding({ subject })
    let observed
    await run(checker, f, config, async (_ctx, _linked, state) => { observed = state })
    assert.deepEqual(observed, { active: true, reason: BROWSER_MEMORY.ACTIVE })
  }
  await readiness(waitForBrowserMemory)
  const activeMutant = await mutated('startMemory(childCtx, linked, browserReadiness(BROWSER_MEMORY.ACTIVE))',
    'startMemory(childCtx, linked)')
  await assert.rejects(() => readiness(activeMutant), { name: 'AssertionError' })
  for (const [guard, change] of [
    ['owner?.subject !== publicBinding.subject', f => f.setOwner({ subject: 'aukora:1:' + 'b'.repeat(64), stateDir: config.memoryOwner.stateDir })],
    ['owner?.stateDir !== ordinary.memoryOwner.stateDir', f => f.setOwner({ subject, stateDir: '/another/memory' })],
    ["!['aumlok:subject:owner', publicBinding.subject].includes(ordinary.memoryOwner.subject)", () => {}],
  ]) {
    const selected = guard.startsWith('![') ? { ...config, memoryOwner: { ...config.memoryOwner, subject: 'aukora:1:' + 'b'.repeat(64) } } : config
    const exercise = async checker => { const f = fixture(); f.setBinding({ subject }); change(f); await run(checker, f, selected); assert.equal(f.mounts(), 0) }
    await exercise(waitForBrowserMemory)
    const mutant = await mutated(guard, 'false')
    await assert.rejects(() => exercise(mutant), { name: 'AssertionError' })
  }
  const paths = async checker => {
    const f = fixture()
    await assert.rejects(() => run(checker, f, { ...config, browserBinding: { ...config.browserBinding, supportRoot: 'relative' } }),
      error => error.code === BROWSER_MEMORY.CONFIG)
  }
  await paths(waitForBrowserMemory)
  const pathMutant = await mutated("typeof binding[field] !== 'string' || !isAbsolute(binding[field]) || resolve(binding[field]) !== binding[field]\n    || /[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]/u.test(binding[field])", 'false')
  await assert.rejects(() => paths(pathMutant), { name: 'AssertionError' })
  const malformed = async checker => {
    const f = fixture(); f.setBinding({ subject: 'malformed' }); f.setOwner({ subject: 'malformed', stateDir: config.memoryOwner.stateDir })
    await run(checker, f, { ...config, memoryOwner: { ...config.memoryOwner, subject: 'malformed' } }); assert.equal(f.mounts(), 0)
  }
  await malformed(waitForBrowserMemory)
  const subjectMutant = await mutated("typeof publicBinding?.subject !== 'string' || !/^aukora:1:[0-9a-f]{64}$/u.test(publicBinding.subject)", 'false')
  await assert.rejects(() => malformed(subjectMutant), { name: 'AssertionError' })
  const disposal = async checker => {
    const f = fixture(); await run(checker, f); f.dispose(); f.setBinding({ subject }); await f.tick(); assert.equal(f.mounts(), 0)
  }
  await disposal(waitForBrowserMemory)
  const disposeMutant = await mutated('live = false; stop()', 'stop()')
  await assert.rejects(() => disposal(disposeMutant), { name: 'AssertionError' })
  const once = async checker => {
    const f = fixture(); await run(checker, f); f.setBinding({ subject }); await f.tick(); await f.tick(); assert.equal(f.mounts(), 1)
  }
  await once(waitForBrowserMemory)
  const onceMutant = await mutated('!live || inFlight || started', '!live || inFlight')
  await assert.rejects(() => once(onceMutant), { name: 'AssertionError' })
  const shape = async checker => {
    const f = fixture()
    await assert.rejects(() => run(checker, f, { ...config, browserBinding: { ...config.browserBinding, extra: '/extra' } }),
      error => error.code === BROWSER_MEMORY.CONFIG)
  }
  await shape(waitForBrowserMemory)
  const shapeMutant = await mutated('Object.keys(binding).length !== fields.length', 'false')
  await assert.rejects(() => shape(shapeMutant), { name: 'AssertionError' })
  const state = async checker => {
    const f = fixture()
    await assert.rejects(() => run(checker, f, { ...config, memoryOwner: { ...config.memoryOwner, stateDir: '/another/memory' } }),
      error => error.code === BROWSER_MEMORY.CONFIG)
  }
  await state(waitForBrowserMemory)
  const stateMutant = await mutated("detached.memoryOwner?.stateDir !== join(binding.stateRoot, 'kira-memory')", 'false')
  await assert.rejects(() => state(stateMutant), { name: 'AssertionError' })
  const concurrent = async checker => {
    let reads = 0, release
    const pending = new Promise(resolve => { release = resolve })
    const f = fixture({ readOverlay: () => { reads++; return pending } })
    try {
      await run(checker, f); f.setBinding({ subject }); await f.tick(); await f.tick(); assert.equal(reads, 1)
    } finally { release({ subject, stateDir: config.memoryOwner.stateDir }); await pause(0) }
  }
  await concurrent(waitForBrowserMemory)
  const concurrentMutant = await mutated('!live || inFlight || started', '!live || started')
  await assert.rejects(() => concurrent(concurrentMutant), { name: 'AssertionError' })
  const lateRead = async (checker, stage) => {
    let release, reads = 0
    const pending = new Promise(resolve => { release = resolve })
    const f = fixture(stage === 'binding' ? { readBinding: () => pending, readOverlay: async () => { reads++; return { subject, stateDir: config.memoryOwner.stateDir } } }
      : { readOverlay: () => pending })
    f.setBinding({ subject })
    const task = run(checker, f)
    await pause(0); f.dispose(); release(stage === 'binding' ? { subject } : { subject, stateDir: config.memoryOwner.stateDir }); await task
    assert.equal(stage === 'binding' ? reads : f.mounts(), 0)
  }
  for (const [stage, next] of [['binding', 'if (publicBinding === null)'], ['overlay', "if (typeof publicBinding?.subject !== 'string'"]]) {
    await lateRead(waitForBrowserMemory, stage)
    const mutant = await mutated(`      if (!live) return\n      ${next}`, `      ${next}`,
      stage === 'overlay' ? [['      await disposeHead()\n      if (!live) return', '      await disposeHead()']] : [])
    await assert.rejects(() => lateRead(mutant, stage), { name: 'AssertionError' })
  }
  t.diagnostic('PASS mutations CAUGHT: 14/14 (quiet wait, active readiness, identity/state equality, owner, paths, subject shape, disposal, once-only, config shape, state root, concurrent/late reads; overlay lifecycle checks jointly removed)')
})

test('prebinding head reads the actual ledger without adding memory or hiding invalid and nonempty state', async t => {
  const state = async checker => {
    const directory = mkdtempSync(join(root, '.browser-head-'))
    const stateRoot = join(directory, 'home'), stateDir = join(stateRoot, 'kira-memory')
    const selected = { ...config, browserBinding: { ...config.browserBinding, stateRoot },
      memoryOwner: { ...config.memoryOwner, stateDir } }
    const f = fixture(), services = new Map()
    f.ctx.provide = (name, service) => { services.set(name, service); return async () => services.delete(name) }
    try {
      mkdirSync(stateRoot)
      await run(checker, f, selected)
      const head = services.get('kira.head')
      assert.ok(head)
      assert.equal(Object.isFrozen(head), true); assert.deepEqual(Object.keys(head), ['readHead'])
      assert.deepEqual(head.readHead(), waitingHead({ head: null, entries: 0, absence: 'kira-ledger-missing' }))
      assert.deepEqual(readdirSync(stateRoot), [])
      const ledger = join(stateDir, 'remembered/aura.jsonl')
      mkdirSync(join(stateDir, 'remembered'), { recursive: true })
      writeFileSync(ledger, 'invalid-ledger\n', { mode: 0o600 })
      assert.deepEqual(head.readHead(), waitingHead({ head: null, entries: null, absence: 'kira-ledger-malformed' }))
      assert.equal(readFileSync(ledger, 'utf8'), 'invalid-ledger\n')
      rmSync(stateDir, { recursive: true })
      await createTrackedMemory({ stateDir, subject }).remember({ text: 'Harmless prebinding ledger fixture note.' })
      const before = readFileSync(ledger)
      const actual = head.readHead()
      assert.equal(actual.entries, 1); assert.match(actual.head, /^[0-9a-f]{64}$/u); assert.equal(actual.absence, null)
      assert.deepEqual(readFileSync(ledger), before)
      await f.dispose()
      assert.equal(services.has('kira.head'), false)
      assert.deepEqual(head.readHead(), waitingHead({ head: null, entries: null, absence: 'kira-ledger-unavailable' }))
    } finally { await f.dispose(); rmSync(directory, { recursive: true, force: true }) }
  }
  await state(waitForBrowserMemory)
  for (const [before, after] of [
    ["readMemoryLedgerHead({ stateDir: ordinary.memoryOwner.stateDir })", "({ head: null, entries: 0, absence: 'kira-ledger-missing' })"],
    ["ctx.provide('kira.head', Object.freeze({", "ctx.provide('kira.head', (value => value)({"],
    ['browserMemory: browserReadiness(lastReason ?? BROWSER_MEMORY.WAITING)',
      'browserMemory: undefined'],
    ['live && headLive ? readMemoryLedgerHead', 'true ? readMemoryLedgerHead'],
    ["headLive = false; await disposeHead() }, 'aukora-kira: browser binding wait'", "headLive = false }, 'aukora-kira: browser binding wait'"],
  ]) {
    const mutant = await mutated(before, after)
    await assert.rejects(() => state(mutant), { name: 'AssertionError' })
  }
  t.diagnostic('PASS prebinding head mutations CAUGHT: 5/5 (actual ledger, browser readiness, frozen read-only service, retained-reader lifetime, owned cleanup)')
})

test('temporary head teardown settles before native Kira starts and disposal prevents a late handoff', async t => {
  const handoff = async (checker, late = false) => {
    const f = fixture(), services = new Map()
    let release, disposals = 0, disposal
    const pending = new Promise(resolve => { release = resolve })
    f.ctx.provide = (name, service) => {
      services.set(name, service)
      return () => disposal ??= (async () => { disposals++; await pending; services.delete(name) })()
    }
    try {
      await run(checker, f)
      const head = services.get('kira.head')
      assert.ok(head)
      f.setBinding({ subject }); await f.tick()
      assert.equal(disposals, 1); assert.equal(f.mounts(), 0, 'native Kira waits for temporary service removal')
      assert.deepEqual(head.readHead(), waitingHead({ head: null, entries: null, absence: 'kira-ledger-unavailable' }))
      if (late) void f.dispose()
      release(); await pause(0)
      assert.equal(f.mounts(), late ? 0 : 1)
      assert.equal(services.has('kira.head'), false)
      assert.deepEqual(head.readHead(), (late ? waitingHead : activeHead)(
        { head: null, entries: null, absence: 'kira-ledger-unavailable' }))
    } finally { release(); await f.dispose() }
  }
  await handoff(waitForBrowserMemory)
  await handoff(waitForBrowserMemory, true)
  for (const [before, after, late] of [
    ['      await disposeHead()\n      if (!live) return', '      disposeHead()\n      if (!live) return', false],
    ['      headLive = false\n      await disposeHead()', '      await disposeHead()', false],
    ['      await disposeHead()\n      if (!live) return', '      await disposeHead()', true],
  ]) {
    const mutant = await mutated(before, after)
    await assert.rejects(() => handoff(mutant, late), { name: 'AssertionError' })
  }
  const failed = fixture()
  failed.ctx.provide = () => async () => { throw new Error('synthetic teardown refusal') }
  await run(waitForBrowserMemory, failed)
  failed.setBinding({ subject }); await failed.tick()
  assert.equal(failed.mounts(), 0)
  assert.ok(failed.warnings.some(message => message.includes(BROWSER_MEMORY.ACTIVATION)))
  t.diagnostic('PASS prebinding handoff mutations CAUGHT: 3/3 (await disposal, invalidate retained reader, late disposal); teardown failure mounts nothing')
})
