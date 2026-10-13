// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser ceremony requests, authenticated reads and rendered confirmation stay bounded.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire, stripTypeScriptTypes } from 'node:module'
import { homedir } from 'node:os'
import { resolve } from 'node:path'
import { runInNewContext } from 'node:vm'
import * as bridgeApi from '../plugins/aukora-face/aumlok/src/client/binding-bridge.ts'
import * as controlApi from '../plugins/aukora-face/aumlok/src/control-projection.ts'
import * as surfaceState from '../plugins/aukora-face/aumlok/src/client/surface-state.ts'
import { en } from '../plugins/aukora-face/aumlok/src/client/locales.ts'

const client = new URL('../plugins/aukora-face/aumlok/src/client/', import.meta.url)
const sources = Object.fromEntries(['binding-bridge.ts', 'control-status-loader.ts', 'index.ts', 'AumlokSurface.tsx', 'surface-state.ts', 'Aumlok.module.css']
  .map(name => [name, readFileSync(new URL(name, client), 'utf8')]))
const words = ['abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb']
const draw = { ceremonyId: 'fixture_ceremony_123', words, language: 'en', entropyBits: 77 }
const reply = (body, status = 200, media = 'application/json') => ({ ok: status >= 200 && status < 300,
  status, headers: { get: () => media }, json: async () => body })
const pending = () => { let complete; return { promise: new Promise(resolve => { complete = resolve }), complete: value => complete(value) } }

async function transportChecks(api) {
  const calls = []
  let response = { ok: true, draw }
  let status = 200, media = 'application/json'
  const fetch = async (url, init) => { calls.push({ url, init }); return reply(response, status, media) }
  for (const protocol of ['http:', 'file:', '', 'ftp:'])
    assert.equal(api.createAumlokBrowserCeremonyBridge(fetch, protocol), undefined)
  const bridge = api.createAumlokBrowserCeremonyBridge(fetch, 'https:')
  assert.equal((await bridge.draw('bind')).reason, 'aumlok:browser-handle-required')
  assert.equal((await bridge.submit('refresh', words, 'owner')).reason, 'aumlok:browser-first-binding-only')
  assert.equal((await bridge.submit('bind', words, 'owner')).reason, 'aumlok:browser-no-pending-draw')
  assert.equal((await bridge.prepare('owner', 'en')).ok, true)
  assert.deepEqual(JSON.parse(calls.at(-1).init.body), { handle: 'owner', language: 'en' })
  assert.equal((await bridge.submit('bind', words, 'changed')).reason, 'aumlok:browser-handle-changed')
  for (const malformed of [words.slice(1), ['x'.repeat(65), ...words.slice(1)], [null, ...words.slice(1)]])
    assert.equal((await bridge.submit('bind', malformed, 'owner')).reason, 'aumlok:browser-phrase-shape')
  response = { ok: true, binding: { public: 'fixture' }, typedPhrase: words.join(' ') }
  const bound = await bridge.submit('bind', words, 'owner')
  assert.deepEqual(bound, { ok: true, drawSpent: true }, 'bind response exposes no phrase or binding material')
  assert.deepEqual(JSON.parse(calls.at(-1).init.body), { ceremonyId: draw.ceremonyId,
    typedPhrase: words.join(' '), acknowledged: true })
  assert.equal((await bridge.submit('bind', words, 'owner')).reason, 'aumlok:browser-no-pending-draw')
  response = { ok: true, draw }
  await bridge.prepare('owner')
  await bridge.prepare('owner')
  assert.deepEqual(JSON.parse(calls.at(-2).init.body), { ceremonyId: draw.ceremonyId })
  assert.equal(calls.at(-2).url, '/api/aukora/aumlok-binding/cancel')
  await bridge.cancel()
  assert.equal((await bridge.submit('bind', words, 'owner')).reason, 'aumlok:browser-no-pending-draw')
  response = { ok: true, bound: false }
  await bridge.status()
  assert.equal(calls.at(-1).url, '/api/aukora/aumlok-binding/status')
  assert.deepEqual(JSON.parse(calls.at(-1).init.body), {})
  for (const { url, init } of calls) {
    assert.match(url, /^\/api\/aukora\/aumlok-binding\/(prepare|bind|cancel|status)$/u)
    assert.equal(init.method, 'POST'); assert.equal(init.credentials, 'same-origin')
    assert.equal(init.mode, 'same-origin'); assert.equal(init.cache, 'no-store')
    assert.equal(init.redirect, 'error'); assert.equal(init.referrerPolicy, 'no-referrer')
    assert.equal(init.headers['content-type'], 'application/json')
    assert.equal(url.includes(words[0]), false)
  }
  for (const body of [null, [], { ok: true }, { ok: true, draw: {} },
    { ok: true, draw: { ...draw, ceremonyId: '../outside' } },
    { ok: true, draw: { ...draw, words: words.slice(1) } },
    { ok: true, draw: { ...draw, entropyBits: 12 } }]) {
    response = body
    assert.equal((await bridge.prepare('owner')).reason, 'aumlok:browser-response-invalid')
  }
  for (const [body, expected] of [[{ ok: false, reason: 'aumlok:binding-exists', typedPhrase: words.join(' ') }, 'aumlok:binding-exists'],
    [{ ok: false, reason: words.join(' ') }, 'aumlok:browser-request-refused']]) {
    response = body
    assert.deepEqual(await bridge.prepare('owner'), { ok: false, reason: expected })
  }
  response = { ok: true, draw }; status = 401
  assert.equal((await bridge.prepare('owner')).ok, false, 'HTTP refusal cannot become success')
  status = 200; media = 'text/html'
  assert.equal((await bridge.prepare('owner')).reason, 'aumlok:browser-response-invalid')
  media = 'application/json'
  for (const binding of [null, undefined, [], 'fixture']) {
    response = { ok: true, draw }; await bridge.prepare('owner')
    response = { ok: true, binding }
    assert.equal((await bridge.submit('bind', words, 'owner')).reason, 'aumlok:browser-response-invalid')
  }
  const throwing = api.createAumlokBrowserCeremonyBridge(async () => { throw Error(words.join(' ')) }, 'https:')
  assert.deepEqual(await throwing.prepare('owner'), { ok: false, reason: 'aumlok:browser-request-failed' })
  const late = pending(), lateCalls = []
  const closing = api.createAumlokBrowserCeremonyBridge(async (url, init) => {
    lateCalls.push({ url, init }); return url.endsWith('/prepare') ? late.promise : reply({ ok: true })
  }, 'https:')
  const started = closing.prepare('owner'); await Promise.resolve(); await Promise.resolve()
  await closing.cancel(); late.complete(reply({ ok: true, draw }))
  assert.equal((await started).reason, 'aumlok:browser-draw-cancelled')
  assert.equal(lateCalls.at(-1).url, '/api/aukora/aumlok-binding/cancel')
  assert.equal((await closing.submit('bind', words, 'owner')).reason, 'aumlok:browser-no-pending-draw')
}

function typescript() {
  const require = createRequire(import.meta.url)
  const roots = [process.env.AUKORA_PINNED_DSH, resolve('vendor/dsh'), resolve(homedir(), 'aukora-genesis/vendor/dsh')].filter(Boolean)
  for (const root of roots) {
    try { return createRequire(resolve(root, 'package.json'))('typescript') } catch {}
  }
  try { return require('typescript') } catch {}
  // The pinned harness build is fetched, not tracked; without it this file is unperformed (exit 2), not failed.
  console.log('UNPERFORMED: aumlok-browser-client needs the pinned harness build for its TypeScript')
  process.exit(2)
}
const ts = typescript()
function compile(text) {
  return ts.transpileModule(text, { compilerOptions: { module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText
}
function loadLoader(text) {
  const exports = {}
  runInNewContext(compile(text), { exports, AbortController,
    require(name) { assert.equal(name, '../control-projection.ts'); return controlApi } })
  return exports
}
const { AumlokControlStatusLoader } = loadLoader(sources['control-status-loader.ts'])
const nodes = value => Array.isArray(value) ? value.flatMap(nodes)
  : value && typeof value === 'object' ? [value, ...nodes(value.props?.children)] : []
const find = (tree, key) => nodes(tree).find(node => Object.hasOwn(node.props ?? {}, key))
const textOf = value => Array.isArray(value) ? value.map(textOf).join('')
  : value && typeof value === 'object' ? textOf(value.props?.children)
    : value === null || value === undefined || typeof value === 'boolean' ? '' : String(value)

function screen(text = sources['AumlokSurface.tsx'], browserCeremony = true, options = {}) {
  const slots = [], updates = [], effects = [], draws = [], submits = []
  let cursor = 0, tree, cancelled = 0, refreshed = 0, opened = 0, started = 0
  let projection = options.projection ?? { status: 'not-connected' }
  const react = {
    useState(initial) { const at = cursor++; if (!(at in slots)) slots[at] = { value: typeof initial === 'function' ? initial() : initial }
      return [slots[at].value, update => updates.push(() => { slots[at].value = typeof update === 'function' ? update(slots[at].value) : update })] },
    useRef(initial) { const at = cursor++; return slots[at] ??= { current: initial } },
    useEffect(callback, dependencies) { const at = cursor++, old = slots[at]
      if (!old || dependencies.some((value, index) => !Object.is(value, old.dependencies[index]))) {
        slots[at] = { dependencies, cleanup: old?.cleanup }
        effects.push(() => { slots[at].cleanup?.(); slots[at].cleanup = callback() })
      } },
  }
  react.useLayoutEffect = react.useEffect
  const jsx = (type, props) => typeof type === 'function' ? type(props) : ({ type, props })
  const exports = {}
  runInNewContext(compile(text), { exports, document: { addEventListener() {}, removeEventListener() {} },
    require(name) {
      if (name === 'react') return react
      if (name === 'react/jsx-runtime') return { jsx, jsxs: jsx, Fragment: 'fragment' }
      if (name === './binding-bridge.ts') return bridgeApi
      if (name === './surface-state.ts') return surfaceState
      if (name === './IdentityVisuals.tsx') return { IdentityIcon: 'IdentityIcon' }
      if (name === '@aukora/face-layout/client') return { Card: 'Card', SectionHeader: 'SectionHeader' }
      if (name === './Aumlok.module.css') return { default: new Proxy({}, { get: (_target, key) => key }) }
      throw Error(`unexpected import ${name}`)
    } })
  let props = { activeSurface: options.activeSurface ?? 'aumlok', closeSurface() {}, openSurface: () => { opened += 1 },
    t: key => en[key], useControlProjection: () => projection,
    ceremonyAvailable: true, browserCeremony, publicFirstRun: options.publicFirstRun ?? browserCeremony,
    cancelCeremony: () => { cancelled += 1 },
    drawPhrase: async (...args) => { draws.push(args); return { ok: true, ...draw } },
    submitPhrase: async (...args) => { submits.push(args); return { ok: true, drawSpent: true } },
    refreshControlStatus: () => { refreshed += 1; projection = { status: 'connected', control: {
      subject: `aukora:1:${'a'.repeat(64)}`, handle: 'owner', epoch: 0, approvalKeyDid: `did:key:z${'1'.repeat(30)}`,
      activeControlDigest: 'b'.repeat(64), custodyClass: 'same-uid-posix-mode-only', revoked: false,
      boundAt: '2026-01-01T00:00:00Z', phraseLanguage: 'en', phraseLegacy: false,
    } } },
    startFirstChat: () => { started += 1 },
  }
  function render() { cursor = 0; tree = exports.AumlokSurface(props); while (effects.length) effects.shift()() }
  async function flush() { for (let step = 0; step < 40; step++) { await Promise.resolve(); while (updates.length) { updates.shift()(); render() } } }
  render()
  return { draws, submits, get tree() { return tree }, get cancelled() { return cancelled }, get refreshed() { return refreshed },
    get opened() { return opened }, get started() { return started }, flush,
    async change(key, value, checked = false) { find(tree, key).props.onChange({ target: checked ? { checked: value } : { value } }); await flush() },
    async click() { find(tree, 'data-aumlok-bind-button').props.onClick(); await flush() },
    async bound() { props.refreshControlStatus(); render(); await flush() },
    async close() { props = { ...props, activeSurface: null }; render(); await flush() },
    unmount() { for (const slot of slots) slot?.cleanup?.() },
  }
}

async function screenChecks(text = sources['AumlokSurface.tsx']) {
  const ui = screen(text)
  const disclosure = find(ui.tree, 'data-aumlok-browser-derivation')
  assert.ok(disclosure)
  assert.match(textOf(disclosure), /words are sent over the encrypted connection to your own node and derived there/u)
  assert.match(textOf(disclosure), /Deriving on your device is later work/u)
  assert.equal(find(ui.tree, 'data-aumlok-first-run-step').props['data-aumlok-first-run-step'], 1)
  assert.equal(find(ui.tree, 'data-aumlok-bind-button').props.disabled, true)
  await ui.change('data-aumlok-handle-input', 'owner')
  assert.equal(find(ui.tree, 'data-aumlok-bind-button').props.disabled, false)
  await ui.click()
  assert.deepEqual(ui.draws, [['bind', 'en', 'owner']])
  assert.equal(find(ui.tree, 'data-aumlok-first-run-step').props['data-aumlok-first-run-step'], 2)
  assert.equal(find(ui.tree, 'data-aumlok-ceremony-beat').props['data-aumlok-ceremony-beat'], 'shown')
  assert.equal(nodes(ui.tree).filter(node => node.props?.['data-aumlok-tile-face'] === 'word' && node.type === 'span').length, 6)
  assert.equal(textOf(find(ui.tree, 'data-aumlok-first-word')), words[0])
  await ui.click()
  assert.equal(find(ui.tree, 'data-aumlok-first-run-step').props['data-aumlok-first-run-step'], 2)
  assert.equal(nodes(ui.tree).filter(node => Object.hasOwn(node.props ?? {}, 'data-aumlok-tile-input')).length, 7)
  for (let at = 0; at < 7; at++) {
    nodes(ui.tree).find(node => node.props?.['data-aumlok-tile-input'] === at).props.onChange({ target: { value: words[at] } })
    await ui.flush()
  }
  await ui.click()
  assert.equal(find(ui.tree, 'data-aumlok-first-run-step').props['data-aumlok-first-run-step'], 3)
  assert.ok(find(ui.tree, 'data-aumlok-confirm-warning'))
  assert.equal(find(ui.tree, 'data-aumlok-bind-button').props.disabled, true)
  await ui.click(); assert.equal(ui.submits.length, 0)
  await ui.change('data-aumlok-confirm-checkbox', true, true)
  nodes(ui.tree).find(node => node.props?.['data-aumlok-tile-input'] === 0).props.onChange({ target: { value: words[0] } })
  await ui.flush()
  assert.equal(find(ui.tree, 'data-aumlok-bind-button').props.disabled, true, 'editing type-back clears acknowledgment')
  await ui.change('data-aumlok-confirm-checkbox', true, true)
  await ui.click()
  assert.deepEqual(JSON.parse(JSON.stringify(ui.submits)), [['bind', words, 'owner']]); assert.equal(ui.refreshed, 1)
  assert.equal(find(ui.tree, 'data-aumlok-badge').props['data-aumlok-badge'], 'bound')
  assert.equal(find(ui.tree, 'data-aumlok-bind-button'), undefined, 'browser binding has no replacement control')
  assert.equal(textOf(find(ui.tree, 'data-aumlok-completion')).includes('Your node is yours'), true)
  assert.equal(textOf(find(ui.tree, 'data-aumlok-completion-handle')), 'owner')
  find(ui.tree, 'data-aumlok-start-chat').props.onClick()
  assert.equal(ui.started, 1)
  await ui.close(); assert.equal(ui.cancelled, 1)
  ui.unmount(); assert.equal(ui.cancelled, 2)
  const browserBound = screen(text, true)
  await browserBound.bound()
  assert.equal(find(browserBound.tree, 'data-aumlok-bind-button'), undefined, 'bound browser cannot replace identity')
  browserBound.unmount()
  const desktop = screen(text, false)
  assert.equal(find(desktop.tree, 'data-aumlok-browser-derivation'), undefined)
  await desktop.bound()
  assert.ok(find(desktop.tree, 'data-aumlok-bind-button'), 'desktop refresh control preserved')
  desktop.unmount()
}

async function loaderChecks(Loader = AumlokControlStatusLoader) {
  const calls = [], connected = [], disconnected = []
  const projection = { connect: value => connected.push(value), disconnect: (...args) => disconnected.push(args) }
  const loader = new Loader(projection, { isLoopback: false }, async (url, init) => {
    calls.push({ url, init }); return reply({ status: 'connected', control: { public: 'fixture' } })
  })
  await loader.refresh()
  assert.equal(calls.length, 1, 'public-origin authenticated status read reaches host')
  assert.equal(connected.length, 1); assert.equal(disconnected.length, 1)
  assert.equal(calls[0].init.credentials, 'same-origin'); assert.equal(calls[0].init.cache, 'no-store')
  assert.equal(calls[0].init.method, 'GET')
  loader.dispose(); await loader.refresh(); assert.equal(calls.length, 1)
}

async function mountingChecks(text = sources['index.ts']) {
  for (const { desktop, loopback } of [
    { desktop: false, loopback: false },
    { desktop: false, loopback: true },
    { desktop: true, loopback: true },
  ]) {
    const calls = [], desktopCalls = [], injected = {}, exports = {}
    const fetch = async (url, init) => { calls.push({ url, init }); return reply(url.endsWith('/prepare')
      ? { ok: true, draw } : url.endsWith('/bind') ? { ok: true, binding: {} } : { ok: true }) }
    const desktopBridge = desktop ? bridgeApi.readAumlokCeremonyBridge({ available: true,
      draw: async (...args) => { desktopCalls.push(args); return { ok: true, ...draw } },
      submit: async (...args) => { desktopCalls.push(args); return { ok: true } },
    }) : undefined
    class Projection {
      constructor(ctx) { ctx.aumlokControlProjection = this; this.store = {} }
      attachCeremony(value) { this.ceremony = value }
      get ceremonyAvailable() { return this.ceremony !== undefined }
      drawPhrase(...args) { return bridgeApi.drawAumlokPhrase(this.ceremony, ...args) }
      submitPhrase(...args) { return bridgeApi.submitAumlokPhrase(this.ceremony, ...args) }
    }
    runInNewContext(compile(text), { exports, fetch,
      require(name) {
        if (name === './binding-bridge.ts') return { ...bridgeApi,
          readAumlokCeremonyBridge: () => desktopBridge,
          createAumlokBrowserCeremonyBridge: () => bridgeApi.createAumlokBrowserCeremonyBridge(fetch, 'https:'),
        }
        if (name === './control-projection.ts') return { AumlokControlProjectionService: Projection }
        if (name === './control-status-loader.ts') return { AumlokControlStatusLoader: class { refresh() {} dispose() {} } }
        if (name === '../identity.ts') return { AUMLOK_IDENTITY_ENDPOINT: '/api/aukora/aumlok-identity' }
        return {}
      } })
    const layoutCalls = []
    const ctx = { locale: { register() {} }, layout: {
      closeSurface: () => { layoutCalls.push('close') }, openConversation: () => { layoutCalls.push('conversation') },
    }, slots: { inject: (_name, callback) => callback(),
      register: options => { if (options.inject) injected[options.id] = options.inject(); return () => {} } },
      effect: callback => callback(), on: () => () => {}, get(name) { return this[name] ?? { isLoopback: false } },
      inject(_services, callback) { callback(this) },
    }
    ctx.connection = { isLoopback: loopback }
    exports.apply(ctx)
    assert.equal(injected.aumlok.ceremonyAvailable, true)
    assert.equal(injected.aumlok.browserCeremony, !desktop)
    assert.equal(injected.aumlok.publicFirstRun, !desktop && !loopback)
    assert.equal((await injected.aumlok.drawPhrase('bind', 'en', 'owner')).ok, true)
    assert.equal((await injected.aumlok.submitPhrase('bind', words, 'owner')).ok, true)
    if (desktop) assert.deepEqual(desktopCalls, [['bind', 'en'], ['bind', words, 'owner']])
    else {
      const count = calls.length
      assert.equal((await injected.aumlok.drawPhrase('refresh', 'en', 'owner')).reason, 'aumlok:browser-first-binding-only')
      assert.equal(calls.length, count)
      assert.equal(typeof injected.aumlok.cancelCeremony, 'function')
    }
    injected.aumlok.startFirstChat()
    assert.deepEqual(layoutCalls, ['close', 'conversation'])
    await injected.identity.readIdentity()
    assert.equal(calls.at(-1).url, '/api/aukora/aumlok-identity')
    assert.equal(calls.at(-1).init.method, 'GET'); assert.equal(calls.at(-1).init.credentials, 'same-origin')
    assert.equal(calls.at(-1).init.cache, 'no-store')
  }
}

async function firstRunDecisionChecks(api = surfaceState) {
  const unbound = { status: 'not-connected', reason: 'controller-absent' }
  const base = { active: false, alreadyOpened: false, browserCeremony: true, isLoopback: false, projection: unbound }
  assert.deepEqual(api.aumlokFirstRunOpen(base), { ok: true })
  for (const [change, refusal] of [
    [{ active: true }, api.AUMLOK_FIRST_RUN_OPEN_REFUSE.ALREADY_OPEN],
    [{ alreadyOpened: true }, api.AUMLOK_FIRST_RUN_OPEN_REFUSE.ALREADY_OPENED],
    [{ browserCeremony: false }, api.AUMLOK_FIRST_RUN_OPEN_REFUSE.NO_BROWSER_CEREMONY],
    [{ isLoopback: true }, api.AUMLOK_FIRST_RUN_OPEN_REFUSE.LOOPBACK],
    [{ projection: { status: 'not-connected' } }, api.AUMLOK_FIRST_RUN_OPEN_REFUSE.NOT_UNBOUND],
    [{ projection: { status: 'not-connected', reason: 'adapter-unbound' } }, api.AUMLOK_FIRST_RUN_OPEN_REFUSE.NOT_UNBOUND],
    [{ projection: { status: 'connected', control: {} } }, api.AUMLOK_FIRST_RUN_OPEN_REFUSE.NOT_UNBOUND],
    [{ projection: { status: 'connected', reason: 'controller-absent', control: {} } }, api.AUMLOK_FIRST_RUN_OPEN_REFUSE.NOT_UNBOUND],
  ]) assert.deepEqual(api.aumlokFirstRunOpen({ ...base, ...change }), { ok: false, reason: refusal })
  const step = (beat, busy = false, bound = false, successfulBind = false) =>
    api.aumlokFirstRunStep({ beat, busy, bound, successfulBind })
  assert.equal(step('none'), 1)
  assert.equal(step('none', true), 2)
  assert.equal(step('shown'), 2)
  assert.equal(step('typed'), 2)
  assert.equal(step('confirm'), 3)
  assert.equal(step('confirm', true), 3)
  assert.equal(step('none', false, true), 'complete')
  assert.equal(step('none', false, false, true), 'complete')
}

function firstRunStyleChecks(text = sources['Aumlok.module.css']) {
  const block = selector => {
    const escaped = selector.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
    const matches = [...text.matchAll(new RegExp(`${escaped} \\{[^}]*\\}`, 'gu'))]
    const shared = matches.find(match => match[0].includes('background: var(--aukora-surface);'))
    assert.ok(shared, `missing shared-surface CSS block ${selector}`)
    return shared[0]
  }
  for (const selector of ['.firstRunSteps li', '.flow', '.completion']) {
    assert.match(block(selector), /border: 1px solid var\(--aukora-border\)/u)
    assert.match(block(selector), /border-radius: var\(--aukora-radius\)/u)
    assert.match(block(selector), /background: var\(--aukora-surface\)/u)
    assert.match(block(selector), /backdrop-filter: blur\(18px\)/u)
  }
  assert.match(text, /@container aumlok \(max-width: 520px\)[\s\S]*\.flowSummary \{ display: list-item; \}[\s\S]*\.flow:not\(\[open\]\) > \.flowBody \{ display: none; \}/u)
  assert.match(text, /@media \(prefers-reduced-motion: reduce\)[\s\S]*\.firstRunSteps li,[\s\S]*\.completion button \{\s*transition: none;/u)
}

async function mutation(name, source, before, after, check, load) {
  assert.ok(source.includes(before), `missing mutation site ${name}`)
  const changed = source.replace(before, after)
  const module = load ? await load(changed) : await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(changed)).toString('base64')}#${name}`)
  await assert.rejects(() => check(module), undefined, `mutation survived ${name}`)
  console.log(`AUMLOK BROWSER CLIENT MUTATION: KILLED ${name}`)
}

test('browser uses HTTPS, same-origin POST bodies, one pending draw and sanitized refusals', async () => {
  await transportChecks(bridgeApi)
  console.log('AUMLOK BROWSER TRANSPORT: PASS HTTPS, POST body, no redirect, first binding, consume/cancel, response refusal')
})
test('rendered screen discloses node derivation and walks draw, hide, type, acknowledge, bind', async () => {
  await screenChecks()
  console.log('AUMLOK BROWSER SCREEN: PASS rendered seven-word ceremony, disclosure, acknowledgment, completion state, desktop refresh preserved')
})
test('public authenticated status reads remain generation-scoped and disposable', async () => {
  await loaderChecks()
  console.log('AUMLOK BROWSER STATUS: PASS public-origin same-origin authenticated GET and dispose')
})
test('browser mounting carries handle and desktop mounting keeps its original transport', async () => {
  await mountingChecks()
  console.log('AUMLOK BROWSER MOUNT: PASS browser transport, prepare handle, desktop precedence, public authenticated identity read')
})
test('first run opens only for public-origin UNBOUND and exposes each binding step', async () => {
  await firstRunDecisionChecks()
  firstRunStyleChecks()
  const publicUnbound = screen(sources['AumlokSurface.tsx'], true, {
    activeSurface: 'threads', publicFirstRun: true,
    projection: { status: 'not-connected', reason: 'controller-absent' },
  })
  assert.equal(publicUnbound.opened, 1)
  const loopback = screen(sources['AumlokSurface.tsx'], true, {
    activeSurface: 'threads', publicFirstRun: false,
    projection: { status: 'not-connected', reason: 'controller-absent' },
  })
  assert.equal(loopback.opened, 0)
  const bound = screen(sources['AumlokSurface.tsx'], true, {
    activeSurface: 'threads', publicFirstRun: true,
    projection: { status: 'connected', control: {} },
  })
  assert.equal(bound.opened, 0)
  console.log('AUMLOK FIRST RUN: PASS public-origin UNBOUND auto-open, loopback/bound refusal, three steps, completion chat action')
})
test('browser client protection mutations are detected', async () => {
  const source = sources['binding-bridge.ts']
  for (const [name, before, after] of [
    ['HTTPS required', "if (protocol !== 'https:') return undefined", ''],
    ['POST only', "method: 'POST'", "method: 'GET'"],
    ['authenticated same-origin', "credentials: 'same-origin'", "credentials: 'omit'"],
    ['same-origin mode', "mode: 'same-origin'", "mode: 'cors'"],
    ['redirect refused', "redirect: 'error'", "redirect: 'follow'"],
    ['cache excluded', "cache: 'no-store'", "cache: 'default'"],
    ['referrer excluded', "referrerPolicy: 'no-referrer'", "referrerPolicy: 'unsafe-url'"],
    ['refresh refused', "if (intent !== 'bind') return refusal('aumlok:browser-first-binding-only')", ''],
    ['pending draw required', "if (ceremonyId === undefined) return refusal('aumlok:browser-no-pending-draw')", ''],
    ['same handle required', "if (handle !== preparedHandle) return refusal('aumlok:browser-handle-changed')", ''],
    ['phrase shape refused', "if (!Array.isArray(words) || words.length !== PHRASE_LENGTH", 'if (false && (!Array.isArray(words) || words.length !== PHRASE_LENGTH'],
    ['draw id bounded', "typeof id !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/u.test(id) || ", ''],
    ['stale draw cancelled', 'if (current !== generation)', 'if (false)'],
    ['draw consumed before bind', "const pending = ceremonyId\n      ceremonyId = undefined", 'const pending = ceremonyId'],
    ['cancel forgets draw', "const pending = ceremonyId\n    ceremonyId = undefined", 'const pending = ceremonyId'],
    ['JSON response required', "response.headers.get('content-type')?.split(';', 1)[0]?.trim() !== 'application/json'", 'false'],
    ['HTTP refusal required', "response.ok && record['ok'] === true", "record['ok'] === true"],
    ['refusal text scrubbed', "/^aumlok:[a-z0-9:_-]{1,112}$/u.test(reason)", 'true'],
    ['binding response required', "if (value['binding'] === null || typeof value['binding'] !== 'object' || Array.isArray(value['binding']))", 'if (false)'],
  ]) {
    let changedAfter = after
    let changedSource = source
    if (name === 'phrase shape refused') {
      changedSource = source.replace("WORD.test(word)))\n        return refusal('aumlok:browser-phrase-shape')", "WORD.test(word))))\n        return refusal('aumlok:browser-phrase-shape')")
    }
    await mutation(name, changedSource, before, changedAfter, transportChecks)
  }
  for (const [name, before, after] of [
    ['cloud disclosure visible', '{browserCeremony ? <p className={css.warning} data-aumlok-browser-derivation>', '{false ? <p className={css.warning} data-aumlok-browser-derivation>'],
    ['bound browser cannot refresh', "ceremonyAvailable && (!browserCeremony || state === 'unbound')", 'ceremonyAvailable'],
    ['confirmation required', 'if (!gate.bindEnabled) return', ''],
    ['type edit clears acknowledgment', "if (beat === 'confirm') setAcknowledged(false)", ''],
    ['close cancels draw', 'cancelCeremony?.()', ''],
  ]) await mutation(name, sources['AumlokSurface.tsx'], before, after, () => screenChecks(sources['AumlokSurface.tsx'].replace(before, after)), () => ({}))
  await mutation('desktop bridge precedence', sources['index.ts'], 'desktopCeremony === undefined ? createAumlokBrowserCeremonyBridge() : undefined',
    'createAumlokBrowserCeremonyBridge()', () => mountingChecks(sources['index.ts'].replace(
      'desktopCeremony === undefined ? createAumlokBrowserCeremonyBridge() : undefined', 'createAumlokBrowserCeremonyBridge()')), () => ({}))
  await mutation('browser refresh mapper refused', sources['index.ts'], "intent !== 'bind' ? Promise.resolve({ ok: false, reason: 'aumlok:browser-first-binding-only' })",
    "false ? Promise.resolve({ ok: false, reason: 'aumlok:browser-first-binding-only' })", () => mountingChecks(sources['index.ts'].replace(
      "intent !== 'bind' ? Promise.resolve({ ok: false, reason: 'aumlok:browser-first-binding-only' })",
      "false ? Promise.resolve({ ok: false, reason: 'aumlok:browser-first-binding-only' })")), () => ({}))
  await mutation('public-origin loopback fence', sources['index.ts'],
    'browserCeremony !== undefined && !connection.isLoopback', 'browserCeremony !== undefined',
    () => mountingChecks(sources['index.ts'].replace(
      'browserCeremony !== undefined && !connection.isLoopback', 'browserCeremony !== undefined')), () => ({}))
  for (const [name, before, after] of [
    ['auto-open once guard', 'if (input.alreadyOpened)', 'if (false)'],
    ['auto-open loopback guard', 'if (input.isLoopback)', 'if (false)'],
    ['auto-open browser ceremony guard', 'if (!input.browserCeremony)', 'if (false)'],
    ['auto-open status guard', "input.projection.status !== 'not-connected'", 'false'],
    ['auto-open absent-controller guard', "input.projection.reason !== 'controller-absent'", 'false'],
    ['step confirmation', "if (input.beat === 'confirm') return 3", 'if (false) return 3'],
    ['step completion', "if (input.bound || input.successfulBind) return 'complete'", 'if (false) return \'complete\''],
  ]) await mutation(name, sources['surface-state.ts'], before, after, firstRunDecisionChecks)
  for (const [name, before, after] of [
    ['shared first-run surface tokens', 'background: var(--aukora-surface);\n  backdrop-filter: blur(18px);', 'background: #000;\n  backdrop-filter: none;'],
    ['narrow explanation control', '.flowSummary { display: list-item; }', '.flowSummary { display: none; }'],
    ['narrow explanation collapse', '.flow:not([open]) > .flowBody { display: none; }', '.flow:not([open]) > .flowBody { display: block; }'],
    ['first-run reduced motion', '.completion button {\n    transition: none;', '.completion button {\n    transition: all 180ms ease;'],
  ]) await mutation(name, sources['Aumlok.module.css'], before, after,
    async () => firstRunStyleChecks(sources['Aumlok.module.css'].replace(before, after)), () => ({}))
  console.log('AUMLOK BROWSER CLIENT MUTATIONS: 38/38 KILLED; source fixtures, no real browser or owner binding')
})
