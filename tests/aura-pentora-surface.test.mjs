// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise the head picture, bounded reads and lifecycle cleanup through hooks.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { stripTypeScriptTypes } from 'node:module'
import { runInNewContext } from 'node:vm'
import * as pentora from '../plugins/aukora-face/settings/src/aura/pentora.mjs'
import * as motion from '../plugins/aukora-face/settings/src/aura/pentora-motion.mjs'
import * as snapshotApi from '../plugins/aukora-face/settings/src/client/aura-snapshot.ts'
import * as escape from '../plugins/aukora-face/settings/src/client/escape.ts'
import { en, zh } from '../plugins/aukora-face/settings/src/client/locales.ts'

const sourceUrl = new URL('../plugins/aukora-face/settings/src/client/AuraCoherenceSurface.tsx', import.meta.url)
const source = readFileSync(sourceUrl, 'utf8')
const style = readFileSync(new URL('../plugins/aukora-face/settings/src/client/AuraCoherenceSurface.module.css', import.meta.url), 'utf8')
const hash = bytes => new Uint8Array(createHash('sha256').update(bytes).digest())
const heads = ['00', '11', '22'].map(byte => byte.repeat(32))
const cellsOf = async head => Array.from(await pentora.pentoraDigits(Uint8Array.from(Buffer.from(head, 'hex')), hash))
const snapshot = (head, entries = 10) => ({
  schema: 'aukora-face/aura-snapshot:v1', head,
  sources: [
    { name: 'gate-ledger', head, entries, absence: null },
    { name: 'kira-chain', head: null, entries: null, absence: 'unavailable' },
    { name: 'code-chain', head: null, entries: null, absence: 'unavailable' },
  ],
})

// Convert only the component's JSX return; Node removes the TypeScript types.
// Unsupported JSX fails rather than silently skipping execution.
function componentJavaScript(text) {
  let at = text.indexOf('return <section') + 'return '.length
  assert.ok(at >= 'return '.length, 'surface-test:jsx-root')
  const start = at
  const whitespace = () => { while (/\s/u.test(text[at] ?? '') && at < text.length) at++ }
  function quoted() {
    const start = at, quote = text[at++]
    while (at < text.length) {
      if (text[at++] === '\\') { at++; continue }
      if (text[at - 1] === quote) return text.slice(start, at)
    }
    assert.fail('surface-test:unterminated-string')
  }
  function expression() {
    assert.equal(text[at++], '{')
    let depth = 1, out = ''
    while (at < text.length) {
      const char = text[at]
      if (char === '"' || char === "'" || char === '`') { out += quoted(); continue }
      if (char === '<' && /^<(?:[A-Za-z][\w-]*(?=[\s/>])|>)/u.test(text.slice(at))) { out += element(); continue }
      at++
      if (char === '{') depth++
      if (char === '}') {
        depth--
        if (depth === 0) return out
      }
      out += char
    }
    assert.fail('surface-test:unterminated-expression')
  }
  function element() {
    assert.equal(text[at++], '<')
    const fragment = text[at] === '>'
    const name = fragment ? '' : text.slice(at).match(/^[A-Za-z][\w-]*/u)?.[0]
    assert.notEqual(name, undefined, 'surface-test:jsx-name')
    at += name.length
    const properties = []
    whitespace()
    while (text[at] !== '>' && !text.startsWith('/>', at)) {
      const property = text.slice(at).match(/^[A-Za-z][\w-]*/u)?.[0]
      assert.ok(property, 'surface-test:jsx-property')
      at += property.length
      whitespace()
      let value = 'true'
      if (text[at] === '=') {
        at++; whitespace()
        value = text[at] === '{' ? `(${expression()})` : quoted()
      }
      properties.push(`${JSON.stringify(property)}:${value}`)
      whitespace()
    }
    const tag = fragment ? '__fragment' : JSON.stringify(name)
    if (text.startsWith('/>', at)) { at += 2; return `__jsx(${tag},{${properties.join(',')}})` }
    assert.equal(text[at++], '>')
    const children = []
    while (!text.startsWith('</', at)) {
      assert.ok(at < text.length, 'surface-test:jsx-close')
      if (text[at] === '<') children.push(element())
      else if (text[at] === '{') children.push(`(${expression()})`)
      else {
        const start = at
        while (at < text.length && text[at] !== '<' && text[at] !== '{') at++
        const content = text.slice(start, at).replace(/\s+/gu, ' ').trim()
        if (content) children.push(JSON.stringify(content))
      }
    }
    const close = `</${name}>`
    assert.equal(text.slice(at, at + close.length), close)
    at += close.length
    if (children.length) properties.push(`children:${children.length === 1 ? children[0] : `[${children.join(',')}]`}`)
    return `__jsx(${tag},{${properties.join(',')}})`
  }
  const returned = element()
  const javascript = stripTypeScriptTypes(text.slice(0, start) + returned + text.slice(at))
  return javascript.replace(/^import \{([^}]+)\} from (['"])([^'"]+)\2\s*$/gmu,
    (_, names, _quote, name) => `const {${names}} = __imports[${JSON.stringify(name)}]`)
    .replace(/^import (\w+) from (['"])([^'"]+)\2\s*$/gmu,
      (_, binding, _quote, name) => `const ${binding} = __imports[${JSON.stringify(name)}].default`)
    .replace('export function AuraCoherenceSurface', 'function AuraCoherenceSurface')
    + '\nexports.AuraCoherenceSurface = AuraCoherenceSurface\n'
}

function events() {
  const listeners = new Map()
  return {
    listeners,
    addEventListener(name, callback) {
      if (!listeners.has(name)) listeners.set(name, new Set())
      listeners.get(name).add(callback)
    },
    removeEventListener(name, callback) { listeners.get(name)?.delete(callback) },
    emit(name) { for (const callback of listeners.get(name) ?? []) callback() },
  }
}

function elements(tree, predicate) {
  const found = []
  const visit = value => {
    if (Array.isArray(value)) { value.forEach(visit); return }
    if (value === null || typeof value !== 'object') return
    if (predicate(value)) found.push(value)
    visit(value.props?.children)
  }
  visit(tree)
  return found
}
const stage = tree => elements(tree, node => node.props?.['data-pentora-state'] !== undefined)[0]
const renderedCells = tree => elements(tree, node => node.props?.['data-pentora-cell'] !== undefined)
  .sort((a, b) => a.props['data-pentora-cell'] - b.props['data-pentora-cell']).map(node => node.props['data-trit'])
function textOf(value) {
  if (Array.isArray(value)) return value.map(textOf).join('')
  if (value === null || value === undefined || typeof value === 'boolean') return ''
  if (typeof value === 'object') return textOf(value.props?.children)
  return String(value)
}

function runtime(text = source, options = {}) {
  let now = 0, nextId = 0, cursor = 0, tree, renders = [], prepared = 0
  const slots = [], updates = [], effects = [], timers = new Map(), frames = new Map(), requests = []
  const document = Object.assign(events(), { visibilityState: 'visible' })
  const media = Object.assign(events(), { matches: options.reduced ?? false })
  const window = Object.assign(events(), {
    matchMedia: () => media,
    requestAnimationFrame(callback) { const id = ++nextId; frames.set(id, { at: now + 16, callback }); return id },
    cancelAnimationFrame(id) { frames.delete(id) },
  })
  let props = { activeSurface: options.active === false ? null : 'aura-coherence', closeSurface() {},
    t: (key, values) => values ? `${key}:${JSON.stringify(values)}` : key }
  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!slots[index]) {
        const slot = { value: typeof initial === 'function' ? initial() : initial }
        slot.set = update => { updates.push(() => {
          const next = typeof update === 'function' ? update(slot.value) : update
          if (Object.is(next, slot.value)) return false
          slot.value = next
          return true
        }) }
        slots[index] = slot
      }
      return [slots[index].value, slots[index].set]
    },
    useRef(initial) { const index = cursor++; return slots[index] ??= { current: initial } },
    useId() { const index = cursor++; return slots[index] ??= ':surface-test:' },
    useEffect(callback, dependencies) {
      const index = cursor++, prior = slots[index]
      if (!prior || dependencies.some((value, index) => !Object.is(value, prior.dependencies[index]))) {
        slots[index] = { dependencies, cleanup: prior?.cleanup }
        effects.push(() => { slots[index].cleanup?.(); slots[index].cleanup = callback() })
      }
    },
  }
  const jsx = (type, props) => ({ type, props })
  const compiled = componentJavaScript(text)
  const exports = {}
  runInNewContext(compiled, {
    exports, document, window, AbortController,
    performance: { now: () => now },
    setTimeout(callback, delay) { const id = ++nextId; timers.set(id, { at: now + delay, callback }); return id },
    clearTimeout(id) { timers.delete(id) },
    fetch(url, init) {
      const request = { url, init }
      requests.push(request)
      return new Promise((resolve, reject) => {
        request.reply = value => resolve({ ok: true, json: async () => value })
        request.fail = reject
        if (!options.ignoreAbort) init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
      })
    },
    __jsx: jsx, __fragment: Symbol('fragment'),
    __imports: {
      react: hooks,
      '../aura/pentora.mjs': pentora,
      '../aura/pentora-motion.mjs': { ...motion,
        createPentoraMotion(...args) { prepared += 1; return motion.createPentoraMotion(args[0], args[1], hash) } },
      './aura-snapshot.ts': snapshotApi,
      './escape.ts': escape,
      './AuraCoherenceSurface.module.css': { default: new Proxy({}, { get: (_, key) => key }) },
    },
  }, { filename: sourceUrl.pathname })
  function render() {
    cursor = 0
    tree = exports.AuraCoherenceSurface(props)
    renders.push({ at: now, tree })
    while (effects.length) effects.shift()()
  }
  async function flush() {
    // Apply state updates separately so no correctness claim relies on batching.
    for (let turn = 0; turn < 30; turn += 1) {
      await Promise.resolve()
      while (updates.length) if (updates.shift()()) render()
    }
  }
  render()
  return {
    requests, frames, timers, document, media, window,
    get tree() { return tree }, get prepared() { return prepared }, get renders() { return renders },
    clearRenders() { renders = [] }, flush,
    async reply(index, value) { requests[index].reply(value); await flush() },
    async fail(index) { requests[index].fail(new Error('synthetic-read-failure')); await flush() },
    async active(active) { props = { ...props, activeSurface: active ? 'aura-coherence' : null }; render(); await flush() },
    async visible(visible) { document.visibilityState = visible ? 'visible' : 'hidden'; document.emit('visibilitychange'); await flush() },
    async reduced(reduced) { media.matches = reduced; media.emit('change'); await flush() },
    async advance(milliseconds) {
      const target = now + milliseconds
      for (let count = 0; count < 1000; count += 1) {
        const due = [...timers].map(([id, value]) => ({ id, ...value, collection: timers }))
          .concat([...frames].map(([id, value]) => ({ id, ...value, collection: frames })))
          .filter(value => value.at <= target).sort((a, b) => a.at - b.at || a.id - b.id)[0]
        if (!due) { now = target; await flush(); return }
        now = due.at; due.collection.delete(due.id); due.callback(now); await flush()
      }
      assert.fail('surface-test:scheduler-unbounded')
    },
    unmount() { for (const slot of slots) slot?.cleanup?.() },
  }
}

async function checkPolling(text) {
  const ui = runtime(text)
  await ui.flush()
  assert.equal(ui.requests.length, 1)
  assert.equal(ui.requests[0].url, '/api/aukora/aura-snapshot')
  assert.equal(ui.requests[0].init.cache, 'no-store')
  assert.equal(ui.requests[0].init.credentials, 'same-origin')
  await ui.reply(0, snapshot(heads[0]))
  assert.equal(stage(ui.tree).props['data-pentora-state'], 'solid')
  assert.deepEqual(renderedCells(ui.tree), await cellsOf(heads[0]))
  assert.equal(elements(ui.tree, node => node.type === 'circle').length, 111)
  assert.equal(elements(ui.tree, node => node.type === 'dt').length, 3)
  await ui.advance(1999)
  assert.equal(ui.requests.length, 1, 'polling waits the full bounded interval')
  await ui.advance(1)
  assert.equal(ui.requests.length, 2)
  await ui.reply(1, snapshot(heads[0]))
  assert.equal(ui.prepared, 1, 'same head keeps the same prepared picture')
  assert.equal(ui.frames.size, 0, 'same head does not start an animation')
  ui.unmount()
}

async function checkSourceLegend(text) {
  const ui = runtime(text)
  const named = ['gate-ledger', 'kira-chain', 'code-chain']
  const available = named.map((name, index) => ({ name, head: heads[index], entries: index === 2 ? 1 : 10, absence: null }))
  const observe = async (index, sources) => {
    await ui.reply(index, { ...snapshot(heads[0]), sources })
    assert.deepEqual(elements(ui.tree, node => node.type === 'dt').map(textOf), named)
    const rows = elements(ui.tree, node => node.type === 'dd').map(textOf)
    for (let at = 0; at < sources.length; at += 1) {
      const source = sources[at]
      assert.ok(rows[at].includes(source.head === null ? 'aura.snapshot.absent' : 'aura.snapshot.available'), `legend availability of ${source.name}`)
      assert.ok(rows[at].includes(source.head === null ? source.absence : source.head.slice(0, 16)), `legend observed head or refusal of ${source.name}`)
    }
    const count = sources.filter(source => source.head !== null).length
    assert.ok(elements(ui.tree, node => node.type === 'p').some(node => node.props.children === `aura.snapshot.present:{"count":${count}}`))
  }
  await observe(0, available)
  await ui.advance(2000)
  await observe(1, available.map((source, index) => index === 1 ? { ...source, head: null, entries: null, absence: 'kira-ledger-torn' } : source))
  await ui.advance(2000)
  await observe(2, available.map(source => ({ ...source, head: null, entries: null, absence: 'fixture-unavailable' })))
  ui.unmount()
}

async function checkClock(text) {
  const ui = runtime(text)
  await ui.reply(0, snapshot(heads[0]))
  await ui.advance(2000)
  await ui.reply(1, snapshot(heads[1], 12))
  await ui.advance(2000)
  assert.equal(stage(ui.tree).props['data-pentora-state'], 'solid')
  ui.clearRenders()
  await ui.reply(2, snapshot(heads[2], 15))
  for (const render of ui.renders) {
    const head = elements(render.tree, node => node.type === 'code' && node.props.title === heads[2])[0]
    if (head) assert.equal(stage(render.tree).props['data-pentora-state'], 'in-motion', 'new head cannot inherit an old settled clock')
  }
  assert.deepEqual(renderedCells(ui.tree), await cellsOf(heads[1]))
  await ui.advance(400)
  assert.equal(stage(ui.tree).props['data-pentora-state'], 'in-motion')
  assert.deepEqual(renderedCells(ui.tree), await cellsOf(heads[2]))
  await ui.advance(816)
  assert.equal(stage(ui.tree).props['data-pentora-state'], 'solid')
  assert.deepEqual(renderedCells(ui.tree), await cellsOf(heads[2]))
  assert.ok(elements(ui.tree, node => node.type === 'p').some(node => node.props.children === 'aura.snapshot.entries:{"count":5}'))
  ui.unmount()
}

async function checkReduced(text) {
  const ui = runtime(text, { reduced: true })
  await ui.reply(0, snapshot(heads[0]))
  await ui.advance(2000)
  await ui.reply(1, snapshot(heads[1], 11))
  assert.equal(stage(ui.tree).props['data-pentora-state'], 'solid')
  assert.deepEqual(renderedCells(ui.tree), await cellsOf(heads[1]))
  assert.equal(ui.frames.size, 0)
  await ui.reduced(false)
  assert.equal(stage(ui.tree).props['data-pentora-state'], 'in-motion')
  await ui.reduced(true)
  assert.equal(stage(ui.tree).props['data-pentora-state'], 'solid')
  assert.equal(ui.frames.size, 0)
  ui.unmount()
}

async function checkLifecycle(text) {
  const dormant = runtime(text, { active: false })
  await dormant.flush()
  assert.equal(dormant.requests.length, 0)
  dormant.unmount()
  const ui = runtime(text)
  await ui.reply(0, snapshot(heads[0]))
  await ui.advance(2000)
  await ui.reply(1, snapshot(heads[1]))
  assert.ok(ui.frames.size > 0)
  await ui.visible(false)
  assert.equal(ui.frames.size, 0)
  assert.equal(ui.timers.size, 0)
  await ui.advance(3000)
  assert.equal(ui.requests.length, 2)
  await ui.visible(true)
  assert.equal(ui.requests.length, 3)
  await ui.active(false)
  assert.equal(ui.requests[2].init.signal.aborted, true)
  assert.equal(ui.frames.size, 0)
  assert.equal(ui.timers.size, 0)
  await ui.advance(6000)
  assert.equal(ui.requests.length, 3)
  ui.unmount()
  assert.equal([...ui.document.listeners.values()].reduce((count, entries) => count + entries.size, 0), 0)
  assert.equal([...ui.media.listeners.values()].reduce((count, entries) => count + entries.size, 0), 0)
}

async function checkTimeout(text) {
  const ui = runtime(text)
  await ui.advance(4999)
  assert.equal(ui.requests[0].init.signal.aborted, false)
  await ui.advance(1)
  assert.equal(ui.requests[0].init.signal.aborted, true)
  assert.ok(elements(ui.tree, node => node.props?.role === 'status').length > 0)
  ui.unmount()
}

async function checkDisposed(text) {
  const ui = runtime(text, { ignoreAbort: true })
  await ui.active(false)
  await ui.reply(0, snapshot(heads[0]))
  assert.equal(stage(ui.tree), undefined, 'late response cannot populate an inactive observation')
  assert.equal(ui.timers.size, 0)
  ui.unmount()
}

async function checkReadFailures(text) {
  const ui = runtime(text)
  assert.equal(stage(ui.tree), undefined, 'pending read has no invented head picture')
  await ui.reply(0, snapshot(heads[0]))
  await ui.advance(2000)
  await ui.fail(1)
  assert.deepEqual(renderedCells(ui.tree), await cellsOf(heads[0]), 'failed read retains the last observed cells')
  assert.ok(elements(ui.tree, node => node.props?.className === 'problem')
    .some(node => node.props.children.includes('aura.snapshot.stale')), 'retained picture is disclosed as stale')
  await ui.advance(2000)
  await ui.reply(2, snapshot('malformed'))
  assert.deepEqual(renderedCells(ui.tree), await cellsOf(heads[0]), 'invalid snapshot cannot become a picture')
  await ui.advance(2000)
  await ui.reply(3, snapshot(heads[1], 11))
  assert.equal(elements(ui.tree, node => node.props?.className === 'problem').length, 0)
  assert.equal(stage(ui.tree).props['data-pentora-state'], 'in-motion')
  ui.unmount()
}

function checkDisclosure(text, dictionaries = { en, zh }, styles = style) {
  const ui = runtime(text)
  for (const key of ['aura.snapshot.meaning', 'aura.snapshot.limit', 'aura.snapshot.polling']) {
    assert.ok(elements(ui.tree, node => node.type === 'p').some(node => node.props.children === key), `visible ${key}`)
  }
  const keys = [...text.matchAll(/t\('(aura\.[^']+)'/gu)].map(match => match[1])
  for (const dictionary of Object.values(dictionaries)) {
    for (const key of keys) assert.ok(typeof dictionary[key] === 'string' && dictionary[key].length > 0, `locale ${key}`)
  }
  assert.match(dictionaries.en['aura.snapshot.limit'], /does not prove completeness, identity, who is looking, or approval/u)
  assert.match(dictionaries.zh['aura.snapshot.limit'], /不证明记录完整、身份、谁在观看或审批/u)
  assert.match(dictionaries.en['aura.snapshot.polling'], /gate approvals, Kira memory and the running release record \(one record\)/u)
  assert.match(dictionaries.zh['aura.snapshot.polling'], /门审批账本、Kira 记忆账本和当前版本的记录（一个记录）/u)
  assert.equal(dictionaries.en['aura.snapshot.available'], 'Present')
  assert.equal(dictionaries.zh['aura.snapshot.available'], '已提供')
  assert.match(dictionaries.en['aura.status.moving'], /transition, not a recorded state/u)
  assert.match(dictionaries.zh['aura.status.moving'], /过渡帧，不是记录状态/u)
  assert.match(styles, /\.root\[hidden\]\s*\{\s*display:\s*none/u)
  assert.match(styles, /\[data-pentora-state='in-motion'\] \.cell\s*\{[^}]*fill-opacity:\s*0\.38;[^}]*stroke:/u)
  const colors = ['0', '1', '2'].map(trit => styles.match(new RegExp(`\\.cell\\[data-trit='${trit}'\\]\\s*\\{\\s*fill:\\s*(#[0-9a-f]+)`, 'u'))?.[1])
  assert.ok(colors.every(Boolean), 'each canonical trit has a color')
  assert.equal(new Set(colors).size, 3, 'canonical trits have distinct colors')
  ui.unmount()
}

for (const [label, check] of [
  ['surface renders reference cells and disclosed sources; unchanged heads do not animate', checkPolling],
  ['legend names all three sources and shows present, mixed and absent observations', checkSourceLegend],
  ['new heads cannot reuse the previous settled clock; transition and counts are real', checkClock],
  ['reduced motion changes directly and preference updates cancel animation', checkReduced],
  ['inactive and hidden surfaces stop reads and frames; cleanup cancels pending work', checkLifecycle],
  ['snapshot reads abort at their bounded deadline', checkTimeout],
  ['disposed reads cannot apply a late snapshot', checkDisposed],
  ['failed and invalid reads preserve the last observed cells with a stale notice; retries recover', checkReadFailures],
]) test(label, () => check(source))

test('rendered disclosures and both locales describe display limits; transitional cells are visibly marked', () => {
  checkDisclosure(source)
})

test('geometry declarations preserve fixed coordinate and edge tuples', () => {
  const declaration = readFileSync(new URL('../plugins/aukora-face/settings/src/aura/pentora.d.mts', import.meta.url), 'utf8')
  function check(types) {
    assert.match(types, /points: \[number, number, number\]\[\];/u)
    assert.match(types, /edges: \[number, number\]\[\];/u)
  }
  check(declaration)
  for (const before of ['points: [number, number, number][];', 'edges: [number, number][];']) {
    assert.ok(declaration.includes(before), `geometry mutation anchor: ${before}`)
    assert.throws(() => check(declaration.replace(before, `${before.split(':')[0]}: number[][];`)), assert.AssertionError)
  }
  console.log('MUTATION aura-pentora-geometry-declarations: 2/2 killed')
})

test('mutations of surface protections are detected by executable hook tests', async () => {
  const mutations = [
    ['poll interval', 'const POLL_MS = 2000', 'const POLL_MS = 20', checkPolling],
    ['private uncached read', "cache: 'no-store'", "cache: 'default'", checkPolling],
    ['same origin credentials', "credentials: 'same-origin'", "credentials: 'omit'", checkPolling],
    ['record derived cell colors', 'const trit = cell === undefined ? 1 : frame.cells[cell]', 'const trit = 1', checkPolling],
    ['absent sources disclosed', 'snapshot.sources.map(source => <div key={source.name}>', 'snapshot.sources.slice(0, 1).map(source => <div key={source.name}>', checkPolling],
    ['present source legend', "t('aura.snapshot.available')", "t('aura.snapshot.absent')", checkSourceLegend],
    ['absent source legend', "t('aura.snapshot.absent')", "t('aura.snapshot.available')", checkSourceLegend],
    ['same head reuse', 'prior?.snapshot.head === snapshot.head ? prior.motion', 'false ? prior.motion', checkPolling],
    ['clock belongs to motion', 'clock?.motion === observation.motion ? clock.elapsed : 0', 'clock?.elapsed ?? 0', checkClock],
    ['transition label', 'data-pentora-state={frame.status}', 'data-pentora-state="solid"', checkClock],
    ['reduced motion', 'const reducedMotion = useReducedMotion()', 'const reducedMotion = false', checkReduced],
    ['inactive polling', 'if (!active || !visible) return', 'if (!visible) return', checkLifecycle],
    ['hidden polling', 'if (!active || !visible) return', 'if (!active) return', checkLifecycle],
    ['timer cleanup', 'clearTimeout(timer)', 'undefined', checkLifecycle],
    ['frame cleanup', 'window.cancelAnimationFrame(request)', 'undefined', checkLifecycle],
    ['abort deadline', 'controller?.abort()', 'undefined', checkTimeout],
    ['disposed response', 'if (disposed) return', 'if (false) return', checkDisposed],
    ['stale notice', "t('aura.snapshot.stale')", "t('aura.snapshot.waiting')", checkReadFailures],
  ]
  for (let offset = 0; offset < mutations.length; offset += 4) await Promise.all(mutations.slice(offset, offset + 4).map(async ([label, before, after, check]) => {
      assert.ok(source.includes(before), `missing mutation anchor: ${label}`)
      await assert.rejects(check(source.replace(before, after)), assert.AssertionError, `surviving mutant: ${label}`)
    }))
  console.log(`MUTATION aura-pentora-surface: ${mutations.length}/${mutations.length} killed`)
})

test('mutations removing display limits, available-source disclosure and transitional styling are detected', () => {
  let killed = 0
  for (const key of ['aura.snapshot.meaning', 'aura.snapshot.limit', 'aura.snapshot.polling']) {
    assert.throws(() => checkDisclosure(source.replace(`{t('${key}')}`, '')), assert.AssertionError)
    killed++
  }
  for (const language of ['en', 'zh']) {
    for (const key of ['aura.snapshot.limit', 'aura.snapshot.polling', 'aura.snapshot.available', 'aura.status.moving']) {
      const dictionaries = { en: { ...en }, zh: { ...zh } }
      dictionaries[language][key] = 'Synthetic omitted disclosure'
      assert.throws(() => checkDisclosure(source, dictionaries), assert.AssertionError)
      killed++
    }
  }
  for (const [before, after] of [
    ['display: none', 'display: block'],
    ['fill-opacity: 0.38', 'fill-opacity: 1'],
    ['stroke: #9faaba', 'outline: #9faaba'],
    ['fill: #57bfff', 'fill: #596475'],
  ]) {
    assert.ok(style.includes(before), `style mutation anchor: ${before}`)
    assert.throws(() => checkDisclosure(source, { en, zh }, style.replace(before, after)), assert.AssertionError)
    killed++
  }
  console.log(`MUTATION aura-pentora-surface-disclosure: ${killed}/${killed} killed`)
})

// A condition from the co-presence builder (2026-10-13): while the picture is between two heads, the page shows
// no digest text. Source-level: every place a head is printed sits behind the settled branch.
test('no digest text is rendered while the Pentora is between two heads', async () => {
  const { readFileSync } = await import('node:fs')
  const source = readFileSync(new URL('../plugins/aukora-face/settings/src/client/AuraCoherenceSurface.tsx', import.meta.url), 'utf8')
  assert.match(source, /const digestsWithheld = frame !== null && frame\.status !== 'solid'/u)
  const branch = source.indexOf("digestsWithheld ? <p className={css.state}>{t('aura.status.moving')}</p> : <>")
  assert.ok(branch > 0, 'the withheld branch is present')
  for (const printed of ['snapshot.head.slice(', 'source.head.slice(', 'JSON.stringify(snapshot']) {
    const at = source.indexOf(printed)
    assert.ok(at > branch, `${printed} is only reachable after the settled branch`)
    assert.equal(source.indexOf(printed, at + 1), -1, `${printed} appears once`)
  }
})
