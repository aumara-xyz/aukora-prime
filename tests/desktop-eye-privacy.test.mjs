// SPDX-License-Identifier: AGPL-3.0-or-later
// Eye routes discard private pixels, AX text and refs, and stop subsequent input across every await.
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import { syncBuiltinESMExports } from 'node:module'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { Script } from 'node:vm'
import nodeTest, { after } from 'node:test'
import * as eye from '../apps/aukora-desktop/eye.mjs'
import { installApprovalBridge } from '../apps/aukora-desktop/aumlok-bridge.mjs'
import { APPROVAL_CHANNELS } from '../apps/aukora-desktop/aumlok-bridge-state.mjs'

const test = (name, fn) => nodeTest(name, { timeout: 5000 }, fn)
const bodyFor = value => Readable.from([Buffer.from(JSON.stringify(value))])

const previousUmask = process.umask(0o002)
after(() => process.umask(previousUmask))

const root = fileURLToPath(new URL('..', import.meta.url))
const desktop = join(root, 'apps/aukora-desktop')
const eyeSource = readFileSync(join(desktop, 'eye.mjs'), 'utf8')
const bridgeSource = readFileSync(join(desktop, 'aumlok-bridge.mjs'), 'utf8')
const mainSource = readFileSync(join(desktop, 'main.mjs'), 'utf8')
const pixels = Buffer.from('synthetic private pixels')
const privateText = 'synthetic private AX phrase'
const publicRef = 'button:synthetic public button:0'
const publicTree = { nodes: [{ role: { value: 'button' }, name: { value: 'synthetic public button' }, backendDOMNodeId: 7 }] }
const changedModule = async (name, source, before, after) => {
  const changed = source.replace(before, after)
  assert.notEqual(changed, source, `mutation target: ${name}`)
  const absolute = changed.replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, new URL(`../apps/aukora-desktop/${name}`, import.meta.url)).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(absolute).toString('base64')}`)
}

class Window extends EventEmitter {
  constructor() { super(); this.destroyed = false; this.webContents = {} }
  isDestroyed() { return this.destroyed }
  destroy() { this.destroyed = true; this.emit('closed') }
}

async function receiver(t, module = eye, state = module.getPrivateSurfaceState) {
  let handler
  t.mock.method(http, 'createServer', callback => {
    handler = callback
    return { once() {}, listen: (_port, _host, ready) => ready(), address: () => ({ port: 12345 }), close: ready => ready() }
  })
  syncBuiltinESMExports()
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports() })
  const window = new Window()
  let captures = 0, encodings = 0
  let duringCapture = () => {}, duringEncoding = () => {}, duringCommand = () => {}, duringWindow = () => {}, duringAttach = () => {}
  const commands = []
  let attached = false, attachments = 0
  window.webContents.debugger = {
    isAttached: () => attached,
    attach() { attached = true; attachments++; duringAttach() },
    async sendCommand(name, args) {
      commands.push({ name, args })
      const result = await duringCommand(name, args)
      return result ?? (name === 'Accessibility.getFullAXTree' ? publicTree
        : name === 'DOM.getBoxModel' ? { model: { content: [0, 0, 2, 0, 2, 2, 0, 2] } } : {})
    },
  }
  window.webContents.capturePage = async () => {
    captures++; await duringCapture()
    return { getSize: () => ({ width: 1, height: 1 }), toPNG() { encodings++; duringEncoding(); return pixels } }
  }
  const logs = []
  const door = await module.installEyeDoor({ getWindow: () => { duringWindow(); return window }, getPrivateSurfaceState: state,
    log: line => logs.push(line) })
  t.after(() => door.dispose())
  return {
    window, logs, commands, counts: () => ({ captures, encodings, attachments }),
    duringCapture: fn => { duringCapture = fn }, duringEncoding: fn => { duringEncoding = fn },
    duringCommand: fn => { duringCommand = fn }, duringWindow: fn => { duringWindow = fn }, duringAttach: fn => { duringAttach = fn },
    request(body = Readable.from([Buffer.from('{}')]), authorization = `Bearer ${door.token}`, path = '/eye/capture') {
      Object.assign(body, { method: 'POST', url: path, headers: { host: '127.0.0.1:12345', authorization } })
      return new Promise(resolve => {
        let status, headers
        handler(body, { headersSent: false, writeHead: (code, fields) => { status = code; headers = fields }, end: data => resolve({ status, headers, data }) })
      })
    },
  }
}

test('public capture still returns PNG and a wrong token never reaches capture', async t => {
  const fence = eye.createPrivateSurfaceFence()
  const f = await receiver(t, eye, fence.getPrivateSurfaceState)
  const reply = await f.request()
  assert.equal(reply.status, 200)
  assert.equal(reply.headers['content-type'], 'image/png')
  assert.deepEqual(reply.data, pixels)
  const bad = await f.request(undefined, 'Bearer synthetic-wrong-token')
  assert.equal(bad.status, 401)
  assert.equal(JSON.parse(bad.data).code, 'eye.unauthorized')
  assert.equal(f.counts().captures, 1)
})

function refused(reply, code) {
  assert.equal(reply.status, 423)
  assert.equal(reply.headers['content-type'], 'application/json')
  assert.equal(JSON.parse(reply.data).code, code)
  assert.ok(!String(reply.data).includes(pixels.toString()))
  assert.ok(!String(reply.data).includes(privateText), 'contains_private_text=false')
}

async function drawnFixture(t, bridge = installApprovalBridge) {
  const base = join(root, '.runtime')
  mkdirSync(base, { recursive: true, mode: 0o700 })
  const scratch = mkdtempSync(join(base, 'eye-privacy-'))
  t.after(() => rmSync(scratch, { recursive: true, force: true }))
  const f = await receiver(t)
  const origin = 'http://127.0.0.1:3187'
  const frame = { url: `${origin}/`, origin, processId: 7, routingId: 11, parent: null, detached: false, isDestroyed: () => false }
  Object.assign(f.window.webContents, { mainFrame: frame, isDestroyed: () => f.window.destroyed })
  const handlers = new Map()
  const installed = bridge({ applicationOrigin: origin, here: desktop, getWindow: () => f.window,
    getReleaseDir: () => root, getPatchPaths: () => [], getStateRoot: () => scratch,
    ipcMain: { handle: (name, fn) => handlers.set(name, fn), removeHandler() {}, removeAllListeners() {} },
    ownerDaemonStatus: async () => ({ installed: false }), headless: true })
  // The destination is explicit and private even with login umask 002.
  mkdirSync(join(scratch, 'aumlok'), { mode: 0o700 })
  const event = { sender: f.window.webContents, senderFrame: frame, type: 'frame', processId: 7, frameId: 11 }
  t.after(() => { installed.dispose(); f.window.destroy() })
  return { ...f, installed, call: (name, payload) => handlers.get(APPROVAL_CHANNELS[name])(event, payload) }
}

async function consumedDraw(t, bridge = installApprovalBridge) {
  const f = await drawnFixture(t, bridge)
  const drawn = await f.call('DRAW', { intent: 'bind' })
  assert.equal(drawn.ok, true)
  const submitted = await f.call('SUBMIT', { intent: 'bind', words: ['invalid-shape'] })
  assert.equal(submitted.drawSpent, true)
  assert.equal(f.installed.isDrawPending(), false, 'reviewer sequence: draw consumed while phrase remains painted')
  refused(await f.request(), 'eye.bind-surface-open')
  assert.equal(f.counts().captures, 0)
}

test('spent draw still painted refuses the reviewer capture sequence', consumedDraw)

async function failedCapture(t, module = eye) {
  const fence = module.createPrivateSurfaceFence()
  const f = await receiver(t, module, fence.getPrivateSurfaceState)
  f.duringCapture(() => { throw new Error(pixels.toString()) })
  const reply = await f.request()
  assert.equal(reply.status, 500)
  assert.deepEqual(JSON.parse(reply.data), { ok: false, code: 'eye.capture-failed' })
  assert.ok(f.logs.every(line => !line.includes(pixels.toString())))
}
test('capture exceptions cannot return or log private pixel data', failedCapture)

async function transient(t, module = eye, phase = 'capture') {
  const fence = module.createPrivateSurfaceFence()
  const f = await receiver(t, module, fence.getPrivateSurfaceState)
  const flash = () => {
    const sheet = new Window()
    fence.privateSurface('approval', () => sheet, sheet)
    sheet.destroy()
    assert.equal(fence.getPrivateSurfaceState().code, null)
  }
  let body
  if (phase === 'body') body = Readable.from((async function* () { flash(); yield Buffer.from('{}') })())
  if (phase === 'capture') f.duringCapture(flash)
  if (phase === 'encoding') f.duringEncoding(flash)
  refused(await f.request(body), 'eye.approval-open')
  if (phase === 'body') assert.equal(f.counts().captures, 0, 'body race refuses before capture starts')
  if (phase !== 'encoding') assert.equal(f.counts().encodings, 0, 'private pixels discarded before encoding')
  assert.ok(f.logs.every(line => !line.includes(pixels.toString())))
}

for (const phase of ['body', 'capture', 'encoding']) {
  test(`private surface opens and closes during ${phase}: generation refuses`, t => transient(t, eye, phase))
}

function openPrivate(fence, kind = 'approval', transient = false) {
  const sheet = new Window()
  fence.privateSurface(kind, () => sheet, sheet)
  if (transient) sheet.destroy()
  return sheet
}

async function accessibilityRace(t, module = eye, transient = false, kind = 'approval', rejects = false, observe = () => {}) {
  const fence = module.createPrivateSurfaceFence()
  const f = await receiver(t, module, fence.getPrivateSurfaceState)
  let entered, finish
  const waiting = new Promise(resolve => { entered = resolve })
  const pending = new Promise(resolve => { finish = resolve })
  let processed = 0
  f.duringCommand(async name => {
    if (name !== 'Accessibility.getFullAXTree') return
    entered()
    await pending
    if (rejects) throw new Error(privateText)
    return { get nodes() { processed++; return [{ role: { value: 'textbox' }, name: { value: privateText }, backendDOMNodeId: 9 }] } }
  })
  const reply = f.request(undefined, undefined, '/eye/snapshot')
  await waiting
  const sheet = openPrivate(fence, kind, transient)
  finish()
  const result = await reply
  observe(result)
  refused(result, kind === 'bind' ? 'eye.bind-surface-open' : 'eye.approval-open')
  assert.equal(processed, 0, 'private AX text is discarded before reading nodes')
  assert.ok(f.logs.every(line => !line.includes(privateText)))
  sheet.destroy()
  f.duringCommand(() => {})
  const stale = await f.request(bodyFor({ action: 'type', ref: `textbox:${privateText}:0`, text: 'synthetic input' }),
    undefined, '/eye/act')
  assert.equal(JSON.parse(stale.data).code, 'eye.unknown-ref', 'ref from refused AX tree cannot survive')
  assert.ok(!f.commands.some(command => command.name.startsWith('Input.')))
}

for (const kind of ['approval', 'bind', 'dialog']) for (const transient of [false, true]) {
  test(`${kind} ${transient ? 'opens and closes' : 'opens'} during the pending AX read: no private text`,
    t => accessibilityRace(t, eye, transient, kind))
}
test('a rejected AX await also discards private error text', t => accessibilityRace(t, eye, true, 'approval', true))

async function actionRace(t, module = eye, phase = 'DOM.getBoxModel', transient = true) {
  const fence = module.createPrivateSurfaceFence()
  const f = await receiver(t, module, fence.getPrivateSurfaceState)
  assert.equal((await f.request(undefined, undefined, '/eye/snapshot')).status, 200)
  const type = phase === 'DOM.focus' || phase === 'Input.insertText'
  const action = type ? 'type' : 'click'
  let entered, finish
  const waiting = new Promise(resolve => { entered = resolve })
  const pending = new Promise(resolve => { finish = resolve })
  f.duringCommand(async (name, args) => {
    if (name !== phase || (phase === 'Input.dispatchMouseEvent' && args.type !== 'mousePressed')) return
    entered(); await pending
  })
  const reply = f.request(bodyFor({ action, ref: publicRef, text: 'synthetic input' }), undefined, '/eye/act')
  await waiting
  const sheet = openPrivate(fence, 'approval', transient)
  finish()
  refused(await reply, 'eye.approval-open')
  const input = f.commands.filter(command => command.name.startsWith('Input.'))
  assert.equal(input.length, phase.startsWith('Input.') ? 1 : 0, 'no input is dispatched after the trip')
  assert.ok(!input.some(command => command.args?.type === 'mouseReleased'), 'a trip during press prevents release')
  sheet.destroy()
  f.duringCommand(() => {})
  const stale = await f.request(bodyFor({ action, ref: publicRef, text: 'synthetic input' }), undefined, '/eye/act')
  assert.equal(JSON.parse(stale.data).code, 'eye.unknown-ref', 'a trip also discards previously published refs')
}
for (const phase of ['DOM.getBoxModel', 'DOM.focus', 'Input.dispatchMouseEvent', 'Input.insertText']) {
  for (const transient of [false, true]) test(`private surface races ${phase} (${transient ? 'transient' : 'visible'}): stop input`,
    t => actionRace(t, eye, phase, transient))
}

async function beforeAction(t, module = eye) {
  const fence = module.createPrivateSurfaceFence()
  const f = await receiver(t, module, fence.getPrivateSurfaceState)
  await f.request(undefined, undefined, '/eye/snapshot')
  f.duringCommand(name => name === 'DOM.getBoxModel' ? { model: { get content() {
    openPrivate(fence, 'approval', true)
    return [0, 0, 2, 0, 2, 2, 0, 2]
  } } } : undefined)
  refused(await f.request(bodyFor({ action: 'click', ref: publicRef }), undefined, '/eye/act'), 'eye.approval-open')
  assert.ok(!f.commands.some(command => command.name.startsWith('Input.')), 'precheck runs before dispatch, not after')
}
test('a private callback during box processing prevents dispatch', beforeAction)

test('public snapshot refs still permit click and type', async t => {
  const fence = eye.createPrivateSurfaceFence()
  const f = await receiver(t, eye, fence.getPrivateSurfaceState)
  const snapshot = await f.request(undefined, undefined, '/eye/snapshot')
  assert.deepEqual(JSON.parse(snapshot.data), { ok: true, nodes: [{ role: 'button', name: 'synthetic public button', ref: publicRef }], count: 1 })
  for (const action of ['click', 'type']) {
    const reply = await f.request(bodyFor({ action, ref: publicRef, text: 'synthetic input' }), undefined, '/eye/act')
    assert.equal(reply.status, 200)
    assert.equal(JSON.parse(reply.data).action, action)
  }
  assert.deepEqual(f.commands.filter(command => command.name.startsWith('Input.')).map(command => command.name),
    ['Input.dispatchMouseEvent', 'Input.dispatchMouseEvent', 'Input.insertText'])
})

for (const route of ['/eye/snapshot', '/eye/act']) for (const phase of ['debugger', 'body-or-enable']) {
  test(`${route} checks its ${phase} await before further window work`, async t => {
    const fence = eye.createPrivateSurfaceFence()
    const f = await receiver(t, eye, fence.getPrivateSurfaceState)
    if (route === '/eye/act') await f.request(undefined, undefined, '/eye/snapshot')
    f.commands.length = 0
    const flash = () => openPrivate(fence, 'approval', true)
    let body
    if (phase === 'debugger') {
      f.window.webContents.debugger.isAttached = () => false
      f.duringAttach(flash)
    } else if (route === '/eye/snapshot') {
      f.duringCommand(name => { if (name === 'Accessibility.enable') flash() })
    } else {
      body = Readable.from((async function* () { flash(); yield Buffer.from(JSON.stringify({ action: 'type', ref: publicRef, text: 'synthetic input' })) })())
    }
    body ??= bodyFor({ action: 'type', ref: publicRef, text: 'synthetic input' })
    refused(await f.request(body, undefined, route), 'eye.approval-open')
    assert.deepEqual(f.commands.map(command => command.name),
      route === '/eye/snapshot' && phase === 'body-or-enable' ? ['Accessibility.enable'] : [])
  })
}

// All route registrations and awaits are inventoried, including helpers outside the route bodies.
function routeInventory(source) {
  const code = source.replace(/\/\*[\s\S]*?\*\/|^\s*\/\/.*$/gmu, '')
  const names = [...code.matchAll(/export const (EYE_\w*ROUTE) = /gu)].map(match => match[1]).sort()
  const table = code.match(/const routes = new Map\(\[([\s\S]*?)\n  \]\)/u)?.[1]
  assert.ok(table, 'one explicit route table')
  const registrations = table.split('\n').filter(line => line.trim() !== '').map(line => {
    const entry = /^\s*\[(EYE_\w*ROUTE), withPrivacyFence\((\w+)\)\],$/u.exec(line)
    assert.ok(entry, 'every table entry must register through withPrivacyFence')
    return entry
  })
  assert.equal([...code.matchAll(/\broutes\b/gu)].length, 2, 'route table is only constructed and dispatched, never mutated or aliased')
  assert.deepEqual(registrations.map(match => match[1]).sort(), names, 'every route registers through withPrivacyFence')
  assert.deepEqual(registrations.map(match => match[2]).sort(), ['act', 'capture', 'snapshot'])
  assert.match(code, /const route = routes\.get\(path\)/u)
  assert.match(code, /return route\(req, res\)/u)
  assert.doesNotMatch(code, /\b(?:capture|snapshot|act)\s*\(/u, 'route invocation bypasses the dispatcher')
  const calls = text => [...text.matchAll(/\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/gu)]
    .map(match => match[1]).filter(name => !['async', 'if'].includes(name)).sort()
  const dispatcher = code.slice(code.indexOf('  const handler = '), code.indexOf('  const server = '))
  assert.doesNotMatch(dispatcher, /\b(?:deps|window|refs|res|privacy)\s*\./u, 'dispatcher cannot read a window or send route results')
  assert.deepEqual(calls(dispatcher), [
    'drain', 'refuse', 'deny', 'split', 'routes.get', 'deny', 'address', 'namesThisListener', 'say', 'deny',
    'namesThisListener', 'say', 'deny', 'tokenMatches', 'presentedToken', 'say', 'deny', 'route',
  ].sort(), 'dispatcher only authenticates, drains, refuses and invokes a wrapped route')
  const server = code.slice(code.indexOf('  const server = '), code.indexOf('  await new Promise('))
  assert.deepEqual(calls(server), ['createServer', 'handler', 'catch', 'refuse', 'res.end'].sort(),
    'server dispatches only through the inventoried handler')
  assert.equal([...code.matchAll(/\bcreateServer\s*\(/gu)].length, 1, 'no second unfenced receiver')
  const snapshot = code.slice(code.indexOf('  const snapshot = '), code.indexOf('  const act = '))
  assert.match(snapshot, /const snapshotRefs = new Map\(\)/u, 'AX refs are staged until the final fence')
  assert.doesNotMatch(snapshot, /\brefs\.(?:set|clear)\(/u, 'AX route cannot publish refs itself')
  const transport = [
    'for await (const chunk of req) {',
    'try { return await operation() } finally { check() }',
    'await drain(req)',
    'await drain(req)',
    'const result = await route(req, window, privacy)',
    'const deny = async (status, code, detail) => { await drain(req); return refuse(res, status, code, detail) }',
    'await new Promise((resolve, reject) => {',
  ].sort()
  const actual = []
  for (const match of code.matchAll(/\bawait\b/gu)) {
    const tail = code.slice(match.index)
    if (tail.startsWith('await privacy.step(() => ')) continue
    const start = code.lastIndexOf('\n', match.index) + 1
    const end = code.indexOf('\n', match.index)
    actual.push(code.slice(start, end < 0 ? undefined : end).trim())
  }
  assert.deepEqual(actual.sort(), transport, 'awaited screen/window work must use privacy.step with a thunk')
  // A fire-and-forget command or capture would escape both post-await checks.
  assert.equal([...code.matchAll(/\.sendCommand\(/gu)].length,
    [...code.matchAll(/await privacy\.step\(\(\) => dbg\.sendCommand\(/gu)].length)
  assert.equal([...code.matchAll(/\.capturePage\(/gu)].length,
    [...code.matchAll(/await privacy\.step\(\(\) => window\.webContents\.capturePage\(/gu)].length)
}

test('route and awaited-call inventory rejects bypasses and new unfenced reads', t => {
  routeInventory(eyeSource)
  const steps = eyeSource.split('\n').filter(line => line.includes('await privacy.step(() => '))
  assert.equal(steps.length, 12)
  for (const line of steps) {
    const raw = line.replace('await privacy.step(() => ', 'await ').slice(0, -1)
    assert.throws(() => routeInventory(eyeSource.replace(line, raw)), assert.AssertionError)
  }
  for (const route of ['capture', 'snapshot', 'act']) {
    assert.throws(() => routeInventory(eyeSource.replace(`withPrivacyFence(${route})`, route)), assert.AssertionError)
  }
  for (const addition of [
    "export const EYE_TITLE_ROUTE = '/eye/title'",
    "const title = async window => await window.webContents.executeJavaScript('document.title')",
    "const elements = async dbg => await dbg.sendCommand('DOM.getDocument')",
    "const eager = async privacy => await privacy.step(readWindow())",
    "const unfenced = window => window.webContents.capturePage()",
    "routes.set('/eye/title', title)",
    'const extraRoutes = routes',
  ]) assert.throws(() => routeInventory(`${eyeSource}\n${addition}`), assert.AssertionError)
  assert.throws(() => routeInventory(eyeSource.replace('const routes = new Map([', "const routes = new Map([\n    ['/eye/title', title],")), assert.AssertionError)
  for (const addition of [
    "if (path === '/eye/title') return res.end(deps.getWindow().getTitle())",
    "if (path === '/eye/title') title(req, res)",
  ]) assert.throws(() => routeInventory(eyeSource.replace('    const route = routes.get(path)', `${addition}\n    const route = routes.get(path)`)), assert.AssertionError)
  assert.throws(() => routeInventory(eyeSource.replace('return route(req, res)', 'return snapshot(req, res)')), assert.AssertionError)
  assert.throws(() => routeInventory(eyeSource.replace('const snapshotRefs = new Map()', 'const snapshotRefs = refs')), assert.AssertionError)
  assert.throws(() => routeInventory(eyeSource.replace('snapshotRefs.set(ref,', 'refs.set(ref,')), assert.AssertionError)
  t.diagnostic('PASS eye route inventory: 12/12 await bypasses, 3/3 route bypasses, 13/13 additions/dispatch/ref bypasses rejected')
})

test('removing shared checks reproduces AX disclosure or input after a privacy trip', async t => {
  let disclosed = false
  for (const [name, before, after, court] of [
    ['AX post-await discard', 'finally { check() }', 'finally {}', mod => accessibilityRace(t, mod, true)],
    ['input precheck', '        check()\n        try { return await operation()', '        try { return await operation()', mod => beforeAction(t, mod)],
    ['AX fence disabled', "if (code !== null) throw Object.assign(new Error('Private surface changed'), { eyePrivacyCode: code })", '',
      mod => accessibilityRace(t, mod, true, 'approval', false, reply => { disclosed = String(reply.data).includes(privateText) })],
    ['discard prior refs', '    } catch (error) {\n      refs.clear()', '    } catch (error) {', mod => actionRace(t, mod)],
  ]) {
    const mod = await changedModule('eye.mjs', eyeSource, before, after)
    await assert.rejects(() => court(mod), assert.AssertionError, name)
    t.diagnostic(`MUTATION CAUGHT ${name}`)
  }
  assert.equal(disclosed, true, 'disabled fence reproduces reviewer contains_private_text=true')
  t.diagnostic('PASS eye shared fence mutations: 4/4 killed by the same AX/input sequences')
})

function sticky(module = eye) {
  const fence = module.createPrivateSurfaceFence()
  const owner = new Window(), child = new Window()
  fence.privateSurface('approval', () => child, owner)
  child.destroy()
  owner.emit('closed')
  assert.equal(fence.getPrivateSurfaceState().code, 'eye.approval-open', 'logical close/child destruction is not parent paint evidence')
  owner.destroy()
  assert.equal(fence.getPrivateSurfaceState().code, null)
  assert.throws(() => fence.privateSurface('unreviewed', () => {}), { code: 'eye.private-surface-unknown' })
}
test('only confirmed destruction of paint owner clears the latch; unknown surfaces refuse', () => sticky())

async function closedApproval(t, bridge = installApprovalBridge) {
  const f = await drawnFixture(t, bridge)
  class Contents extends EventEmitter {
    isDestroyed() { return this.destroyed === true }
    setWindowOpenHandler() {}
    loadFile() { return Promise.resolve() }
    close() { this.destroyed = true; this.emit('destroyed') }
  }
  class View { constructor() { this.webContents = new Contents() } setBackgroundColor() {} }
  f.installed.dispose()
  const installed = bridge({ applicationOrigin: 'http://127.0.0.1:3187', here: desktop,
    getWindow: () => f.window, getReleaseDir: () => root, getPatchPaths: () => [], headless: true,
    WebContentsView: View, session: { fromPartition: () => ({ setPermissionRequestHandler() {} }) },
    ipcMain: { handle() {}, removeHandler() {}, removeAllListeners() {} } })
  const pending = installed.ask({ challenge: 'synthetic-question', subject: 'synthetic', expiresAt: Math.floor(Date.now() / 1000) + 60,
    operationWitness: { words: 'synthetic approval', wordsDigest: 'a'.repeat(64) } })
  assert.equal(installed.isApprovalOpen(), true)
  installed.close()
  assert.equal(installed.isApprovalOpen(), false)
  assert.equal((await pending).approve, false)
  refused(await f.request(), 'eye.approval-open')
  installed.dispose()
}
test('closed approval view cannot clear pixels retained by the captured parent', closedApproval)

// Inventory includes implicit popups, native presenters and documents; every creation must join the shared latch.
function inventory(files) {
  const text = Object.values(files).join('\n')
  const raw = [...text.matchAll(/new\s+(?:BrowserWindow|WebContentsView)\s*\(/gu)]
  const wrapped = [...text.matchAll(/privateSurface\('[^']+',\s*\(\) => new (?:BrowserWindow|WebContentsView)\s*\(/gu)]
  assert.equal(raw.length, wrapped.length, 'unfenced Electron surface')
  assert.equal([...text.matchAll(/privateSurface\('application'/gu)].length, 1, 'only the reviewed main window is public')
  assert.doesNotMatch(text, /action:\s*['"]allow['"]/u, 'implicit popup bypass')
  const dialogs = [...text.matchAll(/dialog\.show\w+\s*\(/gu)]
  assert.equal(dialogs.length, [...text.matchAll(/privateSurface\('dialog',\s*\(\) => dialog\.show\w+\s*\(/gu)].length)
  const presents = [...text.matchAll(/\b(?:await\s+)?presentOwnerAction\(Object\.freeze/gu)]
  // This reviewed adapter delegates to createOwnerAuthorizationBridge, whose producer is fenced above.
  const delegates = [...text.matchAll(/presentOwnerAction: request => presentOwnerAction\(Object\.freeze/gu)]
  assert.equal(delegates.length, 1)
  assert.equal(presents.length, [...text.matchAll(/privateSurface\('owner',\s*\(\) => presentOwnerAction\(Object\.freeze/gu)].length + delegates.length)
  assert.deepEqual(Object.keys(files).filter(name => name.endsWith('.html')).sort(), ['aumlok-approval.html', 'lane-card.html'])
  const native = [...text.matchAll(/class\s+(\w+)\s*:\s*NSViewController/gu)].map(match => match[1]).sort()
  assert.deepEqual(native, ['OwnerAuthorizationApprovalViewController', 'OwnerKeyApprovalViewController'])
  assert.doesNotMatch(text, /\bNS(?:Window|Panel)\s*\(/u, 'unjoined native window')
  assert.match(files['aumlok-bridge.mjs'], /privateSurface\('bind', \(\) => draw\.draw/u)
  assert.match(files['aumlok-presence.mjs'], /privateSurface\('touchid'/u)
}
const files = Object.fromEntries(readdirSync(desktop, { recursive: true }).filter(name => statSync(join(desktop, name)).isFile())
  .map(name => [name, readFileSync(join(desktop, name), 'utf8')]))
test('all desktop surface creation sites join the shared function', () => {
  inventory(files)
  for (const addition of ['new BrowserWindow({})', 'new WebContentsView({})', "dialog.showMessageBox({})",
    "return { action: 'allow' }", 'presentOwnerAction(Object.freeze({}))', 'class NewApproval: NSViewController {}', 'let w = NSWindow()']) {
    assert.throws(() => inventory({ ...files, 'new-surface.mjs': addition }), assert.AssertionError)
  }
  assert.throws(() => inventory({ ...files, 'new-surface.html': '<input type="password">' }), assert.AssertionError)
})

function diagnostic(text, fence, duringCapture, file) {
  const start = text.indexOf('    const capture = process.env.AUKORA_DESKTOP_CAPTURE')
  const end = text.indexOf("\n  })\n  window.webContents.on('did-fail-load'", start)
  assert.ok(start > 0 && end > start)
  return new Script(`(async () => {${text.slice(start, end)}\n})()`).runInNewContext({
    process: { env: { AUKORA_DESKTOP_CAPTURE: file } }, Number,
    getPrivateSurfaceState: fence.getPrivateSurfaceState, writeFileSync,
    console: { log() {} }, window: { webContents: { capturePage: async () => {
      duringCapture(); return { toPNG: () => pixels }
    } } },
  })
}
async function diagnosticCourt(text = mainSource) {
  const base = join(root, '.runtime'); mkdirSync(base, { recursive: true, mode: 0o700 })
  const scratch = mkdtempSync(join(base, 'eye-diagnostic-'))
  try {
    const fence = eye.createPrivateSurfaceFence(), file = join(scratch, 'capture.png')
    await diagnostic(text, fence, () => {}, file)
    assert.equal(statSync(file).mode & 0o777, 0o600)
    writeFileSync(file, 'existing owner file')
    await assert.rejects(diagnostic(text, fence, () => {}, file), { code: 'EEXIST' })
    assert.equal(readFileSync(file, 'utf8'), 'existing owner file')
    const refusedFile = join(scratch, 'refused.png')
    await diagnostic(text, fence, () => {
      const sheet = new Window(); fence.privateSurface('lane', () => sheet); sheet.destroy()
    }, refusedFile)
    assert.ok(!readdirSync(scratch).includes('refused.png'), 'diagnostic must discard raced private pixels too')
  } finally { rmSync(scratch, { recursive: true, force: true }) }
}
test('diagnostic capture fences generations and writes exclusively at 0600 under umask 002', () => diagnosticCourt())

test('removing each privacy protection makes its regression fail', async t => {
  const mutations = [
    ['bind latch', 'aumlok-bridge.mjs', bridgeSource,
      "privateSurface('bind', () => draw.draw(event.sender, intent, getReleaseDir(), { library, language: payload?.language ?? 'en' }), getWindow())",
      "draw.draw(event.sender, intent, getReleaseDir(), { library, language: payload?.language ?? 'en' })", mod => consumedDraw(t, mod.installApprovalBridge)],
    ['approval latch', 'aumlok-bridge.mjs', bridgeSource,
      "privateSurface('approval', () => new WebContentsView(options), win)", 'new WebContentsView(options)', mod => closedApproval(t, mod.installApprovalBridge)],
    ['generation', 'eye.mjs', eyeSource, 'generation += 1n', '', mod => transient(t, mod)],
    ['request arrival', 'eye.mjs', eyeSource, 'try { return await operation() }',
      'try { const result = await operation(); started = privateState(); return result }', mod => transient(t, mod, 'body')],
    ['final fence', 'eye.mjs', eyeSource, 'const result = await route(req, window, privacy)\n      check()',
      'const result = await route(req, window, privacy)', mod => transient(t, mod, 'encoding')],
    ['discard before encode', 'eye.mjs', eyeSource, 'finally { check() }', 'finally {}', mod => transient(t, mod)],
    ['destruction witness', 'eye.mjs', eyeSource, 'if (owner.isDestroyed?.() === true) visible.delete(id)', 'visible.delete(id)', mod => sticky(mod)],
    ['unknown surface refusal', 'eye.mjs', eyeSource, 'if (!Object.hasOwn(codes, kind))', 'if (false)', mod => sticky(mod)],
    ['capture error redaction', 'eye.mjs', eyeSource, 'return refusal(500, EYE_REFUSE.CAPTURE_FAILED)\n    }\n  }',
      'return refusal(500, EYE_REFUSE.CAPTURE_FAILED, String(error?.message ?? error))\n    }\n  }', mod => failedCapture(t, mod)],
  ]
  for (const [name, file, source, before, after, court] of mutations) {
    // A single shifted arrival read, rather than throwing on the frozen snapshot.
    const prepared = name === 'request arrival' ? source.replace('const started = privateState()', 'let started = privateState()') : source
    const mod = await changedModule(file, prepared, before, after)
    await assert.rejects(async () => court(mod), assert.AssertionError, name)
    t.diagnostic(`MUTATION CAUGHT ${name}`)
  }
  for (const [name, before, after] of [
    ['diagnostic generation', 'current.generation !== started.generation', 'false'],
    ['diagnostic private mode', 'mode: 0o600', 'mode: 0o666'],
    ['diagnostic exclusive write', "flag: 'wx'", "flag: 'w'"],
  ]) {
    const mutant = mainSource.replace(before, after); assert.notEqual(mutant, mainSource)
    await assert.rejects(diagnosticCourt(mutant), assert.AssertionError, name)
    t.diagnostic(`MUTATION CAUGHT ${name}`)
  }
  t.diagnostic('PASS desktop eye privacy mutations: 12/12 killed; surface additions: 8/8 rejected')
})
