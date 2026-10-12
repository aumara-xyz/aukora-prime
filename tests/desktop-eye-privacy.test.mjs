// SPDX-License-Identifier: AGPL-3.0-or-later
// Captures discard private pixels across draw consumption, body I/O, capture and encoding.
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import { syncBuiltinESMExports } from 'node:module'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { Script } from 'node:vm'
import test, { after } from 'node:test'
import * as eye from '../apps/aukora-desktop/eye.mjs'
import { installApprovalBridge } from '../apps/aukora-desktop/aumlok-bridge.mjs'
import { APPROVAL_CHANNELS } from '../apps/aukora-desktop/aumlok-bridge-state.mjs'

const previousUmask = process.umask(0o002)
after(() => process.umask(previousUmask))

const root = fileURLToPath(new URL('..', import.meta.url))
const desktop = join(root, 'apps/aukora-desktop')
const eyeSource = readFileSync(join(desktop, 'eye.mjs'), 'utf8')
const bridgeSource = readFileSync(join(desktop, 'aumlok-bridge.mjs'), 'utf8')
const mainSource = readFileSync(join(desktop, 'main.mjs'), 'utf8')
const pixels = Buffer.from('synthetic private pixels')
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
  let duringCapture = () => {}, duringEncoding = () => {}
  window.webContents.capturePage = async () => {
    captures++; await duringCapture()
    return { getSize: () => ({ width: 1, height: 1 }), toPNG() { encodings++; duringEncoding(); return pixels } }
  }
  const logs = []
  const door = await module.installEyeDoor({ getWindow: () => window, getPrivateSurfaceState: state, log: line => logs.push(line) })
  t.after(() => door.dispose())
  return {
    window, logs, counts: () => ({ captures, encodings }),
    duringCapture: fn => { duringCapture = fn }, duringEncoding: fn => { duringEncoding = fn },
    request(body = Readable.from([Buffer.from('{}')]), authorization = `Bearer ${door.token}`) {
      Object.assign(body, { method: 'POST', url: '/eye/capture', headers: { host: '127.0.0.1:12345', authorization } })
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
  if (phase !== 'encoding') assert.equal(f.counts().encodings, 0, 'private pixels discarded before encoding')
  assert.ok(f.logs.every(line => !line.includes(pixels.toString())))
}

for (const phase of ['body', 'capture', 'encoding']) {
  test(`private surface opens and closes during ${phase}: generation refuses`, t => transient(t, eye, phase))
}

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
    ['request arrival', 'eye.mjs', eyeSource, '    const rect = parseRect(read.body.rect)', '    started = privateState()\n    const rect = parseRect(read.body.rect)', mod => transient(t, mod, 'body')],
    ['final fence', 'eye.mjs', eyeSource, 'if (finalCode !== null) return refuse(res, 423, finalCode)', '', mod => transient(t, mod, 'encoding')],
    ['discard before encode', 'eye.mjs', eyeSource, 'if (privateCode !== null) return refuse(res, 423, privateCode)', '', mod => transient(t, mod)],
    ['destruction witness', 'eye.mjs', eyeSource, 'if (owner.isDestroyed?.() === true) visible.delete(id)', 'visible.delete(id)', mod => sticky(mod)],
    ['unknown surface refusal', 'eye.mjs', eyeSource, 'if (!Object.hasOwn(codes, kind))', 'if (false)', mod => sticky(mod)],
    ['capture error redaction', 'eye.mjs', eyeSource, 'return refuse(res, 500, EYE_REFUSE.CAPTURE_FAILED)\n    }\n  }',
      'return refuse(res, 500, EYE_REFUSE.CAPTURE_FAILED, String(error?.message ?? error))\n    }\n  }', mod => failedCapture(t, mod)],
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
