// SPDX-License-Identifier: AGPL-3.0-or-later
// Load compiled faces with absent host files and serve only release-carried app bytes.
import test, { after } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as promises from 'node:fs/promises'
import { dirname, join, matchesGlob, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import vm from 'node:vm'

if (vm.SourceTextModule === undefined) {
  const again = spawnSync(process.execPath, ['--experimental-vm-modules', ...process.execArgv, ...process.argv.slice(1)], { stdio: 'inherit', timeout: 20_000 })
  process.exit(again.status ?? 1)
}

const root = fileURLToPath(new URL('../', import.meta.url))
const facesRoot = join(root, 'plugins/aukora-face')
const faces = fs.readdirSync(facesRoot).filter(face => fs.existsSync(join(facesRoot, face, 'src/index.ts'))).sort()
const fixture = fs.mkdtempSync(join(root, '.face-plugins-load-'))
fs.chmodSync(fixture, 0o700)
after(() => fs.rmSync(fixture, { recursive: true, force: true }))
const materializer = join(root, 'scripts/materialize-aukora-release.py')
const source = fs.readFileSync(materializer, 'utf8')
const strip = JSON.parse(fs.readFileSync(join(root, 'scripts/artifacts-coverage.json'), 'utf8')).strip
let unperformed = false

// Execute the materializer's face-copy statements, without building or copying a harness.
const carriedFaces = JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import ast, json, sys
from pathlib import Path
path, target = sys.argv[1:]
source = sys.stdin.read()
ns = dict(__file__=path, __name__='face_copy_fixture')
exec(compile(source, path, 'exec'), ns)
main = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == 'main')
loop = next(node for node in main.body if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
            and node.target.id == 'face' and isinstance(node.iter, ast.Name) and node.iter.id == 'FACE_PACKAGES')
body = []
for node in loop.body:
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'runtime_deps' for target in node.targets):
        break
    body.append(node)
loop.body = body
ns['target'] = Path(target)
ns['face_builds'] = {face: json.loads((ns['FACE'] / face / 'lib/.build-inputs.json').read_text()) for face in ns['FACE_PACKAGES']}
exec(compile(ast.fix_missing_locations(ast.Module(body=[loop], type_ignores=[])), path, 'exec'), ns)
print(json.dumps(ns['FACE_PACKAGES']))
`, materializer, fixture], { input: source, encoding: 'utf8', timeout: 15_000, env: { PATH: process.env.PATH, HOME: fixture } }))

function absent(path) {
  return Object.assign(new Error(`ENOENT: optional host file absent: ${String(path)}`), { code: 'ENOENT' })
}

function inside(path) {
  const file = path instanceof URL ? fileURLToPath(path) : String(path)
  const suffix = relative(fixture, resolve(file))
  return suffix === '' || (suffix !== '..' && !suffix.startsWith(`..${sep}`))
}

function hostFilesystem(namespace, async) {
  const out = { ...namespace }
  const operations = async
    ? ['access', 'appendFile', 'chmod', 'lstat', 'mkdir', 'open', 'readFile', 'readdir', 'realpath', 'rm', 'stat', 'writeFile']
    : ['accessSync', 'appendFileSync', 'chmodSync', 'lstatSync', 'mkdirSync', 'openSync', 'readFileSync', 'readdirSync', 'realpathSync', 'rmSync', 'statSync', 'statfsSync', 'writeFileSync']
  for (const name of operations) {
    out[name] = async ? async (path, ...args) => {
      if (!inside(path)) throw absent(path)
      return namespace[name](path, ...args)
    } : (path, ...args) => {
      if (!inside(path)) throw absent(path)
      return namespace[name](path, ...args)
    }
  }
  out.existsSync = path => inside(path) && fs.existsSync(path)
  out.default = out
  return out
}

// Schema shims expose defaults and declaration chaining; provider behavior is not exercised.
function schema(value) {
  const result = { value, parse: input => input, safeParse: input => ({ success: true, data: input }) }
  for (const name of ['min', 'max', 'role', 'description', 'nullable', 'optional', 'int', 'nonnegative', 'finite', 'regex', 'passthrough', 'strict']) result[name] = () => result
  result.default = next => { result.value = next; return result }
  return result
}
const schemas = {
  string: () => schema(''), boolean: () => schema(false), natural: () => schema(0), number: () => schema(0),
  array: () => schema([]), enum: values => schema(values[0]), literal: value => schema(value),
  union: values => schema(values[0].value),
  object: shape => schema(Object.fromEntries(Object.entries(shape).map(([key, child]) => [key, child.value]))),
}

function recorder() {
  const routes = [], upgrades = [], logs = [], stdout = [], cleanups = [], registrations = [], pending = []
  const noop = () => undefined
  const register = value => { registrations.push(value); return noop }
  const ctx = {
    logger: { info: message => logs.push(String(message)), warn: message => logs.push(String(message)) },
    connection: { requestRejection: () => undefined },
    credentials: { get: () => undefined }, sessions: { get: () => undefined, list: () => [] },
    subprocess: { spawn: () => assert.fail('face-load: an absent voice installation must not spawn') },
    webServer: {
      host: '127.0.0.1', register(route) { routes.push(route); return noop },
      registerUpgrade(route) { upgrades.push(route); return noop },
    },
    sessionProjections: { register }, commands: { register }, settings: { register },
    sandboxPolicy: { defaultMode: 'read-only' },
    get(name) { return this[name] }, emit: noop, on: noop,
    inject(names, callback) {
      if (!names.every(name => this[name] !== undefined)) return noop
      const result = callback(this)
      if (result?.then) pending.push(result)
      return noop
    },
    effect(callback) { const cleanup = callback(); if (typeof cleanup === 'function') cleanups.push(cleanup); return noop },
  }
  return { ctx, routes, upgrades, logs, stdout, async settle() { await Promise.all(pending) }, async close() { for (const cleanup of cleanups.reverse()) await cleanup() } }
}

async function mount(face, platform, replacement) {
  const file = join(fixture, `plugins/aukora-face-${face}/lib/index.js`)
  assert.ok(fs.existsSync(file), `face-load:compiled-face-not-carried:${face}`)
  const recorded = recorder()
  const syntheticProcess = {
    platform, env: { HOME: join(fixture, 'absent-home'), PATH: '' }, cwd: () => join(fixture, 'absent-workspace'),
    memoryUsage: () => process.memoryUsage(), uptime: () => 0, version: process.version, versions: process.versions,
  }
  const context = vm.createContext({
    process: syntheticProcess, Buffer, URL, TextDecoder, TextEncoder, AbortController, AbortSignal,
    fetch: () => assert.fail('face-load: plugin load must not send a provider or network request'),
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
    console: { log: message => recorded.stdout.push(String(message)), warn: message => recorded.stdout.push(String(message)), error: message => recorded.stdout.push(String(message)) },
  })
  class WebSocketServer {
    clients = new Set()
    close(done) { done() }
  }
  const explicit = {
    '@deepseek-ai/schemastery': { default: schemas }, zod: { z: schemas },
    '@deepseek-ai/dsh-credentials': { credentialRef: value => value },
    '@deepseek-ai/dsh-session': { SessionId: value => value },
    '@deepseek-ai/dsh-session-query': { extractSessionEventText: () => '' },
    '@deepseek-ai/dsh-commands/brand': { CommandDefinitionId: value => value },
    '@deepseek-ai/dsh-sandbox-policy': { setSandboxMode: () => assert.fail('face-load: mode must not change during load') },
    '@deepseek-ai/dsh-sandbox': { requiredConfinement: () => assert.fail('face-load: confinement must not run during load') },
    '@deepseek-ai/dsh-host-frontend-static': {
      async serveStatic(path, res, directory) {
        const file = resolve(directory, `.${path}`)
        assert.ok(inside(file), 'face-load:static-file-outside-release')
        try { const bytes = await promises.readFile(file); res.writeHead(200); res.end(bytes) }
        catch (cause) { if (cause.code !== 'ENOENT') throw cause; res.writeHead(404); res.end() }
      },
    },
    ws: { default: class WebSocket {}, WebSocketServer },
    'node:fs': hostFilesystem(fs, false), 'node:fs/promises': hostFilesystem(promises, true),
    'node:process': { ...syntheticProcess, default: syntheticProcess },
    'node:child_process': {
      execFile(_command, _args, options, callback) {
        const done = typeof options === 'function' ? options : callback
        queueMicrotask(() => done(absent('optional executable'), '', ''))
        return { kill() {} }
      },
    },
  }
  const modules = new Map()
  async function external(specifier) {
    if (modules.has(specifier)) return modules.get(specifier)
    let values = explicit[specifier]
    if (values === undefined && specifier === 'node:os') {
      values = { ...await import(specifier), homedir: () => syntheticProcess.env.HOME }
      values.default = values
    }
    if (values === undefined && specifier.startsWith('node:')) values = await import(specifier)
    if (values === undefined) throw Object.assign(new Error(`UNPERFORMED: ${face} needs an unsupported harness export: ${specifier}`), { code: 'FACE_LOAD_UNPERFORMED' })
    const names = Object.keys(values)
    const module = new vm.SyntheticModule(names, function () { for (const name of names) this.setExport(name, values[name]) }, { context })
    modules.set(specifier, module)
    await module.link(() => assert.fail('face-load: unexpected shim import'))
    await module.evaluate()
    return module
  }
  const bundle = new vm.SourceTextModule(replacement ?? fs.readFileSync(file, 'utf8'), {
    context, identifier: file,
    initializeImportMeta(meta) { meta.url = pathToFileURL(file).href; meta.dirname = dirname(file) },
    importModuleDynamically: external,
  })
  try {
    await bundle.link(external)
    await bundle.evaluate()
    assert.equal(typeof bundle.namespace.apply, 'function', `face-load:apply-absent:${face}`)
    const config = bundle.namespace.Config?.value ?? {}
    await bundle.namespace.apply(recorded.ctx, config)
    await recorded.settle()
    return recorded
  } catch (cause) {
    await recorded.close()
    throw cause
  }
}

const appRoutes = [
  ['prefix', '/app'], ['exact', '/assets/aumara-icon-96.png'], ['exact', '/branding/aumara-icon-96.png'],
  ['exact', '/stock-apps/auma-lingwa.html'], ['exact', '/stock-apps/auma-live.html'],
  ['prefix', '/stock-apps/zeta-harp'], ['prefix', '/stock-apps/human-graph'], ['prefix', '/stock-apps/dakini-code'],
  ...['chat/recent', 'field-degraded', 'minds', 'status', 'presence/stream'].map(path => ['exact', `/api/auma-live/${path}`]),
]

function checkRoutes(recorded) {
  for (const [kind, path] of appRoutes) assert.ok(recorded.routes.some(route => route.kind === kind && route.path === path), `face-load:route-absent:${path}`)
}

function files(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory()
    ? files(join(directory, entry.name)).map(file => `${entry.name}/${file}`) : [entry.name])
}

function appFiles() {
  const app = join(facesRoot, 'apps')
  const rows = [
    ['/assets/aumara-icon-96.png', 'vendor/auma-lingwa/runtime/assets/aumara-icon-96.png'],
    ['/branding/aumara-icon-96.png', 'vendor/auma-lingwa/runtime/assets/aumara-icon-96.png'],
    ['/stock-apps/auma-lingwa.html', 'vendor/auma-lingwa/runtime/auma-lingwa.html'],
    ['/stock-apps/auma-live.html', 'vendor/auma-live/runtime/auma-live.html'],
  ]
  for (const [prefix, tree] of [
    ['/app', 'vendor/auma-lingwa/runtime/app'], ['/app', 'vendor/auma-live/runtime/app'],
    ['/stock-apps/zeta-harp', 'vendor/zeta-harp'], ['/stock-apps/dakini-code', 'vendor/dakini-code'],
    ['/stock-apps/human-graph', 'assets/human-graph'],
  ]) for (const file of files(join(app, tree)).filter(file => !file.endsWith('.d.ts'))) rows.push([`${prefix}/${file}`, `${tree}/${file}`])
  for (const file of ['three.module.min.js', 'three.core.min.js']) rows.push([`/stock-apps/human-graph/three/${file}`, `vendor/three/${file}`])
  return rows
}

async function response(recorded, url) {
  const route = recorded.routes.find(route => route.kind === 'exact' && route.path === url)
    ?? recorded.routes.find(route => route.kind === 'prefix' && url.startsWith(`${route.path}/`))
  assert.ok(route, `face-load:route-absent:${url}`)
  const result = { statusCode: 200, body: Buffer.alloc(0), headers: {},
    setHeader(name, value) { this.headers[name] = value },
    writeHead(status, headers = {}) { this.statusCode = status; Object.assign(this.headers, headers) },
    end(body) { this.body = body === undefined ? Buffer.alloc(0) : Buffer.from(body) },
  }
  await route.handler({ method: 'GET', url, headers: { host: '127.0.0.1' }, socket: { remoteAddress: '127.0.0.1' } }, result)
  return result
}

async function checkAssets(recorded) {
  for (const [url, file] of appFiles()) {
    const carried = `plugins/aukora-face-apps/${file}`
    assert.ok(fs.existsSync(join(fixture, carried)), `face-load:asset-not-carried:${file}`)
    assert.ok(!strip.patterns.some(pattern => matchesGlob(carried, pattern)) || strip.keep.some(pattern => matchesGlob(carried, pattern)), `face-load:asset-stripped:${file}`)
    const result = await response(recorded, url)
    assert.equal(result.statusCode, 200, `face-load:asset-not-served:${url}`)
    let expected = fs.readFileSync(join(facesRoot, 'apps', file))
    if (url === '/app/auma/auma.js') expected = Buffer.from(expected.toString().replace('const isUnlocked = (day, s) => day === 1 || !!s.done[day - 1] || !!s.done[day];', 'const isUnlocked = () => true;'))
    assert.deepEqual(result.body, expected, `face-load:wrong-asset:${url}`)
  }
}

async function checkVoice(recorded) {
  for (const endpoint of ['minds', 'status']) {
    const result = await response(recorded, `/api/auma-live/${endpoint}`)
    assert.equal(result.statusCode, 200, `face-load:voice-status-response:${endpoint}`)
    assert.deepEqual(JSON.parse(result.body).voice, {
      available: false, code: 'voice-pin-unavailable', message: 'voice not installed on this node',
    }, `face-load:voice-status-unavailable:${endpoint}`)
  }
  for (const lines of [recorded.logs, recorded.stdout]) {
    const warnings = lines.filter(line => line.includes('voice not installed on this node'))
    assert.equal(warnings.length, 1, 'face-load:voice-log-once')
    assert.ok(warnings[0].includes('/etc/aukora/auma-live-voice/environment.sha256'), 'face-load:voice-log-names-missing-pin')
  }
  assert.equal(recorded.logs.filter(line => line.includes('repo-lens-unavailable')).length, 1, 'face-load:repo-log-once')
  const upgrade = recorded.upgrades.find(route => route.path === '/stock-apps/auma-live/voice')
  assert.ok(upgrade, 'face-load:voice-upgrade-absent')
  let reply = ''
  upgrade.handler({ url: '/stock-apps/auma-live/voice', headers: { host: '127.0.0.1' }, socket: { remoteAddress: '127.0.0.1' } }, { end(body) { reply = body } }, Buffer.alloc(0))
  assert.match(reply, /^HTTP\/1\.1 503 Service Unavailable\r\n/u, 'face-load:voice-upgrade-unavailable')
  assert.ok(reply.endsWith('voice not installed on this node'), 'face-load:voice-upgrade-status')
}

function pageVoice(text) {
  const start = text.indexOf('  function applyRoster(data) {')
  const end = text.indexOf('  function buildMinds()', start)
  assert.ok(start >= 0 && end > start, 'face-load:page-roster-anchor')
  const voiceAvailability = { textContent: '' }, notices = [], requests = [], timers = new Map()
  let now = 0, nextTimer = 0
  const cleanupStart = text.indexOf('  activeCleanup = () => {')
  const cleanupEnd = text.indexOf('    home.stop();', cleanupStart)
  assert.ok(cleanupStart >= 0 && cleanupEnd > cleanupStart, 'face-load:page-cleanup-anchor')
  const dispose = text.slice(cleanupStart, cleanupEnd).replace('activeCleanup =', 'const dispose =') + '\n  };'
  const runtime = vm.runInNewContext(`let closed = false, voiceStatusAbort = null;\n${text.slice(start, end)}\n${dispose}\n({ apply: applyRoster, refresh: refreshVoiceAvailability, dispose, closeOnly() { closed = true } })`, {
    voiceAvailability, renderProviderSetup() {}, toast: message => notices.push(message), AbortController,
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { at: now + delay, callback }); return id },
    clearTimeout(id) { timers.delete(id) },
    fetch(url, init) {
      const request = { url, init }; requests.push(request)
      return new Promise((resolve, reject) => {
        request.reply = (voice, ok = true) => resolve({ ok, json: async () => ({ voice }) })
        request.fail = () => reject(new Error('synthetic status read failure'))
      })
    },
  })
  return { ...runtime, voiceAvailability, notices, requests, timers,
    advance(ms) {
      now += ms
      for (const [id, timer] of timers) if (timer.at <= now) { timers.delete(id); timer.callback() }
    },
  }
}

function checkPageVoice(text) {
  const page = pageVoice(text)
  page.apply({ minds: [], voice: { available: false } })
  assert.equal(page.voiceAvailability.textContent, 'voice not installed on this node', 'face-load:page-voice-status')
  assert.deepEqual(page.notices, ['voice not installed on this node'], 'face-load:page-voice-notice')
  page.apply({ minds: [], voice: { available: true } })
  assert.equal(page.voiceAvailability.textContent, '', 'face-load:page-voice-status-cleared')
}

async function checkPageRefresh(text) {
  const missing = 'voice not installed on this node'
  const page = pageVoice(text)
  let run = page.refresh()
  void page.refresh()
  assert.equal(page.requests.length, 1, 'face-load:status-request-dedup')
  const request = page.requests[0]
  assert.equal(request.url, '/api/auma-live/status', 'face-load:status-endpoint')
  assert.equal(request.init.cache, 'no-store', 'face-load:status-uncached')
  assert.equal(request.init.credentials, 'same-origin', 'face-load:status-credentials')
  request.reply({ available: false }); await run
  assert.equal(page.voiceAvailability.textContent, missing, 'face-load:late-voice-unavailable')
  assert.equal(page.timers.size, 0, 'face-load:status-timer-cleanup')
  run = page.refresh()
  assert.equal(page.requests.length, 2, 'face-load:status-pending-cleared')
  page.requests[1].fail(); await run
  assert.equal(page.voiceAvailability.textContent, missing, 'face-load:failed-status-retained')
  run = page.refresh()
  assert.equal(page.requests.length, 3, 'face-load:status-retry-after-failure')
  page.requests[2].reply({ available: true }, false); await run
  assert.equal(page.voiceAvailability.textContent, missing, 'face-load:non-success-status-retained')
  run = page.refresh()
  assert.equal(page.requests.length, 4, 'face-load:status-retry-after-refusal')
  page.requests[3].reply({ available: true }); await run
  assert.equal(page.voiceAvailability.textContent, '', 'face-load:late-voice-recovered')

  const expired = pageVoice(text)
  expired.apply({ minds: [], voice: { available: false } })
  run = expired.refresh()
  expired.advance(2999)
  assert.equal(expired.requests[0].init.signal.aborted, false, 'face-load:status-deadline-not-early')
  expired.advance(1)
  assert.equal(expired.requests[0].init.signal.aborted, true, 'face-load:status-deadline')
  expired.requests[0].reply({ available: true }); await run
  assert.equal(expired.voiceAvailability.textContent, missing, 'face-load:aborted-status-ignored')

  const disposed = pageVoice(text)
  disposed.apply({ minds: [], voice: { available: false } })
  run = disposed.refresh(); disposed.dispose()
  assert.equal(disposed.requests[0].init.signal.aborted, true, 'face-load:status-disposal-abort')
  disposed.requests[0].reply({ available: true }); await run
  assert.equal(disposed.voiceAvailability.textContent, missing, 'face-load:disposed-status-ignored')
  const afterDisposal = disposed.refresh()
  assert.equal(disposed.requests.length, 1, 'face-load:closed-page-no-status-request')
  await afterDisposal

  const closed = pageVoice(text)
  closed.apply({ minds: [], voice: { available: false } })
  run = closed.refresh(); closed.closeOnly()
  closed.requests[0].reply({ available: true }); await run
  assert.equal(closed.voiceAvailability.textContent, missing, 'face-load:closed-status-ignored')
}

function checkPageTriggers(text) {
  const start = text.indexOf('    ws.onclose = (event) => {')
  const end = text.indexOf('\n  },\n  enable(owner)', start)
  assert.ok(start >= 0 && end > start, 'face-load:socket-close-anchor')
  const emitted = [], ws = {}, owner = { ws, ready: true, emit: name => emitted.push(name), retry() {} }
  const close = vm.runInNewContext(`(function () { ${text.slice(start, end)}\nreturn ws.onclose }).call(owner)`, { ws, owner, clearTimeout() {} })
  close({ code: 1006 })
  assert.ok(emitted.includes('status'), 'face-load:socket-close-refresh-trigger')
  const listener = text.match(/\s+status\(\) \{[^\n]+\},/u)?.[0]
  assert.ok(listener, 'face-load:voice-status-listener-anchor')
  let refreshed = 0
  vm.runInNewContext(`({ ${listener} }).status()`, { refreshVoiceAvailability() { refreshed++ } })
  assert.equal(refreshed, 1, 'face-load:voice-status-refresh-trigger')
  const panelStart = text.indexOf('  function togglePanel(force) {')
  const panelEnd = text.indexOf('  gear.addEventListener', panelStart)
  assert.ok(panelStart >= 0 && panelEnd > panelStart, 'face-load:panel-toggle-anchor')
  const toggle = vm.runInNewContext(`let panelOpen = false; ${text.slice(panelStart, panelEnd)}\ntogglePanel`, {
    home: { start() {} }, panel: { classList: { toggle() {} } }, gear: { classList: { toggle() {} } },
    refreshVoiceAvailability() { refreshed++ },
  })
  toggle(true)
  assert.equal(refreshed, 2, 'face-load:panel-open-refresh-trigger')
  toggle(false)
  assert.equal(refreshed, 2, 'face-load:panel-close-no-refresh')
  assert.match(text, /ready\(\) \{\s+renderVoiceAvailability\(\{ available: true \}\);/u, 'face-load:voice-ready-clears-status')
}

test('the release carries every compiled face', () => {
  assert.deepEqual([...carriedFaces].sort(), faces, 'face-load:release-face-set')
})
for (const platform of ['linux', 'darwin']) for (const face of faces) test(`compiled ${face} applies on ${platform} with optional host files absent`, async t => {
  try {
    const recorded = await mount(face, platform)
    await recorded.close()
  } catch (cause) {
    if (cause.code !== 'FACE_LOAD_UNPERFORMED') throw cause
    unperformed = true
    t.skip(cause.message)
  }
})

test('compiled apps register every stock route and serve all static files from the carried release tree', async t => {
  const recorded = await mount('apps', 'linux')
  try {
    checkRoutes(recorded)
    await checkAssets(recorded)
    await checkVoice(recorded)
    t.diagnostic(`${appRoutes.length} required routes and ${appFiles().length} carried static responses checked`)
  } finally { await recorded.close() }
})

test('the carried Auma Live page displays missing voice before an empty roster, then clears it', () => {
  checkPageVoice(fs.readFileSync(join(fixture, 'plugins/aukora-face-apps/vendor/auma-live/runtime/app/aumalive.js'), 'utf8'))
})

test('late voice status reads are bounded, deduplicated, cancelled and triggered by socket close and panel open', { timeout: 5000 }, async () => {
  const page = fs.readFileSync(join(fixture, 'plugins/aukora-face-apps/vendor/auma-live/runtime/app/aumalive.js'), 'utf8')
  await checkPageRefresh(page)
  checkPageTriggers(page)
})

test('load-time host lstat, repo throw, removed route, carried asset and voice status mutants are detected', async () => {
  const bundle = fs.readFileSync(join(fixture, 'plugins/aukora-face-apps/lib/index.js'), 'utf8')
  const loadAnchor = 'async function apply(ctx, config) {'
  assert.equal(bundle.split(loadAnchor).length - 1, 1, 'face-load:lstat-mutation-anchor')
  await assert.rejects(mount('apps', 'linux', bundle.replace(loadAnchor, `${loadAnchor}\n lstatSync('/etc/aukora/auma-live-voice/environment.sha256');`)), /ENOENT: optional host file absent/u)
  const repoAnchor = 'ctx.logger.warn("ui-stock-apps: repo-lens-unavailable:'
  assert.equal(bundle.split(repoAnchor).length - 1, 1, 'face-load:repo-mutation-anchor')
  await assert.rejects(mount('apps', 'linux', bundle.replace(repoAnchor, `throw new Error('repo-lens-unavailable');\n${repoAnchor}`)), /repo-lens-unavailable/u)
  const routeAnchor = 'path: "/stock-apps/auma-lingwa.html"'
  assert.equal(bundle.split(routeAnchor).length - 1, 1, 'face-load:route-mutation-anchor')
  const removed = await mount('apps', 'linux', bundle.replace(routeAnchor, 'path: "/removed-lingwa-route"'))
  try { assert.throws(() => checkRoutes(removed), /face-load:route-absent:/u) }
  finally { await removed.close() }
  const recorded = await mount('apps', 'linux')
  const asset = join(fixture, 'plugins/aukora-face-apps/vendor/auma-lingwa/runtime/assets/aumara-icon-96.png')
  const bytes = fs.readFileSync(asset)
  try {
    fs.rmSync(asset)
    await assert.rejects(checkAssets(recorded), /face-load:asset-not-carried:/u)
  } finally { fs.writeFileSync(asset, bytes); await recorded.close() }
  const upgradeAnchor = 'if (voiceStatus().available === false) {'
  assert.equal(bundle.split(upgradeAnchor).length - 1, 1, 'face-load:voice-upgrade-mutation-anchor')
  const unguarded = await mount('apps', 'linux', bundle.replace(upgradeAnchor, 'if (false) {'))
  try { await assert.rejects(checkVoice(unguarded), /face-load:voice-upgrade-unavailable/u) }
  finally { await unguarded.close() }
  const statusAnchor = 'voice: this.dependencies.voiceStatus?.()'
  assert.equal(bundle.split(statusAnchor).length - 1, 2, 'face-load:voice-status-mutation-anchor')
  const undisclosed = await mount('apps', 'linux', bundle.replace(statusAnchor, 'voice: undefined'))
  try { await assert.rejects(checkVoice(undisclosed), /face-load:voice-status-unavailable/u) }
  finally { await undisclosed.close() }
  const page = fs.readFileSync(join(fixture, 'plugins/aukora-face-apps/vendor/auma-live/runtime/app/aumalive.js'), 'utf8')
  const pageAnchor = 'voiceAvailability.textContent = status?.available === false'
  assert.equal(page.split(pageAnchor).length - 1, 1, 'face-load:page-voice-mutation-anchor')
  assert.throws(() => checkPageVoice(page.replace(pageAnchor, 'voiceAvailability.textContent = false')), /face-load:page-voice-status/u)
  console.log('MUTATION face-plugins-load: 7/7 killed')
})

test('late voice status refresh and trigger protections reject mutations', { timeout: 5000 }, async () => {
  const page = fs.readFileSync(join(fixture, 'plugins/aukora-face-apps/vendor/auma-live/runtime/app/aumalive.js'), 'utf8')
  const mutations = [
    ['request dedup', 'closed || voiceStatusAbort', 'closed'],
    ['closed page', 'closed || voiceStatusAbort', 'voiceStatusAbort'],
    ['deadline', 'controller.abort(), 3000', 'controller.abort(), 30000'],
    ['HTTP success', 'if (!response.ok) return;', 'if (false) return;'],
    ['aborted response', '!closed && !controller.signal.aborted', '!closed'],
    ['closed response', '!closed && !controller.signal.aborted', '!controller.signal.aborted'],
    ['retain failed read', '} catch { /* Retain the last observed availability', '} catch { renderVoiceAvailability({ available: true }); /* Retain the last observed availability'],
    ['release pending request', 'clearTimeout(timeout); voiceStatusAbort = null;', 'clearTimeout(timeout);'],
    ['timer cleanup', 'finally { clearTimeout(timeout);', 'finally {'],
    ['uncached read', "cache: 'no-store', credentials: 'same-origin'", "cache: 'default', credentials: 'same-origin'"],
    ['same-origin read', "cache: 'no-store', credentials: 'same-origin'", "cache: 'no-store', credentials: 'omit'"],
    ['cleanup abort', 'voiceStatusAbort?.abort();', 'void 0;'],
  ]
  for (const [label, before, after] of mutations) {
    assert.ok(page.includes(before), `face-load:status-mutation-anchor:${label}`)
    await assert.rejects(checkPageRefresh(page.replace(before, after)), assert.AssertionError, `surviving status mutant: ${label}`)
  }
  const triggers = [
    ["this.emit('status');", 'void 0;'],
    ['status() { void refreshVoiceAvailability(); },', 'status() { void 0; },'],
    ['if (panelOpen) void refreshVoiceAvailability();', 'void 0;'],
    ['ready() {\n      renderVoiceAvailability({ available: true });', 'ready() {'],
  ]
  for (const [before, after] of triggers) {
    assert.ok(page.includes(before), `face-load:trigger-mutation-anchor:${before}`)
    assert.throws(() => checkPageTriggers(page.replace(before, after)), assert.AssertionError)
  }
  console.log(`MUTATION face-voice-status-refresh: ${mutations.length + triggers.length}/${mutations.length + triggers.length} killed`)
})

after(() => { if (unperformed) process.exitCode = 2 })
