// Browser admission runs before route dispatch and reads binding at each request.
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { join } from 'node:path'
import { createAumlokControlService } from '../plugins/aukora-aumlok/lib/service.mjs'
import { bindV3 } from '../plugins/aukora-aumlok/lib/bind-v3.mjs'
import { createAumlokBrowserCeremonyBridge } from '../plugins/aukora-face/aumlok/src/client/binding-bridge.ts'
import * as policy from '../plugins/aukora-action-gate/lib/browser-bootstrap.mjs'
import { generated, rows, root, builder, source as materializerSource } from './helpers/release-composition.mjs'

const reason = 'browser-node:binding-required'
const unavailable = 'browser-node:binding-guard-unavailable'
const policyURL = new URL('../plugins/aukora-action-gate/lib/browser-bootstrap.mjs', import.meta.url)
const policySource = readFileSync(policyURL, 'utf8')
const request = (url, method = 'GET') => ({ url, method, headers: {} })
const reads = ['/api/aukora/theme', '/api/aukora/aura-snapshot', '/api/aukora/aumlok-control', '/api/aukora/aumlok-identity']
const bindings = ['prepare', 'bind', 'cancel', 'status'].map(name => `/api/aukora/aumlok-binding/${name}`)
const staticFiles = ['/', '/favicon.ico', '/assets/main.js', '/plugins/plugin/client.js']

function checkPolicy(api) {
  let bound = false, readCount = 0
  const access = api.createBrowserAccess({ refresh() { readCount++; if (!bound) throw Error('fixture-unbound'); return {} } })
  for (const path of staticFiles) for (const method of ['GET', 'HEAD']) assert.equal(access.requestRejection(request(path, method)), undefined)
  for (const path of reads) assert.equal(access.requestRejection(request(path)), undefined)
  for (const path of bindings) assert.equal(access.requestRejection(request(path, 'POST')), undefined)
  const denied = [request('/api/mux', 'POST'), request('/api/session/create', 'POST'), request('/api/credentials/list'),
    request('/plugins/events'), request('/plugins/events?ignored=1'), request('/plugins/events/child'),
    request('/api/aukora/theme', 'POST'), request('/api/aukora/aura-snapshot', 'HEAD'), request('/api/aukora/aumlok-binding/bind'),
    request('/api/aukora/aumlok-binding/other', 'POST'), request('/assets/main.js', 'POST'), request('/missing'),
    request('/plugins'), request('/assets'), request('/api/aukora/theme/suffix'), request('http://[')]
  for (const req of denied) assert.equal(access.requestRejection(req), reason, `${req.method} ${req.url}`)
  for (const path of [...staticFiles, ...reads, ...bindings, '/api/mux']) assert.equal(access.requestRejection(request(path), true), reason)
  assert.equal(access.requestRejection(request('/api/remote.mux'), true), undefined)
  assert.equal(access.requestRejection(request('/api/remote.mux', 'POST'), true), reason)
  for (const endpoint of api.BOOT_RPC) {
    assert.equal(access.rpcRejection(endpoint), undefined)
    assert.equal(access.requestRejection(request(`/api/${endpoint}`, 'POST')), undefined)
    assert.equal(access.requestRejection(request(`/api/${endpoint}`)), reason)
  }
  for (const endpoint of ['session/create', 'session/prompt', 'session/list', 'session/control', 'session/follow',
    'fileUploads/upload', 'workspaceFiles/list', 'workspaceFiles/read', 'commands/execute',
    'dynamicCordisRunner/syncInspectManifest', '$eventResult', '$events/content', 'credentials/describe/extra', 'unknown/read']) {
    assert.equal(access.rpcRejection(endpoint), reason)
    assert.equal(access.requestRejection(request(`/api/${endpoint}`, 'POST')), reason)
  }
  assert.equal(access.requestRejection(request('/assets/main.js?version=1')), undefined)
  assert.equal(access.requestRejection(request('/api/aukora/theme?version=1')), undefined)
  assert.equal(access.requestRejection(request('/assets/../api/session/create')), reason)
  assert.equal(access.requestRejection(request('/plugins/%2e%2e/api/session/create')), reason)
  assert.equal(readCount > 0, true)
  bound = true
  assert.equal(access.rpcRejection('session/prompt'), undefined)
  for (const req of denied.filter(req => req.url !== 'http://[')) assert.equal(access.requestRejection(req), undefined)
  assert.equal(access.requestRejection(request('/api/mux'), true), undefined)
  bound = false
  assert.equal(access.rpcRejection('session/prompt'), reason)
  assert.equal(access.requestRejection(request('/api/mux', 'POST')), reason, 'binding is re-read after prior admission')
  for (const control of [undefined, {}, { refresh() { throw Error('fixture-private-path') } }]) {
    assert.equal(api.createBrowserAccess(control).requestRejection(request('/api/mux', 'POST')), reason)
  }
  assert.equal(api.name, 'aukora-browser-bootstrap')
  assert.deepEqual(api.inject, ['aumlokControl'])
  let mounted
  api.apply({ aumlokControl: { refresh() { throw Error('unbound') } }, provide(name, value) {
    assert.equal(name, 'aukoraBrowserAccess'); mounted = value
  } })
  assert.equal(typeof mounted?.requestRejection, 'function')
  assert.equal(mounted.requestRejection(request('/api/mux', 'POST')), reason)
}

test('unbound policy admits only bootstrap reads and binding operations; bound requests keep their prior routes', () => {
  checkPolicy(policy)
})

test('the client ceremony can prepare, cancel, inspect and submit through the unbound policy', async () => {
  const access = policy.createBrowserAccess({ refresh() { throw Error('unbound') } }), calls = []
  const words = ['amber', 'birch', 'coral', 'dune', 'elm', 'fern', 'gold']
  const bridge = createAumlokBrowserCeremonyBridge(async (url, init) => {
    assert.equal(access.requestRejection(request(url, init.method)), undefined)
    const verb = url.split('/').at(-1); calls.push(verb)
    return Response.json(verb === 'prepare'
      ? { ok: true, draw: { ceremonyId: 'ceremony_fixture_123', words, language: 'en', entropyBits: 77 } }
      : verb === 'bind' ? { ok: true, binding: {} } : { ok: true })
  }, 'https:')
  assert.equal((await bridge.status()).ok, true)
  assert.equal((await bridge.prepare('bootstrap.fixture')).ok, true)
  assert.equal((await bridge.cancel()).ok, true)
  assert.equal((await bridge.prepare('bootstrap.fixture')).ok, true)
  assert.equal((await bridge.submit('bind', words, 'bootstrap.fixture')).ok, true)
  assert.deepEqual(calls, ['status', 'prepare', 'cancel', 'prepare', 'bind'])
})

test('the actual control reader admits a disposable binding and refuses again when its record disappears', async t => {
  const scratch = mkdtempSync(join(root, '.browser-bootstrap-guard-'))
  t.after(() => rmSync(scratch, { recursive: true, force: true }))
  const directory = join(scratch, 'identity'), access = policy.createBrowserAccess(createAumlokControlService({ directory }))
  const req = request('/api/mux', 'POST')
  assert.equal(access.requestRejection(req), reason)
  await bindV3({ handle: 'bootstrap.fixture', words: ['corals', 'cliff', 'oasis', 'ring', 'amity', 'light', 'summit'],
    directory, boundAt: '2026-10-13T00:00:00Z' })
  assert.equal(access.requestRejection(req), undefined)
  assert.equal(access.requestRejection(req, true), undefined)
  rmSync(join(directory, 'local-control.json'))
  assert.equal(access.requestRejection(req), reason)
})

const pin = JSON.parse(readFileSync(new URL('../upstream-dsh.json', import.meta.url), 'utf8'))
const archive = join(root, 'vendor/dsh-source.tar.gz')
if (!existsSync(archive)) { console.log('UNPERFORMED: pinned harness source archive required'); process.exit(2) }
assert.equal(createHash('sha256').update(readFileSync(archive)).digest('hex'), pin.archiveSha256)
const archiveRoot = execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c',
  "import sys,tarfile\nwith tarfile.open(sys.argv[1], 'r:gz') as tar: print(tar.next().name.split('/')[0])", archive], { encoding: 'utf8' }).trim()
const webserverPath = 'packages/host/webserver/src/index.ts'
const upstream = execFileSync('tar', ['-xOzf', archive, `${archiveRoot}/${webserverPath}`], { encoding: 'utf8' })
const patch = JSON.parse(readFileSync(new URL('../patches/browser-bootstrap-guard.patch.json', import.meta.url), 'utf8'))
let patched = upstream
for (const edit of patch.edits) {
  if (edit.path !== webserverPath) continue
  assert.equal(patched.split(edit.find).length - 1, edit.occurrences, 'patch matches the pinned source exactly')
  patched = patched.replaceAll(edit.find, edit.replace)
}
for (const assertion of patch.expectAfterApply.filter(row => row.path === webserverPath)) assert.ok(patched.includes(assertion.contains))

function webserver(source) {
  let handle
  const listeners = new Map()
  const server = { on(event, callback) { listeners.set(event, callback); return this },
    once(event, callback) { listeners.set(event, callback); return this }, off(event) { listeners.delete(event); return this },
    listen(_port, _host, callback) { callback() }, address() { return { port: 1 } },
    close(callback) { callback() }, closeAllConnections() {} }
  class Service { static init = Symbol('init'); constructor(ctx) { this.ctx = ctx } }
  const schema = new Proxy(() => schema, { get: () => schema })
  const javascript = stripTypeScriptTypes(source, { mode: 'transform' })
    .replace(/^import .*;\n/gmu, '').replace(/^export \{.*;\n/gmu, '')
    .replace('export class WebServer', 'class WebServer').replace('export default WebServer;', '')
  const WebServer = new Function('createServer', 'Service', 'z', 'compressionMiddleware', 'Negotiator', 'renderIndexInjections',
    `${javascript}\nreturn WebServer`)(callback => { handle = callback; return server }, Service, schema,
    () => assert.fail('fixture uses compression none'), undefined, html => html)
  return async ({ enabled = true, access, routes = true } = {}) => {
    const effects = [], forwarded = []
    const ctx = { get(name) { assert.equal(name, 'aukoraBrowserAccess'); return access },
      logger: { warn() {}, error() {} }, effect(create) { effects.push(create()) }, emit() {} }
    const instance = new WebServer(ctx, { host: '127.0.0.1', port: 0, browserAccessGuard: enabled, compression: 'none' })
    if (routes) {
      for (const [kind, path] of [['exact', '/api/mux'], ['prefix', '/api'], ['exact', '/assets/main.js']]) {
        instance.register({ kind, path, handler(req, res) { forwarded.push(req.url); res.writeHead(200); res.end('route') } })
      }
      instance.registerFallback((req, res) => { forwarded.push(req.url); res.writeHead(200); res.end('fallback') })
      instance.registerUpgrade({ path: '/api/mux', handler(req, socket) { forwarded.push(req.url); socket.end('upgraded') } })
      instance.registerUpgrade({ path: '/api/remote.mux', handler(req, socket) { forwarded.push(req.url); socket.end('upgraded') } })
    }
    await instance[Service.init]()
    return { forwarded,
      http(req) {
        return new Promise(resolve => {
          const response = { status: undefined, headers: {}, body: undefined,
            writeHead(status, headers) { this.status = status; this.headers = headers },
            end(body) { this.body = body; resolve(this) }, destroy() { assert.fail('unexpected HTTP destruction') } }
          handle(req, response)
        })
      },
      upgrade(req) {
        let body
        const socket = { on() {}, once() {}, off() {}, end(value) { body = value }, destroy() { body = 'destroyed' } }
        listeners.get('upgrade')(req, socket, Buffer.alloc(0))
        return body
      },
    }
  }
}

async function checkWebserver(source) {
  const create = webserver(source)
  for (const routes of [false, true]) {
    const host = await create({ routes, access: policy.createBrowserAccess({ refresh() { throw Error('unbound') } }) })
    for (const path of ['/api/mux', '/api/workspace/write', '/unknown']) {
      const result = await host.http(request(path, 'POST'))
      assert.equal(result.status, 403)
      assert.equal(result.headers['cache-control'], 'no-store')
      assert.deepEqual(JSON.parse(result.body), { ok: false, reason })
    }
    const responseBody = JSON.stringify({ ok: false, reason })
    assert.equal(host.upgrade(request('/api/mux')), `HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(responseBody)}\r\n\r\n${responseBody}`)
    assert.deepEqual(host.forwarded, [])
  }
  for (const access of [undefined, {}, { requestRejection() { throw Error('fixture-private-path') } },
    ...[null, false, 0, '', {}].map(value => ({ requestRejection() { return value } }))]) {
    const host = await create({ access })
    const result = await host.http(request('/api/mux', 'POST'))
    assert.equal(result.status, 403)
    assert.deepEqual(JSON.parse(result.body), { ok: false, reason: unavailable })
    assert.match(host.upgrade(request('/api/mux')), /browser-node:binding-guard-unavailable/u)
    assert.deepEqual(host.forwarded, [])
  }
  const unbound = await create({ access: policy.createBrowserAccess({ refresh() { throw Error('unbound') } }) })
  assert.equal(unbound.upgrade(request('/api/remote.mux')), 'upgraded')
  for (const endpoint of policy.BOOT_RPC) {
    assert.equal((await unbound.http(request(`/api/${endpoint}`, 'POST'))).status, 200)
  }
  for (const endpoint of ['session/create', 'commands/execute', 'fileUploads/upload', 'workspaceFiles/list',
    'workspaceFiles/read', 'session/follow', 'dynamicCordisRunner/syncInspectManifest']) {
    const result = await unbound.http(request(`/api/${endpoint}`, 'POST'))
    assert.equal(result.status, 403)
    assert.deepEqual(JSON.parse(result.body), { ok: false, reason })
  }
  const bound = await create({ access: policy.createBrowserAccess({ refresh() { return {} } }) })
  assert.equal((await bound.http(request('/api/mux', 'POST'))).status, 200)
  assert.equal(bound.upgrade(request('/api/mux')), 'upgraded')
  const ordinary = await create({ enabled: false })
  assert.equal((await ordinary.http(request('/api/mux', 'POST'))).status, 200)
  assert.equal(ordinary.upgrade(request('/api/mux')), 'upgraded')
}

test('patched pinned WebServer refuses before exact, prefix, fallback and upgrade dispatch, including missing policy', async () => {
  await checkWebserver(patched)
})

function checkComposition(input = materializerSource) {
  for (const browserNode of [false, true]) {
    const emitted = rows(generated(input, { browserNode, includeUpstream: false }).patches['aukora-composition.patch.yml'], 'bootstrap')
    const members = JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c',
      "import sys,json\nns=dict(__file__=sys.argv[1],__name__='bootstrap_policy_test')\nexec(compile(sys.stdin.read(),sys.argv[1],'exec'),ns)\nprint(json.dumps(ns['composition_gate_policy'](browser_node=sys.argv[2]=='true')['pluginSet']))",
      builder, String(browserNode)], { input, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: '/synthetic/home' } }))
    assert.equal(members.includes('aukora-browser-bootstrap'), browserNode)
    const mounted = emitted.find(row => row.id === 'aukora-browser-bootstrap')
    if (browserNode) {
      assert.equal(mounted?.name, './plugins/aukora-action-gate/lib/browser-bootstrap.mjs')
      assert.equal(emitted.find(row => row.id === 'webserver')?.config.browserAccessGuard, true)
      assert.equal(emitted.find(row => row.id === 'typert-gateway')?.config.browserAccessGuard, true)
    } else {
      assert.equal(mounted, undefined)
      assert.notEqual(emitted.find(row => row.id === 'webserver')?.config.browserAccessGuard, true)
      assert.notEqual(emitted.find(row => row.id === 'typert-gateway')?.config.browserAccessGuard, true)
    }
  }
}

test('only browser composition mounts admission, includes policy and opts its web server into the patch', () => {
  checkComposition()
})

test('mutations detect loss of composition mount, required policy and browser-only carrier opt-in', t => {
  const mutations = [
    ['carrier opt-in', "+ '    browserAccessGuard: true\\n'\n            + '- id: typert-gateway", "+ ''\n            + '- id: typert-gateway"],
    ['gateway opt-in', "+ '- id: typert-gateway\\n  config:\\n    browserAccessGuard: true\\n'", "+ ''"],
    ['service mount', "+ '    - id: aukora-browser-bootstrap\\n'\n            + '      name: ./plugins/aukora-action-gate/lib/browser-bootstrap.mjs\\n'", "+ ''"],
    ['required policy', "policy['pluginSet'] = sorted(policy['pluginSet'] + ['aukora-browser-bootstrap'])", 'pass'],
    ['browser-only mount', "def browser_node_rows(browser_node: bool = False, public_origin: str = '') -> str:\n    \"\"\"Disable the pinned shell, file, network and delegation providers.\"\"\"\n    if not browser_node:",
      "def browser_node_rows(browser_node: bool = False, public_origin: str = '') -> str:\n    \"\"\"Disable the pinned shell, file, network and delegation providers.\"\"\"\n    if False:"],
  ]
  for (const [label, before, after] of mutations) {
    assert.equal(materializerSource.split(before).length, 2, `unique mutation anchor: ${label}`)
    assert.throws(() => checkComposition(materializerSource.replace(before, after)), assert.AssertionError, `survived: ${label}`)
  }
  t.diagnostic(`MUTATION browser bootstrap composition: ${mutations.length}/${mutations.length} killed; emitted source rows only`)
})

test('mutations detect removing binding, path, method and stream restrictions', async t => {
  checkPolicy(policy)
  const mutations = [
    ['binding read', 'control.refresh()', 'void control'],
    ['upgrade path', "path === '/api/remote.mux'", 'true'],
    ['upgrade method', "request.method === 'GET' && path ===", 'true && path ==='],
    ['RPC default refusal', 'rpc.has(endpoint) ? undefined : BINDING_REQUIRED', 'undefined'],
    ['RPC HTTP method', "request.method === 'POST' && path.startsWith('/api/')", "path.startsWith('/api/')"],
    ['RPC HTTP allow-list', 'rpc.has(path.slice(5))', 'true'],
    ['static methods', 'if (read &&', 'if (true &&'],
    ['event stream exclusion', "&& path !== '/plugins/events'", ''],
    ['event subtree exclusion', "&& !path.startsWith('/plugins/events/')", ''],
    ['public read method', "request.method === 'GET' && reads.has(path)", 'reads.has(path)'],
    ['binding method', "request.method === 'POST' && binding.has(path)", 'binding.has(path)'],
    ['malformed URL refusal', 'catch { return BINDING_REQUIRED }', 'catch { return undefined }'],
    ['normalized pathname', "new URL(request.url, 'http://node').pathname", 'request.url'],
    ['default refusal', '\n      return BINDING_REQUIRED\n', '\n      return undefined\n'],
    ['service mount', "ctx.provide('aukoraBrowserAccess', createBrowserAccess(ctx.aumlokControl))", 'void ctx'],
  ]
  for (const [label, before, after] of mutations) {
    assert.equal(policySource.split(before).length, 2, `unique mutation anchor: ${label}`)
    const mutant = await import(`data:text/javascript;base64,${Buffer.from(policySource.replace(before, after)).toString('base64')}#${encodeURIComponent(label)}`)
    assert.throws(() => checkPolicy(mutant), assert.AssertionError, `survived: ${label}`)
  }
  const cached = policySource.replace('export function createBrowserAccess(control) {', 'export function createBrowserAccess(control) { let cached = false')
    .replace('control.refresh()', 'if (!cached) control.refresh(); cached = true')
  const mutant = await import(`data:text/javascript;base64,${Buffer.from(cached).toString('base64')}#cache`)
  assert.throws(() => checkPolicy(mutant), assert.AssertionError, 'survived: cached binding')
  t.diagnostic(`MUTATION browser bootstrap policy: ${mutations.length + 1}/${mutations.length + 1} killed; synthetic binding, no owner custody`)
})

test('mutations detect removing HTTP, upgrade and policy availability refusals', async t => {
  await checkWebserver(patched)
  const mutations = [
    ['HTTP admission', 'const reason = this.browserRequestRejection(req, false)', 'const reason = undefined'],
    ['upgrade admission', 'const reason = this.browserRequestRejection(req, true)', 'const reason = undefined'],
    ['missing service', "if (guard === undefined) return 'browser-node:binding-guard-unavailable'", 'if (guard === undefined) return undefined'],
    ['invalid result', ": 'browser-node:binding-guard-unavailable'", ': undefined'],
    ['service exception', "} catch {\n      return 'browser-node:binding-guard-unavailable'", '} catch {\n      return undefined'],
    ['profile opt-in', 'if (this.config.browserAccessGuard !== true) return undefined', 'if (false) return undefined'],
    ['HTTP no-store', "'cache-control': 'no-store'", "'cache-control': 'public'"],
    ['upgrade no-store', 'Cache-Control: no-store\\r\\n', ''],
    ['upgrade framing', 'HTTP/1.1 403 Forbidden\\r\\n', 'HTTP/1.1 403 Forbidden\\\\r\\\\n'],
    ['upgrade body length', 'String(Buffer.byteLength(body))', "'0'"],
  ]
  for (const [label, before, after] of mutations) {
    assert.equal(patched.split(before).length, 2, `unique mutation anchor: ${label}`)
    await assert.rejects(() => checkWebserver(patched.replace(before, after)), assert.AssertionError, `survived: ${label}`)
  }
  t.diagnostic(`MUTATION browser HTTP carrier: ${mutations.length}/${mutations.length} killed; no socket listener or installed runtime`)
})
