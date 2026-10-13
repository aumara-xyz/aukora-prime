// SPDX-License-Identifier: AGPL-3.0-or-later
// Derive bootstrap calls from pinned client source and activate the binding dependency chain.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import vm from 'node:vm'
import { BOOT_RPC, BINDING_REQUIRED, createBrowserAccess } from '../plugins/aukora-action-gate/lib/browser-bootstrap.mjs'

const root = resolve(import.meta.dirname, '..')
const archive = join(root, 'vendor/dsh-source.tar.gz')
const harness = [process.env.AUKORA_PINNED_DSH, join(root, 'vendor/dsh'), join(homedir(), 'aukora-genesis/vendor/dsh')]
  .filter(Boolean).find(path => existsSync(join(path, 'vendor/cordis/lib/index.js')))
if (!existsSync(archive) || !harness) { console.log('UNPERFORMED: pinned harness archive and built Cordis/TypeScript required'); process.exit(2) }
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
assert.equal(sha(readFileSync(archive)), JSON.parse(readFileSync(join(root, 'upstream-dsh.json'))).archiveSha256)
const prefix = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }).split('\n')[0]
const sources = new Map()
function source(path) {
  if (!sources.has(path)) {
    const bytes = execFileSync('tar', ['-xOf', archive, `${prefix}${path}`], { maxBuffer: 8 * 1024 * 1024 })
    assert.equal(sha(readFileSync(join(harness, path))), sha(bytes), `read-only extracted source matches pin: ${path}`)
    sources.set(path, bytes.toString())
  }
  return sources.get(path)
}
const at = (path, expression) => {
  const text = source(path), found = text.match(expression)
  assert.ok(found, `reviewed boot call remains in ${path}`)
  return found[1]
}
const boot = () => [
  at('packages/api/gateway/src/stream-protocol.ts', /REMOTE_EVENT_STREAM_ENDPOINT = '([^']+)'/u),
  `credentials/${at('packages/client/ui-settings-plugins/src/client/web-search-card-controller.ts', /this\.ctx\.remote\.credentials\.(\w+)\(\[ref\]\)/u)}`,
  `agentPresets/${at('packages/client/ui-agent-preset/src/client/settings-store.ts', /ctx\.remote\.agentPresets\.(\w+)\(\)/u)}`,
  `session/${at('packages/client/ui-model-selection/src/client/catalog.ts', /this\.ctx\.remote\.session\.(\w+)\(\)/u)}`,
  `permissionPresets/${at('packages/client/ui-permission-presets/src/client/catalog.ts', /this\.ctx\.remote\.permissionPresets\.(\w+)\(\)/u)}`,
]
const unbound = createBrowserAccess({ refresh() { throw Error('aumlok-local:directory-malformed') } })

test('source-derived read-only boot methods are exactly the permitted bootstrap list', t => {
  assert.deepEqual(boot().sort(), [...BOOT_RPC].sort())
  for (const method of boot()) assert.equal(unbound.rpcRejection(method), undefined, method)
  assert.match(source('packages/api/settings-controller/src/credentials.ts'), /projectCredentialInfo\(await credentials\.describe\(key\)\)/u)
  assert.match(source('packages/preset/agent-presets/src/index.ts'), /presets: presets\.map\(preset => \(\{/u)
  assert.match(source('packages/api/session-controller/src/catalog.ts'), /without requiring a Session/u)
  assert.match(source('packages/interaction/permission-presets/src/index.ts'), /return \{ options: this\.names\.map\(name => this\.optionOf\(name\)\) \}/u)
  t.diagnostic('PASS boot calls: $events, credentials/describe, agentPresets/list, session/modelCatalog, permissionPresets/catalog accepted; archive and cited source bytes verified')
})

test('eager writes and private reads are optional to plugin activation and refused', t => {
  const denied = [
    `dynamicCordisRunner/${at('packages/extensions/cordis-client-runner/src/client/index.ts', /ctx\.remote\.dynamicCordisRunner\.(\w+)\(providers\)/u)}`,
    `session/${at('packages/api/session-controller/src/client/transport.ts', /remote\.session\.(\w+)\(signal\)/u)}`,
    `session/${at('packages/api/session-controller/src/client/sessions/manager.ts', /this\.remote\.session\.(\w+)\(\{\}\)/u)}`,
    `workspace/${at('packages/api/workspace-controller/src/client/index.ts', /remote\.workspace\.(\w+)\(signal\)/u)}`,
    `dynamicCordisRunner/${at('packages/extensions/ui-cordis/src/client/index.ts', /ctx\.remote\.dynamicCordisRunner\.(\w+)\(\)/u)}`,
  ]
  for (const method of denied) assert.equal(unbound.rpcRejection(method), BINDING_REQUIRED, method)
  assert.match(source('packages/extensions/cordis-client-runner/src/client/inspect-registry.ts'), /this\.syncChain = this\.syncChain\.then[^]*?\.catch\(/u)
  assert.match(source('packages/api/session-controller/src/client/index.ts'), /export function apply[^]*?new ClientSessions[^]*?control\.start\(\)/u)
  assert.match(source('packages/extensions/ui-cordis/src/client/index.ts'), /inventory\.refresh\(\)\s*\n\}/u)
  assert.match(source('packages/extensions/ui-cordis/src/client/inventory.ts'), /inFlight = port\.inventory\(\)\.then\([^]*?onError\(error\)[^]*?error: error instanceof Error/u)
  assert.match(source('packages/extensions/cordis-host-runner/src/index.ts'), /agentId: plugin\.sessionId[^]*?purpose: definition\.purpose/u)
  assert.match(source('packages/api/session-controller/src/control.ts'), /message: \{ id: message\.id, content: message\.content/u)
  assert.match(source('packages/client/ui-settings/src/client/index.ts'), /\$host\.isLoopback \? 'host' : 'memory'/u)
  assert.match(source('packages/client/ui-settings/src/client/settings-mirror.ts'), /if \(this\.persistence === 'memory'\) return Promise\.resolve\(\)/u)
  assert.match(readFileSync(join(root, 'plugins/aukora-face/settings/src/client/SettingsOnboarding.tsx'), 'utf8'), /state\.phase !== 'ready'/u)
  assert.match(readFileSync(join(root, 'plugins/aukora-face/threads/src/client/navigation.ts'), 'utf8'), /workspace\.phase !== 'ready' \|\| sessions\.phase !== 'ready'\) return/u)
  t.diagnostic('PASS eager optional calls: syncInspectManifest write and session/control, session/list, workspace/follow, dynamicCordisRunner/inventory private reads refused; public settings describe skipped')
})

const requireHarness = createRequire(join(harness, 'packages/client/ui-renderer/package.json'))
const ts = requireHarness('typescript')
const { JSDOM } = createRequire(join(harness, 'package.json'))('jsdom')
const requireUi = createRequire(join(harness, 'packages/client/ui-primitives/package.json'))
const requireRuntime = createRequire(join(harness, 'packages/api/session-controller/package.json'))
const { Context } = createRequire(join(harness, 'package.json'))(join(harness, 'vendor/cordis/lib/index.js'))
function clientLoader(extra = {}) {
  const cache = new Map(), consoleErrors = [], sandbox = vm.createContext({
    console: { ...console, error(...args) { consoleErrors.push(args) } },
    URL, URLSearchParams, Headers, Response, Request, AbortController, AbortSignal,
    Buffer, setTimeout, clearTimeout, queueMicrotask, TextEncoder, TextDecoder,
    location: { hostname: 'node.example.test', protocol: 'https:' }, ...extra,
  })
  function load(path) {
    const absolute = path.startsWith('plugins/') ? join(root, path) : join(harness, path)
    if (cache.has(absolute)) return cache.get(absolute)
    const exports = {}; cache.set(absolute, exports)
    const text = path.startsWith('plugins/') ? readFileSync(absolute, 'utf8') : source(path)
    const requireHere = createRequire(absolute)
    function imported(specifier) {
      if (specifier === '#jsqr') return () => null
      if (specifier.endsWith('.css?inline')) return { __esModule: true, default: '' }
      if (specifier.includes('.css')) return { __esModule: true, default: new Proxy({}, { get: (_, name) => name }) }
      if (specifier === '@deepseek-ai/cordis') return { ...createRequire(join(harness, 'package.json'))(join(harness, 'vendor/cordis/lib/index.js')) }
      if (specifier === '@deepseek-ai/cordis-plugin-loader') return createRequire(join(harness, 'package.json'))(join(harness, 'vendor/loader/lib/index.js'))
      if (specifier === '@deepseek-ai/dsh-client-ui-primitives') return new Proxy({}, { get: (_, name) => name === '__esModule' ? true : String(name) })
      const faceSource = specifier.match(/^@aukora\/face-([^/]+)\/(src\/.+)$/u)
      if (faceSource) return load(`plugins/aukora-face/${faceSource[1]}/${faceSource[2]}`)
      if (specifier === '@aukora/face-layout/client') return load('plugins/aukora-face/layout/src/client/index.ts')
      if (specifier.startsWith('.')) {
        const next = resolve(dirname(absolute), specifier)
        // The harness may live inside the repository (vendor/dsh): test the harness prefix first.
        return load(next.startsWith(harness + '/') ? next.slice(harness.length + 1) : next.slice(root.length + 1))
      }
      if (specifier.startsWith('@deepseek-ai/') && specifier.endsWith('/client')) {
        const built = requireHere.resolve(specifier), dir = dirname(dirname(built))
        const file = [join(dir, 'src/client/index.ts'), join(dir, 'src/client.ts')].find(existsSync)
        assert.ok(file, `pinned client source entry for ${specifier}`)
        return load(file.slice(harness.length + 1))
      }
      try { return requireHere(specifier) } catch {
        try { return requireRuntime(specifier) } catch {
          try { return requireUi(specifier) } catch { return requireHarness(specifier) }
        }
      }
    }
    const output = ts.transpileModule(text, { compilerOptions: { module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText
    vm.compileFunction(output, ['exports', 'require'], { parsingContext: sandbox, filename: path })(exports, imported)
    return exports
  }
  return { load, consoleErrors, realm: sandbox }
}

async function criticalBoot({ fileUpload = true } = {}) {
  const status = '/api/aukora/aumlok-control', calls = []; let releaseStatus
  const dom = new JSDOM('<!doctype html><html><head></head><body></body></html>', { url: 'https://node.example.test' })
  const statusReady = new Promise(resolve => { releaseStatus = resolve })
  const { load, consoleErrors, realm } = clientLoader({ document: dom.window.document, window: dom.window, navigator: dom.window.navigator, getComputedStyle: dom.window.getComputedStyle, fetch: async url => {
    calls.push(url); assert.equal(url, status); await statusReady
    return { status: 200, headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => vm.runInContext("({ status: 'not-connected', reason: 'control-unreadable', code: 'aumlok-local:directory-malformed' })", realm) }
  } })
  const connection = load('packages/client/connection/src/client/index.ts')
  const gateway = load('packages/api/gateway/src/client/index.ts')
  const bootClient = load('packages/client/web/src/boot-client.ts').bootClient
  const stream = async function* (_prefix, endpoint, _payload, signal) {
    calls.push(endpoint)
    if (endpoint !== '$events') throw Error(unbound.rpcRejection(endpoint))
    yield vm.runInContext("({ type: 'ready', clientId: 'bootstrap-fixture', host: { home: '/bootstrap' } })", realm)
    await new Promise(resolve => { if (signal.aborted) resolve(); else signal.addEventListener('abort', resolve, { once: true }) })
  }
  const ctx = new Context()
  ctx.provide('typert', { contexts: { registerClient() {} } })
  const namespace = name => new Proxy({}, { get: (_, method) => method === 'then' ? undefined : () => {
    const endpoint = `${name}/${method}`
    calls.push(endpoint)
    if (['control', 'follow'].includes(method)) return stream('/api', endpoint)
    return Promise.resolve(unbound.rpcRejection(endpoint) === undefined
      ? { ok: true, value: endpoint === 'session/modelCatalog' ? { default: { provider: 'fixture', model: 'fixture' }, groups: [], routableProviders: [], failures: [] }
          : endpoint === 'agentPresets/list' ? { presets: [], authorable: false, modeSelectionEnabled: false }
          : endpoint === 'permissionPresets/catalog' ? { options: [] } : {} }
      : { ok: false, error: { code: BINDING_REQUIRED, message: BINDING_REQUIRED, details: {} } })
  } })
  const modules = new Map([
    ['fixture-carrier', { apply(scope) { connection.installConnection(scope, { location: { hostname: 'node.example.test' },
      transport: { rpc: { call: async () => ({ ok: true, value: null }), open: stream } } });
      for (const ns of ['commands', 'session', 'subagents', 'settings', 'credentials', 'agentPresets', 'permissionPresets']) scope.provide(`remote.${ns}`, namespace(ns))
    } }],
    ['gateway', gateway],
    ['slots', load('packages/client/ui-renderer/src/client/index.ts')],
    ['settings', load('packages/client/ui-settings/src/client/index.ts')],
    ['locale', load('packages/client/locale/src/client/index.ts')],
    ['theme', load('packages/client/ui-theme/src/client/index.ts')],
    ['sessions', load('packages/api/session-controller/src/client/index.ts')],
    ['model-catalog', { inject: ['sessions', 'remote', 'remote.session'], apply(scope) {
      return scope.plugin(load('packages/client/ui-model-selection/src/client/service.ts').ModelDirectoryResolver, { blockReason: () => 'fixture' })
    } }],
    ['permission-catalog', { inject: ['connection', 'remote', 'remote.permissionPresets'], apply(scope) {
      const directory = new (load('packages/client/ui-permission-presets/src/client/catalog.ts').PermissionCatalogDirectory)(scope)
      scope.effect(() => () => directory.dispose())
    } }],
    ['web-search-credential', load('packages/client/ui-settings-plugins/src/client/index.ts')],
    ['agent-preset', load('packages/client/ui-agent-preset/src/client/index.ts')],
    ['ui-session', load('packages/client/ui-session/src/client/index.ts')],
    ['layout', load('plugins/aukora-face/layout/src/client/index.ts')],
    ['aumlok', load('plugins/aukora-face/aumlok/src/client/index.ts')],
  ])
  if (fileUpload) modules.set('file-upload', load('packages/client/file-upload/src/client/index.ts'))
  for (const [id, module] of modules) {
    const apply = module.apply
    if (typeof apply !== 'function') continue
    module.apply = function(...args) { try { return apply(...args) } catch (error) { consoleErrors.push([id, error.stack]); throw error } }
  }
  const manifest = { plugins: [...modules.keys()].map(id => ({ id })) }
  try {
    await bootClient({ ctx, manifest, modules: { import: async name => modules.get(name) } })
    const entry = ctx.get('slots').entries('root')[0]
    const layoutStore = entry.store.create()
    entry.inject(layoutStore.actions)
    releaseStatus()
    for (let turn = 0; turn < 30; turn++) await Promise.resolve()
    assert.equal(ctx.get('connection').isLoopback, false)
    assert.equal(ctx.get('sessions').list.getSnapshot().phase, 'pending')
    assert.ok(calls.includes(status))
    for (const method of boot()) assert.ok(calls.includes(method), `own client boot calls ${method}`)
    assert.equal(layoutStore.getSnapshot().activeSurface, 'aumlok')
    assert.equal(ctx.get('connection').state.getSnapshot(), 'connected')
    return { ctx, consoleErrors }
  } catch (error) { await ctx.fiber.dispose(); throw new Error(error.message + '\n' + consoleErrors.map(args => args.map(String).join(' ')).join('\n'), { cause: error }) }
}

test('real Cordis activation preserves upload/session chain and opens binding from unbound status', async t => {
  const booted = await criticalBoot()
  await booted.ctx.fiber.dispose()
  t.diagnostic('PASS source client activation: fileUpload -> sessions -> layout; unbound status opens Aumlok; no listener or browser')
})

test('mutations reject missing core service and missing allow-list member', async t => {
  await assert.rejects(criticalBoot({ fileUpload: false }), /pending \(waiting for service: fileUpload\)/u)
  for (const removed of boot()) {
    const original = readFileSync(join(root, 'plugins/aukora-action-gate/lib/browser-bootstrap.mjs'), 'utf8')
    const changed = original.replace(`'${removed}',`, '')
    assert.notEqual(changed, original)
    const mutated = await import(`data:text/javascript;base64,${Buffer.from(changed).toString('base64')}`)
    const access = mutated.createBrowserAccess({ refresh() { throw Error('unbound') } })
    assert.throws(() => { for (const method of boot()) assert.equal(access.rpcRejection(method), undefined, method) })
  }
  t.diagnostic('PASS mutation: removing file-upload reproduces pending session/layout activation; removing each of 5 boot permissions fails completeness')
})
