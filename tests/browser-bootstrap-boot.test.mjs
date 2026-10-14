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
import { generated, source as materializer, sourcePath } from './helpers/release-composition.mjs'
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

test('pinned onboarding rows and supported suppression seams remain explicit', t => {
  const composition = source('packages/bundle/web-app/cordis.patch.yml')
  assert.match(composition, /- id: ui-settings-models\s+name: '@deepseek-ai\/dsh-client-ui-settings-models'/u)
  assert.match(composition, /- id: ui-brand-official\s+name: '@deepseek-ai\/dsh-client-ui-brand-official'/u)
  const models = source('packages/client/ui-settings-models/src/client/index.ts')
  assert.match(models, /id: 'welcome-notice',[\s\S]*?id: 'deepseek-official'/u)
  assert.match(models, /export function apply\(ctx: ClientContext\): void/u)
  const copy = source('packages/client/ui-settings-models/src/onboarding-copy.ts')
  assert.match(copy, /WELCOME_NOTICE_ACK_FIELD = 'welcomeNoticeVersion'/u)
  assert.match(copy, /WELCOME_NOTICE_VERSION = '2026-08-13\.1'/u)
  assert.match(source('packages/client/ui-settings-models/src/client/welcome-store.ts'),
    /scope\.value\?\.\[WELCOME_NOTICE_ACK_FIELD\] === WELCOME_NOTICE_VERSION/u)
  assert.match(source('packages/client/ui-settings/src/client/index.ts'),
    /ctx\.remote\.\$host\.isLoopback \? 'host' : 'memory'/u)
  const readiness = source('packages/client/ui-settings-models/src/client/store.ts')
  for (const fact of ['provider-ready', 'adapter-absent', 'provider-inactive', 'credentials-unavailable',
    'settings-read-only', 'credential-read-only', 'credential-missing']) assert.match(readiness, new RegExp(`'${fact}'`, 'u'))
  const brand = source('packages/client/ui-brand-official/src/client/index.ts')
  assert.match(brand, /process\.env\.DSH_CLIENT_BUILD_PROFILE !== 'official'/u)
  assert.match(brand, /sidebar\.brand\.mark[\s\S]*sidebar\.brand\.name/u)
  assert.equal(brand.includes('settings.models'), false)
  assert.match(source('packages/client/locale/src/client/index.ts'),
    /locale namespace "\$\{ns\}" already has locale/u)
  t.diagnostic('PASS pinned onboarding evidence: rows, persisted welcome version, public-memory scope, readiness exits, brand and locale limits; archive and read-only source bytes verified')
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

function compositionRows(input) {
  const entries = new Map()
  for (const patch of [source('packages/bundle/base/cordis.patch.yml'), source('packages/bundle/web-app/cordis.patch.yml'),
    generated(input, { browserNode: true, includeUpstream: false }).patches['aukora-composition.patch.yml']]) {
    let row, indent
    for (const line of patch.split('\n')) {
      const id = /^(\s*)- id: ([\w-]+)\s*$/u.exec(line)
      if (id) { indent = id[1].length; row = entries.get(id[2]) ?? { id: id[2] }; entries.set(row.id, row); continue }
      const field = /^(\s*)(name|disabled): (.+)$/u.exec(line)
      if (!row || !field || field[1].length !== indent + 2) continue
      row[field[2]] = field[2] === 'disabled' ? field[3] === 'true' : field[3].replace(/^(['"])(.*)\1$/u, '$2')
    }
  }
  return [...entries.values()]
}

const pinnedDeclarations = JSON.parse(execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', `
import hashlib, json, sys, tarfile
with tarfile.open(sys.argv[1], 'r:gz') as tar:
    result = dict(packages={}, sources={})
    for entry in tar.getmembers():
        path = entry.name.partition('/')[2]
        if entry.isfile() and path.endswith('/package.json'):
            data = tar.extractfile(entry).read(); value = json.loads(data)
            if isinstance(value.get('name'), str): result['packages'][value['name']] = dict(path=path, value=value, sha256=hashlib.sha256(data).hexdigest())
        elif entry.isfile() and path.endswith('.ts') and '/src/' in path and ('/' not in path.partition('/src/')[2] or path.endswith('/src/client/index.ts')):
            result['sources'][path] = tar.extractfile(entry).read().decode('utf-8')
    print(json.dumps(result))
`, archive], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }))
const packageDeclarations = pinnedDeclarations.packages
const localPackages = new Map()

const rowDeclarations = new Map()
function rowDeclaration(row) {
  if (rowDeclarations.has(row.name)) return rowDeclarations.get(row.name)
  const local = row.name.replace(/^\.\//u, '').replace(/^\/synthetic\/release\//u, '')
  const name = Object.keys(packageDeclarations).find(name => row.name === name || row.name?.startsWith(name + '/')
    || local.startsWith(dirname(packageDeclarations[name].path) + '/'))
  if (!name) {
    const path = sourcePath(row.name), text = row.id === 'aukora-browser-refusal'
      ? materializer.match(/BROWSER_REFUSAL_SOURCE = '''([^]*?)'''/u)[1] : readFileSync(path, 'utf8')
    const declaration = /(?:export const inject|exports\.inject)\s*=\s*(?:Object\.freeze\()?\[([^\]]*)\]/u.exec(text)
    const packagePath = join(dirname(dirname(path)), 'package.json')
    const metadata = existsSync(packagePath) ? JSON.parse(readFileSync(packagePath, 'utf8')) : undefined
    if (metadata?.name) localPackages.set(metadata.name, { path: packagePath, value: metadata, local: true })
    return { inject: [...(declaration?.[1] ?? '').matchAll(/['"]([^'"]+)['"]/gu)].map(match => match[1]),
      provides: [...text.matchAll(/\.provide\(\s*['"]([^'"]+)['"]/gu)].map(match => match[1]),
      client: metadata?.dsh?.client && { name: metadata.name, ...metadata.dsh.client, local: true } }
  }
  const declaration = packageDeclarations[name]
  assert.equal(sha(readFileSync(join(harness, declaration.path))), declaration.sha256)
  const directory = dirname(declaration.path), subpath = local.startsWith(directory + '/')
    ? '/' + local.slice((directory + '/lib/').length).replace(/\.js$/u, '') : row.name.slice(name.length) || '/index'
  const path = `${directory}/src${subpath}.ts`
  const text = pinnedDeclarations.sources[path]
  assert.equal(typeof text, 'string', `pinned host source: ${path}`)
  // Inspect declarations only: application bodies, sockets and deployment state are not run.
  const exported = declaration.value.exports?.[subpath === '/index' ? '.' : '.' + subpath]
  const builtPath = typeof exported === 'string' ? exported : exported?.default ?? declaration.value.main
  const built = createRequire(join(harness, 'package.json'))(join(harness, directory, builtPath))
  const plugin = built.default ?? built
  const inject = plugin.inject ?? built.inject ?? []
  const required = Array.isArray(inject) ? inject : Object.keys(inject)
  const provides = [...text.matchAll(/(?:super\(ctx,|\.provide\()\s*['"]([^'"]+)['"]/gu)].map(match => match[1])
  const result = { inject: required, provides, client: declaration.value.dsh?.client && { name, ...declaration.value.dsh.client } }
  rowDeclarations.set(row.name, result)
  return result
}

async function profileDeclarationBoot(input = materializer) {
  const rows = compositionRows(input).filter(row => row.name)
  const declared = rows.map(row => ({ row, ...rowDeclaration(row) }))
  const active = declared.filter(({ row }) => !row.disabled)
  const activeProvides = new Set(active.flatMap(entry => entry.provides))
  const absent = new Set(declared.filter(({ row }) => row.disabled).flatMap(entry => entry.provides).filter(name => !activeProvides.has(name)))
  assert.ok(absent.has('workspaceFiles'), 'disabled pinned provider declares workspaceFiles')
  const modules = new Map(), ctx = new Context()
  // Other service bodies are fixture carriers. Disabled providers stay absent, as on the browser node.
  for (const service of new Set(active.flatMap(entry => entry.inject))) {
    if (service !== 'loader' && !absent.has(service) && ctx.get(service) === undefined) ctx.provide(service, {})
  }
  for (const entry of active) modules.set(entry.row.id, { inject: entry.inject, apply() {} })
  const clients = active.filter(entry => entry.client?.platform === 'web').map(entry => entry.client)
  for (const client of clients) {
    for (const specifier of [...client.inject ?? [], ...client.external ?? []]) {
      const name = specifier.replace(/\/client$/u, '')
      const declaration = packageDeclarations[name] ?? localPackages.get(name)
      assert.ok(declaration, `pinned client dependency has a package declaration: ${name}`)
      if (!declaration.local) assert.equal(sha(readFileSync(join(harness, declaration.path))), declaration.sha256)
    }
    const directory = dirname((packageDeclarations[client.name] ?? localPackages.get(client.name)).path)
    const clientPath = [`${directory}/src/client/index.ts`, `${directory}/src/client.ts`, ...(client.local ? [`${directory}/lib/client.js`] : [])]
      .find(path => existsSync(client.local ? path : join(harness, path)))
    assert.ok(clientPath, `pinned client source exists: ${client.name}`)
    const text = client.local ? readFileSync(clientPath, 'utf8') : pinnedDeclarations.sources[clientPath]
    if (!client.local) assert.equal(sha(readFileSync(join(harness, clientPath))), sha(text))
    const declaration = /(?:export const inject|exports\.inject)\s*=\s*\[([^\]]*)\]/u.exec(text)
    const inject = [...(declaration?.[1] ?? '').matchAll(/['"]([^'"]+)['"]/gu)].map(match => match[1])
    for (const service of inject) if (service !== 'loader' && !absent.has(service) && ctx.get(service) === undefined) ctx.provide(service, {})
    modules.set(client.name, { inject, apply() {} })
  }
  const { load } = clientLoader()
  try {
    await load('packages/client/web/src/boot-client.ts').bootClient({ ctx,
      manifest: { plugins: [...modules.keys()].map(id => ({ id })) }, modules: { import: async name => modules.get(name) } })
    return { host: active.length, client: clients.length }
  } finally { await ctx.fiber.dispose() }
}

test('browser composition declaration boot has zero entries that did not activate', async t => {
  const result = await profileDeclarationBoot()
  const guard = "'ui-sidebar-terminal', 'ui-deliverables',"
  assert.equal(materializer.split(guard).length, 2)
  await assert.rejects(profileDeclarationBoot(materializer.replace(guard, "'ui-sidebar-terminal',")),
    /ui-deliverables: pending \(waiting for service: workspaceFiles\)/u)
  t.diagnostic(`PASS browser composition declaration boot: ${result.host} host and ${result.client} client entries; zero did not activate`)
  t.diagnostic('MUTATION browser deliverables dependency: 1/1 killed; restoring ui-deliverables waits for disabled workspaceFiles')
})
