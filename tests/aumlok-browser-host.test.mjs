// SPDX-License-Identifier: AGPL-3.0-or-later
// Mounted browser routes authenticate before loading first-binding code or public records.
import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs'
import { createRequire, stripTypeScriptTypes } from 'node:module'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { runInNewContext } from 'node:vm'
import * as control from '../plugins/aukora-face/aumlok/src/control-projection.ts'
import * as identity from '../plugins/aukora-face/aumlok/src/identity.ts'
import { loadLocalAumlokPublicControl } from '../plugins/aukora-aumlok/lib/store.mjs'
import { resolveMemoryIdentity } from '../plugins/aukora-kira/lib/memory-identity.mjs'

const root = fileURLToPath(new URL('..', import.meta.url))
const indexUrl = new URL('../plugins/aukora-face/aumlok/src/index.ts', import.meta.url)
const source = readFileSync(indexUrl, 'utf8')
const transportSource = source.split('// Browser binding transport.\n')[1]?.split('// End browser binding transport.')[0]
assert.ok(transportSource, 'browser host transport fragment missing')
const helpers = await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(transportSource)).toString('base64')}`)
const publicOrigin = 'https://node.example.test'
const bindingPrefix = helpers.BROWSER_BINDING_PREFIX
function compiler() {
  for (const directory of [process.env.AUKORA_PINNED_DSH, join(root, 'vendor/dsh'),
    join(homedir(), 'aukora-genesis/vendor/dsh')].filter(Boolean)) {
    try { return createRequire(join(directory, 'package.json'))('typescript') } catch {}
  }
  // The pinned harness build is fetched, not tracked; without it this file is unperformed (exit 2), not failed.
  console.log('UNPERFORMED: aumlok-browser-host needs the pinned harness build for its TypeScript')
  process.exit(2)
}
const ts = compiler()

function mounted(fixture, options = {}) {
  const routes = new Map(), imports = [], reads = [], effects = [], exports = {}
  let auth = undefined
  const base = options.flat ? fixture.flatBase : indexUrl.href
  const javascript = ts.transpileModule((options.source ?? source).replaceAll('import.meta.url', JSON.stringify(base)), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: false },
  }).outputText
  runInNewContext(javascript, { exports, URL, TextDecoder, TextEncoder,
    require(specifier) {
      if (specifier.startsWith('file:')) { imports.push(specifier); return import(specifier) }
      if (specifier === './control-projection.ts') return control
      if (specifier === './identity.ts') return identity
      if (specifier === './identity-host.ts') return {
        async readIdentity(directory) { reads.push(directory); return { subject: loadLocalAumlokPublicControl(directory).projection.subject } },
        identityContactIssueRoute: () => ({ kind: 'exact', path: identity.IDENTITY_CONTACT_ENDPOINT, handler() {} }),
      }
      if (specifier === './contact-verification.ts') return {
        identityContactVerificationRoute: () => ({ kind: 'exact', path: identity.IDENTITY_VERIFY_CONTACT_ENDPOINT, handler() {} }),
      }
      throw Error(`unexpected host import ${specifier}`)
    } }, { filename: fileURLToPath(indexUrl) })
  const ctx = { webServer: { host: '127.0.0.1', register(route) {
    assert.equal(routes.has(route.path), false, 'duplicate route'); routes.set(route.path, route)
    return () => routes.delete(route.path)
  } }, connection: { requestRejection() { return auth } },
    get(name) { assert.equal(name, 'aumlokControl'); return options.controller },
    effect(callback, label) { const cleanup = callback(); effects.push({ label, cleanup }); return cleanup },
  }
  exports.apply(ctx, options.config ?? fixture.config)
  return { imports, reads, routes, effects, setAuth(value) { auth = value },
    async request(path, options = {}) {
      const route = routes.get(path); assert.ok(route, `mounted route absent: ${path}`)
      let bodyRead = 0, complete
      const completed = new Promise(resolve => { complete = resolve })
      const response = { status: undefined, headers: {}, body: undefined,
        setHeader(name, value) { this.headers[name] = value },
        writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers) },
        end(body) { this.body = body === undefined ? undefined : JSON.parse(body); complete() },
      }
      const req = { method: options.method ?? (path.startsWith(bindingPrefix) ? 'POST' : 'GET'), url: options.url ?? path,
        headers: { host: new URL(publicOrigin).host, origin: publicOrigin, 'sec-fetch-site': 'same-origin',
          'content-type': 'application/json', ...options.headers },
        async *[Symbol.asyncIterator]() { bodyRead++; yield JSON.stringify(options.body ?? {}) },
      }
      await route.handler(req, response)
      await completed
      return { ...response, bodyRead }
    },
    async close() { for (const effect of effects.toReversed()) effect.cleanup?.(); await Promise.resolve(); await Promise.resolve() },
  }
}

async function fixture(run) {
  const scratch = mkdtempSync(join(root, '.aumlok-browser-host-'))
  const stateRoot = join(scratch, 'state'), supportRoot = join(scratch, 'support')
  const release = join(scratch, 'release')
  const flatLibrary = join(release, 'plugins/aukora-face-aumlok/lib')
  mkdirSync(flatLibrary, { recursive: true, mode: 0o700 })
  symlinkSync(join(root, 'plugins/aukora-aumlok'), join(release, 'plugins/aukora-aumlok'), 'dir')
  const config = { directory: join(stateRoot, 'aumlok'), browserBinding: { publicOrigin, supportRoot, stateRoot } }
  const hosts = []
  const value = { config, supportRoot, stateRoot, flatBase: pathToFileURL(join(flatLibrary, 'index.js')).href,
    mount(options) { const host = mounted(this, options); hosts.push(host); return host },
  }
  try { return await run(value) }
  finally { for (const host of hosts) await host.close(); rmSync(scratch, { recursive: true, force: true }) }
}

async function refusalChecks(text = source) {
  await fixture(async f => {
    const host = f.mount({ source: text })
    for (const verb of ['prepare', 'bind', 'cancel', 'status']) assert.ok(host.routes.has(`${bindingPrefix}/${verb}`))
    assert.ok(host.routes.has(control.AUMLOK_CONTROL_STATUS_ENDPOINT))
    assert.ok(host.routes.has(identity.AUMLOK_IDENTITY_ENDPOINT))
    assert.ok(host.effects.some(effect => effect.label === 'ui-aumlok: browser ceremony lifecycle'))
    for (const path of [`${bindingPrefix}/prepare`, control.AUMLOK_CONTROL_STATUS_ENDPOINT, identity.AUMLOK_IDENTITY_ENDPOINT]) {
      for (const rejection of [401, 403]) {
        host.setAuth(rejection)
        const answer = await host.request(path)
        assert.equal(answer.status, rejection); assert.equal(answer.bodyRead, 0)
        assert.equal(host.imports.length, 0); assert.equal(host.reads.length, 0)
      }
      host.setAuth(undefined)
      for (const headers of [{ host: 'other.example.test' }, { origin: 'http://node.example.test' },
        { 'sec-fetch-site': 'cross-site' }]) {
        const answer = await host.request(path, { headers })
        assert.equal(answer.status, 403); assert.equal(answer.bodyRead, 0)
        assert.equal(host.imports.length, 0); assert.equal(host.reads.length, 0)
      }
    }
    const wrongMethod = await host.request(`${bindingPrefix}/status`, { method: 'GET' })
    assert.equal(wrongMethod.status, 405); assert.equal(wrongMethod.headers.allow, 'POST')
    assert.equal(wrongMethod.bodyRead, 0); assert.equal(host.imports.length, 0)
    const readMethod = await host.request(control.AUMLOK_CONTROL_STATUS_ENDPOINT, { method: 'POST' })
    assert.equal(readMethod.status, 405); assert.equal(host.imports.length, 0)
    assert.equal(existsSync(f.stateRoot), false, 'refused requests created node state')
  })
}

async function configurationChecks(text = source) {
  await fixture(async f => {
    const missingDirectory = f.mount({ source: text, config: { browserBinding: f.config.browserBinding } })
    const absent = await missingDirectory.request(`${bindingPrefix}/status`)
    assert.equal(absent.status, 503); assert.equal(absent.body.reason, 'aumlok:browser-binding-unavailable')
    assert.equal(missingDirectory.imports.length, 0)
    const mismatch = f.mount({ source: text, controller: { directory: join(f.stateRoot, 'other'), refresh() {} } })
    const refused = await mismatch.request(`${bindingPrefix}/status`)
    assert.equal(refused.status, 503); assert.equal(refused.body.reason, 'aumlok:browser-binding-unavailable')
    assert.equal(mismatch.imports.length, 0)
    const noOrigin = f.mount({ source: text, config: { directory: f.config.directory } })
    assert.equal((await noOrigin.request(`${bindingPrefix}/status`)).status, 403)
    assert.equal(noOrigin.imports.length, 0)
    const noStorage = f.mount({ source: text, config: { directory: f.config.directory, browserBinding: { publicOrigin } } })
    assert.equal((await noStorage.request(`${bindingPrefix}/status`)).status, 503)
    assert.equal(noStorage.imports.length, 1)
  })
}

async function layoutChecks(text = source) {
  await fixture(async f => {
    for (const flat of [false, true]) {
      const host = f.mount({ source: text, flat })
      const status = await host.request(`${bindingPrefix}/status`)
      assert.equal(status.status, 200)
      assert.equal(status.body.ok, true); assert.equal(status.body.bound, false)
      assert.equal(host.imports.length, 1)
      const expected = flat ? new URL('../../aukora-aumlok/lib/browser-binding.mjs', f.flatBase).href
        : new URL('../../../aukora-aumlok/lib/browser-binding.mjs', indexUrl).href
      assert.equal(host.imports[0], expected)
      await host.close()
    }
  })
}

async function statusContractChecks(text = source) {
  await fixture(async f => {
    const host = f.mount({ source: text, controller: { refresh() {
      throw Object.assign(new Error('aumlok-local:unavailable'), { code: 'aumlok-local:unavailable' })
    } } })
    const publicRead = await host.request(control.AUMLOK_CONTROL_STATUS_ENDPOINT)
    assert.equal(publicRead.status, 200)
    assert.equal(publicRead.body.status, 'not-connected')
    assert.equal(publicRead.body.reason, 'controller-absent')
    assert.equal(publicRead.body.code, 'aumlok-local:unavailable')
    const loopbackRead = await host.request(control.AUMLOK_CONTROL_STATUS_ENDPOINT, {
      headers: { host: '127.0.0.1:2026', origin: undefined, 'sec-fetch-site': undefined },
    })
    assert.equal(loopbackRead.status, 404)
    assert.deepEqual(loopbackRead.body, publicRead.body)
  })
}

async function liveFixtureChecks(text = source) {
  await fixture(async f => {
    let host = f.mount({ source: text })
    const initial = await host.request(`${bindingPrefix}/status`)
    assert.equal(initial.status, 200); assert.equal(initial.body.bound, false)
    assert.equal(host.imports.length, 1)
    assert.ok(existsSync(join(f.config.directory, 'browser-binding-attempts.sqlite')))
    await host.close()
    host = f.mount({ source: text, flat: true })
    const initialAfterRestart = await host.request(`${bindingPrefix}/status`)
    assert.equal(initialAfterRestart.body.bound, false)
    const prepared = await host.request(`${bindingPrefix}/prepare`, { body: { handle: 'host-fixture-owner', language: 'en' } })
    assert.equal(prepared.status, 200); assert.equal(prepared.body.ok, true, prepared.body.reason)
    assert.equal(host.imports.length, 1, 'one coordinator serves all first-binding verbs')
    const draw = prepared.body.draw
    const bound = await host.request(`${bindingPrefix}/bind`, { body: { ceremonyId: draw.ceremonyId,
      typedPhrase: draw.words.join(' '), acknowledged: true } })
    assert.equal(bound.status, 200); assert.equal(bound.body.ok, true, bound.body.reason)
    assert.equal(JSON.stringify(bound.body).includes(draw.words.join(' ')), false)
    const repeated = await host.request(`${bindingPrefix}/prepare`, { body: { handle: 'replacement', language: 'en' } })
    assert.equal(repeated.body.ok, false); assert.equal(repeated.body.reason, 'aumlok:bind-already-bound')
    const read = await host.request(control.AUMLOK_CONTROL_STATUS_ENDPOINT, { headers: { origin: undefined, 'sec-fetch-site': undefined } })
    assert.equal(read.status, 200); assert.equal(read.body.status, 'connected')
    assert.equal(read.body.control.subject, bound.body.binding.subject)
    assert.equal(read.body.control.handle, 'host-fixture-owner')
    assert.equal(host.imports.at(-1), new URL('../../aukora-aumlok/lib/store.mjs', f.flatBase).href)
    const contact = await host.request(identity.AUMLOK_IDENTITY_ENDPOINT)
    assert.equal(contact.status, 200); assert.equal(contact.body.subject, bound.body.binding.subject)
    assert.deepEqual(host.reads, [f.config.directory])
    assert.deepEqual(resolveMemoryIdentity({ supportRoot: f.supportRoot, installed: true, env: {} }), {
      subject: bound.body.binding.subject, stateDir: join(f.stateRoot, 'kira-memory'),
    })
    await host.close()
    const reopened = f.mount({ source: text })
    const persisted = await reopened.request(control.AUMLOK_CONTROL_STATUS_ENDPOINT)
    assert.equal(persisted.status, 200); assert.equal(persisted.body.control.subject, bound.body.binding.subject)
    assert.equal((await reopened.request(`${bindingPrefix}/status`)).body.subject, bound.body.binding.subject)
  })
}

test('mounted public routes reject auth, method and origin before imports and body reads', async () => {
  await refusalChecks()
  console.log('AUMLOK BROWSER HOST FENCES: PASS mounted auth/POST/public Host/Origin refusals; zero imports, body reads or state writes')
})
test('mounted ceremony refuses missing configuration and mismatched controller directory', async () => {
  await configurationChecks()
  console.log('AUMLOK BROWSER HOST CONFIG: PASS missing configuration and controller directory mismatch refuse')
})
test('canonical and materialized module locations load the actual coordinator', async () => {
  await layoutChecks()
  console.log('AUMLOK BROWSER HOST LAYOUT: PASS canonical source and flattened release dynamic coordinator import')
})
test('public unbound status is explicit HTTP 200 while loopback keeps HTTP 404', async () => {
  await statusContractChecks()
  console.log('AUMLOK BROWSER HOST STATUS: PASS authenticated public UNBOUND 200 body; loopback UNBOUND remains 404')
})
test('mounted full-cost ceremony writes verified identity and survives restart', async () => {
  await liveFixtureChecks()
  console.log('AUMLOK BROWSER HOST BIND: PASS production binding through mounted routes, public GET fallback, Kira subject and restart')
})
test('mounted host guard mutations are detected', async () => {
  const mutations = [
    ['browser routes registered', "for (const verb of ['prepare', 'bind', 'cancel', 'status'] as const)", 'for (const verb of [] as const)', refusalChecks],
    ['browser auth callback', 'browserBindingRoute(verb, publicOrigin,\n      request => fenceRejectionOf(gate(), request).rejection,',
      'browserBindingRoute(verb, publicOrigin,\n      request => undefined,', refusalChecks],
    ['read auth wrapper', 'const rejected = fenceRejectionOf(gate(), request).rejection', 'const rejected = undefined', refusalChecks],
    ['read origin wrapper', '(rejected ?? publicReadRejection(publicOrigin, request))', 'rejected', refusalChecks],
    ['configured directory required', 'if (!browser || !publicOrigin || !directory)', 'if (!browser || !publicOrigin)', configurationChecks],
    ['controller directory matches', 'if (current !== undefined && current !== directory) throw new Error(\'aumlok:browser-directory-mismatch\')', '', configurationChecks],
    ['runtime layout helper selected', "aumlokRuntimeUrl('browser-binding.mjs', import.meta.url)",
      "new URL('../../../aukora-aumlok/lib/browser-binding.mjs', import.meta.url).href", layoutChecks],
    ['public unbound status answers 200', "answer.status === 'connected' || publicRequest ? 200 : 404",
      "answer.status === 'connected' ? 200 : 404", statusContractChecks],
  ]
  for (const [name, before, after, check] of mutations) {
    assert.ok(source.includes(before), `mutation anchor missing: ${name}`)
    await assert.rejects(() => check(source.replace(before, after)), { name: 'AssertionError' }, `mutation survived: ${name}`)
    console.log(`AUMLOK BROWSER HOST MUTATION: KILLED ${name}`)
  }
  const locationBefore = 'new URL(`../../aukora-aumlok/lib/${file}`, base)'
  assert.ok(transportSource.includes(locationBefore))
  await assert.rejects(() => layoutChecks(source.replace(locationBefore, 'new URL(`../../../aukora-aumlok/lib/${file}`, base)')), { name: 'AssertionError' })
  console.log('AUMLOK BROWSER HOST MUTATION: KILLED flattened runtime location')
  const before = 'readControlWithFallback(controller(), directory)'
  assert.ok(source.includes(before))
  await assert.rejects(() => liveFixtureChecks(source.replace(before, 'readControlWithFallback(controller(), undefined)')), { name: 'AssertionError' })
  console.log('AUMLOK BROWSER HOST MUTATION: KILLED configured public-record fallback')
  console.log('AUMLOK BROWSER HOST MUTATIONS: 10/10 KILLED; in-memory requests, no real HTTPS/browser/owner proof')
})
