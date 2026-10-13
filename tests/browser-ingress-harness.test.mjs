// SPDX-License-Identifier: AGPL-3.0-or-later
// In-memory pinned-harness trust and public-browser cookie checks; no listener or browser.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'

const root = fileURLToPath(new URL('../', import.meta.url))
const archive = join(root, 'vendor/dsh-source.tar.gz')
const patchFile = 'patches/public-browser-secure-cookie.patch.json'
const pin = JSON.parse(readFileSync(join(root, 'upstream-dsh.json'), 'utf8'))
const patchBytes = readFileSync(join(root, patchFile))
const patch = JSON.parse(patchBytes)
const sha256 = value => createHash('sha256').update(value).digest('hex')
// The pinned harness archive is fetched, not tracked; without it this file is unperformed (exit 2), not failed.
if (!existsSync(archive)) { console.log('UNPERFORMED: vendor/dsh-source.tar.gz absent'); process.exit(2) }
const listing = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }).trim().split('\n')

function pinnedSource(relative) {
  const entry = listing.find(name => name.endsWith('/' + relative))
  assert.ok(entry, `pinned source missing ${relative}`)
  return execFileSync('tar', ['-xOf', archive, entry], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 })
}

function applyPatch(relative, source, omit = -1) {
  let result = source
  for (const [index, edit] of patch.edits.entries()) {
    if (edit.path !== relative || index === omit) continue
    assert.equal(result.split(edit.find).length - 1, edit.occurrences ?? 1, `exact patch edit ${index}`)
    result = result.replaceAll(edit.find, edit.replace)
  }
  return result
}

function loadTrust(source) {
  const javascript = stripTypeScriptTypes(source
    .replace(/^import .*$/gmu, '')
    .replaceAll('export function ', 'function '))
  const isLoopbackHostname = hostname => hostname === 'localhost' || hostname === '[::1]'
    || /^127(?:\.\d{1,3}){3}$/u.test(hostname)
  return vm.runInNewContext(`${javascript}\n;({ assertTrustedAuthority, isTrustedApiRequest })`,
    { URL, Headers, isLoopbackHostname })
}

function sessionCookie(source) {
  const declaration = source.match(/function sessionCookie\([^]*?^\}/mu)?.[0]
  assert.ok(declaration, 'patched sessionCookie declaration')
  const javascript = stripTypeScriptTypes(declaration)
  const isLoopbackHostname = hostname => hostname === 'localhost' || hostname === '[::1]'
    || /^127(?:\.\d{1,3}){3}$/u.test(hostname)
  return vm.runInNewContext(`${javascript}\n;sessionCookie`, { URL, Date, String, isLoopbackHostname })
}

function browserAuth(source) {
  const javascript = stripTypeScriptTypes(source, { mode: 'transform' })
    .replace(/^import .*$/gmu, '').replace('export class BrowserAuth', 'class BrowserAuth')
  // Use the pinned predicate, including IPv4 range validation.
  const loopbackSource = stripTypeScriptTypes(pinnedSource('packages/client/connection/src/loopback-hostname.ts'))
    .replace('export function ', 'function ')
  const loopback = vm.runInNewContext(`${loopbackSource}\n;isLoopbackHostname`)
  return vm.runInNewContext(`${javascript}\n;BrowserAuth`, {
    Buffer, URL, Headers, Date, createHash, createHmac, randomBytes, timingSafeEqual,
    credentialKey: (namespace, key) => `${namespace}/${key}`, isLoopbackHostname: loopback,
  })
}

async function publicSession(source) {
  const BrowserAuth = browserAuth(source)
  let record
  const auth = await BrowserAuth.create({}, { modifyRecord: async (_key, update) => {
    record = await update(record) ?? record
    return record
  } }, 1)
  const exchange = authority => {
    let status, headers
    auth.authorizeIndex({ method: 'GET', url: auth.authenticatedUrl(`http://${authority}`), headers: { host: authority } },
      { writeHead: (code, values) => { status = code; headers = values }, end: () => {} })
    assert.equal(status, 303)
    return headers['set-cookie']
  }
  return { auth, exchange }
}

function connectionHost(source, auth) {
  const routes = []
  const ctx = { bound: false, effect: callback => callback(), webServer: { register: route => {
    routes.push(route)
    return () => {}
  } } }
  class Service { constructor(context) { this.ctx = context } }
  const javascript = stripTypeScriptTypes(source, { mode: 'transform' })
    .replace(/^import .*$/gmu, '')
    .replace('export class HostConnectionService', 'class HostConnectionService')
  const trust = loadTrust(pinnedSource('packages/client/connection/src/api-request-trust.ts'))
  const HostConnectionService = vm.runInNewContext(`${javascript}\n;HostConnectionService`, {
    Service, Response, URL, API_PATH: '/api', RpcId: value => value,
    isTrustedApiRequest: trust.isTrustedApiRequest,
    clientRequestSchema: { safeParse: data => ({ success: true, data }) },
    bridge: async (req, res, handler) => {
      const response = await handler.fetch(new Request(`https://node.example.test${req.url}`, {
        method: req.method, headers: req.headers, body: JSON.stringify(req.body),
      }))
      res.writeHead(response.status)
      res.end(await response.text())
    },
  })
  return { ctx, routes, connection: new HostConnectionService(ctx, ['node.example.test'], auth) }
}

test('pinned harness public authority accepts same-origin API and refuses hostile HTTP and WebSocket facts', t => {
  assert.equal(sha256(readFileSync(archive)), pin.archiveSha256)
  const trust = loadTrust(pinnedSource('packages/client/connection/src/api-request-trust.ts'))
  const publicHost = 'node.example.test'
  const request = headers => ({ headers })
  assert.equal(trust.isTrustedApiRequest(request({ host: publicHost, origin: `https://${publicHost}` }), [publicHost]), true,
    'matching public Host and Origin reaches authenticated API handling')
  assert.equal(trust.isTrustedApiRequest(request({ host: 'wrong.example.test', origin: 'https://wrong.example.test' }), [publicHost]), false,
    'wrong Host is refused')
  assert.equal(trust.isTrustedApiRequest(request({ host: publicHost, origin: `https://${publicHost}`, 'sec-fetch-site': 'cross-site' }), [publicHost]), false,
    'cross-site Fetch is refused')
  assert.equal(trust.isTrustedApiRequest(request({ host: publicHost, origin: 'https://wrong.example.test',
    connection: 'Upgrade', upgrade: 'websocket' }), [publicHost]), false,
  'the WebSocket upgrade route uses this same request rejection and refuses cross-origin Origin')
  t.diagnostic('PASS pinned harness trust probe: public API accepted; wrong Host, cross-site Fetch and cross-origin WebSocket refused')
})

test('pinned patch uses public __Host- Secure cookies and preserves loopback exchange', async t => {
  const declaration = pin.localPatches.find(entry => entry.file === patchFile)
  assert.equal(declaration?.sha256, sha256(patchBytes))
  assert.equal(declaration?.reason, patch.reason)
  const relative = 'packages/client/connection/src/browser-auth.ts'
  const pristine = pinnedSource(relative)
  const patched = applyPatch(relative, pristine)
  for (const expectation of patch.expectAfterApply.filter(row => row.path === relative)) {
    assert.ok(patched.includes(expectation.contains), expectation.contains)
  }
  const cookie = sessionCookie(patched)
  const publicCookie = cookie('node.example.test', 'dsh-auth-fixture', 'value', 2_000, 1)
  const loopbackCookie = cookie('127.0.0.1:18735', 'dsh-auth-fixture', 'value', 2_000, 1)
  assert.match(publicCookie, /; Secure$/u)
  assert.match(publicCookie, /; HttpOnly; SameSite=Strict; Secure$/u)
  assert.doesNotMatch(loopbackCookie, /; Secure/u)

  async function checkNames(source) {
    const { auth, exchange } = await publicSession(source)
    const issued = exchange('node.example.test')
    assert.match(issued, /^__Host-dsh-auth-[A-Za-z0-9_-]+=/u)
    assert.match(issued, /; Path=\//u)
    assert.doesNotMatch(issued, /; Domain=/iu)
    const pair = issued.split(';')[0]
    assert.equal(auth.isAuthenticated({ headers: { host: 'node.example.test', cookie: pair } }), true)
    assert.equal(auth.isAuthenticated({ headers: { host: 'node.example.test', cookie: pair.replace('__Host-', '') } }), false)
    assert.equal(auth.isAuthenticated({ headers: { host: 'node.example.test',
      cookie: `${pair.replace('__Host-', '').split('=')[0]}=invalid; ${pair}` } }), true,
    'an unprefixed parent-domain cookie cannot shadow the public cookie')
    assert.equal(auth.isAuthenticated({ headers: { host: 'other.example.test', cookie: pair } }), false)
    for (const authority of ['localhost:18735', '127.0.0.1:18735', '127.0.0.2:18735', '[::1]:18735']) {
      const local = exchange(authority)
      assert.match(local, /^dsh-auth-/u)
      assert.doesNotMatch(local, /__Host-|; Secure/u)
      assert.equal(auth.isAuthenticated({ headers: { host: authority, cookie: local.split(';')[0] } }), true)
    }
  }
  await checkNames(patched)
  const nameGuard = "const prefix = isLoopbackHostname(hostname) ? COOKIE_PREFIX : '__Host-' + COOKIE_PREFIX"
  assert.equal(patched.split(nameGuard).length, 2)
  await assert.rejects(checkNames(patched.replace(nameGuard, 'const prefix = COOKIE_PREFIX')), assert.AssertionError)
  await assert.rejects(checkNames(patched.replace(nameGuard, "const prefix = '__Host-' + COOKIE_PREFIX")), assert.AssertionError)

  const guard = "const secure = isLoopbackHostname(hostname) ? '' : '; Secure'"
  assert.equal(patched.split(guard).length, 2)
  const mutant = sessionCookie(patched.replace(guard, "const secure = ''"))
  assert.throws(() => assert.match(mutant('node.example.test', 'n', 'v', 2_000, 1), /; Secure$/u), assert.AssertionError)

  const pristineDeclaration = pristine.match(/function sessionCookie\([^]*?^\}/mu)?.[0]
  assert.ok(pristineDeclaration)
  const pristineCookie = vm.runInNewContext(`${stripTypeScriptTypes(pristineDeclaration)}\n;sessionCookie`, { Date, String })
  assert.throws(() => assert.match(pristineCookie('n', 'v', 2_000, 1), /; Secure$/u), assert.AssertionError,
    'removing the patch restores the insecure public cookie')
  t.diagnostic('MUTATION public cookie guards: 4/4 killed (Secure removal, patch removal, public prefix removal, loopback prefix widening)')
})

test('OPEN: pinned harness admits signed-in unbound general RPC; route registries cannot narrow it', async t => {
  const relative = 'packages/client/connection/src/rpc-host.ts'
  const source = pinnedSource(relative)
  const { auth, exchange } = await publicSession(applyPatch('packages/client/connection/src/browser-auth.ts',
    pinnedSource('packages/client/connection/src/browser-auth.ts')))
  const headers = { host: 'node.example.test', origin: 'https://node.example.test',
    cookie: exchange('node.example.test').split(';')[0], 'content-type': 'application/json' }

  async function observe(source) {
    const { ctx, routes, connection } = connectionHost(source, auth)
    let calls = 0
    const dispatch = async () => { calls++; return { ok: true, value: 'general effect reached' } }
    connection.fetch.register({ path: '/api/aumlok/binding/status', methods: ['GET'], requestBody: 'buffered',
      fetch: async () => Response.json({ bound: ctx.bound }) })
    connection.rpc.intercept('/api', () => true, dispatch)
    assert.throws(() => connection.rpc.intercept('/api', () => false, dispatch), /already has an interceptor/u,
      'the gateway owns the sole shared interceptor; no composable deny interceptor exists')
    assert.throws(() => connection.rpc.intercept('/rpc', () => false, dispatch), /invalid shared RPC channel/u)
    connection.rpc.handle('/rpc', dispatch)
    assert.equal(ctx.bound, false)
    assert.equal(connection.requestRejection({ headers }), undefined,
      'cookie authentication consults no binding state or route scope')
    assert.equal(connection.requestRejection({ headers: { ...headers, cookie: 'invalid' } }), 401)
    assert.equal(connection.requestRejection({ headers: { ...headers, origin: 'https://other.example.test' } }), 403)
    const shared = connection.createSharedFetchHandler('/api')
    const status = await shared.fetch(new Request('https://node.example.test/api/aumlok/binding/status'))
    assert.equal((await status.json()).bound, false)
    const body = { type: 'client-request', rpcId: 'fixture', method: 'session/start', payload: {} }
    const general = await shared.fetch(new Request('https://node.example.test/api/session/start', {
      method: 'POST', headers, body: JSON.stringify(body),
    }))
    assert.equal((await general.json()).result.ok, true)
    let statusCode, responseBody
    await routes[0].handler({ method: 'POST', url: '/rpc/session/start', headers, body }, {
      writeHead: code => { statusCode = code }, end: value => { responseBody = value },
    })
    assert.equal(statusCode, 200)
    assert.equal(JSON.parse(responseBody).result.ok, true)
    assert.equal(calls, 2, 'both shared and separately registered channels dispatched while unbound')
  }
  await observe(source)
  const currentAuthentication = 'return this.browserAuth.isAuthenticated(request) ? undefined : 401'
  assert.equal(source.split(currentAuthentication).length, 2)
  await assert.rejects(observe(source.replace(currentAuthentication, 'return 403')), assert.AssertionError)
  const mux = pinnedSource('packages/api/gateway/src/index.ts')
  assert.match(mux, /const rejection = webCtx\.connection\.requestRejection\(req\)[^]*?mux\.handleUpgrade\(req, socket, head\)/u)
  t.diagnostic('OPEN unbound RPC: shared and separate general channels reached; WebSocket uses same cookie rejection; no global allowlist hook')
  t.diagnostic('MUTATION current-access documentation: 1/1 killed by rejecting authenticated traffic; no new protection claimed')
})
