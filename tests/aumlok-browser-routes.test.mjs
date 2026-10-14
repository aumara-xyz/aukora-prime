// Browser binding refuses unauthenticated, cross-origin and unbounded requests before ceremony work.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'

const origin = 'https://node.example.test'
const path = '/api/aukora/aumlok-binding/bind'
const hostSource = readFileSync(new URL('../plugins/aukora-face/aumlok/src/index.ts', import.meta.url), 'utf8')
const source = hostSource.split('// Browser binding transport.\n')[1].split('// End browser binding transport.')[0]
const routes = await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source)).toString('base64')}`)

async function request(api, options = {}) {
  let calls = 0
  const verb = options.verb ?? 'bind'
  const routePath = `/api/aukora/aumlok-binding/${verb}`
  const chunks = options.chunks ?? [JSON.stringify({ ceremonyId: 'synthetic', typedPhrase: 'synthetic private phrase', acknowledged: true })]
  const req = { method: options.method ?? 'POST', url: options.url ?? routePath,
    headers: { host: new URL(origin).host, origin, 'content-type': 'application/json',
      'sec-fetch-site': 'same-origin', ...options.headers },
    async *[Symbol.asyncIterator]() { yield* chunks },
  }
  const res = { headers: {}, status: 0, body: undefined,
    setHeader(name, value) { this.headers[name] = value },
    writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers) },
    end(body) { this.body = JSON.parse(body) },
  }
  const route = api.browserBindingRoute(verb, options.configuredOrigin ?? origin,
    () => options.auth,
    async body => { calls++; if (options.error) throw new Error(body.typedPhrase); return { ok: true, binding: { subject: 'public-only' } } })
  await route.handler(req, res)
  return { ...res, calls }
}

async function checks(api) {
  for (const base of ['file:///build/plugins/aukora-face/aumlok/src/index.ts',
    'file:///build/plugins/aukora-face/aumlok/lib/index.js', 'file:///release/plugins/aukora-face-aumlok/lib/index.js']) {
    const root = base.includes('/release/') ? 'file:///release/' : 'file:///build/'
    for (const file of ['browser-binding.mjs', 'store.mjs']) {
      assert.equal(api.aumlokRuntimeUrl(file, base), `${root}plugins/aukora-aumlok/lib/${file}`)
    }
  }
  assert.throws(() => api.aumlokRuntimeUrl('../secret', 'file:///release/plugins/aukora-face-aumlok/lib/index.js'), /runtime-file-refused/u)
  assert.throws(() => api.aumlokRuntimeUrl('store.mjs', 'file:///unknown/index.js'), /runtime-layout-refused/u)
  const accepted = await request(api)
  assert.equal(accepted.status, 200)
  assert.equal(accepted.calls, 1)
  assert.equal(accepted.headers['cache-control'], 'no-store')
  assert.equal(accepted.headers['x-content-type-options'], 'nosniff')
  for (const auth of [401, 403]) {
    const status = await request(api, { verb: 'status', auth })
    assert.equal(status.status, auth)
    assert.equal(status.calls, 0)
    assert.deepEqual(status.body, { ok: false, reason: 'aumlok:browser-auth-refused' })
  }
  for (const [options, status, reason] of [
    [{ auth: 401 }, 401, 'auth-refused'], [{ auth: 403 }, 403, 'auth-refused'],
    [{ method: 'GET' }, 405, 'post-required'],
    [{ headers: { host: 'other.example.test' } }, 403, 'origin-refused'],
    [{ headers: { host: [new URL(origin).host] } }, 403, 'origin-refused'],
    [{ headers: { origin: undefined } }, 403, 'origin-refused'],
    [{ headers: { origin: 'http://node.example.test' } }, 403, 'origin-refused'],
    [{ headers: { origin: `${origin}:444` } }, 403, 'origin-refused'],
    [{ headers: { origin: [origin] } }, 403, 'origin-refused'],
    [{ headers: { 'sec-fetch-site': 'cross-site' } }, 403, 'origin-refused'],
    [{ url: `${path}?typedPhrase=synthetic` }, 400, 'url-refused'],
    [{ headers: { 'content-type': 'text/plain' } }, 415, 'json-required'],
    [{ headers: { 'content-length': '8193' } }, 413, 'body-too-large'],
    [{ headers: { 'content-length': '-1' } }, 413, 'body-too-large'],
    [{ headers: { 'content-length': ['1'] } }, 413, 'body-too-large'],
    [{ chunks: ['{', ' '.repeat(8192), '}'] }, 413, 'body-too-large'],
    [{ chunks: [Buffer.from([0xff])] }, 400, 'body-invalid'],
    [{ chunks: [Buffer.concat([Buffer.from('{"value":"'), Buffer.from([0xff]), Buffer.from('"}')])] }, 400, 'body-invalid'],
    [{ chunks: ['broken-json'] }, 400, 'body-invalid'],
    [{ chunks: ['null'] }, 400, 'body-invalid'],
    [{ chunks: ['[]'] }, 400, 'body-invalid'],
    [{ error: true }, 503, 'binding-unavailable'],
  ]) {
    const result = await request(api, options)
    assert.equal(result.status, status, JSON.stringify(options))
    assert.equal(result.body.reason, `aumlok:browser-${reason}`)
    assert.equal(result.calls, options.error ? 1 : 0)
    assert.equal(JSON.stringify(result.body).includes('synthetic private phrase'), false)
  }
  assert.equal((await request(api, { headers: { 'content-type': 'application/json; charset=utf-8' },
    chunks: ['{}'] })).status, 200)
  const unavailable = api.browserBindingRoute('status', undefined, () => undefined, async () => assert.fail())
  let rejected
  await assert.doesNotReject(() => unavailable.handler({ method: 'POST', url: path, headers: { host: new URL(origin).host, origin } },
    { setHeader() {}, writeHead(status) { rejected = status }, end() {} }))
  assert.equal(rejected, 403)
  assert.equal(api.configuredPublicOrigin(origin), origin)
  assert.equal(api.configuredPublicOrigin(undefined), undefined)
  for (const offered of [null, 5, 'garbage', 'http://node.example.test', `${origin}/`, `${origin}/a`,
    'https://owner@node.example.test', `${origin}?phrase=synthetic`]) {
    assert.throws(() => api.configuredPublicOrigin(offered), /aumlok:browser-origin-invalid/u)
  }
  assert.equal(api.publicReadRejection(origin, { headers: { host: new URL(origin).host } }), undefined)
  assert.equal(api.publicReadRejection(origin, { headers: { host: new URL(origin).host, origin,
    'sec-fetch-site': 'same-origin' } }), undefined)
  for (const host of ['127.0.0.1:18735', 'localhost', '[::1]:18735']) {
    assert.equal(api.publicReadRejection(origin, { headers: { host } }), undefined)
  }
  for (const [configured, headers] of [[undefined, { host: new URL(origin).host }],
    [origin, { host: 'wrong.example.test' }], [origin, { host: new URL(origin).host, origin: `http://node.example.test` }],
    [origin, { host: new URL(origin).host, 'sec-fetch-site': 'cross-site' }]]) {
    assert.equal(api.publicReadRejection(configured, { headers }), 403)
  }
}

await checks(routes)
const mutations = [
  ['release module location', 'new URL(`../../aukora-aumlok/lib/${file}`, base)', 'new URL(`../../../aukora-aumlok/lib/${file}`, base)'],
  ['closed runtime files', "if (file !== 'browser-binding.mjs' && file !== 'store.mjs')", 'if (false)'],
  ['closed runtime layout', "throw new Error('aumlok:browser-runtime-layout-refused')", "return new URL(`../../../aukora-aumlok/lib/${file}`, base).href"],
  ['cookie fence', 'if (rejection !== undefined)', 'if (false)'],
  ['POST only', "if (req.method !== 'POST')", 'if (false)'],
  ['public host', "req.headers['host'] !== new URL(origin).host", 'false'],
  ['exact HTTPS Origin', "req.headers['origin'] !== origin", 'false'],
  ['fetch metadata', "req.headers['sec-fetch-site'] !== 'same-origin'", 'false'],
  ['configured origin', 'if (!origin || req.headers', 'if (false || req.headers'],
  ['URL secrecy', 'if (req.url !== path)', 'if (false)'],
  ['JSON content type', "if (!/^application\\/json(?:\\s*;\\s*charset=utf-8)?$/iu.test(String(req.headers['content-type'] ?? '')))", 'if (false)'],
  ['declared body bound', 'Number(declared) > BROWSER_BODY_LIMIT', 'false'],
  ['stream body bound', 'if (length > BROWSER_BODY_LIMIT)', 'if (false)'],
  ['UTF-8 validity', '{ fatal: true }', '{ fatal: false }'],
  ['object body', "if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))", 'if (false)'],
  ['private exception sanitization', "catch { refuse(503, 'aumlok:browser-binding-unavailable') }", "catch (error) { refuse(503, error.message) }"],
  ['HTTPS configuration', "url.protocol !== 'https:'", 'false'],
  ['origin is only an origin', 'value !== url.origin', 'false'],
  ['public read host', 'if (!origin || host !== new URL(origin).host) return 403', 'if (!origin) return 403'],
  ['public read Origin', 'if (offered !== undefined && offered !== origin) return 403', ''],
  ['public read metadata', "if (site !== undefined && site !== 'same-origin') return 403", ''],
]
for (const [name, before, after] of mutations) {
  assert.ok(source.includes(before), `missing mutation anchor: ${name}`)
  const changed = stripTypeScriptTypes(source.replace(before, after))
  const mutant = await import(`data:text/javascript;base64,${Buffer.from(changed).toString('base64')}#${encodeURIComponent(name)}`)
  await assert.rejects(() => checks(mutant), { name: 'AssertionError' }, `survived: ${name}`)
}
console.log('AUMLOK BROWSER ROUTES: PASS 22 refusal cases; authenticated public reads; bounded in-memory transport')
console.log(`AUMLOK BROWSER ROUTE MUTATIONS: ${mutations.length}/${mutations.length} KILLED`)
