// SPDX-License-Identifier: AGPL-3.0-or-later
// Check the probe's client URLs, failure exit and credential suppression without a listener.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { runInNewContext } from 'node:vm'

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8')
const probeSource = read('ops/pilot/ui-probe.mjs')
const apps = 'plugins/aukora-face/apps/'
const clientEntry = file => read(`${apps}src/client/${file}`).match(/src="([^"?]+)"/u)[1]
const relativeAsset = (entry, file, expression) => new URL(read(file).match(expression)[1], `http://probe.invalid${entry}`).pathname
const lingwa = clientEntry('AumaLanguageSurface.tsx')
const live = read(`${apps}src/client/auma-live-session.ts`).match(/LIVE_APP_PATH = '([^']+)'/u)[1]
const zeta = clientEntry('ZetaHarpSurface.tsx')
const graph = clientEntry('HumanGraphSurface.tsx')
const dakini = clientEntry('DakiniCode.tsx')
const expected = [
  read('plugins/aukora-face/threads/src/client/rows/Rows.tsx').match(/src="([^"\n]*aumara-icon-96\.png)"/u)[1],
  '/assets/aumara-icon-96.png',
  lingwa, read(`${apps}vendor/auma-lingwa/runtime/auma-lingwa.html`).match(/from '([^']+)'/u)[1],
  live, read(`${apps}vendor/auma-live/runtime/auma-live.html`).match(/from '([^']+)'/u)[1],
  zeta, relativeAsset(zeta, `${apps}vendor/zeta-harp/index.html`, /<script src="([^"]+)"/u),
  graph, relativeAsset(graph, `${apps}assets/human-graph/index.html`, /<link rel="stylesheet" href="([^"]+)"/u),
  dakini, relativeAsset(dakini, `${apps}vendor/dakini-code/index.html`, /<script[^>]* src="([^"]+)"/u),
  '/api/auma-live/status', '/api/aukora/aura-snapshot',
]
const launch = { url: 'http://127.0.0.1:19443/?token=synthetic-launch-secret' }
const name = 'dsh-auth-' + createHash('sha256').update(new URL(launch.url).host).digest('base64url')
const cookie = `${name}=synthetic-cookie-secret`

async function run(source = probeSource, options = {}) {
  const output = [], requests = [], missingTimeouts = [], state = { argv: ['node', 'ui-probe.mjs', ...(options.text ? [] : ['--json']), '/synthetic/launch.json'] }
  let signal
  const javascript = source.replace("import { readFileSync } from 'node:fs'", 'const readFileSync = __read')
    .replace("import { createHash } from 'node:crypto'", 'const createHash = __hash')
  await runInNewContext(`(async () => { ${javascript}\n })()`, {
    process: state, URL, Buffer, __hash: createHash,
    __read(path) {
      assert.equal(path, '/synthetic/launch.json')
      if (options.readError) throw new Error('synthetic-launch-secret')
      return JSON.stringify(options.launch ?? launch)
    },
    AbortSignal: { timeout(milliseconds) {
      assert.ok(milliseconds > 0 && milliseconds <= 20_000, 'probe:bounded-timeout')
      return signal = AbortSignal.timeout(milliseconds)
    } },
    console: { log: (...args) => output.push(args.join(' ')) },
    async fetch(url, request) {
      if (!signal || request.signal !== signal) missingTimeouts.push(true)
      assert.equal(request.redirect, 'manual')
      if (url === launch.url) {
        if (options.signInError) throw new Error('synthetic-launch-secret')
        return { headers: { getSetCookie: () => options.noCookie ? [] : [`${cookie}; HttpOnly`] } }
      }
      const parsed = new URL(url)
      assert.equal(parsed.origin, new URL(launch.url).origin)
      assert.equal(request.headers.cookie, cookie)
      assert.equal(request.headers.origin, parsed.origin)
      requests.push(parsed.pathname)
      if (options.networkError && parsed.pathname === expected[0]) throw new Error(cookie)
      const failed = options.badPath === parsed.pathname
      return { status: failed ? options.status ?? 404 : 200,
        headers: { get: () => 'text/plain; charset=utf-8' },
        arrayBuffer: async () => new Uint8Array(failed && options.empty ? 0 : 7).buffer }
    },
  })
  assert.deepEqual(missingTimeouts, [], 'probe:shared-timeout')
  const printed = output.join('\n')
  assert.doesNotMatch(printed, /synthetic-(?:launch|cookie)-secret/u, 'probe:credentials-not-printed')
  return { status: state.exitCode, requests, output, result: options.text ? undefined : JSON.parse(printed) }
}

async function served(source = probeSource) {
  const result = await run(source)
  assert.deepEqual(result.requests, expected, 'probe:client-urls')
  assert.equal(result.status, 0)
  assert.equal(result.result.ok, true)
  assert.equal(result.result.code, 'ui-probe:all-served')
  assert.deepEqual(result.result.checks.map(row => row.path), expected)
  assert.ok(result.result.checks.every(row => row.served && row.bytes > 0))
}

async function failed(source = probeSource) {
  for (const options of [{ status: 404 }, { status: 302 }, { status: 200, empty: true }, { networkError: true }]) {
    const result = await run(source, { badPath: expected[0], ...options })
    assert.equal(result.status, 1, 'probe:failure-exit')
    assert.equal(result.result.ok, false)
    assert.equal(result.result.code, 'ui-probe:not-served')
    assert.deepEqual(result.requests, expected, 'probe:checks-continue-after-refusal')
  }
}

test('ui-probe requests the tile entry, one page asset and the thread icon with --json', async () => served())
test('ui-probe exits one for HTTP, empty-body and network refusals', async () => failed())
test('ui-probe suppresses credentials for sign-in, unreadable launch and invalid launch failures', async () => {
  for (const [options, code] of [[{ noCookie: true }, 'sign-in-refused'], [{ signInError: true }, 'sign-in-unavailable'],
    [{ readError: true }, 'launch-unreadable'], [{ launch: { url: 'invalid synthetic-launch-secret' } }, 'launch-url-invalid']]) {
    const result = await run(probeSource, options)
    assert.equal(result.status, 1)
    assert.equal(result.result.code, `ui-probe:${code}`)
    assert.deepEqual(result.result.checks, [])
  }
  const text = await run(probeSource, { text: true })
  assert.equal(text.status, 0)
  assert.equal(text.output.at(-1), 'UI PROBE: all served')
})
test('ui-probe mutants fail for missing entry, obsolete directory URL, exit, timeout and token output', async () => {
  await assert.rejects(served(probeSource.replace("  '/stock-apps/zeta-harp/index.html',\n", '')), /probe:client-urls/u)
  await assert.rejects(served(probeSource.replace("'/stock-apps/zeta-harp/index.html'", "'/stock-apps/zeta-harp/'")), /probe:client-urls/u)
  await assert.rejects(failed(probeSource.replace('process.exitCode = result.ok ? 0 : 1', 'process.exitCode = 0')), /probe:failure-exit/u)
  await assert.rejects(served(probeSource.replaceAll("redirect: 'manual', signal", "redirect: 'manual'")), /probe:shared-timeout/u)
  await assert.rejects(served(probeSource.replace('const name =', 'console.log(launch.url)\n  const name =')), /probe:credentials-not-printed/u)
  console.log('MUTATION pilot-ui-probe: 5/5 killed')
})
