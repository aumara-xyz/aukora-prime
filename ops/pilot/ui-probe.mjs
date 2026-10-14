// Signs in and requires the expected screen paths and browser binding-guard results.
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

const paths = [
  '/branding/aumara-icon-96.png',
  '/assets/aumara-icon-96.png',
  '/stock-apps/auma-lingwa.html',
  '/app/auma/auma.js',
  '/stock-apps/auma-live.html',
  '/app/aumalive.js',
  '/stock-apps/zeta-harp/index.html',
  '/stock-apps/zeta-harp/js/zh-fixtures-1.js',
  '/stock-apps/human-graph/index.html',
  '/stock-apps/human-graph/graph.css',
  '/stock-apps/dakini-code/index.html',
  '/stock-apps/dakini-code/assets/index-t74FFCZZ.js',
  '/api/auma-live/status',
  '/api/aukora/aura-snapshot',
]

// On a browser node that has not been bound yet, the apps and their APIs must answer 403 until binding;
// everything the first screen draws must still be served.
const afterBinding = path => path.startsWith('/stock-apps/') || path.startsWith('/app/') || path.startsWith('/api/auma-live/')

const bindingRequired = 'browser-node:binding-required'
const bootCalls = ['$events', 'credentials/describe', 'agentPresets/list', 'session/modelCatalog',
  'permissionPresets/catalog'].map(endpoint => ({ path: `/api/${endpoint}`, body: '{"args":{}}', readOnly: true }))
const guardedCalls = [
  { path: '/api/session/create', body: '{"args":{"request":{"sessionId":"browser-node-guard-acceptance"}}}' },
  { path: '/api/session/list', body: '{"args":{"_request":{}}}' },
  { path: '/api/session/uploadFileBinary?sessionId=browser-node-guard-acceptance&name=probe.bin',
    body: new Uint8Array(), contentType: 'application/octet-stream' },
]

async function probe(launchFile, { expectUnbound = false, expectBound = false, uiOnly = false, guardOnly = false } = {}) {
  if (expectUnbound && expectBound || uiOnly && guardOnly || guardOnly && !expectUnbound && !expectBound) {
    return { ok: false, code: 'ui-probe:arguments-invalid', checks: [] }
  }
  let launch, url
  try { launch = JSON.parse(readFileSync(launchFile, 'utf8')) }
  catch { return { ok: false, code: 'ui-probe:launch-unreadable', checks: [] } }
  try {
    url = new URL(launch.url)
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('protocol')
  } catch { return { ok: false, code: 'ui-probe:launch-url-invalid', checks: [] } }

  const name = 'dsh-auth-' + createHash('sha256').update(url.host).digest('base64url')
  const signal = AbortSignal.timeout(15_000)
  let cookie
  try {
    const exchange = await fetch(launch.url, { redirect: 'manual', signal })
    cookie = exchange.headers.getSetCookie().map(line => line.split(';')[0]).find(value => value.startsWith(name + '='))
  } catch { return { ok: false, code: 'ui-probe:sign-in-unavailable', checks: [] } }
  if (!cookie) return { ok: false, code: 'ui-probe:sign-in-refused', checks: [] }

  const checks = []
  for (const path of guardOnly ? [] : paths) {
    try {
      const response = await fetch(url.origin + path, {
        headers: { cookie, origin: url.origin }, redirect: 'manual', signal,
      })
      const body = await response.arrayBuffer()
      checks.push({ path, status: response.status, bytes: body.byteLength,
        contentType: (response.headers.get('content-type') ?? '').split(';')[0],
        served: expectUnbound && afterBinding(path) ? response.status === 403 : response.status === 200 && body.byteLength > 0 })
    } catch {
      checks.push({ path, status: null, bytes: 0, contentType: '', served: false,
        code: 'ui-probe:request-unavailable' })
    }
  }
  if (!uiOnly && (expectUnbound || expectBound)) for (const call of [...bootCalls, ...guardedCalls]) {
    try {
      const response = await fetch(url.origin + call.path, {
        method: 'POST', body: call.body, headers: { cookie, origin: url.origin,
          'content-type': call.contentType ?? 'application/json' }, redirect: 'manual', signal,
      })
      const body = new Uint8Array(await response.arrayBuffer())
      let reason
      try { reason = JSON.parse(new TextDecoder().decode(body)).reason } catch {}
      const refused = response.status === 403 && reason === bindingRequired
      checks.push({ path: call.path, status: response.status, bytes: body.byteLength,
        contentType: (response.headers.get('content-type') ?? '').split(';')[0],
        served: call.readOnly || expectBound ? response.status !== 403 : refused,
        ...(reason === undefined ? {} : { code: reason }) })
    } catch {
      checks.push({ path: call.path, status: null, bytes: 0, contentType: '', served: false,
        code: 'ui-probe:request-unavailable' })
    }
  }
  const ok = checks.every(check => check.served)
  return { ok, code: ok ? 'ui-probe:all-served' : 'ui-probe:not-served', checks }
}

const args = process.argv.slice(2)
const json = args.includes('--json')
const expectUnbound = args.includes('--expect-unbound')
const expectBound = args.includes('--expect-bound')
const uiOnly = args.includes('--ui-only')
const guardOnly = args.includes('--guard-only')
const launchFile = args.find(arg => !arg.startsWith('--')) ?? '/home/aukora-host/genesis/state/launch-url.json'
const result = await probe(launchFile, { expectUnbound, expectBound, uiOnly, guardOnly })
if (json) console.log(JSON.stringify(result))
else {
  for (const check of result.checks) console.log(String(check.status ?? 'ERR').padEnd(4),
    String(check.bytes).padStart(8), check.contentType.padEnd(24), check.path)
  console.log(result.ok ? (guardOnly
    ? `BINDING GUARD PROBE: ${expectUnbound ? 'boot reads answered; session create, list and upload refused' : 'calls passed the bound guard'}`
    : expectUnbound ? 'UI PROBE: all served (unbound: first screen and boot reads served; apps and effects refused until binding)'
      : 'UI PROBE: all served') : `UI PROBE: ${result.code}`
    + (result.checks.length ? ` (${result.checks.filter(check => !check.served).length} not served)` : ''))
}
process.exitCode = result.ok ? 0 : 1
