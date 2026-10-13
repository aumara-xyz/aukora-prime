// Signs in without printing credentials and fails when a screen entry or asset is not served.
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
// everything the first screen draws must still be served. --expect-unbound checks exactly that.
const afterBinding = path => path.startsWith('/stock-apps/') || path.startsWith('/app/') || path.startsWith('/api/auma-live/')

async function probe(launchFile, expectUnbound = false) {
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
  for (const path of paths) {
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
  const ok = checks.every(check => check.served)
  return { ok, code: ok ? 'ui-probe:all-served' : 'ui-probe:not-served', checks }
}

const args = process.argv.slice(2)
const json = args.includes('--json')
const expectUnbound = args.includes('--expect-unbound')
const launchFile = args.find(arg => !arg.startsWith('--')) ?? '/home/aukora-host/genesis/state/launch-url.json'
const result = await probe(launchFile, expectUnbound)
if (json) console.log(JSON.stringify(result))
else {
  for (const check of result.checks) console.log(String(check.status ?? 'ERR').padEnd(4),
    String(check.bytes).padStart(8), check.contentType.padEnd(24), check.path)
  console.log(result.ok ? (expectUnbound ? 'UI PROBE: all served (unbound: first screen served, apps refused until binding)' : 'UI PROBE: all served') : `UI PROBE: ${result.code}`
    + (result.checks.length ? ` (${result.checks.filter(check => !check.served).length} not served)` : ''))
}
process.exitCode = result.ok ? 0 : 1
