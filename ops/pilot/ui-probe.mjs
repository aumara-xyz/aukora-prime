// Signs in with the node's own launch token (never printed) and reports the HTTP status of what the screens load.
import { readFileSync } from 'node:fs'; import { createHash } from 'node:crypto'
const launch = JSON.parse(readFileSync(process.argv[2] ?? '/home/aukora-host/genesis/state/launch-url.json', 'utf8'))
const u = new URL(launch.url), name = 'dsh-auth-' + createHash('sha256').update(u.host).digest('base64url')
const ex = await fetch(launch.url, { redirect: 'manual' })
const cookie = ex.headers.getSetCookie().map(l => l.split(';')[0]).find(p => p.startsWith(name + '='))
if (!cookie) { console.log('NO SIGN-IN', ex.status); process.exit(2) }
let bad = 0
for (const path of ['/assets/aumara-icon-96.png', '/branding/aumara-icon-96.png', '/stock-apps/auma-lingwa.html', '/stock-apps/auma-live.html', '/stock-apps/zeta-harp/', '/stock-apps/human-graph/', '/stock-apps/dakini-code/', '/api/auma-live/status', '/api/aukora/aura-snapshot']) {
  const r = await fetch(u.origin + path, { headers: { cookie, origin: u.origin }, redirect: 'manual' }); const body = await r.arrayBuffer()
  const ok = r.status === 200 && body.byteLength > 0; if (!ok) bad++
  console.log(String(r.status).padEnd(4), String(body.byteLength).padStart(8), (r.headers.get('content-type') ?? '').split(';')[0].padEnd(24), path)
}
console.log(bad === 0 ? 'UI PROBE: all served' : `UI PROBE: ${bad} not served`)
