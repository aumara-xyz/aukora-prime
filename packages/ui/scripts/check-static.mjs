import assert from 'node:assert/strict'
import { readFile, mkdtemp, mkdir, writeFile, symlink, rm, realpath } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createStaticAppRoutes } from '../adapters/static-assets.mjs'

const appRoot = fileURLToPath(new URL('../faces/apps/', import.meta.url))
const routes = await createStaticAppRoutes({ appRoot })
const call = async (url, method = 'GET') => {
  const route = routes.find(route => route.kind === 'exact' ? route.path === url.split('?')[0]
    : url === route.path || url.startsWith(route.path + '/'))
  assert(route, 'fixture route missing')
  const result = {}
  await route.handler({ url, method }, { writeHead(status, headers) { Object.assign(result, { status, headers }) }, end(body) { result.body = body } })
  return result
}
for (const url of ['/stock-apps/auma-lingwa.html', '/stock-apps/auma-live.html', '/stock-apps/zeta-harp/index.html',
  '/stock-apps/dakini-code/index.html', '/stock-apps/human-graph/index.html', '/branding/aumara-icon-96.png',
  '/app/aumalive.js', '/app/home-session.js', '/app/lane-bridge.js', '/stock-apps/human-graph/three/three.module.min.js']) {
  const get = await call(url)
  assert.equal(get.status, 200)
  assert(get.body.length > 0)
  const head = await call(url, 'HEAD')
  assert.equal(head.status, 200)
  assert.equal(head.body, undefined)
  assert.equal(head.headers['content-length'], String(get.body.length))
  assert.equal((await call(url, 'POST')).status, 405)
}
const graph = await call('/stock-apps/human-graph/index.html')
assert(graph.headers['content-security-policy'].includes("frame-ancestors 'self'"))
assert.equal((await call('/app/auma/%ZZ')).status, 400)
assert.equal((await call('/app/auma/%2e%2e/%2e%2e/package.json')).status, 404)
assert.equal((await call('/app/auma/not-in-baseline.js')).status, 404)
assert.equal((await call('/stock-apps/human-graph/package.json')).status, 404)
const raw = await readFile(join(appRoot, 'vendor/auma-lingwa/runtime/app/auma/auma.js'), 'utf8')
assert(raw.includes('const isUnlocked = (day, s) =>'))
assert.equal((await call('/app/auma/auma.js')).body.toString(), raw)
assert.equal(await readFile(join(appRoot, 'vendor/auma-lingwa/runtime/app/auma/auma.js'), 'utf8'), raw)
const manifest = JSON.parse(await readFile(new URL('../baseline-manifest.json', import.meta.url), 'utf8'))
await assert.rejects(createStaticAppRoutes({ appRoot, manifest: { ...manifest, commit: 'wrong' } }), /donor mismatch/)
const first = manifest.files.find(item => item.path === 'faces/apps/vendor/auma-lingwa/runtime/auma-lingwa.html')
await assert.rejects(createStaticAppRoutes({ appRoot, manifest: { ...manifest, files: [{ ...first, sha256: '0'.repeat(64) }] } }), /baseline changed/)
const temp = await realpath(await mkdtemp(join(tmpdir(), 'prime-ui-static-')))
try {
  await mkdir(join(temp, 'vendor/auma-lingwa/runtime'), { recursive: true })
  await writeFile(join(temp, 'fixture'), 'disposable')
  await symlink(join(temp, 'fixture'), join(temp, 'vendor/auma-lingwa/runtime/auma-lingwa.html'))
  await assert.rejects(createStaticAppRoutes({ appRoot: temp, manifest: { ...manifest, files: [first] } }), /symlink refused/)
} finally { await rm(temp, { recursive: true, force: true }) }
console.log(JSON.stringify({ result: 'PASS', routes: routes.length, fixture_groups: 5, source_asset_diff: 0,
  effects: 'none', connection_gate: 'H must wrap each returned handler before registration', runtime_parity: 'UNPERFORMED' }))
