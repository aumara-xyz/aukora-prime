import { readFile, lstat, realpath } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve, sep, extname } from 'node:path'

const donor = '645d3213b8aede3b544269b4224ae09df06b0a42'
const appPrefix = 'faces/apps/'
const liveFiles = new Set(['aura-trace.js', 'aumalive.js', 'aumalive-audio.js', 'aumalive-duplex.js',
  'aumalive-mind-choice.js', 'chat-log-key.js', 'field-directives.js', 'field-quality.js',
  'home-session.js', 'lane-bridge.js'])
const graphFiles = new Set(['index.html', 'graph.css', 'bootstrap.js', 'graph.js', 'graph-data.js'])
const threeFiles = new Set(['three.module.min.js', 'three.core.min.js'])
const lessonGate = 'const isUnlocked = (day, s) => day === 1 || !!s.done[day - 1] || !!s.done[day];'
const graphCsp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png',
  '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ico': 'image/x-icon' }

// Only the selected manifest closure is mapped. Original donor host effects stay unmounted.
function routePath(path) {
  if (path === 'vendor/auma-lingwa/runtime/auma-lingwa.html') return '/stock-apps/auma-lingwa.html'
  if (path === 'vendor/auma-live/runtime/auma-live.html') return '/stock-apps/auma-live.html'
  if (path === 'vendor/auma-lingwa/runtime/assets/aumara-icon-96.png') return '/assets/aumara-icon-96.png'
  const lingwa = 'vendor/auma-lingwa/runtime/app/'
  if (path.startsWith(lingwa)) {
    const suffix = path.slice(lingwa.length)
    if (suffix === 'style.css' || suffix === 'aura-core.js' || suffix.startsWith('auma/')) return '/app/' + suffix
  }
  const live = 'vendor/auma-live/runtime/app/'
  if (path.startsWith(live) && liveFiles.has(path.slice(live.length))) return '/app/' + path.slice(live.length)
  for (const app of ['zeta-harp', 'dakini-code']) {
    const prefix = 'vendor/' + app + '/'
    if (path.startsWith(prefix)) return '/stock-apps/' + app + '/' + path.slice(prefix.length)
  }
  const graph = 'assets/human-graph/'
  if (path.startsWith(graph) && graphFiles.has(path.slice(graph.length))) return '/stock-apps/human-graph/' + path.slice(graph.length)
  const three = 'vendor/three/'
  if (path.startsWith(three) && threeFiles.has(path.slice(three.length))) return '/stock-apps/human-graph/three/' + path.slice(three.length)
}

/**
 * Return native webServer routes for copied Apps bytes. H must wrap every handler
 * with its existing connection.requestRejection gate before registration.
 * appRoot is the Prime-owned aukora-face-apps directory in the composed release.
 * An explicit manifest permits copying this adapter alone into the release.
 */
export async function createStaticAppRoutes({ appRoot, manifest } = {}) {
  if (!appRoot) throw new Error('Prime static Apps root required')
  manifest ??= JSON.parse(await readFile(new URL('../baseline-manifest.json', import.meta.url), 'utf8'))
  if (manifest.commit !== donor || !Array.isArray(manifest.files)) throw new Error('Prime static Apps donor mismatch')
  const root = resolve(appRoot)
  if ((await lstat(root)).isSymbolicLink() || await realpath(root) !== root) throw new Error('Prime static Apps root must be owned real directory')
  const bodies = new Map()
  for (const item of manifest.files) {
    if (!item.path.startsWith(appPrefix)) continue
    const path = item.path.slice(appPrefix.length)
    const url = routePath(path)
    if (!url) continue
    const segments = path.split('/')
    if (segments.some(part => !part || part === '.' || part === '..' || part.includes('\\'))) throw new Error('Prime static Apps invalid manifest path')
    const file = resolve(root, path)
    if (!file.startsWith(root + sep)) throw new Error('Prime static Apps path escape')
    for (let i = 1; i <= segments.length; i++) {
      if ((await lstat(resolve(root, ...segments.slice(0, i)))).isSymbolicLink()) throw new Error('Prime static Apps symlink refused: ' + path)
    }
    if (!(await lstat(file)).isFile() || !(await realpath(file)).startsWith(root + sep)) throw new Error('Prime static Apps file refused: ' + path)
    let body = await readFile(file)
    if (body.length !== item.bytes || createHash('sha256').update(body).digest('hex') !== item.sha256) throw new Error('Prime static Apps baseline changed: ' + path)
    if (url === '/app/auma/auma.js') {
      const source = body.toString('utf8')
      if (!source.includes(lessonGate)) throw new Error('Prime static Apps Lingwa gate absent')
      body = Buffer.from(source.replace(lessonGate, 'const isUnlocked = () => true;'))
    }
    if (bodies.has(url)) throw new Error('Prime static Apps duplicate route: ' + url)
    bodies.set(url, { body, type: mime[extname(path)] ?? 'application/octet-stream' })
  }
  const icon = bodies.get('/assets/aumara-icon-96.png')
  if (!icon) throw new Error('Prime static Apps icon absent')
  bodies.set('/branding/aumara-icon-96.png', icon)
  for (const url of ['/stock-apps/auma-lingwa.html', '/stock-apps/auma-live.html', '/stock-apps/zeta-harp/index.html',
    '/stock-apps/dakini-code/index.html', '/stock-apps/human-graph/index.html']) {
    if (!bodies.has(url)) throw new Error('Prime static Apps entry absent: ' + url)
  }
  const handler = async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); res.end(); return }
    let path
    try { path = decodeURIComponent(new URL(req.url ?? '/', 'http://prime-static.local').pathname) }
    catch { res.writeHead(400); res.end(); return }
    const entry = bodies.get(path)
    if (!entry) { res.writeHead(404); res.end(); return }
    const headers = { 'content-type': entry.type, 'content-length': String(entry.body.length), 'x-content-type-options': 'nosniff' }
    if (path.startsWith('/stock-apps/human-graph/')) headers['content-security-policy'] = graphCsp
    res.writeHead(200, headers)
    res.end(req.method === 'HEAD' ? undefined : entry.body)
  }
  return Object.freeze([
    ...['/app', '/stock-apps/zeta-harp', '/stock-apps/dakini-code', '/stock-apps/human-graph'].map(path => Object.freeze({ kind: 'prefix', path, handler })),
    ...['/assets/aumara-icon-96.png', '/branding/aumara-icon-96.png', '/stock-apps/auma-lingwa.html', '/stock-apps/auma-live.html']
      .map(path => Object.freeze({ kind: 'exact', path, handler })),
  ])
}
