'use strict'

// One disposable synthetic check. Uses shipped guards in an actual Electron renderer;
// no browser profiles, owner keys, real backend, approval or executor are accessed.
const { app, BrowserWindow, session } = require('electron')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')
const http = require('node:http')
const { createHash, randomUUID } = require('node:crypto')
const { trustedOrigin, allowsNavigation, allowsRequest, webPreferences, guardSession, guardContents } = require('./policy.cjs')
const { readLaunch, parseCookie, exchangeLaunch } = require('./launch-access.cjs')

app.setName('AUKORA Prime Preview Synthetic Check')
app.enableSandbox()
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'prime-desktop-check-'))
app.setPath('userData', temp)
app.setPath('sessionData', temp)
const pause = ms => new Promise(resolve => setTimeout(resolve, ms))
const listen = server => new Promise((resolve, reject) => {
  server.once('error', reject)
  server.listen(0, '127.0.0.1', resolve)
})
let server, trap, window
let trapRequests = 0, downloads = 0, handshakes = 0, assets = 0

app.whenReady().then(async () => {
  const production = trustedOrigin()
  assert.equal(production.origin, 'http://127.0.0.1:18731')
  for (const url of ['http://127.0.0.1:18732', 'http://localhost:18731', 'http://127.0.0.1:18731@evil.invalid',
    'https://safe.invalid/path', 'https://safe.invalid/?token=test', 'file:///tmp/test', 'http://2130706433:18731']) {
    assert.throws(() => trustedOrigin(url))
  }
  assert.equal(trustedOrigin('https://preview.example').origin, 'https://preview.example')
  for (const value of ['http://127.0.0.1:18732/', 'https://evil.invalid/', 'file:///tmp/test', 'data:text/html,test',
    'http://127.0.0.1:18731@evil.invalid/', 'http://127.0.0.1:18731/?token=test']) {
    assert.equal(allowsNavigation(value, production), false)
  }
  assert.equal(allowsRequest({ url: 'ws://127.0.0.1:18731/socket', resourceType: 'webSocket' }, production), true)
  assert.equal(allowsRequest({ url: 'ws://127.0.0.1:18732/socket', resourceType: 'webSocket' }, production), false)
  assert.equal(allowsRequest({ url: 'http://127.0.0.1:18731/?token=test', resourceType: 'xhr' }, production), false)

  trap = http.createServer((_req, res) => { trapRequests++; res.end('must not be reached') })
  await listen(trap)
  const trapUrl = 'http://127.0.0.1:' + trap.address().port + '/'
  let origin, cookieName, pair
  server = http.createServer((req, res) => {
    if (req.url === '/?token=synthetic-launch') {
      handshakes++
      res.writeHead(303, { location: '/', 'set-cookie': pair + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=60' })
      res.end(); return
    }
    if (req.headers.cookie !== pair) { res.writeHead(403); res.end(); return }
    if (req.url === '/asset') { assets++; res.end('asset'); return }
    if (req.url === '/redirect') { res.writeHead(302, { location: trapUrl }); res.end(); return }
    if (req.url === '/download') {
      downloads++
      res.writeHead(200, { 'content-disposition': 'attachment; filename=synthetic.txt', 'content-type': 'application/octet-stream' })
      res.end('synthetic'); return
    }
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<!doctype html><title>Synthetic fixture</title><p>Disposable synthetic security check</p>')
  })
  await listen(server)
  // A random disposable loopback origin is confined to this check; production
  // trustedOrigin only accepts the fixed tunnel endpoint or explicit HTTPS.
  origin = new URL('http://127.0.0.1:' + server.address().port + '/')
  cookieName = 'dsh-auth-' + createHash('sha256').update(origin.host).digest('base64url')
  pair = cookieName + '=v1.syntheticbody.syntheticsignature'
  const file = path.join(temp, 'launch-url.json')
  const write = data => fs.writeFileSync(file, JSON.stringify(data), { mode: 0o600 })
  write({ pid: process.pid, url: origin.href + '?token=synthetic-launch' })
  assert.throws(() => readLaunch(file, process.pid + 1, origin))
  fs.chmodSync(file, 0o644)
  assert.throws(() => readLaunch(file, process.pid, origin))
  fs.chmodSync(file, 0o600)
  fs.renameSync(file, file + '.real')
  fs.symlinkSync(file + '.real', file)
  assert.throws(() => readLaunch(file, process.pid, origin))
  fs.unlinkSync(file)
  fs.renameSync(file + '.real', file)
  write({ pid: process.pid, url: trapUrl + '?token=synthetic-launch' })
  assert.throws(() => readLaunch(file, process.pid, origin))
  write({ pid: process.pid, url: origin.href + '?token=synthetic-launch' })
  for (const suffix of ['; Domain=127.0.0.1; HttpOnly; SameSite=Strict; Path=/', '; HttpOnly; SameSite=Lax; Path=/', '; SameSite=Strict; Path=/']) {
    assert.throws(() => parseCookie({ 'set-cookie': [pair + suffix] }, origin))
  }
  const cookie = await exchangeLaunch(file, process.pid, origin)
  assert.equal(handshakes, 1)
  assert.equal(cookie.httpOnly, true)
  assert.equal(cookie.sameSite, 'strict')
  assert.equal(cookie.expirationDate, undefined)

  const ses = session.fromPartition('prime-synthetic-' + randomUUID(), { cache: false })
  assert.equal(ses.isPersistent(), false)
  await ses.setProxy({ mode: 'direct' })
  guardSession(ses, origin)
  await ses.cookies.set(cookie)
  assert.equal((await session.defaultSession.cookies.get({ name: cookieName })).length, 0)
  window = new BrowserWindow({ show: false, webPreferences: webPreferences(ses) })
  guardContents(window.webContents, origin)
  await window.loadURL(origin.href)
  const prefs = window.webContents.getLastWebPreferences()
  assert.equal(prefs.sandbox, true)
  assert.equal(prefs.contextIsolation, true)
  assert.equal(prefs.nodeIntegration, false)
  assert.equal(prefs.webSecurity, true)
  assert.equal(prefs.preload, undefined)
  assert.equal(prefs.webviewTag, false)
  const js = source => window.webContents.executeJavaScript(source)
  assert.deepEqual(await js('({require: typeof require, process: typeof process, tokenVisible: location.href.includes("token="), cookieVisible: document.cookie.includes("dsh-auth-")})'),
    { require: 'undefined', process: 'undefined', tokenVisible: false, cookieVisible: false })
  assert.equal(await js('fetch("/asset").then(r=>r.ok)'), true)
  assert.equal(assets, 1)
  assert.equal(await js('fetch(' + JSON.stringify(trapUrl) + ').then(()=>true,()=>false)'), false)
  assert.equal(await js('window.open(' + JSON.stringify(trapUrl) + ') === null'), true)
  await js('location.assign(' + JSON.stringify(trapUrl) + ')')
  await pause(200)
  assert.equal(window.webContents.getURL(), origin.href)
  await js('const frame=document.createElement("iframe"); frame.src=' + JSON.stringify(trapUrl) + '; document.body.append(frame)')
  await pause(200)
  await js('location.assign("/redirect")')
  await pause(300)
  assert.equal(trapRequests, 0)
  await window.loadURL(origin.href)
  assert.equal(await js('Notification.requestPermission()'), 'denied')
  assert.equal(await js('navigator.clipboard.writeText("synthetic").then(()=>true,()=>false)'), false)
  assert.equal(await js('navigator.clipboard.readText().then(()=>true,()=>false)'), false)
  assert.equal(await js('navigator.mediaDevices.getUserMedia({audio:true}).then(s=>{s.getTracks().forEach(t=>t.stop());return true},()=>false)'), false)
  await js('const a=document.createElement("a"); a.href="/download"; a.download="synthetic.txt"; document.body.append(a); a.click()')
  await pause(300)
  assert.equal(downloads, 1)
  assert.equal(fs.existsSync(path.join(app.getPath('downloads'), 'synthetic.txt')), false)
  assert.equal(BrowserWindow.getAllWindows().length, 1)
  assert.equal(trapRequests, 0)
  console.log(JSON.stringify({ check: 'PASS', electron: process.versions.electron,
    groups: ['origin-url-boundary', 'private-descriptor', 'manual-auth-exchange', 'session-isolation',
      'renderer-sandbox', 'navigation-popup-network', 'permissions', 'downloads'],
    external_requests: trapRequests, owner_authority: 'NOT_TESTED', real_backend: 'NOT_ACCESSED' }))
  await ses.clearStorageData()
  window.destroy()
  server.close(); trap.close()
  fs.rmSync(temp, { recursive: true, force: true })
  app.exit(0)
}).catch(error => {
  console.error('PRIME_PREVIEW_SYNTHETIC_CHECK_FAILED', error.code ?? error.name)
  window?.destroy(); server?.close(); trap?.close()
  fs.rmSync(temp, { recursive: true, force: true })
  app.exit(1)
})
