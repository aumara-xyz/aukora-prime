'use strict'

const { app, BrowserWindow, session, Menu } = require('electron')
const { mkdtempSync, mkdirSync, rmSync } = require('node:fs')
const { tmpdir } = require('node:os')
const { join } = require('node:path')
const { randomUUID } = require('node:crypto')
const { TITLE, trustedOrigin, webPreferences, guardSession, guardContents } = require('./policy.cjs')
const { exchangeLaunch } = require('./launch-access.cjs')

app.setName(TITLE)
app.enableSandbox()
const profile = mkdtempSync(join(tmpdir(), 'aukora-prime-preview-'))
app.setPath('userData', profile)
app.setPath('sessionData', profile)
const crashDir = join(profile, 'crashes')
mkdirSync(crashDir, { mode: 0o700 })
app.setPath('crashDumps', crashDir)
app.setAppLogsPath(join(profile, 'logs'))
app.on('will-quit', () => { try { rmSync(profile, { recursive: true, force: true }) } catch {} })
app.on('window-all-closed', () => app.quit())
app.on('open-url', event => event.preventDefault())
app.on('open-file', event => event.preventDefault())

let window
app.whenReady().then(async () => {
  const origin = trustedOrigin(process.env.PRIME_PREVIEW_ORIGIN)
  const pid = Number(process.env.PRIME_PREVIEW_EXPECTED_PID)
  const ses = session.fromPartition('aukora-prime-preview-' + randomUUID(), { cache: false })
  await ses.setProxy({ mode: 'direct' })
  guardSession(ses, origin)
  let cookie = await exchangeLaunch(process.env.PRIME_PREVIEW_ACCESS_FILE, pid, origin)
  await ses.cookies.set(cookie)
  cookie = undefined
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: TITLE, submenu: [{ role: 'about' }, { type: 'separator' }, { role: 'quit' }] },
    { label: 'Edit', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' },
      { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: 'Window', submenu: [{ role: 'minimize' }, { role: 'close' }] }
  ]))
  window = new BrowserWindow({ title: TITLE, width: 1560, height: 960, minWidth: 480, minHeight: 420,
    backgroundColor: '#0B0E14', show: false, webPreferences: webPreferences(ses) })
  guardContents(window.webContents, origin)
  await window.loadURL(origin.href)
  window.setTitle(TITLE)
  window.show()
  console.log(JSON.stringify({ preview: 'WINDOW_OPEN', app: TITLE, electron: process.versions.electron,
    desktop_pid: process.pid, remote_pid: pid, origin: origin.origin, credential_persisted: false }))
}).catch(() => {
  // Never include arbitrary parser/network errors, URL, cookies, or renderer logs.
  console.error('PRIME_PREVIEW_LAUNCH_FAILED: check the current private descriptor, PID and SSH tunnel')
  app.exit(1)
})
