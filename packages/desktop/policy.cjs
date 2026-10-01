'use strict'

const DEFAULT_ORIGIN = 'http://127.0.0.1:18731'
const TITLE = 'AUKORA Prime Preview'

function trustedOrigin(value = DEFAULT_ORIGIN) {
  const url = new URL(value)
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash
    || (value !== url.origin && value !== url.origin + '/')
    || (url.protocol !== 'https:' && url.origin !== DEFAULT_ORIGIN)) {
    throw new Error('PREVIEW_ORIGIN_INVALID')
  }
  return url
}

function allowsNavigation(value, origin) {
  try {
    const url = new URL(value)
    return url.origin === origin.origin && !url.username && !url.password
      && !url.searchParams.has('token')
  } catch { return false }
}

function allowsRequest({ url: value, resourceType }, origin) {
  if (allowsNavigation(value, origin)) return true
  try {
    const url = new URL(value)
    const socketProtocol = origin.protocol === 'https:' ? 'wss:' : 'ws:'
    return resourceType === 'webSocket' && url.protocol === socketProtocol
      && url.host === origin.host && !url.username && !url.password
      && !url.searchParams.has('token')
  } catch { return false }
}

function webPreferences(ses) {
  return {
    session: ses,
    sandbox: true,
    contextIsolation: true,
    nodeIntegration: false,
    nodeIntegrationInWorker: false,
    nodeIntegrationInSubFrames: false,
    webSecurity: true,
    allowRunningInsecureContent: false,
    webviewTag: false,
    experimentalFeatures: false,
    navigateOnDragDrop: false,
    devTools: false,
    safeDialogs: true,
    spellcheck: false,
    autoplayPolicy: 'document-user-activation-required'
  }
}

function guardSession(ses, origin) {
  ses.setPermissionRequestHandler((_contents, _permission, callback) => callback(false))
  ses.setPermissionCheckHandler(() => false)
  ses.setDevicePermissionHandler(() => false)
  ses.setDisplayMediaRequestHandler((_request, callback) => callback({}))
  ses.on('will-download', event => event.preventDefault())
  ses.on('select-hid-device', (event, _details, callback) => { event.preventDefault(); callback() })
  ses.on('select-usb-device', (event, _details, callback) => { event.preventDefault(); callback() })
  ses.on('select-serial-port', (event, _ports, _contents, callback) => { event.preventDefault(); callback('') })
  ses.on('file-system-access-restricted', (_event, _details, callback) => callback('deny'))
  ses.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => {
    callback({ cancel: !allowsRequest(details, origin) })
  })
  // Apply to every request, including the cookie-authenticated SPA and WebSocket.
  // A token is exchanged in Node before any page exists and is never a Referer.
  ses.webRequest.onBeforeSendHeaders({ urls: ['<all_urls>'] }, (details, callback) => {
    const headers = { ...details.requestHeaders }
    for (const name of Object.keys(headers)) if (name.toLowerCase() === 'referer') delete headers[name]
    callback({ requestHeaders: headers })
  })
}

function guardContents(contents, origin) {
  const denyOutside = (event, legacyUrl) => {
    if (!allowsNavigation(event.url ?? legacyUrl, origin)) event.preventDefault()
  }
  contents.on('will-navigate', denyOutside)
  contents.on('will-frame-navigate', denyOutside)
  contents.on('will-redirect', denyOutside)
  contents.setWindowOpenHandler(() => ({ action: 'deny' }))
  contents.on('will-attach-webview', event => event.preventDefault())
  contents.on('select-bluetooth-device', (event, _devices, callback) => { event.preventDefault(); callback('') })
  contents.on('page-title-updated', event => event.preventDefault())
  contents.on('content-bounds-updated', event => event.preventDefault())
}

module.exports = { DEFAULT_ORIGIN, TITLE, trustedOrigin, allowsNavigation, allowsRequest,
  webPreferences, guardSession, guardContents }
