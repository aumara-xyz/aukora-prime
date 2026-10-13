// Refuse non-bootstrap requests and Remote methods until the node has a readable binding.
export const name = 'aukora-browser-bootstrap'
export const inject = ['aumlokControl']
export const BINDING_REQUIRED = 'browser-node:binding-required'

export const BOOT_RPC = Object.freeze([
  '$events', 'credentials/describe', 'agentPresets/list', 'session/modelCatalog',
  'permissionPresets/catalog',
])
const rpc = new Set(BOOT_RPC)

const reads = new Set([
  '/api/aukora/theme', '/api/aukora/aura-snapshot',
  // The public contact card (/api/aukora/aumlok-identity) is NOT readable before binding: it is not
  // needed by the first screen and can create a messaging identity (independent review, 2026-10-14).
  '/api/aukora/aumlok-control',
])
const binding = new Set(['prepare', 'bind', 'cancel', 'status']
  .map(verb => `/api/aukora/aumlok-binding/${verb}`))
const staticFiles = new Set(['/', '/favicon.svg', '/favicon.ico', '/manifest.webmanifest'])

export function createBrowserAccess(control) {
  function bound() {
    try { control.refresh(); return true } catch { return false }
  }
  return Object.freeze({
    rpcRejection(endpoint) {
      if (bound()) return undefined
      return rpc.has(endpoint) ? undefined : BINDING_REQUIRED
    },
    requestRejection(request, upgrade = false) {
      if (bound()) return undefined
      let path
      try { path = new URL(request.url, 'http://node').pathname }
      catch { return BINDING_REQUIRED }
      // No path with an empty segment, an encoded slash or a backslash is static content; refusing them
      // keeps a later router from folding one onto a path this guard denies (independent review, 2026-10-14).
      if (path.includes('//') || /%2f|%5c|\\/iu.test(String(request.url))) return BINDING_REQUIRED
      if (upgrade) return request.method === 'GET' && path === '/api/remote.mux'
        ? undefined : BINDING_REQUIRED
      const read = request.method === 'GET' || request.method === 'HEAD'
      if (read && (staticFiles.has(path)
        || path.startsWith('/assets/')
        // Brand images the first screen draws (seen broken on a rehearsal node when refused).
        || path.startsWith('/branding/')
        || (path.startsWith('/plugins/') && path !== '/plugins/events'
          && !path.startsWith('/plugins/events/')))) return undefined
      if (request.method === 'GET' && reads.has(path)) return undefined
      if (request.method === 'POST' && binding.has(path)) return undefined
      if (request.method === 'POST' && path.startsWith('/api/') && rpc.has(path.slice(5))) return undefined
      return BINDING_REQUIRED
    },
  })
}

export function apply(ctx) {
  ctx.provide('aukoraBrowserAccess', createBrowserAccess(ctx.aumlokControl))
}
