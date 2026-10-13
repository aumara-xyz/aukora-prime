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
  '/api/aukora/aumlok-control', '/api/aukora/aumlok-identity',
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
      if (upgrade) return request.method === 'GET' && path === '/api/remote.mux'
        ? undefined : BINDING_REQUIRED
      const read = request.method === 'GET' || request.method === 'HEAD'
      if (read && (staticFiles.has(path)
        || path.startsWith('/assets/')
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
