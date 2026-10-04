// aukora-auma-theme — Auma's theme through the boundary gate (L2 demo, 2026-10-04).
//
// HOST HALF (this file), Linux pilot only:
//   1. Registers `aukora_gate_propose`: Auma PROPOSES a theme accent. The harness (aukora-host) sends it on the gate's
//      PROPOSE socket with the propose-only client in propose.mjs. It cannot approve: the client has no approve op, the
//      gate's PROPOSE socket refuses approval ops, and the OWNER socket is 0600 aukora-gate (reached only from the owner's
//      Mac). The action gate must list the name (overlays/action-gate.patch.yml allowTools) or it refuses the call.
//   2. Serves `GET /api/aukora/theme` -> {accent}: the gate-applied theme, read through the same PROPOSE socket `read` op.
//      Authenticated by the host's own connection.requestRejection, like the Kira routes.
// CLIENT HALF (lib/client.js): polls that route and applies the accent as a Cordis theme override layer, so an approved
// change shows in the owner's window with no restart; a refused one changes nothing.
import { ACCENT, THEME_TARGET, accentOf, gateCall, proposeTheme } from './propose.mjs'

export const name = 'aukora-auma-theme'
export const inject = ['tools', 'webServer', 'connection']
export const TOOL_NAME = 'aukora_gate_propose'
export const THEME_ROUTE = '/api/aukora/theme'

export function createProposeTool({ socketPath, call = gateCall }) {
  return {
    name: TOOL_NAME,
    description: 'Propose a change to the UI theme accent through the boundary gate. PROPOSE ONLY: this opens an approval '
      + 'popup on the owner\'s screen showing the exact bytes; only the owner can approve or refuse it, and you cannot. '
      + 'accent is "default" or a #RRGGBB colour (e.g. gold = #FFD700). One proposal can be pending at a time; it expires after 5 minutes.',
    parameters: { type: 'object', additionalProperties: false, required: ['accent', 'why'], properties: {
      accent: { type: 'string', pattern: '^(default|#[0-9A-Fa-f]{6})$', description: '"default" or #RRGGBB' },
      why: { type: 'string', maxLength: 200, description: 'one line the owner sees in the popup' },
    } },
    timeoutMs: 20_000,
    isConcurrencySafe: () => false,
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args, exec) {
      try {
        if (args === null || typeof args !== 'object' || Array.isArray(args)) throw new Error('arguments must be {accent, why}')
        const extra = Object.keys(args).filter(k => k !== 'accent' && k !== 'why')
        if (extra.length > 0) throw new Error(`unknown argument(s) ${extra.join(', ')}; this tool only proposes`)
        if (typeof args.accent !== 'string' || !ACCENT.test(args.accent)) throw new Error('accent must be "default" or #RRGGBB')
        const session = exec?.sessionId ?? exec?.session?.id ?? ''
        return JSON.stringify(await proposeTheme(socketPath, { accent: args.accent, why: args.why, session }, call))
      } catch (error) {
        return JSON.stringify({ ok: false, state: 'REFUSED', reason: String(error?.message ?? error) })
      }
    },
  }
}

export function themeHandler({ socketPath, connection, call = gateCall }) {
  return async (req, res) => {
    const ask = connection?.requestRejection
    if (typeof ask !== 'function') { res.statusCode = 403; res.end(); return }
    const rejection = ask.call(connection, req)
    if (rejection !== undefined && rejection !== null && rejection !== false) {
      res.statusCode = typeof rejection === 'number' ? rejection : 403; res.end(); return
    }
    if (String(req.method ?? 'GET').toUpperCase() !== 'GET') { res.statusCode = 405; res.setHeader('allow', 'GET'); res.end(); return }
    let accent = 'default', available = true
    try { accent = accentOf((await call(socketPath, 'read', { target: THEME_TARGET }))?.content) } catch { available = false }
    res.statusCode = 200
    res.setHeader('content-type', 'application/json')
    res.setHeader('cache-control', 'no-store')
    res.end(JSON.stringify({ accent, available }))
  }
}

export function apply(ctx, config = {}) {
  if (process.platform !== 'linux') return // The gate exists only on the Linux pilot; elsewhere this plugin is inert.
  const socketPath = typeof config.proposeSocket === 'string' && config.proposeSocket.startsWith('/') ? config.proposeSocket : '/run/aukora-gate/gate.sock'
  ctx.tools.register(createProposeTool({ socketPath }))
  const webServer = ctx.get?.('webServer') ?? ctx.webServer
  const connection = ctx.get?.('connection') ?? ctx.connection
  if (webServer && typeof webServer.register === 'function') {
    ctx.effect(() => webServer.register({ kind: 'exact', path: THEME_ROUTE, handler: themeHandler({ socketPath, connection }) }),
      `aukora-auma-theme: ${THEME_ROUTE}`)
  }
  console.info('AUKORA_AUMA_THEME_REGISTERED', TOOL_NAME, THEME_ROUTE)
}
