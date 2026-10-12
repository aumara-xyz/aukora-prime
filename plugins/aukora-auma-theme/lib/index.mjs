// Registers a propose-only theme or note tool and serves the authenticated theme route.
import { ACCENT, THEME_TARGET, NOTE_TARGET, accentOf, gateCall, proposeTheme, proposeNote } from './propose.mjs'

export const name = 'aukora-auma-theme'
export const inject = ['tools', 'webServer', 'connection']
export const TOOL_NAME = 'aukora_gate_propose'
export const THEME_ROUTE = '/api/aukora/theme'

export function createProposeTool({ socketPath, call = gateCall }) {
  return {
    name: TOOL_NAME,
    description: 'Propose a UI theme accent or replace the owner note through the boundary gate. PROPOSE ONLY: this opens an approval '
      + 'popup on the owner\'s screen showing the exact bytes; only the owner can approve or refuse it, and you cannot. '
      + 'Omit target for the theme: accent is "default" or a #RRGGBB colour (e.g. gold = #FFD700). '
      + 'For plugins/owner-note/note.md, supply text (exact plain UTF-8, at most 2,000 bytes) instead of accent. '
      + 'One proposal can be pending at a time; it expires after 5 minutes.',
    parameters: { type: 'object', additionalProperties: false, required: ['why'], properties: {
      target: { type: 'string', enum: [THEME_TARGET, NOTE_TARGET], description: 'Fixed target; defaults to the theme' },
      accent: { type: 'string', pattern: '^(default|#[0-9A-Fa-f]{6})$', description: '"default" or #RRGGBB' },
      text: { type: 'string', maxLength: 2000, description: 'Exact owner-note plain text; no markdown is rendered' },
      why: { type: 'string', maxLength: 200, description: 'one line the owner sees in the popup' },
    } },
    timeoutMs: 20_000,
    isConcurrencySafe: () => false,
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args, exec) {
      try {
        if (args === null || typeof args !== 'object' || Array.isArray(args)) throw new Error('arguments must be {accent, why}')
        const extra = Object.keys(args).filter(k => !['accent', 'why', 'target', 'text'].includes(k))
        if (extra.length > 0) throw new Error(`unknown argument(s) ${extra.join(', ')}; this tool only proposes`)
        const target = args.target === undefined ? THEME_TARGET : args.target
        if (target !== THEME_TARGET && target !== NOTE_TARGET) throw new Error('proposal-target-not-allowed')
        const session = exec?.sessionId ?? exec?.session?.id ?? ''
        if (target === NOTE_TARGET) {
          if (Object.hasOwn(args, 'accent')) throw new Error('note-accent-not-allowed')
          return JSON.stringify(await proposeNote(socketPath, { text: args.text, why: args.why, session }, call))
        }
        if (Object.hasOwn(args, 'text')) throw new Error('theme-text-not-allowed')
        if (typeof args.accent !== 'string' || !ACCENT.test(args.accent)) throw new Error('accent must be "default" or #RRGGBB')
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
