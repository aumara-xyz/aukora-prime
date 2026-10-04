// The PROPOSE-ONLY client this plugin uses on the boundary gate's PROPOSE socket (0660 aukora-gate:skgate; the harness
// user aukora-host is in skgate, the agent user auma is not). It can send exactly two ops — `read` and `propose` — and
// nothing else: no approve, decide, review, decide_review, close or revert. The gate's PROPOSE socket refuses approval
// ops on its own side too (packages/boundary-gate/src/gate.mjs invariant); this allowlist is the second wall.
import net from 'node:net'

export const THEME_TARGET = 'plugins/auma-theme/theme.json'
export const PROPOSE_OPS = Object.freeze(['read', 'propose'])
export const ACCENT = /^(default|#[0-9A-Fa-f]{6})$/u

export function gateCall(socketPath, op, args, timeoutMs = 10000) {
  if (!PROPOSE_OPS.includes(op)) return Promise.reject(new Error(`auma-theme: op ${String(op)} is not a propose-side op`))
  return new Promise((resolve, reject) => {
    const c = net.createConnection(socketPath); let buf = ''
    const t = setTimeout(() => { c.destroy(); reject(new Error('gate timeout (fail closed)')) }, timeoutMs)
    c.on('connect', () => c.write(JSON.stringify({ op, args }) + '\n'))
    c.on('data', d => { buf += d; if (buf.length > 1 << 16) { c.destroy(); clearTimeout(t); reject(new Error('gate reply too large')) } })
    c.on('end', () => {
      clearTimeout(t); let r
      try { r = JSON.parse(buf) } catch { return reject(new Error('gate: bad reply (fail closed)')) }
      return r && r.ok === true ? resolve(r.result) : reject(new Error(String(r?.error ?? 'gate refused')))
    })
    c.on('error', e => { clearTimeout(t); reject(new Error(`gate unavailable (${e.code ?? 'error'}); fail closed`)) })
  })
}

/** Canonical theme bytes the gate's schema accepts: exactly {"accent": "default"} or {"accent": "#RRGGBB"} (uppercase). */
export function themeContent(accent) {
  if (typeof accent !== 'string' || !ACCENT.test(accent)) throw new Error('accent must be "default" or #RRGGBB')
  return `{"accent": "${accent === 'default' ? 'default' : accent.toUpperCase()}"}`
}

/** The accent in canonical theme bytes, or 'default' for anything else (absent, unreadable, non-canonical). */
export function accentOf(content) {
  const m = /^\{"accent": "(default|#[0-9A-F]{6})"\}$/u.exec(typeof content === 'string' ? content : '')
  return m ? m[1] : 'default'
}

/** Propose a theme change. Returns a plain result; never approves, never retries. */
export async function proposeTheme(socketPath, { accent, why, session }, call = gateCall) {
  const content = themeContent(accent)
  const cur = await call(socketPath, 'read', { target: THEME_TARGET })
  if (cur?.content === content) return { ok: false, state: 'REFUSED', reason: `the theme is already ${accentOf(content)}` }
  const p = await call(socketPath, 'propose', {
    target: THEME_TARGET, content, why: String(why ?? '').slice(0, 200), claimed_base: cur?.sha256 ?? 'absent', session: String(session ?? ''),
  })
  return {
    ok: true, state: 'PENDING_OWNER', proposal: String(p?.id ?? '').slice(0, 8), target: THEME_TARGET, accent: accentOf(content),
    expires: p?.expires ? new Date(p.expires).toISOString() : null,
    message: 'Proposed. An approval popup is now on the owner\'s screen; only the owner can Approve or Refuse. You cannot approve it.',
  }
}
