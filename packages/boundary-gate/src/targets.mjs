// The boundary's allowlist: declarative, schema-validated targets ONLY. No code targets (no plugin installs,
// no harness code, no policy, keys or launcher); the earlier lab's `plugins/user/<name>/index.js` code target
// was removed on purpose and must not come back. Today exactly one target exists: the UI theme accent.
import path from 'node:path'
import { colorName } from './card.mjs'

export const THEME_TARGET = 'plugins/auma-theme/theme.json'
const CANONICAL = /^\{"accent": "(default|#[0-9A-F]{6})"\}$/

// A target name must be a relative path under plugins/, without "..", absolute parts, empty or dot segments,
// backslashes or control characters. (Symlinks are refused at read/write time by the store.)
export function assertTargetName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 200) throw new Error('target name refused: empty or too long')
  if (path.isAbsolute(name) || name.includes('\\') || /[\x00-\x1f\x7f]/.test(name)) throw new Error('target name refused: absolute path, backslash or control character')
  const parts = name.split('/')
  if (parts[0] !== 'plugins' || parts.length < 3 || parts.some(p => p === '' || p === '.' || p === '..')) throw new Error('target name refused: must be plugins/<entry>/<file> without "." or ".." segments')
  if (path.posix.normalize(name) !== name) throw new Error('target name refused: not normalized')
  return name
}

export function themeTarget(targetRoot) {
  return {
    file: path.join(targetRoot, THEME_TARGET),
    entry: 'auma-theme', maxBytes: 256,
    schema: '{"accent": "default" | "#RRGGBB"} — exactly one key, JSON object, ≤256 bytes',
    // Canonical bytes ONLY: exactly {"accent": "default"} or {"accent": "#RRGGBB"} with UPPERCASE hex, one space
    // after the colon, no newline, nothing else. Kills duplicate keys, \u escapes, case/whitespace/CRLF variants.
    canonical: CANONICAL,
    validate(text) {
      if (CANONICAL.test(text)) return
      let hint = ''
      try { const j = JSON.parse(text); if (j && typeof j.accent === 'string' && /^(default|#[0-9a-fA-F]{6})$/.test(j.accent) && Object.keys(j).length === 1) hint = ` Canonical form of the parsed value would be ${JSON.stringify({ accent: j.accent === 'default' ? 'default' : j.accent.toUpperCase() }).replace('":"', '": "')} (only if that is really what you mean: duplicate keys/escapes are refused).` } catch {}
      throw new Error('theme.json must be byte-exactly {"accent": "#RRGGBB"} (uppercase hex) or {"accent": "default"}: one key, one space after the colon, no newline, no escapes.' + hint)
    },
    accentOf(text) { const m = CANONICAL.exec(text || ''); return m ? m[1] : null },
    plain(oldText, newText) { const a = this.accentOf(oldText) ?? '(non-canonical)', b = this.accentOf(newText) ?? '(invalid)'; return `accent: ${a} ${colorName(a)} -> ${b} ${colorName(b)}` },
    after(newText) { const b = this.accentOf(newText); return `AFTER APPLY: accent = ${b} (${colorName(b)})` },
  }
}

// The registry the production gate serves. Every name is checked; every spec must be declarative.
export function allowlist(targetRoot) {
  if (typeof targetRoot !== 'string' || !path.isAbsolute(targetRoot) || path.normalize(targetRoot) !== targetRoot || targetRoot === '/') throw new Error('target root must be a normalized absolute path')
  const reg = { [THEME_TARGET]: themeTarget(targetRoot) }
  for (const [name, s] of Object.entries(reg)) {
    assertTargetName(name)
    if (/\.(m?js|cjs|ts|sh|py|node|so)$/i.test(name)) throw new Error(`allowlist invariant: code target ${name} refused`)
    if (path.relative(targetRoot, s.file) !== name) throw new Error(`allowlist invariant: ${name} escapes the target root`)
    if (!(s.maxBytes > 0 && s.maxBytes <= 4096) || typeof s.validate !== 'function') throw new Error(`allowlist invariant: ${name} must be small and schema-validated`)
  }
  return Object.freeze(reg)
}

// Harness-side consumer of the theme: the same canonical-bytes rule; anything else falls back to "default".
export function readThemeText(raw) {
  if (typeof raw !== 'string' || !CANONICAL.test(raw)) return { accent: 'default', valid: false }
  return { accent: JSON.parse(raw).accent, valid: true }
}
