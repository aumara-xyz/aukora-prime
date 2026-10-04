// The boundary's allowlist: declarative, schema-validated targets ONLY. No code targets (no plugin installs,
// no harness code, no policy, keys or launcher); the earlier lab's `plugins/user/<name>/index.js` code target
// was removed on purpose and must not come back. Two targets exist: the UI theme accent (agent-proposable) and the
// operator-only plugin-set approval (raised on the owner channel; its receipt is what the launcher accepts).
import path from 'node:path'
import fs from 'node:fs'
import { createHash } from 'node:crypto'
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

// THE PLUGIN-SET APPROVAL (2026-10-04, gate as accepted signer). An OPERATOR-ONLY target: it is raised on the OWNER
// channel (ownerOps.raise) by root on the pilot, never proposed by an agent, and it is approved ONLY through the one owner
// ceremony (review -> decide_review in the Mac popup). Its bytes name exactly one installed release and its plugin set:
//   {"v":1,"kind":"aukora-plugin-set-approval/v1","release":<tipSha>,"release_dir":"release-<7>","plugin_set":<setDigest>,
//    "operation":<operation digest>,"record":<sha256 of .dsh-build/genesis-artifacts.json>}
// validate() rechecks release, set and record against the release ON DISK (a proposal can only name what is installed).
// The operation digest is NOT computed here (that would import release code into the gate); the composition gate
// recomputes it at every boot and refuses a receipt whose operation differs. A pending approval waits up to 24 h so an
// absent owner sees it (re-shown whenever the app is reopened); the 2-minute review challenge is unchanged.
export const PLUGIN_SET_TARGET = 'plugins/aukora-plugin-set/approval.json'
export const PLUGIN_SET_APPROVAL_KIND = 'aukora-plugin-set-approval/v1'
export const PLUGIN_SET_TTL_MS = 24 * 60 * 60 * 1000
export const PLUGIN_SET_CANONICAL = /^\{"v":1,"kind":"aukora-plugin-set-approval\/v1","release":"([0-9a-f]{40})","release_dir":"(release-[0-9a-f]{7})","plugin_set":"([0-9a-f]{64})","operation":"([0-9a-f]{64})","record":"([0-9a-f]{64})"\}$/
export function parsePluginSetApproval(text) {
  const m = PLUGIN_SET_CANONICAL.exec(typeof text === 'string' ? text : '')
  if (!m) return null
  return { release: m[1], release_dir: m[2], plugin_set: m[3], operation: m[4], record: m[5] }
}
export function pluginSetApprovalText({ release, release_dir, plugin_set, operation, record }) {
  const t = `{"v":1,"kind":"${PLUGIN_SET_APPROVAL_KIND}","release":"${release}","release_dir":"${release_dir}","plugin_set":"${plugin_set}","operation":"${operation}","record":"${record}"}`
  if (!parsePluginSetApproval(t)) throw new Error('plugin-set approval fields are not canonical')
  return t
}
const sha256File = (p) => createHash('sha256').update(fs.readFileSync(p)).digest('hex')
// The release as installed: its tip, its plugin-set digest, its record digest. Refuses symlinks and paths outside the root.
export function installedRelease(releasesRoot, releaseDir) {
  if (!/^release-[0-9a-f]{7}$/.test(releaseDir)) throw new Error('release_dir must be release-<7 hex>')
  const dir = path.join(releasesRoot, releaseDir), build = path.join(dir, '.dsh-build')
  for (const p of [dir, build]) if (fs.lstatSync(p).isSymbolicLink()) throw new Error(`symlink refused: ${p}`)
  const file = (n) => { const p = path.join(build, n); if (!fs.lstatSync(p).isFile()) throw new Error(`not a regular file: ${p}`); return p }
  const tip = JSON.parse(fs.readFileSync(file('aukora-release.json'), 'utf8')).tipSha
  const set = JSON.parse(fs.readFileSync(file('plugin-set.json'), 'utf8')).setDigest
  if (!/^[0-9a-f]{40}$/.test(String(tip)) || !/^[0-9a-f]{64}$/.test(String(set))) throw new Error('release records carry no tipSha/setDigest')
  return { release: tip, release_dir: releaseDir, plugin_set: set, record: sha256File(file('genesis-artifacts.json')) }
}
export function pluginSetTarget(targetRoot, { releasesRoot = '/opt/aukora-genesis' } = {}) {
  return {
    file: path.join(targetRoot, PLUGIN_SET_TARGET),
    entry: 'aukora-plugin-set', maxBytes: 512,
    operatorOnly: true, pendingClass: 'owner-release', ttlMs: PLUGIN_SET_TTL_MS,
    schema: `{"v":1,"kind":"${PLUGIN_SET_APPROVAL_KIND}","release":<40 hex>,"release_dir":"release-<7 hex>","plugin_set":<64 hex>,"operation":<64 hex>,"record":<64 hex>} — canonical bytes, operator-only`,
    canonical: PLUGIN_SET_CANONICAL,
    validate(text) {
      const a = parsePluginSetApproval(text)
      if (!a) throw new Error('plugin-set approval must be byte-exactly the canonical one-line JSON (fixed key order, lowercase hex)')
      if (a.release_dir !== 'release-' + a.release.slice(0, 7)) throw new Error('release_dir does not name this release')
      let on
      try { on = installedRelease(releasesRoot, a.release_dir) } catch (e) { throw new Error(`release ${a.release_dir} is not installed and readable: ${String(e.message).slice(0, 160)}`) }
      if (on.release !== a.release) throw new Error(`installed ${a.release_dir} is tip ${on.release}, not ${a.release}`)
      if (on.plugin_set !== a.plugin_set) throw new Error(`installed plugin set is ${on.plugin_set}, not ${a.plugin_set}`)
      if (on.record !== a.record) throw new Error(`installed release record is ${on.record}, not ${a.record}`)
    },
    plain(_oldText, newText) {
      const a = parsePluginSetApproval(newText)
      return a ? `ADMIT AUKORA PLUGIN SET | release ${a.release} (${a.release_dir}) | plugin set ${a.plugin_set} | operation ${a.operation} (rechecked at launch) | release record ${a.record}` : '(invalid plugin-set approval)'
    },
    after(newText) {
      const a = parsePluginSetApproval(newText)
      return a ? `AFTER APPLY: the gate signs a receipt for exactly plugin set ${a.plugin_set.slice(0, 16)}... of release ${a.release.slice(0, 7)}; the operator installs it and only then may the waiver be removed. Nothing is admitted by this click alone.` : 'AFTER APPLY: (invalid)'
    },
  }
}

// The registry the production gate serves. Every name is checked; every spec must be declarative.
export function allowlist(targetRoot, { releasesRoot } = {}) {
  if (typeof targetRoot !== 'string' || !path.isAbsolute(targetRoot) || path.normalize(targetRoot) !== targetRoot || targetRoot === '/') throw new Error('target root must be a normalized absolute path')
  const reg = { [THEME_TARGET]: themeTarget(targetRoot), [PLUGIN_SET_TARGET]: pluginSetTarget(targetRoot, releasesRoot ? { releasesRoot } : {}) }
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
