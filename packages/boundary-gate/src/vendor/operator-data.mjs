// SPDX-License-Identifier: AGPL-3.0-or-later
// Builtin-only operator data/socket closure; hash checked before execution by BOTH operator entrypoints.
// Extracted from boundary-gate targets.mjs and server.mjs at public Prime63f6019.
// Retains canonical approval fields, installed-release digest and Unix RPC grammar. Adds a bounded reply and leaf no-follow refusal.
// No candidate module loader, subprocess, owner page, credentials, ledger or code-target helper is imported.
import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import { createHash } from 'node:crypto'

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
  const file = (n) => { const p = path.join(build, n); const st = fs.lstatSync(p); if (st.isSymbolicLink() || !st.isFile()) throw new Error(`not a regular file: ${p}`); return p }
  const tip = JSON.parse(fs.readFileSync(file('aukora-release.json'), 'utf8')).tipSha
  const set = JSON.parse(fs.readFileSync(file('plugin-set.json'), 'utf8')).setDigest
  if (!/^[0-9a-f]{40}$/.test(String(tip)) || !/^[0-9a-f]{64}$/.test(String(set))) throw new Error('release records carry no tipSha/setDigest')
  return { release: tip, release_dir: releaseDir, plugin_set: set, record: sha256File(file('genesis-artifacts.json')) }
}

export function call(sockPath, op, args = {}, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const c = net.createConnection(sockPath); let buf = ''; let received = 0
    const t = setTimeout(() => { c.destroy(); reject(new Error('gate timeout (fail closed)')) }, timeoutMs)
    c.on('connect', () => c.write(JSON.stringify({ op, args }) + '\n'))
    c.on('data', d => { received += d.length; if (received > 1024 * 1024) { clearTimeout(t); c.destroy(); reject(new Error('gate: reply too large (fail closed)')); return }; buf += d })
    c.on('end', () => { clearTimeout(t); let r; try { r = JSON.parse(buf) } catch { return reject(new Error('gate: bad reply (fail closed)')) } r.ok ? resolve(r.result) : reject(new Error(r.error)) })
    c.on('error', e => { clearTimeout(t); reject(Object.assign(new Error(`gate unavailable (${e.code}); fail closed`), { code: e.code })) })
  })
}
