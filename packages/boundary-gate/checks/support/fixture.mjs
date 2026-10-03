// Test-only support: a synthetic single-key accent target (same canonical shape the gate's cards understand)
// and an in-memory target store. Not a production allowlist.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { colorName } from '../../src/card.mjs'
import { createGate } from '../../src/gate.mjs'
import { loadOwnerSecret, rotateBearer } from '../../src/secrets.mjs'

const CANON = /^\{"accent": "(default|#[0-9A-F]{6})"\}$/
export const ACCENT = 'test/accent.json'
export const accentTarget = {
  entry: 'test-accent', maxBytes: 256, schema: '{"accent": "default" | "#RRGGBB"} (test fixture)',
  validate(text) { if (!CANON.test(text)) throw new Error('accent must be byte-exactly {"accent": "#RRGGBB"} or {"accent": "default"}') },
  accentOf(text) { const m = CANON.exec(text || ''); return m ? m[1] : null },
  plain(a, b) { const x = this.accentOf(a) ?? '(non-canonical)', y = this.accentOf(b) ?? '(invalid)'; return `accent: ${x} ${colorName(x)} -> ${y} ${colorName(y)}` },
  after(b) { const y = this.accentOf(b); return `AFTER APPLY: accent = ${y} (${colorName(y)})` },
}
export const accent = (hex) => `{"accent": "${hex}"}`

export function memoryStore(initial = {}) {
  const files = new Map(Object.entries(initial).map(([k, v]) => [k, Buffer.from(v)]))
  return { files, writes: 0, read: (t) => files.has(t) ? Buffer.from(files.get(t)) : null, write(t, _s, bytes) { this.writes++; files.set(t, Buffer.from(bytes)) } }
}

export function tmpHome() { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'boundary-gate-')); fs.chmodSync(d, 0o700); return d }

export function makeGate({ initial = { [ACCENT]: accent('#FFD700') }, limits = {}, targets = { [ACCENT]: accentTarget }, start = Date.UTC(2026, 9, 3, 12) } = {}) {
  const clock = { t: start }
  const home = tmpHome()
  const owner = loadOwnerSecret(home)
  rotateBearer(home, owner, () => clock.t)
  const store = memoryStore(initial)
  const gate = createGate({ home, owner, targets, store, limits, now: () => clock.t })
  gate.startup({ pid: 1 })
  return { gate, store, clock, home, owner }
}
