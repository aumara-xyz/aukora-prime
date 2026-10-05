// staging only: judge file-tool calls with the INSTALLED release's action-gate plugin. Guard decisions only; the
// guard never reads file bytes. Canaries are harmless marker files inside a disposable workspace.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
const [,, rel] = process.argv
const { apply } = await import(join(rel, 'plugins/aukora-action-gate/lib/index.mjs'))
const root = mkdtempSync('/var/tmp/canary-')
const ws = join(root, 'workspace'); mkdirSync(ws, { recursive: true })
const can = { 'auma.key': 'canary/.config/aukora-relay/auma.key', 'nostr': 'canary/state/home/nostr/identity.json',
  'credentials': 'canary/state/home/.credentials.yaml', 'launch': 'canary/state/launch-url.json', 'plain': 'clean/notes.txt' }
for (const p of Object.values(can)) { mkdirSync(join(ws, p, '..'), { recursive: true }); writeFileSync(join(ws, p), 'CANARY harmless marker\n') }
let guard
const defs = new Map(); apply({ tools: { guard(v) { guard = v }, get(n) { if (!defs.has(n)) defs.set(n, {}); return defs.get(n) } }, get() { return undefined } }, {
  auraDir: join(root, 'aura'), dshHome: '/home/aukora-host/genesis/state/home', home: '/home/aukora-host', supportRoot: join(root, 'support'),
  repoRoots: [], releaseRoots: [], readRoots: [], defaultWorkspace: ws, confineReads: true, allowLoopback: false, networkAllow: [] })
const j = (name, args) => { const r = guard({ name, arguments: args, agent: { id: 'canary', session: { header: { cwd: ws } } } }); return r === undefined ? 'ALLOWED' : 'DENIED ' + String(r?.reason ?? r?.message ?? JSON.stringify(r)).slice(0, 90).replace(/\n/g, ' ') }
const real = ['/home/aukora-host/genesis/state/home/.credentials.yaml', '/home/aukora-host/.config/aukora-relay/auma.key',
  '/home/aukora-host/genesis/state/home/nostr/identity.json', '/home/aukora-host/genesis/state/launch-url.json']
console.log('release', rel)
for (const p of real) console.log('real   read', p, '->', j('read', { file_path: p }))
for (const [k, p] of Object.entries(can)) {
  const f = join(ws, p)
  console.log('canary read', k.padEnd(11), '->', j('read', { file_path: f }))
  console.log('canary grep', k.padEnd(11), '->', j('grep', { pattern: 'CANARY', path: join(f, '..') }))
}
console.log('canary grep whole-workspace ->', j('grep', { pattern: 'CANARY', path: ws }))
