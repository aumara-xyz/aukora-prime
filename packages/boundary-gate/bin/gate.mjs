#!/usr/bin/env node
// Boundary gate entry (run as the gate user, e.g. `sudo -n -u aukora-gate -H node bin/gate.mjs serve ...`).
//   serve  --home DIR --run DIR [--port 17792] [--gid N] [--time-zone Area/City]
//   verify --home DIR | --db FILE --pub FILE      (ledger chain + signatures; exit 0 ok / 1 broken)
// umask 027 is applied before anything is created. No target is allowlisted by this entry unless a target
// registry is wired in; with an empty allowlist every proposal is refused (fail closed).
import fs from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { createPublicKey } from 'node:crypto'
import { createGate } from '../src/gate.mjs'
import { serveGate } from '../src/server.mjs'
import { rotateBearer, loadOwnerSecret } from '../src/secrets.mjs'
import { openDb, verifyLedger, loadOrCreateKey, keyFingerprint } from '../src/ledger.mjs'
import { gateTargets, gateStore } from '../src/wiring.mjs'

process.umask(0o027)
const [cmd, ...rest] = process.argv.slice(2)
const { values: o } = parseArgs({ args: rest, options: { home: { type: 'string' }, run: { type: 'string' }, port: { type: 'string' }, gid: { type: 'string' },
  'time-zone': { type: 'string' }, db: { type: 'string' }, pub: { type: 'string' }, 'target-root': { type: 'string' } }, strict: true })
const abs = (label, p) => { if (!p || !path.isAbsolute(p)) { console.error(`--${label} must be an absolute path`); process.exit(2) } return p }

if (cmd === 'verify') {
  const pub = o.pub ? createPublicKey(fs.readFileSync(abs('pub', o.pub))) : loadOrCreateKey(abs('home', o.home)).pub
  const db = openDb(o.db ? abs('db', o.db) : path.join(abs('home', o.home), 'gate.db'), { readOnly: true })
  const r = verifyLedger(db, pub)
  console.log(JSON.stringify({ ...r, pubkey_fp: keyFingerprint(pub) }, null, 1)); process.exit(r.ok ? 0 : 1)
} else if (cmd === 'serve') {
  const home = abs('home', o.home), runDir = abs('run', o.run)
  const owner = loadOwnerSecret(home)
  const bearerInfo = rotateBearer(home, owner)
  const gate = createGate({ home, owner, targets: gateTargets(), store: gateStore({ targetRoot: o['target-root'], gid: Number(o.gid) || 0 }) })
  const v = gate.startup({ bearerInfo })
  if (!v.ok) console.error('LEDGER VERIFY FAILED', v.errors)
  const srv = await serveGate(gate, { runDir, gid: Number(o.gid) || 0, ownerHttpPort: Number(o.port ?? 17792), timeZone: o['time-zone'] ?? 'UTC' })
  console.log(`boundary-gate PROPOSE ${srv.proposeSocket} OWNER ${srv.ownerSocket} (0600) OWNER-HTTP loopback:${srv.port} pubkey ${gate.fp} targets ${Object.keys(gate.targets).length}`)
  const stop = () => srv.close().finally(() => { gate.close(); process.exit(0) })
  process.on('SIGTERM', stop); process.on('SIGINT', stop)
} else {
  console.error('usage: gate.mjs serve --home DIR --run DIR [--port N] [--gid N] [--time-zone TZ] | verify (--home DIR | --db FILE --pub FILE)'); process.exit(2)
}
