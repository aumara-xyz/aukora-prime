#!/usr/bin/env node
// Boundary gate entry (run as the gate user, e.g. `sudo -n -u aukora-gate -H node bin/gate.mjs serve ...`).
//   serve  --home DIR --run DIR --target-root DIR [--owner-page [--port 17792]] [--gid N] [--time-zone Area/City]
//          The owner web page is OFF unless --owner-page; the popup (owner socket review -> decide_review) is the ceremony.
//   verify --home DIR | --db FILE --pub FILE      (ledger chain + signatures; exit 0 ok / 1 broken)
//   verify-receipt --db FILE --pub FILE --receipt FILE   (receipt JSON {receipt, receipt_sig}; exit 0 ok / 1 not)
// umask 027 is applied before anything is created. The allowlist is the reviewed declarative registry in
// src/targets.mjs (theme accent only), stored under --target-root.
import fs from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { createPublicKey } from 'node:crypto'
import { createGate } from '../src/gate.mjs'
import { serveGate } from '../src/server.mjs'
import { rotateBearer, loadOwnerSecret } from '../src/secrets.mjs'
import { openDb, verifyLedger, loadOrCreateKey, keyFingerprint } from '../src/ledger.mjs'
import { gateTargets, gateStore } from '../src/wiring.mjs'
import { verifyReceipt } from '../src/receipts.mjs'

process.umask(0o027)
const [cmd, ...rest] = process.argv.slice(2)
const { values: o } = parseArgs({ args: rest, options: { home: { type: 'string' }, run: { type: 'string' }, port: { type: 'string' }, gid: { type: 'string' },
  'time-zone': { type: 'string' }, db: { type: 'string' }, pub: { type: 'string' }, 'target-root': { type: 'string' }, receipt: { type: 'string' }, 'owner-page': { type: 'boolean' } }, strict: true })
const abs = (label, p) => { if (!p || !path.isAbsolute(p)) { console.error(`--${label} must be an absolute path`); process.exit(2) } return p }

if (cmd === 'verify') {
  const pub = o.pub ? createPublicKey(fs.readFileSync(abs('pub', o.pub))) : loadOrCreateKey(abs('home', o.home)).pub
  const db = openDb(o.db ? abs('db', o.db) : path.join(abs('home', o.home), 'gate.db'), { readOnly: true })
  const r = verifyLedger(db, pub)
  console.log(JSON.stringify({ ...r, pubkey_fp: keyFingerprint(pub) }, null, 1)); process.exit(r.ok ? 0 : 1)
} else if (cmd === 'verify-receipt') {
  const db = openDb(abs('db', o.db), { readOnly: true })
  const { receipt, receipt_sig } = JSON.parse(fs.readFileSync(abs('receipt', o.receipt), 'utf8'))
  const r = verifyReceipt(db, receipt, receipt_sig, fs.readFileSync(abs('pub', o.pub), 'utf8'))
  console.log(JSON.stringify(r, null, 1)); process.exit(r.ok ? 0 : 1)
} else if (cmd === 'serve') {
  const home = abs('home', o.home), runDir = abs('run', o.run)
  const owner = loadOwnerSecret(home)
  const bearerInfo = rotateBearer(home, owner)
  const gate = createGate({ home, owner, targets: gateTargets(abs('target-root', o['target-root'])), store: gateStore({ gid: Number(o.gid) || 0 }) })
  const v = gate.startup({ bearerInfo })
  if (!v.ok) console.error('LEDGER VERIFY FAILED', v.errors)
  const srv = await serveGate(gate, { runDir, gid: Number(o.gid) || 0, ownerHttpPort: Number(o.port ?? 17792), timeZone: o['time-zone'] ?? 'UTC', ownerPage: o['owner-page'] === true })
  console.log(`boundary-gate PROPOSE ${srv.proposeSocket} OWNER ${srv.ownerSocket} (0600) OWNER-HTTP ${srv.port === null ? 'off' : 'loopback:' + srv.port} pubkey ${gate.fp} targets ${Object.keys(gate.targets).length}`)
  const stop = () => srv.close().finally(() => { gate.close(); process.exit(0) })
  process.on('SIGTERM', stop); process.on('SIGINT', stop)
} else {
  console.error('usage: gate.mjs serve --home DIR --run DIR --target-root DIR [--port N] [--gid N] [--time-zone TZ] | verify (--home DIR | --db FILE --pub FILE) | verify-receipt --db FILE --pub FILE --receipt FILE'); process.exit(2)
}
