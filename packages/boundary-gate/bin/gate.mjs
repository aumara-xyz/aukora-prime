#!/usr/bin/env node
// Boundary gate entry (run as the gate user, e.g. `sudo -n -u aukora-gate -H node bin/gate.mjs serve ...`).
//   serve  --home DIR --run DIR --target-root DIR [--owner-page [--port 17792]] [--gid N] [--time-zone Area/City] [--journal-id aukora-gate-pilot]
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
import * as gateCore from '../src/gate.mjs'
import { serveGate } from '../src/server.mjs'
import { rotateBearer, loadOwnerSecret } from '../src/secrets.mjs'
import { openDb, verifyLedger, loadOrCreateKey, keyFingerprint } from '../src/ledger.mjs'
import { gateTargets, gateStore } from '../src/wiring.mjs'
import { verifyReceipt } from '../src/receipts.mjs'
import { readOwnerState } from '../host/owner-state.mjs'
import { checkGateReadiness } from '../host/readiness.mjs'

process.umask(0o027)
const [cmd, ...rest] = process.argv.slice(2)
const { values: o, tokens } = parseArgs({ args: rest, options: { home: { type: 'string' }, run: { type: 'string' }, port: { type: 'string' }, gid: { type: 'string' },
  'time-zone': { type: 'string' }, db: { type: 'string' }, pub: { type: 'string' }, 'target-root': { type: 'string' }, 'releases-root': { type: 'string' }, receipt: { type: 'string' }, 'owner-page': { type: 'boolean' }, 'journal-id': { type: 'string' } }, strict: true, tokens: true })
// This fixed public journal is an operator startup binding, never a request or
// model value. Reject incompatible commands before opening any gate state.
if (o['journal-id'] !== undefined && (cmd !== 'serve' || o['journal-id'] !== 'aukora-gate-pilot'
  || tokens.filter(token => token.kind === 'option' && token.name === 'journal-id').length !== 1)) {
  console.error('--journal-id requires serve and the fixed aukora-gate-pilot journal'); process.exit(2)
}
const abs = (label, p) => { if (!p || !path.isAbsolute(p)) { console.error(`--${label} must be an absolute path`); process.exit(2) } return p }

if (cmd === 'check-ready') {
  // A fixed readonly core verifier is required; absence is not a legacy-success fallback.
  // It owns retained-proof verification. This entry never constructs a mutable gate or key.
  if (rest.length !== 0) { console.error('boundary-gate:readiness-arguments-refused'); process.exit(2) }
  try {
    if (typeof gateCore.ownerAuthorizationReadiness !== 'function') throw new Error('readiness unavailable')
    readOwnerState()
    checkGateReadiness(() => gateCore.ownerAuthorizationReadiness({ home: '/home/aukora-gate', readOwnerState }))
    console.log('OWNER_AUTHORIZATION_READY')
  } catch { console.error('boundary-gate:readiness-unavailable'); process.exit(1) }
} else if (cmd === 'verify') {
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
  let gate, srv
  try {
    // The ordinary entry always requires independent active public registry custody.
    // Refusal precedes state creation; losing registry access cannot select legacy HMAC approval.
    readOwnerState()
    // The constructor can retain enforcement facts. Verify readiness through the readonly
    // core seam first so an unavailable verifier cannot reach secret/key creation or ledger writes.
    if (typeof gateCore.ownerAuthorizationReadiness !== 'function') throw new Error('boundary-gate:owner-authorization-unavailable')
    checkGateReadiness(() => gateCore.ownerAuthorizationReadiness({ home, readOwnerState }))
    const owner = loadOwnerSecret(home)
    gate = createGate({ home, owner, readOwnerState, targets: gateTargets(abs('target-root', o['target-root']), o['releases-root'] ? { releasesRoot: abs('releases-root', o['releases-root']) } : {}), store: gateStore({ gid: Number(o.gid) || 0 }),
      ...(o['journal-id'] === undefined ? {} : { journalId: o['journal-id'] }) })
    // Verification failure must stop before bearer rotation, startup effects or serving sockets.
    if (gate.verify().ok !== true) throw new Error('boundary-gate:startup-verification-failed')
    if (typeof gate.readiness !== 'function') throw new Error('boundary-gate:owner-authorization-unavailable')
    checkGateReadiness(() => gate.readiness())
    readOwnerState()
    const bearerInfo = rotateBearer(home, owner)
    const v = gate.startup({ bearerInfo })
    if (v?.ok !== true) throw new Error('boundary-gate:startup-verification-failed')
    readOwnerState()
    checkGateReadiness(() => gate.readiness())
    srv = await serveGate(gate, { runDir, gid: Number(o.gid) || 0, ownerHttpPort: Number(o.port ?? 17792), timeZone: o['time-zone'] ?? 'UTC', ownerPage: o['owner-page'] === true })
  } catch {
    gate?.close()
    // Host refusal text is fixed; private registry or retained proof diagnostics stay local.
    console.error('boundary-gate:startup-unavailable'); process.exit(1)
  }
  console.log(`boundary-gate PROPOSE ${srv.proposeSocket} OWNER ${srv.ownerSocket} (0600) OWNER-HTTP ${srv.port === null ? 'off' : 'loopback:' + srv.port} pubkey ${gate.fp} targets ${Object.keys(gate.targets).length}`)
  const stop = () => srv.close().finally(() => { gate.close(); process.exit(0) })
  process.on('SIGTERM', stop); process.on('SIGINT', stop)
} else {
  console.error('usage: gate.mjs serve --home DIR --run DIR --target-root DIR [--port N] [--gid N] [--time-zone TZ] [--journal-id aukora-gate-pilot] | check-ready | verify (--home DIR | --db FILE --pub FILE) | verify-receipt --db FILE --pub FILE --receipt FILE'); process.exit(2)
}
