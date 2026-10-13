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
import { serveGate } from '../src/server.mjs'
import { rotateBearer, loadOwnerSecret } from '../src/secrets.mjs'
import { openDb, verifyLedger, loadOrCreateKey, keyFingerprint } from '../src/ledger.mjs'
import { gateTargets, gateStore } from '../src/wiring.mjs'
import { verifyReceipt } from '../src/receipts.mjs'
import { ownerStateReader, passkeySetupReader, mintPasskeyClaim } from '../src/owner-state.mjs'
import { browserJoinReader, bindingRecordReader } from '../src/browser-join.mjs'

process.umask(0o027)
const [cmd, ...rest] = process.argv.slice(2)
const { values: o, tokens } = parseArgs({ args: rest, options: { home: { type: 'string' }, run: { type: 'string' }, port: { type: 'string' }, gid: { type: 'string' },
  'time-zone': { type: 'string' }, db: { type: 'string' }, pub: { type: 'string' }, 'target-root': { type: 'string' }, 'releases-root': { type: 'string' }, receipt: { type: 'string' }, 'owner-page': { type: 'boolean' }, 'journal-id': { type: 'string' },
  'passkey-setup': { type: 'string' }, 'claim-out': { type: 'string' }, binding: { type: 'string' }, node: { type: 'string' }, 'owner-origin': { type: 'string' }, 'browser-join': { type: 'string' } }, strict: true, tokens: true })
// This fixed public journal is an operator startup binding, never a request or
// model value. Reject incompatible commands before opening any gate state.
if (o['journal-id'] !== undefined && (cmd !== 'serve' || o['journal-id'] !== 'aukora-gate-pilot'
  || tokens.filter(token => token.kind === 'option' && token.name === 'journal-id').length !== 1)) {
  console.error('--journal-id requires serve and the fixed aukora-gate-pilot journal'); process.exit(2)
}
const abs = (label, p) => { if (!p || !path.isAbsolute(p)) { console.error(`--${label} must be an absolute path`); process.exit(2) } return p }
if (o['browser-join'] !== undefined && (cmd !== 'serve' || o['passkey-setup'] === undefined)) {
  console.error('--browser-join requires passkey serve'); process.exit(2)
}
if ((o['passkey-setup'] !== undefined && !['serve', 'mint-passkey-claim'].includes(cmd))
  || (['claim-out', 'binding', 'node', 'owner-origin'].some(k => o[k] !== undefined) && cmd !== 'mint-passkey-claim')
  || (cmd === 'serve' && o['passkey-setup'] !== undefined && o['owner-page'])) {
  console.error('passkey options require the passkey command; legacy owner page cannot share its listener'); process.exit(2)
}

if (cmd === 'mint-passkey-claim') {
  const publicKey = createPublicKey(fs.readFileSync(abs('pub', o.pub)))
  const { ownerAuthorizationGatePin } = await import('../../owner-key/src/authorization.mjs')
  const r = mintPasskeyClaim({ file: abs('passkey-setup', o['passkey-setup']), claimFile: abs('claim-out', o['claim-out']),
    gate: ownerAuthorizationGatePin(publicKey.export({ type: 'spki', format: 'der' }).toString('base64')).gate,
    node: o.node, origin: o['owner-origin'], binding: JSON.parse(fs.readFileSync(abs('binding', o.binding), 'utf8')) })
  console.log(JSON.stringify(r)); process.exit(0)
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
  const owner = loadOwnerSecret(home)
  const bearerInfo = rotateBearer(home, owner)
  const readOwnerState = ownerStateReader()
  const readPasskeySetup = o['passkey-setup'] === undefined ? undefined : passkeySetupReader(abs('passkey-setup', o['passkey-setup']))
  const passkeyEnrollmentCeremony = readPasskeySetup === undefined ? undefined
    : (await import('../../authority/src/passkey-enrollment.mjs')).createPasskeyEnrollmentCeremony
  let browserJoin, browserPage
  if (o['browser-join'] !== undefined) {
    const readJoin = browserJoinReader(abs('browser-join', o['browser-join'])), selected = readJoin()
    const projection = await import('/opt/aukora-aumlok/lib/record-v3.mjs')
    const reader = await import('/opt/aukora-aumlok/lib/strict-read.mjs')
    const readRecord = bindingRecordReader(selected.binding_record, { ...projection, ...reader })
    browserJoin = { appOrigin: selected.app_origin, readBinding: () => { readJoin(); return readRecord() } }
    const setup = readPasskeySetup()
    browserPage = { appOrigin: selected.app_origin, node: setup.node, gateId: setup.gate }
  }
  const gate = createGate({ home, owner, targets: gateTargets(abs('target-root', o['target-root']), o['releases-root'] ? { releasesRoot: abs('releases-root', o['releases-root']) } : {}), store: gateStore({ gid: Number(o.gid) || 0 }),
    ...(readOwnerState === undefined ? {} : { readOwnerState }),
    ...(readPasskeySetup === undefined ? {} : { readPasskeySetup, passkeyEnrollmentCeremony }),
    ...(browserJoin === undefined ? {} : { browserJoin }),
    ...(o['journal-id'] === undefined ? {} : { journalId: o['journal-id'] }) })
  const v = gate.startup({ bearerInfo })
  if (!v.ok) console.error('LEDGER VERIFY FAILED', v.errors)
  const srv = await serveGate(gate, { runDir, gid: Number(o.gid) || 0, ownerHttpPort: Number(o.port ?? 17792), timeZone: o['time-zone'] ?? 'UTC', ownerPage: o['owner-page'] === true,
    ...(readPasskeySetup === undefined ? {} : { passkeyOwner: { origin: readPasskeySetup().origin, rpId: readPasskeySetup().rp_id, ...browserPage } }) })
  console.log(`boundary-gate PROPOSE ${srv.proposeSocket} OWNER ${srv.ownerSocket} (0600) OWNER-HTTP ${srv.port === null ? 'off' : 'loopback:' + srv.port} pubkey ${gate.fp} targets ${Object.keys(gate.targets).length}`)
  const stop = () => srv.close().finally(() => { gate.close(); process.exit(0) })
  process.on('SIGTERM', stop); process.on('SIGINT', stop)
} else {
  console.error('usage: gate.mjs serve --home DIR --run DIR --target-root DIR [--port N] [--gid N] [--time-zone TZ] [--journal-id aukora-gate-pilot] | verify (--home DIR | --db FILE --pub FILE) | verify-receipt --db FILE --pub FILE --receipt FILE'); process.exit(2)
}
