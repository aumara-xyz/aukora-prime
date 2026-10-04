#!/usr/bin/env node
// Operator CLI for the plugin-set approval through the boundary gate (the gate as accepted signer). Run as root on the
// pilot. It approves NOTHING: `raise` only puts the question in front of the owner (Mac popup, review -> decide_review);
// `install` exports the gate's signed receipt AFTER the owner approved and writes the approval + pin the launcher reads.
//   raise   --release-dir /opt/aukora-genesis/release-xxxxxxx [--operation HEX] [--run /run/aukora-gate]
//   install --release-dir DIR --out GATE_STATE_DIR [--run DIR] [--target-root /var/lib/aukora-boundary/targets] [--repin]
//   show    --release-dir DIR [--operation HEX]          (prints what the owner will see; no socket use)
// A CANDIDATE RELEASE IS DATA. This tool runs as root and never imports or executes anything under --release-dir: the
// operation digest and the final verification come from the root-owned gate install (src/plugin-set-canon.mjs), over the
// release's .dsh-build JSON records. `install` also moves the monotonic release floor forward (src/release-floor.mjs).
import fs from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { createPublicKey, createHash, verify as edVerify } from 'node:crypto'
import { call } from '../src/server.mjs'
import { PLUGIN_SET_TARGET, installedRelease, pluginSetApprovalText, parsePluginSetApproval } from '../src/targets.mjs'
import { operationDigestOf, setOperationContent, verifyGateSetApproval } from '../src/plugin-set-canon.mjs'
import { FLOOR_FILE, readFloor, advanceFloor, writeFloor, isRollback } from '../src/release-floor.mjs'

const { values: o, positionals: [cmd] } = parseArgs({ allowPositionals: true, strict: true, options: {
  'release-dir': { type: 'string' }, operation: { type: 'string' }, run: { type: 'string', default: '/run/aukora-gate' },
  out: { type: 'string' }, floor: { type: 'string', default: FLOOR_FILE }, 'target-root': { type: 'string', default: '/var/lib/aukora-boundary/targets' }, repin: { type: 'boolean' } } })
const die = (m) => { console.error(`plugin-set-approval: ${m}`); process.exit(1) }
const sha = (b) => createHash('sha256').update(b).digest('hex')
if (!['raise', 'install', 'show'].includes(cmd)) die('usage: plugin-set-approval.mjs raise|install|show --release-dir DIR ...')
const relDir = o['release-dir']; if (!relDir || !path.isAbsolute(relDir)) die('--release-dir must be an absolute release path')
const on = installedRelease(path.dirname(relDir), path.basename(relDir))

// The release's plugin-set record, read as JSON DATA (installedRelease already refused symlinks and non-regular files).
const record = JSON.parse(fs.readFileSync(path.join(relDir, '.dsh-build/plugin-set.json'), 'utf8'))
function operationDigest() {
  if (o.operation) { if (!/^[0-9a-f]{64}$/.test(o.operation)) die('--operation must be 64 hex'); return o.operation }
  return operationDigestOf(setOperationContent(record))
}
const content = pluginSetApprovalText({ ...on, operation: operationDigest() })
const a = parsePluginSetApproval(content)
const card = [`RELEASE ID   ${a.release}  (${a.release_dir})`, `PLUGIN SET   ${a.plugin_set}`, `OPERATION    ${a.operation}`,
  `RECORD       ${a.record}`, `CONTENT SHA  ${sha(Buffer.from(content))}`].join('\n')

if (cmd === 'show') { console.log(card); process.exit(0) }
if (cmd === 'raise') {
  const r = await call(path.join(o.run, 'owner.sock'), 'raise', { target: PLUGIN_SET_TARGET, content,
    why: `Admit the AUKORA plugin set of release ${a.release.slice(0, 7)} (set ${a.plugin_set.slice(0, 16)}...). Raised by the operator; only the owner approves.` })
  let floor = null; try { floor = readFloor(o.floor) } catch {}
  console.log(card); if (isRollback(floor, a.release)) console.log(`ROLLBACK     ${a.release_dir} is below the release floor ${floor.release_dir}; the owner card says so`)
  console.log(`PENDING      ${r.id}  expires ${new Date(r.expires).toISOString()}  (waits for the owner; nothing applied)`)
  process.exit(0)
}
// install: the newest APPLIED receipt for the target, its bytes on disk, the gate key from the propose socket.
if (!o.out || !path.isAbsolute(o.out)) die('--out must be the absolute gate-state directory')
const log = await call(path.join(o.run, 'owner.sock'), 'log', { limit: 200, target: PLUGIN_SET_TARGET })
if (log.verify?.ok !== true) die('the gate ledger does not verify; refusing')
const applied = log.entries.find(e => e.event === 'apply')
if (!applied) die('no owner-approved plugin-set approval is applied yet (the owner has not approved in the popup)')
const { receipt, receipt_sig } = applied.detail
const bytes = fs.readFileSync(path.join(o['target-root'], PLUGIN_SET_TARGET))
if (sha(bytes) !== receipt.new_sha || bytes.toString('utf8') !== content) die('the applied approval is not this release\'s canonical approval (approve a fresh raise for this release)')
const ping = await call(path.join(o.run, 'gate.sock'), 'ping', {})
const key = createPublicKey(ping.pubkey_pem), fp = sha(key.export({ type: 'spki', format: 'der' })).slice(0, 16)
if (fp !== receipt.pubkey_fp || fp !== ping.pubkey_fp) die('gate key fingerprint mismatch')
if (!edVerify(null, Buffer.from(JSON.stringify(receipt)), key, Buffer.from(receipt_sig, 'base64'))) die('receipt signature does not verify')
const approval = { kind: 'aukora-plugin-set-gate-approval/v1', content, receipt, receipt_sig }
const pin = { kind: 'aukora-boundary-gate-owner/v1', gatePubkeyPem: ping.pubkey_pem, gatePubkeyFp: fp, target: PLUGIN_SET_TARGET, approver: receipt.approver }
const pinFile = path.join(o.out, 'plugin-set-approver.json'), apprFile = path.join(o.out, 'plugin-set-approval.json')
if (fs.existsSync(pinFile) && !o.repin) {
  const cur = JSON.parse(fs.readFileSync(pinFile, 'utf8'))
  if (JSON.stringify(cur) !== JSON.stringify(pin)) die(`${pinFile} pins another approver; pass --repin only if the owner decided to switch signers`)
}
// Final check with the TRUSTED verifier (same verdict the composition gate reaches at import; parity is tested).
let okv
try { okv = verifyGateSetApproval({ record, approval, pin }) } catch (e) { die(`the approval does not verify: ${e.message}`) }
if (okv.release !== on.release || okv.record !== on.record) die('the verified approval names another release or record')
const floorBefore = readFloor(o.floor, { requireRoot: process.getuid?.() === 0 })
const floorAfter = advanceFloor(floorBefore, okv)
const write = (f, obj) => { const t = `${f}.tmp-${process.pid}`; fs.writeFileSync(t, JSON.stringify(obj, null, 2) + '\n', { mode: 0o644, flag: 'wx' }); fs.renameSync(t, f) }
fs.mkdirSync(o.out, { recursive: true })
write(apprFile, approval); write(pinFile, pin)
if (floorAfter !== floorBefore) writeFloor(o.floor, floorAfter)
console.log(card); console.log(`INSTALLED    ${apprFile} + ${pinFile} (gate key ${fp}; verified: ${okv.approvalClass}, ledger seq ${applied.seq})`)
console.log(floorAfter !== floorBefore ? `FLOOR        ${o.floor} -> ${floorAfter.release_dir} (approved ${floorAfter.applied_at})` : `FLOOR        unchanged: ${floorBefore.release_dir} (this approval is not newer)`)
console.log(`NEXT         unit: --approval-state-root <this root> --approved-record-sha ${a.record}; ExecStartPre release-floor.mjs check`)
