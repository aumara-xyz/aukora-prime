#!/usr/bin/env node
// RELEASE FLOOR CHECK, run by aukora-genesis.service as ExecStartPre from the root-owned gate install. Trusted code only:
// the candidate release is read as DATA (.dsh-build JSON), its installed approval is verified against the root pin with
// src/plugin-set-canon.mjs, it must name exactly this release, and its signed ledger ordering must satisfy the floor.
//   check --release-dir /opt/aukora-genesis/release-xxxxxxx --approval-state-root /etc/aukora-approvals/<sha>/state [--floor FILE]
//   migrate-clock-floor --release-dir DIR --approval-state-root DIR [--floor FILE] (explicit root operator action)
//   show  [--floor FILE]
import fs from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

// TRUSTED-BOOTSTRAP-BEGIN: only Node builtins may execute before this block completes.
// The entrypoint + Node runtime are operator-installed trust anchors. No path/hash policy override is accepted.
const OPERATOR_ROOT = '/opt/aukora-boundary-gate'
const BOOTSTRAP_PIN = `${OPERATOR_ROOT}/src/vendor/trusted-verifier-pins.json`
const trustedError = (code) => Object.assign(new Error(code), { code })
const protectedNode = (p, directory) => {
  const st = fs.lstatSync(p)
  if (st.isSymbolicLink()) throw trustedError('trusted-symlink')
  if (st.uid !== 0) throw trustedError('trusted-owner')
  if ((st.mode & 0o022) !== 0) throw trustedError('trusted-mode')
  if (directory ? !st.isDirectory() : !st.isFile()) throw trustedError('trusted-type')
  if (!directory && st.nlink !== 1) throw trustedError('trusted-hardlink')
  return st
}
const protectedAncestors = (p) => {
  const ancestors = []; let d = path.dirname(p)
  while (true) { ancestors.push(d); if (d === '/') break; d = path.dirname(d) }
  for (const d of ancestors.reverse()) protectedNode(d, true)
}
const trustedRead = (p, limit) => {
  protectedAncestors(p); const before = protectedNode(p, false)
  if (before.size > limit) throw trustedError('trusted-size')
  const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  try {
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.uid !== 0 || (st.mode & 0o022) !== 0 || st.nlink !== 1
      || st.dev !== before.dev || st.ino !== before.ino || st.size > limit) throw trustedError('trusted-open-identity')
    const bytes = fs.readFileSync(fd)
    if (bytes.length > limit || bytes.length !== st.size) throw trustedError('trusted-size')
    return bytes
  } finally { fs.closeSync(fd) }
}
const under = (p, root) => p === root || p.startsWith(`${root}/`)
async function trustedBootstrap(candidate) {
  if (process.env.NODE_OPTIONS || process.env.NODE_PATH || process.execArgv.length) throw trustedError('trusted-node-environment')
  const entry = fileURLToPath(import.meta.url)
  if (entry !== `${OPERATOR_ROOT}/bin/release-floor.mjs`) throw trustedError('trusted-entrypoint')
  trustedRead(entry, 128 * 1024)
  if (fs.realpathSync(OPERATOR_ROOT) !== OPERATOR_ROOT) throw trustedError('trusted-root-alias')
  if (candidate !== undefined) {
    if (!path.isAbsolute(candidate) || path.resolve(candidate) !== candidate) throw trustedError('candidate-path')
    const real = fs.realpathSync(candidate)
    if (real !== candidate) throw trustedError('candidate-path-alias')
    if (under(real, OPERATOR_ROOT) || under(OPERATOR_ROOT, real)) throw trustedError('candidate-trusted-overlap')
  }
  const raw = trustedRead(BOOTSTRAP_PIN, 4096), pins = JSON.parse(raw.toString('utf8'))
  const names = ['src/plugin-set-canon.mjs', 'src/release-floor.mjs', 'src/vendor/operator-data.mjs', 'src/vendor/plugin-set-content.mjs', 'src/vendor/signer-epochs.mjs']
  if (pins?.version !== 1 || pins.kind !== 'aukora-operator-verifier-pins/v1'
    || Object.keys(pins).sort().join(',') !== 'files,kind,version'
    || pins.files === null || typeof pins.files !== 'object' || Array.isArray(pins.files)
    || Object.keys(pins.files).sort().join(',') !== names.join(',')
    || !Object.values(pins.files).every(h => typeof h === 'string' && /^[0-9a-f]{64}$/u.test(h))) throw trustedError('trusted-pin-format')
  const buffers = new Map()
  // All hashes are checked before ANY of these module buffers executes. Vendor text is retained as provenance data.
  for (const name of names) {
    const bytes = trustedRead(`${OPERATOR_ROOT}/${name}`, 128 * 1024)
    if (createHash('sha256').update(bytes).digest('hex') !== pins.files[name]) throw trustedError('trusted-hash')
    buffers.set(name, bytes)
  }
  // Executing the checked bytes avoids hashing one pathname and later importing changed bytes from that pathname.
  const checkedModule = bytes => import(`data:text/javascript;base64,${bytes.toString('base64')}`)
  const canon = await checkedModule(buffers.get('src/plugin-set-canon.mjs'))
  const floor = await checkedModule(buffers.get('src/release-floor.mjs'))
  const data = await checkedModule(buffers.get('src/vendor/operator-data.mjs'))
  const epochs = await checkedModule(buffers.get('src/vendor/signer-epochs.mjs'))
  return { canon, floor, data, epochs }
}
// TRUSTED-BOOTSTRAP-END

const { values: o, positionals: [cmd] } = parseArgs({ args: process.argv.slice(2), allowPositionals: true, strict: true, options: {
  'release-dir': { type: 'string' }, 'approval-state-root': { type: 'string' }, floor: { type: 'string', default: '/etc/aukora-approvals/release-floor.json' } } })
const die = (m) => { console.error(`release-floor: REFUSED: ${m}`); process.exit(1) }
const rootOwned = (p) => { const st = fs.lstatSync(p); if (st.isSymbolicLink() || st.uid !== 0 || (st.mode & 0o022) !== 0) die(`${p} is not root-owned, go-w and a real path`) }

let trusted
try { trusted = await trustedBootstrap(o['release-dir']) } catch (e) { die(e.code ?? 'trusted-bootstrap') }
const { verifyOrderedGateApproval } = trusted.canon
const { readFloor, checkFloor, migrateClockFloor, writeFloor } = trusted.floor
const { installedRelease } = trusted.data
const { readSignerEpochs } = trusted.epochs

if (cmd === 'show') {
  try { console.log(JSON.stringify(readFloor(o.floor, { requireRoot: true }), null, 2)); process.exit(0) } catch (e) { die(e.message) }
}
if (cmd !== 'check' && cmd !== 'migrate-clock-floor') die('usage: release-floor.mjs check|migrate-clock-floor --release-dir DIR --approval-state-root DIR [--floor FILE] | show')
if (cmd === 'migrate-clock-floor' && process.getuid?.() !== 0) die('migrate-clock-floor requires the root operator')
const relDir = o['release-dir'], root = o['approval-state-root']
if (!relDir || !path.isAbsolute(relDir) || !root || !path.isAbsolute(root)) die('--release-dir and --approval-state-root must be absolute')
try {
  const gs = path.join(root, 'gate-state')
  for (const p of [root, gs, path.join(gs, 'plugin-set-approval.json'), path.join(gs, 'plugin-set-approver.json')]) rootOwned(p)
  const floor = readFloor(o.floor, { requireRoot: true, allowClockMigration: cmd === 'migrate-clock-floor' })
  const on = installedRelease(path.dirname(relDir), path.basename(relDir))
  const record = JSON.parse(fs.readFileSync(path.join(relDir, '.dsh-build/plugin-set.json'), 'utf8'))
  const approval = JSON.parse(trustedRead(path.join(gs, 'plugin-set-approval.json'),128*1024).toString('utf8'))
  const pin = JSON.parse(trustedRead(path.join(gs, 'plugin-set-approver.json'),64*1024).toString('utf8'))
  const epochs = readSignerEpochs()
  const v = verifyOrderedGateApproval({ record, approval, pin, epochs })
  if (v.release !== on.release || v.release_dir !== on.release_dir || v.record !== on.record) die(`the installed approval names ${v.release_dir}, not ${on.release_dir}`)
  if (cmd === 'migrate-clock-floor') {
    const migrated = migrateClockFloor(floor, v)
    writeFloor(o.floor, migrated, { clockMigrationProof: { old: floor, verified: v } })
    console.log(`release-floor: MIGRATED ${migrated.release_dir} to signer epoch ${migrated.signer_epoch}, ledger sequence ${migrated.ledger_seq}`)
    process.exit(0)
  }
  const r = checkFloor(floor, v)
  console.log(`release-floor: OK ${r.release} (signer epoch ${v.signerEpoch}, ledger sequence ${v.ledgerSeq}) = floor ${r.floor} (${floor.signer_epoch}, ${floor.ledger_seq})`)
} catch (e) { die(e.message) }
