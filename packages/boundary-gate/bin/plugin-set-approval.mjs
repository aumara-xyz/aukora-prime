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
  if (entry !== `${OPERATOR_ROOT}/bin/plugin-set-approval.mjs`) throw trustedError('trusted-entrypoint')
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
  'release-dir': { type: 'string' }, operation: { type: 'string' }, run: { type: 'string', default: '/run/aukora-gate' },
  out: { type: 'string' }, floor: { type: 'string', default: '/etc/aukora-approvals/release-floor.json' }, 'target-root': { type: 'string', default: '/var/lib/aukora-boundary/targets' }, repin: { type: 'boolean' } } })
const die = (m) => { console.error(`plugin-set-approval: ${m}`); process.exit(1) }
const sha = (b) => createHash('sha256').update(b).digest('hex')
if (!['raise', 'install', 'show', 'recover-cache', 'migrate-clock-floor'].includes(cmd)) die('usage: plugin-set-approval.mjs raise|install|recover-cache|migrate-clock-floor|show --release-dir DIR ...')
const relDir = o['release-dir']; if (!relDir || !path.isAbsolute(relDir)) die('--release-dir must be an absolute release path')
let trusted
try { trusted = await trustedBootstrap(o['release-dir']) } catch (e) { die(`REFUSED: ${e.code ?? 'trusted-bootstrap'}`) }
const { operationDigestOf, setOperationContent, verifyOrderedGateApproval } = trusted.canon
const { readFloor, advanceFloor, checkFloor, migrateClockFloor, writeFloor, isRollback } = trusted.floor
const { call, PLUGIN_SET_TARGET, installedRelease, pluginSetApprovalText, parsePluginSetApproval } = trusted.data
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
if (process.getuid?.() !== 0) die('installation, migration and cache recovery require the root operator')
if (!o.out || !path.isAbsolute(o.out)) die('--out must be the absolute gate-state directory')
const log = await call(path.join(o.run, 'owner.sock'), 'log', { limit: 200, target: PLUGIN_SET_TARGET })
if (log.verify?.ok !== true) die('the gate ledger does not verify; refusing')
const applied = log.entries.find(e => e.event === 'apply')
if (!applied) die('no owner-approved plugin-set approval is applied yet (the owner has not approved in the popup)')
const { receipt, receipt_sig } = applied.detail
const ledger_entry = applied.signed_entry
if (!ledger_entry) die('the owner channel supplied no signed ledger entry')
const bytes = fs.readFileSync(path.join(o['target-root'], PLUGIN_SET_TARGET))
if (sha(bytes) !== receipt.new_sha || bytes.toString('utf8') !== content) die('the applied approval is not this release\'s canonical approval (approve a fresh raise for this release)')
const ping = await call(path.join(o.run, 'gate.sock'), 'ping', {})
const key = createPublicKey(ping.pubkey_pem), fp = sha(key.export({ type: 'spki', format: 'der' })).slice(0, 16)
if (fp !== receipt.pubkey_fp || fp !== ping.pubkey_fp) die('gate key fingerprint mismatch')
if (!edVerify(null, Buffer.from(JSON.stringify(receipt)), key, Buffer.from(receipt_sig, 'base64'))) die('receipt signature does not verify')
const approval = { kind: 'aukora-plugin-set-gate-approval/v1', content, receipt, receipt_sig, ledger_entry }
const pin = { kind: 'aukora-boundary-gate-owner/v1', gatePubkeyPem: ping.pubkey_pem, gatePubkeyFp: fp, target: PLUGIN_SET_TARGET, approver: receipt.approver }
const pinFile = path.join(o.out, 'plugin-set-approver.json'), apprFile = path.join(o.out, 'plugin-set-approval.json')
if (fs.existsSync(pinFile) && !o.repin) {
  const cur = JSON.parse(trustedRead(pinFile, 64 * 1024).toString('utf8'))
  if (JSON.stringify(cur) !== JSON.stringify(pin)) die(`${pinFile} pins another approver; pass --repin only if the owner decided to switch signers`)
}
// Final check with the TRUSTED verifier (same verdict the composition gate reaches at import; parity is tested).
let okv
try { okv = verifyOrderedGateApproval({ record, approval, pin, epochs: trusted.epochs.readSignerEpochs() }) } catch (e) { die(`the approval does not verify: ${e.message}`) }
if (okv.release !== on.release || okv.record !== on.record) die('the verified approval names another release or record')
const floorBefore = readFloor(o.floor, { requireRoot: true, allowClockMigration: cmd === 'migrate-clock-floor' })
const floorAfter = cmd === 'migrate-clock-floor' ? migrateClockFloor(floorBefore, okv)
  : cmd === 'recover-cache' ? (checkFloor(floorBefore, okv), floorBefore)
    : advanceFloor(floorBefore, okv)
function prepareApprovalDirectory(dir) {
  if (!path.isAbsolute(dir) || path.resolve(dir) !== dir) throw trustedError('approval-state-path')
  const directories=[]; let p=dir
  while (true) { directories.push(p); if (p==='/') break; p=path.dirname(p) }
  for (const d of directories.reverse()) {
    try { fs.mkdirSync(d,{mode:0o755}) } catch(e) { if(e.code!=='EEXIST') throw e }
    protectedNode(d,true)
  }
}
function write(f,obj) {
  protectedAncestors(f)
  if (fs.existsSync(f)) protectedNode(f,false)
  const t=f+'.tmp-'+process.pid, bytes=Buffer.from(JSON.stringify(obj,null,2)+'\n')
  const fd=fs.openSync(t,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o644)
  try {
    const st=fs.fstatSync(fd)
    if(!st.isFile()||st.uid!==0||(st.mode&0o022)||st.nlink!==1) throw trustedError('approval-state-unprotected')
    fs.writeFileSync(fd,bytes); fs.fsyncSync(fd)
  } finally { fs.closeSync(fd) }
  fs.renameSync(t,f)
  const directoryFd=fs.openSync(path.dirname(f),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW)
  try { fs.fsyncSync(directoryFd) } finally { fs.closeSync(directoryFd) }
}
// Commit the floor before publishing approval cache files. A crash leaves an unavailable exact-proof boot, never an admitted release above an uncommitted floor.
if (cmd !== 'recover-cache') writeFloor(o.floor, floorAfter,
  cmd === 'migrate-clock-floor' ? { clockMigrationProof: { old: floorBefore, verified: okv } } : {})
prepareApprovalDirectory(o.out)
write(apprFile, approval); write(pinFile, pin)
checkFloor(readFloor(o.floor, { requireRoot: true }), okv)
console.log(card); console.log(`INSTALLED    ${apprFile} + ${pinFile} (gate key ${fp}; verified: ${okv.approvalClass}, ledger seq ${applied.seq})`)
console.log(floorAfter !== floorBefore ? `FLOOR        ${o.floor} -> ${floorAfter.release_dir} (signer epoch ${floorAfter.signer_epoch}, signed seq ${floorAfter.ledger_seq})` : `FLOOR        unchanged: ${floorBefore.release_dir} (exact-proof cache recovery; no advancement)`)
console.log(`NEXT         unit: --approval-state-root <this root> --approved-record-sha ${a.record}; ExecStartPre release-floor.mjs check`)
