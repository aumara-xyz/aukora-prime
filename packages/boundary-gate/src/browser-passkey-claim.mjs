// SPDX-License-Identifier: AGPL-3.0-or-later
// Root enrolls a passkey against the installed browser's existing public binding.
import fs from 'node:fs'
import path from 'node:path'
import { createHash, createPublicKey } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { mintPasskeyClaim, passkeySetup, readProtectedJson } from './owner-state.mjs'

export const BROWSER_BINDING_RECORD = '/home/aukora-host/genesis/state/aumlok-binding/local-control.json'
const SETUP = '/etc/aukora-boundary-gate/passkey-setup.json'
const CLAIM = '/var/lib/aukora-browser/passkey-claim.txt'
const DB = '/home/aukora-gate/gate.db'
const JOIN = '/etc/aukora-boundary-gate/browser-join.json'
const DROPIN = '/etc/systemd/system/aukora-boundary-gate.service.d/browser-owner.conf'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const fail = code => { throw Object.assign(new Error('browser-passkey:' + code), { code: 'browser-passkey:' + code }) }
const present = file => { try { fs.lstatSync(file); return true } catch (error) { if (error.code === 'ENOENT') return false; throw error } }

export function browserPasskeyOrigin(value) {
  let url
  try { url = new URL(value) } catch { fail('origin') }
  if (url.protocol !== 'https:' || url.origin !== value || url.port
    || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/u.test(url.hostname)) fail('origin')
  return url.hostname
}

export function verifyBrowserPasskeyComposition(text, appOrigin) {
  browserPasskeyOrigin(appOrigin)
  const directory = path.dirname(BROWSER_BINDING_RECORD), q = JSON.stringify
  const rows = `- id: aukora-aumlok\n  config:\n    directory: ${q(directory)}\n`
    + `- id: aukora-face-aumlok\n  config:\n    directory: ${q(directory)}\n`
    + `    browserBinding:\n      publicOrigin: ${q(appOrigin)}\n`
    + `      supportRoot: "/home/aukora-host/genesis/support"\n      stateRoot: "/home/aukora-host/genesis/state/home"\n`
  if (typeof text !== 'string' || !text.includes(rows)
    || (text.match(/^- id: aukora-aumlok$/gmu) ?? []).length !== 1
    || (text.match(/^- id: aukora-face-aumlok$/gmu) ?? []).length !== 1) fail('composition-binding')
}

export function browserBindingSnapshot(read, project) {
  const p = project({ record: read.value })
  if (!p || !/^aukora:1:[a-f0-9]{64}$/u.test(p.subject) || !/^[a-f0-9]{64}$/u.test(p.activeControlDigest)
    || typeof p.approvalKeyDid !== 'string' || !Number.isSafeInteger(p.epoch) || p.epoch < 0
    || p.epoch >= Number.MAX_SAFE_INTEGER || p.revoked !== false) fail('binding-record')
  return { subject: p.subject, control_digest: p.activeControlDigest, approval_key_did: p.approvalKeyDid,
    authorization_epoch: p.epoch + 1, source_sha256: hash(read.bytes) }
}

export async function readCurrentBinding() {
  if (fs.realpathSync(BROWSER_BINDING_RECORD) !== BROWSER_BINDING_RECORD) fail('binding-alias')
  const { readJsonStrictBytes } = await import('/opt/aukora-aumlok/lib/strict-read.mjs')
  const { projectRecordV3Control } = await import('/opt/aukora-aumlok/lib/record-v3.mjs')
  return browserBindingSnapshot(readJsonStrictBytes(BROWSER_BINDING_RECORD, { maxBytes: 32768 }), projectRecordV3Control)
}

export function browserPasskeyBinding(snapshot, ownerOrigin, appOrigin) {
  const rp = browserPasskeyOrigin(ownerOrigin)
  browserPasskeyOrigin(appOrigin)
  return { identity: { owner_id: snapshot.subject, subject: snapshot.subject,
    approval_key_did: snapshot.approval_key_did, control_digest: snapshot.control_digest,
    authorization_epoch: snapshot.authorization_epoch },
  identity_provenance: { kind: 'owner-approved-initial-public-identity/v1', identity_source_sha256: snapshot.source_sha256,
    approval_reference: 'root-selected-existing-browser-binding/v1:' + appOrigin },
  passkey_profile: { profile: 'https', origin: ownerOrigin, rp_id: rp },
  user: { id: Buffer.from(snapshot.control_digest, 'hex').toString('base64url'), name: snapshot.subject, display_name: 'AUKORA owner' },
  existing_credential_ids: [] }
}

export function checkBrowserPasskeySelection(db) {
  if (present(JOIN) || (present(DROPIN) && fs.readFileSync(DROPIN, 'utf8').includes('--browser-join'))
    || (db.prepare("SELECT 1 FROM sqlite_master WHERE name='owner_browser_config'").get()
      && db.prepare('SELECT 1 FROM owner_browser_config LIMIT 1').get())) fail('browser-join-selected')
  if (db.prepare("SELECT 1 FROM ledger WHERE event='owner-passkey-enrolled' LIMIT 1").get()
    || (db.prepare("SELECT 1 FROM sqlite_master WHERE name='owner_passkey'").get()
      && db.prepare('SELECT state_text FROM owner_passkey WHERE singleton=1').get()?.state_text)
    || (db.prepare("SELECT 1 FROM sqlite_master WHERE name='owner_passkey_ceremony'").get()
      && db.prepare('SELECT failed FROM owner_passkey_ceremony WHERE singleton=1').get()?.failed)) fail('enrollment-closed')
}

export function savedBrowserPasskeyClaim(setup, claim, expected, nowMs = Date.now()) {
  setup = passkeySetup(setup)
  if (setup.gate !== expected.gate || setup.node !== expected.node || setup.origin !== expected.origin
    || JSON.stringify(setup.binding) !== JSON.stringify(expected.binding)) fail('setup-changed')
  if (nowMs >= setup.expires_at_ms) fail('claim-expired')
  if (!/^[A-Za-z0-9_-]{43}\n$/u.test(claim) || hash(claim.trim()) !== setup.claim_sha256) fail('claim-changed')
  return claim.trim()
}

export async function mintBrowserPasskeyClaim({ ownerOrigin, appOrigin, release }) {
  if (process.getuid?.() !== 0) fail('root-required')
  if (process.version !== 'v24.11.1') fail('node-version')
  browserPasskeyOrigin(ownerOrigin); browserPasskeyOrigin(appOrigin)
  if (ownerOrigin === appOrigin) fail('origins-not-separated')
  if (!path.isAbsolute(release) || path.resolve(release) !== release || fs.realpathSync(release) !== release) fail('release-path')
  verifyBrowserPasskeyComposition(fs.readFileSync(path.join(release, 'aukora-composition.patch.yml'), 'utf8'), appOrigin)
  const snapshot = await readCurrentBinding()
  const key = createPublicKey(fs.readFileSync('/run/aukora-gate/receipt-ed25519.pub'))
  const gate = hash(key.export({ type: 'spki', format: 'der' })), node = hash('aukora-browser-node/v1\0' + gate)
  const binding = browserPasskeyBinding(snapshot, ownerOrigin, appOrigin), expected = { gate, node, origin: ownerOrigin, binding }
  const db = new DatabaseSync(DB, { readOnly: true })
  try {
    checkBrowserPasskeySelection(db)
    if (!present(SETUP)) {
      if (present(CLAIM)) fail('claim-without-setup')
      mintPasskeyClaim({ file: SETUP, claimFile: CLAIM, ...expected })
    }
    const claimInfo = fs.lstatSync(CLAIM)
    if (!claimInfo.isFile() || claimInfo.isSymbolicLink() || claimInfo.uid !== 0 || claimInfo.nlink !== 1
      || (claimInfo.mode & 0o077) || claimInfo.size !== 44) fail('claim-unprotected')
    const fd = fs.openSync(CLAIM, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
    let claim
    try {
      const opened = fs.fstatSync(fd)
      if (opened.dev !== claimInfo.dev || opened.ino !== claimInfo.ino || !opened.isFile() || opened.uid !== 0
        || opened.nlink !== 1 || (opened.mode & 0o077) || opened.size !== 44) fail('claim-unprotected')
      claim = fs.readFileSync(fd, 'utf8')
    } finally { fs.closeSync(fd) }
    const code = savedBrowserPasskeyClaim(readProtectedJson(SETUP), claim, expected)
    return ownerOrigin + '/owner/enroll#claim=' + code
  } finally { db.close() }
}
