// SPDX-License-Identifier: AGPL-3.0-or-later
// A root-held public owner state requires owner authorization; the gate cannot remove that requirement.
import fs from 'node:fs'
import path from 'node:path'
import { randomBytes, createHash } from 'node:crypto'
import { ownerAuthorizationOwnerState } from '../../owner-key/src/authorization.mjs'

export const OWNER_STATE_FILE = '/etc/aukora-boundary-gate/owner-state.json'
const refuse = code => Object.assign(new Error(code), { code })

function protectedNode(st, directory) {
  if (st.isSymbolicLink() || (directory ? !st.isDirectory() : !st.isFile())
    || st.uid !== 0 || (st.mode & 0o022) || (!directory && (st.nlink !== 1 || st.size > 16384)))
    throw refuse('owner-state-unprotected')
}

export function readProtectedJson(file) {
  const parents = []; let parent = path.dirname(file)
  while (true) { parents.push(parent); if (parent === '/') break; parent = path.dirname(parent) }
  for (const p of parents.reverse()) protectedNode(fs.lstatSync(p), true)
  const before = fs.lstatSync(file)
  protectedNode(before, false)
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
  try {
    const opened = fs.fstatSync(fd)
    protectedNode(opened, false)
    if (opened.dev !== before.dev || opened.ino !== before.ino) throw refuse('owner-state-changed')
    const bytes = Buffer.alloc(16385), length = fs.readSync(fd, bytes, 0, bytes.length, 0)
    if (length !== opened.size || length > 16384) throw refuse('owner-state-changed')
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)))
  } finally { fs.closeSync(fd) }
}
function readOwnerState() { return ownerAuthorizationOwnerState(readProtectedJson(OWNER_STATE_FILE)) }

// Only initial absence selects legacy. Later loss or invalid state refuses through the configured reader.
export function ownerStateReader() {
  try { fs.lstatSync(OWNER_STATE_FILE) }
  catch (error) { if (error.code === 'ENOENT') return undefined; throw error }
  return readOwnerState
}

// Root selects the node and binding; the gate never accepts these from a browser.
export function passkeySetup(supplied) {
  const fields = ['version', 'kind', 'gate', 'node', 'rp_id', 'origin', 'claim_sha256', 'expires_at_ms', 'binding']
  if (!supplied || Object.keys(supplied).length !== fields.length || fields.some(k => !Object.hasOwn(supplied, k)))
    throw refuse('passkey-setup-shape')
  const s = JSON.parse(JSON.stringify(supplied)), url = new URL(s.origin)
  if (s.version !== 1 || s.kind !== 'aukora-gate-passkey-setup/v1'
    || !['gate', 'node', 'claim_sha256'].every(k => typeof s[k] === 'string' && /^[0-9a-f]{64}$/u.test(s[k]))
    || !Number.isSafeInteger(s.expires_at_ms) || s.expires_at_ms < 1
    || url.protocol !== 'https:' || url.origin !== s.origin || url.hostname !== s.rp_id)
    throw refuse('passkey-setup-binding')
  if (!Number.isSafeInteger(s.binding?.identity?.authorization_epoch) || s.binding.identity.authorization_epoch < 1
    || typeof s.binding.identity.subject !== 'string' || s.binding.identity.subject.length !== 73
    || !/^aukora:1:[0-9a-f]{64}$/u.test(s.binding.identity.subject)
    || s.binding?.passkey_profile?.profile !== 'https' || s.binding.passkey_profile.origin !== s.origin
    || s.binding.passkey_profile.rp_id !== s.rp_id || !Array.isArray(s.binding.existing_credential_ids)
    || s.binding.existing_credential_ids.length !== 0)
    throw refuse('passkey-setup-binding')
  return Object.freeze(s)
}
export function passkeySetupReader(file) {
  if (!path.isAbsolute(file)) throw refuse('passkey-setup-path')
  const read = () => passkeySetup(readProtectedJson(file))
  read()
  return read
}

// Claim secrets go only to an exclusive root-private file, never stdout or a URL.
export function mintPasskeyClaim({ file, claimFile, gate, node, origin, binding, nowMs = Date.now() }) {
  if (process.getuid?.() !== 0) throw refuse('passkey-claim-root-required')
  if (![file, claimFile].every(f => path.isAbsolute(f)) || file === claimFile) throw refuse('passkey-setup-path')
  for (const f of [file, claimFile]) {
    let p = path.dirname(f)
    while (true) { protectedNode(fs.lstatSync(p), true); if (p === '/') break; p = path.dirname(p) }
  }
  const claim = randomBytes(32).toString('base64url')
  const setup = passkeySetup({ version: 1, kind: 'aukora-gate-passkey-setup/v1', gate, node,
    origin, rp_id: new URL(origin).hostname, claim_sha256: createHash('sha256').update(claim).digest('hex'),
    expires_at_ms: nowMs + 300000, binding })
  const write = (f, bytes, mode) => {
    const fd = fs.openSync(f, fs.constants.O_NOFOLLOW | fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, mode)
    try { fs.fchmodSync(fd, mode); fs.writeFileSync(fd, bytes); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
    const d = fs.openSync(path.dirname(f), 'r'); try { fs.fsyncSync(d) } finally { fs.closeSync(d) }
  }
  write(claimFile, claim + '\n', 0o600)
  write(file, JSON.stringify(setup) + '\n', 0o640)
  return { minted: true, expires_at_ms: setup.expires_at_ms }
}
