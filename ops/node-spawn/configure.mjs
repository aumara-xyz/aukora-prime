// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify private gate signers, write private door data and check installed door readers.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createPrivateKey, createPublicKey, createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { verifyClosed } from '../buzz-relay/member.mjs'
import { readJson } from './invite.mjs'
import { verifyRecord } from '../../packages/invites/index.mjs'
import { validateSignerEpochs } from '../../packages/boundary-gate/src/vendor/signer-epochs.mjs'

const refuse = code => { throw Object.assign(new Error(code), { code }) }
export function verifyGateSigner(keyFile, epochsFile) {
  let fd
  try {
    const home = os.homedir(), uid = process.getuid()
    if (!path.isAbsolute(keyFile) || path.normalize(keyFile) !== keyFile || !keyFile.startsWith(home + '/')) refuse('SPAWN_GATE_SIGNER_KEY')
    for (let parent = path.dirname(keyFile); ; parent = path.dirname(parent)) {
      const st = fs.lstatSync(parent)
      if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o022) || st.uid !== uid && st.uid !== 0) refuse('SPAWN_GATE_SIGNER_KEY')
      if (parent === home) break
    }
    fd = fs.openSync(keyFile, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.nlink !== 1 || st.uid !== uid || (st.mode & 0o777) !== 0o600 || st.size < 1 || st.size > 4096) refuse('SPAWN_GATE_SIGNER_KEY')
    const buffer = Buffer.alloc(4097)
    let length = 0, count
    while (length < buffer.length && (count = fs.readSync(fd, buffer, length, buffer.length - length, null))) length += count
    if (length !== st.size || length > 4096) refuse('SPAWN_GATE_SIGNER_KEY')
    const key = createPrivateKey(buffer.subarray(0, length))
    if (key.asymmetricKeyType !== 'ed25519') refuse('SPAWN_GATE_SIGNER_TYPE')
    const digest = createHash('sha256').update(createPublicKey(key).export({ type: 'spki', format: 'der' })).digest('hex')
    let epochs
    try { epochs = validateSignerEpochs(readJson(epochsFile)) } catch { refuse('SPAWN_GATE_SIGNER_EPOCHS') }
    if (!epochs.epochs.some(row => row.gate_pubkey_sha256 === digest)) refuse('SPAWN_GATE_SIGNER_EPOCH')
  } catch (error) {
    if (error.code?.startsWith('SPAWN_GATE_SIGNER_')) throw error
    refuse('SPAWN_GATE_SIGNER_KEY')
  } finally { if (fd !== undefined) fs.closeSync(fd) }
}
export function writeDoor(source, target, configFile, recordFile) {
  const value = readJson(source), config = readJson(configFile), record = readJson(recordFile)
  if (!value || !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value.channel)
    || value.ownerPubkey !== undefined && value.ownerPubkey !== null
    || value.admit !== undefined && (!Array.isArray(value.admit) || value.admit.length !== 0)
    || typeof value.sessionId !== 'string' || !value.sessionId.trim()
    || Object.keys(value).some(key => !['channel', 'admit', 'sessionId'].includes(key))) refuse('SPAWN_DOOR_INVALID')
  value.admit = [verifyRecord({ root: config.root, record }).member]
  const parent = fs.lstatSync(path.dirname(target))
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() || (parent.mode & 0o077)) refuse('SPAWN_DOOR_CUSTODY')
  const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600)
  try { fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
}
export async function acceptance(release, keyFile, configFile) {
  const installed = await import(pathToFileURL(path.join(release, 'plugins/aukora-buzz-door/lib/index.mjs')))
  const key = installed.loadKey(keyFile), config = installed.loadConfig(configFile)
  if (!config.sessionId || config.ownerPubkey != null) refuse('SPAWN_DOOR_INVALID')
  if (!(await verifyClosed()).closed) refuse('SPAWN_RELAY_NOT_CLOSED')
  const url = installed.RELAY_HTTP + '/query', body = JSON.stringify([{ kinds: [9], '#h': [config.channel], limit: 1 }])
  const response = await fetch(url, { method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Authorization: installed.httpAuthHeader({ url, body, secretKeyHex: key }), 'Content-Type': 'application/json' } })
  if (response.status !== 200) refuse('SPAWN_AUMA_NOT_ADMITTED')
  console.log('installed node readback: PASS (private door loaded, closed relay, admitted Auma query)')
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [action, ...args] = process.argv.slice(2)
    if (action === 'door' && args.length === 4) { writeDoor(...args); console.log('DOOR_CONFIGURED') }
    else if (action === 'signer' && args.length === 2) { verifyGateSigner(...args); console.log('SIGNER_OK') }
    else if (action === 'acceptance' && args.length === 3) await acceptance(...args)
    else refuse('SPAWN_USAGE')
  } catch (error) {
    const code = error.code?.startsWith('SPAWN_') ? error.code : 'SPAWN_CONFIG_INPUT'
    console.error('REFUSED ' + code); process.exitCode = 1
  }
}
