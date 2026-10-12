// SPDX-License-Identifier: AGPL-3.0-or-later
// A root-held public owner state requires owner authorization; the gate cannot remove that requirement.
import fs from 'node:fs'
import path from 'node:path'
import { ownerAuthorizationOwnerState } from '../../owner-key/src/authorization.mjs'

export const OWNER_STATE_FILE = '/etc/aukora-boundary-gate/owner-state.json'
const refuse = code => Object.assign(new Error(code), { code })

function protectedNode(st, directory) {
  if (st.isSymbolicLink() || (directory ? !st.isDirectory() : !st.isFile())
    || st.uid !== 0 || (st.mode & 0o022) || (!directory && (st.nlink !== 1 || st.size > 16384)))
    throw refuse('owner-state-unprotected')
}

function readOwnerState() {
  const parents = []; let parent = path.dirname(OWNER_STATE_FILE)
  while (true) { parents.push(parent); if (parent === '/') break; parent = path.dirname(parent) }
  for (const p of parents.reverse()) protectedNode(fs.lstatSync(p), true)
  const before = fs.lstatSync(OWNER_STATE_FILE)
  protectedNode(before, false)
  const fd = fs.openSync(OWNER_STATE_FILE, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
  try {
    const opened = fs.fstatSync(fd)
    protectedNode(opened, false)
    if (opened.dev !== before.dev || opened.ino !== before.ino) throw refuse('owner-state-changed')
    const bytes = Buffer.alloc(16385), length = fs.readSync(fd, bytes, 0, bytes.length, 0)
    if (length !== opened.size || length > 16384) throw refuse('owner-state-changed')
    return ownerAuthorizationOwnerState(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length))))
  } finally { fs.closeSync(fd) }
}

// Only initial absence selects legacy. Later loss or invalid state refuses through the configured reader.
export function ownerStateReader() {
  try { fs.lstatSync(OWNER_STATE_FILE) }
  catch (error) { if (error.code === 'ENOENT') return undefined; throw error }
  return readOwnerState
}
