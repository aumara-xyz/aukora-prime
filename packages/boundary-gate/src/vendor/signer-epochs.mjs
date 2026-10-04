// SPDX-License-Identifier: AGPL-3.0-or-later
// Public root-operator registry. A signer key has exactly one epoch; old keys cannot be relabelled as new epochs.
// No key generation, enrollment, registration, mutation or recovery occurs here.
import fs from 'node:fs'
import path from 'node:path'
export const SIGNER_EPOCHS_FILE = '/etc/aukora-boundary-gate/signer-epochs.json'
export function validateSignerEpochs(value) {
  if (value?.version !== 1 || value.kind !== 'aukora-signer-epochs/v1'
    || Object.keys(value).sort().join(',') !== 'epochs,kind,version'
    || !Array.isArray(value.epochs) || value.epochs.length < 1 || value.epochs.length > 64) throw new Error('signer-epochs-malformed')
  const keys = new Set(); let previous = 0
  for (const row of value.epochs) {
    if (row === null || typeof row !== 'object' || Object.keys(row).sort().join(',') !== 'epoch,gate_pubkey_sha256'
      || !Number.isSafeInteger(row.epoch) || row.epoch !== previous + 1
      || !/^[0-9a-f]{64}$/u.test(row.gate_pubkey_sha256) || keys.has(row.gate_pubkey_sha256)) throw new Error('signer-epochs-malformed')
    previous = row.epoch; keys.add(row.gate_pubkey_sha256)
  }
  return value
}
export function readSignerEpochs() {
  const file = SIGNER_EPOCHS_FILE; let parent = path.dirname(file); const parents = []
  while (true) { parents.push(parent); if (parent === '/') break; parent = path.dirname(parent) }
  for (const p of parents.reverse()) {
    const st = fs.lstatSync(p)
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== 0 || (st.mode & 0o022)) throw new Error('signer-epochs-unprotected')
  }
  const before = fs.lstatSync(file)
  if (!before.isFile() || before.isSymbolicLink() || before.uid !== 0 || (before.mode & 0o022) || before.nlink !== 1 || before.size > 16384) throw new Error('signer-epochs-unprotected')
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  try {
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.uid !== 0 || (st.mode & 0o022) || st.nlink !== 1 || st.dev !== before.dev || st.ino !== before.ino || st.size > 16384) throw new Error('signer-epochs-unprotected')
    const bytes = fs.readFileSync(fd)
    if (bytes.length !== st.size || bytes.length > 16384) throw new Error('signer-epochs-unprotected')
    return validateSignerEpochs(JSON.parse(bytes.toString('utf8')))
  } finally { fs.closeSync(fd) }
}
