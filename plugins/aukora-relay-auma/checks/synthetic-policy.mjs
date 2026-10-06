// SPDX-License-Identifier: AGPL-3.0-or-later
// Invented, retained source fixtures only. This helper never discovers or reads
// operational configuration, and never removes or changes existing files.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { POST_POLICY_PROFILE, PROTECTED_CATEGORIES } from '../lib/post-policy.mjs'

const protectedValues = Object.freeze([
  'river lantern paper hollow',
  'glass kite meadow note',
  'lake birch station word',
  'glow frost paper ember',
])

export function makeSyntheticPostPolicy() {
  const uid = process.getuid?.()
  if (!Number.isSafeInteger(uid) || uid <= 0) throw new Error('non-root synthetic fixture reader required')
  // The validator's ancestor rule refuses group/other-writable parents: the
  // checkout may sit under one (the pilot's ~/aukora-zip is 0775) and /tmp is
  // 1777, so the fixture parent lives under the caller's protected home.
  const parent = path.join(os.homedir(), '.aukora-post-policy-fixtures')
  if (!fs.existsSync(parent)) fs.mkdirSync(parent, { mode: 0o700 })
  const stat = fs.lstatSync(parent)
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o077) !== 0)
    throw new Error('private synthetic fixture parent required')
  const root = fs.mkdtempSync(path.join(parent, 'combined-'))
  const files = PROTECTED_CATEGORIES.map((category, index) => {
    const file = path.join(root, 'invented-' + String(index))
    const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600)
    try { fs.writeFileSync(fd, protectedValues[index]); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
    return { category, path: file, owner_uid: uid, selectors: [{ kind: 'whole-utf8', pointer: '' }] }
  })
  return { config: { ...POST_POLICY_PROFILE, reader_uid: uid, files }, protectedValues, root }
}
