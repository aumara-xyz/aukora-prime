// SPDX-License-Identifier: AGPL-3.0-or-later
/** Project mappings are startup snapshots of isolated root or harness config. */
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { dirname, isAbsolute, normalize } from 'node:path'
import { parseStrictJson } from '../../../packages/contracts/src/json.mjs'
import { createProjectIdentityResolver } from './project-identity.mjs'

const MAX_BYTES = 1024 * 1024
const refuse = code => { throw Object.assign(new Error(`kira.project-map:${code}`), { code: `kira.project-map:${code}` }) }
const owned = stat => stat.uid === 0 || stat.uid === process.getuid?.()

export function loadProjectIdentityFile(file) {
  if (typeof file !== 'string' || !isAbsolute(file) || normalize(file) !== file
    || /[\u0000-\u001f\u007f]/u.test(file)) refuse('path-invalid')
  if (typeof process.getuid !== 'function' || typeof constants.O_NOFOLLOW !== 'number'
    || typeof constants.O_NONBLOCK !== 'number') refuse('isolation-unavailable')
  let fd
  try {
    for (let parent = dirname(file); ; parent = dirname(parent)) {
      const stat = lstatSync(parent)
      if (!stat.isDirectory() || stat.isSymbolicLink()) refuse('parent-invalid')
      if (!owned(stat)) refuse('parent-owner')
      if ((stat.mode & 0o022) !== 0) refuse('parent-writable')
      if (dirname(parent) === parent) break
    }
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const before = fstatSync(fd)
    if (!before.isFile() || before.nlink !== 1) refuse('file-invalid')
    if (!owned(before)) refuse('file-owner')
    if ((before.mode & 0o022) !== 0) refuse('file-writable')
    if (before.size > MAX_BYTES) refuse('file-too-large')
    const buffer = Buffer.alloc(MAX_BYTES + 1)
    let used = 0, read
    while (used < buffer.length && (read = readSync(fd, buffer, used, buffer.length - used, null)) > 0) used += read
    if (used > MAX_BYTES) refuse('file-too-large')
    const after = fstatSync(fd)
    if (used !== before.size || ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']
      .some(key => before[key] !== after[key])) refuse('file-changed')
    let config
    try { config = parseStrictJson(buffer.subarray(0, used).toString('utf8')) }
    catch { refuse('json-invalid') }
    return createProjectIdentityResolver(config)
  } catch (error) {
    if (error?.code?.startsWith('kira.project-') || error?.message?.startsWith('kira.project-identity:')) throw error
    refuse(error?.code === 'ELOOP' ? 'file-symlink' : 'file-unavailable')
  } finally { if (fd !== undefined) closeSync(fd) }
}
