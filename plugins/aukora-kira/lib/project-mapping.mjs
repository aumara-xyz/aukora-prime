// SPDX-License-Identifier: AGPL-3.0-or-later
/** Project mappings read isolated config through held, no-follow ancestors. */
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, normalize } from 'node:path'
import { parseStrictJson } from '../../../packages/contracts/src/json.mjs'
import { createProjectIdentityResolver } from './project-identity.mjs'

const MAX_BYTES = 1024 * 1024
const refuse = code => { throw Object.assign(new Error(`kira.project-map:${code}`), { code: `kira.project-map:${code}` }) }
const owned = stat => stat.uid === 0 || stat.uid === process.getuid?.()

function checkedParent(fd) {
  const stat = fstatSync(fd)
  if (!stat.isDirectory() || stat.isSymbolicLink()) refuse('parent-invalid')
  if (!owned(stat)) refuse('parent-owner')
  if ((stat.mode & 0o022) !== 0) refuse('parent-writable')
  return stat
}

export function loadProjectIdentityFile(file) {
  if (typeof file !== 'string' || !isAbsolute(file) || normalize(file) !== file
    || /[\u0000-\u001f\u007f]/u.test(file)) refuse('path-invalid')
  if (typeof process.getuid !== 'function' || typeof constants.O_NOFOLLOW !== 'number'
    || typeof constants.O_NONBLOCK !== 'number' || typeof constants.O_DIRECTORY !== 'number') refuse('isolation-unavailable')
  let fd
  const parents = []
  try {
    const descriptorPaths = process.platform === 'linux' && existsSync('/proc/self/fd')
    for (const component of ['/', ...dirname(file).split('/').filter(Boolean)]) {
      const previous = parents.at(-1)
      const path = previous ? join(previous.path, component) : '/'
      const source = previous && descriptorPaths ? `/proc/self/fd/${previous.fd}/${component}` : path
      let directory
      try { directory = openSync(source, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW) }
      catch (error) { refuse(['ELOOP', 'ENOTDIR'].includes(error?.code) ? 'parent-invalid' : 'parent-unavailable') }
      const parent = { path, fd: directory }
      parents.push(parent)
      parent.stat = checkedParent(directory)
    }
    const source = descriptorPaths ? `/proc/self/fd/${parents.at(-1).fd}/${basename(file)}` : file
    fd = openSync(source, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    for (const parent of parents) {
      const stat = checkedParent(parent.fd), current = lstatSync(parent.path)
      if (['dev', 'ino', 'uid', 'mode'].some(key => parent.stat[key] !== stat[key] || stat[key] !== current[key]))
        refuse('parent-changed')
    }
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
  } finally {
    if (fd !== undefined) closeSync(fd)
    for (const parent of parents.reverse()) closeSync(parent.fd)
  }
}
