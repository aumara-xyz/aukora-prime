// SPDX-License-Identifier: AGPL-3.0-or-later
// Public host data only. Root custody is checked independently of parsed content.
import fs from 'node:fs'
import path from 'node:path'

export const canonicalAbsolutePath = value => typeof value === 'string' && path.isAbsolute(value)
  && value.length <= 4096 && value.isWellFormed() && !/[\u0000-\u001f\u007f]/u.test(value)
  && path.normalize(value) === value && !value.startsWith('//')
const refuse = () => { throw new Error('protected-public-data:unavailable') }
export const sameFileIdentity = (before, after) => ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']
  .every(field => before[field] === after[field])
// Directory size/timestamps/link count can change during our own file staging.
export const sameDirectoryIdentity = (before, after) => ['dev', 'ino', 'uid', 'gid', 'mode']
  .every(field => before[field] === after[field])

export function checkProtectedPublicAncestors(file, { readerGid } = {}) {
  if (!canonicalAbsolutePath(file)) refuse()
  for (let directory = path.dirname(file); ; directory = path.dirname(directory)) {
    const info = fs.lstatSync(directory)
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0
      || (readerGid !== undefined && (info.mode & 0o001) === 0
        && !(info.gid === readerGid && (info.mode & 0o010) !== 0))) refuse()
    if (directory === '/') break
  }
}

/** No-follow descriptor read; bounded UTF8; no key creation, discovery or writes. */
export function readProtectedPublicBytes(file, maximum = 4096) {
  let fd
  try {
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 32 * 1024 * 1024
      || typeof fs.constants.O_NOFOLLOW !== 'number' || typeof fs.constants.O_NONBLOCK !== 'number') refuse()
    checkProtectedPublicAncestors(file)
    const named = fs.lstatSync(file)
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
    const before = fs.fstatSync(fd)
    if (!before.isFile() || before.uid !== 0 || before.nlink !== 1 || (before.mode & 0o022) !== 0
      || before.size < 1 || before.size > maximum || !sameFileIdentity(named, before)) refuse()
    const bytes = Buffer.alloc(maximum + 1)
    let used = 0, count
    while ((count = fs.readSync(fd, bytes, used, bytes.length - used, null)) > 0) {
      used += count
      if (used > maximum) refuse()
    }
    if (used !== before.size || !sameFileIdentity(before, fs.fstatSync(fd))
      || !sameFileIdentity(before, fs.lstatSync(file))) refuse()
    checkProtectedPublicAncestors(file)
    return bytes.subarray(0, used)
  } catch { refuse() }
  finally { if (fd !== undefined) fs.closeSync(fd) }
}

export function readProtectedPublicText(file, maximum = 4096) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(readProtectedPublicBytes(file, maximum)) }
  catch { refuse() }
}
