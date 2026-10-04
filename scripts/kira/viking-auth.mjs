// SPDX-License-Identifier: AGPL-3.0-or-later
/** Read an existing private door credential. No credential or permission writes. */
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs'
import { isAbsolute } from 'node:path'

export class VikingCredentialError extends Error {
  constructor(code) { super(code); this.name = 'VikingCredentialError'; this.code = code }
}

export function readDoorCredential(file) {
  if (typeof file !== 'string' || !isAbsolute(file) || /[\x00-\x1f\x7f]/u.test(file))
    throw new VikingCredentialError('viking.door:credential-file-missing')
  let fd
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const metadata = fstatSync(fd)
    if (!metadata.isFile() || metadata.size > 4096 || metadata.mode & 0o077
        || (process.getuid && metadata.uid !== process.getuid()))
      throw new VikingCredentialError('viking.door:credential-file-unsafe')
    const buffer = Buffer.alloc(4097)
    let length = 0, n
    while (length < buffer.length && (n = readSync(fd, buffer, length, buffer.length - length, null)) > 0) length += n
    const token = buffer.subarray(0, length).toString('utf8').trim()
    if (length > 4096 || !/^[A-Za-z0-9._~+\/-]+=*$/u.test(token))
      throw new VikingCredentialError('viking.door:credential-file-invalid')
    return token
  } catch (error) {
    if (error instanceof VikingCredentialError) throw error
    throw new VikingCredentialError('viking.door:credential-file-unreadable')
  } finally { if (fd !== undefined) closeSync(fd) }
}
