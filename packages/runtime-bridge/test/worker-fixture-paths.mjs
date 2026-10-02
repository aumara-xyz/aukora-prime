// SPDX-License-Identifier: AGPL-3.0-or-later
// Test ONLY: explicit private fixture socket root; never a production override.
import {lstatSync,mkdtempSync,realpathSync,rmSync} from 'node:fs'
import {isAbsolute,join,resolve} from 'node:path'

const MAX_SOCKET_BYTES=103
function canonicalPath(path) {
  if(typeof path!=='string'||!isAbsolute(path)||resolve(path)!==path||path.includes('\0'))
    throw new TypeError('INVALID: canonical fixture socket root required')
}
function sockets(root) {
  canonicalPath(root)
  const authoritySocket=join(root,'c'),memorySocket=join(root,'d')
  if(Buffer.byteLength(authoritySocket)>MAX_SOCKET_BYTES||Buffer.byteLength(memorySocket)>MAX_SOCKET_BYTES)
    throw new TypeError('INVALID: fixture socket pathname budget exceeded')
  return Object.freeze({root,authoritySocket,memorySocket})
}
export function planWorkerFixtureSockets(parent) {
  canonicalPath(parent)
  // Node's mkdtemp suffix is six characters. Check the full absolute paths
  // before any mkdir, synthetic key/state creation, child start or bind.
  return Object.freeze({parent,...sockets(join(parent,'wXXXXXX'))})
}
export function createWorkerFixtureSockets({temporaryRoot,socketRoot}={}) {
  const parent=socketRoot===undefined?temporaryRoot:socketRoot
  planWorkerFixtureSockets(parent)
  const metadata=lstatSync(parent)
  if(!metadata.isDirectory()||metadata.isSymbolicLink()||realpathSync(parent)!==parent)
    throw new TypeError('INVALID: physical fixture socket root required')
  // Only an explicitly supplied runner root may shorten a long TMPDIR. It
  // must already be private and owned; never discover ancestors or retry in
  // another namespace after a path, permission or transport refusal.
  if(socketRoot!==undefined&&(typeof process.getuid!=='function'||metadata.uid!==process.getuid()||(metadata.mode&0o7777)!==0o700))
    throw new TypeError('INVALID: private owned fixture socket root required')
  const root=mkdtempSync(join(parent,'w'))
  try {return sockets(root)}
  catch(error) {rmSync(root,{recursive:true,force:true});throw error}
}
