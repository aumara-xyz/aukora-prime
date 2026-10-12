// SPDX-License-Identifier: AGPL-3.0-or-later
// Bind a node name to a verified invitation chain under the configured network root.
import { constants, openSync, closeSync, fstatSync, readSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyRecord } from '../../packages/invites/index.mjs'

export const REFUSE = Object.freeze({
  VERSION: 'NODE_VERSION_MISMATCH', NODE: 'NODE_NAME_INVALID', ROOT: 'NETWORK_ROOT_REQUIRED',
  FILE: 'ADMISSION_RECORD_REQUIRED', RECORD: 'ADMISSION_RECORD_INVALID', USAGE: 'ADMISSION_USAGE_INVALID',
})
const MAX_RECORD_BYTES = 262144
function refuse(code) { throw Object.assign(new Error(code), { code }) }

export function createMemberConfig(node, root, record) {
  if (typeof node !== 'string' || !/^[a-z][a-z0-9]*(-[a-z0-9]+)*$/u.test(node)
    || node.length > 63) refuse(REFUSE.NODE)
  if (typeof root !== 'string' || !/^[0-9a-f]{64}$/u.test(root)) refuse(REFUSE.ROOT)
  let member
  try {
    record = structuredClone(record)
    ;({ member } = verifyRecord({ root, record }))
  } catch { refuse(REFUSE.RECORD) }
  return { version: 1, node, network_root_pubkey: root, member_pubkey: member,
    redemption_id: record.chain.at(-1).redemption.id }
}

export function readAdmissionRecord(path) {
  let fd, bytes
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const stat = fstatSync(fd)
    if (!stat.isFile() || stat.size < 1 || stat.size > MAX_RECORD_BYTES) refuse(REFUSE.FILE)
    const buffer = Buffer.alloc(MAX_RECORD_BYTES + 1)
    let length = 0, count
    while ((count = readSync(fd, buffer, length, buffer.length - length, null)) > 0) {
      length += count
      if (length > MAX_RECORD_BYTES) refuse(REFUSE.FILE)
    }
    if (length < 1) refuse(REFUSE.FILE)
    bytes = buffer.subarray(0, length).toString('utf8')
  } catch { refuse(REFUSE.FILE) }
  finally { if (fd !== undefined) closeSync(fd) }
  try { return JSON.parse(bytes) } catch { refuse(REFUSE.RECORD) }
}

export function runCli(args) {
  try {
    if (process.version !== 'v24.11.1') refuse(REFUSE.VERSION)
    if (args.length !== 2) refuse(REFUSE.USAGE)
    const [node, path] = args
    const config = createMemberConfig(node, process.env.AUKORA_NETWORK_ROOT_PUBKEY, readAdmissionRecord(path))
    process.stdout.write(`${JSON.stringify(config)}\n`)
    return 0
  } catch (error) {
    const code = Object.values(REFUSE).includes(error?.code) ? error.code : REFUSE.RECORD
    process.stderr.write(`REFUSED ${code}\n`)
    return 1
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runCli(process.argv.slice(2))
}
