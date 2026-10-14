// SPDX-License-Identifier: AGPL-3.0-or-later
// Project only the gate's verified head through a read-only socket operation.
import net from 'node:net'
import { constants as FS } from 'node:fs'
import { lstat, open, rename, unlink } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'

const SOCKET = '/run/aukora-gate/gate.sock'
const OUTPUT = '/var/lib/aukora-aura/head/gate.json'

function refuse(code) {
  throw Object.assign(new Error(`aura-head:${code}`), { code: `aura-head:${code}` })
}

export function projectGateHead(value) {
  const { ok, entries, head } = value ?? {}
  if (ok !== true || !Number.isSafeInteger(entries) || entries < 0
    || (entries === 0 ? head !== 'GENESIS' : typeof head !== 'string' || !/^[a-f0-9]{64}$/u.test(head))) {
    refuse('unverified')
  }
  return { ok: true, entries, head }
}

export function readGateHead(socketPath = SOCKET, connect = path => net.createConnection(path), timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const connection = connect(socketPath)
    let bytes = Buffer.alloc(0)
    function fail(code) {
      clearTimeout(timer)
      connection.destroy()
      reject(Object.assign(new Error(`aura-head:${code}`), { code: `aura-head:${code}` }))
    }
    const timer = setTimeout(() => fail('timeout'), timeoutMs)
    connection.on('connect', () => connection.write('{"op":"verify","args":{}}\n'))
    connection.on('data', chunk => {
      if (bytes.length + chunk.length > 4096) return fail('reply-limit')
      bytes = Buffer.concat([bytes, chunk])
    })
    connection.on('error', () => fail('unavailable'))
    connection.on('end', () => {
      clearTimeout(timer)
      try {
        const reply = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
        if (reply?.ok !== true) refuse('refused')
        resolve(projectGateHead(reply.result))
      } catch (error) {
        reject(Object.assign(new Error('aura-head:reply-invalid'), { code: 'aura-head:reply-invalid' }))
      }
    })
  })
}

export async function writeGateHead(file, value) {
  const head = projectGateHead(value)
  const directory = dirname(file)
  const info = await lstat(directory)
  if (!info.isDirectory() || info.uid !== process.getuid() || info.mode & 0o022) refuse('output-custody')
  const temporary = join(directory, '.gate-' + randomUUID())
  let handle
  try {
    handle = await open(temporary, FS.O_CREAT | FS.O_EXCL | FS.O_WRONLY | FS.O_NOFOLLOW, 0o640)
    await handle.chmod(0o640)
    await handle.writeFile(JSON.stringify(head) + '\n')
    await handle.sync()
    await handle.close()
    handle = undefined
    await rename(temporary, file)
  } finally {
    await handle?.close()
    await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error })
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 2) refuse('arguments')
    await writeGateHead(OUTPUT, await readGateHead())
    process.stdout.write('AURA_GATE_HEAD_COLLECTED\n')
  } catch {
    await unlink(OUTPUT).catch(() => {})
    process.stderr.write('AURA_GATE_HEAD_REFUSED\n')
    process.exitCode = 1
  }
}
