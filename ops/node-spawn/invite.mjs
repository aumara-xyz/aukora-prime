// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify signed offers, isolate generated keys and require exact remote admission acknowledgements.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { redeemInvite, verifyRecord, REFUSE as INVITE_REFUSE } from '../../packages/invites/index.mjs'
import { publicKeyOf, randomSecretKey } from '../../plugins/aukora-nostr/lib/event.mjs'

export const REFUSE = Object.freeze({
  VERSION: 'NODE_VERSION_MISMATCH', INPUT: 'INVITE_INPUT_INVALID', CONFIG: 'INVITE_CONFIG_INVALID',
  FILE: 'INVITE_FILE_INVALID', KEY: 'INVITE_KEY_UNPROTECTED', EXISTS: 'INVITE_KEY_EXISTS',
  TRANSPORT: 'INVITE_TRANSPORT_FAILED', RESPONSE: 'INVITE_RESPONSE_INVALID',
  AVAILABLE: 'INVITE_AVAILABILITY_UNCONFIRMED', ADMISSION: 'INVITE_ADMISSION_UNCONFIRMED',
  BINDING: 'INVITE_KEY_BINDING_MISMATCH',
})
const MAX_BYTES = 262144
const fail = code => Object.assign(new Error(code), { code })
const seconds = () => Math.floor(Date.now() / 1000)
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === names.slice().sort().join(',')

export function checkedConfig(config) {
  if (!config || config.version !== 1 || !hex(config.root) || typeof config.admission !== 'string') throw fail(REFUSE.CONFIG)
  let endpoint
  try { endpoint = new URL(config.admission) } catch { throw fail(REFUSE.CONFIG) }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname) && endpoint.port !== ''
  if ((endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && loopback))
    || endpoint.username || endpoint.password || endpoint.search || endpoint.hash
    || endpoint.pathname !== '/' || endpoint.port === '0') throw fail(REFUSE.CONFIG)
  return { root: config.root, admission: endpoint.origin }
}

function signedOffer(root, offer) {
  const redemption = redeemInvite({ invite: offer.invite, secretKey: randomSecretKey(), now: offer.invite.created_at })
  verifyRecord({ root, record: { chain: [...offer.chain, { invite: offer.invite, redemption }] } })
}

export function verifyOffer({ root, offer, now = seconds() }) {
  try { offer = structuredClone(offer) } catch { throw fail(REFUSE.INPUT) }
  if (!hex(root) || !fields(offer, ['invite', 'chain']) || !Array.isArray(offer.chain)
    || !Number.isSafeInteger(now) || now < 0) throw fail(REFUSE.INPUT)
  signedOffer(root, offer)
  const value = JSON.parse(offer.invite.content)
  if (now < value.issuedAt) throw fail(INVITE_REFUSE.TIME)
  if (now >= value.expiresAt) throw fail(INVITE_REFUSE.EXPIRED)
  return offer
}

export function readJson(file) {
  let fd
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.nlink !== 1 || st.size < 1 || st.size > MAX_BYTES) throw fail(REFUSE.FILE)
    const bytes = Buffer.alloc(MAX_BYTES + 1)
    let length = 0, count
    while (length < bytes.length && (count = fs.readSync(fd, bytes, length, bytes.length - length, null))) length += count
    if (length > MAX_BYTES) throw fail(REFUSE.FILE)
    return JSON.parse(bytes.subarray(0, length).toString('utf8'))
  } catch { throw fail(REFUSE.FILE) }
  finally { if (fd !== undefined) fs.closeSync(fd) }
}

function privateParent(file, { home = os.homedir(), uid = process.getuid() } = {}) {
  if (typeof file !== 'string' || !path.isAbsolute(file) || path.normalize(file) !== file
    || !path.isAbsolute(home) || path.normalize(home) !== home || !file.startsWith(home + '/')) throw fail(REFUSE.KEY)
  const parent = path.dirname(file)
  for (let directory = parent; ; directory = path.dirname(directory)) {
    const st = fs.lstatSync(directory)
    if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o022)
      || (st.uid !== uid && st.uid !== 0) || (directory === parent && ((st.mode & 0o077) || st.uid !== uid))) throw fail(REFUSE.KEY)
    if (directory === home) break
  }
}

export function createKey(file, options) {
  let fd
  try {
    privateParent(file, options)
    fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600)
    fs.fchmodSync(fd, 0o600)
    fs.writeFileSync(fd, randomSecretKey() + '\n')
    fs.fsyncSync(fd)
  } catch (error) {
    throw fail(error?.code === 'EEXIST' ? REFUSE.EXISTS : REFUSE.KEY)
  } finally { if (fd !== undefined) fs.closeSync(fd) }
}

export function readKey(file, options) {
  let fd
  try {
    privateParent(file, options)
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.nlink !== 1 || st.uid !== (options?.uid ?? process.getuid())
      || (st.mode & 0o777) !== 0o600 || st.size !== 65) throw fail(REFUSE.KEY)
    const key = fs.readFileSync(fd, 'utf8')
    if (!/^[0-9a-f]{64}\n$/u.test(key)) throw fail(REFUSE.KEY)
    publicKeyOf(key.trim())
    return key.trim()
  } catch { throw fail(REFUSE.KEY) }
  finally { if (fd !== undefined) fs.closeSync(fd) }
}

async function post(config, route, body, fetchImpl) {
  let response
  try {
    response = await fetchImpl(config.admission + route, { method: 'POST', redirect: 'error',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(10000) })
  } catch { throw fail(REFUSE.TRANSPORT) }
  let text = '', data
  try {
    const decoder = new TextDecoder()
    let length = 0
    for await (const chunk of response.body) {
      length += chunk.byteLength
      if (length > MAX_BYTES) throw fail(REFUSE.RESPONSE)
      text += decoder.decode(chunk, { stream: true })
    }
    data = JSON.parse(text + decoder.decode())
  } catch { throw fail(REFUSE.RESPONSE) }
  if (response.status !== 200 && fields(data, ['code']) && Object.values(INVITE_REFUSE).includes(data.code)) throw fail(data.code)
  return { status: response.status, data }
}

export async function preflight({ config, offer, now = seconds() }, { fetchImpl = fetch } = {}) {
  config = checkedConfig(config)
  offer = verifyOffer({ root: config.root, offer, now })
  const { status, data } = await post(config, '/preflight', { root: config.root, ...offer }, fetchImpl)
  if (status !== 200 || !fields(data, ['available', 'invite_id']) || data.available !== true
    || data.invite_id !== offer.invite.id) throw fail(REFUSE.AVAILABLE)
}

export async function redeem({ config, offer, keyFile, now = seconds() }, { fetchImpl = fetch, keyOptions } = {}) {
  config = checkedConfig(config)
  offer = verifyOffer({ root: config.root, offer, now })
  const key = readKey(keyFile, keyOptions)
  const redemption = redeemInvite({ invite: offer.invite, secretKey: key, now })
  const expected = { chain: [...offer.chain, { invite: offer.invite, redemption }] }
  const { status, data } = await post(config, '/redeem', { root: config.root, ...offer, redemption }, fetchImpl)
  if (status !== 200 || !fields(data, ['admitted', 'record']) || data.admitted !== true) throw fail(REFUSE.ADMISSION)
  const checked = verifyRecord({ root: config.root, record: data.record })
  if (checked.member !== publicKeyOf(key) || JSON.stringify(data.record) !== JSON.stringify(expected)) throw fail(REFUSE.BINDING)
  return data.record
}

export function verifyBinding({ config, record, keyFile }, { keyOptions } = {}) {
  config = checkedConfig(config)
  const key = readKey(keyFile, keyOptions)
  const checked = verifyRecord({ root: config.root, record })
  if (checked.member !== publicKeyOf(key)) throw fail(REFUSE.BINDING)
}

export function writeRecord(file, record, options) {
  let fd
  try {
    privateParent(file, options)
    fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600)
    fs.fchmodSync(fd, 0o600)
    fs.writeFileSync(fd, JSON.stringify(record) + '\n')
    fs.fsyncSync(fd)
  } catch { throw fail(REFUSE.FILE) }
  finally { if (fd !== undefined) fs.closeSync(fd) }
}

export async function runCli(args, deps = {}) {
  const { out = line => console.log(line), err = line => console.error(line) } = deps
  try {
    if (process.version !== 'v24.11.1') throw fail(REFUSE.VERSION)
    const [command, ...rest] = args
    const allowed = { preflight: ['--config', '--offer'], key: ['--key-file'],
      redeem: ['--config', '--offer', '--key-file', '--out'], verify: ['--config', '--record', '--key-file'] }
    if (!Object.hasOwn(allowed, command)) throw fail(REFUSE.INPUT)
    const opts = {}
    for (let index = 0; index < rest.length; index += 2) {
      const flag = rest[index], value = rest[index + 1]
      if (!allowed[command].includes(flag) || Object.hasOwn(opts, flag) || typeof value !== 'string' || value.startsWith('--')) throw fail(REFUSE.INPUT)
      opts[flag] = value
    }
    if (!allowed[command].every(flag => Object.hasOwn(opts, flag))) throw fail(REFUSE.INPUT)
    const now = (deps.now ?? seconds)()
    if (command === 'key') createKey(opts['--key-file'], deps.keyOptions)
    else {
      const config = readJson(opts['--config']), keyFile = opts['--key-file']
      if (command === 'verify') verifyBinding({ config, record: readJson(opts['--record']), keyFile }, deps)
      else {
        const offer = readJson(opts['--offer'])
        if (command === 'preflight') await preflight({ config, offer, now }, deps)
        else writeRecord(opts['--out'], await redeem({ config, offer, keyFile, now }, deps), deps.keyOptions)
      }
    }
    out({ preflight: 'PREFLIGHT_OK', key: 'KEY_CREATED', redeem: 'ADMITTED', verify: 'BINDING_OK' }[command])
    return 0
  } catch (error) {
    const code = [...Object.values(REFUSE), ...Object.values(INVITE_REFUSE)].includes(error?.code) ? error.code : REFUSE.INPUT
    err(`REFUSED ${code}`)
    return 1
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await runCli(process.argv.slice(2))
