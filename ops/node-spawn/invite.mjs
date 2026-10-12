// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify signed offers, isolate generated keys and require exact remote admission acknowledgements.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { redeemInvite, verifyRecord, verifyAdmissionRecord, REFUSE as INVITE_REFUSE } from '../../packages/invites/index.mjs'
import { publicKeyOf, randomSecretKey } from '../../plugins/aukora-nostr/lib/event.mjs'
import { canonicalJson } from '../../packages/contracts/src/json.mjs'

export const REFUSE = Object.freeze({
  VERSION: 'NODE_VERSION_MISMATCH', INPUT: 'INVITE_INPUT_INVALID', CONFIG: 'INVITE_CONFIG_INVALID',
  FILE: 'INVITE_FILE_INVALID', KEY: 'INVITE_KEY_UNPROTECTED', EXISTS: 'INVITE_KEY_EXISTS',
  TRANSPORT: 'INVITE_TRANSPORT_FAILED', RESPONSE: 'INVITE_RESPONSE_INVALID',
  AVAILABLE: 'INVITE_AVAILABILITY_UNCONFIRMED', ADMISSION: 'INVITE_ADMISSION_UNCONFIRMED',
  BINDING: 'INVITE_KEY_BINDING_MISMATCH',
  SPENT: 'INVITE_SPENT_NOT_CONFIRMED',
})
const MAX_BYTES = 262144
const NOT_SPENT = [INVITE_REFUSE.EXPIRED, INVITE_REFUSE.ALLOTMENT, INVITE_REFUSE.MEMBER, INVITE_REFUSE.UNADMITTED]
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
      headers: { 'Content-Type': 'application/json' }, body: typeof body === 'string' ? body : JSON.stringify(body), signal: AbortSignal.timeout(10000) })
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
  if (route !== '/redeem' && response.status !== 200 && fields(data, ['code']) && Object.values(INVITE_REFUSE).includes(data.code)) throw fail(data.code)
  return { status: response.status, data }
}

export async function preflight({ config, offer, now = seconds() }, { fetchImpl = fetch } = {}) {
  config = checkedConfig(config)
  offer = verifyOffer({ root: config.root, offer, now })
  const { status, data } = await post(config, '/preflight', { root: config.root, ...offer }, fetchImpl)
  if (status !== 200 || !fields(data, ['available', 'invite_id']) || data.available !== true
    || data.invite_id !== offer.invite.id) throw fail(REFUSE.AVAILABLE)
}

const sameValue = (left, right) => canonicalJson(left) === canonicalJson(right)

function boundRecord(config, record, offer, redemption, member) {
  const checked = verifyAdmissionRecord({ root: config.root, record })
  const last = record.chain.at(-1)
  if (!sameValue(record.chain.slice(0, -1), offer.chain)
    || !sameValue(last.invite, offer.invite)
    || !sameValue(last.redemption, redemption)
    || checked.member !== member) throw fail(REFUSE.BINDING)
  return record
}

function privateJson(file, options) {
  let fd
  try {
    privateParent(file, options)
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.nlink !== 1 || st.uid !== (options?.uid ?? process.getuid())
      || (st.mode & 0o777) !== 0o600 || st.size < 1 || st.size > MAX_BYTES) throw fail(REFUSE.FILE)
    const bytes = fs.readFileSync(fd)
    if (bytes.length !== st.size || bytes.length > MAX_BYTES) throw fail(REFUSE.FILE)
    return JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    if (error?.code === 'ENOENT') return undefined
    throw fail(REFUSE.FILE)
  } finally { if (fd !== undefined) fs.closeSync(fd) }
}

function durableRecord(file, value, options) {
  let fd
  try {
    writeRecord(file, value, options)
    fd = fs.openSync(path.dirname(file), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    fs.fsyncSync(fd)
  } catch { throw fail(REFUSE.FILE) }
  finally { if (fd !== undefined) fs.closeSync(fd) }
}

function recordOutput(file, resuming, expected, config, options) {
  if (file === undefined) return undefined
  let fd
  try {
    privateParent(file, options)
    fd = fs.openSync(file, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW
      | fs.constants.O_NONBLOCK | (resuming ? 0 : fs.constants.O_EXCL), 0o600)
    const st = fs.fstatSync(fd)
    if (!st.isFile() || st.nlink !== 1 || st.uid !== (options?.uid ?? process.getuid())
      || (st.mode & 0o777) !== 0o600 || st.size > MAX_BYTES) throw fail(REFUSE.FILE)
    if (st.size) {
      const existing = JSON.parse(fs.readFileSync(fd, 'utf8'))
      if (fields(existing, ['chain'])) verifyRecord({ root: config.root, record: existing })
      else verifyAdmissionRecord({ root: config.root, record: existing })
      if (!sameValue(existing.chain, expected.chain)) throw fail(REFUSE.BINDING)
    }
    fs.fsyncSync(fd)
    return fd
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd)
    throw fail(error?.code === REFUSE.BINDING ? REFUSE.BINDING : REFUSE.FILE)
  }
}

// Pending requests replay exact signed bytes; only owner-confirmed records complete admission.
export async function redeem({ config, offer, keyFile, recordFile, resumeRecord, now = seconds() }, { fetchImpl = fetch, keyOptions } = {}) {
  config = checkedConfig(config)
  const key = readKey(keyFile, keyOptions)
  const member = publicKeyOf(key), pendingFile = keyFile + '.invite-pending.json', responseFile = keyFile + '.invite-response.json'
  const confirmedFile = keyFile + '.invite-confirmed.json', refusedFile = keyFile + '.invite-refused.json'
  const pending = privateJson(pendingFile, keyOptions)
  const response = privateJson(responseFile, keyOptions), confirmed = privateJson(confirmedFile, keyOptions)
  const refused = privateJson(refusedFile, keyOptions)
  if (!pending && (response || confirmed || refused)) throw fail(REFUSE.FILE)
  const pendingNames = ['version', 'config', 'offer', 'redemption', 'member']
  if (pending && ((!fields(pending, pendingNames) && !fields(pending, [...pendingNames, 'request']))
    || !fields(pending.offer, ['invite', 'chain']) || !pending.redemption)) throw fail(REFUSE.FILE)
  offer = verifyOffer({ root: config.root, offer, now: pending ? pending.redemption?.created_at : now })
  if (pending && (pending.version !== 1 || !sameValue(pending.config, config)
    || !sameValue(pending.offer.chain, offer.chain) || !sameValue(pending.offer.invite, offer.invite)
    || pending.member !== member)) throw fail(REFUSE.BINDING)
  if (!pending && resumeRecord !== undefined) throw fail(REFUSE.INPUT)
  const redemption = pending ? pending.redemption : redeemInvite({ invite: offer.invite, secretKey: key, now })
  const expected = { chain: [...offer.chain, { invite: offer.invite, redemption }] }
  verifyRecord({ root: config.root, record: expected })
  const request = pending && Object.hasOwn(pending, 'request') ? pending.request
    : JSON.stringify({ root: config.root, ...(pending?.offer ?? offer), redemption })
  try {
    if (typeof request !== 'string' || !sameValue(JSON.parse(request), { root: config.root, ...offer, redemption })) throw fail(REFUSE.BINDING)
  } catch { throw fail(REFUSE.BINDING) }
  if (resumeRecord !== undefined) boundRecord(config, resumeRecord, offer, redemption, member)
  // Reserve and sync writable output before the authority can consume the invite.
  const output = recordOutput(recordFile, Boolean(pending), expected, config, keyOptions)
  try {
    let record
    if (confirmed && !fields(confirmed, ['chain'])) record = boundRecord(config, confirmed, offer, redemption, member)
    else {
      if (refused) {
        if (!fields(refused, ['request', 'code']) || refused.request !== request || !NOT_SPENT.includes(refused.code)) throw fail(REFUSE.FILE)
        throw Object.assign(fail(refused.code), { inviteId: offer.invite.id, notSpent: true })
      }
      if (confirmed) {
        verifyRecord({ root: config.root, record: confirmed })
        if (!sameValue(confirmed.chain, expected.chain)) throw fail(REFUSE.BINDING)
        // A legacy bare chain is a cache, never authority confirmation.
        fs.unlinkSync(confirmedFile)
      }
      if (!pending) durableRecord(pendingFile, { version: 1, config, offer, redemption, member, request }, keyOptions)
      // Each run dispatches at most once, including recovery after an uncertain transport.
      let answer
      try { answer = await post(config, '/redeem', request, fetchImpl) }
      catch (error) { throw Object.assign(fail(REFUSE.SPENT), { inviteId: offer.invite.id, causeCode: error?.code ?? REFUSE.TRANSPORT }) }
      if (answer.status !== 200 && fields(answer.data, ['code']) && NOT_SPENT.includes(answer.data.code)) {
        durableRecord(refusedFile, { request, code: answer.data.code }, keyOptions)
        throw Object.assign(fail(answer.data.code), { inviteId: offer.invite.id, notSpent: true })
      }
      try {
        if (answer.status !== 200 || !fields(answer.data, ['admitted', 'record'])
          || answer.data.admitted !== true) throw fail(fields(answer.data, ['code']) ? answer.data.code : REFUSE.ADMISSION)
        record = boundRecord(config, answer.data.record, offer, redemption, member)
        durableRecord(confirmedFile, record, keyOptions)
      } catch (error) {
        throw Object.assign(fail(REFUSE.SPENT), { inviteId: offer.invite.id, causeCode: error?.code ?? REFUSE.BINDING })
      }
    }
    try {
      if (output !== undefined) {
        const bytes = Buffer.from(JSON.stringify(record) + '\n')
        let offset = 0
        while (offset < bytes.length) {
          const written = fs.writeSync(output, bytes, offset, bytes.length - offset, offset)
          if (!written) throw fail(REFUSE.FILE)
          offset += written
        }
        fs.ftruncateSync(output, bytes.length)
        fs.fsyncSync(output)
      }
    } catch { throw Object.assign(fail(REFUSE.SPENT), { inviteId: offer.invite.id, causeCode: REFUSE.FILE }) }
    return record
  } finally { if (output !== undefined) fs.closeSync(output) }
}

export function verifyBinding({ config, record, keyFile }, { keyOptions } = {}) {
  config = checkedConfig(config)
  const key = readKey(keyFile, keyOptions)
  const checked = verifyAdmissionRecord({ root: config.root, record })
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
      redeem: ['--config', '--offer', '--key-file', '--out', '--resume-record'], verify: ['--config', '--record', '--key-file'] }
    if (!Object.hasOwn(allowed, command)) throw fail(REFUSE.INPUT)
    const opts = {}
    for (let index = 0; index < rest.length; index += 2) {
      const flag = rest[index], value = rest[index + 1]
      if (!allowed[command].includes(flag) || Object.hasOwn(opts, flag) || typeof value !== 'string' || value.startsWith('--')) throw fail(REFUSE.INPUT)
      opts[flag] = value
    }
    if (!allowed[command].filter(flag => flag !== '--resume-record').every(flag => Object.hasOwn(opts, flag))) throw fail(REFUSE.INPUT)
    const now = (deps.now ?? seconds)()
    if (command === 'key') createKey(opts['--key-file'], deps.keyOptions)
    else {
      const config = readJson(opts['--config']), keyFile = opts['--key-file']
      if (command === 'verify') verifyBinding({ config, record: readJson(opts['--record']), keyFile }, deps)
      else {
        const offer = readJson(opts['--offer'])
        if (command === 'preflight') await preflight({ config, offer, now }, deps)
        else await redeem({ config, offer, keyFile, recordFile: opts['--out'],
          resumeRecord: opts['--resume-record'] ? readJson(opts['--resume-record']) : undefined, now }, deps)
      }
    }
    out({ preflight: 'PREFLIGHT_OK', key: 'KEY_CREATED', redeem: 'ADMITTED', verify: 'BINDING_OK' }[command])
    return 0
  } catch (error) {
    const code = [...Object.values(REFUSE), ...Object.values(INVITE_REFUSE)].includes(error?.code) ? error.code : REFUSE.INPUT
    err(`REFUSED ${code}`)
    if (code === REFUSE.SPENT) {
      const quote = value => "'" + value.replaceAll("'", "'\\''") + "'"
      err(`UNKNOWN_WHETHER_SPENT invite_id=${error.inviteId} cause=${error.causeCode}`)
      const resumeArgs = args.filter((arg, index) => arg !== '--resume-record' && args[index - 1] !== '--resume-record')
      err(`RETRY one identical persisted redemption with a 10-second transport deadline: node ops/node-spawn/invite.mjs ${resumeArgs.map(quote).join(' ')}`)
    }
    if (error?.notSpent === true) err(`NOT_SPENT invite_id=${error.inviteId} cause=${code}`)
    return 1
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await runCli(process.argv.slice(2))
