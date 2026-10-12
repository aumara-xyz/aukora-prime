// SPDX-License-Identifier: AGPL-3.0-or-later
// Bounds HTTP requests and serves durable invite decisions through the relay owner.
import http from 'node:http'
import { isIP } from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { TextDecoder } from 'node:util'
import { parseStrictJson } from '../../packages/contracts/src/json.mjs'
import { REFUSE as INVITES } from '../../packages/invites/index.mjs'
import { preflight, admitIdempotent, resume, REFUSE as ADMIT } from './admit.mjs'
import { createMemberClient, verifyClosed, REFUSE as MEMBER } from './member.mjs'

export const REFUSE = ADMIT
const fail = code => Object.assign(new Error(code), { code })
const codes = new Set([...Object.values(ADMIT), ...Object.values(MEMBER), ...Object.values(INVITES)])
const refusal = error => codes.has(error?.code) ? error.code : ADMIT.UNKNOWN
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const loopback = host => host === '::1' || (isIP(host) === 4 && host.startsWith('127.'))
const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === names.slice().sort().join(',')

function settings(options) {
  const config = { host: '127.0.0.1', port: 3100, bodyLimit: 262144, deadlineMs: 5000,
    windowMs: 60000, addressLimit: 30, globalLimit: 300, ...options }
  if (!isIP(config.host) || (!loopback(config.host) && config.behindTlsProxy !== true)
    || !Number.isInteger(config.port) || config.port < 0 || config.port > 65535
    || !['bodyLimit', 'deadlineMs', 'windowMs', 'addressLimit', 'globalLimit'].every(name =>
      Number.isSafeInteger(config[name]) && config[name] > 0)
    || config.bodyLimit > 262144 || config.deadlineMs > 30000) throw fail(ADMIT.INPUT)
  return config
}

// Address windows share a global cap; forwarded headers cannot allocate identities.
function limiter(config) {
  let window = -1, total = 0
  const addresses = new Map()
  return address => {
    const current = Math.floor(Date.now() / config.windowMs)
    if (window !== current) { window = current; total = 0; addresses.clear() }
    if (++total > config.globalLimit) return false
    const count = (addresses.get(address) ?? 0) + 1
    addresses.set(address, count)
    return count <= config.addressLimit
  }
}

function readBody(request, config, signal) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let length = 0
    const cleanup = () => {
      request.removeListener('data', data); request.removeListener('end', end)
      request.removeListener('error', error); request.removeListener('aborted', aborted)
      signal.removeEventListener('abort', aborted)
    }
    const error = () => { cleanup(); reject(fail(ADMIT.INPUT)) }
    const aborted = () => error()
    const data = chunk => {
      length += chunk.length
      if (length > config.bodyLimit) { cleanup(); reject(Object.assign(fail(ADMIT.INPUT), { status: 413 })); return }
      chunks.push(chunk)
    }
    const end = () => {
      cleanup()
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))
        resolve(parseStrictJson(text, { maxBytes: config.bodyLimit }))
      } catch { reject(fail(ADMIT.INPUT)) }
    }
    request.on('data', data); request.once('end', end); request.once('error', error)
    request.once('aborted', aborted); signal.addEventListener('abort', aborted, { once: true })
    if (signal.aborted) aborted()
  })
}

const statusFor = code => {
  if (code === ADMIT.BUSY || code === ADMIT.PENDING || code === INVITES.REPLAY || code === INVITES.MEMBER) return 409
  if (code === INVITES.ALLOTMENT) return 429
  if (code === INVITES.EXPIRED) return 410
  if ([INVITES.SIGNATURE, INVITES.NETWORK, INVITES.UNADMITTED].includes(code)) return 403
  if ([ADMIT.UNKNOWN, ADMIT.STORE, ADMIT.AURA, MEMBER.CLOSED, MEMBER.TRANSPORT, MEMBER.UNKNOWN, MEMBER.REJECTED, MEMBER.RESPONSE].includes(code)) return 503
  return 400
}

function transport(deps, signal) {
  return { ...deps, fetchImpl: (url, options = {}) => (deps.fetchImpl ?? fetch)(url,
    { ...options, redirect: 'error', signal: options.signal ? AbortSignal.any([signal, options.signal]) : signal }) }
}

async function requireClosed(options, deps) {
  if ((await verifyClosed({ baseUrl: options.baseUrl, fetchImpl: deps.fetchImpl })).closed !== true) throw fail(MEMBER.CLOSED)
}

export async function startAdmissionServer(options, deps = {}) {
  const config = settings(options)
  createMemberClient(config, { keyOptions: deps.keyOptions, fetchImpl: deps.fetchImpl })
  const startup = transport(deps, AbortSignal.timeout(config.deadlineMs))
  await requireClosed(config, startup)
  await resume(config, startup)
  const allow = limiter(config), log = deps.log ?? (line => console.log(line))
  const writeLog = (inviteId, outcome) => {
    try { log(JSON.stringify({ invite_id: inviteId, outcome })) } catch {}
  }
  const pendingRequests = new WeakMap(), malformedSockets = new WeakSet()
  const server = http.createServer({ maxHeaderSize: 4096, connectionsCheckingInterval: 250 }, async (request, response) => {
    let inviteId = null, finished = false
    const controller = new AbortController()
    const finish = (status, value, outcome) => {
      if (finished) return
      finished = true; clearTimeout(timer)
      writeLog(inviteId, outcome)
      if (!response.destroyed) {
        response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', connection: 'close' })
        response.end(JSON.stringify(value))
        response.once('finish', () => request.socket.destroy())
      }
    }
    const timer = setTimeout(() => {
      controller.abort()
      finish(408, { code: ADMIT.INPUT }, ADMIT.INPUT)
    }, config.deadlineMs)
    pendingRequests.set(request.socket, () => {
      controller.abort()
      finish(400, { code: ADMIT.INPUT }, ADMIT.INPUT)
    })
    response.once('close', () => {
      controller.abort()
      if (!finished) { finished = true; clearTimeout(timer); writeLog(inviteId, ADMIT.UNKNOWN) }
    })
    try {
      if (!allow(request.socket.remoteAddress)) { finish(429, { code: ADMIT.BUSY }, ADMIT.BUSY); return }
      if (request.method !== 'POST') { finish(405, { code: ADMIT.INPUT }, ADMIT.INPUT); return }
      if (!['/preflight', '/redeem'].includes(request.url)) { finish(404, { code: ADMIT.INPUT }, ADMIT.INPUT); return }
      const contentTypes = request.rawHeaders.filter((_, index) => index % 2 === 0 && request.rawHeaders[index].toLowerCase() === 'content-type')
      if (request.headers['content-type'] !== 'application/json' || contentTypes.length !== 1
        || request.headers['content-encoding'] !== undefined) { finish(415, { code: ADMIT.INPUT }, ADMIT.INPUT); return }
      if (Number(request.headers['content-length']) > config.bodyLimit) { finish(413, { code: ADMIT.INPUT }, ADMIT.INPUT); return }
      const body = await readBody(request, config, controller.signal)
      if (hex(body?.invite?.id)) inviteId = body.invite.id
      const names = request.url === '/preflight' ? ['root', 'invite', 'chain'] : ['root', 'invite', 'chain', 'redemption']
      if (!fields(body, names)) throw fail(ADMIT.INPUT)
      if (controller.signal.aborted) return
      const engine = transport(deps, controller.signal)
      if (request.url === '/preflight') {
        const result = await preflight({ ...config, ...body }, engine)
        finish(200, result, 'available')
      } else {
        await requireClosed(config, engine)
        if (controller.signal.aborted) return
        const result = await admitIdempotent({ ...config, ...body }, engine)
        finish(200, { admitted: true, record: result.record }, 'admitted')
      }
    } catch (error) {
      const code = refusal(error)
      finish(error?.status ?? statusFor(code), { code }, code)
    }
  })
  server.maxHeadersCount = 32
  server.maxConnections = 128
  server.headersTimeout = config.deadlineMs
  server.requestTimeout = config.deadlineMs
  server.setTimeout(config.deadlineMs * 2, socket => socket.destroy())
  server.on('clientError', (_error, socket) => {
    const pending = pendingRequests.get(socket)
    if (pending) { pending(); return }
    if (malformedSockets.has(socket)) { socket.destroy(); return }
    malformedSockets.add(socket)
    writeLog(null, ADMIT.INPUT)
    if (socket.writable) {
      const body = JSON.stringify({ code: ADMIT.INPUT })
      socket.end(`HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`)
    } else socket.destroy()
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(config.port, config.host, () => { server.removeListener('error', reject); resolve() })
  })
  return server
}

const HELP = `Usage: node ops/buzz-relay/admission-server.mjs --key-file OWNER_PATH --store ABSOLUTE_DIRECTORY
  [--relay http://localhost:3000] [--host 127.0.0.1] [--port 3100] [--behind-tls-proxy] [--gate-socket PATH]
Uses the isolated owner key loader and durable admission engine. Non-loopback binding requires --behind-tls-proxy.
TLS termination is the operator's reverse proxy. Forwarded headers are ignored; limits use the socket peer.
The relay must be closed. Pending spends recover before listening. No service is enabled by this command.`

export async function runCli(args, deps = {}) {
  const err = deps.err ?? (line => console.error(line)), out = deps.out ?? (line => console.log(line))
  try {
    if (args.length === 1 && args[0] === '--help') { out(HELP); return 0 }
    const options = {}, names = { '--key-file': 'keyFile', '--store': 'storeDir', '--relay': 'baseUrl',
      '--host': 'host', '--port': 'port', '--gate-socket': 'gateSocket' }
    for (let i = 0; i < args.length; i++) {
      const flag = args[i]
      if (flag === '--behind-tls-proxy' && !Object.hasOwn(options, 'behindTlsProxy')) { options.behindTlsProxy = true; continue }
      if (!Object.hasOwn(names, flag) || Object.hasOwn(options, names[flag]) || typeof args[i + 1] !== 'string'
        || args[i + 1].startsWith('--')) throw fail(ADMIT.INPUT)
      const value = args[++i]
      if (flag === '--port' && !/^[0-9]+$/u.test(value)) throw fail(ADMIT.INPUT)
      options[names[flag]] = flag === '--port' ? Number(value) : value
    }
    if (!options.keyFile || !options.storeDir) throw fail(ADMIT.INPUT)
    await startAdmissionServer(options, deps)
    return 0
  } catch (error) { err(refusal(error)); return 1 }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCli(process.argv.slice(2))
}
