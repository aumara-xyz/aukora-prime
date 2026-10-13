// Signs membership commands with an isolated key; probes unauthenticated and non-member HTTP access.
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { httpAuthHeader, loadKey, RELAY_HTTP } from '../../plugins/aukora-buzz-door/lib/index.mjs'
import { isHex32, publicKeyOf, randomSecretKey, signEvent } from '../../plugins/aukora-nostr/lib/event.mjs'

export const REFUSE = Object.freeze({
  INPUT: 'buzz-member:invalid-input', KEY: 'buzz-member:isolated-key-required',
  URL: 'buzz-member:loopback-required', TRANSPORT: 'buzz-member:transport-failed',
  RESPONSE: 'buzz-member:invalid-response', REJECTED: 'buzz-member:relay-refused',
  UNKNOWN: 'buzz-member:acceptance-unconfirmed', CLOSED: 'buzz-member:closed-not-proved',
})
const fail = code => Object.assign(new Error(code), { code })
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
const KINDS = Object.freeze({ add: 9030, remove: 9031, role: 9032, 'put-user': 9000 })
const MAX_RESPONSE_BYTES = 16_384
const CHECKOUT = fileURLToPath(new URL('../../', import.meta.url))

function relayUrl(baseUrl) {
  if (typeof baseUrl !== 'string' || !/^http:\/\/(localhost|127\.0\.0\.1):[0-9]{2,5}$/u.test(baseUrl)) throw fail(REFUSE.URL)
  try { if (new URL(baseUrl).port === '0') throw fail(REFUSE.URL) } catch { throw fail(REFUSE.URL) }
  return baseUrl
}

function commandEvent(options, key, now) {
  if (!options || typeof options !== 'object' || Array.isArray(options)
    || Object.keys(options).some(k => !['command', 'pubkey', 'role', 'channel'].includes(k))) throw fail(REFUSE.INPUT)
  const { command, pubkey, channel } = options
  if (!Object.hasOwn(KINDS, command) || !isHex32(pubkey)) throw fail(REFUSE.INPUT)
  let role = options.role
  if (command === 'put-user') {
    if (typeof channel !== 'string' || !UUID.test(channel) || !['member', 'bot'].includes(role)) throw fail(REFUSE.INPUT)
  } else {
    if (channel !== undefined) throw fail(REFUSE.INPUT)
    if (command === 'remove') {
      // Buzz's 9031 handler does not implement the CLI database tool's conditional role filter.
      if (role !== undefined) throw fail(REFUSE.INPUT)
    } else {
      if (command === 'add' && role === undefined) role = 'member'
      if (!['member', 'admin'].includes(role)) throw fail(REFUSE.INPUT)
    }
  }
  return signEvent({ pubkey: publicKeyOf(key), created_at: Math.floor(now() / 1000), kind: KINDS[command], content: '',
    tags: [...(channel === undefined ? [] : [['h', channel]]), ['p', pubkey.toLowerCase()], ...(role === undefined ? [] : [['role', role]])],
  }, key)
}

async function post(baseUrl, route, payload, key, { fetchImpl, now, timeoutMs = 10_000 }) {
  const url = baseUrl + route, body = JSON.stringify(payload)
  let res
  try {
    res = await fetchImpl(url, { method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
      headers: { ...(key === undefined ? {} : { Authorization: httpAuthHeader({ url, body, secretKeyHex: key, now }) }), 'Content-Type': 'application/json' } })
  } catch { throw fail(REFUSE.TRANSPORT) }
  let text = ''
  try {
    const decoder = new TextDecoder(); let bytes = 0
    for await (const chunk of res.body) {
      bytes += chunk.byteLength
      if (bytes > MAX_RESPONSE_BYTES) throw fail(REFUSE.RESPONSE)
      text += decoder.decode(chunk, { stream: true })
    }
    text += decoder.decode()
    return { status: res.status, data: JSON.parse(text) }
  } catch { throw fail(REFUSE.RESPONSE) }
}

/** Relay authorization decides who may administer the roster or channel; signatures alone grant nothing. */
export function createMemberClient({ keyFile, baseUrl = RELAY_HTTP } = {}, {
  keyOptions = { extraDenied: [path.resolve(CHECKOUT), process.cwd()] }, fetchImpl = fetch, now = () => Date.now(),
} = {}) {
  baseUrl = relayUrl(baseUrl)
  let key
  try { key = loadKey(keyFile, keyOptions); publicKeyOf(key) } catch { throw fail(REFUSE.KEY) }
  return {
    pubkey: publicKeyOf(key),
    build(options) { return commandEvent(options, key, now) },
    async send(options) {
      const event = commandEvent(options, key, now)
      const { status, data } = await post(baseUrl, '/events', event, key, { fetchImpl, now })
      if ([408, 425, 429].includes(status) || status >= 500) throw fail(REFUSE.TRANSPORT)
      if (status < 200 || status >= 300 || data?.accepted === false) throw fail(REFUSE.REJECTED)
      if (data?.accepted !== true || data.event_id !== event.id) throw fail(REFUSE.UNKNOWN)
      return { accepted: true, event_id: event.id, kind: event.kind }
    },
  }
}

/** A valid global note can be stored if the relay is open. Only explicit membership refusals prove closure. */
export async function verifyClosed({ baseUrl = RELAY_HTTP, fetchImpl = fetch, now = () => Date.now() } = {}) {
  baseUrl = relayUrl(baseUrl)
  const key = randomSecretKey(), pubkey = publicKeyOf(key)
  const event = signEvent({ pubkey, created_at: Math.floor(now() / 1000), kind: 1,
    tags: [], content: 'AUKORA verify-closed probe' }, key)
  const query = [{ kinds: [1], authors: [pubkey], limit: 1 }], result = {}
  await Promise.all([
    ['unauthenticated_query', '/query', query, undefined], ['unauthenticated_events', '/events', event, undefined],
    ['query', '/query', query, key], ['events', '/events', event, key],
  ].map(async ([name, route, payload, probeKey]) => {
    try {
      const { status, data } = await post(baseUrl, route, payload, probeKey, { fetchImpl, now, timeoutMs: 5_000 })
      const refused = status === 403 && data?.error === 'relay_membership_required' && data.accepted !== true
      const unauthenticatedRefused = probeKey === undefined && status === 401 && typeof data?.error === 'string' && data.error.length > 0 && data.accepted !== true
      const accepted = status >= 200 && status < 300 && (route === '/query' ? Array.isArray(data) : data?.accepted === true && data.event_id === event.id)
      result[name] = { state: refused ? 'MEMBERSHIP_REFUSED' : unauthenticatedRefused ? 'AUTHENTICATION_REFUSED' : accepted ? 'ACCEPTED' : 'NOT_PROVED', status }
    } catch (error) { result[name] = { state: 'NOT_PROVED', code: error.code } }
  }))
  const closed = Object.values(result).every(row => ['MEMBERSHIP_REFUSED', 'AUTHENTICATION_REFUSED'].includes(row.state))
  const state = closed ? 'CLOSED' : Object.values(result).some(row => row.state === 'ACCEPTED') ? 'OPEN' : 'UNKNOWN'
  return { closed, state, ...result }
}

const HELP = `Usage: node ops/buzz-relay/member.mjs <command> [options]
  add      --key-file <absolute-path> --pubkey <hex> [--role member|admin]
  remove   --key-file <absolute-path> --pubkey <hex>
  role     --key-file <absolute-path> --pubkey <hex> --role member|admin
  put-user --key-file <absolute-path> --pubkey <hex> --channel <uuid> --role member|bot
  verify-closed
  All commands accept --relay http://localhost:3000 (loopback only).
Keys must meet the Buzz door's isolated-file rules; secret values are never CLI arguments.
9032 requires the relay owner; 9030/9031 also allow admins within relay policy.
9000 uses channel membership policy; being relay owner alone does not grant channel authority.
verify-closed probes both routes without authentication and with a throwaway non-member key.
It reports CLOSED, OPEN or UNKNOWN; an open relay may store its synthetic kind-1 note.
It checks HTTP requests, not WebSocket admission, NIP-OA delegation, or wake containment.`

export async function runCli(args, { out = line => console.log(line), err = line => console.error(line) } = {}) {
  try {
    if (args.length === 1 && args[0] === '--help') { out(HELP); return 0 }
    const [command, ...rest] = args
    if (!Object.hasOwn(KINDS, command) && command !== 'verify-closed') throw fail(REFUSE.INPUT)
    const opts = {}
    for (let i = 0; i < rest.length; i += 2) {
      const flag = rest[i], value = rest[i + 1]
      if (!['--key-file', '--pubkey', '--role', '--channel', '--relay'].includes(flag)
        || Object.hasOwn(opts, flag) || typeof value !== 'string' || value.startsWith('--')) throw fail(REFUSE.INPUT)
      opts[flag] = value
    }
    const baseUrl = opts['--relay'] ?? RELAY_HTTP
    if (command === 'verify-closed') {
      if (Object.keys(opts).some(k => k !== '--relay')) throw fail(REFUSE.INPUT)
      const result = await verifyClosed({ baseUrl })
      out(JSON.stringify(result))
      if (!result.closed) throw fail(REFUSE.CLOSED)
    } else {
      const client = createMemberClient({ keyFile: opts['--key-file'], baseUrl })
      out(JSON.stringify(await client.send({ command, pubkey: opts['--pubkey'], role: opts['--role'], channel: opts['--channel'] })))
    }
    return 0
  } catch (error) {
    // Reflected relay bodies, file paths and exception messages never reach the terminal.
    err(Object.values(REFUSE).includes(error?.code) ? error.code : REFUSE.INPUT)
    return 1
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCli(process.argv.slice(2))
}
