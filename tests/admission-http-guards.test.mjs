// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic request streams check HTTP guards without qualifying a listening service.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { PassThrough } from 'node:stream'
import { EventEmitter } from 'node:events'
import { spawn } from 'node:child_process'
import { registerHooks } from 'node:module'
import { fileURLToPath } from 'node:url'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { createInvite, redeemInvite, createAdmissionRecord, verifyAdmissionRecord, REFUSE as INVITES } from '../packages/invites/index.mjs'
import { randomSecretKey, publicKeyOf } from '../plugins/aukora-nostr/lib/event.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const SOURCE = path.join(ROOT, 'ops/buzz-relay/admission-server.mjs')
const MUTATIONS = [
  ['TLS proxy acknowledgement', "(!loopback(config.host) && config.behindTlsProxy !== true)", 'false', 'binding'],
  ['POST only', "request.method !== 'POST'", 'false', 'protocol'],
  ['exact path', "!['/preflight', '/redeem'].includes(request.url)", 'false', 'protocol'],
  ['JSON content type', "request.headers['content-type'] !== 'application/json'", 'false', 'protocol'],
  ['single content type', 'contentTypes.length !== 1', 'false', 'protocol'],
  ['no content encoding', "request.headers['content-encoding'] !== undefined", 'false', 'protocol'],
  ['declared body limit', "Number(request.headers['content-length']) > config.bodyLimit", 'false', 'body bounds'],
  ['stream body limit', 'length > config.bodyLimit', 'false', 'body bounds'],
  ['fatal UTF8', "{ fatal: true }", '{ fatal: false }', 'strict JSON'],
  ['strict JSON', 'parseStrictJson(text, { maxBytes: config.bodyLimit })', 'JSON.parse(text)', 'strict JSON'],
  ['unknown fields', '!fields(body, names)', 'false', 'strict JSON'],
  ['request deadline', '}, config.deadlineMs)', '}, config.deadlineMs * 100)', 'deadline'],
  ['global rate limit', 'total >= config.globalLimit', 'false', 'limits'],
  ['address rate limit', 'count > config.addressLimit', 'false', 'limits'],
  ['address refusal global charge', 'if (count > config.addressLimit) return false', 'if (count > config.addressLimit) { total++; return false }', 'limits'],
  ['forwarding proxy opt-in', "config.trustedAddressHeader !== undefined && (config.behindTlsProxy !== true", 'config.trustedAddressHeader !== undefined && (false', 'forwarding'],
  ['single forwarded address', 'headers.length !== 1', 'false', 'forwarding'],
  ['valid forwarded address', '!isIP(address)', 'false', 'forwarding'],
  ['stored confirmation signature', 'verifyAdmissionRecord({ root, record }).member !== result.member', 'false', 'confirmation'],
  ['stored confirmation bytes', 'canonicalJson({ chain: record.chain }) !== canonicalJson(result.record)', 'false', 'confirmation'],
  ['authority confirmation', 'confirmedRecord(config, owner, result, (deps.now ?? (() => Math.floor(Date.now() / 1000)))())', 'result.record', 'recovery'],
  ['persisted confirmation', "database.prepare('INSERT INTO confirmations VALUES (?, ?)').run(redemptionId, row.record)", 'void row', 'recovery'],
  ['no response cache', "'cache-control': 'no-store'", "'cache-control': 'public'", 'protocol'],
  ['refusal redaction', "codes.has(error?.code) ? error.code : ADMIT.UNKNOWN", 'error.message', 'redaction'],
  ['log redaction', 'invite_id: inviteId, outcome', 'invite_id: inviteId, outcome, secret: options.keyFile', 'redaction'],
  ['closed relay', '.closed !== true', '.closed === null', 'closure'],
  ['closure before redemption', 'await requireClosed(config, engine)', 'void engine', 'closure'],
  ['restart recovery', 'await resume(config, startup)', 'void startup', 'recovery'],
  ['parser request correlation', 'const pending = pendingRequests.get(socket)', 'const pending = undefined', 'parser errors'],
  ['parser log once', 'if (malformedSockets.has(socket))', 'if (false)', 'parser errors'],
]
if (process.env.AUKORA_ADMISSION_GUARD_MUTANT !== undefined) {
  const index = Number(process.env.AUKORA_ADMISSION_GUARD_MUTANT), mutation = MUTATIONS[index]
  assert(mutation, 'known mutation')
  registerHooks({ load(url, context, next) {
    const result = next(url, context)
    if (url === new URL('../ops/buzz-relay/admission-server.mjs', import.meta.url).href) {
      const source = String(result.source)
      assert(source.includes(mutation[1]), 'mutation anchor')
      return { ...result, source: source.replace(mutation[1], mutation[2]) }
    }
    return result
  } })
}
const { startAdmissionServer, runCli, REFUSE } = await import('../ops/buzz-relay/admission-server.mjs')

function fixture(t, extra = {}) {
  const old = process.umask(0o002)
  let home
  try {
    home = fs.mkdtempSync(path.join(ROOT, 'tests/.admission-guards-'))
    fs.chmodSync(home, 0o700)
    fs.mkdirSync(path.join(home, 'keys'), { mode: 0o700 })
  } finally { process.umask(old) }
  const key = randomSecretKey(), memberKey = randomSecretKey(), root = publicKeyOf(key)
  const keyFile = path.join(home, 'keys/owner')
  fs.writeFileSync(keyFile, key + '\n', { mode: 0o600 })
  // Only checkout ancestors stand in for protected installation parents; fixture permissions stay real.
  const identities = new Set()
  for (let directory = ROOT; ; directory = path.dirname(directory)) {
    const st = fs.lstatSync(directory); identities.add(`${st.dev}:${st.ino}`)
    if (directory === '/') break
  }
  const standIn = st => {
    if (st && identities.has(`${st.dev}:${st.ino}`)) st.mode &= ~0o022
    return st
  }
  const fstat = fs.fstatSync, lstat = fs.lstatSync
  t.mock.method(fs, 'fstatSync', (...args) => standIn(fstat(...args)))
  t.mock.method(fs, 'lstatSync', (...args) => standIn(lstat(...args)))
  t.mock.method(http.Server.prototype, 'listen', function (_port, _host, callback) { queueMicrotask(callback); return this })
  t.after(() => fs.rmSync(home, { recursive: true, force: true }))
  const now = Math.floor(Date.now() / 1000), logs = [], sends = []
  let closed = true, broken = false
  const fetchImpl = async (_url, options) => {
    if (broken) throw new Error(key)
    const payload = JSON.parse(options.body)
    if (payload.kind === 9030) {
      sends.push(payload)
      return Response.json({ accepted: true, event_id: payload.id })
    }
    return closed ? Response.json({ error: 'relay_membership_required' }, { status: 403 }) : Response.json([])
  }
  const invite = createInvite({ root, secretKey: key, now })
  const body = { root, invite, chain: [] }
  const redemption = redeemInvite({ invite, secretKey: memberKey, now })
  const options = { keyFile, storeDir: path.join(home, 'store'), deadlineMs: 100, ...extra }
  const deps = { keyOptions: { home, deniedRoots: [] }, fetchImpl, now: () => now, log: line => logs.push(line) }
  const counts = () => {
    const file = path.join(options.storeDir, 'admissions.sqlite')
    if (!fs.existsSync(file)) return 0
    const db = new DatabaseSync(file, { readOnly: true })
    try { return db.prepare('SELECT count(*) AS n FROM consumed').get().n } finally { db.close() }
  }
  return { home, key, memberKey, keyFile, root, body, redemption, options, deps, logs, sends, counts,
    setClosed: value => { closed = value }, setBroken: value => { broken = value } }
}

async function request(server, value, { method = 'POST', url = '/preflight', headers = {}, rawHeaders, bytes, slow = false, chunks, parserError = false, address = '127.0.0.1' } = {}) {
  const req = new PassThrough()
  req.method = method; req.url = url
  req.headers = { 'content-type': 'application/json', ...headers }
  req.rawHeaders = rawHeaders ?? Object.entries(req.headers).flat()
  req.socket = Object.assign(new EventEmitter(), { remoteAddress: address, writable: true, end() {}, destroy() {} })
  const res = new EventEmitter()
  res.destroyed = false
  res.writeHead = (status, outputHeaders) => { res.status = status; res.headers = outputHeaders }
  const completed = new Promise(resolve => {
    res.end = body => { res.body = JSON.parse(body); queueMicrotask(() => res.emit('finish')); resolve(res) }
  })
  server.emit('request', req, res)
  if (parserError) queueMicrotask(() => { server.emit('clientError', new Error('invalid chunk'), req.socket); res.emit('close') })
  if (chunks) { for (const chunk of chunks) req.write(chunk); req.end() }
  else if (!slow) req.end(bytes ?? JSON.stringify(value))
  else req.write('{')
  const timeout = new Promise((_, reject) => { const timer = setTimeout(() => { res.emit('close'); reject(new Error('guard did not finish')) }, 700); timer.unref() })
  return Promise.race([completed, timeout])
}
const refused = (result, status, code = REFUSE.INPUT) => {
  assert.equal(result.status, status); assert.deepEqual(result.body, { code })
  assert.equal(result.headers['cache-control'], 'no-store'); assert(!result.headers.location)
}

test('binding requires explicit TLS proxy option; CLI refuses duplicate and unknown options', async t => {
  const f = fixture(t)
  await assert.rejects(() => startAdmissionServer({ ...f.options, host: '0.0.0.0' }, f.deps), error => error.code === REFUSE.INPUT)
  await startAdmissionServer({ ...f.options, host: '0.0.0.0', behindTlsProxy: true }, f.deps)
  const errors = []
  for (const args of [[], ['--key-file', f.keyFile, '--store', f.options.storeDir, '--host', 'bad'],
    ['--key-file', f.keyFile, '--store', f.options.storeDir, '--port', '1x'], ['--secret-key', f.key],
    ['--key-file', f.keyFile, '--store', f.options.storeDir, '--behind-tls-proxy', '--behind-tls-proxy']]) {
    assert.equal(await runCli(args, { ...f.deps, err: line => errors.push(line) }), 1)
  }
  assert(errors.every(line => line === REFUSE.INPUT))
})

test('protocol refuses methods, paths, encodings and repeated content type before spending', async t => {
  const f = fixture(t), server = await startAdmissionServer(f.options, f.deps)
  for (const [options, status] of [[{ method: 'GET' }, 405], [{ url: '/preflight?x=1' }, 404],
    [{ url: '/preflight/' }, 404], [{ url: '/other' }, 404], [{ headers: { 'content-type': 'text/plain' } }, 415],
    [{ headers: { 'content-type': 'application/json; charset=utf-8' } }, 415], [{ headers: { 'content-encoding': 'gzip' } }, 415],
    [{ rawHeaders: ['content-type', 'application/json', 'Content-Type', 'text/plain'] }, 415]]) {
    refused(await request(server, f.body, options), status)
  }
  const success = await request(server, f.body)
  assert.equal(success.status, 200); assert.equal(success.headers['cache-control'], 'no-store')
  assert.equal(f.counts(), 0)
})

test('body bounds refuse declared and streaming overflow without spending', async t => {
  const f = fixture(t), server = await startAdmissionServer({ ...f.options, bodyLimit: 2048 }, f.deps)
  refused(await request(server, f.body, { headers: { 'content-length': '4096' } }), 413)
  refused(await request(server, f.body, { chunks: [Buffer.alloc(1024, 32), Buffer.alloc(2048, 32)] }), 413)
  assert.equal(f.counts(), 0)
})

test('strict JSON rejects duplicate keys, Unicode errors, unknown fields and unsafe integers', async t => {
  const f = fixture(t), server = await startAdmissionServer(f.options, f.deps)
  for (const bytes of [JSON.stringify({ ...f.body, extra: f.key }),
    JSON.stringify(f.body).replace('"root":', '"root":"wrong","root":'),
    JSON.stringify(f.body).replace('"root":', '"extra":9007199254740993,"root":'),
    JSON.stringify(f.body).replace('"root":', '"extra":1.00000000000000001,"root":'),
    JSON.stringify(f.body).replace('"root":', '"extra":"\\ud800","root":'),
    Buffer.concat([Buffer.from('{"root":"'), Buffer.from([0xff]), Buffer.from('","invite":'), Buffer.from(JSON.stringify(f.body.invite)), Buffer.from(',"chain":[]}')]),
    '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0' + ']'.repeat(70)]) {
    refused(await request(server, f.body, { bytes }), 400)
  }
  assert.equal(f.counts(), 0)
})

test('network binds the supplied root before spending', async t => {
  const f = fixture(t), server = await startAdmissionServer(f.options, f.deps)
  refused(await request(server, { ...f.body, root: publicKeyOf(randomSecretKey()) }), 403, INVITES.NETWORK)
  assert.equal(f.counts(), 0)
})

test('deadline stops a slow body without spending or logging request bytes', async t => {
  const f = fixture(t), server = await startAdmissionServer(f.options, f.deps)
  refused(await request(server, f.body, { slow: true }), 408)
  assert.equal(f.counts(), 0); assert.equal(f.logs.length, 1)
})

test('parser errors log an active request or malformed header only once', async t => {
  const f = fixture(t), server = await startAdmissionServer(f.options, f.deps)
  refused(await request(server, f.body, { slow: true, parserError: true }), 400)
  assert.equal(f.logs.length, 1); assert.equal(f.counts(), 0)
  const socket = { writable: true, end() {}, destroy() {} }
  server.emit('clientError', new Error('invalid header'), socket)
  server.emit('clientError', new Error('same invalid header'), socket)
  assert.equal(f.logs.length, 2)
})

test('limits bound one socket peer and globally across peers; forwarding headers do not change identity', async t => {
  const f = fixture(t)
  const server = await startAdmissionServer({ ...f.options, addressLimit: 1, globalLimit: 2, windowMs: 300000 }, f.deps)
  assert.equal((await request(server, f.body)).status, 200)
  refused(await request(server, f.body, { headers: { 'x-forwarded-for': '203.0.113.2' } }), 429, REFUSE.BUSY)
  refused(await request(server, f.body), 429, REFUSE.BUSY)
  assert.equal((await request(server, f.body, { address: '127.0.0.2' })).status, 200)
  refused(await request(server, f.body, { address: '127.0.0.3' }), 429, REFUSE.BUSY)
})

test('forwarding requires an opted-in TLS proxy and a single valid address', async t => {
  const f = fixture(t), trustedAddressHeader = 'x-forwarded-for'
  await assert.rejects(() => startAdmissionServer({ ...f.options, trustedAddressHeader }, f.deps), error => error.code === REFUSE.INPUT)
  for (const value of ['', 'X-Forwarded-For', 'bad header']) {
    await assert.rejects(() => startAdmissionServer({ ...f.options, behindTlsProxy: true, trustedAddressHeader: value }, f.deps), error => error.code === REFUSE.INPUT)
  }
  const server = await startAdmissionServer({ ...f.options, behindTlsProxy: true, trustedAddressHeader, addressLimit: 1 }, f.deps)
  refused(await request(server, f.body), 400)
  for (const address of ['203.0.113.1, 203.0.113.2', 'unknown', ' 203.0.113.1']) {
    refused(await request(server, f.body, { headers: { 'x-forwarded-for': address } }), 400)
  }
  refused(await request(server, f.body, { headers: { 'x-forwarded-for': '203.0.113.1' },
    rawHeaders: ['content-type', 'application/json', 'X-Forwarded-For', '203.0.113.1', 'x-forwarded-for', '203.0.113.1'] }), 400)
  assert.equal((await request(server, f.body, { headers: { 'x-forwarded-for': '203.0.113.1' } })).status, 200)
  refused(await request(server, f.body, { headers: { 'x-forwarded-for': '203.0.113.1' } }), 429, REFUSE.BUSY)
  assert.equal((await request(server, f.body, { headers: { 'x-forwarded-for': '203.0.113.2' } })).status, 200)
  assert.equal(f.counts(), 0)
})

test('redaction returns stable codes and logs only invite id and outcome', async t => {
  const f = fixture(t), server = await startAdmissionServer(f.options, f.deps)
  f.setBroken(true)
  refused(await request(server, { ...f.body, redemption: f.redemption }, { url: '/redeem' }), 503, 'buzz-member:closed-not-proved')
  await request(server, { ...f.body, extra: f.key })
  for (const log of f.logs) {
    assert.deepEqual(Object.keys(JSON.parse(log)).sort(), ['invite_id', 'outcome'])
    assert(!log.includes(f.key)); assert(!log.includes(f.keyFile))
  }
  const errors = []
  f.setBroken(false)
  const failing = await startAdmissionServer(f.options, { ...f.deps, onStage: stage => { if (stage === 'spent') throw new Error(f.key) } })
  refused(await request(failing, { ...f.body, redemption: f.redemption }, { url: '/redeem' }), 503, REFUSE.UNKNOWN)
  await runCli(['--key-file', f.keyFile, '--store', f.options.storeDir], { ...f.deps,
    log: () => { throw new Error(f.key) }, err: value => errors.push(value) })
  assert(errors.every(line => !line.includes(f.key)))
})

test('closure is required at start and again before redemption', async t => {
  const f = fixture(t)
  f.setClosed(false)
  await assert.rejects(() => startAdmissionServer(f.options, f.deps), error => error.code === 'buzz-member:closed-not-proved')
  f.setClosed(true)
  const server = await startAdmissionServer(f.options, f.deps)
  f.setClosed(false)
  refused(await request(server, { ...f.body, redemption: f.redemption }, { url: '/redeem' }), 503, 'buzz-member:closed-not-proved')
  assert.equal(f.counts(), 0)
})

test('recovery completes a pending spend before accepting requests; exact replay spends once', async t => {
  const f = fixture(t)
  const server = await startAdmissionServer(f.options, { ...f.deps, onStage: stage => { if (stage === 'spent') throw new Error('injected crash') } })
  refused(await request(server, { ...f.body, redemption: f.redemption }, { url: '/redeem' }), 503, REFUSE.UNKNOWN)
  assert.equal(f.counts(), 1); assert.equal(f.sends.length, 0)
  const restarted = await startAdmissionServer(f.options, f.deps)
  assert.equal(f.sends.length, 1)
  const replay = await request(restarted, { ...f.body, redemption: f.redemption }, { url: '/redeem' })
  assert.equal(replay.status, 200); assert.equal(f.sends.length, 1); assert.equal(f.counts(), 1)
  assert.equal(verifyAdmissionRecord({ root: f.root, record: replay.body.record }).member, f.redemption.pubkey)
  const repeated = await request(restarted, { ...f.body, redemption: f.redemption }, { url: '/redeem' })
  assert.deepEqual(repeated.body.record, replay.body.record)
  const again = await startAdmissionServer(f.options, f.deps)
  const afterRestart = await request(again, { ...f.body, redemption: f.redemption }, { url: '/redeem' })
  assert.deepEqual(afterRestart.body.record, replay.body.record)
})

test('confirmation cache rejects forged signatures and unrelated owner-signed chains', async t => {
  const f = fixture(t), server = await startAdmissionServer(f.options, f.deps)
  const payload = { ...f.body, redemption: f.redemption }
  const first = await request(server, payload, { url: '/redeem' })
  assert.equal(first.status, 200)
  const database = new DatabaseSync(path.join(f.options.storeDir, 'admissions.sqlite'))
  t.after(() => database.close())
  const update = record => database.prepare('UPDATE confirmations SET record = ? WHERE redemptionId = ?').run(JSON.stringify(record), f.redemption.id)
  const forged = structuredClone(first.body.record)
  forged.confirmation.sig = '00'.repeat(64)
  update(forged)
  refused(await request(server, payload, { url: '/redeem' }), 503, REFUSE.STORE)
  const now = Math.floor(Date.now() / 1000)
  const invite = createInvite({ root: f.root, secretKey: f.key, now })
  const redemption = redeemInvite({ invite, secretKey: f.memberKey, now })
  const unrelated = createAdmissionRecord({ root: f.root, secretKey: f.key, record: { chain: [{ invite, redemption }] }, now })
  update(unrelated)
  refused(await request(server, payload, { url: '/redeem' }), 503, REFUSE.STORE)
  assert.equal(f.counts(), 1); assert.equal(f.sends.length, 1)
})

test('HTTP protections fail under isolated parallel mutations', { skip: process.env.AUKORA_ADMISSION_GUARD_MUTATIONS !== '1' }, async () => {
  const source = fs.readFileSync(SOURCE, 'utf8')
  for (const [name, anchor] of MUTATIONS) assert(source.includes(anchor), `mutation anchor ${name}`)
  const run = index => new Promise(resolve => {
    const args = ['--test', '--test-reporter=tap', '--test-name-pattern', MUTATIONS[index][3], fileURLToPath(import.meta.url)]
    const env = { ...process.env, AUKORA_ADMISSION_GUARD_MUTATIONS: '0', AUKORA_ADMISSION_GUARD_MUTANT: String(index) }
    delete env.NODE_TEST_CONTEXT
    const child = spawn(process.execPath, args, { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] })
    let output = ''
    child.stdout.on('data', bytes => { output += bytes })
    child.stderr.resume()
    const timer = setTimeout(() => child.kill('SIGKILL'), 4000)
    child.on('close', code => { clearTimeout(timer); resolve({ code, output }) })
  })
  for (let start = 0; start < MUTATIONS.length; start += 4) {
    const indices = Array.from({ length: Math.min(4, MUTATIONS.length - start) }, (_, offset) => start + offset)
    const results = await Promise.all(indices.map(run))
    for (let offset = 0; offset < indices.length; offset++) {
      const index = indices[offset], result = results[offset]
      assert(result.code === 1 && /# fail [1-9]/u.test(result.output), `mutation survived or did not run: ${MUTATIONS[index][0]}`)
      console.log(`mutation ${MUTATIONS[index][0]}: KILLED`)
    }
  }
  console.log(`HTTP mutations ${MUTATIONS.length}/${MUTATIONS.length} KILLED (synthetic streams; no listen)`)
})
