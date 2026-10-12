// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise remote admission, bounded HTTP refusals and recovery with a signed closed-relay stand-in.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { DatabaseSync } from 'node:sqlite'
import { createInvite, redeemInvite, verifyAdmissionRecord, TTL_SECONDS, REFUSE as INVITES } from '../packages/invites/index.mjs'
import { publicKeyOf, randomSecretKey, verifyEvent } from '../plugins/aukora-nostr/lib/event.mjs'
import { preflight, redeem, verifyBinding, REFUSE as CLIENT } from '../ops/node-spawn/invite.mjs'
import { REFUSE } from '../ops/buzz-relay/admit.mjs'
import { REFUSE as MEMBER } from '../ops/buzz-relay/member.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SOURCE = fileURLToPath(new URL('../ops/buzz-relay/admission-server.mjs', import.meta.url))
const selected = process.env.AUKORA_ADMISSION_CASE
const priorMask = process.umask(0o002)
// Shared checkout ancestors stand in for protected service paths; fixture and key modes stay real.
const fstat = fs.fstatSync, lstat = fs.lstatSync
const protectedAncestors = new Set()
for (let directory = HERE; ; directory = path.dirname(directory)) {
  const st = lstat(directory); protectedAncestors.add(`${st.dev}:${st.ino}`)
  if (directory === path.dirname(directory)) break
}
const fixtureAncestor = st => {
  if (st?.isDirectory() && protectedAncestors.has(`${st.dev}:${st.ino}`)) st.mode &= ~0o022
  return st
}
fs.fstatSync = (...args) => fixtureAncestor(fstat(...args))
fs.lstatSync = (...args) => fixtureAncestor(lstat(...args))
let passed = 0, failed = 0
const cases = []
const check = (name, callback) => cases.push({ name, callback })
const reject = (callback, code) => assert.rejects(callback, error => error.code === code)
const unperformed = error => error?.syscall === 'listen' && ['EPERM', 'EACCES'].includes(error?.code)

function fixture() {
  const home = fs.mkdtempSync(path.join(HERE, '.admission-server-'))
  fs.chmodSync(home, 0o700)
  const keys = path.join(home, 'keys'); fs.mkdirSync(keys, { mode: 0o700 })
  const people = Array.from({ length: 8 }, (_, index) => {
    const key = randomSecretKey(), keyFile = path.join(keys, String(index))
    fs.writeFileSync(keyFile, key + '\n', { mode: 0o600 })
    assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600)
    return { key, keyFile, pubkey: publicKeyOf(key) }
  })
  const now = Math.floor(Date.now() / 1000), storeDir = path.join(home, 'store')
  return { home, people, now, storeDir, keyOptions: { home, deniedRoots: [] },
    options: { keyFile: people[0].keyFile, storeDir, port: 0, baseUrl: 'http://localhost:3000' } }
}
function pair(f, inviter = 0, member = 1, now = f.now) {
  const invite = createInvite({ root: f.people[0].pubkey, secretKey: f.people[inviter].key, now })
  return { invite, redemption: redeemInvite({ invite, secretKey: f.people[member].key, now }) }
}
const input = (f, claim, chain = []) => ({ root: f.people[0].pubkey, invite: claim.invite, chain, redemption: claim.redemption })
const offer = claim => ({ invite: claim.invite, chain: [] })
function counts(f) {
  const file = path.join(f.storeDir, 'admissions.sqlite')
  if (!fs.existsSync(file)) return { consumed: 0, admissions: 0 }
  const db = new DatabaseSync(file, { readOnly: true })
  try { return Object.fromEntries(['consumed', 'admissions'].map(table => [table,
    db.prepare(`SELECT count(*) AS n FROM ${table}`).get().n])) } finally { db.close() }
}
function journal(f) {
  const file = path.join(f.storeDir, 'admissions.jsonl')
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : []
}

// This is the admit.test.mjs bridge: NIP-98 and owner-signed commands precede each closed-roster change.
function bridge(owner) {
  const members = new Set([owner]), additions = [], errors = [], nonces = new Set()
  const fetchImpl = async (url, options) => {
    try {
      const request = new Request(url, options), route = new URL(url).pathname
      assert.equal(request.method, 'POST'); assert.equal(request.headers.get('content-type'), 'application/json')
      assert.equal(options.redirect, 'error')
      assert.match(request.headers.get('authorization') ?? '', /^Nostr /u)
      const auth = JSON.parse(Buffer.from(request.headers.get('authorization').slice(6), 'base64').toString('utf8'))
      assert.equal(verifyEvent(auth), true); assert.equal(auth.kind, 27235); assert.equal(auth.content, '')
      assert(Math.abs(auth.created_at - Math.floor(Date.now() / 1000)) <= 5)
      const body = await request.text(), tags = Object.fromEntries(auth.tags), data = JSON.parse(body)
      assert.equal(tags.u, url); assert.equal(tags.method, 'POST')
      assert.equal(tags.payload, createHash('sha256').update(body).digest('hex'))
      assert.equal(typeof tags.nonce, 'string'); assert(!nonces.has(tags.nonce)); nonces.add(tags.nonce)
      if (route === '/events') {
        assert.equal(verifyEvent(data), true); assert.equal(data.pubkey, auth.pubkey)
        assert(Math.abs(data.created_at - Math.floor(Date.now() / 1000)) <= 5)
      } else assert.equal(route, '/query')
      if (!members.has(auth.pubkey)) return Response.json({ error: 'relay_membership_required' }, { status: 403 })
      if (route === '/query') return Response.json([])
      assert.equal(data.kind, 9030); assert.equal(auth.pubkey, owner)
      assert.deepEqual(data.tags.map(tag => tag[0]), ['p', 'role'])
      assert.equal(data.tags[1][1], 'member'); assert.equal(data.content, '')
      additions.push(data); members.add(data.tags[0][1])
      return Response.json({ accepted: true, event_id: data.id })
    } catch {
      errors.push('invalid signed request')
      return Response.json({ error: 'auth_failed' }, { status: 401 })
    }
  }
  return { members, additions, errors, fetchImpl }
}
async function close(server) {
  server.closeAllConnections()
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
}
async function serve(f, settings = {}, deps = {}) {
  const b = bridge(f.people[0].pubkey), logs = []
  const server = await startAdmissionServer({ ...f.options, ...settings }, {
    keyOptions: f.keyOptions, now: () => f.now, fetchImpl: b.fetchImpl, log: line => logs.push(line), ...deps,
  })
  const url = `http://127.0.0.1:${server.address().port}`
  return { server, url, b, logs, config: { version: 1, root: f.people[0].pubkey, admission: url } }
}
async function withServer(callback, settings = {}, deps = {}) {
  const f = fixture()
  let s
  try { s = await serve(f, settings, deps); await callback(f, s) }
  finally { if (s) await close(s.server); fs.rmSync(f.home, { recursive: true, force: true }) }
}
async function post(s, route, body, settings = {}) {
  const response = await fetch(s.url + route, { method: 'POST', redirect: 'error',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    signal: AbortSignal.timeout(3000), ...settings })
  const text = await response.text()
  return { status: response.status, headers: response.headers, text, data: JSON.parse(text) }
}
function refused(result, code) {
  assert.notEqual(result.status, 200); assert(result.status >= 400 && result.status < 600)
  assert.deepEqual(result.data, { code }); assert.equal(result.headers.get('cache-control'), 'no-store')
  assert.equal(result.headers.get('location'), null)
}
function logsOnly(logs, people) {
  for (const line of logs) {
    assert.equal(typeof line, 'string')
    const value = JSON.parse(line)
    assert.deepEqual(Object.keys(value).sort(), ['invite_id', 'outcome'])
    assert(value.invite_id === null || /^[0-9a-f]{64}$/u.test(value.invite_id))
    assert(['available', 'admitted', ...Object.values(REFUSE), ...Object.values(INVITES), ...Object.values(MEMBER)].includes(value.outcome))
    for (const person of people) assert(!line.includes(person.key))
  }
}

check('configuration', async () => {
  const f = fixture()
  try {
    for (const host of ['0.0.0.0', '192.0.2.1', '::']) {
      await reject(() => startAdmissionServer({ ...f.options, host }, { keyOptions: f.keyOptions }), REFUSE.INPUT)
    }
    for (const port of [-1, 65536, 1.5, '3100']) {
      await reject(() => startAdmissionServer({ ...f.options, port }, { keyOptions: f.keyOptions }), REFUSE.INPUT)
    }
    assert.deepEqual(counts(f), { consumed: 0, admissions: 0 })
  } finally { fs.rmSync(f.home, { recursive: true, force: true }) }
})
check('client and idempotence', () => withServer(async (f, s) => {
  assert.equal(s.server.address().address, '127.0.0.1')
  const claim = pair(f), o = offer(claim)
  await preflight({ config: s.config, offer: o, now: f.now })
  await preflight({ config: s.config, offer: o, now: f.now })
  assert.deepEqual(counts(f), { consumed: 0, admissions: 0 }); assert.equal(s.b.additions.length, 0)
  const record = await redeem({ config: s.config, offer: o, keyFile: f.people[1].keyFile, now: f.now }, { keyOptions: f.keyOptions })
  assert.equal(verifyAdmissionRecord({ root: s.config.root, record }).member, f.people[1].pubkey)
  assert.equal(record.chain.at(-1).redemption.id, claim.redemption.id)
  claim.redemption = record.chain.at(-1).redemption
  assert.deepEqual(record.chain, [claim]); assert.deepEqual(counts(f), { consumed: 1, admissions: 1 })
  assert.equal(s.b.additions.length, 1); assert(s.b.members.has(f.people[1].pubkey))
  const replay = await post(s, '/redeem', input(f, claim))
  assert.equal(replay.status, 200); assert.deepEqual(replay.data, { admitted: true, record })
  assert.equal(replay.headers.get('cache-control'), 'no-store')
  assert.equal(s.b.additions.length, 1); assert.deepEqual(counts(f), { consumed: 1, admissions: 1 })
  assert.equal(journal(f).length, 1)
  const resigned = redeemInvite({ invite: claim.invite, secretKey: f.people[1].key, now: f.now })
  assert.equal(resigned.id, claim.redemption.id)
  const sameId = await post(s, '/redeem', input(f, { invite: claim.invite, redemption: resigned }))
  assert.deepEqual(sameId.data, replay.data); assert.equal(s.b.additions.length, 1)
  refused(await post(s, '/redeem', input(f, { invite: claim.invite,
    redemption: redeemInvite({ invite: claim.invite, secretKey: f.people[2].key, now: f.now }) })), INVITES.REPLAY)
  const { redemption, ...preflightInput } = input(f, claim)
  refused(await post(s, '/preflight', preflightInput), INVITES.REPLAY)
  assert.deepEqual(s.b.errors, []); assert.equal(s.logs.length, 7); logsOnly(s.logs, f.people)
  for (const name of ['lock.sqlite', 'admissions.sqlite', 'admissions.jsonl']) {
    assert.equal(fs.statSync(path.join(f.storeDir, name)).mode & 0o777, 0o600)
  }
  assert.equal(fs.statSync(f.storeDir).mode & 0o777, 0o700)
}))
check('invite refusals', () => withServer(async (f, s) => {
  const expired = pair(f, 0, 1, f.now - TTL_SECONDS), stranger = pair(f, 6, 7)
  const missing = pair(f), next = pair(f, 1, 2)
  for (const [claim, chain, code] of [[expired, [], INVITES.EXPIRED], [stranger, [], INVITES.CHAIN],
    [next, [missing], INVITES.UNADMITTED]]) {
    for (const route of ['/preflight', '/redeem']) {
      const body = input(f, claim, chain); if (route === '/preflight') delete body.redemption
      refused(await post(s, route, body), code)
    }
  }
  assert.deepEqual(counts(f), { consumed: 0, admissions: 0 }); assert.equal(s.b.additions.length, 0)
  const first = pair(f), admitted = await post(s, '/redeem', input(f, first)), chain = admitted.data.record.chain
  for (const member of [2, 3, 4]) assert.equal((await post(s, '/redeem', input(f, pair(f, 1, member), chain))).status, 200)
  const fourth = input(f, pair(f, 1, 5), chain)
  refused(await post(s, '/redeem', fourth), INVITES.ALLOTMENT)
  delete fourth.redemption; refused(await post(s, '/preflight', fourth), INVITES.ALLOTMENT)
  assert.deepEqual(counts(f), { consumed: 4, admissions: 4 }); assert.equal(s.b.additions.length, 4)
  const wrongRoot = input(f, pair(f, 0, 5)); wrongRoot.root = f.people[7].pubkey
  refused(await post(s, '/redeem', wrongRoot), INVITES.NETWORK)
  assert.deepEqual(counts(f), { consumed: 4, admissions: 4 }); logsOnly(s.logs, f.people)
}))
check('HTTP shape', () => withServer(async (f, s) => {
  const claim = pair(f), body = input(f, claim), valid = JSON.stringify(body)
  for (const [route, settings] of [
    ['/redeem', { method: 'GET', body: undefined }], ['/redeem/', {}], ['/redeem?private-marker=1', {}],
    ['//redeem', {}], ['/unknown', {}], ['/redeem', { headers: { 'content-type': 'text/plain' } }],
    ['/redeem', { headers: {} }], ['/redeem', { headers: { 'content-type': 'application/json; charset=utf-8' } }],
    ['/redeem', { body: JSON.stringify({ ...body, privateMarker: 'private-marker' }) }],
    ['/redeem', { body: valid.replace('{', '{"root":"private-marker",') }],
    ['/redeem', { body: '{"private-marker":1.00000000000000001}' }],
    ['/redeem', { body: '{"private-marker":"\\ud800"}' }],
    ['/redeem', { body: 'null' }], ['/redeem', { body: '[]' }], ['/redeem', { body: '{' }],
    ['/redeem', { body: Buffer.from([0xff, 0xfe]) }],
  ]) {
    const result = await post(s, route, body, settings)
    refused(result, REFUSE.INPUT); assert(!result.text.includes('private-marker'))
  }
  const unknownInviteField = structuredClone(body); unknownInviteField.invite.extra = 'private-marker'
  refused(await post(s, '/redeem', unknownInviteField), INVITES.SHAPE)
  const misplaced = input(f, claim); refused(await post(s, '/preflight', misplaced), REFUSE.INPUT)
  assert.deepEqual(counts(f), { consumed: 0, admissions: 0 }); assert.equal(s.b.additions.length, 0)
  assert.equal(s.logs.length, 18); logsOnly(s.logs, f.people)
  assert(s.logs.every(line => !line.includes('private-marker')))
}))
check('body limits and deadline', () => withServer(async (f, s) => {
  const body = input(f, pair(f))
  refused(await post(s, '/redeem', body, { body: JSON.stringify(body) + ' '.repeat(4097) }), REFUSE.INPUT)
  const partial = await new Promise((resolve, rejectPromise) => {
    const request = http.request(s.url + '/redeem', { method: 'POST', headers: { 'content-type': 'application/json' } }, response => {
      let text = ''; response.setEncoding('utf8'); response.on('data', chunk => { text += chunk })
      response.on('end', () => { request.destroy(); resolve({ status: response.statusCode,
        headers: new Headers(response.headers), text, data: JSON.parse(text) }) })
    })
    request.on('error', rejectPromise); request.setTimeout(1500, () => request.destroy(new Error('test request deadline')))
    request.write('{"root":')
  })
  refused(partial, REFUSE.INPUT)
  const chunks = await new Promise((resolve, rejectPromise) => {
    const request = http.request(s.url + '/redeem', { method: 'POST', headers: { 'content-type': 'application/json' } }, response => {
      let text = ''; response.setEncoding('utf8'); response.on('data', chunk => { text += chunk })
      response.on('end', () => { request.destroy(); resolve({ status: response.statusCode,
        headers: new Headers(response.headers), text, data: JSON.parse(text) }) })
    })
    request.on('error', rejectPromise); request.setTimeout(1500, () => request.destroy(new Error('test request deadline')))
    request.write(' '.repeat(4097)); request.end()
  })
  refused(chunks, REFUSE.INPUT)
  assert.deepEqual(counts(f), { consumed: 0, admissions: 0 }); assert.equal(s.b.additions.length, 0)
  assert.equal(s.logs.length, 3); logsOnly(s.logs, f.people)
}, { bodyLimit: 4096, deadlineMs: 100 }))
check('address limit', async () => {
  const originalNow = Date.now
  let now = originalNow()
  Date.now = () => now
  try { await withServer(async (f, s) => {
    const body = input(f, pair(f)); delete body.redemption
    assert.equal((await post(s, '/preflight', body)).status, 200)
    assert.equal((await post(s, '/preflight', body)).status, 200)
    refused(await post(s, '/preflight', body), REFUSE.BUSY)
    now += 2000
    assert.equal((await post(s, '/preflight', body)).status, 200)
    assert.deepEqual(counts(f), { consumed: 0, admissions: 0 }); assert.equal(s.b.additions.length, 0)
    assert.equal(s.logs.length, 4); logsOnly(s.logs, f.people)
  }, { windowMs: 1000, addressLimit: 2, globalLimit: 10 }) } finally { Date.now = originalNow }
})
check('global limit', () => withServer(async (f, s) => {
  const body = input(f, pair(f)); delete body.redemption
  assert.equal((await post(s, '/preflight', body)).status, 200)
  refused(await post(s, '/preflight', body), REFUSE.BUSY)
  assert.deepEqual(counts(f), { consumed: 0, admissions: 0 }); assert.equal(s.b.additions.length, 0)
  assert.equal(s.logs.length, 2); logsOnly(s.logs, f.people)
}, { addressLimit: 10, globalLimit: 1 }))
check('per-address refusals preserve global allowance', () => withServer(async (f, s) => {
  const body = input(f, pair(f)); delete body.redemption
  const from = address => post(s, '/preflight', body, { headers: {
    'content-type': 'application/json', 'x-client-address': address,
  } })
  assert.equal((await from('192.0.2.1')).status, 200)
  refused(await from('192.0.2.1'), REFUSE.BUSY)
  refused(await from('192.0.2.1'), REFUSE.BUSY)
  assert.equal((await from('192.0.2.2')).status, 200, 'A=200,429,429 must leave B allowance')
  refused(await from('192.0.2.3'), REFUSE.BUSY)
  assert.deepEqual(counts(f), { consumed: 0, admissions: 0 })
}, { behindTlsProxy: true, trustedAddressHeader: 'x-client-address', addressLimit: 1,
  globalLimit: 2, windowMs: 300000 }))
check('isolated key', async () => {
  const f = fixture(), b = bridge(f.people[0].pubkey)
  try {
    fs.chmodSync(f.people[0].keyFile, 0o640)
    await reject(() => startAdmissionServer(f.options, { keyOptions: f.keyOptions, fetchImpl: b.fetchImpl }), MEMBER.KEY)
    assert.deepEqual(counts(f), { consumed: 0, admissions: 0 }); assert.equal(b.additions.length, 0)
  } finally { fs.rmSync(f.home, { recursive: true, force: true }) }
})

async function crashServer(f, b) {
  const config = path.join(f.home, 'crash-config.json')
  fs.writeFileSync(config, JSON.stringify({ options: f.options, keyOptions: f.keyOptions, now: f.now }), { mode: 0o600 })
  const script = `import fs from 'node:fs'; import {startAdmissionServer} from ${JSON.stringify(pathToFileURL(SOURCE).href)};
const c=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));const waiting=new Map();let id=0;
const ancestors=new Set();const fstat=fs.fstatSync,lstat=fs.lstatSync;
for(let dir=${JSON.stringify(HERE)};;dir=dir.slice(0,dir.lastIndexOf('/'))||'/'){const st=lstat(dir);ancestors.add(st.dev+':'+st.ino);if(dir==='/')break}
const protectedStat=st=>{if(st?.isDirectory()&&ancestors.has(st.dev+':'+st.ino))st.mode&=~0o022;return st};
fs.fstatSync=(...args)=>protectedStat(fstat(...args));fs.lstatSync=(...args)=>protectedStat(lstat(...args));
process.on('message',m=>{if(m.kind==='response'){const resolve=waiting.get(m.id);waiting.delete(m.id);resolve(new Response(m.body,{status:m.status}))}});
const fetchImpl=(url,options)=>new Promise(resolve=>{const request=++id;waiting.set(request,resolve);process.send({kind:'fetch',id:request,url,options:{method:options.method,body:options.body,headers:options.headers,redirect:options.redirect}})});
const server=await startAdmissionServer(c.options,{keyOptions:c.keyOptions,now:()=>c.now,fetchImpl,log:()=>{},onStage:stage=>{if(stage==='spent'){fs.writeFileSync(${JSON.stringify(path.join(f.home,'spent-marker'))},'spent',{mode:0o600});process.kill(process.pid,'SIGKILL')}}});
process.send({kind:'ready',port:server.address().port});`
  const child = spawn(process.execPath, ['--input-type=module', '--eval', script, config], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] })
  let stderr = ''
  child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => { stderr += chunk })
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })))
  const ready = new Promise((resolve, rejectPromise) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); rejectPromise(new Error('crash fixture startup deadline')) }, 3000)
    child.on('message', async message => {
      if (message.kind === 'ready') { clearTimeout(timer); resolve(message.port) }
      else if (message.kind === 'fetch') {
        const response = await b.fetchImpl(message.url, message.options), body = await response.text()
        if (child.connected) child.send({ kind: 'response', id: message.id, body, status: response.status })
      }
    })
    child.once('exit', () => { clearTimeout(timer); rejectPromise(new Error('crash fixture exited before ready')) })
  })
  return { child, ready, exited, get stderr() { return stderr } }
}
check('client crash recovery', async () => {
  const f = fixture(), b = bridge(f.people[0].pubkey), claim = pair(f)
  let s, c
  try {
    c = await crashServer(f, b); const port = await c.ready
    const config = { version: 1, root: f.people[0].pubkey, admission: `http://127.0.0.1:${port}` }
    const args = { config, offer: offer(claim), keyFile: f.people[1].keyFile, now: f.now }
    const requests = [], deps = { keyOptions: f.keyOptions, fetchImpl: (url, options) => {
      requests.push(options.body); return fetch(url, options)
    } }
    await reject(() => redeem(args, deps), CLIENT.SPENT)
    const exited = await c.exited; assert.equal(exited.signal, 'SIGKILL'); assert.equal(fs.readFileSync(path.join(f.home, 'spent-marker'), 'utf8'), 'spent')
    assert.deepEqual(counts(f), { consumed: 1, admissions: 1 }); assert.equal(b.additions.length, 0)
    const pending = JSON.parse(fs.readFileSync(args.keyFile + '.invite-pending.json', 'utf8'))
    claim.redemption = pending.redemption
    const forged = { chain: [claim] }
    await assert.rejects(() => redeem({ ...args, resumeRecord: forged }, deps))
    assert.equal(requests.length, 1, 'a locally constructed record cannot confirm admission')
    s = await serve(f, { port }, { fetchImpl: b.fetchImpl, now: () => f.now + TTL_SECONDS + 1 })
    assert.equal(b.additions.length, 1); assert.equal(journal(f).length, 1)
    const record = await redeem({ ...args, now: f.now + TTL_SECONDS + 1 }, deps)
    assert.equal(verifyAdmissionRecord({ root: config.root, record }).member, f.people[1].pubkey)
    assert.equal(requests.length, 2); assert.equal(requests[1], requests[0], 'resume replays identical signed bytes')
    const result = await post(s, '/redeem', input(f, claim))
    assert.equal(result.status, 200); assert.deepEqual(result.data, { admitted: true, record })
    const replay = await post(s, '/redeem', input(f, claim))
    assert.deepEqual(replay.data, result.data); assert.equal(b.additions.length, 1)
    assert.deepEqual(counts(f), { consumed: 1, admissions: 1 }); assert.equal(journal(f).length, 1)
    assert.deepEqual(b.errors, []); for (const person of f.people) assert(!c.stderr.includes(person.key))
  } finally {
    if (s) await close(s.server); if (c?.child.exitCode === null && c?.child.signalCode === null) c.child.kill('SIGKILL')
    fs.rmSync(f.home, { recursive: true, force: true })
  }
})

check('client transport retry and forged record', async () => {
  const f = fixture()
  let s, closed = false
  try {
    s = await serve(f)
    const port = s.server.address().port, config = s.config, claim = pair(f)
    await close(s.server); closed = true
    const args = { config, offer: offer(claim), keyFile: f.people[1].keyFile, now: f.now }
    const requests = [], deps = { keyOptions: f.keyOptions, fetchImpl: (url, options) => {
      requests.push(options.body); return fetch(url, options)
    } }
    await reject(() => redeem(args, deps), CLIENT.SPENT)
    assert.deepEqual(counts(f), { consumed: 0, admissions: 0 })
    const pending = JSON.parse(fs.readFileSync(args.keyFile + '.invite-pending.json', 'utf8'))
    const forged = { chain: [{ invite: claim.invite, redemption: pending.redemption }] }
    await assert.rejects(() => redeem({ ...args, resumeRecord: forged }, deps))
    assert.throws(() => verifyBinding({ config, record: forged, keyFile: args.keyFile }, deps))
    assert.equal(requests.length, 1, 'ADMITTED authority_count=0 is refused')
    assert.equal(fs.existsSync(args.keyFile + '.invite-confirmed.json'), false)
    s = await serve(f, { port }); closed = false
    const record = await redeem(args, deps)
    assert.equal(verifyAdmissionRecord({ root: config.root, record }).member, f.people[1].pubkey)
    assert.equal(requests.length, 2, 'transport_attempts=1 must not strand the pending invite')
    assert.equal(requests[1], requests[0])
    assert.deepEqual(counts(f), { consumed: 1, admissions: 1 }); assert.equal(s.b.additions.length, 1)
  } finally {
    if (s && !closed) await close(s.server)
    fs.rmSync(f.home, { recursive: true, force: true })
  }
})

let startAdmissionServer
try {
  const module = await import(pathToFileURL(SOURCE).href); startAdmissionServer = module.startAdmissionServer
  assert.equal(typeof startAdmissionServer, 'function')
  const offline = name => ['configuration', 'isolated key'].includes(name)
  for (const entry of [...cases.filter(entry => offline(entry.name)), ...cases.filter(entry => !offline(entry.name))]) {
    if (selected && selected !== entry.name) continue
    if (!['configuration', 'isolated key'].includes(entry.name)) {
      const probe = http.createServer()
      try {
        await new Promise((resolve, rejectPromise) => { probe.once('error', rejectPromise); probe.listen(0, '127.0.0.1', resolve) })
        await close(probe)
      } catch (error) {
        if (!unperformed(error)) throw error
        console.log(`UNPERFORMED: loopback listen refused (${error.code})`)
        console.log(`admission-server: ${passed} PASS, ${failed} FAIL, 1 UNPERFORMED`)
        process.exitCode = failed ? 1 : 2
        break
      }
    }
    try { await entry.callback(); passed++; console.log(`PASS: admission-server ${entry.name}`) }
    catch (error) { failed++; console.log(`FAIL: admission-server ${entry.name} (${error?.code ?? 'error'})`) }
  }
  if (process.exitCode !== 2) {
    console.log(`admission-server: ${passed} PASS, ${failed} FAIL, 0 UNPERFORMED`)
    process.exitCode = failed ? 1 : 0
  }
} finally { fs.fstatSync = fstat; fs.lstatSync = lstat; process.umask(priorMask) }
