import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { createMemberClient, verifyClosed, runCli, REFUSE } from './member.mjs'
import { publicKeyOf, randomSecretKey, verifyEvent } from '../../plugins/aukora-nostr/lib/event.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SOURCE = path.join(HERE, 'member.mjs')
const TEST = fileURLToPath(import.meta.url)
const CHANNEL = '12345678-1234-1234-1234-123456789abc'
const target = publicKeyOf(randomSecretKey())
const denial = { status: 403, data: { error: 'relay_membership_required', message: 'You must be a relay member to access this relay' } }
const rejects = (fn, code) => assert.rejects(fn, error => error.code === code)
const throws = (fn, code) => assert.throws(fn, error => error.code === code)
const actualStats = { fstatSync: fs.fstatSync, lstatSync: fs.lstatSync }, protectedContexts = new WeakSet()

// Only checkout ancestors stand in for protected installed parents; fixture permissions remain real.
function protectedAncestors(t) {
  if (protectedContexts.has(t)) return
  protectedContexts.add(t)
  const identities = []
  for (let directory = HERE; ; directory = path.dirname(directory)) {
    const st = actualStats.lstatSync(directory)
    if (st.mode & 0o022) identities.push(`${st.dev}:${st.ino}`)
    if (directory === '/') break
  }
  for (const name of ['fstatSync', 'lstatSync']) t.mock.method(fs, name, (...args) => {
    const st = actualStats[name](...args)
    if (st?.isDirectory() && identities.includes(`${st.dev}:${st.ino}`)) st.mode &= ~0o022
    return st
  })
}

function fixture(t) {
  protectedAncestors(t)
  const home = fs.mkdtempSync(path.join(HERE, '.member-test-'))
  fs.chmodSync(home, 0o700)
  const dir = path.join(home, 'keys'); fs.mkdirSync(dir, { mode: 0o700 })
  const keyFile = path.join(dir, 'key'), key = randomSecretKey()
  fs.writeFileSync(keyFile, key + '\n', { mode: 0o600 })
  t.after(() => fs.rmSync(home, { recursive: true, force: true }))
  return { home, dir, keyFile, key, keyOptions: { home, deniedRoots: [] } }
}

function client(f, options = {}) {
  return createMemberClient({ keyFile: f.keyFile, baseUrl: options.baseUrl }, { keyOptions: f.keyOptions, ...options })
}

// The stand-in checks actual signatures and request bytes before returning any membership decision.
async function bridge(_t, respond = () => denial) {
  const requests = [], errors = [], nonces = new Set()
  const baseUrl = 'http://localhost:3000'
  const fetchImpl = async (url, options) => {
    const req = new Request(url, options), route = new URL(url).pathname
    let data, auth
    try {
      assert.equal(req.method, 'POST')
      assert.equal(req.headers.get('content-type'), 'application/json')
      if (!req.headers.has('authorization')) {
        data = JSON.parse(await req.text())
        if (route === '/events') verifyEvent(data)
        else { assert.equal(route, '/query'); assert.equal(data[0].authors.length, 1) }
        requests.push({ route, data, auth: null })
        const reply = respond({ route, data, auth: null })
        return new Response(reply.raw ?? JSON.stringify(reply.data), { status: reply.status ?? 200 })
      }
      assert.match(req.headers.get('authorization') ?? '', /^Nostr /u)
      auth = JSON.parse(Buffer.from(req.headers.get('authorization').slice(6), 'base64').toString('utf8'))
      verifyEvent(auth)
      assert.equal(auth.kind, 27235); assert.equal(auth.content, '')
      assert(Math.abs(auth.created_at - Math.floor(Date.now() / 1000)) <= 5)
      const body = await req.text()
      const tags = Object.fromEntries(auth.tags)
      assert.equal(tags.u, url)
      assert.equal(tags.method, 'POST')
      assert.equal(tags.payload, createHash('sha256').update(body).digest('hex'))
      assert.equal(typeof tags.nonce, 'string'); assert(!nonces.has(tags.nonce)); nonces.add(tags.nonce)
      data = JSON.parse(body)
      if (route === '/events') {
        verifyEvent(data); assert.equal(data.pubkey, auth.pubkey)
        assert([1, 9000, 9030, 9031, 9032].includes(data.kind))
        assert(Math.abs(data.created_at - Math.floor(Date.now() / 1000)) <= 5)
      } else {
        assert.equal(route, '/query')
        assert.deepEqual(data, [{ kinds: [1], authors: [auth.pubkey], limit: 1 }])
      }
    } catch {
      errors.push('invalid signed request')
      return new Response('{"error":"auth_failed"}', { status: 401 })
    }
    requests.push({ route, data, auth })
    const reply = respond({ route, data, auth })
    return new Response(reply.raw ?? JSON.stringify(reply.data), { status: reply.status ?? 200 })
  }
  return { baseUrl, fetchImpl, requests, errors }
}

test('all four commands have exact tags, kinds and signatures; NIP-98 binds each POST', async t => {
  const f = fixture(t), signer = publicKeyOf(f.key)
  const b = await bridge(t, ({ data, auth }) => auth.pubkey === signer
    ? { data: { accepted: true, event_id: data.id } } : denial)
  const c = client(f, b)
  for (const [options, kind, tags] of [
    [{ command: 'add' }, 9030, [['p', target], ['role', 'member']]],
    [{ command: 'add', role: 'admin' }, 9030, [['p', target], ['role', 'admin']]],
    [{ command: 'remove' }, 9031, [['p', target]]],
    [{ command: 'role', role: 'member' }, 9032, [['p', target], ['role', 'member']]],
    [{ command: 'role', role: 'admin' }, 9032, [['p', target], ['role', 'admin']]],
    [{ command: 'put-user', role: 'member', channel: CHANNEL }, 9000, [['h', CHANNEL], ['p', target], ['role', 'member']]],
    [{ command: 'put-user', role: 'bot', channel: CHANNEL }, 9000, [['h', CHANNEL], ['p', target], ['role', 'bot']]],
  ]) {
    const result = await c.send({ ...options, pubkey: target.toUpperCase() })
    const event = b.requests.at(-1).data
    assert.equal(event.kind, kind); assert.deepEqual(event.tags, tags)
    assert.equal(event.content, ''); assert.equal(event.pubkey, signer); assert.equal(verifyEvent(event), true)
    assert.deepEqual(result, { accepted: true, event_id: event.id, kind })
  }
  assert.deepEqual(b.errors, [])
  assert(!JSON.stringify(b.requests).includes(f.key), 'requests never contain the secret')
})

test('role, target, channel and unknown-field validation rejects unsafe or misleading commands', t => {
  const c = client(fixture(t)), valid = { command: 'add', pubkey: target }
  for (const options of [null, [], { ...valid, command: 'constructor' }, { ...valid, command: 'no' },
    ...['', 'npub1bad', 'z'.repeat(64), null].map(pubkey => ({ ...valid, pubkey })),
    ...['owner', 'bot', '', null].map(role => ({ ...valid, role })),
    { ...valid, channel: CHANNEL }, { ...valid, content: 'unwanted' }, { ...valid, secretKey: 'unwanted' },
    { ...valid, command: 'remove', role: 'member' }, { ...valid, command: 'role' },
    { ...valid, command: 'role', role: 'owner' },
    ...['admin', 'owner', undefined].map(role => ({ ...valid, command: 'put-user', role, channel: CHANNEL })),
    ...['general', CHANNEL.toUpperCase(), undefined].map(channel => ({ ...valid, command: 'put-user', role: 'bot', channel })),
  ]) throws(() => c.build(options), REFUSE.INPUT)
})

test('isolated file loader rejects unsafe key files and parents without disclosing values', t => {
  const f = fixture(t)
  assert.equal(verifyEvent(client(f).build({ command: 'add', pubkey: target })), true)
  throws(() => createMemberClient({ keyFile: f.keyFile }), REFUSE.KEY)
  for (const mode of [0o640, 0o604]) {
    fs.chmodSync(f.keyFile, mode); throws(() => client(f), REFUSE.KEY)
  }
  fs.chmodSync(f.keyFile, 0o600)
  for (const dir of [f.dir, f.home]) {
    for (const mode of [0o720, 0o702]) { fs.chmodSync(dir, mode); throws(() => client(f), REFUSE.KEY) }
    fs.chmodSync(dir, 0o700)
  }
  const link = path.join(f.dir, 'alias'); fs.symlinkSync(f.keyFile, link)
  throws(() => client({ ...f, keyFile: link }), REFUSE.KEY)
  const dirLink = path.join(f.home, 'alias'); fs.symlinkSync(f.dir, dirLink)
  throws(() => client({ ...f, keyFile: path.join(dirLink, 'key') }), REFUSE.KEY)
  for (const keyFile of ['relative', f.dir, f.keyFile.replace('/keys/', '/keys/../keys/')]) throws(() => client({ ...f, keyFile }), REFUSE.KEY)
  for (const options of [{ home: f.home + '-elsewhere' }, { deniedRoots: [f.home] }, { extraDenied: [f.home] }, { uid: process.getuid() + 1 }]) {
    throws(() => client(f, { keyOptions: { ...f.keyOptions, ...options } }), REFUSE.KEY)
  }
  const originalStat = fs.lstatSync
  const mock = t.mock.method(fs, 'lstatSync', name => {
    const st = originalStat(name); if (name === f.dir) st.uid = process.getuid() + 999
    return st
  })
  throws(() => client(f), REFUSE.KEY); mock.mock.restore()
  for (const contents of ['not-hex', '0'.repeat(64), 'f'.repeat(64), 'a'.repeat(201)]) {
    fs.writeFileSync(f.keyFile, contents); throws(() => client(f), REFUSE.KEY)
  }
})

test('production isolation denies the checkout even with a HOME inside it and a different cwd', t => {
  const f = fixture(t), oldHome = process.env.HOME, oldCwd = process.cwd()
  try {
    process.env.HOME = f.home; process.chdir(f.dir)
    const keyFile = path.join(f.home, 'outside-cwd'); fs.writeFileSync(keyFile, f.key, { mode: 0o600 })
    throws(() => createMemberClient({ keyFile }), REFUSE.KEY)
  } finally { process.chdir(oldCwd); if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome }
})

test('key read uses one no-follow descriptor and stays stable after path replacement', async t => {
  const f = fixture(t), originalOpen = fs.openSync, signer = publicKeyOf(f.key)
  let opens = 0
  const mock = t.mock.method(fs, 'openSync', (name, flags, ...rest) => {
    const fd = originalOpen(name, flags, ...rest)
    // On Linux the loader opens the key through its held parent descriptor (/proc/self/fd/<n>/<name>).
    const viaDescriptor = typeof name === 'string' && name.startsWith('/proc/self/fd/') && name.endsWith('/' + path.basename(f.keyFile))
    if ((name === f.keyFile || viaDescriptor) && typeof flags === 'number' && !(flags & fs.constants.O_DIRECTORY)) {
      opens++; assert(flags & fs.constants.O_NOFOLLOW); assert(flags & fs.constants.O_NONBLOCK)
      fs.renameSync(f.keyFile, f.keyFile + '.old')
      fs.writeFileSync(f.keyFile, randomSecretKey(), { mode: 0o600 })
    }
    return fd
  })
  const b = await bridge(t, ({ data }) => ({ data: { accepted: true, event_id: data.id } }))
  const c = client(f, b); mock.mock.restore()
  assert.equal(opens, 1)
  await c.send({ command: 'add', pubkey: target })
  assert.equal(b.requests[0].auth.pubkey, signer); assert.equal(b.requests[0].data.pubkey, signer)
})

test('local bridge only; redirects are refused and requests carry a bounded abort signal', async t => {
  const f = fixture(t)
  for (const baseUrl of ['https://localhost:3000', 'http://example.com:3000', 'http://localhost:3000/x',
    'http://localhost:3000?x', 'http://user@localhost:3000', 'http://localhost:65536', 'http://localhost:00']) {
    throws(() => client(f, { baseUrl }), REFUSE.URL)
    await rejects(() => verifyClosed({ baseUrl }), REFUSE.URL)
  }
  let sentOptions
  await rejects(() => client(f, { fetchImpl: async (_url, options) => {
    sentOptions = options
    throw new Error(f.key)
  } }).send({ command: 'add', pubkey: target }), REFUSE.TRANSPORT)
  assert.equal(sentOptions.redirect, 'error'); assert(sentOptions.signal instanceof AbortSignal)
})

test('admin success requires accepted=true and the exact event id; relay failures are not echoed', async t => {
  const f = fixture(t)
  for (const [reply, code] of [
    [{ status: 403, data: { error: f.key } }, REFUSE.REJECTED],
    [{ data: { accepted: false } }, REFUSE.REJECTED],
    [{ data: { accepted: true, event_id: 'wrong' } }, REFUSE.UNKNOWN],
    [{ data: { accepted: 'true' } }, REFUSE.UNKNOWN], [{ data: {} }, REFUSE.UNKNOWN],
    [{ raw: f.key }, REFUSE.RESPONSE], [{ raw: ' '.repeat(16_385) + '{}' }, REFUSE.RESPONSE],
  ]) {
    const b = await bridge(t, () => reply)
    await rejects(() => client(f, b).send({ command: 'role', pubkey: target, role: 'admin' }), code)
  }
})

test('verify-closed probes BOTH routes with a valid disposable identity and CLI exits zero only for closure', async t => {
  const b = await bridge(t)
  for (let i = 0; i < 2; i++) assert.equal((await verifyClosed(b)).closed, true)
  assert.deepEqual(b.errors, [])
  assert.deepEqual(b.requests.map(r => r.route), ['/query', '/events', '/query', '/events', '/query', '/events', '/query', '/events'])
  assert.equal(b.requests[0].auth, null); assert.equal(b.requests[1].auth, null)
  assert.equal(b.requests[2].auth.pubkey, b.requests[3].auth.pubkey)
  assert.notEqual(b.requests[2].auth.pubkey, b.requests[6].auth.pubkey)
  const event = b.requests[3].data
  assert.equal(event.kind, 1); assert.deepEqual(event.tags, []); assert.equal(verifyEvent(event), true)
  const mock = t.mock.method(globalThis, 'fetch', b.fetchImpl), out = [], err = []
  assert.equal(await runCli(['verify-closed'], { out: x => out.push(x), err: x => err.push(x) }), 0)
  assert.equal(JSON.parse(out[0]).closed, true); assert.deepEqual(err, []); mock.mock.restore()
})

test('acceptance of either query or event fails closure and the CLI exits nonzero', async t => {
  for (const acceptedRoute of ['/query', '/events']) {
    const b = await bridge(t, ({ route, data }) => route === acceptedRoute
      ? { data: route === '/query' ? [] : { accepted: true, event_id: data.id } } : denial)
    const result = await verifyClosed(b)
    assert.equal(result.closed, false)
    assert.equal(result.state, 'OPEN'); assert.equal(b.requests.length, 4)
    const out = [], err = []
    const mock = t.mock.method(globalThis, 'fetch', b.fetchImpl)
    assert.equal(await runCli(['verify-closed', '--relay', b.baseUrl], { out: x => out.push(x), err: x => err.push(x) }), 1)
    assert.equal(JSON.parse(out[0]).closed, false); assert.deepEqual(err, [REFUSE.CLOSED])
    mock.mock.restore()
  }
})

test('unauthenticated refusal does not hide non-member acceptance; authentication refusal alone cannot prove membership closure', async t => {
  const authentication = { status: 401, data: { error: 'authentication_required' } }
  for (const [nonMemberReply, state] of [[denial, 'CLOSED'], [authentication, 'UNKNOWN'], [{ data: [] }, 'OPEN']]) {
    const b = await bridge(t, ({ auth, route, data }) => !auth ? authentication : route === '/query' ? nonMemberReply : denial)
    const result = await verifyClosed(b)
    assert.equal(result.state, state)
    assert.equal(result.closed, state === 'CLOSED')
    assert.equal(b.requests.filter(row => row.auth).length, 2)
    assert.equal(b.requests.filter(row => !row.auth).length, 2)
  }
  const malformedAck = await bridge(t, () => ({ data: { accepted: true, event_id: 'wrong' } }))
  assert.equal((await verifyClosed(malformedAck)).state, 'UNKNOWN')
  const refusedAck = await bridge(t, ({ route, data }) => ({ status: 403, data: route === '/query' ? [] : { accepted: true, event_id: data.id } }))
  assert.equal((await verifyClosed(refusedAck)).state, 'UNKNOWN')
  const timeouts = [], timeout = AbortSignal.timeout
  t.mock.method(AbortSignal, 'timeout', ms => { timeouts.push(ms); return timeout(ms) })
  assert.equal((await verifyClosed(await bridge(t))).state, 'CLOSED')
  assert.deepEqual(timeouts, [5_000, 5_000, 5_000, 5_000])
})

test('unrelated refusals, malformed/large responses and outages never prove closure; the other route is still probed', async t => {
  for (const reply of [
    ...[200, 400, 401, 404, 429, 500].map(status => ({ status, data: denial.data })),
    { status: 403, data: { error: 'auth_failed' } }, { status: 403, data: { error: 'channel_membership_required' } },
    { status: 403, data: { message: 'relay_membership_required' } },
    { status: 403, data: { ...denial.data, accepted: true } },
    { status: 200, data: { accepted: false } }, { status: 403, raw: 'not json' },
    { status: 403, raw: ' '.repeat(16_385) + JSON.stringify(denial.data) },
  ]) {
    const b = await bridge(t, () => reply)
    const result = await verifyClosed(b)
    assert.equal(result.closed, false); assert.equal(result.state, 'UNKNOWN'); assert.equal(b.requests.length, 4)
  }
  let calls = 0
  const result = await verifyClosed({ fetchImpl: async () => { calls++; throw new Error('offline') } })
  assert.equal(calls, 4); assert.equal(result.closed, false); assert.equal(result.state, 'UNKNOWN')
  assert.equal(result.query.code, REFUSE.TRANSPORT); assert.equal(result.events.code, REFUSE.TRANSPORT)
})

test('CLI refuses inline secrets, isolation overrides and invalid options without reflecting arguments', async t => {
  const f = fixture(t)
  for (const [args, code] of [[[], REFUSE.INPUT], [['no'], REFUSE.INPUT], [['add', '--secret-key', f.key], REFUSE.INPUT],
    [['add', '--key', f.key], REFUSE.INPUT], [['add', '--key-file', f.key], REFUSE.KEY],
    [['add', '--home', f.home], REFUSE.INPUT], [['add', '--key-file'], REFUSE.INPUT],
    [['add', '--pubkey', target, '--pubkey', target], REFUSE.INPUT], [['verify-closed', '--key-file', f.keyFile], REFUSE.INPUT],
    [['verify-closed', '--role', 'member'], REFUSE.INPUT], [['verify-closed', '--relay', 'http://example.com:3000'], REFUSE.URL]]) {
    const out = [], err = []
    assert.equal(await runCli(args, { out: x => out.push(x), err: x => err.push(x) }), 1)
    assert.equal(out.length, 0); assert.equal(err.length, 1)
    assert(err[0] === code); assert(!err[0].includes(f.key))
  }
  const out = []; assert.equal(await runCli(['--help'], { out: x => out.push(x) }), 0)
  assert.match(out[0], /put-user/u); assert.match(out[0], /verify-closed/u)
})

test('LIVE verify-closed against localhost:3000', { skip: process.env.AUKORA_BUZZ_LIVE !== '1' }, async () => {
  const result = await verifyClosed({ baseUrl: 'http://localhost:3000' })
  assert.equal(result.closed, true, JSON.stringify(result))
})

test('mutation checks', { skip: process.env.AUKORA_BUZZ_MUTATIONS !== '1' }, () => {
  const source = fs.readFileSync(SOURCE, 'utf8')
  const mutations = [
    ['add kind', 'add: 9030', 'add: 9031'], ['remove kind', 'remove: 9031', 'remove: 9030'],
    ['role kind', 'role: 9032', 'role: 9030'], ['channel kind', "'put-user': 9000", "'put-user': 9030"],
    ['target tag', "['p', pubkey.toLowerCase()]", "['e', pubkey.toLowerCase()]"],
    ['channel tag', "[['h', channel]]", "[['x', channel]]"],
    ['role tag', "[['role', role]]", "[['x', role]]"],
    ['role escalation', "!['member', 'admin'].includes(role)", "!['member', 'admin', 'owner'].includes(role)"],
    ['bot escalation', "!['member', 'bot'].includes(role)", "!['member', 'bot', 'admin'].includes(role)"],
    ['conditional remove', "if (role !== undefined) throw fail(REFUSE.INPUT)", ''],
    ['channel validation', '!UUID.test(channel)', 'false'],
    ['target validation', '!isHex32(pubkey)', 'false'],
    ['unknown fields', "Object.keys(options).some(k => !['command', 'pubkey', 'role', 'channel'].includes(k))", 'false'],
    ['isolated loader', 'loadKey(keyFile, keyOptions)', "(awaitNotNeeded => awaitNotNeeded)(globalThis.process.getBuiltinModule('fs').readFileSync(keyFile, 'utf8').trim())"],
    ['checkout exclusion', 'extraDenied: [path.resolve(CHECKOUT), process.cwd()]', 'extraDenied: []'],
    ['usable key', '; publicKeyOf(key) } catch', ' } catch'],
    ['loopback', 'throw fail(REFUSE.URL)\n  try', '{}\n  try'],
    ['redirect', "redirect: 'error'", "redirect: 'follow'"],
    ['abort bound', 'signal: AbortSignal.timeout(timeoutMs)', 'signal: undefined'],
    ['NIP98', 'Authorization: httpAuthHeader({ url, body, secretKeyHex: key, now })', "Authorization: 'Nostr broken'"],
    ['response bound', 'bytes > MAX_RESPONSE_BYTES', 'false'],
    ['status rejection', 'status < 200 || status >= 300', 'false'],
    ['explicit rejection', 'data?.accepted === false', 'false'],
    ['acknowledgement', 'data?.accepted !== true || data.event_id !== event.id', 'false'],
    ['exact event id', 'data.event_id !== event.id', 'false'],
    ['denial status', "status === 403 && data?.error === 'relay_membership_required'", "data?.error === 'relay_membership_required'"],
    ['denial reason', "status === 403 && data?.error === 'relay_membership_required'", 'status === 403'],
    ['contradictory acceptance', ' && data.accepted !== true', ''],
    ['throwaway key', 'const key = randomSecretKey(), pubkey', "const key = '01'.repeat(32), pubkey"],
    ['both routes', "Object.values(result).every(row => ['MEMBERSHIP_REFUSED', 'AUTHENTICATION_REFUSED'].includes(row.state))", "Object.values(result).some(row => ['MEMBERSHIP_REFUSED', 'AUTHENTICATION_REFUSED'].includes(row.state))"],
    ['non-member probes', "['query', '/query', query, key], ['events', '/events', event, key],", ''],
    ['unauthenticated probes', "['unauthenticated_query', '/query', query, undefined], ['unauthenticated_events', '/events', event, undefined],", ''],
    ['unknown is closed', ": 'UNKNOWN'\n  return { closed, state", ": 'CLOSED'\n  return { closed, state"],
    ['authentication only unsigned', 'probeKey === undefined && status === 401', 'status === 401'],
    ['exact probe acknowledgement', 'data.event_id === event.id', 'true'],
    ['probe success status', 'status >= 200 && status < 300', 'true'],
    ['probe deadline', 'timeoutMs: 5_000', 'timeoutMs: 10_000'],
    ['CLI closure exit', 'if (!result.closed) throw fail(REFUSE.CLOSED)', ''],
    ['CLI option restriction', "!['--key-file', '--pubkey', '--role', '--channel', '--relay'].includes(flag)", 'false'],
    ['CLI error redaction', 'err(Object.values(REFUSE).includes(error?.code) ? error.code : REFUSE.INPUT)', 'err(args.join(" "))'],
  ]
  try {
    for (const [name, before, after] of mutations) {
      assert(source.includes(before), `mutation anchor: ${name}`)
      fs.writeFileSync(SOURCE, source.replace(before, after))
      const env = { ...process.env, AUKORA_BUZZ_MUTATIONS: '0', AUKORA_BUZZ_LIVE: '0' }
      delete env.NODE_TEST_CONTEXT
      const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', TEST], {
        cwd: path.resolve(HERE, '../..'), encoding: 'utf8', timeout: 30_000,
        env,
      })
      assert(result.status === 1 && /# fail [1-9]/u.test(result.stdout), `mutation survived or did not run: ${name}`)
      console.log(`mutation ${name}: KILLED`)
    }
    console.log(`mutations ${mutations.length}/${mutations.length} KILLED`)
  } finally { fs.writeFileSync(SOURCE, source) }
})
