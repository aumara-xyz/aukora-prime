import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { admit, resume, runCli, REFUSE } from './admit.mjs'
import { createMemberClient, verifyClosed, REFUSE as MEMBER } from './member.mjs'
import { createInvite, redeemInvite, TTL_SECONDS, REFUSE as INVITES } from '../../packages/invites/index.mjs'
import { publicKeyOf, randomSecretKey, verifyEvent, signEvent } from '../../plugins/aukora-nostr/lib/event.mjs'
import { httpAuthHeader } from '../../plugins/aukora-buzz-door/lib/index.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SOURCE = path.join(HERE, 'admit.mjs')
const TEST = fileURLToPath(import.meta.url)
const accepted = { accepted: true, event_id: 'ab'.repeat(32), kind: 9030 }
const auraAck = { ok: true, seq: 1, hash: 'cd'.repeat(32) }
const rejects = (fn, code) => assert.rejects(fn, error => error.code === code)

function fixture(t) {
  const home = fs.mkdtempSync(path.join(HERE, '.admit-test-'))
  fs.chmodSync(home, 0o700)
  const keys = path.join(home, 'keys'); fs.mkdirSync(keys, { mode: 0o700 })
  const people = Array.from({ length: 7 }, (_, i) => {
    const key = randomSecretKey(), keyFile = path.join(keys, String(i))
    fs.writeFileSync(keyFile, key + '\n', { mode: 0o600 })
    return { key, keyFile, pubkey: publicKeyOf(key) }
  })
  const storeDir = path.join(home, 'store')
  const now = Math.floor(Date.now() / 1000)
  const keyOptions = { home, deniedRoots: [] }
  t.after(() => fs.rmSync(home, { recursive: true, force: true }))
  return { home, storeDir, people, now, keyOptions,
    options: { keyFile: people[0].keyFile, storeDir }, deps: { keyOptions, now: () => now } }
}

function pair(f, inviter = 0, member = 1, now = f.now) {
  const invite = createInvite({ root: f.people[0].pubkey, secretKey: f.people[inviter].key, now })
  return { invite, redemption: redeemInvite({ invite, secretKey: f.people[member].key, now }) }
}

function lines(f) {
  const file = path.join(f.storeDir, 'admissions.jsonl')
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : []
}

function counts(f) {
  const file = path.join(f.storeDir, 'admissions.sqlite')
  if (!fs.existsSync(file)) return { consumed: 0, admissions: 0 }
  const db = new DatabaseSync(file, { readOnly: true })
  try {
    return Object.fromEntries(['consumed', 'admissions'].map(table => [table,
      db.prepare(`SELECT count(*) AS n FROM ${table}`).get().n]))
  } finally { db.close() }
}

// The stand-in validates NIP-98 and signed owner commands before changing its closed roster.
function bridge(owner) {
  const members = new Set([owner]), requests = [], errors = [], nonces = new Set()
  const baseUrl = 'http://localhost:3000'
  const fetchImpl = async (url, options) => {
    try {
      const request = new Request(url, options), route = new URL(url).pathname
      assert.equal(request.method, 'POST')
      assert.equal(request.headers.get('content-type'), 'application/json')
      assert.match(request.headers.get('authorization') ?? '', /^Nostr /u)
      const auth = JSON.parse(Buffer.from(request.headers.get('authorization').slice(6), 'base64').toString('utf8'))
      assert.equal(verifyEvent(auth), true); assert.equal(auth.kind, 27235)
      assert.equal(auth.content, '')
      assert(Math.abs(auth.created_at - Math.floor(Date.now() / 1000)) <= 5)
      const body = await request.text(), tags = Object.fromEntries(auth.tags), data = JSON.parse(body)
      assert.equal(tags.u, url); assert.equal(tags.method, 'POST')
      assert.equal(tags.payload, createHash('sha256').update(body).digest('hex'))
      assert.equal(typeof tags.nonce, 'string'); assert(!nonces.has(tags.nonce)); nonces.add(tags.nonce)
      if (route === '/events') {
        assert.equal(verifyEvent(data), true); assert.equal(data.pubkey, auth.pubkey)
        assert(Math.abs(data.created_at - Math.floor(Date.now() / 1000)) <= 5)
      } else assert.equal(route, '/query')
      requests.push({ route, data, auth })
      if (!members.has(auth.pubkey)) return Response.json({ error: 'relay_membership_required' }, { status: 403 })
      if (route === '/query') return Response.json([])
      if (data.kind === 9030) {
        if (auth.pubkey !== owner) return Response.json({ error: 'owner_required' }, { status: 403 })
        assert.deepEqual(data.tags.map(tag => tag[0]), ['p', 'role'])
        assert.equal(data.tags[1][1], 'member'); assert.equal(data.content, '')
        members.add(data.tags[0][1])
      }
      return Response.json({ accepted: true, event_id: data.id })
    } catch {
      errors.push('invalid signed request')
      return Response.json({ error: 'auth_failed' }, { status: 401 })
    }
  }
  return { members, requests, errors, baseUrl, fetchImpl }
}

test('root admits A, A vouches for B, and the owner alone sends signed member additions to a closed bridge', async t => {
  const f = fixture(t), b = bridge(f.people[0].pubkey), deps = { ...f.deps, fetchImpl: b.fetchImpl }
  assert.equal((await verifyClosed(b)).closed, true)
  const first = pair(f), a = await admit({ ...f.options, ...first }, deps)
  assert.equal(a.member, f.people[1].pubkey); assert.deepEqual(a.record.chain, [first])
  const second = pair(f, 1, 2), result = await admit({ ...f.options, ...second, chain: a.record.chain }, deps)
  assert.equal(result.member, f.people[2].pubkey)
  assert.deepEqual(result.record.chain, [first, second])
  assert.deepEqual([...b.members], f.people.slice(0, 3).map(person => person.pubkey))
  const adds = b.requests.filter(request => request.data.kind === 9030)
  assert.equal(adds.length, 2)
  assert(adds.every(request => request.auth.pubkey === f.people[0].pubkey))
  assert.deepEqual(lines(f), [first, second].map(({ invite, redemption }) => ({
    root: f.people[0].pubkey, inviteId: invite.id, redemptionId: redemption.id,
    inviter: invite.pubkey, member: redemption.pubkey,
  })))
  assert.deepEqual(counts(f), { consumed: 2, admissions: 2 })
  assert.deepEqual(b.errors, [])
  const output = JSON.stringify({ requests: b.requests, records: lines(f) })
  for (const person of f.people) assert(!output.includes(person.key))
})

test('three redeemed invites exhaust A; fourth, expired, replayed, unadmitted and forged redemptions never reach the relay', async t => {
  const f = fixture(t), b = bridge(f.people[0].pubkey), deps = { ...f.deps, fetchImpl: b.fetchImpl }
  const notes = []
  f.options.gateSocket = '/fixture-gate.sock'
  deps.gate = async (...args) => { notes.push(args); return auraAck }
  const first = pair(f), a = await admit({ ...f.options, ...first }, deps), chain = a.record.chain
  for (const member of [2, 3, 4]) await admit({ ...f.options, ...pair(f, 1, member), chain }, deps)
  const prior = b.requests.length
  const notesBefore = notes.length
  await rejects(() => admit({ ...f.options, ...pair(f, 1, 5), chain }, deps), INVITES.ALLOTMENT)
  await rejects(() => admit({ ...f.options, ...first }, deps), INVITES.REPLAY)
  await rejects(() => admit({ ...f.options, ...pair(f, 0, 5, f.now - TTL_SECONDS) }, deps), INVITES.EXPIRED)
  await rejects(() => admit({ ...f.options, ...pair(f, 5, 6) }, deps), INVITES.CHAIN)
  const forged = pair(f, 0, 5)
  forged.redemption = { ...signEvent({ kind: forged.redemption.kind, pubkey: f.people[6].pubkey,
    created_at: f.now, tags: forged.redemption.tags, content: forged.redemption.content }, f.people[6].key),
  pubkey: f.people[5].pubkey }
  await rejects(() => admit({ ...f.options, ...forged }, deps), INVITES.SIGNATURE)
  assert.equal(b.requests.length, prior); assert.deepEqual(counts(f), { consumed: 4, admissions: 4 })
  assert.equal(notes.length, notesBefore)
  assert.deepEqual(b.errors, [])
})

test('issue and redeem CLI join three key files without putting any secret in output', async t => {
  const f = fixture(t), b = bridge(f.people[0].pubkey), output = [], errors = []
  const notes = []
  const invoke = async args => {
    const out = [], err = []
    assert.equal(await runCli(args, { ...f.deps, fetchImpl: b.fetchImpl,
      gate: async (...args) => { notes.push(args); return auraAck }, out: x => out.push(x), err: x => err.push(x) }), 0)
    output.push(...out); errors.push(...err)
    return JSON.parse(out[0])
  }
  let chain = []
  for (const [inviter, member] of [[0, 1], [1, 2]]) {
    const invite = await invoke(['issue', '--key-file', f.people[inviter].keyFile, '--root', f.people[0].pubkey])
    assert.equal(verifyEvent(invite), true); assert.equal(invite.pubkey, f.people[inviter].pubkey)
    const inviteFile = path.join(f.home, `invite-${member}.json`)
    fs.writeFileSync(inviteFile, JSON.stringify(invite))
    const redemption = await invoke(['redeem', '--key-file', f.people[member].keyFile, '--invite', inviteFile])
    assert.equal(verifyEvent(redemption), true); assert.equal(redemption.pubkey, f.people[member].pubkey)
    const redemptionFile = path.join(f.home, `redemption-${member}.json`), chainFile = path.join(f.home, 'chain.json')
    fs.writeFileSync(redemptionFile, JSON.stringify(redemption)); fs.writeFileSync(chainFile, JSON.stringify(chain))
    const result = await invoke(['admit', '--key-file', f.people[0].keyFile, '--store', f.storeDir,
      '--invite', inviteFile, '--redemption', redemptionFile, '--chain', chainFile, '--gate-socket', '/fixture-gate.sock'])
    assert.equal(result.member, f.people[member].pubkey); chain = result.record.chain
  }
  assert.deepEqual(await invoke(['resume', '--key-file', f.people[0].keyFile, '--store', f.storeDir, '--gate-socket', '/fixture-gate.sock']), [])
  assert.equal(notes.length, 2); assert(notes.every(call => call[0] === '/fixture-gate.sock' && call[1] === 'aura_note'))
  assert.deepEqual(errors, []); assert.deepEqual(b.errors, [])
  for (const person of f.people) assert(!output.join('\n').includes(person.key))
})

test('Aura admission digest is acknowledged after durable append and before relay delivery; absent socket is unchanged', async t => {
  const f = fixture(t), claim = pair(f), calls = []
  let recorded = false
  const result = await admit({ ...f.options, ...claim, gateSocket: '/fixture-gate.sock' }, { ...f.deps,
    gate: async (...args) => {
      calls.push(args)
      assert.equal(lines(f).length, 1); assert.deepEqual(counts(f), { consumed: 1, admissions: 1 })
      await Promise.resolve(); recorded = true
      return auraAck
    }, sender: async () => { assert.equal(recorded, true); return accepted },
  })
  assert.deepEqual(calls, [['/fixture-gate.sock', 'aura_note', { kind: 'admission',
    digest_sha256: createHash('sha256').update(JSON.stringify(result.record)).digest('hex') }]])
  const local = fixture(t)
  await admit({ ...local.options, ...pair(local) }, { ...local.deps,
    gate: async () => assert.fail('unconfigured gate called'), sender: async () => accepted })
})

test('Aura admission failures and malformed acknowledgements never send; durable admission can resume', async t => {
  const bad = [undefined, {}, { ...auraAck, ok: false }, { ...auraAck, ok: 1 },
    ...[0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '1'].map(seq => ({ ...auraAck, seq })),
    ...[undefined, 'aa', 'AB'.repeat(32), 'z'.repeat(64), auraAck.hash + '\n', 1].map(hash => ({ ...auraAck, hash })),
    new Error('private gate error')]
  for (const ack of bad) {
    const f = fixture(t), claim = pair(f), calls = [], options = { ...f.options, gateSocket: '/fixture-gate.sock' }
    let sends = 0
    const deps = { ...f.deps, sender: async () => { sends++; return accepted }, gate: async (...args) => {
      calls.push(args); if (ack instanceof Error) throw ack; return ack
    } }
    await rejects(() => admit({ ...options, ...claim }, deps), REFUSE.AURA)
    assert.equal(sends, 0); assert.equal(lines(f).length, 1)
    assert.deepEqual(counts(f), { consumed: 1, admissions: 1 })
    assert.equal((await resume(options, { ...deps, gate: async (...args) => { calls.push(args); return auraAck } })).length, 1)
    assert.equal(sends, 1); assert.equal(calls.length, 2); assert.deepEqual(calls[0], calls[1])
  }
})

test('Aura admission configured socket must be an absolute path before any spend', async t => {
  const f = fixture(t), claim = pair(f)
  for (const gateSocket of [null, '', 'relative', 1, {}, '/bad\0socket']) {
    await rejects(() => admit({ ...f.options, ...claim, gateSocket }, { ...f.deps,
      gate: async () => assert.fail('invalid socket reached gate'), sender: async () => assert.fail('invalid socket reached relay') }), REFUSE.AURA)
  }
  assert.deepEqual(counts(f), { consumed: 0, admissions: 0 })
})

test('each abrupt process exit resumes durable intent in spend, log, send order', async t => {
  for (const stage of ['record', 'spent', 'append', 'sent', 'done']) {
    await t.test(stage, async t => {
      const f = fixture(t), claim = pair(f), config = path.join(f.home, 'crash.json'), effects = path.join(f.home, 'effects.jsonl')
      fs.writeFileSync(config, JSON.stringify({ ...f.options, ...claim, keyOptions: f.keyOptions, now: f.now, stage, effects }))
      const script = `import fs from 'node:fs'; import { admit } from ${JSON.stringify(new URL('./admit.mjs', import.meta.url).href)};
const cfg=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));
await admit({keyFile:cfg.keyFile,storeDir:cfg.storeDir,invite:cfg.invite,redemption:cfg.redemption},{keyOptions:cfg.keyOptions,now:()=>cfg.now,
sender:async command=>{fs.appendFileSync(cfg.effects,JSON.stringify(command)+'\\n');return ${JSON.stringify(accepted)}},
onStage:stage=>{if(stage===cfg.stage)process.exit(77)}});`
      const child = spawnSync(process.execPath, ['--input-type=module', '--eval', script, config], { encoding: 'utf8', timeout: 10_000 })
      assert.equal(child.status, 77, child.stderr)
      const before = counts(f)
      assert.deepEqual(before, { consumed: stage === 'record' ? 0 : 1, admissions: stage === 'record' ? 0 : 1 })
      assert.equal(lines(f).length, ['append', 'sent', 'done'].includes(stage) ? 1 : 0)
      const sender = async command => {
        assert.deepEqual(counts(f), { consumed: 1, admissions: 1 })
        assert.equal(lines(f).length, 1)
        assert.deepEqual(command, { command: 'add', pubkey: claim.redemption.pubkey, role: 'member' })
        fs.appendFileSync(effects, JSON.stringify(command) + '\n')
        return accepted
      }
      const deps = { ...f.deps, sender }
      if (stage === 'record') await admit({ ...f.options, ...claim }, deps)
      else assert.equal((await resume(f.options, deps)).length, stage === 'done' ? 0 : 1)
      assert.equal(lines(f).length, 1); assert.deepEqual(counts(f), { consumed: 1, admissions: 1 })
      const sent = fs.readFileSync(effects, 'utf8').trim().split('\n').map(JSON.parse)
      assert.equal(sent.length, stage === 'sent' ? 2 : 1)
      assert.equal(new Set(sent.map(command => command.pubkey)).size, 1)
      assert.deepEqual(await resume(f.options, deps), [])
      await rejects(() => admit({ ...f.options, ...claim }, deps), INVITES.REPLAY)
    })
  }
})

test('pending exact retry survives expiry; a conflicting redemption and new admission cannot bypass the pending operation', async t => {
  const f = fixture(t), claim = pair(f), other = pair(f, 0, 2)
  await assert.rejects(() => admit({ ...f.options, ...claim }, { ...f.deps,
    sender: async () => { throw new Error('offline') } }))
  assert.deepEqual(counts(f), { consumed: 1, admissions: 1 }); assert.equal(lines(f).length, 1)
  await rejects(() => admit({ ...f.options, ...other }, { ...f.deps, sender: async () => accepted }), REFUSE.PENDING)
  const changed = redeemInvite({ invite: claim.invite, secretKey: f.people[2].key, now: f.now })
  await rejects(() => admit({ ...f.options, invite: claim.invite, redemption: changed }, { ...f.deps, sender: async () => accepted }), INVITES.REPLAY)
  let sends = 0
  const result = await admit({ ...f.options, ...claim }, { ...f.deps, now: () => f.now + TTL_SECONDS + 1,
    sender: async () => { sends++; return accepted } })
  assert.equal(result.member, f.people[1].pubkey); assert.equal(sends, 1); assert.equal(lines(f).length, 1)
})

test('an in-flight sender holds the store lock and incomplete acknowledgements remain resumable', async t => {
  const f = fixture(t), claim = pair(f)
  let release, entered
  const waiting = new Promise(resolve => { entered = resolve })
  const first = admit({ ...f.options, ...claim }, { ...f.deps, sender: () => new Promise(resolve => {
    release = resolve; entered()
  }) })
  await waiting
  await rejects(() => resume(f.options, { ...f.deps, sender: async () => accepted }), REFUSE.BUSY)
  release(accepted); await first
  for (const ack of [undefined, {}, { ...accepted, accepted: false }, { ...accepted, event_id: 'wrong' }, { ...accepted, kind: 9031 }]) {
    const next = fixture(t), entry = pair(next)
    await rejects(() => admit({ ...next.options, ...entry }, { ...next.deps, sender: async () => ack }), REFUSE.UNKNOWN)
    assert.equal((await resume(next.options, { ...next.deps, sender: async () => accepted })).length, 1)
    assert.equal(lines(next).length, 1)
  }
})

test('private store paths and isolated owner key files are required before sending', async t => {
  const f = fixture(t), claim = pair(f)
  let sends = 0
  const deps = { ...f.deps, sender: async () => { sends++; return accepted } }
  await rejects(() => admit({ ...f.options, ...claim }, { sender: deps.sender }), MEMBER.KEY)
  for (const keyFile of [f.home, 'relative', f.people[0].keyFile + '/missing']) {
    await rejects(() => admit({ ...f.options, ...claim, keyFile }, deps), MEMBER.KEY)
  }
  fs.mkdirSync(f.storeDir, { mode: 0o700 })
  for (const mode of [0o750, 0o707]) {
    fs.chmodSync(f.storeDir, mode)
    await rejects(() => admit({ ...f.options, ...claim }, deps), REFUSE.STORE)
  }
  fs.chmodSync(f.storeDir, 0o700)
  const link = path.join(f.home, 'store-link'); fs.symlinkSync(f.storeDir, link)
  const parentLink = path.join(f.home, 'parent-link'); fs.symlinkSync(f.home, parentLink)
  for (const storeDir of ['relative', link, path.join(parentLink, 'store'), f.people[0].keyFile]) {
    await rejects(() => admit({ ...f.options, ...claim, storeDir }, deps), REFUSE.STORE)
  }
  const original = fs.lstatSync
  const mock = t.mock.method(fs, 'lstatSync', (file, ...args) => {
    const st = original(file, ...args); if (file === f.storeDir) st.uid = process.getuid() + 999; return st
  })
  await rejects(() => admit({ ...f.options, ...claim }, deps), REFUSE.STORE)
  mock.mock.restore()
  assert.equal(sends, 0)
})

test('store files reject symlinks, hardlinks, broad modes and changed ownership', async t => {
  for (const name of ['lock.sqlite', 'admissions.sqlite', 'admissions.jsonl', 'admissions.sqlite-journal']) {
    for (const damage of ['symlink', 'hardlink', 'mode']) {
      const f = fixture(t), claim = pair(f), target = path.join(f.home, 'target')
      fs.mkdirSync(f.storeDir, { mode: 0o700 }); fs.writeFileSync(target, '', { mode: 0o600 })
      const file = path.join(f.storeDir, name)
      if (damage === 'symlink') fs.symlinkSync(target, file)
      else if (damage === 'hardlink') fs.linkSync(target, file)
      else fs.writeFileSync(file, '', { mode: 0o644 })
      let sends = 0
      await rejects(() => admit({ ...f.options, ...claim }, { ...f.deps, sender: async () => { sends++; return accepted } }), REFUSE.STORE)
      assert.equal(sends, 0); assert.equal(fs.readFileSync(target, 'utf8'), '')
    }
  }
  const f = fixture(t), claim = pair(f), original = fs.fstatSync
  const keyInodes = new Set(f.people.map(person => fs.statSync(person.keyFile).ino))
  const mock = t.mock.method(fs, 'fstatSync', fd => {
    const st = original(fd); if (!keyInodes.has(st.ino)) st.uid = process.getuid() + 999; return st
  })
  await rejects(() => admit({ ...f.options, ...claim }, { ...f.deps, sender: async () => accepted }), REFUSE.STORE)
  mock.mock.restore()
})

test('recovery appends a torn matching prefix, refuses altered history and binds owner plus relay', async t => {
  const f = fixture(t), claim = pair(f)
  await assert.rejects(() => admit({ ...f.options, ...claim }, { ...f.deps, onStage: stage => {
    if (stage === 'append') throw new Error('crash')
  }, sender: async () => accepted }))
  const file = path.join(f.storeDir, 'admissions.jsonl'), full = fs.readFileSync(file)
  fs.truncateSync(file, 37)
  const prefix = fs.readFileSync(file)
  assert.equal((await resume(f.options, { ...f.deps, sender: async () => {
    assert(fs.readFileSync(file).subarray(0, prefix.length).equals(prefix)); return accepted
  } })).length, 1)
  assert(fs.readFileSync(file).equals(full))
  for (const content of [Buffer.concat([full, Buffer.from('unexpected\n')]), Buffer.from('x' + full.subarray(1).toString())]) {
    fs.writeFileSync(file, content)
    await rejects(() => resume(f.options, { ...f.deps, sender: async () => accepted }), REFUSE.STORE)
    assert(fs.readFileSync(file).equals(content))
  }
  fs.writeFileSync(file, full)
  await rejects(() => resume({ ...f.options, keyFile: f.people[1].keyFile }, { ...f.deps, sender: async () => accepted }), REFUSE.STORE)
  await rejects(() => resume({ ...f.options, baseUrl: 'http://localhost:3001' }, { ...f.deps, sender: async () => accepted }), REFUSE.STORE)
  const empty = fixture(t)
  assert.deepEqual(await resume(empty.options, empty.deps), [])
  await rejects(() => resume({ ...empty.options, keyFile: empty.people[1].keyFile }, empty.deps), REFUSE.STORE)
  const second = fixture(t), entry = pair(f, 1, 2)
  await rejects(() => admit({ ...second.options, keyFile: f.people[0].keyFile, ...entry, chain: [claim] }, {
    ...f.deps, sender: async () => accepted,
  }), INVITES.UNADMITTED)
})

test('missing delivery and divergent durable records refuse before relay delivery', async t => {
  for (const damage of ['missing', 'record', 'entry', 'admission', 'signature']) {
    const f = fixture(t), claim = pair(f)
    await assert.rejects(() => admit({ ...f.options, ...claim }, { ...f.deps, onStage: stage => {
      if (stage === 'spent') throw new Error('crash')
    }, sender: async () => accepted }))
    const db = new DatabaseSync(path.join(f.storeDir, 'admissions.sqlite'))
    try {
      if (damage === 'missing') db.exec('DELETE FROM delivery')
      if (damage === 'record') db.prepare('UPDATE delivery SET record = ?').run(JSON.stringify({ chain: [pair(f, 0, 2)] }))
      if (damage === 'signature') {
        const record = JSON.parse(db.prepare('SELECT record FROM delivery').get().record)
        record.chain[0].redemption.sig = '00'.repeat(64)
        db.prepare('UPDATE delivery SET record = ?').run(JSON.stringify(record))
      }
      if (damage === 'entry') {
        const entry = JSON.parse(db.prepare('SELECT entry FROM delivery').get().entry)
        entry.inviter = f.people[2].pubkey
        db.prepare('UPDATE delivery SET entry = ?').run(JSON.stringify(entry))
      }
      if (damage === 'admission') db.prepare('UPDATE admissions SET inviter = ?').run(f.people[2].pubkey)
    } finally { db.close() }
    let sends = 0
    await rejects(() => resume(f.options, { ...f.deps, sender: async () => { sends++; return accepted } }), REFUSE.STORE)
    assert.equal(sends, 0); assert.equal(lines(f).length, 0)
  }
})

test('short writes finish and fsync the admission line before send; append failure stays pending', async t => {
  const f = fixture(t), claim = pair(f), open = fs.openSync, write = fs.writeSync, sync = fs.fsyncSync
  const descriptors = new Map(), synced = new Set()
  let writes = 0, sends = 0
  const openMock = t.mock.method(fs, 'openSync', (file, ...args) => {
    const fd = open(file, ...args); descriptors.set(fd, file); return fd
  })
  const writeMock = t.mock.method(fs, 'writeSync', (fd, buffer, offset, length, ...args) => {
    if (descriptors.get(fd)?.endsWith('admissions.jsonl')) { writes++; length = Math.min(length, 7) }
    return write(fd, buffer, offset, length, ...args)
  })
  const syncMock = t.mock.method(fs, 'fsyncSync', fd => { synced.add(descriptors.get(fd)); return sync(fd) })
  await admit({ ...f.options, ...claim }, { ...f.deps, sender: async () => {
    sends++; assert(writes > 1); assert(synced.has(path.join(f.storeDir, 'admissions.jsonl')))
    assert(synced.has(f.storeDir)); assert(synced.has(f.home)); assert.equal(lines(f).length, 1); return accepted
  } })
  assert.equal(sends, 1)
  syncMock.mock.restore(); writeMock.mock.restore(); openMock.mock.restore()
  const second = fixture(t), entry = pair(second)
  const failure = t.mock.method(fs, 'writeSync', () => { throw new Error('disk full') })
  await assert.rejects(() => admit({ ...second.options, ...entry }, { ...second.deps, sender: async () => { sends++; return accepted } }))
  assert.equal(sends, 1); assert.deepEqual(counts(second), { consumed: 1, admissions: 1 })
  failure.mock.restore()
  assert.equal((await resume(second.options, { ...second.deps, sender: async () => accepted })).length, 1)
  const third = fixture(t), last = pair(third)
  let attempts = 0
  const stalled = t.mock.method(fs, 'writeSync', () => {
    if (++attempts === 1) return 0
    throw new Error('no progress')
  })
  await rejects(() => admit({ ...third.options, ...last }, { ...third.deps, sender: async () => { sends++; return accepted } }), REFUSE.STORE)
  assert.equal(sends, 1); stalled.mock.restore()
  assert.equal((await resume(third.options, { ...third.deps, sender: async () => accepted })).length, 1)
})

test('CLI permits no secret arguments, isolation overrides or reflected exception messages', async t => {
  const f = fixture(t), claim = pair(f), inviteFile = path.join(f.home, 'invite.json'), redemptionFile = path.join(f.home, 'redemption.json')
  fs.writeFileSync(inviteFile, JSON.stringify(claim.invite)); fs.writeFileSync(redemptionFile, JSON.stringify(claim.redemption))
  const valid = ['admit', '--key-file', f.people[0].keyFile, '--store', f.storeDir, '--invite', inviteFile, '--redemption', redemptionFile]
  const isolationErrors = []
  assert.equal(await runCli(['issue', '--key-file', f.people[0].keyFile, '--root', f.people[0].pubkey], {
    out: () => assert.fail('isolated checkout key accepted'), err: value => isolationErrors.push(value),
  }), 1)
  assert.deepEqual(isolationErrors, [REFUSE.KEY])
  for (const args of [[], ['unknown'], ['issue', '--secret-key', f.people[0].key], ['issue', '--home', f.home],
    ['issue', '--key-file', f.people[0].keyFile, '--root', f.people[0].pubkey, '--secret-key', f.people[0].key],
    ['issue', '--key-file', f.people[0].keyFile, '--root', f.people[0].pubkey, '--home', f.home],
    ['issue', '--key-file', f.people[0].keyFile, '--root', f.people[0].pubkey, '--root', f.people[0].pubkey],
    ['issue', '--root'], ['issue', '--root', f.people[0].pubkey, '--root', f.people[0].pubkey],
    ['resume', '--invite', inviteFile], ['issue', '--key-file', f.people[0].key], valid]) {
    const out = [], err = []
    assert.equal(await runCli(args, { ...f.deps, sender: async () => { throw new Error(f.people[0].key) },
      out: x => out.push(x), err: x => err.push(x) }), 1)
    assert.deepEqual(out, []); assert.equal(err.length, 1)
    assert.match(err[0], /^(buzz-admit|buzz-member|invites):[a-z-]+$/u)
    for (const person of f.people) assert(!err[0].includes(person.key))
  }
  const out = []; assert.equal(await runCli(['--help'], { out: x => out.push(x) }), 0)
  for (const word of ['issue', 'redeem', 'admit', 'resume']) assert(out[0].includes(word))
})

test('admission protections fail under mutation', { skip: process.env.AUKORA_ADMIT_MUTATIONS !== '1' }, () => {
  const source = fs.readFileSync(SOURCE, 'utf8')
  const mutations = [
    ['Aura required recording', 'if (ctx.gateSocket !== undefined) {', 'if (false) {'],
    ['Aura digest-only payload', "digest_sha256: createHash('sha256').update(json(record)).digest('hex')", "digest_sha256: createHash('sha256').update(json(record)).digest('hex'), record"],
    ['Aura exact record digest', ".update(json(record)).digest('hex')", ".update(json(entry)).digest('hex')"],
    ['Aura positive acknowledgement', 'ack?.ok !== true || ', ''],
    ['Aura integer sequence', '!Number.isSafeInteger(ack.seq) || ', ''],
    ['Aura positive sequence', 'ack.seq < 1', 'false'],
    ['Aura hash acknowledgement', "typeof ack.hash !== 'string' || !/^[0-9a-f]{64}$/.test(ack.hash)", 'false'],
    ['Aura refusal surface', '} catch { throw fail(REFUSE.AURA) }', '} catch {}'],
    ['Aura configured socket', "if (options.gateSocket !== undefined && (typeof options.gateSocket !== 'string'\n    || !path.isAbsolute(options.gateSocket) || options.gateSocket.includes('\\0'))) throw fail(REFUSE.AURA)", ''],
    ['Aura CLI configuration', "gateSocket: opts['--gate-socket']", 'gateSocket: undefined'],
    ['verifier authorization', 'verifyAdmission({ root, invite, redemption, chain, state, now: (deps.now ?? seconds)() })',
      'state.transaction(tx => { tx.consume(invite.id); tx.record(compact(root, invite, redemption)) })'],
    ['atomic membership record', 'tx.record(entry)\n        store.db', 'void entry\n        store.db'],
    ['durable outbox', '.run(invite.id, json(entry), json(record))',
      ".run(invite.id, json(entry), json(record)); store.db.prepare('DELETE FROM delivery WHERE inviteId = ?').run(invite.id)"],
    ['log before relay', "appendAdmissions(store)\n  onStage('append')", "onStage('append')"],
    ['completion after acknowledgement', "const ack = await sender({ command: 'add', pubkey: entry.member, role: 'member' })",
      "store.db.prepare('UPDATE delivery SET done = 1 WHERE inviteId = ?').run(entry.inviteId); const ack = await sender({ command: 'add', pubkey: entry.member, role: 'member' })"],
    ['accepted acknowledgement', 'ack?.accepted !== true || ', ''],
    ['member-kind acknowledgement', 'ack.kind !== 9030 || ', ''],
    ['event-id acknowledgement', '!isHex32(ack.event_id)', 'false'],
    ['durable completion', 'UPDATE delivery SET done = 1 WHERE inviteId = ?', 'UPDATE delivery SET done = done WHERE inviteId = ?'],
    ['expired pending resume', 'if (existing) {', 'if (false) {'],
    ['completed replay', 'existing.done || ', ''],
    ['exact pending pair', 'if (existing.done || existing.entry !== json(compact(root, invite, redemption))) throw fail(INVITE_REFUSE.REPLAY)\n      if (existing.record !== json(record)) throw fail(INVITE_REFUSE.CHAIN)',
      'if (existing.done) throw fail(INVITE_REFUSE.REPLAY)'],
    ['pending serialization', "if (store.db.prepare('SELECT 1 FROM delivery WHERE done = 0').get()) throw fail(REFUSE.PENDING)", ''],
    ['owner binding', 'network.root !== root || ', ''],
    ['relay binding', 'network.relay !== baseUrl', 'false'],
    ['append-only prefix', 'actual.length > expected.length || !actual.equals(expected.subarray(0, actual.length))', 'false'],
    ['single-link store', 'st.nlink !== 1 || ', ''],
    ['private store files', '(st.mode & 0o077) || st.uid !== process.getuid()', 'st.uid !== process.getuid()'],
    ['store file owner', ' || st.uid !== process.getuid())', ')'],
    ['no-follow store files', ' | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK', ' | fs.constants.O_NONBLOCK'],
    ['private store directory', '!st.isDirectory() || (st.mode & 0o077)', '!st.isDirectory()'],
    ['store directory owner', '!st.isDirectory() || (st.mode & 0o077) || st.uid !== process.getuid()', '!st.isDirectory() || (st.mode & 0o077)'],
    ['store parent symlink', '|| fs.realpathSync(directory) !== directory', ''],
    ['SQLite companion protection', 'if (fs.lstatSync(file, { throwIfNoEntry: false })) privateFile(file)', ''],
    ['concurrent sender lock', 'PRAGMA busy_timeout = 0; BEGIN IMMEDIATE', 'PRAGMA busy_timeout = 0'],
    ['admission fsync', '    fs.fsyncSync(fd)\n  } finally', '  } finally'],
    ['directory fsync', '    syncDirectory(directory)\n    return', '    return'],
    ['new-store parent fsync', '    syncDirectory(path.dirname(directory))\n', ''],
    ['short-write completion', 'offset += written', 'offset = expected.length'],
    ['no-progress write refusal', 'if (!written) throw fail(REFUSE.STORE)', ''],
    ['missing outbox refusal', "if (db.prepare('SELECT 1 FROM admissions LEFT JOIN delivery USING (inviteId) WHERE delivery.inviteId IS NULL LIMIT 1').get()) throw fail(REFUSE.STORE)", ''],
    ['durable admission match', ' || json(stored) !== row.entry', ''],
    ['outbox pair match', 'row.entry !== json(compact(root, last.invite, last.redemption)) || json(stored) !== row.entry', 'false'],
    ['pending record signature', 'verifyRecord({ root, record }).member !== entry.member', 'false'],
    ['validate before recovery append', "for (const row of db.prepare('SELECT * FROM delivery ORDER BY sequence').all()) checkedRecord({ state }, root, row)", ''],
    ['isolated issuance key', "loadKey(opts['--key-file'], deps.keyOptions ?? defaultKeyOptions())", "fs.readFileSync(opts['--key-file'], 'utf8').trim()"],
    ['CLI option restriction', '!allowed[command].includes(flag)', 'false'],
    ['CLI duplicate option', 'Object.hasOwn(opts, flag)', 'false'],
    ['CLI error redaction', 'err(codes.includes(error?.code) ? error.code : REFUSE.INPUT)', 'err(error.message)'],
  ]
  const targets = [
    [['Aura required recording', 'Aura digest-only payload', 'Aura exact record digest'], 'Aura admission digest'],
    [['Aura positive acknowledgement', 'Aura integer sequence', 'Aura positive sequence', 'Aura hash acknowledgement', 'Aura refusal surface'], 'Aura admission failures'],
    [['Aura configured socket'], 'Aura admission configured socket'],
    [['Aura CLI configuration'], 'issue and redeem CLI'],
    [['verifier authorization', 'completed replay'], 'three redeemed invites'],
    [['atomic membership record', 'durable outbox', 'log before relay'], 'root admits A'],
    [['completion after acknowledgement', 'accepted acknowledgement', 'member-kind acknowledgement', 'event-id acknowledgement', 'concurrent sender lock'], 'in-flight sender'],
    [['durable completion'], 'each abrupt process exit'],
    [['expired pending resume', 'exact pending pair', 'pending serialization'], 'pending exact retry'],
    [['owner binding', 'relay binding', 'append-only prefix'], 'recovery appends'],
    [['single-link store', 'private store files', 'store file owner', 'no-follow store files', 'SQLite companion protection'], 'store files reject'],
    [['private store directory', 'store directory owner', 'store parent symlink'], 'private store paths'],
    [['admission fsync', 'directory fsync', 'new-store parent fsync', 'short-write completion', 'no-progress write refusal'], 'short writes finish'],
    [['missing outbox refusal', 'durable admission match', 'outbox pair match', 'pending record signature', 'validate before recovery append'], 'missing delivery'],
    [['isolated issuance key', 'CLI option restriction', 'CLI duplicate option', 'CLI error redaction'], 'CLI permits'],
  ]
  const env = { ...process.env, AUKORA_ADMIT_MUTATIONS: '0', AUKORA_BUZZ_LIVE: '0' }
  delete env.NODE_TEST_CONTEXT
  const run = pattern => spawnSync(process.execPath, ['--test', '--test-reporter=tap', ...(pattern ? ['--test-name-pattern', pattern] : []), TEST], {
    cwd: path.resolve(HERE, '../..'), encoding: 'utf8', timeout: 30_000, env,
  })
  const baseline = run()
  assert(baseline.status === 0 && /# fail 0/u.test(baseline.stdout), 'unmodified mutation baseline must pass')
  const interrupted = () => { fs.writeFileSync(SOURCE, source); process.exit(130) }
  process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted)
  try {
    for (const [name, before, after] of mutations) {
      assert(source.includes(before), `mutation anchor: ${name}`)
      const pattern = targets.find(([names]) => names.includes(name))?.[1]
      assert(pattern, `mutation test target: ${name}`)
      fs.writeFileSync(SOURCE, source.replace(before, after))
      const result = run(pattern)
      assert(result.status === 1 && /# fail [1-9]/u.test(result.stdout), `mutation survived or did not run: ${name}`)
      console.log(`mutation ${name}: KILLED`)
    }
    console.log(`mutations ${mutations.length}/${mutations.length} KILLED`)
  } finally {
    fs.writeFileSync(SOURCE, source)
    process.removeListener('SIGINT', interrupted); process.removeListener('SIGTERM', interrupted)
  }
})

test('LIVE root to A to B, quota and refusals against the closed loopback relay', {
  skip: process.env.AUKORA_BUZZ_LIVE !== '1',
}, async t => {
  const keyFile = process.env.AUKORA_BUZZ_OWNER_KEY_FILE
  assert(keyFile, 'AUKORA_BUZZ_OWNER_KEY_FILE is required for the gated LIVE check')
  const owner = createMemberClient({ keyFile }), f = fixture(t), baseUrl = 'http://localhost:3000'
  assert.equal((await verifyClosed({ baseUrl })).closed, true)
  const issue = async (inviter = 0, now = f.now) => {
    const out = [], err = []
    assert.equal(await runCli(['issue', '--key-file', inviter ? f.people[inviter].keyFile : keyFile, '--root', owner.pubkey], {
      out: line => out.push(line), err: line => err.push(line), now: () => now,
      ...(inviter ? { keyOptions: f.keyOptions } : {}),
    }), 0)
    assert.deepEqual(err, []); return JSON.parse(out[0])
  }
  const entry = async (inviter, member, now = f.now) => {
    const invite = await issue(inviter, now)
    return { invite, redemption: redeemInvite({ invite, secretKey: f.people[member].key, now }) }
  }
  const query = async member => {
    const url = baseUrl + '/query', body = JSON.stringify([{ kinds: [1], authors: [f.people[member].pubkey], limit: 1 }])
    return fetch(url, { method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(10_000),
      headers: { 'Content-Type': 'application/json', Authorization: httpAuthHeader({ url, body, secretKeyHex: f.people[member].key }) } })
  }
  const options = { keyFile, baseUrl, storeDir: f.storeDir }, attempted = new Set()
  const fetchImpl = async (url, options) => {
    if (new URL(url).pathname === '/events') {
      const event = JSON.parse(options.body)
      if (event.kind === 9030) attempted.add(event.tags.find(tag => tag[0] === 'p')[1])
    }
    return fetch(url, options)
  }
  const admitLive = options => admit(options, { fetchImpl })
  try {
    assert.equal((await query(1)).status, 403)
    const first = await entry(0, 1)
    const a = await admitLive({ ...options, ...first })
    assert.equal(a.member, f.people[1].pubkey)
    const chain = a.record.chain
    for (const member of [2, 3, 4]) {
      await admitLive({ ...options, ...await entry(1, member), chain })
      assert.equal((await query(member)).status, 200)
    }
    assert.equal((await query(1)).status, 200)
    await owner.send({ command: 'add', pubkey: f.people[1].pubkey })
    assert.equal((await query(1)).status, 200, 'repeated idempotent add leaves the membership usable')
    await rejects(async () => admitLive({ ...options, ...await entry(1, 5), chain }), INVITES.ALLOTMENT)
    await rejects(() => admitLive({ ...options, ...first }), INVITES.REPLAY)
    await rejects(async () => admitLive({ ...options, ...await entry(0, 5, f.now - TTL_SECONDS) }), INVITES.EXPIRED)
    const forged = await entry(0, 5)
    forged.redemption = { ...signEvent({ kind: forged.redemption.kind, pubkey: f.people[6].pubkey,
      created_at: f.now, tags: forged.redemption.tags, content: forged.redemption.content }, f.people[6].key),
    pubkey: f.people[5].pubkey }
    await rejects(() => admitLive({ ...options, ...forged }), INVITES.SIGNATURE)
    assert.equal((await query(5)).status, 403)
    const member = createMemberClient({ keyFile: f.people[1].keyFile }, { keyOptions: f.keyOptions, fetchImpl })
    await rejects(() => member.send({ command: 'add', pubkey: f.people[5].pubkey }), MEMBER.REJECTED)
  } finally {
    const cleanup = await Promise.allSettled([...attempted].map(pubkey => owner.send({ command: 'remove', pubkey })))
    assert(cleanup.every(result => result.status === 'fulfilled'), 'LIVE throwaway membership cleanup failed')
  }
})
