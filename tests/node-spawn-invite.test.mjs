// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise signed offers, remote accounting refusals and isolated exact-key admission.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createInvite, redeemInvite, verifyAdmission, createAdmissionRecord, createMemoryStore, REFUSE as INVITE_REFUSE } from '../packages/invites/index.mjs'
import { publicKeyOf, randomSecretKey, signEvent } from '../plugins/aukora-nostr/lib/event.mjs'

const source = fileURLToPath(new URL('../ops/node-spawn/invite.mjs', import.meta.url))
const moduleUrl = process.env.NODE_SPAWN_INVITE_MODULE ?? pathToFileURL(source).href
const { REFUSE, checkedConfig, verifyOffer, createKey, readKey, readJson, writeRecord,
  preflight, redeem, verifyBinding, runCli } = await import(moduleUrl)
const NOW = 1800000000
const refusal = (callback, code) => assert.throws(callback, error => error.code === code)
const rejected = (callback, code) => assert.rejects(callback, error => error.code === code)
const reply = (data, status = 200) => new Response(JSON.stringify(data), { status })

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '.node-spawn-invite-'))
  const home = path.join(directory, 'home'), privateDir = path.join(home, 'private')
  fs.mkdirSync(home, { mode: 0o700 }); fs.mkdirSync(privateDir, { mode: 0o700 })
  const keyFile = path.join(privateDir, 'node-key'), recordFile = path.join(privateDir, 'record.json')
  const keyOptions = { home }
  const rootKey = randomSecretKey(), root = publicKeyOf(rootKey)
  const config = { version: 1, root, admission: 'https://admission.invalid', unrelated: 'allowed' }
  const invite = createInvite({ root, secretKey: rootKey, now: NOW })
  const offer = { invite, chain: [] }
  const state = createMemoryStore(), spent = new Set(), requests = [], records = new Map()
  const fetchImpl = async (url, options) => {
    requests.push({ route: new URL(url).pathname, options })
    assert.equal(options.redirect, 'error')
    assert.equal(options.method, 'POST')
    assert.ok(options.signal instanceof AbortSignal)
    const body = JSON.parse(options.body)
    try {
      if (new URL(url).pathname === '/preflight') {
        verifyOffer({ root, offer: { invite: body.invite, chain: body.chain }, now: NOW })
        state.transaction(tx => {
          for (const prior of body.chain) {
            const entry = tx.admission(root, prior.redemption.pubkey)
            if (!entry || entry.inviteId !== prior.invite.id || entry.redemptionId !== prior.redemption.id) throw { code: INVITE_REFUSE.UNADMITTED }
          }
          if (spent.has(body.invite.id)) throw { code: INVITE_REFUSE.REPLAY }
          if (tx.count(root, body.invite.pubkey) >= 3) throw { code: INVITE_REFUSE.ALLOTMENT }
        })
        return reply({ available: true, invite_id: body.invite.id })
      }
      assert.equal(new URL(url).pathname, '/redeem')
      if (records.has(body.redemption.id)) return reply({ admitted: true, record: records.get(body.redemption.id) })
      const result = verifyAdmission({ ...body, state, now: NOW })
      spent.add(body.invite.id)
      const record = createAdmissionRecord({ root, secretKey: rootKey, record: result.record, now: NOW })
      records.set(body.redemption.id, record)
      return reply({ admitted: true, record })
    } catch (error) { return reply({ code: error.code }, 409) }
  }
  t.after(() => { state.close(); fs.rmSync(directory, { recursive: true, force: true }) })
  return { directory, home, privateDir, keyFile, recordFile, keyOptions, rootKey, root, config,
    invite, offer, state, spent, requests, records, deps: { fetchImpl, keyOptions }, fetchImpl }
}

test('signed offers reject forged signatures, wrong roots, strangers and bad clocks before transport', async t => {
  const f = fixture(t), forged = structuredClone(f.offer)
  forged.invite.sig = '00'.repeat(64)
  let calls = 0
  const transport = { fetchImpl: async () => { calls++; return reply({ available: true, invite_id: f.invite.id }) } }
  await rejected(() => preflight({ config: f.config, offer: forged, now: NOW }, transport), INVITE_REFUSE.SIGNATURE)
  const stranger = { invite: createInvite({ root: f.root, secretKey: randomSecretKey(), now: NOW }), chain: [] }
  await rejected(() => preflight({ config: f.config, offer: stranger, now: NOW }, transport), INVITE_REFUSE.CHAIN)
  await rejected(() => preflight({ config: { ...f.config, root: publicKeyOf(randomSecretKey()) }, offer: f.offer, now: NOW }, transport), INVITE_REFUSE.NETWORK)
  await rejected(() => preflight({ config: f.config, offer: f.offer, now: NOW - 1 }, transport), INVITE_REFUSE.TIME)
  await rejected(() => preflight({ config: f.config, offer: f.offer, now: NOW + 48 * 60 * 60 }, transport), INVITE_REFUSE.EXPIRED)
  assert.equal(calls, 0)
  refusal(() => verifyOffer({ root: f.root, offer: { ...f.offer, extra: true }, now: NOW }), REFUSE.INPUT)
  refusal(() => verifyOffer({ root: f.root, offer: f.offer, now: 1.5 }), REFUSE.INPUT)
})

test('endpoint config requires a root and HTTPS or explicitly ported loopback', t => {
  const f = fixture(t)
  assert.equal(checkedConfig(f.config).admission, f.config.admission)
  for (const admission of ['http://admission.invalid', 'ftp://admission.invalid', 'http://localhost',
    'http://localhost:0', 'https://user:password@admission.invalid', 'https://admission.invalid/path',
    'https://admission.invalid?secret=ignored', 'https://admission.invalid#fragment']) {
    refusal(() => checkedConfig({ ...f.config, admission }), REFUSE.CONFIG)
  }
  for (const admission of ['http://localhost:12345', 'http://127.0.0.1:12345', 'http://[::1]:12345']) {
    assert.equal(checkedConfig({ ...f.config, admission }).admission, admission)
  }
  for (const config of [null, { ...f.config, version: 2 }, { ...f.config, root: 'bad' }]) refusal(() => checkedConfig(config), REFUSE.CONFIG)
})

test('preflight asks the configured authority without spending and requires the exact availability reply', async t => {
  const f = fixture(t)
  await preflight({ config: f.config, offer: f.offer, now: NOW }, f.deps)
  await preflight({ config: f.config, offer: f.offer, now: NOW }, f.deps)
  assert.equal(f.state.transaction(tx => tx.count(f.root, f.root)), 0)
  assert.equal(f.requests.length, 2)
  assert.equal(f.requests[0].route, '/preflight')
  for (const [data, status] of [[{ available: true, invite_id: f.invite.id }, 201],
    [{ available: false, invite_id: f.invite.id }, 200], [{ available: true, invite_id: '00'.repeat(32) }, 200],
    [{ available: true, invite_id: f.invite.id, extra: true }, 200]]) {
    await rejected(() => preflight({ config: f.config, offer: f.offer, now: NOW }, { fetchImpl: async () => reply(data, status) }), REFUSE.AVAILABLE)
  }
  await rejected(() => preflight({ config: f.config, offer: f.offer, now: NOW }, { fetchImpl: async () => { throw new Error('private address') } }), REFUSE.TRANSPORT)
  for (const response of [new Response('not json'), new Response(JSON.stringify({ available: true,
    invite_id: f.invite.id }) + ' '.repeat(262145))]) {
    await rejected(() => preflight({ config: f.config, offer: f.offer, now: NOW }, { fetchImpl: async () => response }), REFUSE.RESPONSE)
  }
})

test('authoritative replay, unadmitted ancestry and three-invite quota refuse', async t => {
  const f = fixture(t)
  createKey(f.keyFile, f.keyOptions)
  await preflight({ config: f.config, offer: f.offer, now: NOW }, f.deps)
  await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps)
  await rejected(() => preflight({ config: f.config, offer: f.offer, now: NOW }, f.deps), INVITE_REFUSE.REPLAY)
  const requests = f.requests.length
  await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps)
  assert.equal(f.requests.length, requests, 'completed local request never spends again')
  const unadmittedKey = randomSecretKey()
  const parentInvite = createInvite({ root: f.root, secretKey: f.rootKey, now: NOW })
  const parentRedemption = redeemInvite({ invite: parentInvite, secretKey: unadmittedKey, now: NOW })
  const child = { chain: [{ invite: parentInvite, redemption: parentRedemption }],
    invite: createInvite({ root: f.root, secretKey: unadmittedKey, now: NOW }) }
  await rejected(() => preflight({ config: f.config, offer: child, now: NOW }, f.deps), INVITE_REFUSE.UNADMITTED)
  for (let index = 0; index < 2; index++) {
    const invite = createInvite({ root: f.root, secretKey: f.rootKey, now: NOW })
    verifyAdmission({ root: f.root, invite, redemption: redeemInvite({ invite, secretKey: randomSecretKey(), now: NOW }), state: f.state, now: NOW })
  }
  const fourth = { invite: createInvite({ root: f.root, secretKey: f.rootKey, now: NOW }), chain: [] }
  await rejected(() => preflight({ config: f.config, offer: fourth, now: NOW }, f.deps), INVITE_REFUSE.ALLOTMENT)
})

test('remote redemption binds the signed record to exactly the generated key and offer', async t => {
  const f = fixture(t)
  createKey(f.keyFile, f.keyOptions)
  const record = await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps)
  assert.ok(record.chain.at(-1).redemption.pubkey === publicKeyOf(readKey(f.keyFile, f.keyOptions)), 'generated member binding')
  verifyBinding({ config: f.config, record, keyFile: f.keyFile }, { keyOptions: f.keyOptions })
  const other = path.join(f.privateDir, 'other-key')
  createKey(other, f.keyOptions)
  refusal(() => verifyBinding({ config: f.config, record, keyFile: other }, { keyOptions: f.keyOptions }), REFUSE.BINDING)
  for (const variant of ['member', 'status', 'admitted', 'shape']) {
    const g = fixture(t)
    createKey(g.keyFile, g.keyOptions)
    const different = createAdmissionRecord({ root: g.root, secretKey: g.rootKey, now: NOW,
      record: { chain: [{ invite: g.invite, redemption: redeemInvite({ invite: g.invite, secretKey: randomSecretKey(), now: NOW }) }] } })
    await rejected(() => redeem({ config: g.config, offer: g.offer, keyFile: g.keyFile, now: NOW }, {
      keyOptions: g.keyOptions, fetchImpl: async (url, options) => {
        const body = JSON.parse(options.body), record = createAdmissionRecord({ root: g.root, secretKey: g.rootKey, now: NOW,
          record: { chain: [...body.chain, { invite: body.invite, redemption: body.redemption }] } })
        const data = { admitted: variant !== 'admitted', record: variant === 'member' ? different : record }
        if (variant === 'shape') data.extra = true
        return reply(data, variant === 'status' ? 201 : 200)
      },
    }), REFUSE.SPENT)
  }
})

const reordered = value => Array.isArray(value) ? value.map(reordered)
  : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reordered(item)])) : value

test('a spent admission with reordered JSON keys is accepted exactly once', async t => {
  const f = fixture(t)
  createKey(f.keyFile, f.keyOptions)
  const fetchImpl = async (...args) => {
    const response = await f.fetchImpl(...args)
    return reply(reordered(await response.json()), response.status)
  }
  const record = await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, { ...f.deps, fetchImpl })
  assert.equal(f.spent.size, 1)
  verifyBinding({ config: f.config, record, keyFile: f.keyFile }, f.deps)
  assert.deepEqual(await redeem({ config: f.config, offer: reordered(f.offer), keyFile: f.keyFile, now: NOW + 172801 }, f.deps), record)
  assert.equal(f.requests.length, 1)
})

test('valid alternative ancestry, offer and redemption values each refuse after spending', async t => {
  for (const field of ['ancestry', 'offer', 'redemption']) {
    const f = fixture(t)
    createKey(f.keyFile, f.keyOptions)
    let offer = f.offer, signer = f.rootKey
    if (field === 'ancestry') {
      signer = randomSecretKey()
      offer = { chain: [{ invite: f.invite, redemption: redeemInvite({ invite: f.invite, secretKey: signer, now: NOW }) }],
        invite: createInvite({ root: f.root, secretKey: signer, now: NOW }) }
    }
    let calls = 0
    await rejected(() => redeem({ config: f.config, offer, keyFile: f.keyFile, now: NOW }, {
      keyOptions: f.keyOptions, fetchImpl: async (url, options) => {
        calls++
        const body = JSON.parse(options.body), record = { chain: [...body.chain, { invite: body.invite, redemption: body.redemption }] }
        const event = field === 'ancestry' ? record.chain[0].invite
          : field === 'offer' ? record.chain.at(-1).invite : record.chain.at(-1).redemption
        const oldId = event.id, oldSig = event.sig
        signEvent(event, field === 'ancestry' ? f.rootKey : field === 'offer' ? signer : readKey(f.keyFile, f.keyOptions))
        assert.equal(event.id, oldId, 'same bound event id')
        assert.notEqual(event.sig, oldSig, 'different valid bound signature value')
        return reply({ admitted: true, record: createAdmissionRecord({ root: f.root, secretKey: f.rootKey, record, now: NOW }) })
      },
    }), REFUSE.SPENT)
    assert.equal(calls, 1)
  }
})

test('the generated expected ancestry is checked before spending and pending input changes refuse before transport', async t => {
  const f = fixture(t)
  createKey(f.keyFile, f.keyOptions)
  const key = readKey(f.keyFile, f.keyOptions)
  const ancestry = { invite: f.invite, redemption: redeemInvite({ invite: f.invite, secretKey: key, now: NOW }) }
  const circular = { chain: [ancestry], invite: createInvite({ root: f.root, secretKey: key, now: NOW }) }
  await rejected(() => redeem({ config: f.config, offer: circular, keyFile: f.keyFile, now: NOW }, f.deps), INVITE_REFUSE.MEMBER)
  assert.equal(f.requests.length, 0)
  await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps)
  const otherOffer = { chain: [], invite: createInvite({ root: f.root, secretKey: f.rootKey, now: NOW }) }
  await rejected(() => redeem({ config: f.config, offer: otherOffer, keyFile: f.keyFile, now: NOW }, f.deps), REFUSE.BINDING)
  await rejected(() => redeem({ config: { ...f.config, admission: 'https://changed.invalid' }, offer: f.offer,
    keyFile: f.keyFile, now: NOW }, f.deps), REFUSE.BINDING)
  assert.equal(f.requests.length, 1)
})

test('spent then dropped reply resumes through the authority with the identical request and one admission', async t => {
  const previousMask = process.umask(0o002)
  t.after(() => process.umask(previousMask))
  const f = fixture(t), output = [], errors = []
  createKey(f.keyFile, f.keyOptions)
  const configFile = path.join(f.privateDir, 'config.json'), offerFile = path.join(f.privateDir, 'offer.json')
  fs.writeFileSync(configFile, JSON.stringify(f.config)); fs.writeFileSync(offerFile, JSON.stringify(f.offer))
  const args = ['redeem', '--config', configFile, '--offer', offerFile, '--key-file', f.keyFile, '--out', f.recordFile]
  const fetchImpl = async (url, options) => {
    await f.fetchImpl(url, options)
    throw new Error('reply lost after spending')
  }
  const deps = { ...f.deps, fetchImpl, now: () => NOW, out: line => output.push(line), err: line => errors.push(line) }
  assert.equal(await runCli(args, deps), 1)
  assert.match(errors.join('\n'), new RegExp(`UNKNOWN_WHETHER_SPENT invite_id=${f.invite.id} cause=${REFUSE.TRANSPORT}`))
  assert.match(errors.at(-1), /RETRY one identical persisted redemption with a 10-second transport deadline/u)
  assert.ok(errors.at(-1).includes(args.map(arg => "'" + arg + "'").join(' ')), 'exact original command is preserved')
  const pending = readJson(f.keyFile + '.invite-pending.json')
  const exact = f.records.get(pending.redemption.id)
  assert.equal(pending.redemption.id, exact.chain.at(-1).redemption.id)
  assert.equal(pending.request, f.requests[0].options.body)
  for (const file of [f.keyFile + '.invite-pending.json', f.recordFile]) {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600, 'state and reserved output stay private under umask 002')
  }
  assert.equal(await runCli(args, { ...deps, fetchImpl: f.fetchImpl, now: () => NOW + 172801 }), 0)
  assert.equal(f.requests.length, 2, 'resume replays to the authority')
  assert.equal(f.requests[1].options.body, f.requests[0].options.body, 'exact bytes replayed')
  assert.equal(f.state.transaction(tx => tx.count(f.root, f.root)), 1, 'authority spent exactly once')
  assert.deepEqual(readJson(f.recordFile), exact)
  assert.equal(fs.statSync(f.keyFile + '.invite-confirmed.json').mode & 0o777, 0o600)
  assert.equal(await runCli(args, { ...deps, now: () => NOW + 172801 }), 0, 'plain rerun uses the persisted reconciliation')
  assert.equal(f.requests.length, 2, 'confirmed state needs no additional dispatch')
  assert.deepEqual(output, ['ADMITTED', 'ADMITTED'])
})

test('pre-spend transport failure retries identical bytes; a forged local record cannot print ADMITTED authority_count=0', async t => {
  const f = fixture(t), output = [], errors = [], bodies = []
  createKey(f.keyFile, f.keyOptions)
  const configFile = path.join(f.privateDir, 'config.json'), offerFile = path.join(f.privateDir, 'offer.json')
  const forgedFile = path.join(f.privateDir, 'forged.json')
  fs.writeFileSync(configFile, JSON.stringify(f.config)); fs.writeFileSync(offerFile, JSON.stringify(f.offer))
  const args = ['redeem', '--config', configFile, '--offer', offerFile, '--key-file', f.keyFile, '--out', f.recordFile]
  const failed = async (_url, options) => { bodies.push(options.body); throw new Error('connection refused before spending') }
  const deps = { ...f.deps, fetchImpl: failed, now: () => NOW, out: line => output.push(line), err: line => errors.push(line) }
  assert.equal(await runCli(args, deps), 1)
  const pending = readJson(f.keyFile + '.invite-pending.json')
  const forged = { chain: [...f.offer.chain, { invite: f.invite, redemption: pending.redemption }] }
  fs.writeFileSync(forgedFile, JSON.stringify(forged))
  assert.equal(await runCli([...args, '--resume-record', forgedFile], deps), 1)
  assert.equal(output.length, 0, 'no ADMITTED without an authority signature')
  assert.equal(f.state.transaction(tx => tx.count(f.root, f.root)), 0, 'authority_count=0')
  assert.equal(bodies.length, 1, 'forged local record refuses before transport')
  fs.writeFileSync(offerFile, JSON.stringify(reordered(f.offer)))
  const succeeds = async (url, options) => { bodies.push(options.body); return f.fetchImpl(url, options) }
  assert.equal(await runCli(args, { ...deps, fetchImpl: succeeds, now: () => NOW + 1 }), 0)
  assert.equal(bodies.length, 2, 'transport_attempts=2')
  assert.equal(bodies[1], bodies[0], 'retry keeps persisted request bytes and redemption signature')
  assert.deepEqual(output, ['ADMITTED'])
  assert.equal(f.state.transaction(tx => tx.count(f.root, f.root)), 1)
})

test('each transport gets a bounded deadline and one attempt per run', async t => {
  const f = fixture(t), deadlines = []
  createKey(f.keyFile, f.keyOptions)
  const original = AbortSignal.timeout
  AbortSignal.timeout = milliseconds => { deadlines.push(milliseconds); return new AbortController().signal }
  let attempts = 0
  try {
    await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, {
      ...f.deps, fetchImpl: async () => { attempts++; throw new Error('timeout fixture') },
    }), REFUSE.SPENT)
  } finally { AbortSignal.timeout = original }
  assert.deepEqual(deadlines, [10000])
  assert.equal(attempts, 1)
})

test('unsigned service records and locally forged confirmation state never establish admission', async t => {
  for (const where of ['response', 'confirmed', 'output']) {
    const f = fixture(t)
    createKey(f.keyFile, f.keyOptions)
    let unsigned
    await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, {
      ...f.deps, fetchImpl: async (_url, options) => {
        const body = JSON.parse(options.body)
        unsigned = { chain: [...body.chain, { invite: body.invite, redemption: body.redemption }] }
        return reply({ admitted: true, record: unsigned })
      },
    }), REFUSE.SPENT)
    if (where === 'confirmed') writeRecord(f.keyFile + '.invite-confirmed.json', unsigned, f.keyOptions)
    if (where === 'output') writeRecord(f.recordFile, unsigned, f.keyOptions)
    if (where !== 'response') await rejected(() => redeem({ config: f.config, offer: f.offer,
      keyFile: f.keyFile, recordFile: where === 'output' ? f.recordFile : undefined, now: NOW }, {
      ...f.deps, fetchImpl: async () => { throw new Error('authority unavailable') },
    }), REFUSE.SPENT)
    refusal(() => verifyBinding({ config: f.config, record: unsigned, keyFile: f.keyFile }, f.deps), INVITE_REFUSE.CHAIN)
    assert.equal(f.state.transaction(tx => tx.count(f.root, f.root)), 0)
  }
})

test('legacy pending and unsigned local caches resume only by replaying the persisted signed request', async t => {
  const f = fixture(t), bodies = []
  createKey(f.keyFile, f.keyOptions)
  const failed = async (_url, options) => { bodies.push(options.body); throw new Error('no reply') }
  await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, {
    ...f.deps, fetchImpl: failed,
  }), REFUSE.SPENT)
  const pendingFile = f.keyFile + '.invite-pending.json', pending = readJson(pendingFile)
  delete pending.request
  fs.writeFileSync(pendingFile, JSON.stringify(pending))
  const bare = { chain: [...pending.offer.chain, { invite: pending.offer.invite, redemption: pending.redemption }] }
  writeRecord(f.keyFile + '.invite-response.json', { status: 200, data: { admitted: true, record: bare } }, f.keyOptions)
  writeRecord(f.keyFile + '.invite-confirmed.json', bare, f.keyOptions)
  writeRecord(f.recordFile, bare, f.keyOptions)
  await rejected(() => redeem({ config: f.config, offer: reordered(f.offer), keyFile: f.keyFile,
    recordFile: f.recordFile, now: NOW + 1 }, { ...f.deps, fetchImpl: failed }), REFUSE.SPENT)
  assert.equal(f.state.transaction(tx => tx.count(f.root, f.root)), 0)
  assert.equal(bodies[1], bodies[0], 'legacy reconstruction preserves the original signed POST bytes')
  const record = await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, recordFile: f.recordFile,
    now: NOW + 1 }, f.deps)
  assert.ok(record.confirmation)
  assert.deepEqual(readJson(f.recordFile), record)
  assert.equal(f.state.transaction(tx => tx.count(f.root, f.root)), 1)
})

test('only definitive authority refusals leave the pending state; ambiguous refusals stay replayable', async t => {
  for (const code of [INVITE_REFUSE.EXPIRED, INVITE_REFUSE.ALLOTMENT, INVITE_REFUSE.MEMBER, INVITE_REFUSE.UNADMITTED,
    INVITE_REFUSE.REPLAY, INVITE_REFUSE.CHAIN, INVITE_REFUSE.STATE]) {
    const f = fixture(t), bodies = []
    createKey(f.keyFile, f.keyOptions)
    const fetchImpl = async (_url, options) => { bodies.push(options.body); return reply({ code }, 409) }
    const exact = [INVITE_REFUSE.EXPIRED, INVITE_REFUSE.ALLOTMENT, INVITE_REFUSE.MEMBER, INVITE_REFUSE.UNADMITTED].includes(code)
    await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, { ...f.deps, fetchImpl }), exact ? code : REFUSE.SPENT)
    if (exact) {
      await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps), code)
      assert.equal(bodies.length, 1, 'definitive no-spend outcome does not retry or generate a new request')
      assert.equal(f.requests.length, 0)
    } else {
      const fetchImpl = async (url, options) => { bodies.push(options.body); return f.fetchImpl(url, options) }
      await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW + 1 }, { ...f.deps, fetchImpl })
      assert.equal(bodies.length, 2)
      assert.equal(bodies[1], bodies[0], 'ambiguous refusal retains exact request')
    }
  }
})

test('unwritable or occupied output and non-durable pending state refuse before spending', async t => {
  for (const variant of ['existing', 'unsafe', 'sync', 'occupied-response', 'occupied-confirmation', 'occupied-refusal']) {
    const f = fixture(t)
    createKey(f.keyFile, f.keyOptions)
    if (variant === 'existing') fs.writeFileSync(f.recordFile, '{}', { mode: 0o600 })
    if (variant === 'unsafe') fs.chmodSync(f.privateDir, 0o755)
    if (variant === 'occupied-response') fs.writeFileSync(f.keyFile + '.invite-response.json', '{}', { mode: 0o600 })
    if (variant === 'occupied-confirmation') fs.writeFileSync(f.keyFile + '.invite-confirmed.json', '{}', { mode: 0o600 })
    if (variant === 'occupied-refusal') fs.writeFileSync(f.keyFile + '.invite-refused.json', '{}', { mode: 0o600 })
    const originalSync = fs.fsyncSync
    if (variant === 'sync') fs.fsyncSync = fd => {
      if (fs.fstatSync(fd).isDirectory()) throw Object.assign(new Error('fixture'), { code: 'EIO' })
      return originalSync(fd)
    }
    try { await assert.rejects(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile,
      recordFile: f.recordFile, now: NOW }, f.deps)) }
    finally { fs.fsyncSync = originalSync }
    assert.equal(f.requests.length, 0, variant + ' never spends')
  }
})

test('pending and saved responses refuse unsafe files and malformed local bindings before another spend', async t => {
  for (const variant of ['pending-mode', 'pending-link', 'pending-shape', 'member', 'request', 'response-mode']) {
    const f = fixture(t)
    createKey(f.keyFile, f.keyOptions)
    await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps)
    const pendingFile = f.keyFile + '.invite-pending.json', responseFile = f.keyFile + '.invite-response.json'
    if (variant === 'pending-mode') fs.chmodSync(pendingFile, 0o644)
    if (variant === 'pending-link') fs.linkSync(pendingFile, path.join(f.privateDir, 'linked-pending'))
    if (variant === 'pending-shape') fs.writeFileSync(pendingFile, '{}')
    if (variant === 'member' || variant === 'request') {
      const state = readJson(pendingFile)
      if (variant === 'member') state.member = publicKeyOf(randomSecretKey())
      else state.request = '{}'
      fs.writeFileSync(pendingFile, JSON.stringify(state))
    }
    if (variant === 'response-mode') fs.writeFileSync(responseFile, '{}', { mode: 0o644 })
    await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps),
      ['member', 'request'].includes(variant) ? REFUSE.BINDING : REFUSE.FILE)
    assert.equal(f.requests.length, 1, variant + ' never dispatches again')
  }
})

test('key generation is exclusive and private; reads refuse unsafe custody and links', t => {
  const f = fixture(t)
  createKey(f.keyFile, f.keyOptions)
  assert.equal(fs.statSync(f.keyFile).mode & 0o777, 0o600)
  const before = fs.readFileSync(f.keyFile)
  refusal(() => createKey(f.keyFile, f.keyOptions), REFUSE.EXISTS)
  assert.ok(fs.readFileSync(f.keyFile).equals(before), 'existing key preserved')
  refusal(() => readKey(f.keyFile, { ...f.keyOptions, uid: process.getuid() + 1 }), REFUSE.KEY)
  fs.chmodSync(f.keyFile, 0o644)
  refusal(() => readKey(f.keyFile, f.keyOptions), REFUSE.KEY)
  fs.chmodSync(f.keyFile, 0o600)
  fs.chmodSync(f.privateDir, 0o755)
  refusal(() => readKey(f.keyFile, f.keyOptions), REFUSE.KEY)
  fs.chmodSync(f.privateDir, 0o700)
  const link = path.join(f.privateDir, 'linked-key')
  fs.symlinkSync(f.keyFile, link)
  refusal(() => readKey(link, f.keyOptions), REFUSE.KEY)
  fs.unlinkSync(link)
  fs.linkSync(f.keyFile, link)
  refusal(() => readKey(f.keyFile, f.keyOptions), REFUSE.KEY)
  fs.unlinkSync(link)
  fs.appendFileSync(f.keyFile, 'extra')
  refusal(() => readKey(f.keyFile, f.keyOptions), REFUSE.KEY)
  fs.writeFileSync(f.keyFile, before)
  const originalStat = fs.fstatSync
  fs.fstatSync = (...args) => {
    const st = originalStat(...args)
    return new Proxy(st, { get: (target, field) => field === 'size' ? 66 : Reflect.get(target, field) })
  }
  try { refusal(() => readKey(f.keyFile, f.keyOptions), REFUSE.KEY) }
  finally { fs.fstatSync = originalStat }
  refusal(() => createKey(path.join(f.directory, 'outside-home'), f.keyOptions), REFUSE.KEY)
})

test('key parents must be real protected directories and keys need canonical usable bytes', t => {
  const f = fixture(t)
  const target = path.join(f.home, 'target'), linked = path.join(f.home, 'linked')
  fs.mkdirSync(target, { mode: 0o700 }); fs.symlinkSync(target, linked)
  refusal(() => createKey(path.join(linked, 'key'), f.keyOptions), REFUSE.KEY)
  fs.chmodSync(f.home, 0o777)
  refusal(() => createKey(f.keyFile, f.keyOptions), REFUSE.KEY)
  fs.chmodSync(f.home, 0o700)
  fs.writeFileSync(f.keyFile, '00'.repeat(32) + '\n', { mode: 0o600 })
  refusal(() => readKey(f.keyFile, f.keyOptions), REFUSE.KEY)
  fs.writeFileSync(f.keyFile, 'GG'.repeat(32) + '\n')
  refusal(() => readKey(f.keyFile, f.keyOptions), REFUSE.KEY)
})

test('JSON input and admission output are bounded no-follow regular files and never replace records', t => {
  const f = fixture(t)
  const jsonFile = path.join(f.privateDir, 'input.json')
  fs.writeFileSync(jsonFile, '{}')
  assert.deepEqual(readJson(jsonFile), {})
  writeRecord(f.recordFile, { chain: [] }, f.keyOptions)
  assert.equal(fs.statSync(f.recordFile).mode & 0o777, 0o600)
  const before = fs.readFileSync(f.recordFile)
  refusal(() => writeRecord(f.recordFile, { chain: [1] }, f.keyOptions), REFUSE.FILE)
  assert.ok(fs.readFileSync(f.recordFile).equals(before), 'existing record preserved')
  const link = path.join(f.privateDir, 'link.json')
  fs.symlinkSync(jsonFile, link)
  refusal(() => readJson(link), REFUSE.FILE)
  refusal(() => readJson(f.privateDir), REFUSE.FILE)
  fs.writeFileSync(jsonFile, ' '.repeat(262145))
  refusal(() => readJson(jsonFile), REFUSE.FILE)
})

test('CLI emits fixed labels and refusal codes without keys, offers or reflected errors', async t => {
  const f = fixture(t), output = [], errors = []
  const configFile = path.join(f.privateDir, 'config.json'), offerFile = path.join(f.privateDir, 'offer.json')
  fs.writeFileSync(configFile, JSON.stringify(f.config)); fs.writeFileSync(offerFile, JSON.stringify(f.offer))
  const deps = { ...f.deps, now: () => NOW, out: line => output.push(line), err: line => errors.push(line) }
  assert.equal(await runCli(['preflight', '--config', configFile, '--offer', offerFile], deps), 0)
  assert.equal(await runCli(['key', '--key-file', f.keyFile], deps), 0)
  assert.equal(await runCli(['redeem', '--config', configFile, '--offer', offerFile, '--key-file', f.keyFile, '--out', f.recordFile], deps), 0)
  assert.equal(await runCli(['verify', '--config', configFile, '--record', f.recordFile, '--key-file', f.keyFile], deps), 0)
  assert.equal(await runCli(['key', '--key-file', f.keyFile], deps), 1)
  assert.equal(await runCli(['key', '--key-file', f.keyFile, '--unknown', 'sensitive'], deps), 1)
  assert.deepEqual(output, ['PREFLIGHT_OK', 'KEY_CREATED', 'ADMITTED', 'BINDING_OK'])
  assert.deepEqual(errors, [`REFUSED ${REFUSE.EXISTS}`, `REFUSED ${REFUSE.INPUT}`])
  const g = fixture(t), refusals = []
  createKey(g.keyFile, g.keyOptions)
  const refusedConfig = path.join(g.privateDir, 'config.json'), refusedOffer = path.join(g.privateDir, 'offer.json')
  fs.writeFileSync(refusedConfig, JSON.stringify(g.config)); fs.writeFileSync(refusedOffer, JSON.stringify(g.offer))
  assert.equal(await runCli(['redeem', '--config', refusedConfig, '--offer', refusedOffer,
    '--key-file', g.keyFile, '--out', g.recordFile], { ...g.deps, now: () => NOW,
    fetchImpl: async () => reply({ code: INVITE_REFUSE.ALLOTMENT }, 409), err: line => refusals.push(line) }), 1)
  assert.deepEqual(refusals, [`REFUSED ${INVITE_REFUSE.ALLOTMENT}`,
    `NOT_SPENT invite_id=${g.invite.id} cause=${INVITE_REFUSE.ALLOTMENT}`])
})

if (process.argv.includes('--mutations')) test('removing each new protection fails its regression', async t => {
  const f = fixture(t), original = fs.readFileSync(source, 'utf8')
  const mutations = [
    ['signed-offer', '  signedOffer(root, offer)', ''],
    ['offer-time', 'if (now < value.issuedAt)', 'if (false)'],
    ['offer-expiry', 'if (now >= value.expiresAt)', 'if (false)'],
    ['endpoint-protocol', "endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && loopback)", 'false'],
    ['endpoint-credentials', 'endpoint.username || endpoint.password', 'false'],
    ['endpoint-path', "endpoint.pathname !== '/'", 'false'],
    ['preflight-status', "if (status !== 200 || !fields(data, ['available', 'invite_id'])", "if (false || !fields(data, ['available', 'invite_id'])"],
    ['preflight-shape', "!fields(data, ['available', 'invite_id'])", 'false'],
    ['preflight-available', 'data.available !== true', 'false'],
    ['preflight-invite', 'data.invite_id !== offer.invite.id', 'false'],
    ['remote-refusal-code', "if (route !== '/redeem' && response.status !== 200 && fields(data, ['code'])", "if (false && fields(data, ['code'])"],
    ['response-bound', 'if (length > MAX_BYTES)', 'if (false)'],
    ['redeem-status', 'answer.status !== 200', 'false'],
    ['redeem-shape', "!fields(answer.data, ['admitted', 'record'])", 'false'],
    ['redeem-admitted', 'answer.data.admitted !== true', 'false'],
    ['authority-proof', '  const checked = verifyAdmissionRecord({ root: config.root, record })', '  const checked = verifyRecord({ root: config.root, record })'],
    ['canonical-values', 'canonicalJson(left) === canonicalJson(right)', 'JSON.stringify(left) === JSON.stringify(right)'],
    ['redeem-binding', '|| !sameValue(last.redemption, redemption)', '|| false'],
    ['redeem-offer-binding', '|| !sameValue(last.invite, offer.invite)', '|| false'],
    ['redeem-ancestry-binding', 'if (!sameValue(record.chain.slice(0, -1), offer.chain)', 'if (false'],
    ['redeem-member-binding', '|| !sameValue(last.redemption, redemption)\n    || checked.member !== member', '|| false'],
    ['expected-before-spend', '  verifyRecord({ root: config.root, record: expected })', ''],
    ['pending-retry', "try { answer = await post(config, '/redeem', request, fetchImpl) }", "try { if (pending) throw fail(REFUSE.ADMISSION); answer = await post(config, '/redeem', request, fetchImpl) }"],
    ['persisted-request', "const request = pending && Object.hasOwn(pending, 'request') ? pending.request\n    : JSON.stringify({ root: config.root, ...(pending?.offer ?? offer), redemption })", 'const request = JSON.stringify({ root: config.root, ...offer, redemption })'],
    ['pending-request-binding', "!sameValue(JSON.parse(request), { root: config.root, ...offer, redemption })", 'false'],
    ['one-attempt', "try { answer = await post(config, '/redeem', request, fetchImpl) }", "try { await post(config, '/redeem', request, fetchImpl); answer = await post(config, '/redeem', request, fetchImpl) }"],
    ['transport-deadline', 'AbortSignal.timeout(10000)', 'AbortSignal.timeout(100000)'],
    ['ambiguous-refusal', 'NOT_SPENT.includes(answer.data.code)', 'Object.values(INVITE_REFUSE).includes(answer.data.code)'],
    ['terminal-refusal', 'if (refused) {', 'if (false) {'],
    ['no-spend-message', 'if (error?.notSpent === true)', 'if (false)'],
    ['legacy-confirmation', "if (confirmed && !fields(confirmed, ['chain']))", 'if (confirmed)'],
    ['pending-offer-binding', '|| !sameValue(pending.offer.chain, offer.chain) || !sameValue(pending.offer.invite, offer.invite)', '|| false'],
    ['pending-endpoint-binding', 'pending.version !== 1 || !sameValue(pending.config, config)', 'pending.version !== 1'],
    ['pending-member-binding', '|| pending.member !== member', '|| false'],
    ['pending-file-custody', "if (!st.isFile() || st.nlink !== 1 || st.uid !== (options?.uid ?? process.getuid())\n      || (st.mode & 0o777) !== 0o600 || st.size < 1 || st.size > MAX_BYTES)", 'if (false)'],
    ['output-before-spend', 'const output = recordOutput(recordFile, Boolean(pending), expected, config, keyOptions)', 'const output = undefined'],
    ['pending-directory-sync', '    fs.fsyncSync(fd)\n  } catch { throw fail(REFUSE.FILE) }', '  } catch { throw fail(REFUSE.FILE) }'],
    ['response-path-before-spend', '  if (!pending && (response || confirmed || refused)) throw fail(REFUSE.FILE)', ''],
    ['resume-binding', 'if (checked.member !== publicKeyOf(key))', 'if (false)'],
    ['exclusive-key', 'fs.constants.O_CREAT | fs.constants.O_EXCL', 'fs.constants.O_CREAT'],
    ['key-home-custody', '    privateParent(file, options)', ''],
    ['parent-write', '(st.mode & 0o022)', 'false'],
    ['private-parent', '(st.mode & 0o077)', 'false'],
    ['key-file-mode', '(st.mode & 0o777) !== 0o600', 'false'],
    ['key-file-link', 'st.nlink !== 1 || st.uid', 'false || st.uid'],
    ['key-file-size', 'st.size !== 65', 'false'],
    ['key-no-follow', 'fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK', 'fs.constants.O_RDONLY | fs.constants.O_NONBLOCK'],
    ['json-no-follow', 'fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK', 'fs.constants.O_RDONLY | fs.constants.O_NONBLOCK'],
  ]
  // Isolated mutants run their focused regressions a few at a time.
  const patterns = {
    'signed-offer': 'signed offers', 'offer-time': 'signed offers', 'offer-expiry': 'signed offers',
    'endpoint-protocol': 'endpoint config', 'endpoint-credentials': 'endpoint config', 'endpoint-path': 'endpoint config',
    'preflight-status': 'preflight asks', 'preflight-shape': 'preflight asks', 'preflight-available': 'preflight asks',
    'preflight-invite': 'preflight asks', 'response-bound': 'preflight asks', 'remote-refusal-code': 'authoritative replay',
    'redeem-status': 'remote redemption', 'redeem-shape': 'remote redemption', 'redeem-admitted': 'remote redemption',
    'authority-proof': 'unsigned service records', 'canonical-values': 'a spent admission with reordered',
    'redeem-binding': 'valid alternative ancestry', 'redeem-offer-binding': 'valid alternative ancestry',
    'redeem-ancestry-binding': 'valid alternative ancestry', 'redeem-member-binding': 'remote redemption',
    'expected-before-spend': 'generated expected ancestry', 'pending-retry': 'pre-spend transport failure',
    'persisted-request': 'pre-spend transport failure', 'pending-request-binding': 'pending and saved responses',
    'one-attempt': 'spent then dropped', 'transport-deadline': 'bounded deadline',
    'ambiguous-refusal': 'only definitive', 'terminal-refusal': 'only definitive', 'no-spend-message': 'CLI emits fixed labels',
    'legacy-confirmation': 'legacy pending', 'pending-offer-binding': 'generated expected ancestry',
    'pending-endpoint-binding': 'generated expected ancestry', 'pending-member-binding': 'pending and saved responses',
    'pending-file-custody': 'pending and saved responses', 'output-before-spend': 'unwritable or occupied output',
    'pending-directory-sync': 'unwritable or occupied output', 'response-path-before-spend': 'unwritable or occupied output',
    'resume-binding': 'remote redemption', 'exclusive-key': 'key generation is exclusive',
    'key-home-custody': 'key generation is exclusive', 'parent-write': 'key parents must be real',
    'private-parent': 'key generation is exclusive', 'key-file-mode': 'key generation is exclusive',
    'key-file-link': 'key generation is exclusive', 'key-file-size': 'key generation is exclusive',
    'key-no-follow': 'key generation is exclusive', 'json-no-follow': 'JSON input and admission output',
  }
  const { spawn } = await import('node:child_process')
  const runOne = ([name, before, after], index) => new Promise((resolve, reject) => {
    assert.ok(original.includes(before), `mutation target missing: ${name}`)
    assert.ok(patterns[name], `mutation regression missing: ${name}`)
    let mutant = original.replaceAll(before, after)
    mutant = mutant.replace("'../../packages/invites/index.mjs'", JSON.stringify(pathToFileURL(path.resolve(source, '../../../packages/invites/index.mjs')).href))
      .replace("'../../plugins/aukora-nostr/lib/event.mjs'", JSON.stringify(pathToFileURL(path.resolve(source, '../../../plugins/aukora-nostr/lib/event.mjs')).href))
      .replace("'../../packages/contracts/src/json.mjs'", JSON.stringify(pathToFileURL(path.resolve(source, '../../../packages/contracts/src/json.mjs')).href))
    const mutantFile = path.join(f.directory, `mutant-${index}.mjs`)
    fs.writeFileSync(mutantFile, mutant)
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', '--test-name-pattern=' + patterns[name], fileURLToPath(import.meta.url)], {
      timeout: 15000, env: { ...process.env, NODE_SPAWN_INVITE_MODULE: pathToFileURL(mutantFile).href }, stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = '', stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk }); child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', reject)
    child.on('close', status => {
      try {
        assert.equal(status, 1, `mutation survived: ${name}`)
        assert.match(stdout, /not ok \d+ - /u, `mutation lacked a failing test: ${name}`)
        assert.doesNotMatch(stdout + stderr, /SyntaxError/u, `invalid mutation: ${name}`)
        resolve(name)
      } catch (error) { reject(error) }
    })
  })
  const queue = mutations.map((mutation, index) => [mutation, index])
  const worker = async () => { for (let next = queue.shift(); next; next = queue.shift()) t.diagnostic(`MUTATION ${await runOne(...next)}: KILLED`) }
  await Promise.all(Array.from({ length: 6 }, worker))
  t.diagnostic(`MUTATIONS ${mutations.length}/${mutations.length} KILLED`)
})
