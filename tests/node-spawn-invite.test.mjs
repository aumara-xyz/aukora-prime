// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise signed offers, remote accounting refusals and isolated exact-key admission.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createInvite, redeemInvite, verifyAdmission, createMemoryStore, REFUSE as INVITE_REFUSE } from '../packages/invites/index.mjs'
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
  const state = createMemoryStore(), spent = new Set(), requests = []
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
      const result = verifyAdmission({ ...body, state, now: NOW })
      spent.add(body.invite.id)
      return reply({ admitted: true, record: result.record })
    } catch (error) { return reply({ code: error.code }, 409) }
  }
  t.after(() => { state.close(); fs.rmSync(directory, { recursive: true, force: true }) })
  return { directory, home, privateDir, keyFile, recordFile, keyOptions, rootKey, root, config,
    invite, offer, state, spent, requests, deps: { fetchImpl, keyOptions }, fetchImpl }
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
    const different = { chain: [{ invite: g.invite, redemption: redeemInvite({ invite: g.invite, secretKey: randomSecretKey(), now: NOW }) }] }
    await rejected(() => redeem({ config: g.config, offer: g.offer, keyFile: g.keyFile, now: NOW }, {
      keyOptions: g.keyOptions, fetchImpl: async (url, options) => {
        const body = JSON.parse(options.body), record = { chain: [...body.chain, { invite: body.invite, redemption: body.redemption }] }
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
        return reply({ admitted: true, record })
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

test('spent then mismatched record persists an exact resume step and a second run spends nothing', async t => {
  const f = fixture(t), output = [], errors = []
  createKey(f.keyFile, f.keyOptions)
  const configFile = path.join(f.privateDir, 'config.json'), offerFile = path.join(f.privateDir, 'offer.json')
  const authorityRecord = path.join(f.privateDir, 'authority-record.json')
  fs.writeFileSync(configFile, JSON.stringify(f.config)); fs.writeFileSync(offerFile, JSON.stringify(f.offer))
  const args = ['redeem', '--config', configFile, '--offer', offerFile, '--key-file', f.keyFile, '--out', f.recordFile]
  let exact, spends = 0
  const fetchImpl = async (url, options) => {
    const result = await f.fetchImpl(url, options), data = await result.json()
    if (data.admitted) { spends++; exact = data.record }
    const different = { chain: [{ invite: f.invite, redemption: redeemInvite({ invite: f.invite,
      secretKey: randomSecretKey(), now: NOW }) }] }
    return reply({ admitted: true, record: different })
  }
  const deps = { ...f.deps, fetchImpl, now: () => NOW, out: line => output.push(line), err: line => errors.push(line) }
  assert.equal(await runCli(args, deps), 1)
  assert.match(errors.join('\n'), new RegExp(`SPENT_NOT_CONFIRMED invite_id=${f.invite.id} cause=${REFUSE.BINDING}`))
  assert.ok(errors.at(-1).endsWith('--resume-record AUTHORITY_RECORD_PATH'))
  assert.ok(errors.at(-1).includes(args.map(arg => "'" + arg + "'").join(' ')), 'exact original command is preserved')
  const pending = readJson(f.keyFile + '.invite-pending.json')
  const saved = readJson(f.keyFile + '.invite-response.json')
  assert.equal(pending.redemption.id, exact.chain.at(-1).redemption.id)
  assert.equal(saved.data.record.chain.at(-1).redemption.pubkey === pending.member, false)
  for (const file of [f.keyFile + '.invite-pending.json', f.keyFile + '.invite-response.json', f.recordFile]) {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600, 'state and reserved output stay private under umask 002')
  }
  assert.equal(await runCli(args, { ...deps, now: () => NOW + 172801 }), 1)
  assert.equal(spends, 1)
  assert.equal(f.requests.length, 1, 'a repeated command never dispatches the invite again')
  fs.writeFileSync(authorityRecord, JSON.stringify(reordered(exact)))
  assert.equal(await runCli([...args, '--resume-record', authorityRecord], { ...deps, now: () => NOW + 172801 }), 0)
  assert.equal(spends, 1)
  assert.deepEqual(readJson(f.recordFile), reordered(exact))
  assert.equal(fs.statSync(f.keyFile + '.invite-confirmed.json').mode & 0o777, 0o600)
  assert.equal(await runCli(args, { ...deps, now: () => NOW + 172801 }), 0, 'plain rerun uses the persisted reconciliation')
  assert.equal(f.requests.length, 1)
  assert.deepEqual(output, ['ADMITTED', 'ADMITTED'])
})

test('unwritable or occupied output and non-durable pending state refuse before spending', async t => {
  for (const variant of ['existing', 'unsafe', 'sync', 'occupied-response', 'occupied-confirmation']) {
    const f = fixture(t)
    createKey(f.keyFile, f.keyOptions)
    if (variant === 'existing') fs.writeFileSync(f.recordFile, '{}', { mode: 0o600 })
    if (variant === 'unsafe') fs.chmodSync(f.privateDir, 0o755)
    if (variant === 'occupied-response') fs.writeFileSync(f.keyFile + '.invite-response.json', '{}', { mode: 0o600 })
    if (variant === 'occupied-confirmation') fs.writeFileSync(f.keyFile + '.invite-confirmed.json', '{}', { mode: 0o600 })
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
  for (const variant of ['pending-mode', 'pending-link', 'pending-shape', 'member', 'response-mode']) {
    const f = fixture(t)
    createKey(f.keyFile, f.keyOptions)
    await redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps)
    const pendingFile = f.keyFile + '.invite-pending.json', responseFile = f.keyFile + '.invite-response.json'
    if (variant === 'pending-mode') fs.chmodSync(pendingFile, 0o644)
    if (variant === 'pending-link') fs.linkSync(pendingFile, path.join(f.privateDir, 'linked-pending'))
    if (variant === 'pending-shape') fs.writeFileSync(pendingFile, '{}')
    if (variant === 'member') {
      const state = readJson(pendingFile)
      state.member = publicKeyOf(randomSecretKey())
      fs.writeFileSync(pendingFile, JSON.stringify(state))
    }
    if (variant === 'response-mode') fs.chmodSync(responseFile, 0o644)
    await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps),
      variant === 'member' ? REFUSE.BINDING : REFUSE.FILE)
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
    ['redeem-status', 'response.status !== 200', 'false'],
    ['redeem-shape', "!fields(response.data, ['admitted', 'record'])", 'false'],
    ['redeem-admitted', 'response.data.admitted !== true', 'false'],
    ['canonical-values', 'canonicalJson(left) === canonicalJson(right)', 'JSON.stringify(left) === JSON.stringify(right)'],
    ['redeem-binding', '|| !sameValue(last.redemption, redemption)', '|| false'],
    ['redeem-offer-binding', '|| !sameValue(last.invite, offer.invite)', '|| false'],
    ['redeem-ancestry-binding', 'if (!sameValue(record.chain.slice(0, -1), offer.chain)', 'if (false'],
    ['redeem-member-binding', '|| !sameValue(last.redemption, redemption)\n    || checked.member !== member', '|| false'],
    ['expected-before-spend', '  boundRecord(config, expected, offer, redemption, member)', ''],
    ['request-not-resent', "    } else response = privateJson(responseFile, keyOptions)", "    } else response = await post(config, '/redeem', { root: config.root, ...offer, redemption }, fetchImpl)"],
    ['pending-offer-binding', '|| !sameValue(pending.offer.chain, offer.chain) || !sameValue(pending.offer.invite, offer.invite)', '|| false'],
    ['pending-endpoint-binding', '|| pending.version !== 1 || !sameValue(pending.config, config)', '|| pending.version !== 1'],
    ['pending-member-binding', '|| pending.member !== member', '|| false'],
    ['pending-file-custody', "if (!st.isFile() || st.nlink !== 1 || st.uid !== (options?.uid ?? process.getuid())\n      || (st.mode & 0o777) !== 0o600 || st.size < 1 || st.size > MAX_BYTES)", 'if (false)'],
    ['output-before-spend', 'const output = recordOutput(recordFile, Boolean(pending), expected, keyOptions)', 'const output = undefined'],
    ['pending-directory-sync', '    fs.fsyncSync(fd)\n  } catch { throw fail(REFUSE.FILE) }', '  } catch { throw fail(REFUSE.FILE) }'],
    ['response-path-before-spend', '  if (!pending && (privateJson(responseFile, keyOptions) || privateJson(confirmedFile, keyOptions))) throw fail(REFUSE.FILE)', ''],
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
  // Each mutant reruns this whole file; one after another that outgrew the runner's 55 seconds on a busy
  // Linux machine, so they run a few at a time, each from its own file.
  const { spawn } = await import('node:child_process')
  const runOne = ([name, before, after], index) => new Promise((resolve, reject) => {
    assert.ok(original.includes(before), `mutation target missing: ${name}`)
    let mutant = original.replaceAll(before, after)
    mutant = mutant.replace("'../../packages/invites/index.mjs'", JSON.stringify(pathToFileURL(path.resolve(source, '../../../packages/invites/index.mjs')).href))
      .replace("'../../plugins/aukora-nostr/lib/event.mjs'", JSON.stringify(pathToFileURL(path.resolve(source, '../../../plugins/aukora-nostr/lib/event.mjs')).href))
      .replace("'../../packages/contracts/src/json.mjs'", JSON.stringify(pathToFileURL(path.resolve(source, '../../../packages/contracts/src/json.mjs')).href))
    const mutantFile = path.join(f.directory, `mutant-${index}.mjs`)
    fs.writeFileSync(mutantFile, mutant)
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', fileURLToPath(import.meta.url)], {
      timeout: 30000, env: { ...process.env, NODE_SPAWN_INVITE_MODULE: pathToFileURL(mutantFile).href }, stdio: ['ignore', 'pipe', 'pipe'],
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
