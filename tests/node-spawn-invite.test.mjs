// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise signed offers, remote accounting refusals and isolated exact-key admission.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createInvite, redeemInvite, verifyAdmission, createMemoryStore, REFUSE as INVITE_REFUSE } from '../packages/invites/index.mjs'
import { publicKeyOf, randomSecretKey } from '../plugins/aukora-nostr/lib/event.mjs'

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
  await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, f.deps), INVITE_REFUSE.REPLAY)
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
  const different = { chain: [{ invite: f.invite, redemption: redeemInvite({ invite: f.invite, secretKey: randomSecretKey(), now: NOW }) }] }
  await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, {
    keyOptions: f.keyOptions, fetchImpl: async () => reply({ admitted: true, record: different }),
  }), REFUSE.BINDING)
  for (const [data, status] of [[{ admitted: true, record }, 201], [{ admitted: false, record }, 200],
    [{ admitted: true, record, extra: true }, 200]]) {
    await rejected(() => redeem({ config: f.config, offer: f.offer, keyFile: f.keyFile, now: NOW }, {
      keyOptions: f.keyOptions, fetchImpl: async () => reply(data, status),
    }), REFUSE.ADMISSION)
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

if (process.argv.includes('--mutations')) test('removing each new protection fails its regression', t => {
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
    ['remote-refusal-code', "if (response.status !== 200 && fields(data, ['code'])", "if (false && fields(data, ['code'])"],
    ['response-bound', 'if (length > MAX_BYTES)', 'if (false)'],
    ['redeem-status', "if (status !== 200 || !fields(data, ['admitted', 'record'])", "if (false || !fields(data, ['admitted', 'record'])"],
    ['redeem-shape', "!fields(data, ['admitted', 'record'])", 'false'],
    ['redeem-admitted', 'data.admitted !== true', 'false'],
    ['redeem-binding', 'if (checked.member !== publicKeyOf(key) || JSON.stringify(data.record) !== JSON.stringify(expected))', 'if (false)'],
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
  const mutantFile = path.join(f.directory, 'mutant.mjs')
  for (const [name, before, after] of mutations) {
    assert.ok(original.includes(before), `mutation target missing: ${name}`)
    let mutant = original.replaceAll(before, after)
    mutant = mutant.replace("'../../packages/invites/index.mjs'", JSON.stringify(pathToFileURL(path.resolve(source, '../../../packages/invites/index.mjs')).href))
      .replace("'../../plugins/aukora-nostr/lib/event.mjs'", JSON.stringify(pathToFileURL(path.resolve(source, '../../../plugins/aukora-nostr/lib/event.mjs')).href))
    fs.writeFileSync(mutantFile, mutant)
    const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', fileURLToPath(import.meta.url)], {
      encoding: 'utf8', timeout: 30000, env: { ...process.env, NODE_SPAWN_INVITE_MODULE: pathToFileURL(mutantFile).href },
    })
    assert.equal(result.status, 1, `mutation survived: ${name}`)
    assert.match(result.stdout, /not ok \d+ - /u, `mutation lacked a failing test: ${name}`)
    assert.doesNotMatch(result.stdout + result.stderr, /SyntaxError/u, `invalid mutation: ${name}`)
    t.diagnostic(`MUTATION ${name}: KILLED`)
  }
  t.diagnostic(`MUTATIONS ${mutations.length}/${mutations.length} KILLED`)
})
