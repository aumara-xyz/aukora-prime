// Exercise configured Messages routes with real contact signatures, gift wraps and relay authentication.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { registerHooks, stripTypeScriptTypes } from 'node:module'
import { dirname, join } from 'node:path'
import { Readable } from 'node:stream'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createBinding, loadOrCreateNostrKey } from '../plugins/aukora-nostr/lib/identity.mjs'
import { isValidEvent, randomSecretKey, signEvent } from '../plugins/aukora-nostr/lib/event.mjs'
import { composeDirectMessage, openGiftWrap } from '../plugins/aukora-nostr/lib/giftwrap.mjs'
import { fetchGiftWraps } from '../plugins/aukora-nostr/lib/relay.mjs'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = dirname(HERE)
const FACE = join(ROOT, 'plugins/aukora-face/messages/src/index.ts')
const compiled = process.argv.includes('--compiled')
const NODE_RELAY = 'ws://localhost:3000'
const ENV = ['DSH_HOME', 'AUKORA_NOSTR_CONTACT_MODULE', 'AUKORA_NOSTR_RELAYS', 'AUKORA_NOSTR_TIMEOUT_MS']
const mutations = [
  { name: 'no-public-default', file: FACE,
    before: 'config.nodeRelay === undefined ? [] : [config.nodeRelay]',
    after: "config.nodeRelay === undefined ? ['wss://relay.damus.io'] : [config.nodeRelay]" },
  { name: 'no-relay-thread-refusal', file: FACE, count: 2,
    before: 'if (relays.length === 0) {', after: 'if (false) {' },
  { name: 'no-relay-send-refusal', file: FACE, count: 2, last: true,
    before: 'if (relays.length === 0) {', after: 'if (false) {' },
  { name: 'invalid-override-refuses', file: join(ROOT, 'plugins/aukora-face/messages/src/contacts-store.ts'),
    before: '})) return []', after: '})) return nodeRelays' },
  { name: 'announcement-stays-on-node', file: FACE,
    before: 'relays, timeoutMs: 2000', after: 'relays: modules.DEFAULT_RELAYS, timeoutMs: 2000' },
  { name: 'send-stays-on-node', file: FACE,
    before: 'publishOne(modules.modules, entry.wrap, relays,',
    after: 'publishOne(modules.modules, entry.wrap, modules.modules.DEFAULT_RELAYS,' },
  { name: 'thread-stays-on-node', file: FACE,
    before: 'since: requested.since ?? 0,\n        relays,',
    after: 'since: requested.since ?? 0,\n        relays: modules.modules.DEFAULT_RELAYS,' },
  { name: 'thread-pages-inbox', file: FACE,
    before: 'stateDir: stateRoots.stateDir,', after: '' },
  { name: 'thread-forwards-scan-state', file: FACE,
    before: '...(spec.stateDir === undefined ? {} : { stateDir: spec.stateDir }),', after: '' },
  { name: 'advertised-inbox-cannot-redirect', file: FACE,
    before: 'publishOne(modules.modules, entry.wrap, relays,',
    after: 'publishOne(modules.modules, entry.wrap, recipient ? (await modules.modules.fetchDmRelays({ pubkey: recipientPubkey, relays, secretKeyHex: key.secretKeyHex, timeoutMs: 2500 })).relays : relays,' },
  { name: 'foreign-refused', file: FACE,
    before: "if (found.contact.state === 'FOREIGN') {", after: 'if (false) {' },
]
const mutant = process.env.AUKORA_MESSAGES_MUTANT
registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('@aukora/face-messages/src/')) {
      return { url: pathToFileURL(join(ROOT, 'plugins/aukora-face/messages/src', specifier.split('/src/')[1])).href, shortCircuit: true }
    }
    return next(specifier, context)
  },
  load(url, context, next) {
    if (!url.startsWith(pathToFileURL(join(ROOT, 'plugins/aukora-face')).href) || !url.endsWith('.ts')) return next(url, context)
    let source = readFileSync(fileURLToPath(url), 'utf8')
    const change = mutations.find(entry => entry.name === mutant && fileURLToPath(url) === entry.file)
    if (change) {
      assert.equal(source.split(change.before).length, (change.count ?? 1) + 1, `mutation anchor: ${change.name}`)
      const at = change.last ? source.lastIndexOf(change.before) : source.indexOf(change.before)
      source = source.slice(0, at) + change.after + source.slice(at + change.before.length)
    }
    return { format: 'module', source: stripTypeScriptTypes(source, { mode: 'transform' }), shortCircuit: true }
  },
})
const { apply, loadMailModules } = await import(pathToFileURL(compiled ? join(ROOT, 'plugins/aukora-face/messages/lib/index.js') : FACE).href)
const { contactPayload, liveContactEvent } = await import('../plugins/aukora-face/aumlok/src/contact-qr.ts')
const { identityContactVerificationRoute } = await import('../plugins/aukora-face/aumlok/src/contact-verification.ts')
const { parseContactInput } = await import('../plugins/aukora-face/messages/src/client/add-contact.ts')
const { parseMessagesRefusalBody } = await import('../plugins/aukora-face/messages/src/messages-route.ts')

function party(root, name) {
  const stateDir = join(root, name), controllerDir = join(stateDir, 'controller')
  mkdirSync(controllerDir, { recursive: true, mode: 0o700 })
  const pair = generateKeyPairSync('ed25519')
  const controller = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex')
  const file = join(controllerDir, 'local-control.json')
  // createBinding's legacy signer is disposable; no owner approval or enrollment is asserted.
  writeFileSync(file, JSON.stringify({ activeControl: { publicKeys: { ed25519: controller } },
    ed25519PrivateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) }), { mode: 0o600 })
  const nostr = loadOrCreateNostrKey(stateDir), rootId = randomBytes(32).toString('hex')
  const subject = `aukora:1:${rootId}`
  const binding = createBinding({ controllerDir, nostr, subject, handle: name, label: 'TEST',
    createdAt: new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z') })
  writeFileSync(join(stateDir, 'nostr/binding.json'), JSON.stringify(binding), { mode: 0o600 })
  writeFileSync(file, JSON.stringify({ version: 3, publicRoot: { rootId, handle: name, epoch: 1,
    machines: [{ ed25519: controller }] }, revokedMachines: [] }), { mode: 0o600 })
  return { stateDir, controllerDir, controller, binding, subject, label: name, ...nostr }
}

function fixture(t) {
  const root = mkdtempSync(join(HERE, '.messages-node-'))
  const before = Object.fromEntries(ENV.map(key => [key, process.env[key]])), websocket = globalThis.WebSocket
  for (const key of ENV) delete process.env[key]
  process.env.AUKORA_NOSTR_CONTACT_MODULE = join(ROOT, 'plugins/aukora-nostr/lib/contact.mjs')
  process.env.AUKORA_NOSTR_TIMEOUT_MS = '2500'
  t.after(() => {
    globalThis.WebSocket = websocket
    for (const key of ENV) { if (before[key] === undefined) delete process.env[key]; else process.env[key] = before[key] }
    rmSync(root, { recursive: true, force: true })
  })
  return { a: party(root, 'alice'), b: party(root, 'bob') }
}

function mount(owner, config = { nodeRelay: NODE_RELAY }) {
  const routes = new Map()
  const requestRejection = req => req.headers.authorization === 'Bearer fixture' ? undefined : 401
  apply({ webServer: { host: '127.0.0.1', register(route) { routes.set(route.path, route); return () => {} } },
    connection: { requestRejection },
    get(name) { return name === 'aumlokControl' ? { directory: owner.controllerDir } : undefined },
    effect(effect) { effect() },
  }, config)
  const scan = identityContactVerificationRoute(requestRejection)
  routes.set(scan.path, scan)
  return async (path, body, authorized = true) => {
    process.env.DSH_HOME = owner.stateDir
    const req = Readable.from(body === undefined ? [] : [JSON.stringify(body)])
    Object.assign(req, { url: path, method: body === undefined ? 'GET' : 'POST', headers: {
      host: '127.0.0.1:18735', origin: 'http://127.0.0.1:18735', 'content-type': 'application/json',
      ...(authorized ? { authorization: 'Bearer fixture' } : {}),
    } })
    const res = { statusCode: 200, headersSent: false, writableEnded: false, text: '',
      setHeader() {}, writeHead(status) { this.statusCode = status; this.headersSent = true },
      end(text = '') { this.text = text; this.writableEnded = true },
    }
    const route = routes.get(new URL(path, 'http://localhost').pathname)
    assert.ok(route, 'real apply() registered the route')
    await route.handler(req, res)
    return { status: res.statusCode, body: res.text ? JSON.parse(res.text) : null }
  }
}

async function addSignedContact(call, peer) {
  const identity = { npub: peer.npub, peerControllerKey: peer.controller,
    subject: peer.subject, binding: peer.binding, label: peer.label }
  const proof = { nonce: randomBytes(32).toString('hex'), issuedAt: Math.floor(Date.now() / 1000) }
  proof.expiresAt = proof.issuedAt + 60
  proof.signature = signEvent(liveContactEvent(contactPayload(identity), proof, peer.xonlyHex), peer.secretKeyHex).sig
  const raw = contactPayload(identity, proof)
  const scan = await call('/api/aukora/identity/verify-contact', JSON.parse(raw))
  assert.equal(scan.status, 200)
  const checked = scan.body
  assert.equal(checked.npub, peer.npub); assert.equal(checked.controller, peer.controller)
  assert.equal(checked.liveChallengePerformed, false)
  const replay = await call('/api/aukora/identity/verify-contact', JSON.parse(raw))
  assert.equal(replay.status, 400); assert.equal(replay.body.code, 'identity:replayed-contact')
  const parsed = parseContactInput(raw)
  assert.equal(parsed.ok, true)
  const result = await call('/aukora-messages/add-contact', { npub: parsed.npub, controller: parsed.controller,
    name: checked.label, binding: parsed.binding })
  assert.equal(result.status, 200); assert.equal(result.body.binding, 'verified')
}

// This replaces transport only: signatures, challenge, time windows and the recipient gate are checked.
function relay() {
  const events = [], urls = [], requests = [], authenticated = [], refusals = []
  class Socket extends EventTarget {
    constructor(url) {
      super(); this.url = url; this.challenge = randomBytes(32).toString('hex'); this.closed = false
      urls.push(url)
      queueMicrotask(() => {
        if (url !== NODE_RELAY && url !== 'ws://127.0.0.1:3000') { this.dispatchEvent(new Event('error')); return }
        this.dispatchEvent(new Event('open')); this.reply(['AUTH', this.challenge])
      })
    }
    close() { this.closed = true }
    reply(frame) { if (!this.closed) this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(frame) })) }
    send(raw) { queueMicrotask(() => this.receive(JSON.parse(raw))) }
    receive(frame) {
      if (this.closed) return
      const [kind, value, filter] = frame, now = Math.floor(Date.now() / 1000)
      if (kind === 'CLOSE') return
      if (kind === 'AUTH') {
        const valid = isValidEvent(value) && value.kind === 22242 && value.content === ''
          && Math.abs(value.created_at - now) <= 900
          && JSON.stringify(value.tags) === JSON.stringify([['relay', this.url], ['challenge', this.challenge]])
        if (valid) { this.reader = value.pubkey; authenticated.push(value.pubkey) }
        this.reply(['OK', value.id, valid, valid ? '' : 'restricted: invalid authentication']); return
      }
      if (!this.reader) {
        this.reply(kind === 'REQ' ? ['CLOSED', value, 'auth-required: authenticate first']
          : ['OK', value.id, false, 'auth-required: authenticate first']); return
      }
      if (kind === 'EVENT') {
        const valid = isValidEvent(value) && (value.kind === 1059
          ? value.created_at >= now - 172800 && value.created_at <= now
          : Math.abs(value.created_at - now) <= 900)
        if (valid && !events.some(item => item.id === value.id)) events.push(value)
        this.reply(['OK', value.id, valid, valid ? '' : 'invalid: event timestamp or signature']); return
      }
      assert.equal(kind, 'REQ'); requests.push(filter)
      if (filter.kinds.some(eventKind => eventKind === 1059 || eventKind === 21059)
        && (filter['#p']?.length !== 1 || filter['#p'][0] !== this.reader)) {
        refusals.push('restricted: recipient filter must match authenticated key')
        this.reply(['CLOSED', value, refusals.at(-1)]); return
      }
      const matches = events.filter(event => filter.kinds.includes(event.kind)
        && (!filter.authors || filter.authors.includes(event.pubkey))
        && (!filter['#p'] || event.tags.some(tag => tag[0] === 'p' && filter['#p'].includes(tag[1])))
        && (filter.since === undefined || event.created_at >= filter.since)
        && (filter.until === undefined || event.created_at <= filter.until))
        .sort((a, b) => b.created_at - a.created_at).slice(0, filter.limit)
      for (const event of matches) this.reply(['EVENT', value, event])
      this.reply(['EOSE', value])
    }
  }
  return { Socket, events, urls, requests, authenticated, refusals }
}

async function exchange(t, live = false) {
  const { a, b } = fixture(t), server = live ? null : relay()
  if (server) globalThis.WebSocket = server.Socket
  const A = mount(a), B = mount(b)
  await addSignedContact(A, b); await addSignedContact(B, a)
  if (server) server.events.push(signEvent({ pubkey: b.xonlyHex, kind: 10050,
    created_at: Math.floor(Date.now() / 1000), tags: [['relay', 'wss://8.8.8.8']], content: '' }, b.secretKeyHex))
  const message = 'Disposable route test: hello Bob.'
  const sent = await A('/aukora-messages/send', { npub: b.npub, text: message })
  assert.equal(sent.status, 200); assert.equal(sent.body.status, 'sent')
  assert.equal(sent.body.ok, true, `node relay send: ${sent.body.verdict}`)
  assert.deepEqual(sent.body.copies.map(copy => [copy.copy, copy.accepted]), [['recipient', true], ['self', true]])
  assert.deepEqual(sent.body.accepted, [NODE_RELAY, NODE_RELAY])
  const received = await B(`/aukora-messages/thread?npub=${a.npub}`)
  assert.equal(received.status, 200); assert.equal(received.body.status, 'ok')
  assert.deepEqual(received.body.messages.map(({ from, text, id }) => ({ from, text, id })),
    [{ from: 'them', text: message, id: sent.body.id }])
  assert.deepEqual(received.body.answered, [NODE_RELAY])
  const own = await A(`/aukora-messages/thread?npub=${b.npub}`)
  assert.deepEqual(own.body.messages.map(({ from, text }) => ({ from, text })), [{ from: 'me', text: message }])
  const fetched = await fetchGiftWraps({ recipientPubkey: b.xonlyHex, secretKeyHex: b.secretKeyHex,
    relays: [NODE_RELAY], timeoutMs: 2500, since: 0 })
  assert.equal(fetched.verdict, null)
  const wrap = fetched.wraps.find(event => openGiftWrap(event, { recipientSecretKey: b.secretKeyHex }).rumor.id === sent.body.id)
  assert.ok(wrap)
  const opened = openGiftWrap(wrap, { recipientSecretKey: b.secretKeyHex, expectSender: a.xonlyHex })
  assert.equal(opened.sender, a.xonlyHex); assert.equal(opened.rumor.content, message)
  assert.notEqual(wrap.pubkey, a.xonlyHex); assert.ok(!JSON.stringify(wrap).includes(message))
  assert.throws(() => openGiftWrap(wrap, { recipientSecretKey: b.secretKeyHex, expectSender: b.xonlyHex }))
  const stranger = await fetchGiftWraps({ recipientPubkey: b.xonlyHex, secretKeyHex: randomSecretKey(),
    relays: [NODE_RELAY], timeoutMs: 2500, since: 0 })
  assert.equal(stranger.verdict, 'nostr:no-relay-answered'); assert.deepEqual(stranger.wraps, [])
  assert.equal(stranger.outcomes[0].state, 'relay:refused')
  if (server) {
    assert.ok(server.authenticated.includes(a.xonlyHex)); assert.ok(server.authenticated.includes(b.xonlyHex))
    assert.equal(server.refusals.length, 1)
    assert.ok(server.urls.every(url => url === NODE_RELAY), 'all socket targets stay on the configured node relay')
    assert.ok(server.requests.every(filter => !filter.kinds.includes(10050)), 'advertised inboxes cannot select another relay')
  }
  return { a, b, A, B, server }
}

test('real Messages route: signed contact, two copies, authenticated recipient, proved sender and stranger refusal', async t => {
  await exchange(t)
})

test('thread reads older pages through the host state folder and retains history for an offline read', async t => {
  const { a, b } = fixture(t), server = relay(); globalThis.WebSocket = server.Socket
  const A = mount(a)
  await addSignedContact(A, b)
  const texts = ['oldest retained message', 'middle retained message', 'newest retained message']
  const now = Math.floor(Date.now() / 1000) - 60
  for (const [index, text] of texts.entries()) {
    const message = composeDirectMessage({ text, senderSecretKey: b.secretKeyHex,
      recipientPubkeys: [a.xonlyHex], now: now + index, random: () => 0 })
    server.events.push(message.wraps.find(copy => copy.recipient === a.xonlyHex).wrap)
  }
  // Reduce only the page size; the production defaults still choose one stateless or 32 persisted pages.
  const modules = await loadMailModules(), original = modules.fetchGiftWraps, reads = []
  modules.fetchGiftWraps = async spec => {
    const result = await original({ ...spec, limit: 2, maxKeptWraps: 3 })
    reads.push(result)
    return result
  }
  t.after(() => { modules.fetchGiftWraps = original })
  const thread = await A(`/aukora-messages/thread?npub=${b.npub}`)
  assert.equal(thread.status, 200)
  assert.deepEqual(thread.body.messages.map(message => message.text), texts, 'older than the first relay page is visible')
  const outcome = reads[0].outcomes[0]
  assert.equal(outcome.complete, true)
  assert.ok(outcome.pages > 1 && outcome.pages <= 32, 'persisted read uses bounded additional pages')
  assert.ok(outcome.replies <= 10000, 'persisted read stays inside its reply budget')
  const scans = join(a.stateDir, 'nostr/scans', a.xonlyHex)
  const cursor = readdirSync(scans).find(name => !name.endsWith('.kept.json'))
  assert.equal(JSON.parse(readFileSync(join(scans, cursor), 'utf8')).scan, null)
  const kept = JSON.parse(readFileSync(join(scans, cursor.replace('.json', '.kept.json')), 'utf8')).kept
  assert.equal(kept.length, 3)
  server.events.length = 0
  globalThis.WebSocket = class extends EventTarget {
    constructor() { super(); queueMicrotask(() => this.dispatchEvent(new Event('error'))) }
    close() {}
  }
  const offline = await A(`/aukora-messages/thread?npub=${b.npub}`)
  assert.equal(offline.status, 200)
  assert.deepEqual(offline.body.messages.map(message => message.text), texts)
  assert.deepEqual(offline.body.answered, [])
})

test('unconfigured, empty or malformed relay configuration refuses before any socket or identity change', async t => {
  const { a, b } = fixture(t), server = relay(); globalThis.WebSocket = server.Socket
  const key = readFileSync(join(a.stateDir, 'nostr/identity.json')), binding = readFileSync(join(a.stateDir, 'nostr/binding.json'))
  for (const [config, override] of [[{}, undefined], [{ nodeRelay: NODE_RELAY }, ''],
    [{ nodeRelay: NODE_RELAY }, 'https://not-a-relay.invalid'], [{ nodeRelay: 'ws://user:pass@localhost:3000' }, undefined],
    [{ nodeRelay: 'ws://' }, undefined], [{ nodeRelay: `${NODE_RELAY}#fragment` }, undefined],
    [{ nodeRelay: NODE_RELAY }, `${NODE_RELAY},https://not-a-relay.invalid`]]) {
    if (override === undefined) delete process.env.AUKORA_NOSTR_RELAYS; else process.env.AUKORA_NOSTR_RELAYS = override
    const call = mount(a, config)
    for (const [url, body] of [['/aukora-messages/send', { npub: b.npub, text: 'must not leave' }],
      [`/aukora-messages/thread?npub=${b.npub}`, undefined]]) {
      const reply = await call(url, body)
      assert.equal(reply.status, 503); assert.equal(reply.body.reason, 'messages:no-relay-configured')
      assert.equal(reply.body.subject, 'no relay configured')
      assert.equal(parseMessagesRefusalBody(reply.body)?.reason, 'messages:no-relay-configured')
    }
    assert.equal((await call('/aukora-messages/identity')).status, 200)
    await new Promise(resolve => setImmediate(resolve))
  }
  assert.deepEqual(server.urls, [])
  assert.ok(readFileSync(join(a.stateDir, 'nostr/identity.json')).equals(key))
  assert.ok(readFileSync(join(a.stateDir, 'nostr/binding.json')).equals(binding))
})

test('explicit relay override is captured at mount; FOREIGN and unauthenticated send have no publication', async t => {
  const { a, b } = fixture(t), server = relay(); globalThis.WebSocket = server.Socket
  process.env.AUKORA_NOSTR_RELAYS = NODE_RELAY
  const A = mount(a, { nodeRelay: 'ws://127.0.0.1:3000' })
  process.env.AUKORA_NOSTR_RELAYS = 'wss://8.8.8.8'
  await addSignedContact(A, b)
  const good = await A('/aukora-messages/send', { npub: b.npub, text: 'configured relay only' })
  assert.equal(good.body.ok, true); assert.ok(server.urls.every(url => url === NODE_RELAY))
  const file = join(a.stateDir, 'nostr/contacts.json'), contacts = JSON.parse(readFileSync(file, 'utf8'))
  contacts.contacts[0].binding.signature = '00'.repeat(64)
  writeFileSync(file, JSON.stringify(contacts), { mode: 0o600 })
  const before = server.events.length
  const foreign = await A('/aukora-messages/send', { npub: b.npub, text: 'foreign must not leave' })
  assert.equal(foreign.status, 409); assert.equal(foreign.body.reason, 'messages:contact-foreign')
  assert.equal(parseMessagesRefusalBody(foreign.body)?.reason, 'messages:contact-foreign')
  const unauthenticated = await A('/aukora-messages/send', { npub: b.npub, text: 'no token' }, false)
  assert.equal(unauthenticated.status, 401)
  assert.equal(server.events.length, before)
})

test('LIVE ws://localhost:3000: disposable identities through real routes',
  { skip: process.env.AUKORA_BUZZ_LIVE !== '1' }, async t => { await exchange(t, true) })

test('mutation guards', { skip: compiled ? 'source mutations do not target the compiled artifact'
  : process.env.AUKORA_MESSAGES_MUTATIONS !== '1' || !!mutant }, () => {
  assert.ok(mutations.length > 0, 'production mutations must be declared')
  for (const mutation of mutations) {
    const env = { ...process.env, AUKORA_MESSAGES_MUTANT: mutation.name, AUKORA_MESSAGES_MUTATIONS: '0', AUKORA_BUZZ_LIVE: '0' }
    delete env.NODE_TEST_CONTEXT
    const result = spawnSync(process.execPath, ['--test', fileURLToPath(import.meta.url)], {
      cwd: ROOT, encoding: 'utf8', env, timeout: 30000,
    })
    assert.equal(result.signal, null, `${mutation.name} terminated`)
    assert.notEqual(result.status, 0, `${mutation.name} survived`)
    assert.match(result.stdout + result.stderr, /AssertionError/u, `${mutation.name} did not reach a behavioral assertion`)
    assert.doesNotMatch(result.stdout + result.stderr, /mutation anchor:|SyntaxError|ERR_MODULE/u,
      `${mutation.name} failed before a behavioral assertion`)
    console.log(`MUTATION CAUGHT ${mutation.name}`)
  }
})
