// Posts only gate-fetched, correctly signed receipts for applied proposals through the channel post controls.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { EventEmitter } from 'node:events'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto'
import { keyFingerprint } from '../packages/boundary-gate/src/ledger.mjs'
import { isValidEvent, randomSecretKey } from '../plugins/aukora-nostr/lib/event.mjs'
import { parseReceiptMessage, verifyChannelReceipt } from '../plugins/aukora-buzz-door/lib/receipt.mjs'
import { apply, createDoor, createDoorTools, gateCall, loadConfig, loadGatePublicKey, POST_RECEIPT_TOOL,
  POST_GAP_MS, GATE_OPS } from '../plugins/aukora-buzz-door/lib/index.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const evidence = new URL('../docs/evidence/l2-demo-2026-10-04/', import.meta.url)
const read = name => fs.readFileSync(new URL(name, evidence), 'utf8')
const receiptBytes = Buffer.from(read('receipt.json').replace(/\n$/u, ''))
const result = { receipt: JSON.parse(receiptBytes), receipt_sig: read('receipt.sig').trim() }
const entries = JSON.parse(read('ledger-entries.json')), gatePem = read('gate-ed25519.pub')
const proposal = result.receipt.proposal, otherProposal = '99999999-2222-4333-8444-555555555555'
const channel = '11111111-2222-4333-8444-555555555555', sessionId = 'buzz-receipt-session'
const caller = { agent: { id: sessionId } }
const applied = () => ({ state: 'applied', ...structuredClone(result), ledger_seq: entries.at(-1).seq })
const logEntry = () => ({ ...entries.at(-1), detail: JSON.parse(entries.at(-1).detail) })
const parse = value => JSON.parse(value)

function fixture({ state = applied(), log = { entries: [logEntry()] }, gatePublicKey = createPublicKey(gatePem), omitKey = false, failPhase } = {}) {
  const events = [], calls = [], sequence = [], key = randomSecretKey()
  let clock = 1791072000000
  const gate = async (socket, op, args) => {
    calls.push({ socket, op, args: structuredClone(args) }); sequence.push(`gate:${op}:${args.phase ?? ''}`)
    if (op === 'state') return structuredClone(state)
    if (op === 'log') return structuredClone(log)
    assert.equal(op, 'relay_record')
    if (args.phase === failPhase) throw new Error('Aura recording unavailable')
    return { ok: true }
  }
  const fetchImpl = async (url, init) => {
    assert.equal(url, 'http://localhost:3000/events')
    const event = JSON.parse(init.body)
    assert(isValidEvent(event))
    events.push(event); sequence.push('relay:post')
    return new Response(JSON.stringify({ accepted: true, event_id: event.id }))
  }
  const door = createDoor({ getKey: () => key, channel, ...(omitKey ? {} : { gatePublicKey }), gateSocket: '/run/aukora-gate/gate.sock', gate, fetchImpl, now: () => clock })
  const tools = createDoorTools(door, { sessionId })
  return { door, tools, calls, events, sequence, advance: () => { clock += POST_GAP_MS },
    post: (args = { proposal_id: proposal }, exec = caller) => tools.postReceipt.execute(args, exec).then(parse) }
}

function isolatedFiles(t) {
  const home = fs.mkdtempSync(path.join(root, '.post-receipt-test-')), dir = path.join(home, 'config')
  fs.mkdirSync(dir, { mode: 0o700 })
  t.after(() => fs.rmSync(home, { recursive: true, force: true }))
  const file = path.join(dir, 'gate.pub'), config = path.join(dir, 'door.json')
  fs.writeFileSync(file, gatePem, { mode: 0o600 })
  fs.writeFileSync(config, JSON.stringify({ channel, sessionId, gatePublicKeyFile: file }), { mode: 0o600 })
  return { home, dir, file, config, options: { home, deniedRoots: [] } }
}

function refused(value, reason) {
  assert.deepEqual(value, { ok: false, state: 'REFUSED', reason })
}

test('buzz_post_receipt publishes the real gate receipt and the stranger checker accepts its posted event', async t => {
  const f = fixture(), reply = await f.post()
  assert.equal(POST_RECEIPT_TOOL, 'buzz_post_receipt')
  assert.equal(f.tools.postReceipt.name, POST_RECEIPT_TOOL)
  assert.equal(f.tools.postReceipt.isConcurrencySafe(), false)
  assert.equal(reply.state, 'POSTED'); assert.equal(reply.ok, true)
  assert.deepEqual(f.calls.map(c => [c.op, c.args.phase]), [['state', undefined], ['relay_record', 'intent'], ['relay_record', 'posted']])
  assert.deepEqual(f.calls[0].args, { id: proposal })
  assert(f.calls.every(c => c.socket === '/run/aukora-gate/gate.sock'))
  assert.deepEqual(f.sequence, ['gate:state:', 'gate:relay_record:intent', 'relay:post', 'gate:relay_record:posted'])
  const [event] = f.events, parsed = parseReceiptMessage(event)
  assert.deepEqual(parsed.receiptBytes, receiptBytes)
  assert.equal(parsed.receipt_sig, result.receipt_sig)
  assert.equal(reply.id, event.id)
  assert.equal(f.calls[1].args.body_sha256, createHash('sha256').update(event.content).digest('hex'))
  assert.equal(f.calls[1].args.bytes, Buffer.byteLength(event.content))
  assert.equal(f.calls[2].args.message_id, event.id)
  // The anchor is derived from the historical fixture, not fetched independently from the running gate.
  const anchor = { seq: entries.at(-1).seq, head: entries.at(-1).hash, gate_fp: keyFingerprint(createPublicKey(gatePem)) }
  const pins = { channel, doorPubkey: f.door.pubkey(), gatePublicKey: gatePem, entries, anchors: [anchor] }
  const expected = { valid: true, reason: 'valid against the supplied anchor', proposal, ledger_seq: 24, anchored_seq: 24 }
  assert.deepEqual(verifyChannelReceipt(event, pins), expected)
  const files = isolatedFiles(t), eventFile = path.join(files.home, 'event.json'), anchorFile = path.join(files.home, 'anchors.jsonl')
  fs.writeFileSync(eventFile, JSON.stringify(event)); fs.writeFileSync(anchorFile, JSON.stringify(anchor) + '\n')
  const out = spawnSync(process.execPath, ['plugins/aukora-buzz-door/bin/verify-channel-receipt.mjs', eventFile,
    '--gate-key', files.file, '--ledger', fileURLToPath(new URL('ledger-entries.json', evidence)), '--anchor', anchorFile,
    '--door-key', f.door.pubkey(), '--channel', channel], { cwd: root, encoding: 'utf8' })
  assert.equal(out.status, 0, out.stderr); assert.deepEqual(JSON.parse(out.stdout), expected)
})

test('a legacy state result falls back to the matching apply entry with parsed detail', async () => {
  const good = logEntry(), wrong = { ...good, proposal: otherProposal }
  const f = fixture({ state: { state: 'applied', ledger_seq: 24 }, log: { entries: [wrong, { ...good, event: 'decide' }, good] } })
  assert.equal((await f.post()).state, 'POSTED')
  assert.deepEqual(f.calls.slice(0, 2).map(c => [c.op, c.args]), [['state', { id: proposal }], ['log', { limit: 200 }]])
  assert.deepEqual(parseReceiptMessage(f.events[0]).receiptBytes, receiptBytes)
})

test('pending and applying proposals cannot post even when a lying gate includes a valid receipt', async () => {
  for (const state of ['pending', 'applying']) {
    const f = fixture({ state: { ...applied(), state } })
    refused(await f.post(), 'buzz-receipt:undecided')
    assert.deepEqual(f.calls.map(c => c.op), ['state']); assert.equal(f.events.length, 0)
  }
})

test('rejected, missing and other unapplied proposals have no publishable receipt', async () => {
  for (const state of ['refused', 'rejected', 'unknown', 'cancelled', 'expired', 'incomplete', 'conflict']) {
    const f = fixture({ state: { state } })
    refused(await f.post(), 'buzz-receipt:unavailable')
    assert.deepEqual(f.calls.map(c => c.op), ['state']); assert.equal(f.events.length, 0)
  }
})

test('an applied proposal without a matching receipt refuses unrelated or malformed log entries', async () => {
  const good = logEntry()
  for (const log of [{ entries: [] }, {}, { entries: [{ ...good, proposal: otherProposal }] },
    { entries: [{ ...good, event: 'decide' }] }, { entries: [{ ...good, detail: '{}' }] }, { entries: [{ ...good, detail: null }] }]) {
    const f = fixture({ state: { state: 'applied' }, log })
    refused(await f.post(), 'buzz-receipt:unavailable')
    assert.equal(f.events.length, 0); assert.equal(f.calls.length, 2)
  }
  for (const state of [{ state: 'applied', receipt: result.receipt }, { state: 'applied', receipt_sig: result.receipt_sig }]) {
    const f = fixture({ state })
    refused(await f.post(), 'buzz-receipt:unavailable')
    assert.deepEqual(f.calls.map(c => c.op), ['state']); assert.equal(f.events.length, 0)
  }
})

test('a lying gate cannot replace receipt bytes, their order, signature or the configured signer', async () => {
  const tampered = applied(); tampered.receipt.target += '.forged'
  const reordered = applied(); reordered.receipt = Object.fromEntries(Object.entries(reordered.receipt).reverse())
  for (const options of [{ state: tampered }, { state: reordered },
    { state: { ...applied(), receipt_sig: Buffer.alloc(64).toString('base64') } },
    { gatePublicKey: generateKeyPairSync('ed25519').publicKey },
    { state: { state: 'applied' }, log: { entries: [{ ...logEntry(), detail: tampered }] } }]) {
    const f = fixture(options)
    refused(await f.post(), 'buzz-receipt:receipt-signature')
    assert.equal(f.events.length, 0); assert(f.calls.every(c => c.op !== 'relay_record'))
  }
})

test('a correctly signed receipt must identify the requested proposal', async () => {
  for (const options of [{}, { state: { state: 'applied' }, log: { entries: [{ ...logEntry(), proposal: otherProposal }] } }]) {
    const f = fixture(options)
    refused(await f.post({ proposal_id: otherProposal }), 'buzz-receipt:proposal')
    assert.equal(f.events.length, 0); assert(f.calls.every(c => c.op !== 'relay_record'))
  }
})

test('only the configured Buzz caller can fetch and post receipts', async () => {
  const f = fixture()
  for (const exec of [undefined, {}, { agent: { id: 'another-session' } }, { sessionId }]) {
    refused(parse(await f.tools.postReceipt.execute({ proposal_id: proposal }, exec)), 'buzz-receipt:session')
  }
  refused(parse(await createDoorTools(f.door).postReceipt.execute({ proposal_id: proposal }, caller)), 'buzz-receipt:session')
  assert.equal(f.calls.length, 0); assert.equal(f.events.length, 0)
})

test('the model supplies only a canonical proposal id, never receipt bytes or a destination', async () => {
  const f = fixture(), schema = f.tools.postReceipt.parameters
  assert.deepEqual(Object.keys(schema.properties), ['proposal_id'])
  assert.deepEqual(schema.required, ['proposal_id']); assert.equal(schema.additionalProperties, false)
  for (const proposal_id of [undefined, null, 3, '', 'bad', proposal.toUpperCase(), proposal + '\n', ' ' + proposal]) {
    refused(await f.post({ proposal_id }), 'buzz-receipt:proposal-id')
  }
  for (const extra of [{ receipt: result.receipt }, { receipt_sig: result.receipt_sig }, { text: 'forged' }, { channel }, { gatePublicKeyFile: '/tmp/key' }]) {
    const reply = await f.post({ proposal_id: proposal, ...extra })
    assert.equal(reply.state, 'REFUSED'); assert.match(reply.reason, /unknown argument/u)
  }
  assert.equal(f.calls.length, 0); assert.equal(f.events.length, 0)
})

test('without a configured gate public key the receipt tool is absent', () => {
  const f = fixture({ omitKey: true })
  assert.equal(typeof f.door.postReceipt, 'undefined')
  assert.equal(f.tools.postReceipt, undefined)
  assert.deepEqual(Object.keys(f.tools), ['read', 'post'])
})

test('the configured gate key must be public Ed25519 and may be supplied as PEM', async () => {
  assert.equal((await fixture({ gatePublicKey: gatePem }).post()).state, 'POSTED')
  for (const gatePublicKey of [null, 'not a key', generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey]) {
    assert.throws(() => fixture({ gatePublicKey }), /buzz-receipt:gate-key/u)
  }
})

test('apply registers receipt posting only with the configured isolated gate public key', t => {
  const f = isolatedFiles(t), keyFile = path.join(f.dir, 'key'), platform = Object.getOwnPropertyDescriptor(process, 'platform')
  fs.writeFileSync(keyFile, randomSecretKey(), { mode: 0o600 })
  Object.defineProperty(process, 'platform', { value: 'linux' })
  t.after(() => Object.defineProperty(process, 'platform', platform))
  t.mock.method(os, 'homedir', () => f.home)
  t.mock.method(console, 'info', () => {})
  t.mock.method(console, 'warn', () => {})
  for (const [gatePublicKeyFile, expected] of [[undefined, ['buzz_read', 'buzz_post']],
    [f.file, ['buzz_read', 'buzz_post', 'buzz_post_receipt']], [path.join(f.dir, 'missing'), []]]) {
    fs.writeFileSync(f.config, JSON.stringify({ channel, sessionId, gatePublicKeyFile }))
    const registered = []
    apply({ tools: { register: tool => registered.push(tool.name) }, agents: {}, effect() {} }, { keyFile, configFile: f.config })
    assert.deepEqual(registered, expected)
  }
})

test('receipt and text posts consume the same rate allowance in either order', async () => {
  for (const receiptFirst of [true, false]) {
    const f = fixture(), text = () => f.tools.post.execute({ text: 'ordinary channel post' }, caller).then(parse)
    assert.equal((await (receiptFirst ? f.post() : text())).state, 'POSTED')
    const limited = await (receiptFirst ? text() : f.post())
    assert.equal(limited.state, 'REFUSED'); assert.match(limited.reason, /rate limit/u)
    assert.equal(f.events.length, 1)
    f.advance(); assert.equal((await (receiptFirst ? text() : f.post())).state, 'POSTED')
  }
})

test('receipt posts require Aura intent and retain completion-failure reporting', async () => {
  const denied = fixture({ failPhase: 'intent' }), refusedPost = await denied.post()
  assert.equal(refusedPost.state, 'REFUSED'); assert.match(refusedPost.reason, /Aura recording unavailable/u)
  assert.equal(denied.events.length, 0)
  const incomplete = fixture({ failPhase: 'posted' }), reply = await incomplete.post()
  assert.equal(reply.state, 'POSTED_UNRECORDED'); assert.equal(incomplete.events.length, 1)
  assert.equal(incomplete.calls.filter(c => c.args.phase === 'posted').length, 3)
})

test('door config loads the optional public key from the same isolated file policy as its signing key', t => {
  const f = isolatedFiles(t), config = loadConfig(f.config, f.options)
  assert.equal(config.gatePublicKeyFile, f.file)
  const key = loadGatePublicKey(config.gatePublicKeyFile, f.options)
  assert.equal(key.asymmetricKeyType, 'ed25519')
  assert.equal(keyFingerprint(key), keyFingerprint(createPublicKey(gatePem)))
  for (const mode of [0o640, 0o604, 0o620, 0o602]) {
    fs.chmodSync(f.file, mode)
    assert.throws(() => loadGatePublicKey(f.file, f.options), /private to the harness/u)
  }
  fs.chmodSync(f.file, 0o600)
  assert.throws(() => loadGatePublicKey(f.file, { ...f.options, extraDenied: [f.home] }), /workspace/u)
  assert.throws(() => loadGatePublicKey(f.file, { ...f.options, deniedRoots: [f.home] }), /guest/u)
  assert.throws(() => loadGatePublicKey(f.file, { ...f.options, home: f.dir + '-other' }), /beneath HOME/u)
  assert.throws(() => loadGatePublicKey(f.file, { ...f.options, uid: process.getuid() + 1 }), /owned/u)
  const link = path.join(f.dir, 'link'); fs.symlinkSync(f.file, link)
  assert.throws(() => loadGatePublicKey(link, f.options), /regular file/u)
  for (const parent of [f.dir, f.home]) {
    fs.chmodSync(parent, 0o720)
    assert.throws(() => loadGatePublicKey(f.file, f.options), /parents/u)
    fs.chmodSync(parent, 0o700)
  }
})

test('gate key loader refuses malformed, non-Ed25519, oversized and non-file inputs', t => {
  const f = isolatedFiles(t)
  for (const text of ['not a public key', generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'pem' })]) {
    fs.writeFileSync(f.file, text)
    assert.throws(() => loadGatePublicKey(f.file, f.options), /buzz-receipt:gate-key/u)
  }
  fs.writeFileSync(f.file, 'x'.repeat(1025))
  assert.throws(() => loadGatePublicKey(f.file, f.options), /too large/u)
  assert.throws(() => loadGatePublicKey(f.dir, f.options), /regular file/u)
  for (const gatePublicKeyFile of [null, 3, '', 'gate.pub', f.dir + '/./gate.pub']) {
    fs.writeFileSync(f.config, JSON.stringify({ channel, gatePublicKeyFile }))
    assert.throws(() => loadConfig(f.config, f.options), /buzz-receipt:gate-key/u)
  }
})

test('the gate allow-list permits only recording and receipt reads, with the propose socket request and result framing', async t => {
  assert.deepEqual([...GATE_OPS].sort(), ['aura_note', 'log', 'relay_record', 'state'])
  const requests = []
  t.mock.method(net, 'createConnection', socket => {
    assert.equal(socket, '/gate.sock')
    const connection = new EventEmitter()
    connection.destroy = () => {}
    connection.write = wire => {
      assert(wire.endsWith('\n')); requests.push(JSON.parse(wire))
      queueMicrotask(() => { connection.emit('data', JSON.stringify({ ok: true, result: { state: 'applied' } })); connection.emit('end') })
    }
    queueMicrotask(() => connection.emit('connect'))
    return connection
  })
  for (const [op, args] of [['state', { id: proposal }], ['log', { limit: 200 }]]) {
    assert.deepEqual(await gateCall('/gate.sock', op, args), { state: 'applied' })
    assert.deepEqual(requests.at(-1), { op, args })
  }
  for (const op of ['approve', 'decide_review', 'close', 'ping']) await assert.rejects(gateCall('/gate.sock', op, {}), /not allowed/u)
  assert.equal(requests.length, 2)
})
