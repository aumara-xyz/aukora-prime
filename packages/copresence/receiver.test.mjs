// Checks verified, fresh, role-bound, single-use evidence and digest-only storage.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import childProcess, { spawn } from 'node:child_process'
import fs, { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { publicKeyOf, signEvent } from '../../plugins/aukora-nostr/lib/event.mjs'
import { RECEIVER_REFUSE as R, receiveReceipt, verifyDeviceBinding, createMemoryStore, createFileStore } from './receiver.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const temporary = mkdtempSync(path.join(here, '.receiver-test-'))
const scratchDir = path.join(temporary, 'scratch')
mkdirSync(scratchDir)
after(() => rmSync(temporary, { recursive: true, force: true }))
const fixture = name => JSON.parse(readFileSync(path.join(here, 'fixtures', name), 'utf8'))
const vector = name => JSON.parse(readFileSync(path.join(here, 'vectors', name), 'utf8'))
const good = fixture('good.json')
const auraAck = { ok: true, seq: 1, hash: 'cd'.repeat(32) }
const text = readFileSync(path.join(here, 'fixtures', 'TEXT.txt'), 'utf8').replace(/\n$/u, '')
const options = (receipt = good, extra = {}) => ({ now: receipt.t_B, store: createMemoryStore(), scratchDir, ...extra })
const receive = (receipt = good, extra = {}) => receiveReceipt(receipt, options(receipt, extra))
const refusal = (promise, code) => assert.rejects(promise, error => error.code === code)
const hash = (label, ...parts) => createHash('sha256').update(Buffer.concat([Buffer.from(label), Buffer.from([0]), ...parts])).digest()
const hex = value => Buffer.from(value, 'hex')
const coreOf = receipt => {
  const time = Buffer.alloc(8)
  time.writeBigUInt64BE(BigInt(receipt.t_B))
  return hash('copresence.v0', hex(receipt.pk_A), hex(receipt.pk_B), hex(receipt.nonce_A), hex(receipt.nonce_B), time).toString('hex')
}

// Synthetic signers exercise both asking sides with the published P1363 encodings.
function ceremony(intentText, side = 'A') {
  const pairs = Object.fromEntries(['A', 'B'].map(key => [key, generateKeyPairSync('ec', { namedCurve: 'prime256v1' })]))
  const other = side === 'A' ? 'B' : 'A'
  const receipt = { v: 0, nonce_A: '11'.repeat(8), nonce_B: '22'.repeat(8), t_A: 1791800000, t_B: 1791800002 }
  for (const key of ['A', 'B']) receipt[`pk_${key}`] = pairs[key].publicKey.export({ format: 'der', type: 'spki' }).subarray(-65).toString('hex')
  const digest = hash('copresence.intent.v1', Buffer.from(intentText))
  const salt = Buffer.alloc(16, 0x5a)
  receipt[`nonce_${side}`] = hash('copresence.intent-nonce.v1', digest, salt).subarray(0, 8).toString('hex')
  const signing = (key, message) => sign('sha256', message, { key: pairs[key].privateKey, dsaEncoding: 'ieee-p1363' }).toString('hex')
  const core = coreOf(receipt)
  for (const key of ['A', 'B']) receipt[`sig_${key}`] = signing(key, hex(core))
  receipt.intent = {
    text: intentText, digest: digest.toString('hex'), salt: salt.toString('hex'), side,
    ack: { by: other, sig: signing(other, hash('copresence.intent-ack.v1', digest, hex(receipt[`pk_${side}`]), hex(receipt[`nonce_${other}`]))) },
  }
  return receipt
}

test('good fixture returns exact evidence, recomputes the core, and grants nothing', async () => {
  const receipt = { ...good, core: '00'.repeat(32) }
  assert.equal(coreOf(receipt), good.core)
  assert.deepEqual(await receive(receipt), { core: good.core, keys: { A: good.pk_A, B: good.pk_B }, t_B: good.t_B })
  assert.deepEqual(await receive(receipt, { expectedText: text, expectedAsker: good.pk_B, expectedApprover: good.pk_A }), {
    core: good.core, keys: { A: good.pk_A, B: good.pk_B, asker: good.pk_B, approver: good.pk_A },
    t_B: good.t_B, textDigest: good.intent.digest,
  })
})

test('child process errors, unsuccessful exits, signals, and unexpected output refuse without consuming', async () => {
  const original = childProcess.spawnSync
  let consumed = 0
  const store = { consume() { consumed++; return true } }
  try {
    for (const result of [
      { status: 1, stdout: 'valid' },
      { status: 0, signal: 'SIGTERM', stdout: 'valid' },
      { status: 0, error: new Error('synthetic launch failure'), stdout: 'valid' },
      { status: 0, stdout: 'unexpected success output' },
    ]) {
      let calls = 0
      childProcess.spawnSync = () => { calls++; return result }
      syncBuiltinESMExports()
      await refusal(receive(good, { store }), R.VERIFIER)
      assert.equal(calls, 1)
      assert.equal(consumed, 0)
      assert.deepEqual(readdirSync(scratchDir), [])
    }
  } finally {
    childProcess.spawnSync = original
    syncBuiltinESMExports()
  }
})

test('intent output must match independently computed evidence before consuming', async () => {
  const original = childProcess.spawnSync
  const verified = { valid: true, core: good.core, t_B: good.t_B, asker_key: good.pk_B, approver_key: good.pk_A, text_digest: good.intent.digest }
  let consumed = 0
  const store = { consume() { consumed++; return true } }
  try {
    for (const changed of [
      { valid: false }, { core: '00'.repeat(32) }, { t_B: good.t_B + 1 },
      { asker_key: good.pk_A }, { approver_key: good.pk_B }, { text_digest: '00'.repeat(32) },
    ]) {
      let calls = 0
      childProcess.spawnSync = () => ({ status: 0, stdout: ++calls === 1 ? 'valid' : JSON.stringify({ ...verified, ...changed }) })
      syncBuiltinESMExports()
      await refusal(receive(good, { expectedText: text, store }), R.VERIFIER)
      assert.equal(calls, 2)
      assert.equal(consumed, 0)
      assert.deepEqual(readdirSync(scratchDir), [])
    }
  } finally {
    childProcess.spawnSync = original
    syncBuiltinESMExports()
  }
})

for (const name of ['fail-wrong-text.json', 'fail-missing-ack.json', 'fail-bad-ack-signature.json']) {
  test(`frozen intent verifier refuses ${name} before consuming`, async () => {
    let calls = 0
    await refusal(receive(fixture(name), { expectedText: text, store: { consume() { calls++; return true } } }), R.VERIFIER)
    assert.equal(calls, 0)
    assert.deepEqual(readdirSync(scratchDir), [])
  })
}

for (const name of ['sig_b_tampered.json', 'sig_a_garbage.json', 'pk_b_swapped.json', 'window_11s.json', 'audio_nonce_mismatch.json', 'audio_relay_delayed.json']) {
  test(`frozen base verifier refuses ${name}`, async () => {
    let calls = 0
    await refusal(receive(vector(name), { store: { consume() { calls++; return true } } }), R.VERIFIER)
    assert.equal(calls, 0)
  })
}

for (const name of ['genuine.json', 'audio_genuine.json', 'spacetime_genuine.json', 'spacetime_contradiction.json', 'spacetime_spoofed_acc0.json']) {
  test(`accepts signed core and ignores location claims in ${name}`, async () => {
    const receipt = vector(name)
    assert.equal((await receive(receipt)).core, coreOf(receipt))
  })
}

test('freshness uses the supplied clock, default 300 seconds, and five-second future slack', async () => {
  await receive(good, { now: good.t_B + 300 })
  await receive(good, { now: good.t_B - 5 })
  await refusal(receive(good, { now: good.t_B + 300.001 }), R.STALE)
  await refusal(receive(good, { now: good.t_B - 5.001 }), R.FUTURE)
  await receive(good, { now: good.t_B, maxAge: 0 })
  await refusal(receive(good, { now: good.t_B + 0.001, maxAge: 0 }), R.STALE)
  await receive(good, { now: good.t_B + 600, maxAge: 600 })
  const store = createMemoryStore()
  await refusal(receive(good, { store, now: good.t_B + 301 }), R.STALE)
  await refusal(receive(good, { store, now: good.t_B - 6 }), R.FUTURE)
  await receive(good, { store })
})

test('malformed receipt encodings and caller clock refuse without consuming', async () => {
  let calls = 0
  const store = { consume() { calls++; return true } }
  const mutations = [
    null, [], {}, { ...good, v: 1 }, { ...good, pk_A: good.pk_A.slice(2) }, { ...good, pk_B: 'ff'.repeat(65) },
    { ...good, nonce_A: 'z'.repeat(16) }, { ...good, nonce_B: '11' },
    { ...good, sig_A: 'z'.repeat(128) }, { ...good, sig_B: '11' }, { ...good, t_A: good.t_B - 0.5 },
    ...[-1, NaN, Infinity, 0.1, Number.MAX_SAFE_INTEGER + 1].flatMap(value => [{ ...good, t_A: value }, { ...good, t_B: value }]),
  ]
  for (const receipt of mutations) await refusal(receiveReceipt(receipt, options(good, { store })), R.MALFORMED)
  for (const value of [undefined, -1, NaN, Infinity, '1791800000']) await refusal(receive(good, { store, now: value }), R.MALFORMED)
  for (const value of [-1, NaN, Infinity, '300']) await refusal(receive(good, { store, maxAge: value }), R.MALFORMED)
  await refusal(receive(good, { store, expectedText: 1 }), R.MALFORMED)
  for (const field of ['expectedAsker', 'expectedApprover']) await refusal(receive(good, { store, expectedText: text, [field]: 'bad' }), R.MALFORMED)
  await refusal(receiveReceipt(good, null), R.MALFORMED)
  await refusal(verifyDeviceBinding(good, null), R.MALFORMED)
  assert.equal(calls, 0)
})

test('expected roles require verified text and cannot be swapped', async () => {
  const store = createMemoryStore()
  await refusal(receive(good, { store, expectedAsker: good.pk_B }), R.ROLES_REQUIRE_TEXT)
  await refusal(receive(good, { store, expectedApprover: good.pk_A }), R.ROLES_REQUIRE_TEXT)
  await refusal(receive(good, { store, expectedText: text, expectedAsker: good.pk_A }), R.WRONG_ASKER)
  await refusal(receive(good, { store, expectedText: text, expectedApprover: good.pk_B }), R.WRONG_APPROVER)
  await refusal(receive(good, { store, expectedText: `${text} ` }), R.VERIFIER)
  await receive(good, { store, expectedText: text, expectedAsker: good.pk_B.toUpperCase(), expectedApprover: good.pk_A.toUpperCase() })
})

for (const side of ['A', 'B']) {
  test(`verified intent side ${side} determines roles, independently of ack.by`, async () => {
    const receipt = ceremony('synthetic role text', side)
    const other = side === 'A' ? 'B' : 'A'
    receipt.intent.ack.by = side
    const evidence = await receive(receipt, { expectedText: receipt.intent.text, expectedAsker: receipt[`pk_${side}`], expectedApprover: receipt[`pk_${other}`] })
    assert.equal(evidence.keys.asker, receipt[`pk_${side}`])
    assert.equal(evidence.keys.approver, receipt[`pk_${other}`])
  })
}

test('intent nonce and acknowledgment cannot be transplanted into another signed ceremony', async () => {
  const receipt = ceremony('approved text')
  const other = ceremony('other text')
  await refusal(receive({ ...receipt, intent: other.intent }, { expectedText: 'other text' }), R.VERIFIER)
  await refusal(receive({ ...receipt, intent: { ...receipt.intent, ack: other.intent.ack } }, { expectedText: 'approved text' }), R.VERIFIER)
})

test('store sees exactly one digest argument, never receipt or self-reported location', async () => {
  const receipt = structuredClone(good)
  const forbidden = () => { throw new Error('private metadata was read') }
  receipt.toJSON = forbidden
  receipt.intent.toJSON = forbidden
  receipt.intent.ack.toJSON = forbidden
  for (const object of [receipt, receipt.intent, receipt.intent.ack]) {
    for (const field of ['geo_A', 'geo_B', 'location', 'position_source', 'sentinel_verdict']) Object.defineProperty(object, field, { enumerable: true, get: forbidden })
  }
  receipt.audio = { nonce: '11'.repeat(16), delay_ms: 25, matched: true, toJSON: forbidden }
  Object.defineProperty(receipt.audio, 'location', { enumerable: true, get: forbidden })
  Object.defineProperty(receipt.intent.ack, 'by', { enumerable: true, get: forbidden })
  const calls = [], notes = []
  const result = await receive(receipt, { expectedText: text, store: { consume(...args) { calls.push(args); return true } },
    gateSocket: '/fixture-gate.sock', gate: async (...args) => { notes.push(args); return auraAck } })
  assert.deepEqual(calls, [[good.core]])
  assert.deepEqual(notes, [['/fixture-gate.sock', 'aura_note', { kind: 'copresence-accepted', digest_sha256: good.core }]])
  assert.deepEqual(Object.keys(result).sort(), ['core', 'keys', 't_B', 'textDigest'])
  assert.deepEqual(readdirSync(scratchDir), [])
})

test('Aura receives only the verified consumed core; invalid, stale and replayed receipts add no notes', async () => {
  const store = createMemoryStore(), notes = []
  let consumed = false
  const extra = { gateSocket: '/fixture-gate.sock',
    store: { async consume(core) { const result = store.consume(core); await Promise.resolve(); consumed = result; return result } },
    gate: async (...args) => { assert.equal(consumed, true); notes.push(args); return auraAck } }
  await refusal(receive(vector('sig_b_tampered.json'), extra), R.VERIFIER)
  await refusal(receive(good, { ...extra, now: good.t_B + 301 }), R.STALE)
  await refusal(receive(good, { ...extra, store: { consume: () => false } }), R.REPLAY)
  await refusal(receive(good, { ...extra, store: { consume: () => undefined } }), R.STORE)
  assert.deepEqual(notes, [])
  assert.equal((await receive({ ...good, core: '00'.repeat(32) }, extra)).core, good.core)
  assert.deepEqual(notes, [['/fixture-gate.sock', 'aura_note', { kind: 'copresence-accepted', digest_sha256: good.core }]])
  await refusal(receive(good, extra), R.REPLAY)
  assert.equal(notes.length, 1)
  await receive(good, { gate: async () => assert.fail('unconfigured gate called') })
})

test('Aura failures refuse returned evidence and keep the consumed receipt spent', async () => {
  const bad = [undefined, {}, { ...auraAck, ok: false }, { ...auraAck, ok: 1 },
    ...[0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '1'].map(seq => ({ ...auraAck, seq })),
    ...[undefined, 'aa', 'AB'.repeat(32), 'z'.repeat(64), auraAck.hash + '\n', 1].map(hash => ({ ...auraAck, hash })),
    new Error('private gate error')]
  for (const ack of bad) {
    let calls = 0
    const extra = { store: createMemoryStore(), gateSocket: '/fixture-gate.sock',
      gate: async () => { calls++; if (ack instanceof Error) throw ack; return ack } }
    await refusal(receive(good, extra), R.AURA)
    await refusal(receive(good, extra), R.REPLAY)
    assert.equal(calls, 1)
  }
})

test('Aura configured socket must be an absolute path before consumption', async () => {
  for (const gateSocket of [null, '', 'relative', 1, {}, '/bad\0socket']) {
    await refusal(receive(good, { gateSocket, store: { consume: () => assert.fail('invalid socket consumed receipt') },
      gate: async () => assert.fail('invalid socket reached gate') }), R.AURA)
  }
})

test('receipt core is consumed only once, including simultaneous memory attempts', async () => {
  const store = createMemoryStore()
  const attempts = await Promise.allSettled(Array.from({ length: 6 }, () => receive(good, { store })))
  assert.equal(attempts.filter(result => result.status === 'fulfilled').length, 1)
  for (const result of attempts.filter(result => result.status === 'rejected')) assert.equal(result.reason.code, R.REPLAY)
  await refusal(receive({ ...good, core: 'ab'.repeat(32) }, { store }), R.REPLAY)
})

test('missing, failed and ambiguous stores fail closed; false is replay', async () => {
  for (const store of [undefined, {}, { consume() { throw new Error('disk unavailable') } }, { async consume() { throw new Error('disk unavailable') } }, { consume() { return 1 } }, { consume() {} }]) {
    await refusal(receive(good, { store }), R.STORE)
  }
  await refusal(receive(good, { store: { consume() { return false } } }), R.REPLAY)
  assert.deepEqual(readdirSync(scratchDir), [])
})

test('memory and file stores reject noncanonical or path-like digest keys', async () => {
  const directory = path.join(temporary, 'canonical-store')
  mkdirSync(directory)
  for (const store of [createMemoryStore(), createFileStore(directory)]) {
    for (const invalid of ['', '../escape', 'AB'.repeat(32), '00'.repeat(31), 'gg'.repeat(32), null, {}, { core: good.core }]) {
      await assert.rejects(async () => store.consume(invalid))
    }
    assert.equal(await store.consume(good.core), true)
    assert.equal(await store.consume(good.core), false)
  }
  assert.deepEqual(readdirSync(directory), [good.core])
  assert.equal(statSync(path.join(directory, good.core)).size, 0)
})

function childConsume(directory, core) {
  const source = `import { createFileStore } from ${JSON.stringify(new URL('./receiver.mjs', import.meta.url).href)}; console.log(await createFileStore(process.argv[1]).consume(process.argv[2]))`
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '--eval', source, directory, core], { encoding: 'utf8' })
    let stdout = '', stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', reject)
    child.on('close', code => code === 0 ? resolve(stdout.trim()) : reject(new Error(`store child exit ${code}: ${stderr}`)))
  })
}

test('file consumption is atomic across processes, survives restart, and stores digests only', async () => {
  const directory = path.join(temporary, 'durable-store')
  mkdirSync(directory)
  const results = await Promise.all(Array.from({ length: 8 }, () => childConsume(directory, good.core)))
  assert.equal(results.filter(result => result === 'true').length, 1)
  assert.equal(results.filter(result => result === 'false').length, 7)
  assert.equal(await childConsume(directory, good.core), 'false')
  await refusal(receive(good, { store: createFileStore(directory) }), R.REPLAY)
  assert.deepEqual(readdirSync(directory), [good.core])
  assert.equal(readFileSync(path.join(directory, good.core), 'utf8'), '')
})

test('file storage errors refuse evidence without pretending a consume succeeded', async () => {
  const directory = path.join(temporary, 'removed-store')
  mkdirSync(directory)
  const store = createFileStore(directory)
  rmSync(directory, { recursive: true })
  await refusal(receive(good, { store }), R.STORE)
  assert.deepEqual(readdirSync(scratchDir), [])
})

for (const target of ['marker', 'directory']) {
  test(`a failed ${target} fsync refuses evidence and leaves the digest spent`, async () => {
    const directory = path.join(temporary, `fsync-${target}`)
    mkdirSync(directory)
    const store = createFileStore(directory)
    const original = fs.fsyncSync
    let failures = 0
    fs.fsyncSync = fd => {
      if (fs.fstatSync(fd).isDirectory() === (target === 'directory')) {
        failures++
        throw new Error('synthetic sync failure')
      }
      return original(fd)
    }
    syncBuiltinESMExports()
    try {
      await refusal(receive(good, { store }), R.STORE)
      assert.equal(failures, 1)
    } finally {
      fs.fsyncSync = original
      syncBuiltinESMExports()
    }
    assert.deepEqual(readdirSync(directory), [good.core])
    assert.equal(await createFileStore(directory).consume(good.core), false)
  })
}

const memberSecret = '31'.repeat(32)
const memberPubkey = publicKeyOf(memberSecret)
const bindingText = `aukora-device:v1:${memberPubkey}`
function bindingStatement(receipt, overrides = {}, secret = memberSecret) {
  return signEvent({ pubkey: publicKeyOf(secret), created_at: receipt.t_B + 1, kind: 1, tags: [], content: `${bindingText}:${coreOf(receipt)}`, ...overrides }, secret)
}
const bindingOptions = (receipt, extra = {}) => options(receipt, {
  memberPubkey, deviceKey: receipt[`pk_${receipt.intent.side === 'A' ? 'B' : 'A'}`], event: bindingStatement(receipt), ...extra,
})

for (const side of ['A', 'B']) {
  test(`self-ceremony verifies member signature and device approver with asker ${side}`, async () => {
    const receipt = ceremony(bindingText, side)
    const opts = bindingOptions(receipt, { memberPubkey: memberPubkey.toUpperCase(), expectedAsker: receipt[`pk_${side}`] })
    const evidence = await verifyDeviceBinding(receipt, opts)
    assert.equal(evidence.core, coreOf(receipt))
    assert.equal(evidence.keys.approver, opts.deviceKey)
    assert.equal(evidence.textDigest, receipt.intent.digest)
    await refusal(verifyDeviceBinding(receipt, opts), R.REPLAY)
  })
}

test('binding refuses wrong text, member, device, core, signature, kind, tags, and malformed fields before consuming', async () => {
  const receipt = ceremony(bindingText)
  let calls = 0
  const store = { consume() { calls++; return true } }
  const base = bindingOptions(receipt, { store })
  const wrongText = ceremony(`${bindingText} `)
  await refusal(verifyDeviceBinding(wrongText, bindingOptions(wrongText, { store })), R.VERIFIER)
  await refusal(verifyDeviceBinding(receipt, { ...base, deviceKey: receipt.pk_A }), R.WRONG_APPROVER)
  await refusal(verifyDeviceBinding(receipt, { ...base, expectedAsker: receipt.pk_B }), R.WRONG_ASKER)
  for (const extra of [
    { memberPubkey: 'bad' }, { deviceKey: undefined }, { event: undefined },
    { expectedApprover: 1 }, { expectedApprover: receipt.pk_A }, { expectedText: 'wrong override' },
    { event: bindingStatement(receipt, {}, '32'.repeat(32)) },
    { event: bindingStatement(receipt, { content: `${bindingText}:${'00'.repeat(32)}` }) },
    { event: bindingStatement(receipt, { content: `aukora-device:v1:${'00'.repeat(32)}:${coreOf(receipt)}` }) },
    { event: { ...base.event, sig: '00'.repeat(64) } },
    { event: { ...base.event, id: '00'.repeat(32) } },
    { event: bindingStatement(receipt, { kind: 2 }) },
    { event: bindingStatement(receipt, { tags: [['location', 'synthetic']] }) },
    { event: { ...base.event, created_at: -1 } },
  ]) await refusal(verifyDeviceBinding(receipt, { ...base, ...extra }), R.BINDING)
  assert.equal(calls, 0)
  await verifyDeviceBinding({ ...receipt, core: 'ff'.repeat(32) }, base)
  assert.equal(calls, 1)
})

test('Aura device binding records only after the member signature verifies', async () => {
  const receipt = ceremony(bindingText), calls = []
  const opts = bindingOptions(receipt, { gateSocket: '/fixture-gate.sock', gate: async (...args) => { calls.push(args); return auraAck } })
  await refusal(verifyDeviceBinding(receipt, { ...opts, event: { ...opts.event, sig: '00'.repeat(64) } }), R.BINDING)
  assert.equal(calls.length, 0)
  await verifyDeviceBinding(receipt, opts)
  assert.deepEqual(calls, [['/fixture-gate.sock', 'aura_note', { kind: 'copresence-accepted', digest_sha256: coreOf(receipt) }]])
  await refusal(verifyDeviceBinding(receipt, opts), R.REPLAY)
  assert.equal(calls.length, 1)
})

test('Aura receiver protections fail under mutation', { skip: process.env.AUKORA_COPRESENCE_MUTATIONS !== '1' }, () => {
  const file = path.join(here, 'receiver.mjs'), source = readFileSync(file, 'utf8')
  const mutations = [
    ['required recording', 'if (gateSocket !== undefined) {', 'if (false) {'],
    ['digest-only payload', 'digest_sha256: evidence.core }', 'digest_sha256: evidence.core, evidence }'],
    ['verified core digest', 'digest_sha256: evidence.core', "digest_sha256: '00'.repeat(32)"],
    ['positive acknowledgement', 'ack?.ok !== true || ', ''],
    ['integer sequence', '!Number.isSafeInteger(ack.seq) || ', ''],
    ['positive sequence', 'ack.seq < 1', 'false'],
    ['hash acknowledgement', "typeof ack.hash !== 'string' || !/^[0-9a-f]{64}$/.test(ack.hash)", 'false'],
    ['failure surface', '} catch { throw refuse(RECEIVER_REFUSE.AURA) }', '} catch {}'],
    ['configured socket', "if (options.gateSocket !== undefined && (typeof options.gateSocket !== 'string'\n    || !path.isAbsolute(options.gateSocket) || options.gateSocket.includes('\\0'))) throw refuse(RECEIVER_REFUSE.AURA)", ''],
    ['consume before record', 'if (result === false) throw refuse(RECEIVER_REFUSE.REPLAY)\n  if (result !== true) throw refuse(RECEIVER_REFUSE.STORE)', ''],
    ['receipt gate configuration', 'return consume(evidence, options)\n}', 'return consume(evidence, { store: options.store })\n}'],
    ['binding gate configuration', 'catch { throw refuse(RECEIVER_REFUSE.BINDING) }\n  return consume(evidence, options)',
      'catch { throw refuse(RECEIVER_REFUSE.BINDING) }\n  return consume(evidence, { store: options.store })'],
  ]
  const env = { ...process.env, AUKORA_COPRESENCE_MUTATIONS: '0' }
  delete env.NODE_TEST_CONTEXT
  const run = () => childProcess.spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-name-pattern', '^Aura', fileURLToPath(import.meta.url)], {
    encoding: 'utf8', timeout: 30_000, env,
  })
  const baseline = run()
  assert(baseline.status === 0 && /# fail 0/u.test(baseline.stdout), 'unmodified Aura mutation baseline must pass')
  const interrupted = () => { fs.writeFileSync(file, source); process.exit(130) }
  process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted)
  try {
    for (const [name, before, replacement] of mutations) {
      assert(source.includes(before), `mutation anchor: ${name}`)
      fs.writeFileSync(file, source.replace(before, replacement))
      const result = run()
      assert(result.status === 1 && /# fail [1-9]/u.test(result.stdout), `mutation survived or did not run: ${name}`)
      console.log(`mutation Aura ${name}: KILLED`)
    }
    console.log(`Aura receiver mutations ${mutations.length}/${mutations.length} KILLED`)
  } finally {
    fs.writeFileSync(file, source)
    process.removeListener('SIGINT', interrupted); process.removeListener('SIGTERM', interrupted)
  }
})
