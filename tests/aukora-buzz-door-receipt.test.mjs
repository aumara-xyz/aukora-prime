// Checks signed receipt bytes, independent pins, ledger inclusion and bounded channel/file inputs.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { entryBody, keyFingerprint, sha256 } from '../packages/boundary-gate/src/ledger.mjs'
import { publicKeyOf, randomSecretKey, signEvent } from '../plugins/aukora-nostr/lib/event.mjs'
import { receiptMessage, parseReceiptMessage, verifyChannelReceipt, RECEIPT_KIND, RECEIPT_FORMAT,
  RECEIPT_LINE, RECEIPT_REFUSE as R, MAX_RECEIPT_CONTENT_BYTES, MAX_RECEIPT_EVENT_BYTES,
  MAX_RECEIPT_LEDGER_BYTES } from '../plugins/aukora-buzz-door/lib/receipt.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const evidence = new URL('../docs/evidence/l2-demo-2026-10-04/', import.meta.url)
const read = name => fs.readFileSync(new URL(name, evidence), 'utf8')
const receiptBytes = Buffer.from(read('receipt.json').replace(/\n$/u, ''))
const result = { receipt: JSON.parse(receiptBytes), receipt_sig: read('receipt.sig').trim() }
const entries = JSON.parse(read('ledger-entries.json')), gatePublicKey = read('gate-ed25519.pub')
const channel = '11111111-2222-4333-8444-555555555555'
const otherChannel = '99999999-2222-4333-8444-555555555555'
const doorKey = randomSecretKey(), doorPubkey = publicKeyOf(doorKey)
// These anchors are synthesized from the fixture, not fetched independent published anchors.
const anchorFor = (entry, key = gatePublicKey) => ({ seq: entry.seq, head: entry.hash, gate_fp: keyFingerprint(createPublicKey(key)) })
const pins = { doorPubkey, channel, gatePublicKey, entries, anchors: [anchorFor(entries.at(-1))] }
const message = value => receiptMessage(value, { channel })
const signed = (body = message(result), key = doorKey) => signEvent({ pubkey: publicKeyOf(key), created_at: 1791072000, ...body }, key)
const event = signed()
const rejected = (candidate, reason, overrides = {}) => assert.deepEqual(verifyChannelReceipt(candidate, { ...pins, ...overrides }), { valid: false, reason })
const throws = (run, reason) => assert.throws(run, { code: reason })
const envelope = value => ({ ...message(result), content: RECEIPT_LINE + JSON.stringify(value) })

test('fixture receipt round-trips exact signed bytes in bounded kind-9 content and tags', () => {
  const body = message({ ...result, state: 'applied', ledger_seq: 24 })
  assert.deepEqual(body.tags, [['h', channel], ['t', RECEIPT_FORMAT]])
  assert.equal(body.kind, RECEIPT_KIND)
  assert(Buffer.byteLength(body.content) < MAX_RECEIPT_CONTENT_BYTES)
  const parsed = parseReceiptMessage(signed(body))
  assert.deepEqual(parsed.receiptBytes, receiptBytes)
  assert.deepEqual(parsed.receipt, result.receipt)
  assert.equal(parsed.receipt_sig, result.receipt_sig)
  assert.equal(parsed.channel, channel)
  assert.deepEqual(verifyChannelReceipt(event, pins), { valid: true, reason: 'valid against the supplied anchor', proposal: result.receipt.proposal, ledger_seq: 24, anchored_seq: 24 })
})

test('one altered receipt byte fails after the door correctly re-signs its event', () => {
  const changed = structuredClone(result)
  changed.receipt.target = changed.receipt.target.replace('theme.json', 'theme.jsom')
  const changedBytes = Buffer.from(JSON.stringify(changed.receipt))
  assert.equal(changedBytes.length, receiptBytes.length)
  assert.equal(changedBytes.filter((b, i) => b !== receiptBytes[i]).length, 1)
  rejected(signed(message(changed)), R.RECEIPT)
})

test('a different gate key cannot sign the pinned gate receipt', () => {
  const foreign = generateKeyPairSync('ed25519')
  const changed = { ...result, receipt_sig: sign(null, receiptBytes, foreign.privateKey).toString('base64') }
  rejected(signed(message(changed)), R.RECEIPT)
  rejected(event, R.RECEIPT, { gatePublicKey: foreign.publicKey.export({ format: 'pem', type: 'spki' }) })
})

test('the door author and channel must equal independent pins', () => {
  rejected(signed(message(result), randomSecretKey()), R.AUTHOR)
  for (const key of [undefined, 'bad', doorPubkey.toUpperCase()]) rejected(event, R.AUTHOR, { doorPubkey: key })
  for (const value of [undefined, 'bad', otherChannel]) rejected(event, R.CHANNEL, { channel: value })
  rejected(signed(receiptMessage(result, { channel: otherChannel })), R.CHANNEL)
})

test('forged Nostr signature, id and signed content fail', () => {
  rejected({ ...event, sig: '0'.repeat(128) }, R.EVENT)
  rejected({ ...event, id: '0'.repeat(64) }, R.EVENT)
  rejected({ ...event, created_at: event.created_at + 1 }, R.EVENT)
})

test('gate public key must parse as Ed25519', () => {
  for (const key of [undefined, 'not a public key']) rejected(event, R.GATE_KEY, { gatePublicKey: key })
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 })
  rejected(event, R.GATE_KEY, { gatePublicKey: rsa.publicKey.export({ format: 'pem', type: 'spki' }) })
})

test('receipt formatter refuses invalid channels and unsafe JSON objects without invoking getters', () => {
  for (const value of [undefined, 'bad', 'ABCDEFAB-2222-4333-8444-555555555555', channel + '\n']) throws(() => receiptMessage(result, { channel: value }), R.CHANNEL)
  let touched = false
  const unsafe = { ...result, receipt: { get v() { touched = true; return 2 } } }
  throws(() => message(unsafe), R.FORMAT)
  assert.equal(touched, false)
  const cycle = {}; cycle.receipt = cycle
  for (const value of [undefined, {}, cycle, { ...result, receipt: { ...result.receipt, target: '\ud800' } }]) throws(() => message(value), R.FORMAT)
})

test('content bounds count UTF-8 bytes at the exact limit and reject oversized formatter output', () => {
  const exact = structuredClone(result)
  exact.receipt.approver += 'x'.repeat(MAX_RECEIPT_CONTENT_BYTES - Buffer.byteLength(message(exact).content))
  assert.equal(Buffer.byteLength(message(exact).content), MAX_RECEIPT_CONTENT_BYTES)
  assert.equal(parseReceiptMessage(message(exact)).receipt.approver, exact.receipt.approver)
  exact.receipt.approver += 'x'
  throws(() => message(exact), R.SIZE)
  const unicode = structuredClone(result)
  unicode.receipt.approver += '🪷'.repeat(400)
  const body = envelope(unicode)
  assert(body.content.length < MAX_RECEIPT_CONTENT_BYTES)
  assert(Buffer.byteLength(body.content) > MAX_RECEIPT_CONTENT_BYTES)
  throws(() => message(unicode), R.SIZE)
  rejected(signed(body), R.SIZE)
})

test('the full event is bounded even when the receipt content fits', () => {
  const exact = { ...event, extra: '' }
  exact.extra = 'x'.repeat(MAX_RECEIPT_EVENT_BYTES - Buffer.byteLength(JSON.stringify(exact)))
  assert.equal(Buffer.byteLength(JSON.stringify(exact)), MAX_RECEIPT_EVENT_BYTES)
  assert.equal(verifyChannelReceipt(exact, pins).valid, true)
  rejected({ ...exact, extra: exact.extra + 'x' }, R.SIZE)
  rejected({ ...event, extra: '🪷'.repeat(2000) }, R.SIZE)
})

test('only the exact kind, channel tag and receipt format tag are accepted', () => {
  for (const candidate of [null, {}, signed({ ...message(result), kind: 1 }), { ...event, tags: null }, { ...event, tags: [] }, { ...event, tags: [...event.tags, ['x', 'extra']] }]) rejected(candidate, R.FORMAT)
  for (const tags of [[['h', 'bad'], ['t', RECEIPT_FORMAT]], [['h', channel, 'extra'], ['t', RECEIPT_FORMAT]], [...event.tags].reverse(), [['h', channel], ['t', 'other']]]) {
    rejected(signed({ ...message(result), tags }), R.CHANNEL)
  }
})

test('canonical receipt envelope rejects malformed JSON, extra keys and unsupported v3', () => {
  rejected(signed({ ...message(result), content: 'X' + event.content.slice(1) }), R.FORMAT)
  for (const content of [null, '', '{}', RECEIPT_LINE + '{', RECEIPT_LINE + 'null', RECEIPT_LINE + JSON.stringify(result, null, 2), event.content + '\n']) rejected({ ...event, content }, R.FORMAT)
  for (const value of [{ receipt_sig: result.receipt_sig, receipt: result.receipt }, { ...result, extra: true }, { ...result, receipt: [] }, { ...result, receipt: null }, { ...result, receipt_sig: 'bad' }]) rejected(signed(envelope(value)), R.FORMAT)
  const v3 = { ...result, receipt: { ...result.receipt, v: 3 } }
  throws(() => message(v3), R.VERSION)
  rejected(signed(envelope(v3)), R.VERSION)
  const reordered = { ...result, receipt: Object.fromEntries(Object.entries(result.receipt).reverse()) }
  rejected(signed(message(reordered)), R.RECEIPT)
})

test('ledger must be present, bounded, ordered, complete and preserve signed detail TEXT', () => {
  for (const value of [undefined, {}, []]) rejected(event, R.LEDGER, { entries: value })
  rejected(event, R.SIZE, { entries: [{ detail: 'x'.repeat(MAX_RECEIPT_LEDGER_BYTES) }] })
  rejected(event, R.LEDGER, { entries: entries.filter((_, i) => i !== 5) })
  const reordered = structuredClone(entries); [reordered[1], reordered[2]] = [reordered[2], reordered[1]]
  rejected(event, R.LEDGER, { entries: reordered })
  const rewritten = structuredClone(entries)
  rewritten.at(-1).detail = JSON.stringify(JSON.parse(rewritten.at(-1).detail), null, 2)
  rejected(event, R.LEDGER, { entries: rewritten })
  const badSignature = structuredClone(entries); badSignature[0].sig = Buffer.alloc(64).toString('base64')
  rejected(event, R.LEDGER, { entries: badSignature })
  rejected(event, R.LEDGER, { entries: [null] })
})

// Re-sign a copy only to test mismatched signed inclusion; this is not pilot evidence.
function synthetic(mutate = () => {}, beforeSign = () => {}) {
  const key = generateKeyPairSync('ed25519'), gatePublicKey = key.publicKey.export({ format: 'pem', type: 'spki' })
  const copy = structuredClone(entries), receipt = { ...result.receipt, pubkey_fp: keyFingerprint(key.publicKey) }
  const value = { receipt, receipt_sig: sign(null, Buffer.from(JSON.stringify(receipt)), key.privateKey).toString('base64') }
  copy.at(-1).detail = JSON.stringify(value)
  mutate(copy.at(-1), value, copy)
  let previous = 'GENESIS'
  for (const row of copy) {
    row.prev = previous; beforeSign(row); row.hash = sha256(entryBody(row)); row.sig = sign(null, Buffer.from(row.hash, 'hex'), key.privateKey).toString('base64'); previous = row.hash
  }
  return { event: signed(message(value)), pins: { ...pins, gatePublicKey, entries: copy, anchors: [anchorFor(copy.at(-1), gatePublicKey)] } }
}

const moduleText = file => fs.readFileSync(new URL(file, import.meta.url), 'utf8')
const moduleUrl = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`
function replaceOnce(source, from, to) {
  assert.equal(source.split(from).length, 2, `mutation must replace exactly one guard: ${from}`)
  return source.replace(from, to)
}
async function ledgerMutant(from, to, bypass = false) {
  let ledger = moduleText('../packages/boundary-gate/src/ledger.mjs')
  if (!bypass) ledger = replaceOnce(ledger, from, to)
  let receipt = moduleText('../packages/boundary-gate/src/receipts.mjs').replace("'./ledger.mjs'", JSON.stringify(moduleUrl(ledger)))
  if (bypass) receipt = replaceOnce(receipt, 'const chain = verifyLedger(db, pub)', 'const chain = { ok: true, entries: 0 }')
  const source = moduleText('../plugins/aukora-buzz-door/lib/receipt.mjs')
    .replace("'../../../packages/boundary-gate/src/receipts.mjs'", JSON.stringify(moduleUrl(receipt)))
    .replace(/from '(\.\.[^']+)'/gu, (_, file) => `from ${JSON.stringify(new URL(file, new URL('../plugins/aukora-buzz-door/lib/receipt.mjs', import.meta.url)).href)}`)
  return (await import(moduleUrl(source))).verifyChannelReceipt
}

test('10-04 receipt refuses forged neighbours, missing sequence and another gate signer; chain bypass mutant dies', async t => {
  const foreign = generateKeyPairSync('ed25519'), forged = structuredClone(entries)
  let previous = 'GENESIS'
  // Keep the genuine apply row byte-for-byte; self-consistent attacker-signed neighbours cannot authenticate it.
  for (const row of forged.slice(0, -1)) {
    row.detail = '{}'; row.prev = previous; row.hash = sha256(entryBody(row))
    row.sig = sign(null, Buffer.from(row.hash, 'hex'), foreign.privateKey).toString('base64'); previous = row.hash
  }
  const after = { ...forged.at(-1), seq: 25, event: 'start', proposal: null, detail: '{}', prev: forged.at(-1).hash }
  after.hash = sha256(entryBody(after)); after.sig = sign(null, Buffer.from(after.hash, 'hex'), foreign.privateKey).toString('base64')
  forged.push(after)
  assert.deepEqual(forged[23], entries[23])
  const wrongKey = structuredClone(entries)
  wrongKey[0].sig = sign(null, Buffer.from(wrongKey[0].hash, 'hex'), foreign.privateKey).toString('base64')
  const attacks = [
    { ...pins, entries: forged, anchors: [anchorFor(after)] },
    { ...pins, entries: entries.filter(row => row.seq !== 6) },
    { ...pins, entries: wrongKey },
  ]
  const check = (verify, candidate) => assert.deepEqual(verify(event, candidate), { valid: false, reason: R.LEDGER })
  for (const candidate of attacks) check(verifyChannelReceipt, candidate)
  const mutant = await ledgerMutant(null, null, true)
  for (const candidate of attacks) assert.throws(() => check(mutant, candidate), assert.AssertionError)
  t.diagnostic('MUTATION reused verifyLedger bypass: KILLED by all three 10-04 attacks')
})

test('each ledger guard rejects independently; sequence, link, hash and signature removal mutants die', async t => {
  const sequence = synthetic((row, value, copy) => { copy[5].seq = 99 })
  const link = synthetic(() => {}, row => { if (row.seq === 6) row.prev = '0'.repeat(64) })
  const hash = { event, pins: { ...pins, entries: structuredClone(entries) } }
  hash.pins.entries[5].detail = '{}'
  const signature = { event, pins: { ...pins, entries: structuredClone(entries) } }
  signature.pins.entries[5].sig = Buffer.alloc(64).toString('base64')
  const cases = [
    ['sequence', 'if (e.seq !== n)', 'if (false)', sequence],
    ['link', 'if (e.prev !== prev)', 'if (false)', link],
    ['hash', 'if (sha256(entryBody(e)) !== e.hash)', 'if (false)', hash],
    ['signature', 'if (!good) errors.push(`seq ${e.seq}: bad signature`)', 'if (false) errors.push(`seq ${e.seq}: bad signature`)', signature],
  ]
  for (const [name, from, to, candidate] of cases) {
    const check = verify => assert.deepEqual(verify(candidate.event, candidate.pins), { valid: false, reason: R.LEDGER })
    check(verifyChannelReceipt)
    const mutant = await ledgerMutant(from, to)
    assert.throws(() => check(mutant), assert.AssertionError)
    t.diagnostic(`MUTATION ledger ${name} guard removed: KILLED`)
  }
})

test('signed inclusion must match receipt, signature, proposal, target, hashes and event kind', () => {
  const good = synthetic()
  assert.equal(verifyChannelReceipt(good.event, good.pins).valid, true)
  for (const mutate of [row => { row.detail = '{}' }, row => { row.detail = '{' }, row => { const detail = JSON.parse(row.detail); detail.receipt_sig = 'A'.repeat(86) + '=='; row.detail = JSON.stringify(detail) }, row => { row.proposal = 'other' }, row => { row.target = 'other' }, row => { row.base_sha = '0'.repeat(64) }, row => { row.new_sha = '0'.repeat(64) }, row => { row.event = 'revert-applied' }]) {
    const altered = synthetic(mutate)
    assert.deepEqual(verifyChannelReceipt(altered.event, altered.pins), { valid: false, reason: R.LEDGER })
  }
})

test('anchors must pin the gate key, increasing sequence, exact hash and exported tail', () => {
  const first = anchorFor(entries[0]), tail = pins.anchors[0]
  assert.equal(verifyChannelReceipt(event, { ...pins, anchors: [first, tail] }).valid, true)
  for (const anchors of [undefined, {}, [], [null], [{ ...tail, seq: 24.5 }], [{ ...tail, seq: 0 }], [{ ...tail, head: 'bad' }], [{ ...tail, head: '0'.repeat(64) }], [{ ...tail, gate_fp: '0'.repeat(16) }], [tail, first], [tail, tail], [first], [{ ...tail, seq: 25 }]]) rejected(event, R.ANCHOR, { anchors })
  const extended = synthetic((row, value, copy) => copy.push({ ...row, seq: 25, event: 'start', proposal: null, detail: '{}' }))
  assert.equal(verifyChannelReceipt(extended.event, extended.pins).valid, true)
  // An anchor covering the receipt still cannot establish a later export tail.
  const old = anchorFor(extended.pins.entries[23], extended.pins.gatePublicKey)
  assert.deepEqual(verifyChannelReceipt(extended.event, { ...extended.pins, anchors: [old] }), { valid: false, reason: R.ANCHOR })
})

function cliFixture(t) {
  const dir = fs.mkdtempSync(path.join(root, '.receipt-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const files = { event: path.join(dir, 'event.json'), key: path.join(dir, 'gate.pub'), ledger: path.join(dir, 'ledger.json'), anchor: path.join(dir, 'anchors.jsonl') }
  fs.writeFileSync(files.event, JSON.stringify(event)); fs.writeFileSync(files.key, gatePublicKey)
  fs.writeFileSync(files.ledger, JSON.stringify(entries)); fs.writeFileSync(files.anchor, JSON.stringify(pins.anchors[0]) + '\n')
  const args = [files.event, '--gate-key', files.key, '--ledger', files.ledger, '--anchor', files.anchor, '--door-key', doorPubkey, '--channel', channel]
  const bin = path.join(root, 'plugins/aukora-buzz-door/bin/verify-channel-receipt.mjs')
  const run = (argv = args, prefix = []) => spawnSync(process.execPath, [...prefix, bin, ...argv], { cwd: root, encoding: 'utf8' })
  const check = (reason, argv = args) => { const out = run(argv); assert.equal(out.status, 1, out.stderr); assert.deepEqual(JSON.parse(out.stdout), { valid: false, reason }) }
  return { files, args, bin, run, check, dir }
}

test('CLI validates the fixture and reports invalid signatures with a nonzero exit', t => {
  const f = cliFixture(t), out = f.run()
  assert.equal(out.status, 0, out.stderr)
  assert.equal(JSON.parse(out.stdout).valid, true)
  fs.writeFileSync(f.files.event, JSON.stringify({ ...event, sig: '0'.repeat(128) }))
  f.check(R.EVENT)
})

test('CLI qualifies a supplied anchor and requires a named independent source; provenance removal mutant dies', t => {
  const f = cliFixture(t), source = 'independent witness checkpoint #24 (synthetic test declaration)'
  const out = f.run(), supplied = JSON.parse(out.stdout)
  assert.equal(out.status, 0, out.stderr)
  assert.equal(supplied.reason, 'valid against the supplied anchor')
  assert.equal(Object.hasOwn(supplied, 'anchor_source'), false)
  const independent = f.run([...f.args, '--independent-anchor-source', source])
  assert.equal(independent.status, 0, independent.stderr)
  assert.deepEqual(JSON.parse(independent.stdout), { ...supplied, reason: 'valid, anchor independently obtained', anchor_source: source, anchor_source_verified: false })
  for (const flags of [['--independent-anchor-source'], ['--independent-anchor-source', ' '], ['--independent-anchor-source', source, '--independent-anchor-source', source]]) {
    f.check('buzz-receipt:usage', [...f.args, ...flags])
  }
  f.check('buzz-receipt:usage', [...f.args.slice(0, -2), '--independent-anchor-source', source])
  const changed = replaceOnce(fs.readFileSync(f.bin, 'utf8'), 'result.valid && Object.hasOwn(options, sourceFlag)', 'result.valid')
    .replace("'../lib/receipt.mjs'", JSON.stringify(new URL('../plugins/aukora-buzz-door/lib/receipt.mjs', import.meta.url).href))
  const script = `process.argv = ${JSON.stringify([process.execPath, f.bin, ...f.args])}; await import(${JSON.stringify(moduleUrl(changed))})`
  const mutant = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: root, encoding: 'utf8' })
  assert.equal(mutant.status, 0, mutant.stderr)
  assert.throws(() => assert.equal(JSON.parse(mutant.stdout).reason, supplied.reason), assert.AssertionError)
  t.diagnostic('MUTATION independent-source requirement removed: KILLED')
})

test('CLI rejects missing, duplicate, unknown and incomplete flags and offers help', t => {
  const f = cliFixture(t)
  for (const args of [[], ['--bogus'], f.args.slice(0, -1), [...f.args, '--extra', 'x'], f.args.map(x => x === '--anchor' ? '--ledger' : x), f.args.map(x => x === '--anchor' ? '--unknown' : x), f.args.map(x => x === channel ? '--no-value' : x)]) f.check('buzz-receipt:usage', args)
  const help = f.run(['--help'])
  assert.equal(help.status, 0)
  assert.match(help.stdout, /EVENT\.json --gate-key GATE\.pub/u)
  for (const text of ['--independent-anchor-source HOW', 'exporting party does not control', 'ledger-anchor/anchors/gate-ledger.jsonl', 'repository owner controls it', 'not a fact this offline checker can verify']) assert(help.stdout.includes(text), text)
})

test('CLI bounds every input file before parsing and requires files with valid UTF-8 JSON', t => {
  const f = cliFixture(t)
  for (const [name, max] of [['event', MAX_RECEIPT_EVENT_BYTES], ['key', 1024], ['ledger', MAX_RECEIPT_LEDGER_BYTES], ['anchor', MAX_RECEIPT_LEDGER_BYTES]]) {
    const original = fs.readFileSync(f.files[name]); fs.writeFileSync(f.files[name], Buffer.concat([original, Buffer.alloc(max + 1 - original.length, ' ')])); f.check(R.SIZE); fs.writeFileSync(f.files[name], original)
  }
  const invalidUtf8 = Buffer.concat([Buffer.from(JSON.stringify(event).slice(0, -1) + ',"extra":"'), Buffer.from([0xff]), Buffer.from('"}')])
  for (const content of ['{', Buffer.from([0xff]), invalidUtf8]) { fs.writeFileSync(f.files.event, content); f.check('buzz-receipt:input') }
  f.check('buzz-receipt:input', [f.dir, ...f.args.slice(1)])
  f.check('buzz-receipt:input', [path.join(f.dir, 'missing'), ...f.args.slice(1)])
})

test('CLI refuses oversized and non-regular descriptors before reading', t => {
  const f = cliFixture(t)
  for (const [override, reason] of [
    ['value.size = 8193', R.SIZE],
    ['value.isFile = () => false', 'buzz-receipt:input'],
  ]) {
    const script = `import fs from 'node:fs'; const stat = fs.fstatSync, read = fs.readSync, open = fs.openSync; let reads = 0, eventFd;
      fs.openSync = (file, ...args) => { const fd = open(file, ...args); if (file === ${JSON.stringify(f.files.event)}) eventFd = fd; return fd };
      fs.fstatSync = fd => { const value = stat(fd); if (fd === eventFd) { ${override} }; return value };
      fs.readSync = (...args) => { if (args[0] === eventFd) reads++; return read(...args) };
      process.argv = ${JSON.stringify([process.execPath, f.bin, ...f.args])}; await import(${JSON.stringify(f.bin)});
      if (reads !== 0) process.exitCode = 99;`
    const out = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: root, encoding: 'utf8' })
    assert.equal(out.status, 1, out.stderr)
    assert.deepEqual(JSON.parse(out.stdout), { valid: false, reason })
  }
})

test('CLI bounds bytes read even if the file grows after fstat', t => {
  const f = cliFixture(t)
  const bytes = JSON.stringify(event)
  fs.writeFileSync(f.files.event, bytes + ' '.repeat(MAX_RECEIPT_EVENT_BYTES + 1 - Buffer.byteLength(bytes)))
  const script = `import fs from 'node:fs'; const stat = fs.fstatSync; fs.fstatSync = fd => { const value = stat(fd); value.size = 0; return value }; process.argv = ${JSON.stringify([process.execPath, f.bin, ...f.args])}; await import(${JSON.stringify(f.bin)})`
  const out = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: root, encoding: 'utf8' })
  assert.equal(out.status, 1, out.stderr)
  assert.deepEqual(JSON.parse(out.stdout), { valid: false, reason: R.SIZE })
})
