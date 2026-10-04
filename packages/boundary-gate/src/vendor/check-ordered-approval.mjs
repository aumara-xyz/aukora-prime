// SPDX-License-Identifier: AGPL-3.0-or-later
// SOURCE_ONLY: actual gate core, disposable SQLite and generated synthetic Ed25519/HMAC keys.
// Declarative target bytes stay in a fixture store. No sockets, UID enforcement, enrollment,
// human decision, installation or runtime qualification is exercised or claimed.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHmac, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto'
import { createGate } from '../gate.mjs'
import { openDb, sha256, entryBody, signedEntryData } from '../ledger.mjs'
import * as canon from '../plugin-set-canon.mjs'
import { validateSignerEpochs } from './signer-epochs.mjs'

const TARGET = canon.GATE_PLUGIN_SET_TARGET
const APPROVER = 'owner via owner.sock (synthetic source fixture)'
const columns = ['seq', 'at', 'event', 'proposal', 'target', 'base_sha', 'new_sha', 'detail', 'prev', 'hash', 'sig']
const digest = n => n.toString(16).padStart(64, '0')
const errorCode = code => error => error?.code === code
const load = text => import(`data:text/javascript;base64,${Buffer.from(text).toString('base64')}`)
const gateUrl = new URL('../gate.mjs', import.meta.url)
const canonSource = fs.readFileSync(new URL('../plugin-set-canon.mjs', import.meta.url), 'utf8')
const gateSource = fs.readFileSync(gateUrl, 'utf8')
const ledgerSource = fs.readFileSync(new URL('../ledger.mjs', import.meta.url), 'utf8')

function syntheticKey() {
  const pair = generateKeyPairSync('ed25519')
  const pubPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const full = sha256(pair.publicKey.export({ type: 'spki', format: 'der' }))
  return { priv: pair.privateKey, pub: pair.publicKey, pubPem, fp: full.slice(0, 16), full }
}
const registry = (...keys) => ({ version: 1, kind: 'aukora-signer-epochs/v1',
  epochs: keys.map((key, i) => ({ epoch: i + 1, gate_pubkey_sha256: key.full })) })

function fixture(t, factory = createGate, key = syntheticKey()) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aukora-ordered-source-'))
  const db = openDb(path.join(home, 'gate.db'))
  let gate
  t.after(() => { if (gate) gate.close(); else db.close(); fs.rmSync(home, { recursive: true, force: true }) })
  const bytes = new Map(), writes = []
  const store = {
    read(target) { const b = bytes.get(target); return b ? Buffer.from(b) : null },
    write(target, spec, value, proposal) { writes.push({ target, proposal }); bytes.set(target, Buffer.from(value)) },
  }
  const owner = { hmacKey: randomBytes(32).toString('hex'), bearer: 'synthetic-unused-bearer' }
  const files = { 'plugins/synthetic/index.mjs': sha256('synthetic declarative file digest') }
  const artifact = { id: 'synthetic', entry: Object.keys(files)[0], files, digest: canon.artifactDigest(files) }
  const record = { kind: canon.PLUGIN_SET_KIND, count: 1, artifacts: { synthetic: artifact },
    setDigest: canon.pluginSetDigest({ synthetic: artifact }) }
  const fields = { release: 'abcdef0' + '1'.repeat(33), release_dir: 'release-abcdef0',
    plugin_set: record.setDigest, operation: canon.operationDigestOf(canon.setOperationContent(record)), record: digest(1) }
  const content = JSON.stringify({ v: 1, kind: 'aukora-plugin-set-approval/v1', ...fields })
  const targets = { [TARGET]: { entry: TARGET, maxBytes: 2048, operatorOnly: true, schema: 'synthetic declarative approval',
    validate(text) { assert.ok(canon.parseGateApprovalContent(text), 'fixture accepts canonical approval data only') } } }
  gate = factory({ home, db, key, owner, targets, store, now: () => 1791072000000,
    iso: () => '2026-10-04T00:00:00.000Z' })
  const pin = { kind: canon.GATE_PIN_KIND, gatePubkeyPem: key.pubPem, gatePubkeyFp: key.fp, target: TARGET, approver: APPROVER }
  function apply() {
    const pending = gate.ownerOps.raise({ target: TARGET, content, why: 'Synthetic source acceptance' })
    assert.equal(writes.length, 0, 'raising does not write')
    const review = gate.ownerOps.review({ id: pending.id })
    assert.equal(review.content, content); assert.equal(writes.length, 0, 'reviewing does not write')
    const decision = { id: review.id, base_sha: review.base_sha, new_sha: review.new_sha,
      review_challenge: review.review_challenge, outcome: 'allowed-once' }
    const applied = gate.ownerOps.decide_review(decision, APPROVER)
    assert.equal(applied.applied, true); assert.equal(writes.length, 1)
    const exported = gate.ownerOps.log({ limit: 200, target: TARGET })
    assert.equal(exported.verify.ok, true)
    const row = exported.entries.find(e => e.seq === applied.ledger_seq)
    assert.ok(row, 'actual owner export contains applied row')
    const approval = { kind: canon.GATE_APPROVAL_KIND, content, receipt: row.detail.receipt,
      receipt_sig: row.detail.receipt_sig, ledger_entry: row.signed_entry }
    return { pending, review, decision, applied, exported, row, input: { record, approval, pin, epochs: registry(key) } }
  }
  return { home, db, gate, key, owner, bytes, writes, record, content, fields, pin, apply }
}

function resign(input, key, change) {
  const next = structuredClone(input), e = next.approval.ledger_entry
  change(e, next)
  e.hash = sha256(entryBody(e)); e.sig = sign(null, Buffer.from(e.hash, 'hex'), key.priv).toString('base64')
  return next
}
const verifyInput = input => canon.verifyOrderedGateApproval(input)
function insertSignedDetail(w, input, rawDetail) {
  const last = w.db.prepare('SELECT seq,hash FROM ledger ORDER BY seq DESC LIMIT 1').get()
  const e = { ...input.approval.ledger_entry, seq: last.seq + 1, prev: last.hash, detail: rawDetail }
  e.hash = sha256(entryBody(e)); e.sig = sign(null, Buffer.from(e.hash, 'hex'), w.key.priv).toString('base64')
  w.db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(...columns.map(name => e[name]))
  return e
}
function corrupt(w) {
  // Only this disposable fixture removes a trigger to simulate damaged persistent data.
  w.db.exec('DROP TRIGGER ledger_no_update')
  w.db.prepare('UPDATE ledger SET detail=? WHERE seq=1').run('{"synthetic_corruption":true}')
  assert.equal(w.gate.verify().ok, false, 'real ledger verifier observes fixture corruption')
}

test('actual owner raise/review/decide exports signed sequence, exact effect and synthetic HMAC', t => {
  const w = fixture(t), { applied, decision, row, input } = w.apply()
  const result = verifyInput(input)
  assert.equal(result.ledgerSeq, 4); assert.equal(result.ledgerSeq, applied.ledger_seq)
  assert.equal(result.ledgerHash, applied.ledger_hash); assert.equal(result.signerEpoch, 1)
  assert.equal(result.signerKeySha256, w.key.full); assert.equal(result.release, w.fields.release)
  assert.equal(w.bytes.get(TARGET).toString(), w.content)
  const stored = w.db.prepare('SELECT * FROM ledger WHERE seq=?').get(result.ledgerSeq)
  assert.deepEqual(row.signed_entry, signedEntryData(stored)); assert.equal(typeof row.signed_entry.detail, 'string')
  assert.deepEqual(row.detail, JSON.parse(row.signed_entry.detail))
  assert.equal(sha256(entryBody(row.signed_entry)), row.signed_entry.hash)
  assert.equal(verify(null, Buffer.from(row.signed_entry.hash, 'hex'), w.key.pub, Buffer.from(row.signed_entry.sig, 'base64')), true)
  const r = input.approval.receipt
  const hmac = createHmac('sha256', Buffer.from(w.owner.hmacKey, 'hex'))
    .update(`${r.proposal}\n${r.base_sha}\n${r.new_sha}\n${r.approver}`).digest('base64')
  assert.equal(r.approval_evidence_hmac, hmac)
  assert.throws(() => w.gate.ownerOps.decide_review(decision, APPROVER), /no live review challenge/u)
  assert.equal(w.writes.length, 1, 'review challenge replay cannot repeat the effect')
  assert.equal(Object.hasOwn(w.gate.proposeOps.log({ limit: 200 }).entries.find(e => e.event === 'apply'), 'signed_entry'), false)
})

test('owner export preserves original SQLite TEXT even for noncompact signed JSON detail', t => {
  const w = fixture(t), { input } = w.apply()
  const detail = `{\n  "receipt": ${JSON.stringify(input.approval.receipt)},\n  "receipt_sig": ${JSON.stringify(input.approval.receipt_sig)}\n}`
  const inserted = insertSignedDetail(w, input, detail)
  const row = w.gate.ownerOps.log({ limit: 1, target: TARGET }).entries[0]
  assert.equal(row.signed_entry.detail, detail); assert.equal(row.signed_entry.hash, inserted.hash)
  assert.notEqual(JSON.stringify(row.detail), detail, 'fixture distinguishes parsed from signed representation')
  const updated = structuredClone(input); updated.approval.ledger_entry = row.signed_entry
  assert.equal(verifyInput(updated).ledgerSeq, inserted.seq)
})

test('closed row shape, safe sequence, apply event and predecessor grammar refuse malformed rows', t => {
  const w = fixture(t), { input } = w.apply()
  for (const ledger_entry of [undefined, null, [], { ...input.approval.ledger_entry, extra: true }]) {
    const next = structuredClone(input); next.approval.ledger_entry = ledger_entry
    assert.throws(() => verifyInput(next), errorCode('signed-ledger-entry-malformed'))
  }
  for (const seq of [undefined, null, '4', 0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
    assert.throws(() => verifyInput(resign(input, w.key, e => { e.seq = seq })), errorCode('signed-ledger-entry-malformed'))
  }
  for (const changes of [{ event: 'reject' }, { prev: 'GENESIS' }, { seq: 1, prev: digest(1) }, { hash: 'A'.repeat(64) },
    { sig: null }, { detail: {} }, { detail: ' '.repeat(65537) }]) {
    const next = structuredClone(input); Object.assign(next.approval.ledger_entry, changes)
    assert.throws(() => verifyInput(next), errorCode('signed-ledger-entry-malformed'))
  }
  const first = resign(input, w.key, e => { e.seq = 1; e.prev = 'GENESIS' })
  assert.equal(verifyInput(first).ledgerSeq, 1, 'valid individually signed first-row grammar')
})

test('signed row must bind exact receipt effect and exact signed receipt detail', t => {
  const w = fixture(t), { input } = w.apply()
  for (const name of ['proposal', 'target', 'base_sha', 'new_sha']) {
    assert.throws(() => verifyInput(resign(input, w.key, e => { e[name] = 'changed' })), errorCode('signed-ledger-entry-binding'))
  }
  for (const at of [null, 'a'.repeat(65)]) {
    assert.throws(() => verifyInput(resign(input, w.key, e => { e.at = at })), errorCode('signed-ledger-entry-binding'))
  }
  for (const change of [d => { d.receipt.applied_at = '1990-01-01T00:00:00.000Z' },
    d => { d.receipt_sig = Buffer.alloc(64).toString('base64') }, d => { d.extra = true }]) {
    const next = resign(input, w.key, e => { const detail = JSON.parse(e.detail); change(detail); e.detail = JSON.stringify(detail) })
    assert.throws(() => verifyInput(next), errorCode('signed-ledger-entry-binding'))
  }
  for (const detail of ['null', '[]', '{}']) {
    assert.throws(() => verifyInput(resign(input, w.key, e => { e.detail = detail })), errorCode('signed-ledger-entry-binding'))
  }
  assert.throws(() => verifyInput(resign(input, w.key, e => { e.detail = '{' })), SyntaxError)
})

test('sequence, timestamp and raw detail tamper need their own authentic row hash and signature', t => {
  const w = fixture(t), { input } = w.apply()
  for (const change of [e => { e.seq++ }, e => { e.at = '1990-01-01T00:00:00.000Z' },
    e => { e.prev = digest(9) }, e => { e.detail = ' ' + e.detail }]) {
    const next = structuredClone(input); change(next.approval.ledger_entry)
    assert.throws(() => verifyInput(next), errorCode('signed-ledger-entry-hash'))
  }
  const otherKey = syntheticKey()
  assert.throws(() => verifyInput(resign(input, otherKey, e => { e.seq++ })), errorCode('signed-ledger-entry-signature'))
  const missingSig = structuredClone(input); missingSig.approval.ledger_entry.sig = ''
  assert.throws(() => verifyInput(missingSig), errorCode('signed-ledger-entry-signature'))
  const receipt = structuredClone(input); receipt.approval.receipt_sig = Buffer.alloc(64).toString('base64')
  assert.throws(() => verifyInput(receipt), errorCode('plugin-set-approval-signature-invalid'))
})

test('full SPKI key selects its registered epoch and another key cannot inherit it', t => {
  const first = syntheticKey(), second = syntheticKey(), w = fixture(t, createGate, second), { input } = w.apply()
  input.epochs = registry(first, second)
  assert.equal(verifyInput(input).signerEpoch, 2); assert.equal(verifyInput(input).signerKeySha256, second.full)
  const unregistered = structuredClone(input); unregistered.epochs = registry(first)
  assert.throws(() => verifyInput(unregistered), errorCode('signer-epoch-unpinned'))
  const shortMatch = structuredClone(input)
  shortMatch.epochs = { ...registry(second), epochs: [{ epoch: 1,
    gate_pubkey_sha256: second.full.slice(0, 16) + (second.full[16] === '0' ? '1' : '0') + second.full.slice(17) }] }
  assert.throws(() => verifyInput(shortMatch), errorCode('signer-epoch-unpinned'))
  const replaced = structuredClone(input); replaced.pin.gatePubkeyPem = first.pubPem; replaced.pin.gatePubkeyFp = first.fp
  assert.throws(() => verifyInput(replaced), errorCode('plugin-set-approval-by-unpinned-key'))
})

test('registry shape, contiguous epochs and nonreusable full keys agree with public validator', t => {
  const w = fixture(t), { input } = w.apply(), good = registry(w.key), row = good.epochs[0]
  assert.deepEqual(validateSignerEpochs(good), good)
  const invalid = [undefined, null, {}, { ...good, extra: true }, { ...good, version: 2 }, { ...good, epochs: [] },
    { ...good, epochs: [{ ...row, epoch: 2 }] }, { ...good, epochs: [row, { ...row, epoch: 2 }] },
    { ...good, epochs: [row, { epoch: 3, gate_pubkey_sha256: digest(2) }] },
    { ...good, epochs: [{ ...row, epoch: '1' }] }, { ...good, epochs: [{ ...row, epoch: Number.MAX_SAFE_INTEGER + 1 }] },
    { ...good, epochs: [{ ...row, gate_pubkey_sha256: w.key.fp }] }, { ...good, epochs: [{ ...row, extra: true }] },
    { ...good, epochs: Array.from({ length: 65 }, (_, i) => ({ epoch: i + 1, gate_pubkey_sha256: digest(i + 1) })) }]
  for (const epochs of invalid) {
    assert.throws(() => validateSignerEpochs(epochs), /signer-epochs-malformed/u)
    assert.throws(() => verifyInput({ ...input, epochs }), errorCode('signer-epochs-malformed'))
  }
})

test('actual corrupted SQLite ledger refuses owner signed export, including corruption outside target filter', t => {
  const w = fixture(t); w.apply()
  assert.throws(() => w.db.prepare('UPDATE ledger SET detail=? WHERE seq=1').run('{}'), /ledger is append-only/u)
  assert.throws(() => w.db.prepare('DELETE FROM ledger WHERE seq=1').run(), /ledger is append-only/u)
  corrupt(w)
  for (const args of [{ limit: 1, target: TARGET }, { limit: 1, target: 'another-target' }, { limit: 200 }]) {
    assert.throws(() => w.gate.ownerOps.log(args), /signed-ledger-export-unverified/u)
  }
})

if (process.argv.includes('--mutations')) test('named single-guard mutants are killed by focused behavior checks', async t => {
  const w = fixture(t), { input } = w.apply()
  const refuses = (m, next, code) => assert.throws(() => m.verifyOrderedGateApproval(next), errorCode(code))
  const mutations = [
    ['registry-contiguous', 'row.epoch !== previous + 1', 'false', m => refuses(m,
      { ...input, epochs: { ...registry(w.key), epochs: [{ epoch: 2, gate_pubkey_sha256: w.key.full }] } }, 'signer-epochs-malformed')],
    ['registry-key-reuse', 'keys.has(row.gate_pubkey_sha256)', 'false', m => refuses(m,
      { ...input, epochs: { ...registry(w.key), epochs: [{ epoch: 1, gate_pubkey_sha256: w.key.full }, { epoch: 2, gate_pubkey_sha256: w.key.full }] } }, 'signer-epochs-malformed')],
    ['registry-full-spki', 'row.gate_pubkey_sha256 === signerKeySha256', 'row.gate_pubkey_sha256.slice(0, 16) === signerKeySha256.slice(0, 16)', m => refuses(m,
      { ...input, epochs: { ...registry(w.key), epochs: [{ epoch: 1, gate_pubkey_sha256: w.key.full.slice(0, 16) + (w.key.full[16] === '0' ? '1' : '0') + w.key.full.slice(17) }] } }, 'signer-epoch-unpinned')],
    ['row-safe-sequence', '!Number.isSafeInteger(e.seq)', '!Number.isInteger(e.seq)', m => refuses(m,
      resign(input, w.key, e => { e.seq = Number.MAX_SAFE_INTEGER + 1 }), 'signed-ledger-entry-malformed')],
    ['row-effect-proposal', 'e.proposal !== r.proposal', 'false', m => refuses(m,
      resign(input, w.key, e => { e.proposal = 'another-proposal' }), 'signed-ledger-entry-binding')],
    ['row-detail-receipt', 'JSON.stringify(detail.receipt) !== JSON.stringify(r)', 'false', m => refuses(m,
      resign(input, w.key, e => { const d = JSON.parse(e.detail); d.receipt.applied_at = '1990-01-01T00:00:00.000Z'; e.detail = JSON.stringify(d) }), 'signed-ledger-entry-binding')],
    ['row-detail-signature', 'detail.receipt_sig !== approval.receipt_sig', 'false', m => refuses(m,
      resign(input, w.key, e => { const d = JSON.parse(e.detail); d.receipt_sig = ''; e.detail = JSON.stringify(d) }), 'signed-ledger-entry-binding')],
    ['row-body-hash', "digestOf(Buffer.from(body, 'utf8')) !== e.hash", 'false', m => {
      const next = structuredClone(input); next.approval.ledger_entry.seq++; refuses(m, next, 'signed-ledger-entry-hash') }],
    ['row-signature', "if (!valid) throw refuse('signed-ledger-entry-signature'", "if (false) throw refuse('signed-ledger-entry-signature'", m => refuses(m,
      resign(input, syntheticKey(), e => { e.seq++ }), 'signed-ledger-entry-signature')],
  ]
  for (const [name, before, after, exercise] of mutations) await t.test(name, async () => {
    assert.equal(canonSource.split(before).length - 1, 1, 'exactly one named source guard')
    const mutant = await load(canonSource.replace(before, after) + '\n// mutant ' + name)
    let killed = false; try { exercise(mutant) } catch { killed = true }
    assert.equal(killed, true, `${name} must fail its focused oracle`)
  })
  const loadGate = async (text, ledger = new URL('../ledger.mjs', import.meta.url).href) => {
    for (const name of ['./ledger.mjs', './secrets.mjs', './card.mjs', './targets.mjs']) {
      text = text.replace(`from '${name}'`, `from '${name === './ledger.mjs' ? ledger : new URL(name, gateUrl).href}'`)
    }
    return load(text)
  }
  await t.test('owner-export-unverified', async st => {
    const guard = "if (!checked.ok) throw new Error('signed-ledger-export-unverified')"
    assert.equal(gateSource.split(guard).length - 1, 1)
    const mutant = await loadGate(gateSource.replace(guard, 'if (false) throw new Error(\'signed-ledger-export-unverified\')'))
    const world = fixture(st, mutant.createGate); world.apply(); corrupt(world)
    let killed = false
    try { assert.throws(() => world.gate.ownerOps.log({ limit: 1, target: TARGET }), /signed-ledger-export-unverified/u) } catch { killed = true }
    assert.equal(killed, true, 'owner export guard removal must fail corruption refusal')
  })
  await t.test('original-detail-export', async st => {
    const guard = '[k, e[k]]'
    assert.equal(ledgerSource.split(guard).length - 1, 1)
    const changed = ledgerSource.replace(guard, "[k, k === 'detail' && e[k] !== null ? JSON.stringify(JSON.parse(e[k])) : e[k]]")
    const ledger = `data:text/javascript;base64,${Buffer.from(changed).toString('base64')}`
    const mutant = await loadGate(gateSource, ledger), world = fixture(st, mutant.createGate), applied = world.apply()
    const raw = ' ' + applied.input.approval.ledger_entry.detail
    insertSignedDetail(world, applied.input, raw)
    let killed = false
    try { assert.equal(world.gate.ownerOps.log({ limit: 1 }).entries[0].signed_entry.detail, raw) } catch { killed = true }
    assert.equal(killed, true, 'reserialized detail must fail exact SQLite TEXT preservation')
  })
})

test.after(() => console.log('SOURCE_ONLY; ACTUAL_GATE_AND_DISPOSABLE_SQLITE; SYNTHETIC_ED25519_HMAC_AND_DECLARATIVE_STORE; NO_SOCKET_UID_HUMAN_OR_RUNTIME_QUALIFICATION'))
