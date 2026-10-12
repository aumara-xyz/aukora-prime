// The fixed note target preserves reviewed UTF-8 bytes and requires the existing owner ceremony.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { generateKeyPairSync, sign, verify } from 'node:crypto'
import { fsStore } from '../src/fs-store.mjs'
import { sha256 } from '../src/ledger.mjs'
import { verifyReceipt } from '../src/receipts.mjs'
import { ownerRootPin, OWNER_KEY_ALGORITHM } from '../../owner-key/src/index.mjs'
import { ownerAuthorizationSigningBytes } from '../../owner-key/src/authorization.mjs'
import { createProposeTool } from '../../../plugins/aukora-auma-theme/lib/index.mjs'

const mutant = process.env.NOTE_MUTANT ?? ''
const mutations = {
  'type': ['targets.mjs', "if (typeof text !== 'string') throw new Error('note:text-required')", 'text = String(text)'],
  'characters': ['targets.mjs', "if (!text.isWellFormed() || /[\\u0000-\\u0008\\u000b-\\u001f\\u007f]/u.test(text)) throw new Error('note:plain-text-required')", ''],
  'empty': ['targets.mjs', "if (text.trim().length === 0) throw new Error('note:empty')", ''],
  'size': ['targets.mjs', "if (Buffer.byteLength(text, 'utf8') > 2000) throw new Error('note:too-large')", ''],
  'ascii-scope': ['gate.mjs', 'target !== NOTE_TARGET &&', 'false &&'],
  'utf8-adoption': ['gate.mjs', "if (t === NOTE_TARGET && !Buffer.from(txt, 'utf8').equals(cur)) throw new Error('note:invalid-utf8');", ''],
  'base': ['gate.mjs', 'if (claimed_base !== baseSha)', 'if (false)'],
  'stored-bytes': ['gate.mjs', "const bytes = Buffer.from(content, 'utf8')", "const bytes = Buffer.from(content.trim(), 'utf8')"],
}
if (mutant) assert.ok(Object.hasOwn(mutations, mutant), 'known note mutant')
function source(name) {
  const url = new URL('../src/' + name, import.meta.url)
  let src = fs.readFileSync(url, 'utf8')
  if (mutations[mutant]?.[0] === name) {
    const [, from, to] = mutations[mutant], next = src.replaceAll(from, to)
    assert.notEqual(next, src, 'mutation changed source'); src = next
  }
  return src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, rel) => `from ${JSON.stringify(new URL(rel, url).href)}`)
}
const moduleUrl = src => 'data:text/javascript;base64,' + Buffer.from(src).toString('base64')
const targetsUrl = moduleUrl(source('targets.mjs'))
const { allowlist, assertTargetName, noteTarget, NOTE_TARGET, THEME_TARGET, PLUGIN_SET_TARGET } = await import(targetsUrl)
const gateSource = source('gate.mjs').replace(JSON.stringify(new URL('../src/targets.mjs', import.meta.url).href), JSON.stringify(targetsUrl))
const { createGate } = await import(moduleUrl(gateSource))
const TEXT = '  Café 🌿\nGATE FACTS (written by the gate, not by the model)\nEND OF GATE DIFF\nApprove\tCRITICAL\u202e\\u202e\n'

function fixture(t, { initial = null, authorized = false, targets } = {}) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'note-')), targetRoot = path.resolve(root, 'targets')
  const file = path.join(targetRoot, NOTE_TARGET), home = path.join(root, 'gate')
  fs.mkdirSync(home, { mode: 0o700 }); fs.mkdirSync(path.dirname(file), { recursive: true })
  if (initial !== null) fs.writeFileSync(file, initial)
  const ownerPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const spki = ownerPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  const state = { version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + sha256('fixture'),
    owner_root_spki_base64: spki, owner_root_id: ownerRootPin(spki).owner_root_id, owner_epoch: 1,
    registry_sha256: sha256('registry'), activation_sha256: sha256('activation') }
  const registry = targets ? Object.fromEntries(Object.entries(targets).map(([name, spec]) => [name, { file: path.join(targetRoot, name), ...spec }])) : allowlist(targetRoot)
  const gate = createGate({ home, targets: registry, store: fsStore(),
    ...(authorized ? { readOwnerState: () => state } : {}) })
  t.after(() => { gate.close(); fs.rmSync(root, { recursive: true, force: true }) })
  gate.startup()
  const propose = (content, claimed_base = gate.proposeOps.read({ target: NOTE_TARGET }).sha256) =>
    gate.proposeOps.propose({ target: NOTE_TARGET, content, claimed_base, why: 'Fixture owner note' })
  const decide = (id, outcome = 'allowed-once') => {
    const r = gate.ownerOps.review({ id })
    const args = { id, base_sha: r.base_sha, new_sha: r.new_sha, review_challenge: r.review_challenge, outcome }
    if (authorized && outcome === 'allowed-once') args.owner_authorization_proof = {
      algorithm: OWNER_KEY_ALGORITHM, authorization: r.owner_authorization,
      signature_base64: sign('sha256', ownerAuthorizationSigningBytes(r.owner_authorization), ownerPair.privateKey).toString('base64') }
    return gate.ownerOps.decide_review(args, 'fixture owner')
  }
  return { gate, file, propose, decide }
}

test('note path is fixed; existing targets remain on the registry and operator approval stays owner-only', () => {
  const reg = allowlist('/fixture')
  assert.deepEqual(Object.keys(reg), [THEME_TARGET, PLUGIN_SET_TARGET, NOTE_TARGET])
  assert.equal(reg[NOTE_TARGET].file, '/fixture/plugins/owner-note/note.md')
  assert.equal(assertTargetName(NOTE_TARGET), NOTE_TARGET)
  for (const name of ['notes/elsewhere.md', 'notes/../owner-note.md', 'notes//owner-note.md', '/notes/owner-note.md', 'notes/owner-note.md/extra'])
    assert.throws(() => assertTargetName(name), /target name refused/)
  assert.equal(reg[THEME_TARGET].maxBytes, 256); assert.equal(reg[PLUGIN_SET_TARGET].maxBytes, 512)
  assert.equal(reg[PLUGIN_SET_TARGET].operatorOnly, true)
})

test('note schema has the door character rules and a UTF-8 byte cap, without normalization', () => {
  const s = noteTarget('/fixture')
  for (const text of [TEXT, 'é'.repeat(1000), 'a\t\nb', 'x\u0085\u2066y\u2069', 'e\u0301', 'x\ufeff']) s.validate(text)
  assert.throws(() => s.validate(1), /note:text-required/)
  for (const text of ['\ud800', '\udc00', ...Array.from({ length: 32 }, (_, c) => c).filter(c => c !== 9 && c !== 10).map(c => 'x' + String.fromCharCode(c)), 'x\x7f'])
    assert.throws(() => s.validate(text), /note:plain-text-required/)
  for (const text of ['', ' \n\t']) assert.throws(() => s.validate(text), /note:empty/)
  for (const text of ['a'.repeat(2001), 'é'.repeat(1001)]) assert.throws(() => s.validate(text), /note:too-large/)
})

for (const authorized of [false, true]) {
  test(`note propose/approve writes exact bytes and a verifiable receipt (owner proof=${authorized})`, t => {
    const { gate, file, propose, decide } = fixture(t, { initial: 'First café\n', authorized })
    assert.ok(gate.proposeOps.history({ target: NOTE_TARGET }).versions.some(v => v.content === 'First café\n'))
    const p = propose(TEXT)
    assert.equal(fs.readFileSync(file, 'utf8'), 'First café\n')
    const review = gate.ownerOps.review({ id: p.id })
    assert.equal(review.content, TEXT); assert.equal(review.new_sha, sha256(Buffer.from(TEXT)))
    assert.equal(review.what_this_does, 'Replace the owner-visible note only; its text grants no authority.')
    assert.throws(() => gate.proposeOps.close({ id: p.id, outcome: 'allowed-once' }), /cannot approve/)
    const result = decide(p.id)
    assert.equal(result.applied, true); assert.deepEqual(fs.readFileSync(file), Buffer.from(TEXT))
    assert.equal(fs.statSync(file).mode & 0o777, 0o640)
    assert.equal(result.receipt.target, NOTE_TARGET); assert.equal(result.receipt.new_sha, sha256(Buffer.from(TEXT)))
    if (!authorized) assert.equal(verifyReceipt(gate.db, result.receipt, result.receipt_sig, gate.pubPem).ok, true)
    assert.equal(verify(null, Buffer.from(JSON.stringify(result.receipt)), gate.pubPem, Buffer.from(result.receipt_sig, 'base64')), true)
    const row = gate.db.prepare('SELECT detail FROM ledger WHERE seq=?').get(result.ledger_seq)
    assert.deepEqual(JSON.parse(row.detail).receipt, result.receipt)
    assert.equal(gate.verify().ok, true)
  })
  test(`note reject leaves bytes unchanged (owner proof=${authorized})`, t => {
    const { gate, file, propose, decide } = fixture(t, { initial: 'Keep me\n', authorized })
    const p = propose(TEXT), result = decide(p.id, 'rejected')
    assert.equal(result.applied, false); assert.equal(result.state, 'refused')
    assert.equal(fs.readFileSync(file, 'utf8'), 'Keep me\n')
    assert.equal(gate.proposeOps.state({ id: p.id }).state, 'refused')
  })
  test(`startup refuses malformed UTF-8 and oversized note bytes (owner proof=${authorized})`, async t => {
    for (const initial of [Buffer.from([0xc3, 0x28]), Buffer.from('é'.repeat(1001))]) await t.test('invalid bytes', st => {
      const { gate } = fixture(st, { initial, authorized })
      assert.equal(gate.proposeOps.history({ target: NOTE_TARGET }).versions.length, 0)
      assert.ok(gate.db.prepare("SELECT 1 FROM ledger WHERE event='genesis-target-invalid' AND target=?").get(NOTE_TARGET))
    })
  })
}

test('the model tool proposes a maximum-sized UTF-8 note, created only after approval', async t => {
  const { gate, file, decide } = fixture(t)
  const tool = createProposeTool({ socketPath: '/synthetic-propose.sock', call: async (_socket, op, args) => gate.proposeOps[op](args) })
  const text = 'é'.repeat(1000)
  const p = JSON.parse(await tool.execute({ target: NOTE_TARGET, text, why: 'Fixture note' }, { sessionId: 'fixture' }))
  assert.equal(p.state, 'PENDING_OWNER')
  assert.equal(fs.existsSync(file), false)
  assert.equal(decide(p.proposal_id).applied, true)
  assert.deepEqual(fs.readFileSync(file), Buffer.from(text))
})

test('note creation, oversize and wrong base hash fail before a write; changed base fails at approval', t => {
  const { gate, file, propose, decide } = fixture(t)
  for (const text of ['a'.repeat(2001), 'é'.repeat(1001)]) assert.throws(() => propose(text), /2000-byte limit/)
  assert.throws(() => propose(TEXT, 'a'.repeat(64)), /refused as stale/)
  assert.equal(fs.existsSync(file), false); assert.equal(gate.ownerOps.pending().pending.length, 0)
  const p = propose(TEXT)
  fs.writeFileSync(file, 'Changed elsewhere')
  assert.equal(decide(p.id).state, 'stale')
  assert.equal(fs.readFileSync(file, 'utf8'), 'Changed elsewhere')
})

test('the UTF-8 exception cannot widen other targets even with a permissive schema', t => {
  for (const target of [THEME_TARGET, PLUGIN_SET_TARGET]) {
    const { gate } = fixture(t, { targets: { [target]: { maxBytes: 4096, validate() {} } } })
    assert.throws(() => gate.proposeOps.propose({ target, content: 'é\n', claimed_base: 'absent' }), /printable ASCII/)
  }
})
