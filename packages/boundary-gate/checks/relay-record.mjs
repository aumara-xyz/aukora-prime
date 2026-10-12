// Source checks for the gate's relay_record op: every AUMA relay post leaves a signed intent (digest, size) before it is
// sent and the server-assigned id after, in the same append-only ledger Aura collects. Closed shapes, auma only, no bodies.
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeGate } from './support/fixture.mjs'
import { AURA_NOTE_REFUSE } from '../src/gate.mjs'

const H = 'a'.repeat(64), M = 'b'.repeat(64)
const intent = (x = {}) => ({ phase: 'intent', author: 'auma', client_request_id: 'auma-1', body_sha256: H, bytes: 12, ...x })
const posted = (x = {}) => ({ ...intent(), phase: 'posted', message_id: M, cursor: '130', ...x })
const rows = g => g.db.prepare("SELECT seq, event, detail FROM ledger WHERE event LIKE 'relay-%' ORDER BY seq").all()

test('relay_record: intent then posted are signed ledger entries that carry digests and ids, never the body', () => {
  const { gate } = makeGate()
  const a = gate.proposeOps.relay_record(intent()); const b = gate.proposeOps.relay_record(posted())
  assert.equal(a.ok, true); assert.equal(b.seq, a.seq + 1)
  const r = rows(gate); assert.deepEqual(r.map(x => x.event), ['relay-intent', 'relay-posted'])
  assert.deepEqual(JSON.parse(r[1].detail), { author: 'auma', client_request_id: 'auma-1', body_sha256: H, bytes: 12, message_id: M, cursor: '130' })
  assert.equal(gate.verify().ok, true)
})
test('relay_record: posted without a matching intent is refused and writes nothing', () => {
  const { gate } = makeGate()
  assert.throws(() => gate.proposeOps.relay_record(posted()), /without a matching recorded intent/)
  gate.proposeOps.relay_record(intent())
  assert.throws(() => gate.proposeOps.relay_record(posted({ body_sha256: 'c'.repeat(64) })), /without a matching recorded intent/)
  assert.deepEqual(rows(gate).map(x => x.event), ['relay-intent'])
})
test('relay_record: closed shapes; only auma; size 1..2000; no body field accepted', () => {
  const { gate } = makeGate()
  for (const bad of [intent({ author: 'grok' }), intent({ author: 'peter' }), intent({ bytes: 0 }), intent({ bytes: 2001 }), intent({ body: 'hello' }),
    intent({ body_sha256: 'x' }), intent({ client_request_id: 'a b' }), { ...intent(), phase: 'decide' }, null, 'intent',
    posted({ message_id: 'short' }), posted({ cursor: '0' }), posted({ cursor: 7 })]) {
    assert.throws(() => gate.proposeOps.relay_record(bad), /relay_record/, JSON.stringify(bad))
  }
  assert.equal(rows(gate).length, 0)
})
test('relay_record is a harness (propose-channel) op only: the owner channel has no relay op and nothing approves through it', () => {
  const { gate } = makeGate()
  assert.equal(Object.hasOwn(gate.ownerOps, 'relay_record'), false)
  const r = gate.proposeOps.relay_record(intent())
  assert.deepEqual(Object.keys(r).sort(), ['hash', 'ok', 'seq'])
})

const notes = [
  { kind: 'buzz-wake', event_id: H, sender_pubkey: M, session_sha256: 'c'.repeat(64) },
  { kind: 'admission', digest_sha256: H },
  { kind: 'copresence-accepted', digest_sha256: M },
]
test('aura_note: each closed kind appends a signed caller report without approval or target writes', () => {
  const { gate, store } = makeGate()
  try {
    const before = gate.verify().entries
    assert.equal(Object.hasOwn(gate.ownerOps, 'aura_note'), false)
    for (const [i, note] of notes.entries()) {
      const result = gate.proposeOps.aura_note(note)
      const row = gate.db.prepare('SELECT * FROM ledger WHERE seq=?').get(result.seq)
      assert.deepEqual(result, { ok: true, seq: before + i + 1, hash: row.hash })
      assert.equal(row.event, 'aura-note')
      assert.equal(row.proposal, null); assert.equal(row.target, null)
      assert.deepEqual(JSON.parse(row.detail), { ...note, source: 'propose-socket',
        verification: 'caller-reported-unverified', grants_authority: false })
    }
    assert.equal(store.writes, 0)
    assert.equal(gate.db.prepare('SELECT count(*) AS n FROM proposals').get().n, 0)
    assert.equal(gate.verify().ok, true)
    assert.throws(() => gate.db.prepare("UPDATE ledger SET detail='{}' WHERE event='aura-note'").run(), /append-only/)
  } finally { gate.close() }
})
test('aura_note: unknown kinds, extra fields, accessors and non-digests write nothing', () => {
  const { gate } = makeGate({ limits: { proposeMaxPerWindow: 1024 } })
  let accessed = false
  const check = (input, code) => assert.throws(() => gate.proposeOps.aura_note(input), { code })
  try {
    const before = gate.verify()
    for (const kind of ['approve', 'relay-posted', 'toString', '', null, undefined]) check({ kind, digest_sha256: H }, AURA_NOTE_REFUSE.KIND)
    for (const input of [null, [], 'admission', { get kind() { accessed = true; return 'admission' } }]) check(input, AURA_NOTE_REFUSE.KIND)
    for (const note of notes) {
      for (const extra of [{ body: 'private' }, { session: 'private' }, { owner_subject: 'aumlok:subject:owner' }, { grants_authority: true }, { [Symbol('extra')]: H }]) {
        check({ ...note, ...extra }, AURA_NOTE_REFUSE.SHAPE)
      }
      check(Object.assign(Object.create({ inherited: true }), note), AURA_NOTE_REFUSE.SHAPE)
      for (const field of Object.keys(note).filter(k => k !== 'kind')) {
        const missing = { ...note }; delete missing[field]; check(missing, AURA_NOTE_REFUSE.SHAPE)
        const accessor = { ...note }; Object.defineProperty(accessor, field, { get() { accessed = true; return H } })
        check(accessor, AURA_NOTE_REFUSE.SHAPE)
        const hidden = { ...note }; Object.defineProperty(hidden, field, { enumerable: false })
        check(hidden, AURA_NOTE_REFUSE.SHAPE)
        for (const value of [H.slice(1), H + '0', H.toUpperCase(), 'g'.repeat(64), H + '\n', '', null, 1, {}]) {
          check({ ...note, [field]: value }, AURA_NOTE_REFUSE.DIGEST)
        }
      }
    }
    assert.equal(accessed, false)
    assert.deepEqual(gate.verify(), before)
  } finally { gate.close() }
})
test('aura_note: valid and refused notes share the persistent propose budget', () => {
  const { gate, clock } = makeGate({ limits: { proposeMaxPerWindow: 2, proposeWindowMs: 1000 } })
  try {
    gate.proposeOps.aura_note(notes[0])
    assert.throws(() => gate.proposeOps.aura_note({ kind: 'approve' }), { code: AURA_NOTE_REFUSE.KIND })
    assert.equal(gate.db.prepare('SELECT used FROM propose_budget').get().used, 2)
    const before = gate.verify()
    assert.throws(() => gate.proposeOps.aura_note(notes[1]), /budget exhausted/)
    assert.throws(() => gate.proposeOps.selfcheck({ result: null }), /budget exhausted/)
    assert.deepEqual(gate.ownerOps.verify(), before)
    clock.t += 1000
    assert.equal(gate.proposeOps.aura_note(notes[2]).ok, true)
  } finally { gate.close() }
})
