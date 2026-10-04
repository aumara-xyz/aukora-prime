// Source checks for the gate's relay_record op: every AUMA relay post leaves a signed intent (digest, size) before it is
// sent and the server-assigned id after, in the same append-only ledger Aura collects. Closed shapes, auma only, no bodies.
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeGate } from './support/fixture.mjs'

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
