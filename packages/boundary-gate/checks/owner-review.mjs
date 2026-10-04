// Owner review / decide_review (L2 popup seam). In-process gate, synthetic accent target, in-memory store,
// controllable clock. GATE_REVIEW_MUTANT removes one guard in memory to prove these checks bite.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { verify as edVerify } from 'node:crypto'
import { accent, ACCENT, accentTarget, memoryStore, tmpHome } from './support/fixture.mjs'
import { loadOwnerSecret, rotateBearer } from '../src/secrets.mjs'

const gateUrl = new URL('../src/gate.mjs', import.meta.url)
async function loadCreateGate() {
  const mutant = process.env.GATE_REVIEW_MUTANT
  if (!mutant) return (await import(gateUrl.href)).createGate
  let src = fs.readFileSync(gateUrl, 'utf8'); const orig = src
  if (mutant === 'consume-late') src = src.replace('    if (id !== null) reviews.delete(id)\n', '').replace('    return ownerDecide({ id, outcome: args.outcome }, approver)\n  }', '    reviews.delete(id)\n    return ownerDecide({ id, outcome: args.outcome }, approver)\n  }')
  else if (mutant === 'no-challenge-check') src = src.replace("!timingSafeEqual(Buffer.from(args.review_challenge, 'hex'), Buffer.from(stored.challenge, 'hex'))", 'false')
  else if (mutant === 'no-sha-check') src = src.replace("if (args.base_sha !== stored.base_sha || args.new_sha !== stored.new_sha || p.base_sha !== stored.base_sha || p.new_sha !== stored.new_sha) refuse('base/new do not match the reviewed proposal')", '')
  else throw new Error('unknown mutant')
  assert.notEqual(src, orig, 'mutant must change the source')
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, rel) => `from ${JSON.stringify(new URL(rel, gateUrl).href)}`)
  return (await import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)).createGate
}
const createGate = await loadCreateGate()
function makeGate() {
  const clock = { t: Date.UTC(2026, 9, 4, 2) }, home = tmpHome(), owner = loadOwnerSecret(home)
  rotateBearer(home, owner, () => clock.t)
  const store = memoryStore({ [ACCENT]: accent('#FFD700') })
  const gate = createGate({ home, owner, targets: { [ACCENT]: accentTarget }, store, now: () => clock.t })
  gate.startup({ pid: 1 })
  return { gate, store, clock }
}
const propose = (g, hex) => g.proposeOps.propose({ target: ACCENT, content: accent(hex), why: 'TEST accent', claimed_base: g.proposeOps.read({ target: ACCENT }).sha256, session: 's' })
const decide = (g, r, outcome, over = {}) => g.ownerOps.decide_review({ id: r.id, base_sha: r.base_sha, new_sha: r.new_sha, review_challenge: r.review_challenge, outcome, ...over }, 'owner-socket')

test('review gives full stored bytes/diff and a fresh challenge; approve applies once with a signed receipt', () => {
  const { gate, store, clock } = makeGate()
  const p = propose(gate, '#1E90FF')
  const r = gate.ownerOps.review({ id: p.id })
  assert.equal(r.version, 1); assert.equal(r.content, accent('#1E90FF')); assert.equal(r.diff, p.diff); assert.equal(r.displayable, true)
  assert.match(r.review_challenge, /^[0-9a-f]{64}$/); assert.equal(r.review_expires, Math.min(p.expires, clock.t + 120000)); assert.equal(r.pubkey_fp, gate.fp)
  assert.notEqual(gate.ownerOps.review({ id: p.id }).review_challenge, r.review_challenge, 'each review mints a new challenge')
  const r2 = gate.ownerOps.review({ id: p.id })
  assert.throws(() => decide(gate, r2, 'allowed-once', { review_challenge: r.review_challenge }), /challenge mismatch/, 'only the latest challenge counts')
  const r3 = gate.ownerOps.review({ id: p.id })
  const out = decide(gate, r3, 'allowed-once')
  assert.equal(out.applied, true); assert.equal(store.read(ACCENT).toString(), accent('#1E90FF'))
  assert.equal(out.receipt.approver, 'owner-socket')
  assert.ok(edVerify(null, Buffer.from(JSON.stringify(out.receipt)), gate.pub, Buffer.from(out.receipt_sig, 'base64')))
  assert.throws(() => decide(gate, r3, 'allowed-once'), /no live review challenge/, 'replay with a spent challenge refused')
  assert.equal(gate.verify().ok, true)
})

test('refuse changes nothing; wrong/forged/expired/mismatched decisions are refused and consume the challenge', () => {
  const { gate, store, clock } = makeGate()
  const before = store.read(ACCENT).toString()
  const p = propose(gate, '#1E90FF')
  let r = gate.ownerOps.review({ id: p.id })
  assert.throws(() => decide(gate, r, 'allowed-once', { review_challenge: 'a'.repeat(64) }), /challenge mismatch/)
  assert.throws(() => decide(gate, r, 'allowed-once'), /no live review challenge/, 'a failed attempt consumed the challenge')
  r = gate.ownerOps.review({ id: p.id })
  assert.throws(() => decide(gate, r, 'allowed-once', { new_sha: 'b'.repeat(64) }), /do not match/)
  r = gate.ownerOps.review({ id: p.id })
  assert.throws(() => decide(gate, r, 'allowed-once', { extra: 1 }), /takes exactly/)
  r = gate.ownerOps.review({ id: p.id })
  assert.throws(() => decide(gate, r, 'approved'), /outcome must be/)
  r = gate.ownerOps.review({ id: p.id }); clock.t += 120001
  assert.throws(() => decide(gate, r, 'allowed-once'), /challenge expired/)
  assert.equal(store.read(ACCENT).toString(), before)
  r = gate.ownerOps.review({ id: p.id })
  const out = decide(gate, r, 'rejected')
  assert.equal(out.applied, false); assert.equal(out.state, 'refused'); assert.equal(store.read(ACCENT).toString(), before)
  assert.throws(() => gate.ownerOps.review({ id: p.id }), /proposal is refused/)
})

test('the propose channel has no review or decide_review, and cannot approve', () => {
  const { gate } = makeGate()
  for (const op of ['review', 'decide_review', 'approve', 'decide']) assert.equal(Object.hasOwn(gate.proposeOps, op), false, op)
  const p = propose(gate, '#1E90FF')
  assert.throws(() => gate.proposeOps.close({ id: p.id, outcome: 'allowed-once' }), /cannot approve/)
})
