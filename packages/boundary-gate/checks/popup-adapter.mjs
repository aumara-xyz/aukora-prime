// L2 popup adapter (apps/aukora-desktop createGateOwnerAdapter) against a REAL gate served on REAL unix sockets.
// Approve applies only through OWNER review/decide_review with a signed receipt; Refuse changes nothing; the
// PROPOSE socket (the agent's channel) can never drive the popup's approve; tampered reviews never arm Approve.
// GATE_POPUP_MUTANT removes one adapter guard in memory to prove these checks bite.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash, verify as edVerify } from 'node:crypto'
import { accent, ACCENT, accentTarget, memoryStore, tmpHome } from './support/fixture.mjs'
import { loadOwnerSecret, rotateBearer } from '../src/secrets.mjs'
import { createGate } from '../src/gate.mjs'
import { serveGate } from '../src/server.mjs'

const adapterUrl = new URL('../../../apps/aukora-desktop/aumlok-signer-airlock.mjs', import.meta.url)
async function loadAdapter() {
  const mutant = process.env.GATE_POPUP_MUTANT
  if (!mutant) return (await import(adapterUrl.href)).createGateOwnerAdapter
  let src = fs.readFileSync(adapterUrl, 'utf8'); const orig = src
  if (mutant === 'no-content-sha') src = src.replace("\n    || createHash('sha256').update(value.content, 'utf8').digest('hex') !== pending.new_sha) {", ') {')
  else if (mutant === 'no-spend') src = src.replace('      reviews.delete(uiQuestionId) // Spend', '      // Spend')
  else if (mutant === 'no-visible') src = src.replace('if (disposed || stillVisible() !== true) {', 'if (disposed) {')
  else if (mutant === 'receipt-unchecked') src = src.replace('|| r.base_sha !== review.base_sha || r.new_sha !== review.new_sha || r.pubkey_fp !== review.pubkey_fp', '')
  else throw new Error('unknown mutant')
  assert.notEqual(src, orig, 'mutant must change the source')
  src = src.replace(/from (['"])(\.[^'"]+)\1/gu, (_m, _q, rel) => `from ${JSON.stringify(new URL(rel, adapterUrl).href)}`)
  return (await import(`data:text/javascript;base64,${Buffer.from(src).toString('base64')}`)).createGateOwnerAdapter
}
const createGateOwnerAdapter = await loadAdapter()

async function served() {
  const clock = { t: Date.UTC(2026, 9, 4, 2) }, home = tmpHome(), owner = loadOwnerSecret(home)
  rotateBearer(home, owner, () => clock.t)
  const store = memoryStore({ [ACCENT]: accent('#FFD700') })
  const gate = createGate({ home, owner, targets: { [ACCENT]: accentTarget }, store, now: () => clock.t })
  gate.startup({ pid: 1 })
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-run-'))
  const srv = await serveGate(gate, { runDir, ownerHttpPort: 0 })
  const propose = (hex) => gate.proposeOps.propose({ target: ACCENT, content: accent(hex), why: 'TEST accent', claimed_base: gate.proposeOps.read({ target: ACCENT }).sha256, session: 's' })
  return { gate, store, clock, srv, propose, now: () => clock.t }
}

test('approve: exact stored bytes reviewed, applied once through OWNER decide_review, signed receipt matches', async () => {
  const { gate, store, srv, propose, now } = await served()
  try {
    const p = propose('#1E90FF')
    const a = createGateOwnerAdapter({ socketPath: srv.ownerSocket, now })
    const q = await a.pending()
    assert.equal(q.mode, 'boundary-gate'); assert.equal(q.approveAvailable, true); assert.equal(q.pending.id, p.id)
    assert.equal(q.review.content, accent('#1E90FF')); assert.ok(q.text.includes(accent('#1E90FF')))
    assert.equal(q.textDigest, createHash('sha256').update('aukora:approval-words:v1\0' + q.text, 'utf8').digest('hex'))
    assert.equal(await a.pending(), null, 'one live question at a time')
    const out = await a.decide(q.uiQuestionId, true, () => true)
    assert.equal(out.state, 'applied'); assert.equal(out.applied, true)
    assert.equal(store.read(ACCENT).toString(), accent('#1E90FF'))
    assert.equal(out.receipt.approver, 'owner via owner.sock (local; 0600 gate user/root only)')
    assert.ok(edVerify(null, Buffer.from(JSON.stringify(out.receipt)), gate.pub, Buffer.from(out.receipt_sig, 'base64')))
    const again = await a.decide(q.uiQuestionId, true, () => true)
    assert.equal(again.applied, false); assert.equal(again.reason, 'gate:question-not-pending', 'a spent question cannot be replayed')
    assert.equal(gate.verify().ok, true)
  } finally { await srv.close() }
})

test('refuse changes nothing; hidden card sends nothing; spent question cannot be reused', async () => {
  const { gate, store, srv, propose, now } = await served()
  try {
    const before = store.read(ACCENT).toString()
    const p = propose('#00FF7F')
    const a = createGateOwnerAdapter({ socketPath: srv.ownerSocket, now })
    let q = await a.pending()
    const hidden = await a.decide(q.uiQuestionId, true, () => false)
    assert.equal(hidden.applied, false); assert.equal(hidden.state, 'unavailable')
    assert.equal(store.read(ACCENT).toString(), before)
    assert.equal(gate.ownerOps.pending().pending.length, 1, 'still pending after a hidden-card answer')
    q = await a.pending()
    const out = await a.decide(q.uiQuestionId, false, () => true)
    assert.equal(out.state, 'refused'); assert.equal(out.applied, false); assert.equal(out.reason, 'gate:owner-rejected')
    assert.equal(store.read(ACCENT).toString(), before, 'refuse wrote nothing')
    assert.equal(gate.proposeOps.state({ id: p.id }).state, 'refused')
    const again = await a.decide(q.uiQuestionId, true, () => true)
    assert.equal(again.applied, false)
    assert.equal(store.read(ACCENT).toString(), before)
  } finally { await srv.close() }
})

test('the PROPOSE socket (agent channel) cannot drive the popup; tampered review never arms Approve', async () => {
  const { gate, store, srv, propose, now } = await served()
  try {
    const before = store.read(ACCENT).toString()
    propose('#FF4500')
    const viaPropose = createGateOwnerAdapter({ socketPath: srv.proposeSocket, now })
    await assert.rejects(viaPropose.pending(), /gate:owner-refused/, 'propose socket has no pending/review')
    const real = (await import('../../../apps/aukora-desktop/aumlok-signer-airlock.mjs')).exchangeGateOwner
    const tamper = async (sock, op, args) => {
      const r = await real(sock, op, args)
      return op === 'review' ? { ...r, content: accent('#000000') } : r
    }
    const a = createGateOwnerAdapter({ socketPath: srv.ownerSocket, call: tamper, now })
    const q = await a.pending()
    assert.equal(q.approveAvailable, false, 'content not hashing to new_sha disables Approve')
    const out = await a.decide(q.uiQuestionId, true, () => true)
    assert.equal(out.applied, false); assert.equal(out.reason, 'gate:stored-byte-review-unavailable')
    assert.equal(store.read(ACCENT).toString(), before)
    const forged = async (sock, op, args) => {
      const r = await real(sock, op, args)
      return r && r.receipt ? { ...r, receipt: { ...r.receipt, new_sha: 'f'.repeat(64) } } : r
    }
    const b = createGateOwnerAdapter({ socketPath: srv.ownerSocket, call: forged, now })
    const q2 = await b.pending()
    const res = await b.decide(q2.uiQuestionId, true, () => true)
    assert.equal(res.state, 'unknown'); assert.equal(res.applied, null, 'a receipt that does not match the review is never reported as applied')
    assert.equal(gate.verify().ok, true)
  } finally { await srv.close() }
})
