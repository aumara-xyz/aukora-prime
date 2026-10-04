// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual G/H source join, one disposable SQLite fixture per scenario. Published RFC6979/RFC8032
// test keys only; no new keys, native authentication, transport or production enrollment.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { createGate } from '../../boundary-gate/src/gate.mjs'
import { sha256 } from '../../boundary-gate/src/ledger.mjs'
import { ownerRootPin } from '../src/index.mjs'
import { ownerAuthorizationSigningBytes, ownerAuthorizationDigest, ownerAuthorizationGateReview,
  verifyOwnerAuthorizationGateReceipt } from '../src/authorization.mjs'
import { createGateOwnerAuthorizationCaller } from '../../../apps/aukora-desktop/owner-key-bridge.mjs'

const b64url = hex => Buffer.from(hex, 'hex').toString('base64url')
const ownerFixture = createPrivateKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
  d: b64url('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'),
  x: b64url('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'),
  y: b64url('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299') } })
const ownerSpki = createPublicKey(ownerFixture).export({ format: 'der', type: 'spki' }).toString('base64')
const gateFixture = createPrivateKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519',
  d: b64url('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
  x: b64url('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a') } })
const gatePublic = createPublicKey(gateFixture)
const gateSpki = gatePublic.export({ format: 'der', type: 'spki' }).toString('base64')
const key = { priv: gateFixture, pub: gatePublic,
  pubPem: gatePublic.export({ format: 'pem', type: 'spki' }).toString(),
  fp: sha256(Buffer.from(gateSpki, 'base64')).slice(0, 16) }
const target = 'plugins/auma-theme/theme.json'
const oldBytes = '{"accent": "default"}', newBytes = '{"accent": "#102030"}'
const proof = authorization => ({ algorithm: 'p256-ecdsa-sha256', authorization,
  signature_base64: sign('sha256', ownerAuthorizationSigningBytes(authorization), ownerFixture).toString('base64') })
const native = async request => ({ status: 'signed', proof: proof(JSON.parse(request.wire)) })
const clone = value => JSON.parse(JSON.stringify(value))
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done }); return { promise, resolve } }

async function fixture(run, { nativeAction = native, transport, noRegistry = false } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aukora-owner-caller-'))
  let bytes = Buffer.from(oldBytes), writes = 0, time = 100000
  let state = { version: 1, kind: 'aukora-owner-state/v1', owner_subject: `aukora:1:${'1'.repeat(64)}`,
    owner_root_spki_base64: ownerSpki, owner_root_id: ownerRootPin(ownerSpki).owner_root_id,
    owner_epoch: 1, registry_sha256: 'e'.repeat(64), activation_sha256: 'f'.repeat(64) }
  const calls = [], nativeRequests = []
  const gate = createGate({ home, key, owner: {}, now: () => time,
    readOwnerState: noRegistry ? undefined : () => ({ ...state }),
    targets: { [target]: { entry: 'auma-theme', maxBytes: 256, schema: 'fixture theme',
      ownerCardLabel: 'ROUTINE', ownerCardAction: 'Change the fixture theme accent only.',
      validate: text => { if (!/^\{"accent": "(default|#[0-9A-F]{6})"\}$/u.test(text)) throw Error('fixture schema') } } },
    store: { read: () => Buffer.from(bytes), write: (_target, _spec, next) => { writes++; bytes = Buffer.from(next) } } })
  const call = async (op, args) => {
    calls.push({ op, args: clone(args) })
    const actual = () => gate.ownerOps[op](args, 'synthetic-owner-channel')
    return transport ? transport(op, args, actual) : actual()
  }
  const caller = createGateOwnerAuthorizationCaller({ callGateOwner: call, gateSpkiBase64: gateSpki,
    readOwnerState: () => ({ ...state }), nowMs: () => time,
    presentOwnerAction: typeof nativeAction === 'function' ? async request => {
      nativeRequests.push(request); return nativeAction(request)
    } : undefined })
  const proposal = gate.proposeOps.propose({ target, content: newBytes, why: 'Synthetic G/H source join',
    claimed_base: sha256(Buffer.from(oldBytes)) })
  try {
    await run({ caller, gate, calls, nativeRequests, proposal, home,
      get writes() { return writes }, get bytes() { return bytes },
      get state() { return state }, set state(next) { state = next },
      get time() { return time }, set time(next) { time = next },
      changeBytes: text => { bytes = Buffer.from(text) } })
  } finally { caller.dispose(); gate.close(); fs.rmSync(home, { recursive: true, force: true }) }
}

test('actual caller and H gate commit one exact owner proof before effect and authenticate v3 acknowledgement', async () => {
  await fixture(async f => {
    const question = await f.caller.review(f.proposal.id)
    assert.equal(question.status, 'review-ready'); assert.equal(question.grants_authority, false)
    assert.equal(question.review.content, newBytes)
    const result = await f.caller.decide(question.question_id, 'allowed-once', () => true)
    assert.equal(result.status, 'applied'); assert.equal(result.applied, true); assert.equal(result.grants_authority, false)
    assert.equal(result.retained_history, 'H/D/E-verification-required')
    assert.equal(f.writes, 1); assert.equal(f.bytes.toString(), newBytes)
    assert.equal(f.nativeRequests[0].review.content, newBytes)
    const args = f.calls.find(c => c.op === 'decide_review').args
    assert.deepEqual(Object.keys(args), ['id', 'base_sha', 'new_sha', 'review_challenge', 'outcome', 'owner_authorization_proof'])
    const c = f.gate.db.prepare('SELECT * FROM owner_authorization_consumptions').get()
    assert.equal(c.proof_text, JSON.stringify(args.owner_authorization_proof))
    assert.equal(c.authorization_id, result.receipt.owner_authorization.authorization_id)
    assert.equal(c.proof_sha256, result.receipt.owner_authorization.proof_sha256)
    assert(c.issue_seq < c.consume_seq && c.consume_seq < result.ledger_seq)
    assert.equal(f.gate.db.prepare('SELECT state FROM owner_authorization_reviews').get().state, 'spent')
    assert.equal(f.gate.verify().ok, true)
    assert.throws(() => f.gate.ownerOps.decide_review(args), /single use|replay/u)
    assert.equal((await f.caller.decide(question.question_id, 'allowed-once', () => true)).applied, false)
    assert.equal(f.writes, 1)
    assert(!fs.existsSync(path.join(f.home, 'receipt-ed25519.pem')))
    assert(!fs.existsSync(path.join(f.home, 'owner-secret.json')))
  })
})

test('full review bytes, exact body/digest, gate identity and clock are checked before native presentation', async () => {
  for (const mutate of [r => { r.content = oldBytes }, r => { r.owner_authorization.target = 'plugins/other/theme.json' },
    r => { r.authorization_digest = '0'.repeat(64) }, r => { r.gate_pubkey_sha256 = '0'.repeat(64) },
    r => { r.review_issued_at_ms++ }, r => { r.approved = true }, r => { r.diff += '\u202e' },
    r => {
      // A fully internally consistent returned row must still match the caller's selected proposal.
      r.id = '11234567-89ab-4cde-8123-456789abcdef'
      r.owner_authorization = { ...r.owner_authorization, proposal_id: r.id }
      r.authorization_digest = ownerAuthorizationDigest(r.owner_authorization)
    }]) {
    await fixture(async f => {
      assert.equal((await f.caller.review(f.proposal.id)).status, 'unavailable')
      assert.equal(f.writes, 0); assert.equal(f.nativeRequests.length, 0)
      assert.equal(f.calls.filter(c => c.op === 'decide_review').length, 0)
    }, { transport: (op, _args, actual) => { const r = actual(); if (op === 'review') mutate(r); return r } })
  }
})

test('missing custody, substituted proof, legacy approval and stale actual target never authorize effects', async () => {
  const custodyUnavailable = async () => ({ status: 'unavailable', reason: 'owner-key:secure-custody-join-unavailable' })
  for (const nativeAction of [undefined, custodyUnavailable,
    async () => ({ approved: true, local_seed: 'not-a-key' }), async request => {
      const a = JSON.parse(request.wire); a.challenge = '0'.repeat(64); return { status: 'signed', proof: proof(a) }
    }]) {
    // undefined deliberately means no native mount, rather than fixture's default signer.
    await fixture(async f => {
      const q = await f.caller.review(f.proposal.id), result = await f.caller.decide(q.question_id, 'allowed-once', () => true)
      assert.equal(result.applied, false); assert.equal(f.writes, 0)
      assert.equal(f.calls.filter(c => c.op === 'decide_review').length, 0)
      if (nativeAction === custodyUnavailable) assert.equal(result.reason, 'owner-key:secure-custody-join-unavailable')
    }, { nativeAction: nativeAction ?? null })
  }
  await fixture(async f => {
    const q = await f.caller.review(f.proposal.id); f.changeBytes('{"accent": "#112233"}')
    const result = await f.caller.decide(q.question_id, 'allowed-once', () => true)
    // Sent decision uncertainty is never converted to a safe-to-retry assertion.
    assert.equal(result.status, 'unknown'); assert.equal(result.applied, null); assert.equal(f.writes, 0)
    assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 0)
    assert.equal(f.gate.db.prepare('SELECT state FROM owner_authorization_reviews').get().state, 'invalidated')
  })
})

test('inflight serialization, cancellation, disposal, epoch and expiry changes prevent dispatch; sent cancellation is unknown', async () => {
  for (const change of ['forget', 'dispose', 'epoch', 'expiry', 'hidden']) {
    const wait = deferred(); let presented
    await fixture(async f => {
      const q = await f.caller.review(f.proposal.id); let visible = true
      const pending = f.caller.decide(q.question_id, 'allowed-once', () => visible)
      assert.equal((await f.caller.review(f.proposal.id)).reason, 'owner-authorization:caller-busy-or-disposed')
      if (change === 'forget') f.caller.forget(q.question_id)
      if (change === 'dispose') f.caller.dispose()
      if (change === 'epoch') f.state = { ...f.state, owner_epoch: 2 }
      if (change === 'expiry') f.time = q.review.review_expires
      if (change === 'hidden') visible = false
      wait.resolve(await native(presented))
      assert.equal((await pending).applied, false)
      assert.equal(f.calls.filter(c => c.op === 'decide_review').length, 0); assert.equal(f.writes, 0)
    }, { nativeAction: request => { presented = request; return wait.promise } })
  }
  const wait = deferred(); let entered
  const dispatch = deferred()
  await fixture(async f => {
    const q = await f.caller.review(f.proposal.id)
    const pending = f.caller.decide(q.question_id, 'allowed-once', () => true)
    await dispatch.promise; assert.equal(entered.applied, true); f.caller.forget(q.question_id); wait.resolve(entered)
    assert.equal((await pending).status, 'unknown'); assert.equal(f.writes, 1)
    assert.equal((await f.caller.decide(q.question_id, 'allowed-once', () => true)).applied, false)
    assert.equal(f.calls.filter(c => c.op === 'decide_review').length, 1)
  }, { transport: async (op, _args, actual) => {
    const result = actual(); if (op !== 'decide_review') return result
    entered = result; dispatch.resolve(); return wait.promise
  } })
})

test('signed accepted-time acknowledgement survives expiry; tampered receipt/reference/signature stays unknown without retry', async () => {
  await fixture(async f => {
    const q = await f.caller.review(f.proposal.id)
    const result = await f.caller.decide(q.question_id, 'allowed-once', () => true)
    const prepared = ownerAuthorizationGateReview(q.review, f.state, gateSpki, 100000)
    const signedProof = f.calls.find(c => c.op === 'decide_review').args.owner_authorization_proof
    assert.equal(verifyOwnerAuthorizationGateReceipt(result.receipt, result.receipt_sig, signedProof,
      prepared, q.review.review_expires + 1).status, 'authenticated-gate-acknowledgement')
    // Freshly gate-signed fabricated acceptance time cannot backdate an expired/future owner proof.
    const bad = clone(result.receipt); bad.owner_accepted_at_ms = q.review.review_expires
    bad.applied_at = new Date(bad.owner_accepted_at_ms).toISOString()
    const badSig = sign(null, Buffer.from(JSON.stringify(bad)), gateFixture).toString('base64')
    assert.throws(() => verifyOwnerAuthorizationGateReceipt(bad, badSig, signedProof, prepared, q.review.review_expires + 1))
    for (const change of [r => { r.target = 'plugins/other/theme.json' }, r => { r.new_sha = '0'.repeat(64) },
      r => { r.owner_authorization.proof_sha256 = '0'.repeat(64) },
      r => { r.owner_consumption.review_issue.ledger_hash = '0'.repeat(64) }]) {
      const changed = clone(result.receipt); change(changed)
      const signature = sign(null, Buffer.from(JSON.stringify(changed)), gateFixture).toString('base64')
      assert.throws(() => verifyOwnerAuthorizationGateReceipt(changed, signature, signedProof, prepared, f.time))
    }
    const reordered = Object.fromEntries(Object.entries(result.receipt).reverse())
    reordered.owner_consumption = Object.fromEntries(Object.entries(reordered.owner_consumption).reverse())
    reordered.owner_consumption.review_issue = Object.fromEntries(Object.entries(reordered.owner_consumption.review_issue).reverse())
    assert.throws(() => verifyOwnerAuthorizationGateReceipt(reordered, result.receipt_sig, signedProof, prepared, f.time))
    const reorderedSig = sign(null, Buffer.from(JSON.stringify(reordered)), gateFixture).toString('base64')
    assert.equal(verifyOwnerAuthorizationGateReceipt(reordered, reorderedSig, signedProof, prepared, f.time).status,
      'authenticated-gate-acknowledgement')
  })
  for (const mutate of [r => { r.receipt_sig = 'A'.repeat(86) + '==' }, r => { r.receipt.new_sha = '0'.repeat(64) },
    r => { r.receipt.owner_authorization.proof_sha256 = '0'.repeat(64) }, r => { r.receipt.v = 2 },
    r => { r.receipt.owner_consumption.review_issue.ledger_hash = '0'.repeat(64) }]) {
    await fixture(async f => {
      const q = await f.caller.review(f.proposal.id), result = await f.caller.decide(q.question_id, 'allowed-once', () => true)
      assert.equal(result.status, 'unknown'); assert.equal(result.applied, null); assert.equal(f.writes, 1)
      assert.equal((await f.caller.decide(q.question_id, 'allowed-once', () => true)).applied, false)
      assert.equal(f.calls.filter(c => c.op === 'decide_review').length, 1)
    }, { transport: (op, _args, actual) => { const r = actual(); if (op === 'decide_review') mutate(r); return r } })
  }
})

test('rejection keeps exact old five-field grammar; missing registry and lost acknowledgement have no fallback', async () => {
  await fixture(async f => {
    const q = await f.caller.review(f.proposal.id), result = await f.caller.decide(q.question_id, 'rejected', () => true)
    assert.equal(result.status, 'refused'); assert.equal(result.applied, false)
    assert.equal(f.nativeRequests.length, 0); assert.equal(f.writes, 0)
    assert.deepEqual(Object.keys(f.calls.find(c => c.op === 'decide_review').args),
      ['id', 'base_sha', 'new_sha', 'review_challenge', 'outcome'])
    assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 0)
  }, { nativeAction: null })
  await fixture(async f => {
    assert.equal((await f.caller.review(f.proposal.id)).status, 'unavailable')
    assert.equal(f.writes, 0); assert.equal(f.nativeRequests.length, 0)
  }, { noRegistry: true })
  await fixture(async f => {
    const q = await f.caller.review(f.proposal.id), result = await f.caller.decide(q.question_id, 'allowed-once', () => true)
    assert.equal(result.status, 'unknown'); assert.equal(result.applied, null); assert.equal(f.writes, 1)
    assert.equal(f.calls.filter(c => c.op === 'decide_review').length, 1)
  }, { transport: (op, _args, actual) => { const r = actual(); if (op === 'decide_review') throw Error('lost ack'); return r } })
})
