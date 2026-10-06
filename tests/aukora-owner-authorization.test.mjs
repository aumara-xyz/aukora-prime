// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable fixture keys only; these checks make no enrollment or custody claim.
import assert from 'node:assert/strict'
import { createHmac, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { Worker } from 'node:worker_threads'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { createLedger, gateCompletedResultDigest, keyFingerprint, openDb, sha256, signedEntryData,
  verifyCompletedGateCapture } from '../packages/boundary-gate/src/ledger.mjs'
import { THEME_TARGET, themeTarget } from '../packages/boundary-gate/src/targets.mjs'
import { OWNER_KEY_ALGORITHM, ownerRootPin } from '../packages/owner-key/src/index.mjs'
import { ownerAuthorizationDigest, ownerAuthorizationProofDigest, ownerAuthorizationProofText,
  ownerAuthorizationSigningBytes } from '../packages/owner-key/src/authorization.mjs'
import { gateCall, PROPOSE_OPS, proposeTheme } from '../plugins/aukora-auma-theme/lib/propose.mjs'
import { fixtureParent } from './fixtures/owner-effect-worker.mjs'

const BEFORE = '{"accent": "default"}'
const AFTER = '{"accent": "#112233"}'
const BASE_TIME = 1791072000000
const JOURNAL_ID = 'aukora-gate-pilot'

function fixture(t, options = {}) {
  const home = mkdtempSync(path.join(fixtureParent(), 'owner-authorization-'))
  const gatePair = generateKeyPairSync('ed25519')
  const ownerPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const ownerSpki = ownerPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  const f = {
    home, dbPath: path.join(home, 'gate.db'), clock: BASE_TIME, current: Buffer.from(BEFORE), writes: [],
    ownerPair, gatePair, beforeWrite: null, gate: null, readFailures: 0,
    ownerState: { version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + sha256('fixture-owner'),
      owner_root_spki_base64: ownerSpki, owner_root_id: ownerRootPin(ownerSpki).owner_root_id, owner_epoch: 1,
      registry_sha256: sha256('independently-configured-fixture-registry'),
      activation_sha256: sha256('independently-configured-fixture-activation') },
  }
  const key = { priv: gatePair.privateKey, pub: gatePair.publicKey,
    pubPem: gatePair.publicKey.export({ format: 'pem', type: 'spki' }).toString(), fp: keyFingerprint(gatePair.publicKey) }
  f.key = key
  const store = {
    read: () => {
      if (f.readFailures > 0) { f.readFailures--; throw new Error('fixture target unreadable') }
      return Buffer.from(f.current)
    },
    write: (target, _spec, bytes, id) => {
      f.beforeWrite?.({ target, bytes: Buffer.from(bytes), id })
      f.writes.push({ target, id, bytes: Buffer.from(bytes) })
      f.current = Buffer.from(bytes)
    },
  }
  if (options.legacy) {
    const old = new DatabaseSync(f.dbPath)
    old.exec(`CREATE TABLE proposals(id TEXT PRIMARY KEY, kind TEXT, target TEXT, base_sha TEXT, new_sha TEXT, diff TEXT,
      why TEXT, session TEXT, call_id TEXT, created INTEGER, expires INTEGER, displayable INTEGER, state TEXT, note TEXT, updated INTEGER);
      CREATE TABLE blobs(sha TEXT PRIMARY KEY, target TEXT, bytes BLOB, first_seen TEXT);
      CREATE TABLE ledger(seq INTEGER PRIMARY KEY, at TEXT NOT NULL, event TEXT NOT NULL, proposal TEXT, target TEXT,
      base_sha TEXT, new_sha TEXT, detail TEXT, prev TEXT NOT NULL, hash TEXT NOT NULL, sig TEXT NOT NULL);`)
    f.historicalEntry = signedEntryData(createLedger(old, key, () => new Date(f.clock).toISOString())
      .append('historical-fixture', { detail: { receipt: { v: 2, approval_evidence_hmac: 'disposable-historical-fixture' } } }))
    old.close()
  }
  function makeGate() {
    const args = { home, key, owner: { bearer: 'disposable-fixture-only', hmacKey: sha256('disposable-fixture-hmac') }, db: openDb(f.dbPath), store,
      targets: { [THEME_TARGET]: { ...themeTarget(home), ...options.target } }, now: () => f.clock,
      limits: { rejectCooldownMs: 0, maxPerWindow: 100 } }
    if (options.iso) args.iso = () => options.iso(f)
    if (options.journalId !== null) args.journalId = options.journalId ?? JOURNAL_ID
    if (options.ownerStateMode !== 'missing') args.readOwnerState = options.readOwnerState
      ? () => options.readOwnerState(f) : () => f.ownerState
    if (options.ownerStateMode === 'null') args.readOwnerState = null
    try { return (options.createGate ?? createGate)(args) }
    catch (error) { args.db.close(); throw error }
  }
  t.after(() => { f.gate?.close() }) // Retain every synthetic fixture, including failed state.
  f.gate = makeGate()
  f.openGate = makeGate
  f.reopen = () => { f.gate.close(); f.gate = makeGate(); return f.gate }
  f.propose = (content = AFTER) => f.gate.proposeOps.propose({ target: THEME_TARGET, content,
    claimed_base: sha256(f.current), why: 'Fixture accent change', session: 'fixture', call_id: 'fixture-call' })
  f.review = proposal => f.gate.ownerOps.review({ id: proposal.id })
  return f
}

function proofFor(f, authorization) {
  return { algorithm: OWNER_KEY_ALGORITHM, authorization,
    signature_base64: sign('sha256', ownerAuthorizationSigningBytes(authorization), f.ownerPair.privateKey).toString('base64') }
}

function decision(review, proof, outcome = 'allowed-once') {
  const args = { id: review.id, base_sha: review.base_sha, new_sha: review.new_sha,
    review_challenge: review.review_challenge, outcome }
  if (proof !== undefined) args.owner_authorization_proof = proof
  return args
}

function assertRefused(f, action) {
  const count = f.writes.length
  let result
  try { result = action() } catch (error) {
    assert.match(String(error.message), /refus|authoriz|owner.state|review|challenge|pending|spent|unavailable|epoch|replay|compare.and.set/i)
    assert.equal(f.writes.length, count)
    return
  }
  assert.equal(result?.applied, false, 'a denied operation must fail or return applied:false')
  assert.equal(f.writes.length, count)
}

function consumption(f, id) {
  return f.gate.db.prepare('SELECT * FROM owner_authorization_consumptions WHERE authorization_id=?').get(id)
}

function assertUnconsumedPending(f, review) {
  assert.equal(consumption(f, review.authorization_digest), undefined)
  assert.equal(f.gate.proposeOps.state({ id: review.id }).state, 'pending')
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE proposal=? AND event='owner-authorization-consumed'").get(review.id).n, 0)
  assert.equal(f.gate.db.prepare('SELECT state FROM owner_authorization_reviews WHERE authorization_id=?').get(review.authorization_digest).state, 'invalidated')
  assert.equal(f.writes.length, 0)
}

function commitFaultFixture(t, fault, create = createGate) {
  return fixture(t, { createGate: create, readOwnerState: f => {
    if (f.commitFault && f.gate?.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n) {
      if (fault === 'expiry') f.clock = f.commitDeadline
      else if (fault === 'async') return Promise.resolve(f.ownerState)
      else return { ...f.ownerState, owner_epoch: f.ownerState.owner_epoch + 1 }
    }
    return f.ownerState
  } })
}

async function inMemoryGateMutant(replacements) {
  const gateUrl = new URL('../packages/boundary-gate/src/gate.mjs', import.meta.url)
  let source = readFileSync(gateUrl, 'utf8')
  for (const [before, after] of replacements) {
    assert.ok(source.includes(before), 'named mutation must match the current guard')
    source = source.replace(before, after)
  }
  source = source.replace(/from\s+(['"])(\.[^'"]+)\1/g, (_match, quote, specifier) =>
    'from ' + quote + new URL(specifier, gateUrl).href + quote)
  return (await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'))).createGate
}

function captureExpectations(f) {
  return { journal_id: JOURNAL_ID, gate_public_key_pem: f.gatePair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    gate_pubkey_sha256: sha256(f.gatePair.publicKey.export({ type: 'spki', format: 'der' })) }
}

// Independent protocol preimages: deliberately do not call either production encoder.
function independentCompletedDigest(result) {
  const core = { applied: result.applied, state: result.state, entry: result.entry, receipt: result.receipt,
    receipt_sig: result.receipt_sig, ledger_seq: result.ledger_seq, ledger_hash: result.ledger_hash, message: result.message }
  return sha256(Buffer.from('aukora:gate-completed-result:v1\0' + JSON.stringify(core), 'utf8'))
}

function independentCaptureBytes(capture) {
  const wire = { version: capture.version, kind: capture.kind,
    source: { journal_id: capture.source.journal_id, position: capture.source.position, hash: capture.source.hash },
    proposal_id: capture.proposal_id, gate_pubkey_sha256: capture.gate_pubkey_sha256,
    completed_result_sha256: capture.completed_result_sha256 }
  return Buffer.from('aukora:gate-capture:v1\0' + JSON.stringify(wire), 'utf8')
}

function resignCapture(f, result) {
  result.gate_capture.capture.completed_result_sha256 = independentCompletedDigest(result)
  result.gate_capture.signature_base64 = sign(null, independentCaptureBytes(result.gate_capture.capture),
    f.gatePair.privateKey).toString('base64')
  assert.equal(verify(null, independentCaptureBytes(result.gate_capture.capture), f.gatePair.publicKey,
    Buffer.from(result.gate_capture.signature_base64, 'base64')), true)
  return result
}

function forbidPollingSignatures(f) {
  f.pollingSignReads = 0
  Object.defineProperty(f.key, 'priv', { enumerable: true, configurable: true, get() {
    f.pollingSignReads++
    throw new Error('fixture polling must not create a new signature')
  } })
}

function assertUnavailableCompletion(f, proposal) {
  const writes = f.writes.length, signatures = f.pollingSignReads
  const state = f.gate.proposeOps.state({ id: proposal.id })
  assert.equal(state.state, 'applied')
  assert.equal(state.gate_capture_status, 'UNAVAILABLE')
  for (const field of ['applied', 'entry', 'receipt', 'receipt_sig', 'gate_capture', 'message'])
    assert.equal(Object.hasOwn(state, field), false, 'unavailable evidence must not fabricate ' + field)
  assert.throws(() => verifyCompletedGateCapture(state, captureExpectations(f)))
  assert.equal(f.writes.length, writes)
  assert.equal(f.pollingSignReads, signatures)
}

test('review binds the exact G body to a durable signed issuance anchor', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal)
  const gateId = sha256(f.gatePair.publicKey.export({ format: 'der', type: 'spki' }))
  assert.equal(review.gate_pubkey_sha256, gateId)
  assert.equal(review.review_issued_at_ms, f.clock)
  assert.equal(review.authorization_digest, ownerAuthorizationDigest(review.owner_authorization))
  assert.deepEqual({ ...review.owner_authorization }, {
    after_sha256: proposal.new_sha, before_sha256: proposal.base_sha, challenge: review.review_challenge,
    expires_at_ms: review.review_expires, gate: gateId, issued_at_ms: f.clock,
    kind: 'aukora-owner-authorization/v1', operation: 'change', owner_epoch: f.ownerState.owner_epoch,
    owner_root_id: f.ownerState.owner_root_id, owner_subject: f.ownerState.owner_subject,
    proposal_id: proposal.id, target: THEME_TARGET, version: 1,
  })
  const row = f.gate.db.prepare('SELECT * FROM owner_authorization_reviews WHERE authorization_id=?').get(review.authorization_digest)
  assert.equal(row.state, 'live')
  assert.deepEqual(JSON.parse(row.authorization_text), { ...review.owner_authorization })
  assert.deepEqual(JSON.parse(row.owner_state_text), f.ownerState)
  assert.deepEqual(review.review_issue, { ledger_seq: row.issue_seq, ledger_hash: row.issue_hash })
  const issue = f.gate.db.prepare('SELECT * FROM ledger WHERE seq=?').get(row.issue_seq)
  assert.equal(issue.event, 'review-issued')
  assert.equal(issue.hash, row.issue_hash)
  assert.equal(JSON.parse(issue.detail).authorization_id, review.authorization_digest)
  assert.equal(JSON.parse(issue.detail).authorization_text, row.authorization_text)
  assert.equal(f.gate.verify().ok, true)
  assert.equal(f.writes.length, 0)
})

test('configured unavailable and asynchronous trusted owner state fail closed', async t => {
  const cases = [
    ['null reader', { readOwnerState: null, ownerStateMode: 'null' }],
    ['unavailable', { readOwnerState: () => null }],
    ['undefined state', { readOwnerState: () => undefined }],
    ['throwing reader', { readOwnerState: () => { throw new Error('trusted owner state unavailable') } }],
    ['promise', { readOwnerState: f => Promise.resolve(f.ownerState) }],
    ['thenable', { readOwnerState: f => ({ ...f.ownerState, then() { throw new Error('must not be awaited') } }) }],
    ['extra field', { readOwnerState: f => ({ ...f.ownerState, approved: true }) }],
  ]
  for (const [name, options] of cases) await t.test(name, st => {
    const f = fixture(st, options), proposal = f.propose()
    assertRefused(f, () => f.review(proposal))
    assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 0)
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'pending')
  })
})

test('a virgin unconfigured gate preserves the legacy one-click review and exact v2 receipt', t => {
  const f = fixture(t, { ownerStateMode: 'missing', journalId: null }), proposal = f.propose(), review = f.review(proposal)
  assert.equal(review.version, 2)
  assert.deepEqual(Object.keys(review), ['version', 'id', 'kind', 'target', 'base_sha', 'new_sha', 'content', 'diff',
    'from_to', 'clarity_label', 'what_this_does', 'model_note', 'displayable', 'created', 'expires',
    'review_challenge', 'review_expires', 'pubkey_fp'])
  const issue = f.gate.db.prepare("SELECT detail FROM ledger WHERE proposal=? AND event='review-issued'").get(proposal.id)
  assert.deepEqual(JSON.parse(issue.detail), { via: 'owner', review_expires: new Date(review.review_expires).toISOString() })
  assert.deepEqual(f.gate.proposeOps.log({}).entries.find(row => row.event === 'review-issued').detail, JSON.parse(issue.detail))
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_required').get().n, 0)
  const approver = 'owner.sock:legacy-fixture', result = f.gate.ownerOps.decide_review(decision(review), approver)
  assert.deepEqual(Object.keys(result), ['applied', 'state', 'entry', 'receipt', 'receipt_sig', 'ledger_seq', 'ledger_hash', 'message'])
  assert.deepEqual(Object.keys(result.receipt), ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha',
    'applied_at', 'approver', 'approval_evidence_hmac', 'pubkey_fp'])
  assert.equal(result.receipt.v, 2)
  assert.equal(result.receipt.approver, approver)
  assert.equal(result.receipt.approval_evidence_hmac, createHmac('sha256', Buffer.from(sha256('disposable-fixture-hmac'), 'hex'))
    .update(`${proposal.id}\n${proposal.base_sha}\n${proposal.new_sha}\n${approver}`).digest('base64'))
  assert.equal(verify(null, Buffer.from(JSON.stringify(result.receipt)), f.gatePair.publicKey, Buffer.from(result.receipt_sig, 'base64')), true)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 0)
  assert.equal(f.writes.length, 1)
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), approver))
})

test('configured enforcement latches without reading or activating the owner state and survives restart removal', t => {
  let reads = 0
  const options = { readOwnerState: () => { reads++; throw new Error('trusted owner state unavailable: fixture registry unreadable') } }
  const f = fixture(t, options)
  assert.equal(reads, 0, 'constructing enforcement must not activate or inspect the deferred owner profile')
  const marker = f.gate.db.prepare('SELECT * FROM owner_authorization_required').get()
  const row = f.gate.db.prepare('SELECT * FROM ledger WHERE seq=?').get(marker.require_seq)
  assert.equal(row.event, 'owner-authorization-required')
  assert.equal(row.hash, marker.require_hash)
  assert.equal(JSON.parse(row.detail).reason, 'trusted-reader-configured')
  assert.throws(() => f.gate.db.prepare('DELETE FROM owner_authorization_required').run(), /retained/)
  assert.throws(() => f.gate.db.prepare('UPDATE owner_authorization_required SET gate=?').run(sha256('other-gate')), /immutable/)
  const proposal = f.propose()
  assertRefused(f, () => f.review(proposal))
  options.ownerStateMode = 'missing'
  f.reopen()
  assertRefused(f, () => f.review(proposal))
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_required').get().n, 1)
  assert.equal(f.writes.length, 0)
})

test('signed G history blocks downgrade when enforcement and review snapshot tables are lost', t => {
  const options = {}, f = fixture(t, options), proposal = f.propose(), review = f.review(proposal)
  f.gate.db.exec('DROP TABLE owner_authorization_required; DROP TABLE owner_authorization_reviews')
  options.ownerStateMode = 'missing'
  f.reopen()
  assertRefused(f, () => f.review(proposal))
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture'))
  const marker = f.gate.db.prepare('SELECT * FROM owner_authorization_required').get()
  assert.equal(JSON.parse(f.gate.db.prepare('SELECT detail FROM ledger WHERE seq=?').get(marker.require_seq).detail).reason, 'retained-G-history')
  assert.equal(f.writes.length, 0)
})

test('configuration committed between legacy spend and write prevents the legacy effect', t => {
  const options = { ownerStateMode: 'missing' }, f = fixture(t, options), proposal = f.propose(), review = f.review(proposal)
  const originalExec = f.gate.db.exec.bind(f.gate.db)
  let armed = true
  f.gate.db.exec = sql => {
    const result = originalExec(sql)
    if (armed && sql === 'COMMIT' && f.gate.db.prepare("SELECT 1 FROM proposals WHERE state='applying'").get()) {
      armed = false
      options.ownerStateMode = undefined
      const configured = f.openGate()
      configured.close()
      options.ownerStateMode = 'missing'
    }
    return result
  }
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture'))
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_required').get().n, 1)
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event IN ('apply','revert-applied')").get().n, 0)
})

test('legacy startup between spend and effect cannot erase the applying fence and then permit writing', t => {
  const options = { ownerStateMode: 'missing' }, f = fixture(t, options), proposal = f.propose(), review = f.review(proposal)
  const originalExec = f.gate.db.exec.bind(f.gate.db)
  let armed = true
  f.gate.db.exec = sql => {
    const result = originalExec(sql)
    if (armed && sql === 'COMMIT' && f.gate.db.prepare("SELECT 1 FROM proposals WHERE state='applying'").get()) {
      armed = false
      const recovered = f.openGate()
      recovered.startup({ pid: 2 })
      recovered.close()
    }
    return result
  }
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture'))
  assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'failed')
  assert.equal(f.writes.length, 0)
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event IN ('apply','revert-applied')").get().n, 0)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM gate_completed_results').get().n, 0)
})

test('a G configuration winning the startup writer lock refuses a missing reader without changing retained uncertainty', t => {
  const options = { ownerStateMode: 'missing' }, f = fixture(t, options), proposal = f.propose()
  const originalExec = f.gate.db.exec.bind(f.gate.db)
  const originalGateSpki = f.gate.pub.export({ type: 'spki', format: 'der' })
  const snapshot = () => ({
    proposals: f.gate.db.prepare('SELECT * FROM proposals ORDER BY id').all(),
    blobs: f.gate.db.prepare('SELECT * FROM blobs ORDER BY sha').all(),
    latch: f.gate.db.prepare('SELECT * FROM owner_authorization_required ORDER BY singleton').all(),
    reviews: f.gate.db.prepare('SELECT * FROM owner_authorization_reviews ORDER BY gate,challenge').all(),
    consumptions: f.gate.db.prepare('SELECT * FROM owner_authorization_consumptions ORDER BY authorization_id').all(),
    ledger: f.gate.db.prepare('SELECT * FROM ledger ORDER BY seq').all(),
    completions: f.gate.db.prepare('SELECT * FROM gate_completed_results ORDER BY proposal_id').all(),
    budget: f.gate.db.prepare('SELECT * FROM propose_budget ORDER BY singleton').all(),
    gate_spki: f.gate.pub.export({ type: 'spki', format: 'der' }),
    current: Buffer.from(f.current), writes: f.writes.map(row => ({ ...row, bytes: Buffer.from(row.bytes) })),
  })
  let originalReview, originalProof, beforeRefusal
  let armed = true
  f.gate.db.exec = sql => {
    if (armed && sql === 'BEGIN IMMEDIATE') {
      armed = false
      options.ownerStateMode = undefined
      const configured = f.openGate()
      const review = configured.ownerOps.review({ id: proposal.id })
      originalReview = review
      originalProof = proofFor(f, review.owner_authorization)
      f.beforeWrite = ({ bytes }) => { f.current = bytes; throw new Error('fixture interrupted after bytes became present') }
      assert.throws(() => configured.ownerOps.decide_review(decision(review, originalProof), 'fixture-G-owner'), /fixture interrupted/)
      f.beforeWrite = null
      configured.close()
      options.ownerStateMode = 'missing'
      // The authorized concurrent setup committed first. Compare only the
      // refused outer startup against that exact retained state.
      beforeRefusal = snapshot()
    }
    return originalExec(sql)
  }
  assert.throws(() => f.gate.startup({ pid: 3 }), /owner authorization unavailable: trusted owner state is unconfigured/)
  assert.ok(beforeRefusal, 'the G setup must win before observing the refused startup')
  assert.deepEqual(snapshot(), beforeRefusal, 'refused startup must append, reconcile and effect nothing')
  assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applying')
  const retained = consumption(f, originalReview.authorization_digest)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 1)
  assert.equal(retained.proof_text, ownerAuthorizationProofText(originalProof))
  assert.equal(retained.proof_sha256, ownerAuthorizationProofDigest(originalProof))
  assert.equal(retained.gate, sha256(originalGateSpki))
  assert.deepEqual(f.gate.pub.export({ type: 'spki', format: 'der' }), originalGateSpki)
  assert.deepEqual({ ledger_seq: retained.issue_seq, ledger_hash: retained.issue_hash }, originalReview.review_issue)
  const spent = f.gate.db.prepare('SELECT * FROM owner_authorization_reviews WHERE authorization_id=?').get(retained.authorization_id)
  assert.equal(spent.state, 'spent')
  assert.equal(spent.spend_seq, retained.consume_seq)
  assert.equal(spent.spent_at_ms, retained.accepted_at_ms)
  assert.equal(verify('sha256', ownerAuthorizationSigningBytes(originalProof.authorization), f.ownerPair.publicKey,
    Buffer.from(originalProof.signature_base64, 'base64')), true, 'the retained original P256 proof remains valid')
  assert.equal(f.current.toString(), AFTER)
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event='genesis-target'").get().n, 0)
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event IN ('apply','revert-applied')").get().n, 0)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM gate_completed_results').get().n, 0)
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event='gate-start'").get().n, 0)
  assert.equal(f.writes.length, 0)
  assert.equal(f.gate.verify().ok, true)
})

test('legacy effect refuses a base changed after its durable spend', t => {
  const f = fixture(t, { ownerStateMode: 'missing' }), proposal = f.propose(), review = f.review(proposal)
  const originalExec = f.gate.db.exec.bind(f.gate.db)
  let armed = true
  f.gate.db.exec = sql => {
    const result = originalExec(sql)
    if (armed && sql === 'COMMIT' && f.gate.db.prepare("SELECT 1 FROM proposals WHERE state='applying'").get()) {
      armed = false
      f.current = Buffer.from('{"accent": "#445566"}')
    }
    return result
  }
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture'))
  assert.equal(f.writes.length, 0)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM gate_completed_results').get().n, 0)
})

test('the legacy write transaction serializes a concurrent configuration attempt', t => {
  const options = { ownerStateMode: 'missing' }, f = fixture(t, options), proposal = f.propose(), review = f.review(proposal)
  let blocked = false
  f.beforeWrite = () => {
    options.ownerStateMode = undefined
    try {
      const configured = f.openGate()
      configured.close()
      assert.fail('configuration must not commit across a held legacy writer lock')
    } catch (error) {
      assert.match(String(error.message), /locked|busy/)
      blocked = true
    } finally { options.ownerStateMode = 'missing' }
  }
  const original = f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture')
  assert.equal(blocked, true)
  assert.equal(original.receipt.v, 2)
  options.ownerStateMode = undefined
  const configured = f.openGate()
  configured.close()
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_required').get().n, 1)
  assert.deepEqual(f.gate.proposeOps.state({ id: proposal.id }), original)
})

test('a retained v2 capture authenticates original legacy bytes without a G owner proof', t => {
  const f = fixture(t, { ownerStateMode: 'missing' }), proposal = f.propose(), review = f.review(proposal)
  const original = f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture')
  assert.equal(original.receipt.v, 2)
  assert.equal(Object.hasOwn(original.receipt, 'owner_authorization'), false)
  assert.deepEqual(verifyCompletedGateCapture(original, captureExpectations(f)).source, original.gate_capture.capture.source)
  forbidPollingSignatures(f)
  assert.deepEqual(f.gate.proposeOps.state({ id: proposal.id }), original)
  assert.equal(f.pollingSignReads, 0)
  for (const mutate of [copy => { copy.receipt.owner_authorization = {} },
    copy => { copy.receipt.approval_evidence_hmac += '\n' }, copy => { copy.receipt.v = 3 },
    copy => { copy.receipt.pubkey_fp = 'f'.repeat(16) }]) {
    const copy = structuredClone(original)
    mutate(copy)
    assert.throws(() => verifyCompletedGateCapture(copy, captureExpectations(f)))
  }
})

test('legacy floor issuance and spend recheck facts at their final commit', async t => {
  for (const phase of ['issuance', 'spend']) await t.test(phase, st => {
    let floor = 1, armed = false
    const f = fixture(st, { ownerStateMode: 'missing', target: {
      reviewFacts: () => ({ from_to: 'GATE FACT: fixture release floor ' + floor, release_floor: { fixture: floor } }),
    }, iso: f => {
      if (armed && (phase === 'issuance' || f.gate.db.prepare("SELECT 1 FROM proposals WHERE state='applying'").get())) {
        armed = false
        floor = 2
      }
      return new Date(f.clock).toISOString()
    } })
    const proposal = f.propose()
    if (phase === 'issuance') {
      armed = true
      assertRefused(f, () => f.review(proposal))
      assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event='review-issued'").get().n, 0)
    } else {
      const review = f.review(proposal)
      armed = true
      assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture'))
      floor = 1
      assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'pending')
      assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event='decide'").get().n, 0)
    }
    assert.equal(f.writes.length, 0)
  })
})

test('legacy floor unavailable facts remain visible and cannot authorize an effect', t => {
  const f = fixture(t, { ownerStateMode: 'missing', target: {
    reviewFacts: () => { throw new Error('fixture release floor unreadable') },
  } }), proposal = f.propose(), review = f.review(proposal)
  assert.equal(review.version, 2)
  assert.equal(review.displayable, false)
  assert.match(review.what_this_does, /UNAVAILABLE/)
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture'))
  assert.equal(f.writes.length, 0)
})

test('legacy owner-channel identity and a review challenge cannot substitute for the G proof', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal)
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), 'owner.sock:legacy-principal'))
  assert.equal(consumption(f, review.authorization_digest), undefined)
  for (const op of ['approve', 'decide']) assert.equal(Object.hasOwn(f.gate.ownerOps, op), false)
  for (const op of ['approve', 'decide', 'review', 'decide_review', 'raise']) assert.equal(Object.hasOwn(f.gate.proposeOps, op), false)
})

test('every G authorization field is checked against the independent review', async t => {
  const changes = {
    after_sha256: () => sha256('other-after'), before_sha256: () => sha256('other-before'),
    challenge: () => sha256('other-challenge'), expires_at_ms: a => a.expires_at_ms - 1,
    gate: () => sha256('other-gate'), issued_at_ms: a => a.issued_at_ms + 1,
    kind: () => 'different-kind', operation: () => 'revert', owner_epoch: a => a.owner_epoch + 1,
    owner_root_id: () => sha256('other-root'), owner_subject: () => 'aukora:1:' + sha256('other-owner'),
    proposal_id: () => randomUUID(), target: () => 'plugins/other/target.json', version: () => 2,
  }
  for (const [field, change] of Object.entries(changes)) await t.test(field, st => {
    const f = fixture(st), proposal = f.propose(), review = f.review(proposal)
    f.clock += 10
    const altered = { ...review.owner_authorization, [field]: change(review.owner_authorization) }
    // Re-sign format-valid changes, proving comparison with the issued action, not only signature checking.
    const proof = ['kind', 'version'].includes(field)
      ? { ...proofFor(f, review.owner_authorization), authorization: altered } : proofFor(f, altered)
    assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
    assert.equal(consumption(f, review.authorization_digest), undefined)
  })
})

test('an otherwise exact proof signed by a different P256 owner root is refused', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal)
  const stranger = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const proof = { algorithm: OWNER_KEY_ALGORITHM, authorization: review.owner_authorization,
    signature_base64: sign('sha256', ownerAuthorizationSigningBytes(review.owner_authorization), stranger.privateKey).toString('base64') }
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
  assert.equal(consumption(f, review.authorization_digest), undefined)
})

test('the authorization expires at its exact deadline', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  f.clock = review.owner_authorization.expires_at_ms
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
  assert.equal(consumption(f, review.authorization_digest), undefined)
})

test('commit rechecks epoch, root, registry, and activation against current trusted state', async t => {
  const changes = {
    epoch: state => ({ ...state, owner_epoch: state.owner_epoch + 1 }),
    subject: state => ({ ...state, owner_subject: 'aukora:1:' + sha256('replacement-owner') }),
    root: state => {
      const replacement = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      const spki = replacement.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
      return { ...state, owner_root_spki_base64: spki, owner_root_id: ownerRootPin(spki).owner_root_id }
    },
    registry: state => ({ ...state, registry_sha256: sha256('replacement-registry') }),
    activation: state => ({ ...state, activation_sha256: sha256('replacement-activation') }),
  }
  for (const [name, change] of Object.entries(changes)) await t.test(name, st => {
    const f = fixture(st), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
    f.ownerState = change(f.ownerState)
    assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
    assert.equal(consumption(f, review.authorization_digest), undefined)
  })
})

test('final commit rechecks current expiry and fresh synchronous trusted state', async t => {
  for (const fault of ['expiry', 'state', 'async']) await t.test(fault, st => {
    const f = commitFaultFixture(st, fault), proposal = f.propose(), review = f.review(proposal)
    const proof = proofFor(f, review.owner_authorization)
    f.commitDeadline = review.owner_authorization.expires_at_ms
    f.commitFault = true
    assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
    assertUnconsumedPending(f, review)
    assert.equal(f.gate.verify().ok, true)
  })
})

test('late trusted-state callback expiry rolls back issuance and its signed anchor', t => {
  const f = fixture(t, { readOwnerState: f => {
    const live = f.issueFault && f.gate?.db.prepare("SELECT expires_at_ms FROM owner_authorization_reviews WHERE state='live'").get()
    if (live) f.clock = live.expires_at_ms
    return f.ownerState
  } })
  const proposal = f.propose()
  f.issueFault = true
  assertRefused(f, () => f.review(proposal))
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_reviews').get().n, 0)
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE proposal=? AND event='review-issued'").get(proposal.id).n, 0)
  assert.equal(f.gate.verify().ok, true)
})

test('either ignored CAS rolls back the accepted proof, spend, and applying transition', async t => {
  const triggers = {
    proposal: `CREATE TRIGGER fixture_ignore_cas BEFORE UPDATE ON proposals WHEN NEW.state='applying'
      BEGIN SELECT RAISE(IGNORE); END;`,
    review: `CREATE TRIGGER fixture_ignore_cas BEFORE UPDATE ON owner_authorization_reviews WHEN NEW.state='spent'
      BEGIN SELECT RAISE(IGNORE); END;`,
  }
  for (const [name, trigger] of Object.entries(triggers)) await t.test(name, st => {
    const f = fixture(st), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
    f.gate.db.exec(trigger)
    assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
    assertUnconsumedPending(f, review)
    assert.equal(f.gate.verify().ok, true)
  })
})

test('a newer review invalidates the earlier challenge and proof', t => {
  const f = fixture(t), proposal = f.propose(), first = f.review(proposal), firstProof = proofFor(f, first.owner_authorization)
  const second = f.review(proposal)
  assert.notEqual(first.review_challenge, second.review_challenge)
  assert.equal(f.gate.db.prepare('SELECT state FROM owner_authorization_reviews WHERE authorization_id=?').get(first.authorization_digest).state, 'invalidated')
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(first, firstProof), 'fixture-owner-channel'))
  // A fresh independent issuance remains usable even if failed decisions consume the current review.
  const fresh = f.review(proposal), proof = proofFor(f, fresh.owner_authorization)
  assert.equal(f.gate.ownerOps.decide_review(decision(fresh, proof), 'fixture-owner-channel').applied, true)
  assert.equal(f.writes.length, 1)
})

test('proof retention, challenge spend, and applying are visible to another connection before write', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  let checked = false
  f.beforeWrite = ({ id, bytes }) => {
    const observer = openDb(f.dbPath, { readOnly: true })
    try {
      const retained = observer.prepare('SELECT * FROM owner_authorization_consumptions WHERE authorization_id=?').get(review.authorization_digest)
      const spent = observer.prepare('SELECT * FROM owner_authorization_reviews WHERE authorization_id=?').get(review.authorization_digest)
      assert.equal(observer.prepare('SELECT state FROM proposals WHERE id=?').get(id).state, 'applying')
      assert.equal(spent.state, 'spent')
      assert.equal(retained.proof_text, ownerAuthorizationProofText(proof))
      assert.equal(retained.proof_sha256, ownerAuthorizationProofDigest(proof))
      assert.equal(retained.accepted_at_ms, f.clock)
      assert.equal(retained.issue_seq, review.review_issue.ledger_seq)
      assert.equal(retained.issue_hash, review.review_issue.ledger_hash)
      assert.equal(spent.spend_seq, retained.consume_seq)
      const consumedEntry = observer.prepare('SELECT event,hash,detail FROM ledger WHERE seq=?').get(retained.consume_seq)
      assert.equal(consumedEntry.hash, retained.consume_hash)
      assert.equal(consumedEntry.event, 'owner-authorization-consumed')
      assert.equal(JSON.parse(consumedEntry.detail).proof_text, retained.proof_text)
      assert.deepEqual(JSON.parse(retained.owner_state_text), f.ownerState)
      assert.equal(bytes.toString(), AFTER)
      assert.equal(f.current.toString(), BEFORE)
      checked = true
    } finally { observer.close() }
  }
  assert.equal(f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel').applied, true)
  assert.equal(checked, true)
  assert.equal(f.writes.length, 1)
  assert.equal(f.gate.verify().ok, true)
})

test('signed v3 receipt joins the exact proof, issuance, and durable consumption', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const result = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  const retained = consumption(f, review.authorization_digest), receipt = result.receipt
  assert.equal(result.applied, true)
  assert.equal(receipt.v, 3)
  assert.equal(receipt.approver, f.ownerState.owner_subject)
  assert.equal(Object.hasOwn(receipt, 'approval_evidence_hmac'), false)
  assert.equal(receipt.gate_pubkey_sha256, review.gate_pubkey_sha256)
  assert.equal(receipt.owner_accepted_at_ms, retained.accepted_at_ms)
  assert.deepEqual(receipt.owner_authorization, { version: 1, kind: 'aukora-owner-authorization-ref/v1',
    authorization_id: review.authorization_digest, proof_sha256: ownerAuthorizationProofDigest(proof) })
  assert.deepEqual(receipt.owner_consumption, { ledger_seq: retained.consume_seq, ledger_hash: retained.consume_hash,
    review_issue: review.review_issue })
  assert.equal(verify(null, Buffer.from(JSON.stringify(receipt)), f.gatePair.publicKey, Buffer.from(result.receipt_sig, 'base64')), true)
  const apply = f.gate.db.prepare('SELECT detail FROM ledger WHERE seq=?').get(result.ledger_seq)
  assert.deepEqual(JSON.parse(apply.detail).receipt, receipt)
  assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
  assert.equal(f.writes.length, 1)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 1)
})

test('rejecting a review requires no proof and cannot trigger a target write', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal)
  const result = f.gate.ownerOps.decide_review(decision(review, undefined, 'rejected'), 'fixture-owner-channel')
  assert.equal(result.applied, false)
  assert.equal(result.state, 'refused')
  assert.equal(f.writes.length, 0)
  assert.equal(consumption(f, review.authorization_digest), undefined)
})

test('interrupted finalization is reconciled on reopen without a second effect', async t => {
  for (const effectPresent of [false, true]) await t.test(effectPresent ? 'bytes present' : 'bytes absent', st => {
    const f = fixture(st), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
    f.gate.db.exec(`CREATE TRIGGER fixture_interrupt_finalization BEFORE UPDATE ON proposals
      WHEN OLD.state='applying' BEGIN SELECT RAISE(ABORT, 'fixture interrupted finalization'); END;`)
    if (!effectPresent) f.beforeWrite = () => { throw new Error('fixture interrupted before effect') }
    assert.throws(() => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'), /fixture interrupted/)
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applying')
    const retainedText = consumption(f, review.authorization_digest).proof_text
    assert.equal(retainedText, ownerAuthorizationProofText(proof))
    assert.equal(f.writes.length, effectPresent ? 1 : 0)
    f.gate.db.exec('DROP TRIGGER fixture_interrupt_finalization')
    f.beforeWrite = null
    const startup = f.reopen().startup()
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, effectPresent ? 'incomplete' : 'failed')
    assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE proposal=? AND event='apply'").get(proposal.id).n, 0)
    assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE target=? AND new_sha=? AND event='genesis-target'").get(THEME_TARGET, proposal.new_sha).n, 0)
    assert.equal(Object.hasOwn(startup, 'gate_capture'), false)
    assert.throws(() => verifyCompletedGateCapture(startup, captureExpectations(f)))
    assert.equal(consumption(f, review.authorization_digest).proof_text, retainedText)
    assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
    assert.equal(f.writes.length, effectPresent ? 1 : 0)
    assert.equal(f.gate.verify().ok, true)
  })
})

test('additive migration preserves historical signed entries while enabling new authorization', t => {
  const f = fixture(t, { legacy: true })
  assert.deepEqual(signedEntryData(f.gate.db.prepare('SELECT * FROM ledger WHERE seq=1').get()), f.historicalEntry)
  assert.equal(f.gate.verify().ok, true)
  const proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  assert.equal(f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel').applied, true)
  assert.deepEqual(signedEntryData(f.gate.db.prepare('SELECT * FROM ledger WHERE seq=1').get()), f.historicalEntry)
  assert.equal(f.gate.verify().ok, true)
})

test('two concurrent database connections can consume the same signed proof only once', { timeout: 15000 }, async t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const targetFile = path.join(f.home, 'disposable-target.json')
  writeFileSync(targetFile, BEFORE)
  const shared = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 3)
  const barrier = new Int32Array(shared)
  const workerCode = `
    const { parentPort, workerData } = require('node:worker_threads');
    (async () => {
      const [{ createGate }, { keyFingerprint }, { THEME_TARGET, themeTarget }, crypto, fs, sqlite] = await Promise.all([
        import(workerData.gateUrl), import(workerData.ledgerUrl), import(workerData.targetsUrl),
        import('node:crypto'), import('node:fs'), import('node:sqlite')]);
      const db = new sqlite.DatabaseSync(workerData.dbPath); db.exec('PRAGMA busy_timeout=5000');
      const priv = crypto.createPrivateKey(workerData.disposableReceiptPrivatePem), pub = crypto.createPublicKey(priv);
      const signals = new Int32Array(workerData.shared);
      const gate = createGate({ home: workerData.home, db, owner: { bearer: 'disposable-worker-fixture' },
        key: { priv, pub, pubPem: pub.export({ type: 'spki', format: 'pem' }).toString(), fp: keyFingerprint(pub) },
        targets: { [THEME_TARGET]: themeTarget(workerData.home) }, now: () => workerData.now,
        readOwnerState: () => workerData.ownerState,
        store: { read: () => fs.readFileSync(workerData.targetFile),
          write: (_target, _spec, bytes) => { fs.writeFileSync(workerData.targetFile, bytes); Atomics.add(signals, 2, 1); } } });
      parentPort.postMessage({ ready: true }); Atomics.wait(signals, 1, 0, 10000);
      let applied = false, error = null;
      try { applied = gate.ownerOps.decide_review(workerData.args, 'concurrent-fixture-channel').applied === true; }
      catch (cause) { error = String(cause.message); }
      finally { gate.close(); }
      parentPort.postMessage({ done: true, applied, error });
    })().catch(error => parentPort.postMessage({ setupFailed: String(error.message) }));
  `
  function launch() {
    const worker = new Worker(workerCode, { eval: true, workerData: {
      gateUrl: new URL('../packages/boundary-gate/src/gate.mjs', import.meta.url).href,
      ledgerUrl: new URL('../packages/boundary-gate/src/ledger.mjs', import.meta.url).href,
      targetsUrl: new URL('../packages/boundary-gate/src/targets.mjs', import.meta.url).href,
      dbPath: f.dbPath, home: f.home, targetFile, shared, now: f.clock, ownerState: f.ownerState,
      disposableReceiptPrivatePem: f.gatePair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      args: decision(review, proof),
    } })
    let readyResolve, readyReject, doneResolve, doneReject
    const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject })
    const done = new Promise((resolve, reject) => { doneResolve = resolve; doneReject = reject })
    worker.on('message', message => {
      if (message.ready) readyResolve()
      if (message.done) doneResolve(message)
      if (message.setupFailed) { const error = new Error(message.setupFailed); readyReject(error); doneReject(error) }
    })
    worker.on('error', error => { readyReject(error); doneReject(error) })
    t.after(() => worker.terminate())
    return { ready, done }
  }
  const first = launch(), second = launch()
  await Promise.all([first.ready, second.ready])
  Atomics.store(barrier, 1, 1)
  Atomics.notify(barrier, 1, 2)
  const results = await Promise.all([first.done, second.done])
  assert.equal(results.filter(result => result.applied).length, 1)
  assert.equal(Atomics.load(barrier, 2), 1)
  assert.equal(readFileSync(targetFile, 'utf8'), AFTER)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 1)
  assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applied')
  assert.equal(f.gate.verify().ok, true)
})

test('specific in-memory faults are killed by proof, final-clock, and atomic CAS assertions', async t => {
  await t.test('legacy no-proof fallback and retained-proof fence omitted', async st => {
    const create = await inMemoryGateMutant([
      ["if (outcome && Object.hasOwn(outcome, 'value') && outcome.value === 'allowed-once') fields.push('owner_authorization_proof')",
        "if (outcome && Object.hasOwn(outcome, 'value') && outcome.value === 'allowed-once' && args.owner_authorization_proof !== undefined) fields.push('owner_authorization_proof')"],
      ['const verified = verifyOwnerAuthorization(args.owner_authorization_proof, expectations, currentMs())',
        `const verified = args.owner_authorization_proof === undefined ? {
          proof: { algorithm: 'p256-ecdsa-sha256', authorization: a, signature_base64: 'AAAAAAAAAAA=' },
          reference: { version: 1, kind: 'aukora-owner-authorization-ref/v1', authorization_id: r.authorization_id,
            proof_sha256: '0'.repeat(64) } } : verifyOwnerAuthorization(args.owner_authorization_proof, expectations, currentMs())`],
      ['assertRetainedConsumption(p, consumption, review)', '/* named mutant: retained owner-proof fence omitted */'],
    ])
    const f = fixture(st, { createGate: create }), proposal = f.propose(), review = f.review(proposal)
    assert.throws(() => assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review), 'legacy-fixture-channel')), assert.AssertionError)
    assert.equal(f.writes.length, 1, 'the named fallback mutant really crosses the effect boundary')
  })
  await t.test('final commit and dispatch expiry omitted', async st => {
    const create = await inMemoryGateMutant([
      ["if (at < c.accepted_at_ms || at >= r.expires_at_ms || at >= p.expires) throw new Error('owner authorization expired at final commit clock')",
        "if (at < c.accepted_at_ms) throw new Error('owner authorization expired at final commit clock')"],
      ['|| at < consumption.accepted_at_ms || at >= review.expires_at_ms || at >= p.expires)',
        '|| at < consumption.accepted_at_ms)'],
    ])
    const f = commitFaultFixture(st, 'expiry', create), proposal = f.propose(), review = f.review(proposal)
    const proof = proofFor(f, review.owner_authorization)
    f.commitDeadline = review.owner_authorization.expires_at_ms; f.commitFault = true
    assert.throws(() => assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')), assert.AssertionError)
    assert.equal(f.writes.length, 1)
  })
  await t.test('proposal CAS, final-state and dispatch applying-state fences omitted', async st => {
    const create = await inMemoryGateMutant([
      ["if (spent.changes !== 1 || !setState(id, 'pending', 'applying', 'owner authorization spent')) throw new Error('owner consumption compare-and-set failed')",
        "setState(id, 'pending', 'applying', 'owner authorization spent')"],
      ["!r || r.state !== 'spent' || !p || p.state !== 'applying' || JSON.stringify(activeOwnerState()) !== c.owner_state_text",
        "!r || !p || JSON.stringify(activeOwnerState()) !== c.owner_state_text"],
      ["if (!current || current.state !== 'applying'", 'if (!current'],
    ])
    const f = fixture(st, { createGate: create }), proposal = f.propose(), review = f.review(proposal)
    const proof = proofFor(f, review.owner_authorization)
    f.gate.db.exec(`CREATE TRIGGER fixture_ignore_cas BEFORE UPDATE ON proposals WHEN NEW.state='applying'
      BEGIN SELECT RAISE(IGNORE); END;`)
    try { f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel') } catch {}
    assert.throws(() => assertUnconsumedPending(f, review), assert.AssertionError)
    assert.equal(f.writes.length, 1)
  })
})

test('completed capture verifies and projects the original signed apply source', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const result = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  const { gate_capture, ...core } = result
  assert.equal(Object.keys(core).length, 8)
  assert.equal(gate_capture.capture.completed_result_sha256, independentCompletedDigest(core))
  assert.equal(gateCompletedResultDigest(core), independentCompletedDigest(core))
  assert.equal(verify(null, independentCaptureBytes(gate_capture.capture), f.gatePair.publicKey,
    Buffer.from(gate_capture.signature_base64, 'base64')), true)
  assert.deepEqual(gate_capture.capture.source, { journal_id: JOURNAL_ID, position: result.ledger_seq, hash: result.ledger_hash })
  const projected = verifyCompletedGateCapture(result, captureExpectations(f))
  assert.deepEqual(projected, { source: gate_capture.capture.source })
  assert.equal(Object.isFrozen(projected), true)
  assert.equal(Object.isFrozen(projected.source), true)
})

test('capture rejects altered metadata or result, wrong public pin, and wrong journal', async t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const result = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  const changes = {
    'source hash': copy => { copy.gate_capture.capture.source.hash = sha256('tampered-source') },
    'source position': copy => { copy.gate_capture.capture.source.position++ },
    'proposal metadata': copy => { copy.gate_capture.capture.proposal_id = randomUUID() },
    'completed digest': copy => { copy.gate_capture.capture.completed_result_sha256 = sha256('tampered-result') },
    'core receipt': copy => { copy.receipt.applied_at = new Date(f.clock + 1).toISOString() },
    'core apply pointer': copy => { copy.ledger_hash = sha256('tampered-apply') },
    'extra field': copy => { copy.owner_approved = true },
  }
  for (const [name, change] of Object.entries(changes)) await t.test(name, () => {
    const copy = JSON.parse(JSON.stringify(result)); change(copy)
    assert.throws(() => verifyCompletedGateCapture(copy, captureExpectations(f)))
  })
  const stranger = generateKeyPairSync('ed25519')
  assert.throws(() => verifyCompletedGateCapture(result, { ...captureExpectations(f),
    gate_public_key_pem: stranger.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    gate_pubkey_sha256: sha256(stranger.publicKey.export({ type: 'spki', format: 'der' })) }))
  assert.throws(() => verifyCompletedGateCapture(result, { ...captureExpectations(f), journal_id: 'different-journal' }))
})

test('capture detaches receipt descriptors and refuses Proxy toJSON substitution', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const result = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  let serializationTraps = 0
  const substitutedReceipt = new Proxy({ ...result.receipt, new_sha: sha256('descriptor-visible-tampered-bytes') }, {
    get(target, property, receiver) {
      if (property === 'toJSON') { serializationTraps++; return () => result.receipt }
      return Reflect.get(target, property, receiver)
    },
  })
  assert.throws(() => verifyCompletedGateCapture({ ...result, receipt: substitutedReceipt }, captureExpectations(f)))
  assert.equal(serializationTraps, 0, 'caller serialization hooks must not choose the authenticated receipt bytes')
  const ownHook = { ...result.receipt, toJSON: () => result.receipt }
  assert.throws(() => verifyCompletedGateCapture({ ...result, receipt: ownHook }, captureExpectations(f)))
})

test('a newly valid capture signature cannot substitute for receipt authentication', async t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const result = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  const changes = {
    'different receipt signature': copy => { copy.receipt_sig = sign(null, Buffer.from('different receipt bytes'), f.gatePair.privateKey).toString('base64') },
    'different receipt content': copy => { copy.receipt.applied_at = new Date(f.clock + 1).toISOString() },
  }
  for (const [name, change] of Object.entries(changes)) await t.test(name, () => {
    const copy = JSON.parse(JSON.stringify(result)); change(copy); resignCapture(f, copy)
    assert.equal(copy.gate_capture.capture.completed_result_sha256, independentCompletedDigest(copy))
    assert.equal(verify(null, Buffer.from(JSON.stringify(copy.receipt)), f.gatePair.publicKey,
      Buffer.from(copy.receipt_sig, 'base64')), false)
    assert.throws(() => verifyCompletedGateCapture(copy, captureExpectations(f)))
  })
})

test('authenticated capture metadata must still join the completed result and trusted pins', async t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const result = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  const changes = {
    'source hash': copy => { copy.gate_capture.capture.source.hash = sha256('different-authenticated-source') },
    'source position': copy => { copy.gate_capture.capture.source.position++ },
    'source journal': copy => { copy.gate_capture.capture.source.journal_id = 'different-authenticated-journal' },
    'core pointer hash': copy => { copy.ledger_hash = sha256('different-authenticated-core-pointer') },
    'core pointer position': copy => { copy.ledger_seq++ },
    'proposal id': copy => { copy.gate_capture.capture.proposal_id = randomUUID() },
    'capture full gate key id': copy => { copy.gate_capture.capture.gate_pubkey_sha256 = sha256('different-authenticated-gate-id') },
    'receipt full gate key id': copy => {
      copy.receipt.gate_pubkey_sha256 = sha256('different-authenticated-receipt-gate-id')
      copy.receipt.pubkey_fp = copy.receipt.gate_pubkey_sha256.slice(0, 16)
      copy.receipt_sig = sign(null, Buffer.from(JSON.stringify(copy.receipt)), f.gatePair.privateKey).toString('base64')
    },
  }
  for (const [name, change] of Object.entries(changes)) await t.test(name, () => {
    const copy = JSON.parse(JSON.stringify(result)); change(copy); resignCapture(f, copy)
    assert.equal(verify(null, Buffer.from(JSON.stringify(copy.receipt)), f.gatePair.publicKey,
      Buffer.from(copy.receipt_sig, 'base64')), true)
    assert.throws(() => verifyCompletedGateCapture(copy, captureExpectations(f)))
  })
})

test('trusted journal IDs with a final newline are refused', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const result = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  assert.throws(() => verifyCompletedGateCapture(result, { ...captureExpectations(f), journal_id: JOURNAL_ID + '\n' }))
  assert.throws(() => createGate({ home: f.home, db: f.gate.db, owner: { bearer: 'disposable-fixture' },
    key: { priv: f.gatePair.privateKey, pub: f.gatePair.publicKey,
      pubPem: f.gatePair.publicKey.export({ type: 'spki', format: 'pem' }).toString(), fp: keyFingerprint(f.gatePair.publicKey) },
    store: { read: () => Buffer.from(f.current), write() { assert.fail('invalid journal must not write') } },
    targets: { [THEME_TARGET]: themeTarget(f.home) }, readOwnerState: () => f.ownerState, now: () => f.clock,
    journalId: JOURNAL_ID + '\n' }), /journal|capture|invalid/i)
})

test('unconfigured journals and failed decisions cannot provide completed captures', async t => {
  await t.test('journal unconfigured', st => {
    const f = fixture(st, { journalId: null }), proposal = f.propose(), review = f.review(proposal)
    const result = f.gate.ownerOps.decide_review(decision(review, proofFor(f, review.owner_authorization)), 'fixture-owner-channel')
    assert.equal(result.applied, true)
    assert.equal(Object.keys(result).length, 8)
    assert.equal(Object.hasOwn(result, 'gate_capture'), false)
    assert.throws(() => verifyCompletedGateCapture(result, captureExpectations(f)))
  })
  await t.test('owner rejection', st => {
    const f = fixture(st), proposal = f.propose(), review = f.review(proposal)
    const result = f.gate.ownerOps.decide_review(decision(review, undefined, 'rejected'), 'fixture-owner-channel')
    assert.equal(Object.hasOwn(result, 'gate_capture'), false)
    assert.throws(() => verifyCompletedGateCapture(result, captureExpectations(f)))
  })
})


test('unreadable post-write recovery and repeated restarts retain the uncertainty fence', async t => {
  for (const unreadableRestarts of [0, 2]) await t.test(unreadableRestarts ? 'repeated unreadable restarts' : 'readable reopen', st => {
    const f = fixture(st), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
    f.beforeWrite = () => { f.readFailures = 2 }
    let completed
    assert.throws(() => { completed = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel') }, /fixture target unreadable/)
    assert.equal(completed, undefined, 'an ambiguous effect has no completed result or capture')
    assert.equal(f.writes.length, 1)
    assert.equal(f.current.toString(), AFTER)
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applying')
    const retained = consumption(f, review.authorization_digest)
    assert.equal(retained.proof_text, ownerAuthorizationProofText(proof))
    assert.equal(f.gate.db.prepare('SELECT state FROM owner_authorization_reviews WHERE authorization_id=?').get(review.authorization_digest).state, 'spent')
    f.beforeWrite = null
    f.readFailures = unreadableRestarts
    f.reopen()
    for (let i = 0; i < unreadableRestarts; i++) {
      assert.equal(f.gate.startup({ pid: 1 }).ok, true)
      assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applying')
      assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event IN ('apply','revert-applied','genesis-target')").get().n, 0)
      assert.equal(f.writes.length, 1)
      if (i + 1 < unreadableRestarts) f.reopen()
    }
    f.reopen()
    assert.equal(f.gate.startup({ pid: 1 }).ok, true)
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'incomplete')
    assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event IN ('apply','revert-applied','genesis-target')").get().n, 0)
    assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 1)
    assert.equal(consumption(f, review.authorization_digest).proof_text, retained.proof_text)
    assertRefused(f, () => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'))
    assert.equal(f.writes.length, 1)
    assert.equal(f.gate.verify().ok, true)
  })
})

test('state polling returns the exact durably retained completion across later changes and reopen', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const original = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  const originalText = JSON.stringify(original)
  // No asynchronous yield before this independent connection observes committed retention.
  const observer = openDb(f.dbPath, { readOnly: true })
  try {
    const row = observer.prepare('SELECT * FROM gate_completed_results WHERE proposal_id=?').get(proposal.id)
    assert.equal(row.result_text, originalText)
    assert.equal(row.apply_seq, original.ledger_seq)
    assert.equal(row.apply_hash, original.ledger_hash)
    assert.equal(row.completed_result_sha256, independentCompletedDigest(original))
    assert.equal(row.retained_at_ms, f.clock)
    assert.equal(observer.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id).state, 'applied')
    assert.deepEqual(JSON.parse(row.result_text), original)
  } finally { observer.close() }
  assert.deepEqual(f.gate.proposeOps.state({ id: proposal.id }), original)
  assert.deepEqual(verifyCompletedGateCapture(original, captureExpectations(f)).source, original.gate_capture.capture.source)
  assert.throws(() => f.gate.db.prepare('UPDATE gate_completed_results SET result_text=? WHERE proposal_id=?').run('{}', proposal.id), /immutable|append|retained/i)
  assert.throws(() => f.gate.db.prepare('DELETE FROM gate_completed_results WHERE proposal_id=?').run(proposal.id), /immutable|append|retained/i)
  f.clock += 1000
  f.current = Buffer.from('{"accent": "#445566"}')
  f.gate.append('later-fixture-entry', { detail: { note: 'completion must keep its original source pointer' } })
  forbidPollingSignatures(f)
  const fresh = f.gate.proposeOps.state({ id: proposal.id })
  assert.equal(JSON.stringify(fresh), originalText)
  assert.equal(Object.keys(fresh).length, 9)
  assert.deepEqual(verifyCompletedGateCapture(fresh, captureExpectations(f)).source, original.gate_capture.capture.source)
  f.reopen()
  const reopened = f.gate.proposeOps.state({ id: proposal.id })
  assert.equal(JSON.stringify(reopened), originalText)
  assert.deepEqual(verifyCompletedGateCapture(reopened, captureExpectations(f)).source, original.gate_capture.capture.source)
  assert.equal(f.writes.length, 1)
  assert.equal(f.pollingSignReads, 0)
})

test('missing completion evidence after apply is unavailable and cannot be reconstructed by polling', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const original = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
  assert.equal(original.applied, true)
  f.gate.db.exec('DROP TABLE gate_completed_results')
  forbidPollingSignatures(f)
  assertUnavailableCompletion(f, proposal)
  f.reopen() // Additive schema setup recreates an empty table, never the original evidence.
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM gate_completed_results').get().n, 0)
  assertUnavailableCompletion(f, proposal)
  assert.equal(f.writes.length, 1)
  assert.equal(f.pollingSignReads, 0)
})

test('missing completion storage before authorization refuses the effect and rolls back acceptance', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  f.gate.db.exec('DROP TABLE gate_completed_results')
  assert.throws(() => f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel'), /gate_completed_results|completion|retention/i)
  assertUnconsumedPending(f, review)
  assert.equal(f.current.toString(), BEFORE)
  assert.equal(f.gate.verify().ok, true)
})

test('post-apply completion retention failure preserves applied without a polling capture', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  f.gate.db.exec(`CREATE TRIGGER fixture_retention_failure BEFORE INSERT ON gate_completed_results
    BEGIN SELECT RAISE(ABORT, 'fixture completed retention unavailable'); END;`)
  let returned
  assert.throws(() => { returned = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel') }, /fixture completed retention unavailable/)
  assert.equal(returned, undefined)
  assert.equal(f.gate.db.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id).state, 'applied')
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM gate_completed_results').get().n, 0)
  assert.equal(consumption(f, review.authorization_digest).proof_text, ownerAuthorizationProofText(proof))
  forbidPollingSignatures(f)
  assertUnavailableCompletion(f, proposal)
  f.reopen()
  assertUnavailableCompletion(f, proposal)
  assert.equal(f.writes.length, 1)
})

test('an ignored completion insert cannot return a capture that was never retained', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  f.gate.db.exec(`CREATE TRIGGER fixture_retention_ignore BEFORE INSERT ON gate_completed_results
    BEGIN SELECT RAISE(IGNORE); END;`)
  let returned
  assert.throws(() => { returned = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel') }, /completion|retention|compare|insert|retain/i)
  assert.equal(returned, undefined)
  assert.equal(f.gate.db.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id).state, 'applied')
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM gate_completed_results').get().n, 0)
  assert.equal(consumption(f, review.authorization_digest).proof_text, ownerAuthorizationProofText(proof))
  forbidPollingSignatures(f)
  assertUnavailableCompletion(f, proposal)
  f.reopen()
  assertUnavailableCompletion(f, proposal)
  assert.equal(f.writes.length, 1)
})

test('damaged retained bytes or coordinates cannot be rebuilt from the signed apply ledger', async t => {
  for (const damage of ['result text', 'apply coordinates']) await t.test(damage, st => {
    const f = fixture(st), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
    const original = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel')
    assert.equal(original.applied, true)
    // Deliberate corruption of the disposable fixture only, bypassing its immutable row triggers.
    for (const { name } of f.gate.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='gate_completed_results'").all())
      f.gate.db.exec('DROP TRIGGER "' + name.replaceAll('"', '""') + '"')
    if (damage === 'result text') f.gate.db.prepare('UPDATE gate_completed_results SET result_text=? WHERE proposal_id=?').run('{}', proposal.id)
    else f.gate.db.prepare('UPDATE gate_completed_results SET apply_hash=? WHERE proposal_id=?').run(sha256('damaged-retained-coordinate'), proposal.id)
    forbidPollingSignatures(f)
    assertUnavailableCompletion(f, proposal)
    f.reopen()
    assertUnavailableCompletion(f, proposal)
    assert.equal(f.writes.length, 1)
    assert.equal(f.pollingSignReads, 0)
  })
})

test('capture-only signing failure happens after apply commit and polling never retries signing', t => {
  const f = fixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  let captureOnlyFailure = false
  Object.defineProperty(f.key, 'priv', { enumerable: true, configurable: true, get() {
    const observer = openDb(f.dbPath, { readOnly: true })
    let committed
    try { committed = observer.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id)?.state === 'applied' }
    finally { observer.close() }
    if (committed) { captureOnlyFailure = true; throw new Error('fixture capture signer unavailable after apply commit') }
    return f.gatePair.privateKey
  } })
  let returned
  assert.throws(() => { returned = f.gate.ownerOps.decide_review(decision(review, proof), 'fixture-owner-channel') }, /fixture capture signer unavailable after apply commit/)
  assert.equal(captureOnlyFailure, true)
  assert.equal(returned, undefined)
  assert.equal(f.gate.db.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id).state, 'applied')
  const apply = f.gate.db.prepare("SELECT detail FROM ledger WHERE proposal=? AND event='apply'").get(proposal.id)
  const signed = JSON.parse(apply.detail)
  assert.equal(verify(null, Buffer.from(JSON.stringify(signed.receipt)), f.gatePair.publicKey, Buffer.from(signed.receipt_sig, 'base64')), true)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM gate_completed_results').get().n, 0)
  forbidPollingSignatures(f)
  assertUnavailableCompletion(f, proposal)
  f.reopen()
  assertUnavailableCompletion(f, proposal)
  assert.equal(f.writes.length, 1)
})

test('an applied result with no configured journal stays unavailable to completion polling', t => {
  const f = fixture(t, { journalId: null }), proposal = f.propose(), review = f.review(proposal)
  const original = f.gate.ownerOps.decide_review(decision(review, proofFor(f, review.owner_authorization)), 'fixture-owner-channel')
  assert.equal(original.applied, true)
  assert.equal(Object.keys(original).length, 8)
  assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM gate_completed_results').get().n, 0)
  forbidPollingSignatures(f)
  assertUnavailableCompletion(f, proposal)
  f.reopen()
  assertUnavailableCompletion(f, proposal)
  assert.equal(f.writes.length, 1)
})

test('theme proposal helper preserves the gate full id and ignores model-supplied proposal ids', async () => {
  const id = randomUUID(), calls = [], modelId = randomUUID()
  const result = await proposeTheme('unused-fixture-socket', { accent: '#123abc', why: 'fixture', session: 'fixture', proposal_id: modelId },
    async (_socket, op, args) => {
      calls.push({ op, args })
      if (op === 'read') return { content: BEFORE, sha256: sha256(BEFORE) }
      if (op === 'propose') return { id, expires: BASE_TIME + 1000 }
      assert.fail('unexpected helper gate operation')
    })
  assert.equal(result.proposal_id, id)
  assert.equal(result.proposal, id.slice(0, 8))
  assert.notEqual(result.proposal_id, modelId)
  assert.deepEqual(calls.map(call => call.op), ['read', 'propose'])
  assert.equal(calls[1].args.claimed_base, sha256(BEFORE))
  assert.equal(calls[1].args.content, '{"accent": "#123ABC"}')
  assert.equal(Object.hasOwn(calls[1].args, 'proposal_id'), false)
})

test('theme proposal helper rejects missing, malformed, and accessor full ids', async t => {
  let accessorReads = 0
  const accessorReply = Object.defineProperty({}, 'id', { enumerable: true, get() { accessorReads++; return randomUUID() } })
  const replies = { missing: {}, short: { id: '12345678' }, malformed: { id: 'x'.repeat(36) },
    'wrong uuid version': { id: '12345678-1234-1234-8123-123456789abc' }, accessor: accessorReply }
  for (const [name, reply] of Object.entries(replies)) await t.test(name, async () => {
    const ops = []
    await assert.rejects(() => proposeTheme('unused-fixture-socket', { accent: '#123ABC' }, async (_socket, op) => {
      ops.push(op)
      return op === 'read' ? { content: BEFORE, sha256: sha256(BEFORE) } : reply
    }), /missing or malformed full proposal id/)
    assert.deepEqual(ops, ['read', 'propose'])
  })
  assert.equal(accessorReads, 0)
})

test('theme client permits exactly read/propose/state and refuses owner operations before connecting', async () => {
  assert.deepEqual(PROPOSE_OPS, ['read', 'propose', 'state'])
  assert.equal(Object.isFrozen(PROPOSE_OPS), true)
  const original = net.createConnection
  let connections = 0
  net.createConnection = () => { connections++; throw new Error('fixture must not open a socket') }
  try {
    for (const op of ['approve', 'decide', 'review', 'decide_review', 'raise'])
      await assert.rejects(() => gateCall('unused-fixture-socket', op, {}), /not a propose-side op/)
    assert.equal(connections, 0)
  } finally { net.createConnection = original }
})
