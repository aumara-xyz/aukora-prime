// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual gate/SQLite/physical-byte fixtures; no installed acceptance or owner enrollment claim.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { entryBody, openDb, sha256, verifyCompletedGateCapture } from '../packages/boundary-gate/src/ledger.mjs'
import { AFTER, BEFORE, DIFFERENT, JOURNAL_ID, decision, effectFixture, proofFor } from './fixtures/owner-effect-worker.mjs'

const workerPath = fileURLToPath(new URL('./fixtures/owner-effect-worker.mjs', import.meta.url))
const gateUrl = new URL('../packages/boundary-gate/src/gate.mjs', import.meta.url)

function accepted(f) {
  const proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  return { proposal, review, proof, args: decision(review, proof) }
}

function retainedConsumption(f, proposalId) {
  return f.gate.db.prepare('SELECT * FROM owner_authorization_consumptions WHERE proposal_id=?').get(proposalId)
}

function noCompletedResult(f, proposalId) {
  const db = f.gate.db
  assert.equal(db.prepare("SELECT COUNT(*) n FROM ledger WHERE proposal=? AND event IN ('apply','revert-applied')").get(proposalId).n, 0)
  assert.equal(db.prepare('SELECT COUNT(*) n FROM gate_completed_results WHERE proposal_id=?').get(proposalId).n, 0)
  const state = f.gate.proposeOps.state({ id: proposalId })
  for (const field of ['receipt', 'receipt_sig', 'gate_capture'])
    assert.equal(Object.hasOwn(state, field), false, 'unresolved/spent action must not fabricate ' + field)
  return state
}

function assertSpent(f, proposalId, review) {
  const row = retainedConsumption(f, proposalId)
  assert.ok(row, 'actual consumption must remain committed')
  assert.equal(row.authorization_id, review.authorization_digest)
  assert.equal(f.gate.db.prepare('SELECT state FROM owner_authorization_reviews WHERE authorization_id=?').get(row.authorization_id).state, 'spent')
  assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE proposal=? AND event='owner-authorization-consumed'").get(proposalId).n, 1)
  return JSON.stringify(row)
}

function afterConsumptionCommit(f, proposalId, callback) {
  const db = f.gate.db, exec = db.exec.bind(db)
  let fired = false
  db.exec = sql => {
    const result = exec(sql)
    if (!fired && sql === 'COMMIT') {
      const row = db.prepare('SELECT state FROM proposals WHERE id=?').get(proposalId)
      if (row?.state === 'applying' && db.prepare('SELECT 1 FROM owner_authorization_consumptions WHERE proposal_id=?').get(proposalId)) {
        fired = true
        callback()
      }
    }
    return result
  }
  return () => assert.equal(fired, true, 'fixture must interleave after the real consumption COMMIT')
}

function refuseWithoutWrite(f, action) {
  const count = f.writes.length
  assert.throws(action, /refus|applying|consum|owner|state|expired|base|replay|compare.and.set|pending|spent|unavailable|no live durable review challenge \(single use\)/i)
  assert.equal(f.writes.length, count, 'no physical target write may follow a spent/refused state')
}

function captureExpectations(f) {
  return { journal_id: JOURNAL_ID, gate_public_key_pem: f.gatePair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    gate_pubkey_sha256: sha256(f.gatePair.publicKey.export({ format: 'der', type: 'spki' })) }
}

function durableSnapshot(f) {
  const tables = f.gate.db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all()
    .map(({ name }) => [name, f.gate.db.prepare('SELECT * FROM "' + name.replaceAll('"', '""') + '" ORDER BY rowid').all()])
  const attemptsFile = join(f.home, 'write-attempts.jsonl')
  return JSON.stringify({ tables, target: f.read().toString('base64'), writes: f.writes.length,
    attempts: existsSync(attemptsFile) ? readFileSync(attemptsFile, 'utf8') : null })
}

function readinessMethods(f) {
  return [() => f.gate.readiness(), () => f.gate.proposeOps.readiness(), () => f.gate.ownerOps.readiness()]
}

function assertReadiness(f, { ready = true, retained = 0, unresolved = 0, applying = 0, incomplete = 0, conflict = 0 } = {}) {
  const checked = f.gate.verify()
  assert.equal(checked.ok, true)
  const expected = { version: 1, kind: 'aukora-boundary-gate-readiness/v1', ready, checked_at_ms: f.clock,
    gate_pubkey_sha256: sha256(f.gatePair.publicKey.export({ format: 'der', type: 'spki' })),
    owner_state_sha256: sha256(JSON.stringify(f.ownerState)), owner_subject: f.ownerState.owner_subject,
    owner_root_id: f.ownerState.owner_root_id, owner_epoch: f.ownerState.owner_epoch,
    registry_sha256: f.ownerState.registry_sha256, activation_sha256: f.ownerState.activation_sha256,
    ledger: { entries: checked.entries, head: checked.head }, consumed_effects: { retained, unresolved, applying, incomplete, conflict } }
  for (const observe of readinessMethods(f)) {
    const before = durableSnapshot(f)
    const ownerReads = f.ownerObservations
    assert.deepEqual(observe(), expected, 'every readiness route returns only the exact current public observation')
    assert.ok(f.ownerObservations > ownerReads, 'each readiness route must freshly observe the trusted owner')
    assert.equal(durableSnapshot(f), before, 'readiness must not append, sweep budgets/state, reconcile, write targets or spend')
  }
}

function refuseReadinessWithoutMutation(f) {
  for (const observe of readinessMethods(f)) {
    const before = durableSnapshot(f)
    assert.throws(observe, /retained|binding|consum|original|proof|issuance|unavailable|terminal|signed/i)
    assert.equal(durableSnapshot(f), before, 'rejected readiness must preserve every stored row, budget, target and attempt')
  }
}

function damagedCopy(f, fault) {
  const original = durableSnapshot(f)
  const file = join(f.home, 'damaged-' + fault + '.db')
  const copy = openDb(file)
  try {
    copy.exec('BEGIN IMMEDIATE')
    const tables = f.gate.db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all()
    for (const { name } of tables) {
      const quoted = '"' + name.replaceAll('"', '""') + '"'
      const columns = f.gate.db.prepare('PRAGMA table_info(' + quoted + ')').all().map(row => row.name)
      const insert = copy.prepare('INSERT INTO ' + quoted + '(' + columns.map(column => '"' + column.replaceAll('"', '""') + '"').join(',')
        + ') VALUES(' + columns.map(() => '?').join(',') + ')')
      for (const originalRow of f.gate.db.prepare('SELECT * FROM ' + quoted + ' ORDER BY rowid').all()) {
        const row = { ...originalRow }
        if (name === 'owner_authorization_consumptions') {
          if (fault === 'proof_sha256') row.proof_sha256 = sha256('synthetic-damaged-proof-digest')
          if (fault === 'accepted_at_ms') row.accepted_at_ms++
          if (fault === 'owner_state_text') row.owner_state_text = JSON.stringify({ ...JSON.parse(row.owner_state_text),
            registry_sha256: sha256('synthetic-damaged-owner-state') })
        }
        if (name === 'owner_authorization_reviews' && fault === 'authorization_text') {
          const authorization = JSON.parse(row.authorization_text)
          authorization.after_sha256 = sha256('synthetic-damaged-authorized-bytes')
          row.authorization_text = JSON.stringify(authorization)
        }
        insert.run(...columns.map(column => row[column]))
      }
    }
    copy.exec('COMMIT')
  } catch (error) { copy.exec('ROLLBACK'); throw error }
  finally { copy.close() }
  assert.equal(durableSnapshot(f), original, 'making a damaged test-owned snapshot must leave the original store unchanged')
  f.closeGate(f.gate)
  f.gate = f.openGate({ dbPath: file })
  assert.equal(f.gate.verify().ok, true, 'damaged metadata must retain the original valid signed ledger, not an invalid-signature shortcut')
}

test('readiness returns fresh and applied public bindings under the writer lock without changing any durable state', t => {
  const f = effectFixture(t), second = f.openGate()
  let ownerObservations = 0
  f.beforeOwnerState = () => {
    ownerObservations++
    assert.throws(() => second.db.exec('BEGIN IMMEDIATE'), /locked|busy/i,
      'readiness must hold the real shared writer while observing the trusted owner state')
  }
  assertReadiness(f)
  assert.ok(ownerObservations >= 3, 'all three readiness routes must observe the current owner under the fence')
  f.beforeOwnerState = null
  const { proposal, args } = accepted(f)
  const result = f.gate.ownerOps.decide_review(args, 'synthetic-owner-channel')
  assert.equal(result.applied, true)
  assertReadiness(f, { retained: 1 })
  f.clock++
  f.ownerState = { ...f.ownerState, owner_epoch: f.ownerState.owner_epoch + 1,
    registry_sha256: sha256('synthetic-refreshed-registry'), activation_sha256: sha256('synthetic-refreshed-activation') }
  assertReadiness(f, { retained: 1 })
  assert.equal(JSON.stringify(f.gate.proposeOps.state({ id: proposal.id })), JSON.stringify(result),
    'a readiness refresh must not replace the original completion or historical owner proof')
})

test('a fabricated applied or failed proposal label is not a signed terminal outcome for readiness', async t => {
  for (const terminal of ['applied', 'failed']) await t.test(terminal, st => {
    const f = effectFixture(st), { proposal, review, args } = accepted(f)
    const didInterleave = afterConsumptionCommit(f, proposal.id, () => {
      // Only this nonimmutable proposal label changes; the original proof and signed rows stay retained.
      f.gate.db.prepare('UPDATE proposals SET state=? WHERE id=?').run(terminal, proposal.id)
      refuseReadinessWithoutMutation(f)
    })
    refuseWithoutWrite(f, () => f.gate.ownerOps.decide_review(args, 'synthetic-owner-channel'))
    didInterleave()
    assertSpent(f, proposal.id, review)
    assert.equal(noCompletedResult(f, proposal.id).state, terminal)
    assert.equal(f.read().toString(), BEFORE)
    assert.equal(f.gate.verify().ok, true)
  })
})

test('readiness and startup refuse damaged retained metadata copied into new owned snapshots without modifying originals', async t => {
  for (const fault of ['proof_sha256', 'accepted_at_ms', 'owner_state_text', 'authorization_text']) await t.test(fault, st => {
    const f = effectFixture(st), { args } = accepted(f)
    assert.equal(f.gate.ownerOps.decide_review(args, 'synthetic-owner-channel').applied, true)
    damagedCopy(f, fault)
    refuseReadinessWithoutMutation(f)
    const before = durableSnapshot(f)
    assert.throws(() => f.gate.startup(), /retained|binding|consum|original|proof|issuance|unavailable|signed/i)
    assert.equal(durableSnapshot(f), before, 'startup must refuse corrupted retention before any adoption, reconciliation or append')
  })
})

async function guardRemovedGate() {
  let source = readFileSync(gateUrl, 'utf8')
  const call = 'assertConsumedEffect(p, consumption)'
  const pattern = new RegExp('(?<!function )' + call.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')
  const matches = source.match(pattern) ?? []
  assert.equal(matches.length, 1, 'named effect guard must have exactly one removable call')
  source = source.replace(pattern, 'void 0 /* synthetic removal control: effect guard absent */')
  source = source.replace(/from\s+(['"])(\.[^'"]+)\1/g, (_match, quote, specifier) =>
    'from ' + quote + new URL(specifier, gateUrl).href + quote)
  return (await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'))).createGate
}

test('second gate startup wins after consumption COMMIT; first gate must not write from stale applying state', t => {
  const f = effectFixture(t), { proposal, review, args } = accepted(f), second = f.openGate()
  const didInterleave = afterConsumptionCommit(f, proposal.id, () => {
    assert.equal(second.startup({ extra: { synthetic: 'between-consumption-and-effect' } }).ok, true)
    assert.equal(second.proposeOps.state({ id: proposal.id }).state, 'failed')
    assert.equal(f.read().toString(), BEFORE)
  })
  refuseWithoutWrite(f, () => f.gate.ownerOps.decide_review(args, 'synthetic-owner-channel'))
  didInterleave()
  const retained = assertSpent(f, proposal.id, review)
  assert.equal(noCompletedResult(f, proposal.id).state, 'failed')
  assert.equal(f.read().toString(), BEFORE)
  f.reopen().startup()
  refuseWithoutWrite(f, () => f.gate.ownerOps.decide_review(args, 'synthetic-replay'))
  assert.equal(JSON.stringify(retainedConsumption(f, proposal.id)), retained)
  assert.equal(f.gate.verify().ok, true)
})

test('removing only the named effect guard exposes the same real two-connection stray-write defect', async t => {
  const create = await guardRemovedGate(), f = effectFixture(t, { create }), { proposal, review, args } = accepted(f)
  const second = f.openGate()
  const didInterleave = afterConsumptionCommit(f, proposal.id, () => second.startup())
  assert.throws(() => f.gate.ownerOps.decide_review(args, 'synthetic-removal-control'), /state|compare.and.set/i)
  didInterleave()
  assert.equal(f.writes.length, 1, 'guard removal must cross the actual physical effect boundary')
  assert.equal(f.read().toString(), AFTER)
  assertSpent(f, proposal.id, review)
  assert.equal(noCompletedResult(f, proposal.id).state, 'failed')
})

test('effect writer lock remains held through target write and original apply receipt', t => {
  const f = effectFixture(t), { proposal, review, args } = accepted(f), second = f.openGate()
  let checked = false
  f.beforeWrite = () => {
    checked = true
    assert.throws(() => second.db.exec('BEGIN IMMEDIATE'), /locked|busy/i,
      'another gate writer must not enter between effect validation and target write')
  }
  const exec = f.gate.db.exec.bind(f.gate.db)
  let receiptCommitChecks = 0
  f.gate.db.exec = sql => {
    if (checked && ['COMMIT', 'ROLLBACK'].includes(sql))
      assert.equal(f.gate.db.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id)?.state, 'applied',
        'the first writer release after target write must include the original applied state and receipt')
    if (sql === 'COMMIT' && f.gate.db.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id)?.state === 'applied') {
      receiptCommitChecks++
      assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE proposal=? AND event='apply'").get(proposal.id).n, 1)
      assert.throws(() => second.db.exec('BEGIN IMMEDIATE'), /locked|busy/i,
        'the same writer fence must protect the signed apply row until its actual COMMIT')
    }
    return exec(sql)
  }
  const result = f.gate.ownerOps.decide_review(args, 'synthetic-owner-channel')
  assert.equal(checked, true)
  assert.ok(receiptCommitChecks >= 1, 'fixture must inspect the uncommitted original apply receipt')
  assert.equal(result.applied, true)
  assert.equal(f.writes.length, 1)
  assert.equal(f.read().toString(), AFTER)
  const spent = retainedConsumption(f, proposal.id)
  assert.equal(result.receipt.owner_authorization.authorization_id, review.authorization_digest)
  assert.equal(result.receipt.owner_authorization.proof_sha256, spent.proof_sha256)
  assert.equal(result.receipt.owner_consumption.ledger_seq, spent.consume_seq)
  assert.equal(result.receipt.owner_consumption.ledger_hash, spent.consume_hash)
  assert.deepEqual(verifyCompletedGateCapture(result, captureExpectations(f)).source, result.gate_capture.capture.source)
  const originalText = JSON.stringify(result)
  f.reopen().startup()
  assert.equal(JSON.stringify(f.gate.proposeOps.state({ id: proposal.id })), originalText,
    'cold polling returns the original same-action capture, never a newly signed reconstruction')
  refuseWithoutWrite(f, () => f.gate.ownerOps.decide_review(args, 'synthetic-replay'))
  assert.equal(f.writes.length, 1)
  assert.equal(f.gate.verify().ok, true)
})

test('post-consumption changes to base, owner state and exact expiry refuse before the physical effect', async t => {
  for (const fault of ['base', 'owner', 'review-expiry', 'proposal-expiry']) await t.test(fault, st => {
    const f = effectFixture(st), { proposal, review, args } = accepted(f)
    const didInterleave = afterConsumptionCommit(f, proposal.id, () => {
      if (fault === 'base') f.setTarget(DIFFERENT)
      else if (fault === 'owner') f.ownerState = { ...f.ownerState, owner_epoch: f.ownerState.owner_epoch + 1 }
      else if (fault === 'review-expiry') f.clock = review.review_expires
      else f.clock = proposal.expires
    })
    refuseWithoutWrite(f, () => f.gate.ownerOps.decide_review(args, 'synthetic-owner-channel'))
    didInterleave()
    const retained = assertSpent(f, proposal.id, review)
    noCompletedResult(f, proposal.id)
    assert.equal(f.read().toString(), fault === 'base' ? DIFFERENT : BEFORE)
    f.reopen().startup()
    refuseWithoutWrite(f, () => f.gate.ownerOps.decide_review(args, 'synthetic-replay'))
    assert.equal(JSON.stringify(retainedConsumption(f, proposal.id)), retained)
    noCompletedResult(f, proposal.id)
    assert.equal(f.gate.verify().ok, true)
  })
})

test('owner state or expiry changing inside the dispatch base read still refuses before any write', async t => {
  for (const fault of ['review-expiry', 'owner-state']) await t.test(fault, st => {
    const f = effectFixture(st), { proposal, review, args } = accepted(f)
    let fired = false
    f.beforeRead = () => {
      if (fired || !retainedConsumption(f, proposal.id)
        || f.gate.db.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id)?.state !== 'applying') return
      fired = true
      if (fault === 'review-expiry') f.clock = review.review_expires
      else f.ownerState = { ...f.ownerState, owner_epoch: f.ownerState.owner_epoch + 1 }
    }
    refuseWithoutWrite(f, () => f.gate.ownerOps.decide_review(args, 'synthetic-owner-channel'))
    f.beforeRead = null
    assert.equal(fired, true, 'fixture must change the live guard during the actual dispatch base read')
    assertSpent(f, proposal.id, review)
    assert.equal(noCompletedResult(f, proposal.id).state, 'failed')
    assert.equal(f.read().toString(), BEFORE)
    assert.equal(f.gate.verify().ok, true)
  })
})

async function killAtStage(t, f, proposalId, stage) {
  const child = spawn(process.execPath, [workerPath, '--crash-stage', f.home, stage], { stdio: ['ignore', 'pipe', 'pipe'] })
  let closed = false, stderr = '', stdout = ''
  child.stderr.on('data', bytes => { stderr += bytes.toString(); if (stderr.length > 4096) stderr = stderr.slice(-4096) })
  const exit = new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => { closed = true; resolve({ code, signal }) })
  })
  t.after(async () => { if (!closed) { child.kill('SIGKILL'); await exit } })
  const phase = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('synthetic crash worker stage unavailable: ' + stderr)), 15000)
    child.once('error', error => { clearTimeout(timeout); reject(error) })
    child.once('close', (code, signal) => { clearTimeout(timeout); reject(new Error(`synthetic worker exited before stage (${code}/${signal}): ${stderr}`)) })
    child.stdout.on('data', bytes => {
      stdout += bytes.toString()
      if (!stdout.includes('\n')) return
      clearTimeout(timeout)
      try { resolve(JSON.parse(stdout.slice(0, stdout.indexOf('\n')))) } catch (error) { reject(error) }
    })
  })
  assert.deepEqual(phase, { stage, proposal_id: proposalId })
  assert.equal(child.kill('SIGKILL'), true, 'kill only this test-owned paused child')
  const result = await exit
  assert.equal(result.signal, 'SIGKILL')
}

test('actual child-process kills retain consumption, cold reconcile once, and never reapply or fabricate completion', async t => {
  const expected = { beforewrite: 'failed', duringwrite: 'conflict', 'afterwrite-before-receipt': 'incomplete' }
  for (const [stage, state] of Object.entries(expected)) await t.test(stage, async st => {
    const f = effectFixture(st), { proposal, review, args } = accepted(f)
    f.workerRequest(args)
    f.closeGate(f.gate)
    await killAtStage(st, f, proposal.id, stage)
    f.gate = f.openGate()
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applying', 'killed effect transaction rolls back while committed spend survives')
    const retained = assertSpent(f, proposal.id, review)
    noCompletedResult(f, proposal.id)
    const attemptsFile = join(f.home, 'write-attempts.jsonl')
    const attempts = () => existsSync(attemptsFile) ? readFileSync(attemptsFile, 'utf8').trim().split('\n').filter(Boolean).length : 0
    assert.equal(attempts(), stage === 'beforewrite' ? 0 : 1)
    const targetAfterKill = f.read()
    assertReadiness(f, { ready: false, retained: 1, unresolved: 1, applying: 1 })
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applying',
      'readiness must leave interrupted effects unresolved until actual startup')
    const second = f.openGate()
    let startupReadChecks = 0
    f.beforeRead = () => {
      startupReadChecks++
      assert.throws(() => second.db.exec('BEGIN IMMEDIATE'), /locked|busy/i,
        'startup must hold the shared writer fence while reading the interrupted target')
    }
    assert.equal(f.gate.startup().ok, true)
    f.beforeRead = null
    assert.ok(startupReadChecks >= 1, 'fixture must observe a real reconciliation target read')
    assert.equal(noCompletedResult(f, proposal.id).state, state)
    assert.equal(JSON.stringify(retainedConsumption(f, proposal.id)), retained)
    assertReadiness(f, { ready: state === 'failed', retained: 1, unresolved: state === 'failed' ? 0 : 1,
      incomplete: state === 'incomplete' ? 1 : 0, conflict: state === 'conflict' ? 1 : 0 })
    f.reopen().startup()
    assert.equal(noCompletedResult(f, proposal.id).state, state)
    refuseWithoutWrite(f, () => f.gate.ownerOps.decide_review(args, 'synthetic-replay'))
    assert.equal(attempts(), stage === 'beforewrite' ? 0 : 1, 'restarts and replay must never perform a second write')
    assert.deepEqual(f.read(), targetAfterKill)
    assert.equal(f.gate.verify().ok, true)
  })
})

test('G startup with no trusted owner-state reader or a corrupted ledger stops before reconciliation or append', async t => {
  for (const fault of ['missing-owner-reader', 'corrupted-ledger']) await t.test(fault, async st => {
    const f = effectFixture(st), { proposal, review, args } = accepted(f)
    f.workerRequest(args)
    f.closeGate(f.gate)
    await killAtStage(st, f, proposal.id, 'beforewrite')
    f.gate = f.openGate({ ownerStateMode: fault === 'missing-owner-reader' ? 'missing' : 'configured' })
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applying')
    const retained = assertSpent(f, proposal.id, review)
    if (fault === 'corrupted-ledger') {
      const last = f.gate.db.prepare('SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1').get()
      const invalid = { seq: last.seq + 1, at: new Date(f.clock).toISOString(), event: 'synthetic-invalid-signature',
        proposal: null, target: null, base_sha: null, new_sha: null, detail: JSON.stringify({ synthetic: true }), prev: last.hash }
      invalid.hash = sha256(entryBody(invalid))
      invalid.sig = Buffer.alloc(64).toString('base64')
      // Add a test-owned invalid row; every original signed row/proof remains byte-identical and retained.
      f.gate.db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(invalid.seq, invalid.at, invalid.event,
        invalid.proposal, invalid.target, invalid.base_sha, invalid.new_sha, invalid.detail, invalid.prev, invalid.hash, invalid.sig)
      assert.equal(f.gate.verify().ok, false, 'fixture must contain an actual invalid ledger signature')
    }
    const originalRows = JSON.stringify(f.gate.db.prepare('SELECT * FROM ledger ORDER BY seq').all())
    for (const observe of readinessMethods(f)) {
      const before = durableSnapshot(f)
      assert.throws(observe, fault === 'missing-owner-reader' ? /owner.*state|unconfigured|unavailable/i : /ledger|signature|invalid/i)
      assert.equal(durableSnapshot(f), before, 'refused readiness must not append, change budgets/state, reconcile or write')
    }
    assert.throws(() => f.gate.startup(), fault === 'missing-owner-reader' ? /owner.*state|unconfigured|unavailable/i : /ledger|signature|invalid/i)
    assert.equal(JSON.stringify(f.gate.db.prepare('SELECT * FROM ledger ORDER BY seq').all()), originalRows,
      'failed startup may not append genesis-target, reconciliation or gate-start rows')
    assert.equal(JSON.stringify(retainedConsumption(f, proposal.id)), retained)
    assert.equal(noCompletedResult(f, proposal.id).state, 'applying', 'failed startup retains the interrupted effect fence')
    assert.equal(f.writes.length, 0)
    assert.equal(f.read().toString(), BEFORE)
    assert.equal(existsSync(join(f.home, 'write-attempts.jsonl')), false)
  })
})
