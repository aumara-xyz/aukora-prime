// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable installed-release records and fixture keys; no enrollment or production-floor claim.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { tmpdir } from 'node:os'
import { generateKeyPairSync, sign } from 'node:crypto'
import test from 'node:test'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { keyFingerprint, openDb, sha256 } from '../packages/boundary-gate/src/ledger.mjs'
import { PLUGIN_SET_TARGET, pluginSetApprovalText, pluginSetTarget } from '../packages/boundary-gate/src/targets.mjs'
import { FLOOR_KIND, readFloor } from '../packages/boundary-gate/src/release-floor.mjs'
import { OWNER_KEY_ALGORITHM, ownerRootPin } from '../packages/owner-key/src/index.mjs'
import { AUTHORIZATION_FIELDS, ownerAuthorizationSigningBytes, verifyOwnerAuthorization } from '../packages/owner-key/src/authorization.mjs'

const TIME = 1791072000000

function fixture(t, options = {}) {
  const home = fs.mkdtempSync(path.join(tmpdir(), 'aukora-plugin-set-floor-card-'))
  const releasesRoot = path.join(home, 'installed'), floorFile = path.join(home, 'release-floor.json')
  function installed(release) {
    const release_dir = 'release-' + release.slice(0, 7), build = path.join(releasesRoot, release_dir, '.dsh-build')
    fs.mkdirSync(build, { recursive: true })
    const plugin_set = sha256('fixture-plugin-set-' + release), operation = sha256('fixture-operation-' + release)
    const recordBytes = JSON.stringify({ fixture: true, release })
    fs.writeFileSync(path.join(build, 'aukora-release.json'), JSON.stringify({ tipSha: release }))
    fs.writeFileSync(path.join(build, 'plugin-set.json'), JSON.stringify({ setDigest: plugin_set }))
    fs.writeFileSync(path.join(build, 'genesis-artifacts.json'), recordBytes)
    return { release, release_dir, plugin_set, operation, record: sha256(recordBytes) }
  }
  const earlier = installed('a'.repeat(40)), latest = installed('b'.repeat(40))
  const ownerPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), gatePair = generateKeyPairSync('ed25519')
  const ownerSpki = ownerPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  const f = { home, releasesRoot, floorFile, earlier, latest, ownerPair, gatePair, clock: TIME,
    current: options.initial ? null : Buffer.from(pluginSetApprovalText(latest)), writes: [], floorUnreadable: false,
    floorReadHook: null, ownerStateHook: null, gate: null,
    floor: { kind: FLOOR_KIND, release: latest.release, release_dir: latest.release_dir, record: latest.record,
      signer_epoch: 1, ledger_seq: 10, signer_key_sha256: sha256('fixture-floor-signer'),
      ledger_hash: sha256('fixture-floor-entry'), history: [earlier.release] },
    ownerState: { version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + sha256('fixture-owner'),
      owner_root_spki_base64: ownerSpki, owner_root_id: ownerRootPin(ownerSpki).owner_root_id, owner_epoch: 1,
      registry_sha256: sha256('fixture-registry'), activation_sha256: sha256('fixture-activation') },
  }
  const originalOpen = fs.openSync
  fs.openSync = function(file, flags, ...rest) {
    if (file === floorFile && typeof flags === 'number' && (flags & 3) === 0) {
      f.floorReadHook?.()
      if (f.floorUnreadable) throw Object.assign(new Error('fixture release floor unreadable'), { code: 'EACCES' })
    }
    return originalOpen.call(this, file, flags, ...rest)
  }
  t.after(() => { fs.openSync = originalOpen; f.gate?.close(); fs.rmSync(home, { recursive: true, force: true }) })
  f.setFloor = value => {
    fs.rmSync(floorFile, { recursive: true, force: true })
    if (value !== null) fs.writeFileSync(floorFile, JSON.stringify(value))
  }
  f.advanceFloor = () => f.setFloor({ ...f.floor, ledger_seq: f.floor.ledger_seq + 1, ledger_hash: sha256('changed-floor-entry') })
  f.setFloor(options.absentFloor ? null : f.floor)
  f.target = (options.pluginSetTarget ?? pluginSetTarget)(home, { releasesRoot, floorFile })
  f.gate = (options.createGate ?? createGate)({ home, db: openDb(path.join(home, 'gate.db')),
    key: { priv: gatePair.privateKey, pub: gatePair.publicKey, fp: keyFingerprint(gatePair.publicKey),
      pubPem: gatePair.publicKey.export({ type: 'spki', format: 'pem' }).toString() },
    owner: { bearer: 'disposable-fixture-only' }, targets: { [PLUGIN_SET_TARGET]: f.target }, now: () => f.clock,
    readOwnerState: () => { f.ownerStateHook?.(); return f.ownerState },
    store: { read: () => f.current === null ? null : Buffer.from(f.current),
      write: (target, _spec, bytes, id) => { f.writes.push({ target, id, bytes: Buffer.from(bytes) }); f.current = Buffer.from(bytes) } },
  })
  f.raise = () => f.gate.ownerOps.raise({ target: PLUGIN_SET_TARGET, content: pluginSetApprovalText(earlier), why: 'fixture operator release approval' })
  f.review = proposal => f.gate.ownerOps.review({ id: proposal.id })
  f.proof = review => ({ algorithm: OWNER_KEY_ALGORITHM, authorization: review.owner_authorization,
    signature_base64: sign('sha256', ownerAuthorizationSigningBytes(review.owner_authorization), ownerPair.privateKey).toString('base64') })
  f.decide = (review, proof = f.proof(review)) => f.gate.ownerOps.decide_review({ id: review.id,
    base_sha: review.base_sha, new_sha: review.new_sha, review_challenge: review.review_challenge,
    outcome: 'allowed-once', owner_authorization_proof: proof }, 'fixture-owner-channel')
  return f
}

function assertUnavailableCard(review) {
  assert.equal(review.from_to, null)
  assert.equal(review.displayable, false)
  assert.match(JSON.stringify(review), /UNAVAILABLE/)
}

function assertNoEffect(f, action) {
  let result
  try { result = action() } catch (error) { assert.match(String(error.message), /floor|unavailable|display|review|refus|facts/i) }
  if (result !== undefined) assert.equal(result.applied, false)
  assert.equal(f.writes.length, 0)
}

function assertValidGProof(f, review, proof) {
  const expectations = { owner_root_spki_base64: f.ownerState.owner_root_spki_base64,
    authorization_digest: review.authorization_digest,
    ...Object.fromEntries(AUTHORIZATION_FIELDS.map(field => [field, review.owner_authorization[field]])) }
  assert.equal(verifyOwnerAuthorization(proof, expectations, f.clock).status, 'verified-owner-authorization')
}

function issueSnapshot(f, review) {
  const row = f.gate.db.prepare('SELECT detail FROM ledger WHERE seq=? AND hash=?').get(review.review_issue.ledger_seq, review.review_issue.ledger_hash)
  return JSON.parse(row.detail).target_review
}

function armFloorFault(f, stage, fault) {
  const change = () => {
    if (fault === 'changed') f.advanceFloor()
    else if (fault === 'deleted') f.setFloor(null)
    else f.floorUnreadable = true
  }
  if (stage === 'before consume') { change(); return }
  if (stage === 'final commit') {
    let armed = true
    f.ownerStateHook = () => {
      if (armed && f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n) {
        armed = false
        change()
      }
    }
    return
  }
  const db = f.gate.db, originalExec = db.exec.bind(db)
  let armed = true
  db.exec = sql => {
    const result = originalExec(sql)
    if (armed && sql === 'COMMIT' && db.prepare("SELECT 1 FROM proposals WHERE state='applying'").get()) {
      armed = false
      change()
    }
    return result
  }
}

async function inMemoryMutant(file, replacements, exported) {
  const url = new URL(file, import.meta.url)
  let source = fs.readFileSync(url, 'utf8')
  for (const [before, after] of replacements) {
    assert.ok(source.includes(before), 'named floor mutation must match the current source')
    source = source.replace(before, after)
  }
  source = source.replace(/from\s+(['"])(\.[^'"]+)\1/g, (_match, quote, specifier) =>
    'from ' + quote + new URL(specifier, url).href + quote)
  return (await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64')))[exported]
}

test('an absent floor is a valid initial approval fact', t => {
  const f = fixture(t, { absentFloor: true, initial: true }), proposal = f.raise(), review = f.review(proposal)
  assert.equal(readFloor(f.floorFile), null)
  assert.equal(review.base_sha, 'absent')
  assert.equal(review.displayable, true)
  assert.match(review.from_to, /first plugin-set approval/)
  assert.doesNotMatch(review.from_to, /ROLLBACK|UNAVAILABLE/)
  const retained = issueSnapshot(f, review)
  assert.equal(retained.available, true)
  assert.equal(JSON.parse(retained.facts_text).release_floor, null)
  assert.equal(f.decide(review).applied, true)
  assert.equal(f.writes.length, 1)
})

test('a readable release floor preserves the explicit rollback fact', t => {
  const f = fixture(t), proposal = f.raise(), review = f.review(proposal)
  assert.deepEqual(Object.keys(review), ['version', 'id', 'kind', 'target', 'base_sha', 'new_sha', 'content', 'diff',
    'from_to', 'clarity_label', 'what_this_does', 'model_note', 'displayable', 'created', 'expires', 'review_challenge',
    'review_expires', 'review_issued_at_ms', 'pubkey_fp', 'gate_pubkey_sha256', 'owner_authorization',
    'authorization_digest', 'review_issue'])
  assert.deepEqual(Object.keys(review.owner_authorization), AUTHORIZATION_FIELDS)
  assert.equal(review.displayable, true)
  assert.match(review.from_to, /GATE FACT: ROLLBACK/)
  assert.match(review.from_to, /release-aaaaaaa.*release-bbbbbbb/)
  const retained = issueSnapshot(f, review)
  assert.equal(retained.from_to, review.from_to)
  assert.deepEqual(JSON.parse(retained.facts_text), { from_to: review.from_to, release_floor: f.floor })
  assert.equal(f.decide(review).applied, true)
  assert.equal(f.writes.length, 1)
})

test('unavailable floor evidence cannot be displayed as absence or approved with a valid G proof', async t => {
  const faults = {
    unreadable: f => { f.floorUnreadable = true },
    malformed: f => { fs.writeFileSync(f.floorFile, '{not-json') },
    'wrong JSON type': f => { fs.writeFileSync(f.floorFile, '[]') },
    directory: f => { f.setFloor(null); fs.mkdirSync(f.floorFile) },
    symlink: f => { const other = path.join(f.home, 'other-floor.json'); fs.writeFileSync(other, JSON.stringify(f.floor)); f.setFloor(null); fs.symlinkSync(other, f.floorFile) },
    legacy: f => { f.setFloor({ kind: 'aukora-release-floor/v1', release: f.latest.release, release_dir: f.latest.release_dir,
      record: f.latest.record, applied_at: new Date(TIME).toISOString(), history: [f.earlier.release] }) },
  }
  for (const [name, fault] of Object.entries(faults)) await t.test(name, st => {
    const f = fixture(st)
    fault(f)
    assert.throws(() => readFloor(f.floorFile))
    const proposal = f.raise(), review = f.review(proposal), proof = f.proof(review)
    assert.equal(proposal.displayable, true, 'byte displayability must not substitute for readable floor evidence')
    assert.match(proposal.popup.plain_change, /UNAVAILABLE/)
    assert.match(JSON.stringify(proposal.popup.flags), /UNAVAILABLE/)
    const pending = f.gate.ownerOps.pending().pending.find(row => row.id === proposal.id)
    assert.match(pending.plain, /UNAVAILABLE/)
    assert.match(JSON.stringify(pending.warnings), /UNAVAILABLE/)
    assertUnavailableCard(review)
    assert.deepEqual(issueSnapshot(f, review), { available: false, from_to: null, facts_text: null })
    assertValidGProof(f, review, proof)
    assertNoEffect(f, () => f.decide(review, proof))
    assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 0)
  })
})

test('floor changes and lost readability are rechecked at consumption, final commit, and pre-write', async t => {
  for (const stage of ['before consume', 'final commit', 'pre-write']) for (const fault of ['changed', 'unreadable', 'deleted'])
    await t.test(stage + ': ' + fault, st => {
      const f = fixture(st), proposal = f.raise(), review = f.review(proposal), proof = f.proof(review)
      const original = issueSnapshot(f, review)
      assert.match(review.from_to, /ROLLBACK/)
      assertValidGProof(f, review, proof)
      armFloorFault(f, stage, fault)
      assertNoEffect(f, () => f.decide(review, proof))
      assert.deepEqual(issueSnapshot(f, review), original, 'the original reviewed floor must not be silently replaced')
      const consumed = f.gate.db.prepare('SELECT * FROM owner_authorization_consumptions WHERE proposal_id=?').get(proposal.id)
      if (stage === 'pre-write') {
        assert.ok(consumed, 'the already committed proof remains spent despite the refused effect')
        assert.equal(JSON.parse(consumed.proof_text).signature_base64, proof.signature_base64)
        assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'failed')
        assert.equal(f.gate.db.prepare('SELECT state FROM owner_authorization_reviews WHERE authorization_id=?').get(review.authorization_digest).state, 'spent')
      } else {
        assert.equal(consumed, undefined)
        assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'pending')
        assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE event='owner-authorization-consumed'").get().n, 0)
      }
      assert.equal(f.gate.verify().ok, true)
    })
})

test('an absent floor cannot erase previous target bytes or retained history', async t => {
  for (const historyDeleted of [false, true]) await t.test(historyDeleted ? 'retained history with deleted current target' : 'previous canonical target bytes', st => {
    const f = fixture(st)
    if (historyDeleted) {
      assert.equal(f.gate.startup().ok, true)
      assert.equal(f.gate.db.prepare("SELECT COUNT(*) n FROM ledger WHERE target=? AND event='genesis-target'").get(PLUGIN_SET_TARGET).n, 1)
      f.current = null
    }
    f.setFloor(null)
    assert.equal(readFloor(f.floorFile), null)
    const proposal = f.raise(), review = f.review(proposal), proof = f.proof(review)
    assert.match(proposal.popup.plain_change, /UNAVAILABLE/)
    assertUnavailableCard(review)
    assertValidGProof(f, review, proof)
    assertNoEffect(f, () => f.decide(review, proof))
    assert.equal(f.gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_consumptions').get().n, 0)
  })
})

test('a trailing newline in floor history cannot silently erase a rollback fact', t => {
  const f = fixture(t)
  f.setFloor({ ...f.floor, history: [f.earlier.release + '\n'] })
  assert.throws(() => readFloor(f.floorFile), /release-floor-malformed/)
  const proposal = f.raise(), review = f.review(proposal), proof = f.proof(review)
  assertUnavailableCard(review)
  assertValidGProof(f, review, proof)
  assertNoEffect(f, () => f.decide(review, proof))
})

test('specific in-memory floor faults have concrete unsafe witnesses', async t => {
  await t.test('read failure silently substituted as absent floor', async st => {
    const factory = await inMemoryMutant('../packages/boundary-gate/src/targets.mjs', [
      ['const floor = exactOwnerFloor(readFloor(floorFile))', 'let floor; try { floor = exactOwnerFloor(readFloor(floorFile)) } catch { floor = null }'],
    ], 'pluginSetTarget')
    const f = fixture(st, { pluginSetTarget: factory, initial: true })
    f.floorUnreadable = true
    const proposal = f.raise(), review = f.review(proposal), proof = f.proof(review)
    assertValidGProof(f, review, proof)
    assert.throws(() => assertUnavailableCard(review), assert.AssertionError)
    assert.equal(f.decide(review, proof).applied, true)
    assert.equal(f.writes.length, 1, 'the suppressed floor error crosses the effect boundary')
  })
  await t.test('final floor guard omitted commits changed facts and allows an effect after the floor is restored', async st => {
    const create = await inMemoryMutant('../packages/boundary-gate/src/gate.mjs', [
      ['assertTargetReview(p, c)', '/* fixture mutant omits final floor guard */'],
    ], 'createGate')
    const f = fixture(st, { createGate: create }), proposal = f.raise(), review = f.review(proposal), proof = f.proof(review)
    armFloorFault(f, 'final commit', 'changed')
    const db = f.gate.db, originalExec = db.exec.bind(db)
    let changedFactsAtCommit = false, restoredBeforeEffect = false
    db.exec = sql => {
      const consumptionCommit = sql === 'COMMIT' && db.prepare("SELECT 1 FROM proposals WHERE state='applying'").get()
      if (consumptionCommit && !restoredBeforeEffect)
        changedFactsAtCommit = readFloor(f.floorFile).ledger_seq !== f.floor.ledger_seq
      const result = originalExec(sql)
      if (consumptionCommit && changedFactsAtCommit && !restoredBeforeEffect) {
        f.setFloor(f.floor)
        restoredBeforeEffect = true
      }
      return result
    }
    let decision
    assert.throws(() => assertNoEffect(f, () => { decision = f.decide(review, proof); return decision }), assert.AssertionError)
    const accepted = f.gate.db.prepare('SELECT * FROM owner_authorization_consumptions WHERE proposal_id=?').get(proposal.id)
    assert.throws(() => assert.equal(accepted, undefined), assert.AssertionError)
    assert.ok(accepted, 'the omitted final guard durably accepts the stale reviewed floor')
    assert.equal(changedFactsAtCommit, true, 'changed floor facts were present at the consumption COMMIT')
    assert.equal(restoredBeforeEffect, true, 'the independent pre-write guard sees the original floor again')
    assert.equal(decision.applied, true)
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applied')
    assert.equal(f.writes.length, 1)
  })
  await t.test('pre-write floor guard omitted writes after a committed floor change', async st => {
    const create = await inMemoryMutant('../packages/boundary-gate/src/gate.mjs', [
      ['assertTargetReview(p, consumption)', '/* fixture mutant omits pre-write floor guard */'],
    ], 'createGate')
    const f = fixture(st, { createGate: create }), proposal = f.raise(), review = f.review(proposal), proof = f.proof(review)
    armFloorFault(f, 'pre-write', 'changed')
    assert.throws(() => assertNoEffect(f, () => f.decide(review, proof)), assert.AssertionError)
    assert.equal(f.writes.length, 1)
    assert.equal(f.gate.proposeOps.state({ id: proposal.id }).state, 'applied')
  })
  await t.test('exact floor identity wrapper omitted admits a mismatched floor release directory', async st => {
    const factory = await inMemoryMutant('../packages/boundary-gate/src/targets.mjs', [
      ['exactOwnerFloor(readFloor(floorFile))', 'readFloor(floorFile)'],
    ], 'pluginSetTarget')
    const f = fixture(st, { pluginSetTarget: factory })
    f.setFloor({ ...f.floor, release_dir: 'release-ccccccc' })
    assert.equal(readFloor(f.floorFile).release_dir, 'release-ccccccc', 'the parser accepts shape without joining the directory to the release')
    const proposal = f.raise(), review = f.review(proposal), proof = f.proof(review)
    assertValidGProof(f, review, proof)
    assert.match(review.from_to, /ROLLBACK.*release-ccccccc/)
    assert.match(review.from_to, /ADMIT/)
    assert.throws(() => assertUnavailableCard(review), assert.AssertionError)
    assert.equal(f.decide(review, proof).applied, true)
    assert.equal(f.writes.length, 1)
  })
})
