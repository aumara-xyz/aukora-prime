// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic source checks only: real read-only SQLite, original signed ledger and
// historical P-256 proof validation. The public carrier seam does not qualify
// installed protected-file custody or startup admission.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { join } from 'node:path'
import test from 'node:test'

const carrierUrl = new URL('../packages/boundary-gate/host/aura/context.mjs', import.meta.url).href
const gateUrl = new URL('../packages/boundary-gate/src/gate.mjs', import.meta.url)
const publicCarrierState = Symbol.for('aukora.synthetic.preconstruction-public-carrier')
globalThis[publicCarrierState] = { text: null, texts: null, reads: [] }
// Only this existing protected PUBLIC carrier module is substituted. The gate,
// owner verifier, ledger, fs and DatabaseSync modules are never mocked.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (context.parentURL?.includes('/packages/boundary-gate/src/gate.mjs')
      && specifier.endsWith('/host/aura/context.mjs')) return { url: carrierUrl, shortCircuit: true }
    return nextResolve(specifier, context)
  },
  load(url, context, nextLoad) {
    if (url === gateUrl.href && process.env.AUKORA_OWNER_READINESS_REMOVE_LEDGER_GUARD === '1') {
      const source = readFileSync(gateUrl, 'utf8')
      const guard = "if (!checked.ok) throw new Error('readiness refused: signed ledger unavailable')"
      assert.equal(source.split(guard).length - 1, 1, 'removal control changes only the named signed-chain refusal')
      return { format: 'module', shortCircuit: true,
        source: source.replace(guard, '/* synthetic removal control: signed-chain refusal removed */') }
    }
    if (url === carrierUrl) return { format: 'module', shortCircuit: true, source: `
      export const AURA_CONTEXT_PATH = '/etc/aukora-boundary-gate/aura-context.json'
      export function readProtectedAuraData(path) {
        const s = globalThis[Symbol.for('aukora.synthetic.preconstruction-public-carrier')]
        s.reads.push(path)
        if (s.text === null) throw new Error('synthetic protected public carrier unavailable')
        return s.texts?.length ? s.texts.shift() : s.text
      }
    ` }
    return nextLoad(url, context)
  },
})

const { ownerAuthorizationReadiness } = await import(gateUrl.href)
const { entryBody, sha256 } = await import('../packages/boundary-gate/src/ledger.mjs')
const { AFTER, BEFORE, decision, effectFixture, fixtureParent, proofFor } = await import('./fixtures/owner-effect-worker.mjs')
const { DatabaseSync } = process.getBuiltinModule('node:sqlite')

function carrier(f) {
  return { version: 1, kind: 'aukora-aura-context/v1', owner_subject: f.ownerState.owner_subject,
    store_dir: join(f.home, 'synthetic-read-only-store'),
    source: { db_path: join(f.home, 'gate.db'), source_id: 'synthetic-preconstruction-readiness',
      public_key_pem: f.gatePair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      key_sha256: sha256(f.gatePair.publicKey.export({ format: 'der', type: 'spki' })),
      max_rows: 256, max_bytes: 1048576, max_record_bytes: 48 * 1024 },
    // These public fields belong to the existing carrier, not G authority.
    // No secret path is opened and no Nostr controller profile is fabricated.
    nostr: {}, anchors: [], python_executable: '/usr/bin/python3' }
}

function useCarrier(configuration) {
  globalThis[publicCarrierState].text = JSON.stringify(configuration)
  globalThis[publicCarrierState].texts = null
  globalThis[publicCarrierState].reads = []
}

function inspect(f, reader = () => f.ownerState) {
  return ownerAuthorizationReadiness({ home: f.home, readOwnerState: reader })
}

function rows(db) {
  return db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all()
    .map(({ name }) => [name, db.prepare('SELECT * FROM "' + name.replaceAll('"', '""') + '" ORDER BY rowid').all()])
}

function files(home) {
  return readdirSync(home).sort().map(name => {
    const path = join(home, name), st = lstatSync(path)
    assert.ok(st.isFile() && !st.isSymbolicLink(), 'synthetic observation has regular retained files only')
    return { name, mode: st.mode, size: st.size, mtime: st.mtimeMs, sha256: sha256(readFileSync(path)) }
  })
}

function snapshot(f) {
  return JSON.stringify({ rows: rows(f.gate?.db ?? f.db), files: files(f.home), writes: f.writes ?? 0 })
}

function assertUnchanged(f, fn) {
  const before = snapshot(f)
  try { return fn() } finally {
    assert.equal(snapshot(f), before, 'preconstruction observation must not create files, change bytes/schema/rows, reconcile, sign or write')
  }
}

function accept(f) {
  const proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  const result = f.gate.ownerOps.decide_review(decision(review, proof), 'synthetic-public-readiness-fixture')
  assert.equal(result.applied, true)
  return { proposal, review, result }
}

function expectation(f, verified, counts = {}) {
  return { version: 1, kind: 'aukora-boundary-gate-readiness/v1', ready: true,
    gate_pubkey_sha256: sha256(f.gatePair.publicKey.export({ format: 'der', type: 'spki' })),
    owner_state_sha256: sha256(JSON.stringify(f.ownerState)), owner_subject: f.ownerState.owner_subject,
    owner_root_id: f.ownerState.owner_root_id, owner_epoch: f.ownerState.owner_epoch,
    registry_sha256: f.ownerState.registry_sha256, activation_sha256: f.ownerState.activation_sha256,
    ledger: { entries: verified.entries, head: verified.head },
    consumed_effects: { retained: 0, unresolved: 0, applying: 0, incomplete: 0, conflict: 0, ...counts } }
}

function assertObservation(f, expected) {
  const before = Date.now(), result = assertUnchanged(f, () => inspect(f)), after = Date.now()
  const { checked_at_ms, ...rest } = result
  assert.ok(Number.isSafeInteger(checked_at_ms) && checked_at_ms >= before && checked_at_ms <= after,
    'preconstruction time comes from the current trusted clock')
  assert.deepEqual(rest, expected, 'public readiness is the exact closed original-history observation')
  assert.deepEqual(globalThis[publicCarrierState].reads, Array(2).fill('/etc/aukora-boundary-gate/aura-context.json'),
    'verifier obtains and freshly rechecks the gate key only from the fixed existing public carrier')
}

function retainedCopy(t, f, fault) {
  const before = snapshot(f), home = mkdtempSync(join(fixtureParent(), fault ? 'readiness-damaged-' : 'readiness-public-'))
  // A newly owned DELETE-journal snapshot keeps the original WAL fixture intact.
  // Construction happens here, before observation. The verifier must only open
  // this existing SQLite file read-only and must never create or migrate it.
  const db = new DatabaseSync(join(home, 'gate.db'))
  try {
    db.exec('BEGIN IMMEDIATE')
    const schema = f.gate.db.prepare("SELECT type, name, sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, name").all()
    for (const { sql } of schema) db.exec(sql)
    for (const [name, originalRows] of rows(f.gate.db)) {
      const quoted = '"' + name.replaceAll('"', '""') + '"'
      const columns = f.gate.db.prepare('PRAGMA table_info(' + quoted + ')').all().map(row => row.name)
      const insert = db.prepare('INSERT INTO ' + quoted + '(' + columns.map(column => '"' + column.replaceAll('"', '""') + '"').join(',')
        + ') VALUES(' + columns.map(() => '?').join(',') + ')')
      for (const originalRow of originalRows) {
        const row = { ...originalRow }
        if (name === 'owner_authorization_consumptions') {
          if (fault === 'proof_sha256') row.proof_sha256 = sha256('synthetic-changed-retained-proof')
          if (fault === 'accepted_at_ms') row.accepted_at_ms++
          if (fault === 'owner_state_text') row.owner_state_text = JSON.stringify({ ...JSON.parse(row.owner_state_text),
            registry_sha256: sha256('synthetic-changed-retained-registry') })
        }
        if (name === 'owner_authorization_reviews' && fault === 'authorization_text') {
          const authorization = JSON.parse(row.authorization_text)
          authorization.after_sha256 = sha256('synthetic-changed-authorized-bytes')
          row.authorization_text = JSON.stringify(authorization)
        }
        if (name === 'proposals' && fault === 'terminal-label') row.state = 'failed'
        insert.run(...columns.map(column => row[column]))
      }
    }
    db.exec('COMMIT')
  } catch (error) { db.exec('ROLLBACK'); db.close(); throw error }
  t.after(() => db.close())
  assert.equal(snapshot(f), before, 'snapshot construction preserves every original WAL byte, signed row and stored proof')
  assert.equal(db.prepare('PRAGMA journal_mode').get().journal_mode, 'delete')
  return { home, db, gatePair: f.gatePair, ownerState: f.ownerState }
}

test('preconstruction verifier returns fresh and original applied bindings without operational private/bearer files', t => {
  assert.equal(typeof ownerAuthorizationReadiness, 'function', 'H must receive its concrete synchronous preconstruction export')
  const f = effectFixture(t)
  for (const name of ['receipt-ed25519.pem', 'owner.json', 'owner-bearer.txt'])
    assert.equal(existsSync(join(f.home, name)), false, 'positive fixture does not supply a production constructor secret')
  const fresh = retainedCopy(t, f)
  useCarrier(carrier(fresh))
  assertObservation(fresh, expectation(f, f.gate.verify()))
  const { result } = accept(f), original = JSON.stringify(result)
  const applied = retainedCopy(t, f)
  useCarrier(carrier(applied))
  assertObservation(applied, expectation(f, f.gate.verify(), { retained: 1 }))
  assert.equal(f.read().toString(), AFTER)
  f.ownerState = { ...f.ownerState, owner_epoch: f.ownerState.owner_epoch + 1,
    registry_sha256: sha256('synthetic-current-public-registry'), activation_sha256: sha256('synthetic-current-public-activation') }
  applied.ownerState = f.ownerState
  useCarrier(carrier(applied))
  assertObservation(applied, expectation(f, f.gate.verify(), { retained: 1 }))
  assert.equal(JSON.stringify(f.gate.proposeOps.state({ id: result.receipt.proposal })), original,
    'a current registry refresh neither invalidates nor reconstructs the original historical receipt')
})

test('missing existing database and missing existing schema refuse without initialization', async t => {
  for (const fault of ['missing-database', 'missing-schema']) await t.test(fault, st => {
    const f = effectFixture(st), home = mkdtempSync(join(fixtureParent(), 'readiness-virgin-'))
    const configuration = carrier({ ...f, home })
    useCarrier(configuration)
    let db
    if (fault === 'missing-schema') {
      // Only a genuine empty SQLite file, not openDb's schema constructor.
      db = new DatabaseSync(join(home, 'gate.db'))
      db.exec('CREATE TABLE synthetic_only(value TEXT)')
      st.after(() => db.close())
    }
    const before = files(home)
    assert.throws(() => ownerAuthorizationReadiness({ home, readOwnerState: () => f.ownerState }),
      fault === 'missing-database' ? { code: 'ENOENT' } : /schema|table|unavailable/i)
    assert.deepEqual(files(home), before, 'refusal cannot create DB/WAL/key/bearer/schema files or alter the empty DB')
    assert.equal(existsSync(join(home, 'receipt-ed25519.pem')), false)
  })
})

test('preconstruction rejects unavailable, wrong-owner, wrong-db, wrong-key and non-Ed25519 public carriers', async t => {
  for (const fault of ['unavailable', 'owner', 'db', 'hash', 'algorithm', 'extra-source-field']) await t.test(fault, st => {
    const original = effectFixture(st), f = retainedCopy(st, original), configuration = carrier(f)
    if (fault === 'owner') configuration.owner_subject = 'aukora:1:' + sha256('synthetic-unrelated-owner')
    if (fault === 'db') configuration.source.db_path = join(f.home, 'unrelated.db')
    if (fault === 'hash') configuration.source.key_sha256 = sha256('synthetic-wrong-public-key')
    if (fault === 'algorithm') {
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      configuration.source.public_key_pem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString()
      configuration.source.key_sha256 = sha256(pair.publicKey.export({ format: 'der', type: 'spki' }))
    }
    if (fault === 'extra-source-field') configuration.source.ready = true
    useCarrier(configuration)
    if (fault === 'unavailable') globalThis[publicCarrierState].text = null
    assertUnchanged(f, () => assert.throws(() => inspect(f), /public|source|carrier|owner|key|invalid|unavailable|binding/i))
  })
})

test('preconstruction validates plain synchronous current owner state without evaluating getters', async t => {
  for (const fault of ['missing-reader', 'promise', 'getter', 'then-getter', 'extra-field', 'root']) await t.test(fault, st => {
    const f = retainedCopy(st, effectFixture(st))
    useCarrier(carrier(f))
    let getterRuns = 0, reader = () => f.ownerState
    if (fault === 'missing-reader') reader = undefined
    if (fault === 'promise') reader = () => Promise.resolve(f.ownerState)
    if (fault === 'getter') {
      const state = { ...f.ownerState }
      Object.defineProperty(state, 'owner_epoch', { enumerable: true, get() { getterRuns++; return 1 } })
      reader = () => state
    }
    if (fault === 'then-getter') {
      const state = { ...f.ownerState }
      Object.defineProperty(state, 'then', { get() { getterRuns++; return undefined } })
      reader = () => state
    }
    if (fault === 'extra-field') reader = () => ({ ...f.ownerState, ready: true })
    if (fault === 'root') reader = () => ({ ...f.ownerState, owner_root_id: sha256('synthetic-unrelated-root') })
    assertUnchanged(f, () => assert.throws(() => ownerAuthorizationReadiness({ home: f.home, readOwnerState: reader }),
      /owner|state|synchronous|unconfigured|invalid|unavailable/i))
    assert.equal(getterRuns, 0, 'untrusted accessors must be rejected before execution')
  })
})

test('owner-state and public-carrier drift during one observation refuse without mutations', async t => {
  for (const fault of ['owner-drift', 'final-owner-drift', 'public-carrier-drift']) await t.test(fault, st => {
    const f = retainedCopy(st, effectFixture(st)), configuration = carrier(f)
    useCarrier(configuration)
    let reads = 0
    const reader = () => {
      reads++
      return fault === 'owner-drift' && reads > 1 || fault === 'final-owner-drift' && reads === 4
        ? { ...f.ownerState, owner_epoch: f.ownerState.owner_epoch + 1 }
        : f.ownerState
    }
    if (fault === 'public-carrier-drift') globalThis[publicCarrierState].texts = [JSON.stringify(configuration),
      JSON.stringify({ ...configuration, source: { ...configuration.source, source_id: 'synthetic-changed-public-source' } })]
    assertUnchanged(f, () => assert.throws(() => inspect(f, reader), /owner|state|source|carrier|changed|readiness|unavailable|binding/i))
  })
})

test('valid signed consumption with an unresolved effect remains not ready and never reconciles', t => {
  const f = effectFixture(t), proposal = f.propose(), review = f.review(proposal), proof = proofFor(f, review.owner_authorization)
  f.beforeRead = () => {
    if (f.gate.db.prepare('SELECT 1 FROM owner_authorization_consumptions WHERE proposal_id=?').get(proposal.id))
      throw new Error('synthetic effect source unreadable')
  }
  assert.throws(() => f.gate.ownerOps.decide_review(decision(review, proof), 'synthetic-unknown-effect'), /synthetic effect source unreadable/)
  f.beforeRead = null
  assert.equal(f.gate.db.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id).state, 'applying')
  assert.equal(f.gate.verify().ok, true)
  const observed = retainedCopy(t, f)
  useCarrier(carrier(observed))
  const expected = expectation(f, f.gate.verify(), { retained: 1, unresolved: 1, applying: 1 })
  expected.ready = false
  assertObservation(observed, expected)
  assert.equal(f.read().toString(), BEFORE)
  assert.equal(f.writes.length, 0)
  assert.equal(f.gate.db.prepare('SELECT state FROM proposals WHERE id=?').get(proposal.id).state, 'applying')
})

test('original signed ledger verification is required before a public readiness result', t => {
  const f = effectFixture(t), last = f.gate.db.prepare('SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1').get()
  const invalid = { seq: last.seq + 1, at: new Date(f.clock).toISOString(), event: 'synthetic-invalid-signature',
    proposal: null, target: null, base_sha: null, new_sha: null, detail: JSON.stringify({ synthetic: true }), prev: last.hash }
  invalid.hash = sha256(entryBody(invalid)); invalid.sig = Buffer.alloc(64).toString('base64')
  f.gate.db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(invalid.seq, invalid.at, invalid.event,
    invalid.proposal, invalid.target, invalid.base_sha, invalid.new_sha, invalid.detail, invalid.prev, invalid.hash, invalid.sig)
  assert.equal(f.gate.verify().ok, false, 'fixture retains an actual invalid signature alongside all original signed entries')
  const observed = retainedCopy(t, f)
  useCarrier(carrier(observed))
  assertUnchanged(observed, () => assert.throws(() => inspect(observed), /ledger|signature|invalid|unavailable/i))
})

test('removing the sole signed-chain refusal makes the real invalid-signature court fail', () => {
  const childEnv = { ...process.env, AUKORA_OWNER_READINESS_REMOVE_LEDGER_GUARD: '1' }
  // The child is its own Node test runner, not a runner-managed test child.
  delete childEnv.NODE_TEST_CONTEXT
  const child = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-name-pattern',
    '^original signed ledger verification is required before a public readiness result$', new URL(import.meta.url).pathname],
  { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
    env: childEnv })
  assert.equal(child.error, undefined, 'task-owned removal child must run to its factual assertion result')
  assert.equal(child.status, 1, 'guard removal must break the actual rejection court, not a test double')
  assert.match(child.stdout, /not ok.*original signed ledger verification[\s\S]*Missing expected exception/,
    'the control must fail specifically because genuine invalid signed history was accepted')
})

test('retained consumption facts and applied terminal outcome must match original signed history', async t => {
  for (const fault of ['proof_sha256', 'accepted_at_ms', 'owner_state_text', 'authorization_text', 'terminal-label']) await t.test(fault, st => {
    const f = effectFixture(st)
    accept(f)
    const damaged = retainedCopy(st, f, fault)
    useCarrier(carrier(damaged))
    assertUnchanged(damaged, () => assert.throws(() => inspect(damaged), /retained|binding|consum|original|proof|issuance|unavailable|terminal|signed/i))
  })
})
