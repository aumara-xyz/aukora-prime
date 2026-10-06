// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic source checks only: real read-only SQLite, original signed ledger and
// historical P-256 proof validation. Only public carrier filesystem metadata and
// FD reads are synthetic; this does not qualify installed custody or admission.
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'

const syntheticFsUrl = 'aukora-synthetic:readiness-public-fs'
const gateUrl = new URL('../packages/boundary-gate/src/gate.mjs', import.meta.url)
const repoRoot = fileURLToPath(new URL('..', import.meta.url))
const publicCarrierState = Symbol.for('aukora.synthetic.preconstruction-public-carrier')
globalThis[publicCarrierState] = { text: null, texts: null, reads: [], closes: 0, liveFds: 0,
  namedReads: 0, ancestorReads: 0, fault: null, bytes: null }
const builtinFsNames = Object.keys(process.getBuiltinModule('node:fs')).filter(name => /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(name))
const overriddenFsNames = new Set(['lstatSync', 'openSync', 'fstatSync', 'readSync', 'closeSync', 'realpathSync'])
const publicFsSource = `
  const fs = process.getBuiltinModule('node:fs')
  const fixed = '/etc/aukora-boundary-gate/aura-context.json'
  const ancestors = ['/', '/etc', '/etc/aukora-boundary-gate']
  const handles = new Map()
  let nextFd = 1073741824
  const state = () => globalThis[Symbol.for('aukora.synthetic.preconstruction-public-carrier')]
  const fileInfo = bytes => ({dev:1,ino:7,uid:0,gid:0,mode:0o100644,nlink:1,size:bytes.length,
    mtimeMs:100,ctimeMs:100,isDirectory:()=>false,isFile:()=>true,isSymbolicLink:()=>false})
  function lstatSync(file, ...args) {
    const s = state()
    if (ancestors.includes(file)) {
      s.ancestorReads++
      return {dev:1,ino:2,uid:s.fault==='ancestor-owner' || s.fault==='ancestor-drift' && s.ancestorReads>3?1000:0,
        mode:s.fault==='ancestor-write'?0o40775:0o40755,nlink:1,size:0,
        isDirectory:()=>s.fault!=='ancestor-symlink',isFile:()=>false,isSymbolicLink:()=>s.fault==='ancestor-symlink'}
    }
    if (file===fixed) {
      const info=fileInfo(s.bytes ?? Buffer.from(s.text ?? '', 'utf8'))
      s.namedReads++
      if (s.fault==='named-identity' && s.namedReads>1) info.ino++
      return info
    }
    return fs.lstatSync(file, ...args)
  }
  function openSync(file, flags, ...args) {
    if (file!==fixed) return fs.openSync(file, flags, ...args)
    const s = state()
    s.reads.push(file)
    if (s.text===null || s.fault==='file-symlink') throw Object.assign(new Error('synthetic public file unavailable'),{code:'ENOENT'})
    if ((flags & (fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_WRONLY | fs.constants.O_RDWR))!==0
      || (flags & fs.constants.O_NOFOLLOW)===0 || (flags & fs.constants.O_NONBLOCK)===0)
      throw new Error('synthetic public file requires exact nonmutating no-follow open')
    const text = s.texts?.length ? s.texts.shift() : s.text
    const fd = nextFd++
    handles.set(fd,{bytes:s.bytes ?? Buffer.from(text,'utf8'),offset:0,statReads:0})
    s.liveFds++
    return fd
  }
  function fstatSync(fd, ...args) {
    if (!handles.has(fd)) return fs.fstatSync(fd, ...args)
    const h=handles.get(fd),s=state(),info=fileInfo(h.bytes)
    h.statReads++
    if (s.fault==='file-owner') info.uid=1000
    if (s.fault==='file-write') info.mode=0o100664
    if (s.fault==='file-hardlink') info.nlink=2
    if (s.fault==='fd-identity' && h.statReads>1) info.ino++
    if (s.fault==='oversize') info.size=1024*1024+1
    return info
  }
  function readSync(fd, buffer, offset, length, position) {
    if (!handles.has(fd)) return fs.readSync(fd,buffer,offset,length,position)
    const h=handles.get(fd),count=Math.min(length,h.bytes.length-h.offset)
    h.bytes.copy(buffer,offset,h.offset,h.offset+count)
    h.offset+=count
    return count
  }
  function closeSync(fd) {
    if (handles.has(fd)) {handles.delete(fd);state().closes++;state().liveFds--;return}
    return fs.closeSync(fd)
  }
  function realpathSync(file, ...args) {
    return file===fixed || ancestors.includes(file) ? file : fs.realpathSync(file,...args)
  }
  const forwarded = {...fs,lstatSync,openSync,fstatSync,readSync,closeSync,realpathSync}
  export default forwarded
  ${builtinFsNames.map(name => overriddenFsNames.has(name) ? 'export { ' + name + ' }'
    : 'export const ' + name + ' = forwarded[' + JSON.stringify(name) + ']').join('\n')}
`
// Only the fixed PUBLIC carrier and its reserved synthetic FDs are substituted.
// Gate/owner validators, ledger/crypto/DatabaseSync and all other fs paths run real code.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'node:fs') return { url: syntheticFsUrl, shortCircuit: true }
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
    if (url === syntheticFsUrl) return { format: 'module', shortCircuit: true, source: publicFsSource }
    return nextLoad(url, context)
  },
})

const { ownerAuthorizationReadiness } = await import(gateUrl.href)
const { entryBody, sha256, readGateReadinessPublicSource } = await import('../packages/boundary-gate/src/ledger.mjs')
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
  globalThis[publicCarrierState].closes = 0
  globalThis[publicCarrierState].liveFds = 0
  globalThis[publicCarrierState].namedReads = 0
  globalThis[publicCarrierState].ancestorReads = 0
  globalThis[publicCarrierState].fault = null
  globalThis[publicCarrierState].bytes = null
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
  assert.equal(globalThis[publicCarrierState].closes, 2, 'both public descriptors are closed')
  assert.equal(globalThis[publicCarrierState].liveFds, 0, 'observation leaks no public descriptor')
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

test('local public carrier parser preserves exact UTF8 and rejects decoded duplicates, rounding, surrogate, BOM and depth faults', async t => {
  const f = effectFixture(t), configuration = carrier(f)
  useCarrier(configuration)
  const text = globalThis[publicCarrierState].text
  assert.deepEqual(readGateReadinessPublicSource(), { text, value: configuration },
    'real local strict parser returns the original public bytes and decoded data')
  assert.equal(globalThis[publicCarrierState].closes, 1)
  const faults = [
    ['decoded-duplicate', text.replace('"version":1', '"version":1,"\\u0076ersion":1'), 'JSON_DUPLICATE_KEY'],
    ['decimal-rounding', text.replace('"max_rows":256', '"max_rows":256.000000000000000001'), 'JSON_UNSAFE_NUMBER'],
    ['lone-surrogate', text.replace('"nostr":{}', '"nostr":{"unused":"\\ud800"}'), 'JSON_LONE_SURROGATE'],
    ['BOM', '\ufeff' + text, 'JSON_MALFORMED'],
    ['negative-zero', text.replace('"version":1', '"version":-0'), 'JSON_NEGATIVE_ZERO'],
    ['depth', text.replace('"nostr":{}', '"nostr":{"unused":' + '['.repeat(65) + '1' + ']'.repeat(65) + '}'), 'JSON_DEPTH'],
  ]
  for (const [fault, bytes, reason] of faults) await t.test(fault, () => {
    useCarrier(configuration)
    globalThis[publicCarrierState].text = bytes
    assert.throws(() => readGateReadinessPublicSource(), { reason })
    assert.equal(globalThis[publicCarrierState].liveFds, 0, 'parse refusal follows an already closed public descriptor')
    assert.equal(globalThis[publicCarrierState].closes, 1)
  })
  await t.test('invalid-UTF8', () => {
    useCarrier(configuration)
    globalThis[publicCarrierState].bytes = Buffer.from([0xc3, 0x28])
    assert.throws(() => readGateReadinessPublicSource(), /^Error: protected-public-data:unavailable$/u)
    assert.equal(globalThis[publicCarrierState].liveFds, 0)
    assert.equal(globalThis[publicCarrierState].closes, 1)
  })
})

test('real protected reader rejects synthetic public metadata and identity faults and closes opened descriptors', async t => {
  for (const fault of ['ancestor-owner', 'ancestor-write', 'ancestor-symlink', 'ancestor-drift', 'file-owner',
    'file-write', 'file-hardlink', 'file-symlink', 'fd-identity', 'named-identity', 'oversize']) await t.test(fault, st => {
    const f = retainedCopy(st, effectFixture(st))
    useCarrier(carrier(f))
    globalThis[publicCarrierState].fault = fault
    assertUnchanged(f, () => assert.throws(() => inspect(f), /^Error: protected-public-data:unavailable$/u))
    assert.equal(globalThis[publicCarrierState].liveFds, 0, 'every opened synthetic public FD closes even on identity refusal')
    const beforeOpen = ['ancestor-owner', 'ancestor-write', 'ancestor-symlink', 'file-symlink'].includes(fault)
    assert.equal(globalThis[publicCarrierState].closes, beforeOpen ? 0 : 1)
  })
})

test('corrected eight-file gate closure imports cold alone while old gate imports refuse missing Aura context', () => {
  const selected = ['boundary-gate/src/gate.mjs', 'boundary-gate/src/ledger.mjs', 'boundary-gate/src/card.mjs',
    'boundary-gate/src/targets.mjs', 'boundary-gate/src/secrets.mjs', 'boundary-gate/src/release-floor.mjs',
    'owner-key/src/index.mjs', 'owner-key/src/authorization.mjs']
  const materialize = oldGate => {
    const home = mkdtempSync(join(fixtureParent(), oldGate ? 'readiness-flat-old-' : 'readiness-flat-new-'))
    for (const relative of selected) {
      const destination = join(home, relative)
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 })
      const bytes = oldGate && relative === 'boundary-gate/src/gate.mjs'
        ? execFileSync('git', ['show', '809c7c5e1668222567f150cf72b7d9aecfba4489:packages/' + relative], { cwd: repoRoot })
        : readFileSync(join(repoRoot, 'packages', relative))
      writeFileSync(destination, bytes, { flag: 'wx', mode: 0o600 })
    }
    assert.deepEqual(readdirSync(home).sort(), ['boundary-gate', 'owner-key'],
      'flat fixture contains only the two selected source directories')
    for (const directory of ['contracts', 'host', 'plugins', 'scripts', 'node_modules'])
      assert.equal(existsSync(join(home, directory)), false, 'no unselected dependency is materialized')
    return home
  }
  const run = home => {
    const childEnv = { ...process.env }
    delete childEnv.NODE_TEST_CONTEXT
    delete childEnv.AUKORA_OWNER_READINESS_REMOVE_LEDGER_GUARD
    return spawnSync(process.execPath, ['--input-type=module', '-e',
      "const g=await import(process.argv[1]); if(typeof g.ownerAuthorizationReadiness!=='function') throw new Error('missing concrete export'); console.log('FLAT_GATE_IMPORT_OK')",
      pathToFileURL(join(home, 'boundary-gate/src/gate.mjs')).href],
    { cwd: home, env: childEnv, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 })
  }
  const current = run(materialize(false))
  assert.equal(current.error, undefined)
  assert.equal(current.status, 0, current.stderr)
  assert.equal(current.stdout, 'FLAT_GATE_IMPORT_OK\n', 'fresh child imports concrete export without any module substitution')
  const old = run(materialize(true))
  assert.equal(old.error, undefined)
  assert.equal(old.status, 1, 'old gate source alone must fail in the identical minimal closure')
  assert.match(old.stderr, /ERR_MODULE_NOT_FOUND/u)
  assert.match(old.stderr, /boundary-gate\/host\/aura\/context\.mjs/u,
    'control fails for the precise old uninstalled dependency, not an unrelated missing module')
})
