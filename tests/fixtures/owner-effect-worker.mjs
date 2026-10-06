// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic, retained fixtures only. No owner enrollment or installed custody claim.
import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { appendFileSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readFileSync, realpathSync, writeFileSync, writeSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createGate } from '../../packages/boundary-gate/src/gate.mjs'
import { keyFingerprint, openDb, sha256 } from '../../packages/boundary-gate/src/ledger.mjs'
import { THEME_TARGET, themeTarget } from '../../packages/boundary-gate/src/targets.mjs'
import { OWNER_KEY_ALGORITHM, ownerRootPin } from '../../packages/owner-key/src/index.mjs'
import { ownerAuthorizationSigningBytes } from '../../packages/owner-key/src/authorization.mjs'

export const BEFORE = '{"accent": "default"}'
export const AFTER = '{"accent": "#112233"}'
export const DIFFERENT = '{"accent": "#445566"}'
export const BASE_TIME = 1791072000000
export const JOURNAL_ID = 'synthetic-owner-effect-fence'
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')

function assertPrivateDirectory(directory) {
  const st = lstatSync(directory)
  assert.ok(st.isDirectory() && !st.isSymbolicLink(), 'fixture parent must be a real directory')
  assert.equal(st.mode & 0o777, 0o700, 'fixture parent must already be private (0700)')
  if (typeof process.getuid === 'function') assert.equal(st.uid, process.getuid(), 'fixture parent must belong to caller')
  assert.equal(realpathSync(directory), directory, 'fixture parent must not traverse symlinks')
}

export function fixtureParent() {
  const directory = resolve(process.env.AUKORA_OWNER_EFFECT_FIXTURE_PARENT ?? join(homedir(), '.aukora-owner-effect-fixtures'))
  assert.ok(isAbsolute(directory), 'fixture parent must be absolute')
  const fromRepo = relative(repoRoot, directory)
  assert.ok(fromRepo.startsWith('..' + sep) || isAbsolute(fromRepo), 'fixture custody must be outside the repo checkout')
  if (!existsSync(directory)) mkdirSync(directory, { mode: 0o700 })
  // An existing parent's mode is verified, never repaired or broadened by a test.
  assertPrivateDirectory(directory)
  return directory
}

function durableBytes(file, bytes) {
  const fd = openSync(file, 'w', 0o600)
  try { writeFileSync(fd, bytes); fsyncSync(fd) } finally { closeSync(fd) }
}

function retainedWriteAttempt(home, id, bytes) {
  const file = join(home, 'write-attempts.jsonl')
  appendFileSync(file, JSON.stringify({ proposal_id: id, bytes_sha256: sha256(bytes) }) + '\n', { mode: 0o600 })
  const fd = openSync(file, 'r')
  try { fsyncSync(fd) } finally { closeSync(fd) }
}

function keyFromPrivate(privateKey) {
  const pub = createPublicKey(privateKey)
  return { priv: privateKey, pub, pubPem: pub.export({ format: 'pem', type: 'spki' }).toString(), fp: keyFingerprint(pub) }
}

export function proofFor(f, authorization) {
  return { algorithm: OWNER_KEY_ALGORITHM, authorization,
    signature_base64: sign('sha256', ownerAuthorizationSigningBytes(authorization), f.ownerPair.privateKey).toString('base64') }
}

export function decision(review, proof) {
  return { id: review.id, base_sha: review.base_sha, new_sha: review.new_sha,
    review_challenge: review.review_challenge, outcome: 'allowed-once', owner_authorization_proof: proof }
}

export function effectFixture(t, { create = createGate } = {}) {
  const home = mkdtempSync(join(fixtureParent(), 'case-'))
  assertPrivateDirectory(home)
  const gatePair = generateKeyPairSync('ed25519')
  const ownerPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  // These exclusive private files are for test-owned child cold opens only. They are never printed.
  writeFileSync(join(home, 'synthetic-gate.pem'), gatePair.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600, flag: 'wx' })
  writeFileSync(join(home, 'synthetic-owner.pem'), ownerPair.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600, flag: 'wx' })
  const spki = ownerPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  const f = { home, dbPath: join(home, 'gate.db'), targetFile: join(home, 'synthetic-theme.json'),
    clock: BASE_TIME, writes: [], beforeRead: null, beforeWrite: null, beforeOwnerState: null, ownerObservations: 0,
    gatePair, ownerPair, gates: new Set(),
    ownerState: { version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + sha256('synthetic-effect-owner'),
      owner_root_spki_base64: spki, owner_root_id: ownerRootPin(spki).owner_root_id, owner_epoch: 1,
      registry_sha256: sha256('synthetic-effect-registry'), activation_sha256: sha256('synthetic-effect-activation') } }
  durableBytes(f.targetFile, Buffer.from(BEFORE))
  f.read = () => readFileSync(f.targetFile)
  f.setTarget = text => durableBytes(f.targetFile, Buffer.from(text))
  const store = {
    read: () => { f.beforeRead?.(); return f.read() },
    write: (target, _spec, bytes, id) => {
      f.beforeWrite?.({ target, bytes: Buffer.from(bytes), id })
      retainedWriteAttempt(home, id, bytes)
      durableBytes(f.targetFile, bytes)
      f.writes.push({ target, id, bytes: Buffer.from(bytes) })
    },
  }
  f.openGate = ({ ownerStateMode = 'configured', dbPath = f.dbPath } = {}) => {
    const db = openDb(dbPath)
    db.exec('PRAGMA busy_timeout=0')
    try {
      const args = { home, key: keyFromPrivate(gatePair.privateKey),
        owner: { bearer: 'synthetic-fixture-only', hmacKey: sha256('synthetic-unused-legacy-hmac') }, db, store,
        targets: { [THEME_TARGET]: themeTarget(home) }, now: () => f.clock,
        journalId: JOURNAL_ID, limits: { rejectCooldownMs: 0, maxPerWindow: 100 } }
      if (ownerStateMode !== 'missing') args.readOwnerState = () => {
        f.ownerObservations++
        f.beforeOwnerState?.()
        return f.ownerState
      }
      const gate = create(args)
      f.gates.add(gate)
      return gate
    } catch (error) { db.close(); throw error }
  }
  f.closeGate = gate => { gate.close(); f.gates.delete(gate) }
  f.gate = f.openGate()
  f.reopen = () => { f.closeGate(f.gate); f.gate = f.openGate(); return f.gate }
  f.propose = (content = AFTER) => f.gate.proposeOps.propose({ target: THEME_TARGET, content,
    claimed_base: sha256(f.read()), why: 'Synthetic effect fence check', session: 'synthetic', call_id: 'synthetic-call' })
  f.review = proposal => f.gate.ownerOps.review({ id: proposal.id })
  f.workerRequest = args => {
    const descriptor = { clock: f.clock, owner_state: f.ownerState, decision: args }
    writeFileSync(join(home, 'worker-request.json'), JSON.stringify(descriptor), { mode: 0o600, flag: 'wx' })
  }
  t.after(() => {
    for (const gate of f.gates) gate.close()
    f.gates.clear()
    // Retain all owned fixture files, consumed proofs and failed state for inspection. No cleanup deletes.
  })
  return f
}

function pauseAt(stage, proposalId) {
  writeSync(1, JSON.stringify({ stage, proposal_id: proposalId }) + '\n')
  // Only the parent test kills this child. The pause never advances an effect or retries it.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0)
}

function crashWorker(home, stage) {
  assertPrivateDirectory(home)
  assert.ok(['beforewrite', 'duringwrite', 'afterwrite-before-receipt'].includes(stage), 'unknown synthetic crash stage')
  const descriptor = JSON.parse(readFileSync(join(home, 'worker-request.json'), 'utf8'))
  const gatePrivate = createPrivateKey(readFileSync(join(home, 'synthetic-gate.pem')))
  const targetFile = join(home, 'synthetic-theme.json')
  const db = openDb(join(home, 'gate.db'))
  let armed = stage === 'beforewrite'
  const exec = db.exec.bind(db)
  db.exec = sql => {
    const result = exec(sql)
    if (armed && sql === 'COMMIT') {
      const state = db.prepare('SELECT state FROM proposals WHERE id=?').get(descriptor.decision.id)
      const consumed = db.prepare('SELECT 1 FROM owner_authorization_consumptions WHERE proposal_id=?').get(descriptor.decision.id)
      if (state?.state === 'applying' && consumed) { armed = false; pauseAt(stage, descriptor.decision.id) }
    }
    return result
  }
  const gate = createGate({ home, key: keyFromPrivate(gatePrivate),
    owner: { bearer: 'synthetic-fixture-only', hmacKey: sha256('synthetic-unused-legacy-hmac') }, db,
    targets: { [THEME_TARGET]: themeTarget(home) }, now: () => descriptor.clock,
    readOwnerState: () => descriptor.owner_state, journalId: JOURNAL_ID,
    store: { read: () => readFileSync(targetFile), write: (_target, _spec, bytes, id) => {
      retainedWriteAttempt(home, id, bytes)
      if (stage === 'duringwrite') {
        durableBytes(targetFile, Buffer.from(bytes).subarray(0, Math.floor(bytes.length / 2)))
        pauseAt(stage, id)
      }
      durableBytes(targetFile, bytes)
      pauseAt(stage, id)
    } } })
  gate.ownerOps.decide_review(descriptor.decision, 'synthetic-child-owner-channel')
  throw new Error('crash worker must never reach a completed result')
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv[2], '--crash-stage', 'worker only accepts its synthetic crash mode')
  crashWorker(resolve(process.argv[3]), process.argv[4])
}
