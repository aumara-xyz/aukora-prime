// SPDX-License-Identifier: AGPL-3.0-or-later
// Real serve entry and gate; synthetic Linux metadata and disposable software keys, never enrollment.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateKeyPairSync, sign, verify } from 'node:crypto'
import { registerHooks } from 'node:module'
import { spawnSync } from 'node:child_process'

const bin = new URL('../bin/gate.mjs', import.meta.url)
const self = fileURLToPath(import.meta.url)
const mutations = {
  wiring: ['...(readOwnerState === undefined ? {} : { readOwnerState }),', '', '/boundary-gate/bin/gate.mjs'],
  signature: ["if (!verify('sha256', ownerAuthorizationSigningBytes(a), key, Buffer.from(proof.signature_base64, 'base64'))) fail('signature')", '', '/owner-key/src/authorization.mjs'],
}

async function exercise(mode, directory, mutant) {
  if (mutant) registerHooks({ load(url, context, next) {
    const result = next(url, context), [before, after, suffix] = mutations[mutant]
    if (!url.split('?')[0].endsWith(suffix)) return result
    const source = String(result.source)
    assert.equal(source.split(before).length, 2, 'mutation preimage')
    return { ...result, source: source.replace(before, after) }
  } })
  const { OWNER_STATE_FILE } = await import('../src/owner-state.mjs')
  const { sha256 } = await import('../src/ledger.mjs')
  const { THEME_TARGET } = await import('../src/targets.mjs')
  const { ownerAuthorizationSigningBytes, ownerAuthorizationProofDigest } = await import('../../owner-key/src/authorization.mjs')
  const { serveGate, call } = await import('../src/server.mjs')
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' })
  const state = { version: 1, kind: 'aukora-owner-state/v1', owner_subject: 'aukora:1:' + sha256('fixture-owner'),
    owner_root_spki_base64: spki.toString('base64'), owner_root_id: sha256(spki), owner_epoch: 1,
    registry_sha256: sha256('fixture-registry'), activation_sha256: sha256('fixture-activation') }
  let present = mode !== 'legacy'
  const original = Object.fromEntries(['lstatSync', 'openSync', 'fstatSync', 'readSync', 'closeSync'].map(k => [k, fs[k]]))
  const fd = 900001, bytes = Buffer.from(JSON.stringify(state))
  const metadata = directory => ({ uid: 0, mode: directory ? 0o40755 : 0o100644, nlink: 1,
    size: directory ? 0 : bytes.length, ino: 10, dev: 1,
    isDirectory: () => directory, isFile: () => !directory, isSymbolicLink: () => false })
  fs.lstatSync = (file, ...args) => {
    if (file === OWNER_STATE_FILE) {
      if (!present) throw Object.assign(new Error('fixture absent'), { code: 'ENOENT' })
      return metadata(false)
    }
    if (['/', '/etc', '/etc/aukora-boundary-gate'].includes(file)) return metadata(true)
    return original.lstatSync(file, ...args)
  }
  fs.openSync = (file, ...args) => file === OWNER_STATE_FILE ? fd : original.openSync(file, ...args)
  fs.fstatSync = (file, ...args) => file === fd ? metadata(false) : original.fstatSync(file, ...args)
  fs.readSync = (file, buffer, offset, length, position) => file === fd
    ? bytes.copy(buffer, offset, position, position + length) : original.readSync(file, buffer, offset, length, position)
  fs.closeSync = (file, ...args) => file === fd ? undefined : original.closeSync(file, ...args)

  let gate, server, unavailable, serial = 0
  globalThis.ownerStateTestServe = async (g, options) => {
    gate = g
    if (mode === 'socket') {
      try { server = await serveGate(g, { ...options, runDir: path.relative(process.cwd(), options.runDir) }) }
      catch (error) { if (error.code !== 'EPERM') throw error; unavailable = 'listen EPERM' }
    }
    return server ?? { proposeSocket: 'fixture', ownerSocket: 'fixture', port: null }
  }
  registerHooks({ resolve(specifier, context, next) {
    if (context.parentURL?.startsWith(bin.href) && specifier === '../src/server.mjs')
      return { url: 'data:text/javascript,export const serveGate = globalThis.ownerStateTestServe', shortCircuit: true }
    return next(specifier, context)
  } })
  const home = path.join(directory, 'home'), targetRoot = path.join(directory, 'targets')
  fs.mkdirSync(home, { mode: 0o700 })
  fs.mkdirSync(path.join(targetRoot, path.dirname(THEME_TARGET)), { recursive: true })
  fs.writeFileSync(path.join(targetRoot, THEME_TARGET), '{"accent": "default"}')
  async function start() {
    process.argv = [process.execPath, fileURLToPath(bin), 'serve', '--home', home, '--run', path.join(directory, 'run'), '--target-root', targetRoot]
    await import(bin.href + '?fixture=' + serial++)
  }
  const request = (op, args) => mode === 'socket' ? call(server.ownerSocket, op, args)
    : Promise.resolve().then(() => gate.ownerOps[op](args, 'fixture owner.sock'))
  const decision = review => ({ id: review.id, base_sha: review.base_sha, new_sha: review.new_sha,
    review_challenge: review.review_challenge, outcome: 'allowed-once' })
  const proof = (review, key = pair.privateKey) => ({ algorithm: 'p256-ecdsa-sha256', authorization: review.owner_authorization,
    signature_base64: sign('sha256', ownerAuthorizationSigningBytes(review.owner_authorization), key).toString('base64') })
  const propose = () => gate.proposeOps.propose({ target: THEME_TARGET, content: '{"accent": "#112233"}',
    claimed_base: sha256(fs.readFileSync(path.join(targetRoot, THEME_TARGET))), why: 'Fixture change', session: 'fixture' })
  console.log = () => {} // Suppress the entry point's fixture paths/public fingerprint.
  try {
    await start()
    if (unavailable) return { skip: unavailable }
    const proposal = propose()
    let review = await request('review', { id: proposal.id })
    if (mode === 'legacy') {
      assert.equal(review.version, 2)
      const result = await request('decide_review', decision(review))
      assert.equal(result.applied, true); assert.equal(result.receipt.v, 2)
      assert.equal(typeof result.receipt.approval_evidence_hmac, 'string')
      assert.equal(verify(null, Buffer.from(JSON.stringify(result.receipt)), gate.pub, Buffer.from(result.receipt_sig, 'base64')), true)
      assert.equal(gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_required').get().n, 0)
      return { mode: 'legacy', applied: true }
    }
    assert.equal(review.version, 3)
    assert.equal(gate.db.prepare('SELECT COUNT(*) n FROM owner_authorization_required').get().n, 1)
    await assert.rejects(request('decide_review', decision(review)), /owner proof/)
    review = await request('review', { id: proposal.id })
    const stranger = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    await assert.rejects(request('decide_review', { ...decision(review), owner_authorization_proof: proof(review, stranger.privateKey) }), /signature/)
    assert.equal(fs.readFileSync(path.join(targetRoot, THEME_TARGET), 'utf8'), '{"accent": "default"}')
    if (mode === 'restart') {
      assert.throws(() => gate.db.exec('DELETE FROM owner_authorization_required'), /retained/)
      gate.close(); gate = null
      present = false; await start()
      await assert.rejects(request('review', { id: proposal.id }), /unconfigured/)
      gate.close(); gate = null
      // Even wholesale gate-owned DB replacement cannot remove the root-held requirement.
      for (const name of ['gate.db', 'gate.db-wal', 'gate.db-shm']) fs.rmSync(path.join(home, name), { force: true })
      present = true; await start()
      const fresh = propose(), next = await request('review', { id: fresh.id })
      assert.equal(next.version, 3)
      await assert.rejects(request('decide_review', decision(next)), /owner proof/)
      return { mode, retained: true }
    }
    review = await request('review', { id: proposal.id })
    const valid = proof(review)
    const result = await request('decide_review', { ...decision(review), owner_authorization_proof: valid })
    assert.equal(result.applied, true); assert.equal(result.receipt.v, 3)
    assert.equal(Object.hasOwn(result.receipt, 'approval_evidence_hmac'), false)
    assert.equal(result.receipt.owner_authorization.proof_sha256, ownerAuthorizationProofDigest(valid))
    assert.equal(verify(null, Buffer.from(JSON.stringify(result.receipt)), gate.pub, Buffer.from(result.receipt_sig, 'base64')), true)
    await assert.rejects(request('decide_review', { ...decision(review), owner_authorization_proof: valid }), /single use/)
    return { mode, applied: true }
  } finally {
    await server?.close(); gate?.close()
    Object.assign(fs, original)
  }
}

if (process.argv[2] === '--fixture') {
  const result = await exercise(process.argv[3], process.argv[4], process.argv[5])
  process.stdout.write(JSON.stringify(result) + '\n')
} else {
  function run(t, mode, mutant) {
    const directory = fs.mkdtempSync(path.join(process.cwd(), '.owner-state-bin-'))
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
    return spawnSync(process.execPath, [self, '--fixture', mode, directory, ...(mutant ? [mutant] : [])],
      { encoding: 'utf8', timeout: 20000, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } })
  }
  for (const mode of ['legacy', 'enforced', 'restart', 'socket']) test(`serve entry owner state: ${mode}`, t => {
    const result = run(t, mode)
    assert.equal(result.status, 0, result.stderr)
    const outcome = JSON.parse(result.stdout)
    if (outcome.skip) t.skip('UNPERFORMED: ' + outcome.skip)
    else assert.equal(outcome.mode, mode)
  })
  test('serve entry wiring and owner signature guard-removal mutants are killed', t => {
    for (const mutant of Object.keys(mutations)) {
      const result = run(t, 'enforced', mutant)
      assert.notEqual(result.status, 0, `${mutant} survived`)
      assert.match(result.stderr, /AssertionError/, `${mutant} must fail a behavior assertion`)
      assert.doesNotMatch(result.stderr, /mutation preimage/)
      t.diagnostic(`KILLED ${mutant}`)
    }
  })
}
