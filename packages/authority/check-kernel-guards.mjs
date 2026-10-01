#!/usr/bin/env node
/**
 * Direct replay and rollback checks for the copied donor kernel and its original-default
 * TrustedStateStore. These probes import no broker, approval adapter, or store subclass.
 * Their only inputs are the public conformance vector plus synthetic consumption IDs.
 * Mutations run in realpath temporary copies and must fail the particular guard assertion;
 * a pin refusal, import error, or unrelated assertion never counts as killing a mutation.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'

const SELF = fileURLToPath(import.meta.url)
const DONOR = join(dirname(SELF), 'upstream')
const REPLAY_FILE = 'vendor/authority/lib/reducer.js'
const STORE_FILE = 'scripts/aukora/trusted-state-store.mjs'
const VECTOR_FILE = 'vendor/authority/conformance/v1.json'
const REPLAY_GUARD = '    if (request.consumptionId !== null && state.consumedIds.includes(request.consumptionId))\n        return refused("replay");'
const HIGH_WATER_GUARD = '    if (rec.state.receiptHead.count < highWater) { // @source L278\n      throw new RollbackRefusedError(`trusted state rolled back: loaded count ${rec.state.receiptHead.count} < high-water ${highWater}`); // @source L279\n    } // @source L280'
const SCENARIOS = ['pure-replay', 'store-replay', 'store-high-water']
const FAILURE_CHECKS = {
  'pure-replay': 'KERNEL_REPLAY_REFUSAL',
  'store-replay': 'STORE_KERNEL_REPLAY_REFUSAL',
  'store-high-water': 'STORE_HIGH_WATER_ROLLBACK_REFUSAL',
}
const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex')

class GuardCheckError extends Error {
  constructor(check, observed) {
    super(check)
    this.check = check
    this.observed = observed
  }
}

async function probe(upstream, scenario) {
  assert(SCENARIOS.includes(scenario), `unknown guard scenario: ${scenario}`)
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'prime-kernel-guard-probe-'))
  let checks = 0
  const check = (condition, name, observed) => {
    if (!condition) throw new GuardCheckError(name, observed)
    checks++
  }
  const withStore = (Store, dir, body) => {
    // No injected decide, external highWater seam, adapter, or broker guard.
    const store = new Store(dir)
    try { store.open(); return body(store) } finally { store.close() }
  }
  try {
    const kernel = await import(pathToFileURL(join(upstream, 'vendor/authority/lib/index.js')).href)
    const { TrustedStateStore, RollbackRefusedError } = await import(pathToFileURL(join(upstream, STORE_FILE)).href)
    const vector = JSON.parse(readFileSync(join(upstream, VECTOR_FILE), 'utf8')).reducerVectors[0]
    const genesis = () => structuredClone(vector.trustedState)
    const policyBytes = new TextEncoder().encode(vector.policyCanonicalJson)
    const request = (id, suffix) => ({ ...structuredClone(vector.request), requestId: `synthetic-guard-${suffix}`, consumptionId: id })
    const args = (id, suffix) => ({
      genesis: genesis(), request: request(id, suffix), policyBytes, nowMs: vector.nowMs,
      effect: { effectId: `synthetic-effect-${suffix}`, descriptorKind: 'public-test-only', targetPath: 'synthetic:no-effect', contentHash: 'a'.repeat(64) },
    })

    if (scenario === 'pure-replay') {
      const first = kernel.decide(request('synthetic-consumption-a', 'first'), genesis(), policyBytes, vector.nowMs)
      check(first.decision.status === 'allowed', 'KERNEL_FIRST_USE_ALLOWED', first.decision)
      check(first.nextState.consumedIds.length === 1 && first.nextState.consumedIds[0] === 'synthetic-consumption-a', 'KERNEL_FIRST_USE_CONSUMED', first.nextState.consumedIds)
      const repeated = kernel.decide(request('synthetic-consumption-a', 'different-request'), first.nextState, policyBytes, vector.nowMs)
      check(repeated.decision.status === 'refused' && repeated.decision.code === 'replay', FAILURE_CHECKS[scenario], repeated.decision)
      check(JSON.stringify(repeated.nextState.consumedIds) === JSON.stringify(first.nextState.consumedIds), 'KERNEL_REPLAY_CONSUMED_IDS_UNCHANGED', repeated.nextState.consumedIds)
    }

    if (scenario === 'store-replay') {
      const dir = join(root, 'original-default-store')
      const first = withStore(TrustedStateStore, dir, store => store.authorizeAndPrepare(args('synthetic-consumption-a', 'first')))
      check(first.ok === true && first.record.state.receiptHead.count === 1, 'STORE_FIRST_USE_PREPARED', first)
      check(first.record.state.consumedIds.length === 1 && first.record.state.consumedIds[0] === 'synthetic-consumption-a', 'STORE_FIRST_USE_CONSUMED', first.record.state.consumedIds)
      const statePath = join(dir, 'trusted-state.json'), witnessPath = join(dir, 'receipt-highwater.json')
      const beforeState = readFileSync(statePath), beforeWitness = readFileSync(witnessPath)
      const repeated = withStore(TrustedStateStore, dir, store => store.authorizeAndPrepare(args('synthetic-consumption-a', 'different-request')))
      // Check the second return before any reload: a replay mutant commits duplicate IDs,
      // and a later validator's corruption error must not hide that successful replay.
      check(repeated.ok === false && repeated.decision.status === 'refused' && repeated.decision.code === 'replay', FAILURE_CHECKS[scenario], { ok: repeated.ok, decision: repeated.decision })
      check(readFileSync(statePath).equals(beforeState), 'STORE_REPLAY_STATE_UNCHANGED')
      check(readFileSync(witnessPath).equals(beforeWitness), 'STORE_REPLAY_HIGH_WATER_UNCHANGED')
      const loaded = withStore(TrustedStateStore, dir, store => store.load(genesis()))
      check(loaded.state.receiptHead.count === 1 && loaded.prepared.length === 1, 'STORE_REPLAY_PERSISTENCE_UNCHANGED', loaded)
    }

    if (scenario === 'store-high-water') {
      const dir = join(root, 'original-default-store')
      const first = withStore(TrustedStateStore, dir, store => store.authorizeAndPrepare(args('synthetic-consumption-a', 'first')))
      check(first.ok === true && first.record.state.receiptHead.count === 1, 'STORE_ROLLBACK_FIRST_PREPARED', first)
      const statePath = join(dir, 'trusted-state.json'), witnessPath = join(dir, 'receipt-highwater.json')
      const olderState = readFileSync(statePath)
      const second = withStore(TrustedStateStore, dir, store => store.authorizeAndPrepare(args('synthetic-consumption-b', 'second')))
      check(second.ok === true && second.record.state.receiptHead.count === 2, 'STORE_ROLLBACK_SECOND_PREPARED', second)
      const retainedWitness = readFileSync(witnessPath)
      check(JSON.parse(retainedWitness).count === 2, 'STORE_HIGH_WATER_ADVANCED', JSON.parse(retainedWitness))
      // Restore an existing, valid state file. The original default missing-file branch
      // is deliberately not used; this checks its actual retained-high-water comparison.
      writeFileSync(statePath, olderState, { mode: 0o600 })
      const expectRollback = (body, name) => {
        let observed, error
        try { observed = withStore(TrustedStateStore, dir, body) } catch (caught) { error = caught }
        if (error && !(error instanceof RollbackRefusedError)) throw error
        check(error instanceof RollbackRefusedError && error.message === 'trusted state rolled back: loaded count 1 < high-water 2', name,
          error ? { error: error.name, message: error.message } : { loadedCount: observed?.state?.receiptHead?.count, ok: observed?.ok })
      }
      expectRollback(store => store.load(genesis()), FAILURE_CHECKS[scenario])
      expectRollback(store => store.authorizeAndPrepare(args('synthetic-consumption-c', 'after-restore')), 'STORE_HIGH_WATER_PREPARE_REFUSAL')
      check(readFileSync(statePath).equals(olderState), 'STORE_ROLLBACK_STATE_UNCHANGED')
      check(readFileSync(witnessPath).equals(retainedWitness), 'STORE_ROLLBACK_HIGH_WATER_UNCHANGED')
    }
    return { status: 'PASS', scenario, checks }
  } finally { rmSync(root, { recursive: true, force: true }) }
}

function childProbe(upstream, scenario) {
  return new Promise((resolveChild, reject) => {
    const child = spawn(process.execPath, [SELF, '--guard-probe', upstream, scenario], { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = '', stderr = ''
    const timeout = setTimeout(() => child.kill('SIGKILL'), 30000)
    child.stdout.on('data', bytes => { stdout += bytes })
    child.stderr.on('data', bytes => { stderr += bytes })
    child.once('error', error => { clearTimeout(timeout); reject(error) })
    child.once('close', (code, signal) => {
      clearTimeout(timeout)
      let result
      try { result = JSON.parse(stdout) } catch { reject(new Error(`guard probe did not return JSON (${scenario}, exit ${code}, signal ${signal}): ${stdout}${stderr}`)); return }
      resolveChild({ code, result, stderr })
    })
  })
}

function copiedRuntime(root, name) {
  const copy = join(root, name)
  mkdirSync(join(copy, 'vendor'), { recursive: true, mode: 0o700 })
  cpSync(join(DONOR, 'vendor/authority'), join(copy, 'vendor/authority'), { recursive: true, verbatimSymlinks: true })
  for (const relative of [STORE_FILE, 'plugins/aukora-kira/lib/strict-read.mjs']) {
    mkdirSync(dirname(join(copy, relative)), { recursive: true, mode: 0o700 })
    cpSync(join(DONOR, relative), join(copy, relative))
  }
  return realpathSync(copy)
}

function removeGuard(copy, relative, guard, replacement) {
  const file = join(copy, relative), source = readFileSync(file, 'utf8')
  assert.equal(source.split(guard).length - 1, 1, `expected one mutation target in ${relative}`)
  writeFileSync(file, source.replace(guard, replacement))
}

export async function runKernelGuardChecks() {
  const provenance = JSON.parse(readFileSync(join(DONOR, 'vendor/authority/PROVENANCE.json'), 'utf8'))
  for (const [relative, entries, pinnedPath] of [
    [REPLAY_FILE, provenance.generated, 'lib/reducer.js'],
    [VECTOR_FILE, provenance.upstream, 'conformance/v1.json'],
  ]) {
    const entry = entries.find(pin => pin.path === pinnedPath)
    assert(entry, `missing donor pin for ${relative}`)
    assert.equal(digest(join(DONOR, relative)), entry.sha256, `donor pin mismatch: ${relative}`)
  }
  const watched = [REPLAY_FILE, STORE_FILE, VECTOR_FILE, 'vendor/authority/PROVENANCE.json', 'vendor/authority/reference/trustedStateStore.ts', 'vendor/authority/reference/PROVENANCE.json']
  const before = new Map(watched.map(relative => [relative, digest(join(DONOR, relative))]))
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'prime-kernel-guard-mutations-'))
  try {
    const baseline = []
    for (const scenario of SCENARIOS) {
      const result = await childProbe(DONOR, scenario)
      assert.equal(result.code, 0, JSON.stringify(result))
      assert.equal(result.result.status, 'PASS', JSON.stringify(result))
      assert.equal(result.result.scenario, scenario)
      baseline.push(result.result)
    }
    const replayCopy = copiedRuntime(root, 'replay-guard-removed')
    removeGuard(replayCopy, REPLAY_FILE, REPLAY_GUARD, '    // Disposable mutation: kernel replay refusal removed.')
    const highWaterCopy = copiedRuntime(root, 'high-water-guard-removed')
    removeGuard(highWaterCopy, STORE_FILE, HIGH_WATER_GUARD, '    // Disposable mutation: loaded-state high-water refusal removed.')
    const mutations = []
    for (const [copy, scenario, mutation] of [
      [replayCopy, 'pure-replay', 'kernel-replay-guard-removed'],
      [replayCopy, 'store-replay', 'kernel-replay-guard-removed'],
      [highWaterCopy, 'store-high-water', 'original-store-high-water-guard-removed'],
    ]) {
      const result = await childProbe(copy, scenario)
      assert.equal(result.code, 1, `mutation survived or failed unexpectedly: ${JSON.stringify(result)}`)
      assert.equal(result.result.status, 'FAIL', JSON.stringify(result))
      assert.equal(result.result.failed_check, FAILURE_CHECKS[scenario], `mutation was not caught by its direct guard assertion: ${JSON.stringify(result)}`)
      mutations.push({ mutation, scenario, caught_by: result.result.failed_check, observed: result.result.observed })
    }
    return { status: 'PASS', checks: baseline.reduce((total, result) => total + result.checks, 0), baseline, mutations,
      scope: 'Direct pure kernel and original-default TrustedStateStore; public synthetic fixtures; temporary copies only' }
  } finally {
    rmSync(root, { recursive: true, force: true })
    for (const [relative, hash] of before) assert.equal(digest(join(DONOR, relative)), hash, `donor changed during mutation checks: ${relative}`)
  }
}

if (process.argv[1] && resolve(process.argv[1]) === SELF) {
  if (process.argv[2] === '--guard-probe') {
    try { console.log(JSON.stringify(await probe(realpathSync(process.argv[3]), process.argv[4]))) }
    catch (error) {
      console.log(JSON.stringify({ status: 'FAIL', scenario: process.argv[4], failed_check: error.check ?? null, observed: error.observed ?? null, error: error.message }))
      process.exitCode = 1
    }
  } else {
    console.log(JSON.stringify(await runKernelGuardChecks()))
  }
}
