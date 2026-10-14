// SPDX-License-Identifier: AGPL-3.0-or-later
// Abrupt process exits at each durable first-bind step must recover to unbound or complete bound custody.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const lockName = 'browser-first-bind.lock', recordName = 'local-control.json'
const seedName = 'machine-seed-v3.json', overlayName = 'kira-deployment-overlay.patch.yml'
const crashExit = 86
const configuration = base => ({ dir: join(base, 'controller'), supportRoot: join(base, 'support'), stateRoot: join(base, 'state') })

if (process.argv[2] === '--crash-worker') {
  const stage = process.argv[3], config = configuration(process.argv[4])
  const originals = { openSync: fs.openSync, closeSync: fs.closeSync, fsyncSync: fs.fsyncSync }
  const descriptors = new Map()
  let latestCreate
  fs.openSync = (path, flags, ...args) => {
    const descriptor = originals.openSync(path, flags, ...args)
    descriptors.set(descriptor, path)
    const creates = typeof flags === 'number' ? (flags & fs.constants.O_CREAT) !== 0 : /[wx]/u.test(flags)
    if (creates) {
      if (path === join(config.dir, lockName)) latestCreate = 'LOCK'
      else if (path === join(config.dir, recordName)) latestCreate = 'RECORD'
      else if (path === join(config.dir, seedName)) latestCreate = 'SEED'
      else if (typeof path === 'string' && path.startsWith(`${join(config.supportRoot, overlayName)}.tmp-`)) latestCreate = 'OVERLAY'
    }
    return descriptor
  }
  fs.closeSync = descriptor => {
    try { return originals.closeSync(descriptor) } finally { descriptors.delete(descriptor) }
  }
  fs.fsyncSync = descriptor => {
    const result = originals.fsyncSync(descriptor)
    const parent = latestCreate === 'OVERLAY' ? config.supportRoot : config.dir
    if (latestCreate === stage && descriptors.get(descriptor) === parent) process.exit(crashExit)
    return result
  }
  syncBuiltinESMExports()
  try {
    const { createBrowserBinding } = await import('../plugins/aukora-aumlok/lib/browser-binding.mjs')
    const service = createBrowserBinding(config)
    const prepared = service.prepare({ handle: 'crash-fixture' })
    if (prepared.ok) await service.bind({ ceremonyId: prepared.draw.ceremonyId,
      typedPhrase: prepared.draw.words.join(' '), acknowledged: true })
    service.close()
    process.exit(2)
  } catch { process.exit(3) }
}

const { createBrowserBinding } = await import('../plugins/aukora-aumlok/lib/browser-binding.mjs')
const { recordProjection } = await import('../plugins/aukora-aumlok/lib/record-v3.mjs')
const { ed25519FromSeed } = await import('../plugins/aukora-aumlok/lib/derive-v3.mjs')
const { readKiraDeploymentOverlay } = await import('../plugins/aukora-kira/lib/memory-identity.mjs')
const scratch = fs.mkdtempSync(join(root, '.aumlok-browser-recovery-'))

function files(config) {
  return [join(config.dir, lockName), join(config.dir, recordName), join(config.dir, seedName),
    join(config.supportRoot, overlayName)]
}

function assertState(service, config, state) {
  const present = files(config).map(path => fs.existsSync(path))
  assert.deepEqual(present, state === 'unbound' ? [false, false, false, false] : [false, true, true, true],
    'startup reconciles all custody and overlay files before status')
  const status = service.status()
  assert.equal(status.ok, true, status.reason)
  assert.equal(status.state, state)
  assert.equal(status.bound, state === 'bound')
  if (state === 'unbound') return
  const record = JSON.parse(fs.readFileSync(join(config.dir, recordName), 'utf8'))
  const projection = recordProjection(record)
  const machine = JSON.parse(fs.readFileSync(join(config.dir, seedName), 'utf8'))
  const overlay = readKiraDeploymentOverlay(fs.readFileSync(join(config.supportRoot, overlayName), 'utf8'))
  assert.equal(status.subject, projection.subject)
  assert.equal(status.rootId, projection.rootId)
  assert.equal(overlay.subject, projection.subject)
  assert.equal(overlay.stateDir, join(config.stateRoot, 'kira-memory'))
  assert.equal(machine.ed25519PublicKeyHex, ed25519FromSeed(Buffer.from(machine.ed25519SeedHex, 'hex')).publicKeyHex)
  assert.equal(record.publicRoot.machines.some(entry => entry.index === machine.machineIndex
    && entry.ed25519 === machine.ed25519PublicKeyHex), true)
}

try {
  let passed = 0
  for (const [stage, snapshot, state] of [
    ['LOCK', [true, false, false, false], 'unbound'],
    ['RECORD', [true, true, false, false], 'unbound'],
    ['SEED', [true, true, true, false], 'bound'],
    ['OVERLAY', [true, true, true, true], 'bound'],
  ]) {
    const base = fs.mkdtempSync(join(scratch, `${stage.toLowerCase()}-`)), config = configuration(base)
    const worker = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--crash-worker', stage, base],
      { encoding: 'utf8', timeout: 120_000, maxBuffer: 128 * 1024 })
    assert.ifError(worker.error)
    assert.equal(worker.status, crashExit, `${stage}: worker must exit at the requested durable step`)
    assert.deepEqual(files(config).map(path => fs.existsSync(path)), snapshot, `${stage}: exact crash boundary`)
    const service = createBrowserBinding(config)
    try {
      assertState(service, config, state)
      if (state === 'unbound') {
        const prepared = service.prepare({ handle: 'fresh-crash-fixture' })
        assert.equal(prepared.ok, true, prepared.reason)
        const bound = await service.bind({ ceremonyId: prepared.draw.ceremonyId,
          typedPhrase: prepared.draw.words.join(' '), acknowledged: true })
        assert.equal(bound.ok, true, bound.reason)
        assert.equal(service.status().state, 'bound')
        assertState(service, config, 'bound')
      }
      passed += 1
    } finally { service.close() }
  }
  console.log(`aumlok browser crash recovery: ${passed} PASS, 0 FAIL (LOCK, RECORD, SEED, OVERLAY; fresh binds after UNBOUND)`)
} finally { fs.rmSync(scratch, { recursive: true, force: true }) }
