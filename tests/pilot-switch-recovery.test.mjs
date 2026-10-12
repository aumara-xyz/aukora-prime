// Recovery restores each interrupted phase and refuses another switch until recovery completes.
import test, { describe } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, copyFileSync, mkdirSync, existsSync, writeFileSync, readdirSync, unlinkSync, statSync } from 'node:fs'
import { fixture, commit, oldCommit, units, script } from './pilot-switch-fixture.mjs'

const phases = ['backup', 'stage', 'approval', 'prepared', 'stop', 'gate-package-out', 'gate-package-in', 'owner-key-out', 'owner-key-in', 'manifest', 'bootstrap', 'launcher', 'check-package', 'gate-start', 'approval-install', 'floor', 'drain', 'release-env', 'harness-start', 'ui-probe', 'log-check', 'units']
const afterStop = phases.slice(phases.indexOf('stop'))
const text = result => (result.stdout ?? '') + (result.stderr ?? '')
function restored(f) {
  for (const [path, body] of Object.entries(f.oldFiles)) assert.equal(readFileSync(f.at(path), 'utf8'), body, path)
  assert.equal(existsSync(f.at('/etc/aukora-approvals/' + commit)), false, 'candidate approval cache removed')
  assert.equal(statSync(f.at('/opt/aukora-genesis/src/fresh-module')).mode & 0o777, 0o755)
  assert.equal(statSync(f.at('/opt/aukora-genesis/src/fresh-module/index.mjs')).mode & 0o777, 0o644)
  assert.equal(f.head(), oldCommit)
  assert.deepEqual(f.active(), units.toSorted())
}

describe('live-switch-main.sh hard-kill phase recovery', { concurrency: 4 }, () => {
  for (const phase of [...phases, 'restoring']) test('SIGKILL at ' + phase + ': only --recover restores the original units and release', async () => {
    const f = fixture({ killPhase: phase, floorFails: phase === 'restoring' })
    try {
      const killed = await f.runAsync()
      assert.equal(killed.signal, 'SIGKILL', text(killed))
      assert.equal(f.backups().length, 1)
      const backup = f.backups()[0]
      assert.match(readFileSync(backup + '/state', 'utf8'), new RegExp('^phase=' + phase + '$', 'm'))
      const before = f.events().length
      const refused = await f.runAsync()
      assert.notEqual(refused.status, 0, text(refused))
      assert.match(text(refused), /UNFINISHED_SWITCH/)
      assert.equal(f.events().slice(before).filter(event => event.name === 'systemctl' && event.args.some(arg => ['start', 'stop'].includes(arg))).length, 0, 'refusal changes no running unit')
      f.config({ killPhase: '' })
      const recover = await f.runAsync(['--recover', backup])
      assert.equal(recover.status, 0, text(recover))
      assert.match(text(recover), /RECOVERED|RESTORED/)
      restored(f)
      assert.match(readFileSync(backup + '/state', 'utf8'), /^phase=done$/m)
      const again = await f.runAsync(['--recover', backup])
      assert.equal(again.status, 0, text(again))
      restored(f)
    } finally { f.cleanup() }
  })
})

describe('live-switch-main.sh trapped post-stop failures', { concurrency: 4 }, () => {
  for (const phase of afterStop) test('failure entering ' + phase + ' restores all original files and active units', async () => {
    const f = fixture({ failPhase: phase })
    try {
      const result = await f.runAsync()
      assert.notEqual(result.status, 0, text(result))
      assert.match(text(result), /PHASE_FAILED/)
      assert.match(text(result), /RESTORED/)
      restored(f)
    } finally { f.cleanup() }
  })
})

describe('live-switch-main.sh preflight and absent-owner recovery', { concurrency: 4 }, () => {
  test('SIGKILL after done leaves the verified new release usable and explicit recovery is repeatable', async () => {
    const f = fixture({ killPhase: 'done' })
    try {
      const result = await f.runAsync()
      assert.equal(result.signal, 'SIGKILL', text(result))
      assert.deepEqual(f.active(), units.toSorted())
      assert.equal(f.head(), commit)
      assert.match(readFileSync(f.at('/etc/aukora-genesis/release.env'), 'utf8'), /release-bbbbbbb/)
      const backup = f.backups()[0]
      f.config({ killPhase: '' })
      const recover = await f.runAsync(['--recover', backup])
      assert.equal(recover.status, 0, text(recover))
      restored(f)
    } finally { f.cleanup() }
  })
  test('an incomplete existing lock refuses without creating a nested lock', async () => {
    const f = fixture()
    try {
      mkdirSync(f.at('/root/aukora-switch.lock'))
      const result = await f.runAsync()
      assert.notEqual(result.status, 0, text(result))
      assert.match(text(result), /SWITCH_LOCK_INCOMPLETE/)
      assert.deepEqual(readdirSync(f.at('/root/aukora-switch.lock')), [])
      restored(f)
    } finally { f.cleanup() }
  })
  test('two simultaneous switches use an atomic lock and stop no services while waiting', async () => {
    const f = fixture({ lockPause: true, neverApprove: true })
    let children = []
    try {
      const waitReady = async count => {
        const end = Date.now() + 6000
        while (readdirSync(f.root).filter(name => name.startsWith('test-lock-ready-')).length < count) {
          assert.ok(Date.now() < end, 'both switches reached the atomic publish step')
          await new Promise(resolve => setTimeout(resolve, 10))
        }
      }
      children.push(f.runAsync()); await waitReady(1)
      children.push(f.runAsync()); await waitReady(2)
      writeFileSync(f.at('/test-lock-release'), '')
      const results = await Promise.all(children)
      assert.equal(results.filter(result => /SWITCH_LOCK_FAILED/.test(text(result))).length, 1)
      assert.equal(results.filter(result => /APPROVAL_NOT_RECEIVED/.test(text(result))).length, 1)
      assert.ok(results.every(result => result.status !== 0))
      assert.equal(f.events().filter(event => event.name === 'systemctl' && event.args.includes('stop')).length, 0)
      restored(f)
    } finally { writeFileSync(f.at('/test-lock-release'), ''); await Promise.allSettled(children); f.cleanup() }
  })
  test('invalid recovery backup preserves its unfinished state and changes no running unit', async () => {
    const f = fixture({ killPhase: 'stop' })
    try {
      const killed = await f.runAsync()
      assert.equal(killed.signal, 'SIGKILL', text(killed))
      const backup = f.backups()[0], path = backup + '/manifest.old'
      const manifest = readFileSync(path), state = readFileSync(backup + '/state', 'utf8')
      unlinkSync(path); f.config({ killPhase: '' })
      const before = f.events().length
      const refused = await f.runAsync(['--recover', backup])
      assert.notEqual(refused.status, 0, text(refused))
      assert.match(text(refused), /RECOVERY_BACKUP_MISSING/)
      assert.equal(readFileSync(backup + '/state', 'utf8'), state)
      assert.equal(f.events().slice(before).filter(event => event.name === 'systemctl' && event.args.some(arg => ['start', 'stop'].includes(arg))).length, 0)
      writeFileSync(path, manifest)
      const recover = await f.runAsync(['--recover', backup])
      assert.equal(recover.status, 0, text(recover))
      restored(f)
    } finally { f.cleanup() }
  })
  test('missing sibling UI probe refuses before any service stop', async () => {
    const f = fixture()
    try {
      mkdirSync(f.at('/court'), { recursive: true }); copyFileSync(script, f.at('/court/live-switch-main.sh'))
      const result = await f.runAsync([commit], {}, { script: f.at('/court/live-switch-main.sh') })
      assert.notEqual(result.status, 0, text(result))
      assert.match(text(result), /UI_PROBE_MISSING/)
      assert.equal(f.events().filter(event => event.name === 'systemctl' && event.args.includes('stop')).length, 0)
      restored(f)
    } finally { f.cleanup() }
  })
  test('newly installed owner-key package is removed when no old owner-key existed', async () => {
    const f = fixture({ ownerAbsent: true, floorFails: true })
    try {
      const result = await f.runAsync()
      assert.notEqual(result.status, 0, text(result))
      assert.match(text(result), /FLOOR_CHECK_FAILED/)
      assert.equal(existsSync(f.at('/opt/owner-key')), false)
      restored(f)
    } finally { f.cleanup() }
  })
})
