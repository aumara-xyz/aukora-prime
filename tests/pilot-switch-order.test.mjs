// Approval is collected before service interruption and every verified switch runs both post-start checks.
import test, { describe } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, statSync, existsSync } from 'node:fs'
import { fixture, commit, oldCommit, units } from './pilot-switch-fixture.mjs'

const text = result => (result.stdout ?? '') + (result.stderr ?? '')
const eventIs = (name, arg) => event => event.name === name && event.args.includes(arg)
async function withFixture(config, body) { const f = fixture(config); try { return await body(f) } finally { f.cleanup() } }
export function assertRestored(f) {
  for (const [path, body] of Object.entries(f.oldFiles)) assert.equal(readFileSync(f.at(path), 'utf8'), body, path + ' restored byte-for-byte')
  if (!Object.keys(f.oldFiles).some(path => path.startsWith('/etc/aukora-approvals/' + commit + '/'))) assert.equal(existsSync(f.at('/etc/aukora-approvals/' + commit)), false, 'new candidate approval cache removed')
  assert.equal(statSync(f.at('/opt/aukora-genesis/src/fresh-module')).mode & 0o777, 0o755, 'launcher directory is readable by its service user')
  assert.equal(statSync(f.at('/opt/aukora-genesis/src/fresh-module/index.mjs')).mode & 0o777, 0o644, 'launcher module is readable by its service user')
  assert.equal(f.head(), oldCommit, 'launcher restored')
  assert.deepEqual(f.active(), units.toSorted(), 'all initially active units restored')
  for (const backup of f.backups()) assert.equal(statSync(backup).mode & 0o077, 0, 'backup stays private under umask 002')
}
export function assertApprovalBeforeStop(f) {
  const events = f.events()
  const firstStop = events.findIndex(eventIs('systemctl', 'stop'))
  assert.ok(firstStop >= 0, 'switch actually stops services')
  const show = events.findIndex(eventIs('python3', 'show'))
  const raise = events.findIndex(eventIs('python3', 'raise'))
  const approved = events.findIndex(event => event.name === 'node' && event.args.some(arg => arg.includes('--input-type')) && event.args.some(arg => arg.includes('/approval.json')))
  assert.ok(show >= 0 && show < firstStop, 'installed gate shows approval before any service stop')
  assert.ok(raise >= 0 && raise < firstStop, 'installed gate raises card before any service stop')
  assert.ok(approved >= 0 && approved < firstStop, 'exact owner-approved target checked before any service stop')
  for (const event of events.slice(show, firstStop)) {
    assert.ok(event.active.includes('aukora-genesis'), 'old harness stays active throughout owner wait')
    assert.ok(event.active.includes('aukora-boundary-gate'), 'old gate stays active throughout owner wait')
    assert.equal(event.head, oldCommit, 'installed launcher stays unchanged during owner wait')
    assert.ok(event.release.includes('release-aaaaaaa'), 'release remains old during owner wait')
  }
}

describe('live-switch-main.sh real-script regression', { concurrency: 4 }, () => {
test('real switch: approval before stop, private backup, signed-in UI and new-run log checks', () => withFixture({}, async f => {
  const result = await f.runAsync([commit], { SHELL: '/bin/bash' })
  assert.equal(result.status, 0, text(result))
  assert.match(text(result), /SWITCH_DONE/)
  assertApprovalBeforeStop(f)
  assert.deepEqual(f.active(), units.toSorted())
  assert.equal(f.head(), commit)
  assert.equal(statSync(f.at('/opt/aukora-genesis/src/fresh-module')).mode & 0o777, 0o755)
  assert.equal(statSync(f.at('/opt/aukora-genesis/src/fresh-module/index.mjs')).mode & 0o777, 0o644)
  assert.match(readFileSync(f.at('/etc/aukora-genesis/release.env'), 'utf8'), /release-bbbbbbb/)
  const events = f.events(), start = events.findIndex(event => eventIs('systemctl', 'start')(event) && event.args.includes('aukora-genesis'))
  const probe = events.findIndex(event => event.name === 'node' && event.args.some(arg => arg.endsWith('/ui-probe.mjs')))
  const logs = events.findIndex(event => event.name === 'journalctl' && event.args.some(arg => arg.startsWith('_SYSTEMD_INVOCATION_ID=')))
  assert.ok(probe > start, 'UI probe runs after new harness starts')
  assert.ok(logs > start, 'only new-run log is checked after start')
  assert.equal(events[probe].args.at(-1), f.at('/home/aukora-host/genesis/state/launch-url.json'))
  assert.equal(f.backups().length, 1)
  assert.match(readFileSync(f.backups()[0] + '/state', 'utf8'), /^phase=done$/m)
}))

test('real switch: approval timeout never stops or changes the running installation', () => withFixture({ neverApprove: true }, async f => {
  const result = await f.runAsync()
  assert.notEqual(result.status, 0, text(result))
  assert.match(text(result), /APPROVAL|approval/)
  assert.equal(f.events().filter(eventIs('systemctl', 'stop')).length, 0, 'timeout stops no unit')
  assertRestored(f)
}))

for (const config of [{ showFails: true }, { raiseFails: true, noPending: true, neverApprove: true }]) test('real switch: unsupported installed approval route refuses before stop ' + JSON.stringify(config), () => withFixture(config, async f => {
  const result = await f.runAsync()
  assert.notEqual(result.status, 0, text(result))
  assert.match(text(result), /INSTALLED_GATE|APPROVAL|RAISE/)
  assert.equal(f.events().filter(eventIs('systemctl', 'stop')).length, 0)
  assertRestored(f)
}))

test('real switch: a pending card and an already approved card permit a repeat run', () => withFixture({ raiseFails: true, approveAfter: 3 }, async f => {
  const first = await f.runAsync()
  assert.equal(first.status, 0, text(first))
  const second = await f.runAsync()
  assert.equal(second.status, 0, text(second))
  assert.equal(f.backups().length, 2, 'same-second runs have separate backups')
  assert.deepEqual(f.active(), units.toSorted())
}))

test('real switch: an initially inactive selfcheck timer remains inactive', () => withFixture({ timerInactive: true }, async f => {
  const result = await f.runAsync()
  assert.equal(result.status, 0, text(result))
  assert.deepEqual(f.active(), units.filter(unit => !unit.endsWith('.timer')).toSorted())
}))

test('real switch: executable PATH stubs agree with the fast fixture', () => withFixture({ approved: true }, async f => {
  const result = await f.runAsync([commit], {}, { external: true })
  assert.equal(result.status, 0, text(result))
  assert.match(text(result), /SWITCH_DONE/)
  assert.deepEqual(f.active(), units.toSorted())
}))

test('real switch: ROOT without its test marker is refused without running commands', () => withFixture({}, async f => {
  const result = await f.runAsync([commit], { PILOT_SWITCH_TEST: '' })
  assert.notEqual(result.status, 0, text(result))
  assert.match(text(result), /ROOT|TEST/)
  assert.equal(f.events().length, 0)
}))

for (const [label, config, code] of [
  ['pre-existing candidate approval cache', { approvalCache: true, floorFails: true }, /FLOOR_CHECK_FAILED/],
  ['package check', { packageFails: true }, /PACKAGE|check-package/],
  ['launcher checkout', { checkoutFails: true }, /CHECKOUT|launcher|RESTOR/],
  ['new gate start', { gateStartFails: true }, /GATE|RESTOR/],
  ['approval install', { approvalInstallFails: true }, /APPROVAL|RESTOR/],
  ['floor check', { floorFails: true }, /FLOOR|floor/],
  ['new start', { startNewFails: true }, /START|RESTOR/],
  ['signed-in UI probe', { probeFails: true }, /UI_PROBE|UI PROBE/],
  ['plugin load log', { pluginError: true }, /PLUGIN|plugin|LOG/],
  ['busy port in a large ss listing', { portBusyOnNew: true, ssLarge: true }, /PORT_NOT_DRAINED/],
  ['new checkout port remains busy', { portBusyOnNew: true }, /PORT_NOT_DRAINED/],
]) test('real switch: ' + label + ' failure restores all files and units', () => withFixture(config, async f => {
  const result = await f.runAsync()
  assert.notEqual(result.status, 0, text(result))
  assert.match(text(result), code)
  assertRestored(f)
}))

test('real switch: durable phase synchronization fails before any stop', () => withFixture({ syncFailPhase: 'prepared' }, async f => {
  const result = await f.runAsync()
  assert.notEqual(result.status, 0, text(result))
  assert.match(text(result), /STATE_SYNC_FAILED/)
  assert.equal(f.events().filter(eventIs('systemctl', 'stop')).length, 0)
  assertRestored(f)
}))

for (const [label, options] of [['nohup', { nohup: true }], ['new session', { session: true }], ['matching journal stream', { journal: true }]]) test('real switch: ' + label + ' with inherited SSH variables does not detach again', () => withFixture({ approved: true }, async f => {
  const result = await f.runAsync([commit], { SSH_CONNECTION: 'fixture ssh' }, options)
  assert.equal(result.status, 0, text(result))
  assert.match(text(result), /SWITCH_DONE/)
  assert.doesNotMatch(text(result), /DETACHED:/)
  assert.deepEqual(f.active(), units.toSorted())
}))

test('real switch: a port that never drains reports bounded recovery and HARNESS DOWN', () => withFixture({ portNeverDrains: true }, async f => {
  const result = await f.runAsync()
  assert.notEqual(result.status, 0, text(result))
  assert.match(text(result), /PORT_NOT_DRAINED/)
  assert.match(text(result), /HARNESS DOWN/)
  assert.ok(f.active().includes('aukora-selfcheck.timer'), 'timer is restored even when harness cannot be')
  assert.ok(!f.active().includes('aukora-genesis'))
  assert.equal(f.head(), oldCommit)
  assert.equal(readFileSync(f.at('/etc/aukora-genesis/release.env'), 'utf8'), f.oldFiles['/etc/aukora-genesis/release.env'])
  assert.ok(f.events().filter(eventIs('ss', '-tan')).length <= 240, 'drain retries are bounded')
}))

})

export { withFixture, text }
