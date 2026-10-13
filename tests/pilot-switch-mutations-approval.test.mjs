// Removes owner approval guards from private copies of the real switch.
import assert from 'node:assert/strict'
import { statSync } from 'node:fs'
import { commit } from './pilot-switch-fixture.mjs'
import { mutation, output, replaceOnce, runMutationCourt, stops } from './pilot-switch-mutation-support.mjs'

mutation('approval-before-stop', { neverApprove: true },
  'phase approval\n', 'phase approval\nsystemctl stop aukora-genesis\n',
  (f, result, initial) => {
    assert.equal(stops(f).length, 0, 'approval-before-stop')
    assert.deepEqual(f.active(), initial, 'approval-before-stop')
    assert.match(output(result), /APPROVAL_NOT_RECEIVED/, 'approval-before-stop')
  })
mutation('owner-approval-required', { neverApprove: true },
  'approval_exists || refuse APPROVAL_NOT_RECEIVED', 'true',
  (f, result) => {
    assert.equal(stops(f).length, 0, 'owner-approval-required')
    assert.match(output(result), /APPROVAL_NOT_RECEIVED/, 'owner-approval-required')
  })
mutation('installed-gate-incompatibility', { showFails: true },
  "|| refuse 'INSTALLED_GATE_SHOW_FAILED: old release remains up; upgrade compatibility requires owner review'", '|| true',
  (f, result) => {
    assert.match(output(result), /INSTALLED_GATE_SHOW_FAILED/, 'installed-gate-incompatibility')
    assert.equal(stops(f).length, 0, 'installed-gate-incompatibility')
  })

mutation('both-gate-sockets-waited-for', { socketDelay: 3 },
  'for ((i=0; i<30; i++)); do [ -S "$ROOT/run/aukora-gate/gate.sock" ] && [ -S "$ROOT/run/aukora-gate/owner.sock" ] && break; sleep 1; done', ':',
  (f, result) => {
    assert.equal(result.status, 0, 'both-gate-sockets-waited-for')
    assert.equal(f.events().filter(event => event.name === 'sleep' && event.head === commit).length, 3, 'both-gate-sockets-waited-for')
  })
for (const missing of ['gate.sock', 'owner.sock']) mutation('both-gate-sockets-required-' + missing, { socketsMissing: missing },
  '[ -S "$ROOT/run/aukora-gate/gate.sock" ] && [ -S "$ROOT/run/aukora-gate/owner.sock" ] || refuse GATE_SOCKETS_MISSING',
  '[ -S "$ROOT/run/aukora-gate/gate.sock" ] || [ -S "$ROOT/run/aukora-gate/owner.sock" ] || refuse GATE_SOCKETS_MISSING',
  (f, result) => {
    const label = 'both-gate-sockets-required-' + missing
    assert.notEqual(result.status, 0, label)
    assert.match(output(result), /GATE_SOCKETS_MISSING/, label)
    assert.equal(f.events().filter(event => event.name === 'python3' && event.args.some(arg => ['install', 'recover-cache'].includes(arg))).length, 0, label)
  })
mutation('approval-files-readable-by-harness', {}, source => {
  source = replaceOnce(source, '(umask 022; boot approval recover-cache', '(boot approval recover-cache')
  return replaceOnce(source, 'chmod -R u+rwX,go+rX,go-w "$ROOT/etc/aukora-approvals/$C"', ':')
}, undefined, (f, result) => {
  assert.equal(result.status, 0, 'approval-files-readable-by-harness')
  assert.equal(statSync(f.at('/etc/aukora-approvals/' + commit + '/state/gate-state/approval.fixture')).mode & 0o777, 0o644, 'approval-files-readable-by-harness')
})
mutation('approval-folders-readable-by-harness', {}, source => {
  source = replaceOnce(source, 'install -d -o root -g root -m 0755', 'install -d -o root -g root -m 0700')
  return replaceOnce(source, 'chmod -R u+rwX,go+rX,go-w "$ROOT/etc/aukora-approvals/$C"', ':')
}, undefined, (f, result) => {
  assert.equal(result.status, 0, 'approval-folders-readable-by-harness')
  for (const path of ['', '/state', '/state/gate-state']) assert.equal(statSync(f.at('/etc/aukora-approvals/' + commit + path)).mode & 0o777, 0o755, 'approval-folders-readable-by-harness')
})
mutation('release-floor-readable-by-harness', {}, source => {
  source = replaceOnce(source, '(umask 022; boot approval recover-cache', '(boot approval recover-cache')
  return replaceOnce(source, '[ ! -f "$FLOOR" ] || chmod 0644 "$FLOOR"', ':')
}, undefined, (f, result) => {
  assert.equal(result.status, 0, 'release-floor-readable-by-harness')
  assert.equal(statSync(f.at('/etc/aukora-approvals/release-floor.json')).mode & 0o777, 0o644, 'release-floor-readable-by-harness')
})

runMutationCourt('pilot switch owner approval mutations', [
  ['approval and sockets', ['approval-before-stop', 'owner-approval-required', 'installed-gate-incompatibility',
    'both-gate-sockets-waited-for', 'both-gate-sockets-required-gate.sock', 'both-gate-sockets-required-owner.sock']],
  ['readability', ['approval-files-readable-by-harness', 'approval-folders-readable-by-harness', 'release-floor-readable-by-harness']],
])
