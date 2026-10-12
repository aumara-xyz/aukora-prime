// Removes owner approval guards from private copies of the real switch.
import assert from 'node:assert/strict'
import { mutation, output, runMutationCourt, stops } from './pilot-switch-mutation-support.mjs'

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

runMutationCourt('pilot switch owner approval mutations')
