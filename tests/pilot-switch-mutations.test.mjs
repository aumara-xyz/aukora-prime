// Removes drain, floor and restoration guards from private copies of the real switch.
import assert from 'node:assert/strict'
import { mutation, output, restored, runMutationCourt } from './pilot-switch-mutation-support.mjs'

mutation('selfcheck-timer-restored', { approved: true, floorFails: true },
  'if [ "$unit" != aukora-genesis ]; then try systemctl start "$unit"; fi',
  'if [ "$unit" != aukora-genesis ] && [ "$unit" != aukora-selfcheck.timer ]; then try systemctl start "$unit"; fi',
  (f, result, initial) => {
    assert.match(output(result), /FLOOR_CHECK_FAILED/, 'selfcheck-timer-restored')
    assert.deepEqual(f.active(), initial, 'selfcheck-timer-restored')
    restored(f, 'selfcheck-timer-restored')
  })
mutation('port-drain-must-fail', { approved: true, portBusyOnNew: true },
  'echo PORT_NOT_DRAINED; return 1', 'echo PORT_NOT_DRAINED; return 0',
  (f, result, initial) => {
    assert.notEqual(result.status, 0, 'port-drain-must-fail')
    assert.match(output(result), /REFUSED: PORT_NOT_DRAINED/, 'port-drain-must-fail')
    restored(f, 'port-drain-must-fail')
    assert.deepEqual(f.active(), initial, 'port-drain-must-fail')
  })
mutation('large-port-status-stays-busy', { approved: true, portBusyOnNew: true, ssLarge: true },
  'if ! grep -q ":$PORT " <<< "$connections"; then',
  "if ! printf '%s\\n' \"$connections\" | grep -q \":$PORT \"; then",
  (f, result, initial) => {
    assert.notEqual(result.status, 0, 'large-port-status-stays-busy')
    assert.match(output(result), /PORT_NOT_DRAINED/, 'large-port-status-stays-busy')
    restored(f, 'large-port-status-stays-busy')
    assert.deepEqual(f.active(), initial, 'large-port-status-stays-busy')
  })
mutation('recovery-start-attempts-bounded', { approved: true, floorFails: true, startAllFails: true },
  'attempt<3', 'attempt<4',
  (f, result) => {
    const starts = f.events().filter(event => event.name === 'systemctl' && event.args[0] === 'start' && event.args[1] === 'aukora-genesis')
    assert.equal(starts.length, 3, 'recovery-start-attempts-bounded')
    assert.notEqual(result.status, 0, 'recovery-start-attempts-bounded')
    assert.match(output(result), /HARNESS DOWN/, 'recovery-start-attempts-bounded')
  })
mutation('recovery-harness-down-explicit', { approved: true, floorFails: true, startAllFails: true },
  "echo 'HARNESS DOWN: recovery exhausted three drain-then-start attempts'; bad=1", 'bad=1',
  (f, result) => {
    assert.match(output(result), /HARNESS DOWN/, 'recovery-harness-down-explicit')
    assert.notEqual(result.status, 0, 'recovery-harness-down-explicit')
  })
mutation('floor-check-required', { approved: true, floorFails: true },
  '|| refuse FLOOR_CHECK_FAILED', '|| true',
  (f, result, initial) => {
    assert.notEqual(result.status, 0, 'floor-check-required')
    assert.match(output(result), /FLOOR_CHECK_FAILED/, 'floor-check-required')
    restored(f, 'floor-check-required')
    assert.deepEqual(f.active(), initial, 'floor-check-required')
  })

runMutationCourt('pilot switch drain and restoration mutations')
