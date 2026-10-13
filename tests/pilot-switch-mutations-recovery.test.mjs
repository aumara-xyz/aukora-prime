// Removes interruption markers, recovery and last-moment release publication from private script copies.
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { mutation, output, replaceOnce, restored, runMutationCourt, stops } from './pilot-switch-mutation-support.mjs'

mutation('unfinished-run-refused', { approved: true },
  'grep -qx \'phase=done\' "$prior" || refuse "UNFINISHED_SWITCH: $SCRIPT --recover ${prior%/state}"', 'true',
  (f, result) => {
    assert.match(output(result), /UNFINISHED_SWITCH/, 'unfinished-run-refused')
    assert.equal(f.backups().length, 1, 'unfinished-run-refused')
    assert.equal(stops(f).length, 0, 'unfinished-run-refused')
  }, { prepare: f => { const b = f.at('/root/aukora-backup-pre-interrupted'); mkdirSync(b); writeFileSync(join(b, 'state'), 'phase=approval\n') } })

function recoveryScenario() {
  return async (f, path) => {
    const first = await f.runAsync(undefined, undefined, { script: path })
    const recovered = first.signal === 'SIGKILL' ? await f.runAsync(['--recover', f.backups()[0]], undefined, { script: path }) : null
    return { first, recovered }
  }
}
function recovered(label) {
  return (f, result, initial) => {
    assert.equal(result.first.signal, 'SIGKILL', label)
    assert.equal(result.recovered.status, 0, label)
    restored(f, label)
    assert.deepEqual(f.active(), initial, label)
  }
}
for (const [label, phase, from] of [
  ['package-out-phase-recorded', 'gate-package-out', 'phase "$name-out"'],
  ['package-in-phase-recorded', 'gate-package-in', 'phase "$name-in"'],
]) mutation(label, { approved: true, killPhase: phase }, from, ':', recovered(label), { execute: recoveryScenario(phase) })

mutation('armed-marker-survives-kill', { approved: true, killPhase: 'gate-package-in' },
  'touch "$B/armed"; ARMED=1', 'ARMED=1', recovered('armed-marker-survives-kill'),
  { execute: recoveryScenario('gate-package-in') })
mutation('recover-dispatch-restores', { approved: true, killPhase: 'ui-probe' },
  'if [ "${1:-}" = --recover ]; then', 'if [ "${1:-}" = --removed-recover ]; then',
  recovered('recover-dispatch-restores'), { execute: recoveryScenario('ui-probe') })
mutation('recovery-restores-release-env', { approved: true, killPhase: 'ui-probe' },
  'try cp -a "$B/release.env.old" "$ENVFILE"', ':',
  recovered('recovery-restores-release-env'), { execute: recoveryScenario('ui-probe') })
mutation('release-env-published-last', { approved: true, floorFails: true }, source => {
  const start = source.indexOf("printf 'AUKORA_RELEASE_DIR=")
  const end = source.indexOf('phase release-env', start)
  assert.ok(start > 0 && end > start, 'release publication block exists')
  const block = source.slice(start, end)
  source = replaceOnce(source, block, '')
  source = replaceOnce(source, 'mv "$B/release.env.new" "$ENVFILE"\n', '')
  return replaceOnce(source, 'phase floor\n', block + 'mv "$B/release.env.new" "$ENVFILE"\nphase floor\n')
}, undefined, (f, result) => {
  assert.ok(!f.events().some(event => event.release.includes('release-bbbbbbb')), 'release-env-published-last')
  restored(f, 'release-env-published-last')
})
mutation('recovery-removes-candidate-cache', { approved: true, floorFails: true },
  'dest=$ROOT/etc/aukora-approvals/$candidate\n    try rm -rf "$dest"',
  'dest=$ROOT/etc/aukora-approvals/$candidate\n    :',
  (f, result) => {
    assert.match(output(result), /FLOOR_CHECK_FAILED/, 'recovery-removes-candidate-cache')
    assert.ok(!existsSync(f.at('/etc/aukora-approvals/' + 'b'.repeat(40))), 'recovery-removes-candidate-cache')
  })
mutation('failed-recovery-remains-unfinished', {},
  'elif [ "$MODE" = switch ] && [ -n "$B" ] && [ "$RESTORING" = 0 ]; then',
  'elif [ -n "$B" ] && [ "$RESTORING" = 0 ]; then',
  (f, result) => {
    assert.match(output(result), /RECOVERY_BACKUP_MISSING/, 'failed-recovery-remains-unfinished')
    assert.equal(readFileSync(f.backups()[0] + '/state', 'utf8'), 'phase=gate-package-in\n', 'failed-recovery-remains-unfinished')
  }, {
    prepare: f => { const b = f.at('/root/aukora-backup-pre-incomplete'); mkdirSync(b); writeFileSync(join(b, 'state'), 'phase=gate-package-in\n'); writeFileSync(join(b, 'armed'), '') },
    execute: (f, path) => f.runAsync(['--recover', f.backups()[0]], undefined, { script: path }),
  })
mutation('state-flushed-before-stop', { approved: true },
  /  "\$\{CLEAN\[@\]\}" "\$PYTHON" -I -S -c 'import os,sys\n[\s\S]*?finally: os\.close\(f\)' "\$B\/state"/, ':',
  (f, result) => {
    assert.equal(result.status, 0, 'state-flushed-before-stop')
    const events = f.events()
    const stop = events.findIndex(event => event.name === 'systemctl' && event.args[0] === 'stop')
    const prior = events[stop - 1]
    assert.ok(prior?.name === 'python3' && prior.args.includes('-c') && prior.args.at(-1).endsWith('/state'), 'state-flushed-before-stop')
  })

runMutationCourt('pilot switch interruption and recovery mutations', [
  ['interruption markers', ['unfinished-run-refused', 'package-out-phase-recorded', 'package-in-phase-recorded',
    'armed-marker-survives-kill', 'recover-dispatch-restores']],
  ['restoration and publication', ['recovery-restores-release-env', 'release-env-published-last',
    'recovery-removes-candidate-cache', 'failed-recovery-remains-unfinished', 'state-flushed-before-stop']],
])
