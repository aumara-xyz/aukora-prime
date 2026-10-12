// Removes root, detached-session and post-start verification guards from private script copies.
import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { mutation, output, restored, runMutationCourt, staticMutation, stops } from './pilot-switch-mutation-support.mjs'

async function waitDetached(f, result) {
  const pid = result.stdout.match(/DETACHED: pid ([0-9]+)/)?.[1]
  if (!pid) return result
  const deadline = Date.now() + 24000
  while (Date.now() < deadline) {
    const log = readdirSync(f.at('/root')).find(name => name.startsWith('aukora-switch-log-'))
    if (log && /SWITCH_DONE|RECOVERY_FAILED|RESTORED|REFUSED:/.test(readFileSync(f.at('/root/' + log), 'utf8'))) {
    await new Promise(resolve => setTimeout(resolve, 100))
    return result
    }
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  try { process.kill(Number(pid), 'SIGKILL') } catch {}
  await new Promise(resolve => setTimeout(resolve, 500))
  assert.fail('ssh-session-detached: detached child did not finish before fixture cleanup')
}

mutation('root-prefix-test-only', { approved: true },
  '[ "${PILOT_SWITCH_TEST:-}" = 1 ] || refuse ROOT_TEST_ONLY', ':',
  (f, result) => {
    assert.match(output(result), /ROOT_TEST_ONLY/, 'root-prefix-test-only')
    assert.equal(f.events().length, 0, 'root-prefix-test-only')
  }, { env: { PILOT_SWITCH_TEST: '' } })
mutation('private-state-under-umask-002', { approved: true, killPhase: 'stop' },
  'umask 077', 'umask 002',
  (f, result) => {
    assert.equal(result.signal, 'SIGKILL', 'private-state-under-umask-002')
    assert.equal(statSync(f.at('/root/aukora-switch.lock')).mode & 0o777, 0o700, 'private-state-under-umask-002')
    assert.equal(statSync(f.backups()[0] + '/state').mode & 0o777, 0o600, 'private-state-under-umask-002')
  })
mutation('ssh-session-detached', { approved: true },
  'if { [ -t 0 ] || [ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ]; } && ! detached; then', 'if false; then',
  (f, result) => {
    assert.match(output(result), /DETACHED: pid [0-9]+; tail -f /, 'ssh-session-detached')
    const log = readdirSync(f.at('/root')).find(name => name.startsWith('aukora-switch-log-'))
    assert.ok(log, 'ssh-session-detached')
    assert.equal(statSync(f.at('/root/' + log)).mode & 0o777, 0o600, 'ssh-session-detached')
  }, { execute: async (f, path) => {
    const result = await f.runAsync(undefined, { SSH_CONNECTION: 'synthetic session' }, { script: path })
    await waitDetached(f, result)
    return result
  } })
mutation('existing-detached-session-preserved', { approved: true },
  '} && ! detached; then', '}; then',
  (f, result) => {
    assert.equal(result.status, 0, 'existing-detached-session-preserved')
    assert.match(output(result), /SWITCH_DONE/, 'existing-detached-session-preserved')
    assert.ok(!output(result).includes('DETACHED:'), 'existing-detached-session-preserved')
  }, { execute: async (f, path) => {
    const result = await f.runAsync(undefined, { SSH_CONNECTION: 'synthetic existing detached session' }, { script: path, nohup: true })
    await waitDetached(f, result)
    return result
  } })
mutation('journal-stream-identity-required', { approved: true },
  'service=stream==str(st.st_dev)+":"+str(st.st_ino)', 'service=True',
  (f, result) => {
    assert.match(output(result), /DETACHED:/, 'journal-stream-identity-required')
  }, { execute: async (f, path) => {
    const result = await f.runAsync(undefined, { SSH_CONNECTION: 'synthetic forged journal', INVOCATION_ID: 'a'.repeat(32), JOURNAL_STREAM: '999999999999999999999999:999999999999999999999999' }, { script: path })
    await waitDetached(f, result)
    return result
  } })
mutation('ui-probe-preflight-required', { approved: true },
  '[ -f "$SCRIPT_DIR/ui-probe.mjs" ] || refuse UI_PROBE_MISSING', ':',
  (f, result) => {
    assert.match(output(result), /UI_PROBE_MISSING/, 'ui-probe-preflight-required')
    assert.equal(stops(f).length, 0, 'ui-probe-preflight-required')
    assert.equal(f.backups().length, 0, 'ui-probe-preflight-required')
  }, { probe: false })
mutation('signed-in-ui-probe-required', { approved: true, probeFails: true },
  '|| refuse UI_PROBE_FAILED', '|| true',
  (f, result, initial) => {
    assert.notEqual(result.status, 0, 'signed-in-ui-probe-required')
    assert.match(output(result), /UI_PROBE_FAILED/, 'signed-in-ui-probe-required')
    restored(f, 'signed-in-ui-probe-required')
    assert.deepEqual(f.active(), initial, 'signed-in-ui-probe-required')
  })
mutation('plugin-load-errors-refused', { approved: true, pluginError: true },
  "if grep -qE '^aukora-[a-z-]+ \\(file://.*\\): Error' \"$B/harness.log\"; then refuse PLUGIN_LOAD_ERROR; fi", ':',
  (f, result, initial) => {
    assert.notEqual(result.status, 0, 'plugin-load-errors-refused')
    assert.match(output(result), /PLUGIN_LOAD_ERROR/, 'plugin-load-errors-refused')
    restored(f, 'plugin-load-errors-refused')
    assert.deepEqual(f.active(), initial, 'plugin-load-errors-refused')
  })
mutation('harness-readiness-required', { approved: true, harnessNotReady: true },
  'wait_harness || refuse HARNESS_NOT_READY', ':',
  (f, result, initial) => {
    assert.notEqual(result.status, 0, 'harness-readiness-required')
    assert.match(output(result), /HARNESS_NOT_READY/, 'harness-readiness-required')
    restored(f, 'harness-readiness-required')
    assert.deepEqual(f.active(), initial, 'harness-readiness-required')
  })
mutation('floor-lock-preflight-refused', { approved: true },
  '[ ! -e "$FLOOR.lock" ] || refuse FLOOR_LOCK_REQUIRES_RECONCILIATION', ':',
  (f, result) => {
    assert.match(output(result), /FLOOR_LOCK_REQUIRES_RECONCILIATION/, 'floor-lock-preflight-refused')
    assert.equal(stops(f).length, 0, 'floor-lock-preflight-refused')
  }, { prepare: f => writeFileSync(f.at('/etc/aukora-approvals/release-floor.json.lock'), 'pre-existing lock\n') })
mutation('incomplete-lock-refused', { approved: true },
  '[[ "$PID" =~ ^[0-9]+$ ]] || refuse SWITCH_LOCK_INCOMPLETE', ':',
  (f, result) => {
    assert.match(output(result), /SWITCH_LOCK_INCOMPLETE/, 'incomplete-lock-refused')
    assert.equal(stops(f).length, 0, 'incomplete-lock-refused')
  }, { prepare: f => mkdirSync(f.at('/root/aukora-switch.lock')) })
mutation('atomic-lock-excludes-racer', { lockPause: true, neverApprove: true },
  'os.symlink(sys.argv[1],sys.argv[2])', 'pass # os.symlink',
  (f, results) => {
    assert.equal(f.backups().length, 1, 'atomic-lock-excludes-racer')
    assert.ok(results.some(result => output(result).includes('SWITCH_LOCK_FAILED')), 'atomic-lock-excludes-racer')
    assert.equal(stops(f).length, 0, 'atomic-lock-excludes-racer')
  }, { execute: async (f, path) => {
    const children = []
    const ready = async count => {
      const deadline = Date.now() + 10000
      while (readdirSync(f.root).filter(name => name.startsWith('test-lock-ready-')).length < count) {
        assert.ok(Date.now() < deadline, 'atomic-lock-excludes-racer: barrier timeout')
        await new Promise(resolve => setTimeout(resolve, 10))
      }
    }
    try {
      children.push(f.runAsync(undefined, undefined, { script: path })); await ready(1)
      children.push(f.runAsync(undefined, undefined, { script: path })); await ready(2)
      writeFileSync(f.at('/test-lock-release'), '')
      return await Promise.all(children)
    } finally { writeFileSync(f.at('/test-lock-release'), ''); await Promise.allSettled(children) }
  } })
mutation('launcher-checkout-readable', { approved: true },
  '(umask 022; git -c', '(git -c',
  (f, result) => {
    assert.equal(result.status, 0, 'launcher-checkout-readable')
    assert.equal(statSync(f.at('/opt/aukora-genesis/src/fresh-module')).mode & 0o777, 0o755, 'launcher-checkout-readable')
    assert.equal(statSync(f.at('/opt/aukora-genesis/src/fresh-module/index.mjs')).mode & 0o777, 0o644, 'launcher-checkout-readable')
  })
staticMutation('truthful-history-header',
  '# Collects owner approval before stopping services and restores interrupted switches. History: ops/pilot/README.md.',
  '# NOT RUN anywhere: switches the live harness.',
  (source, label) => {
    const header = source.split('\n').slice(0, 3).join('\n')
    assert.match(header, /History: ops\/pilot\/README\.md/, label)
    assert.ok(!header.includes('NOT RUN'), label)
  })
staticMutation('selfcheck-timer-in-recovery-instructions',
  'aukora-selfcheck.timer when units.old records it active, and verifies the original unit set.',
  'the original unit set is verified.',
  (source, label) => {
    const recovery = source.slice(source.indexOf('cat > "$B/RECOVERY.txt"'), source.indexOf('\nRECOVERY\n'))
    assert.match(recovery, /starts[\s\S]*aukora-selfcheck\.timer/, label)
  })

runMutationCourt('pilot switch runtime and preflight mutations')
