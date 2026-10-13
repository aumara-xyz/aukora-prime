// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise the actual shell child runner, collector and aggregate with bounded
// synthetic reports. No whole court, DSH, store, network or installed acceptance.
// Fixtures are retained: this check never deletes files under the no-delete hold.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const source = readFileSync(new URL('../scripts/check.sh', import.meta.url), 'utf8')
const root = mkdtempSync(join(tmpdir(), 'aukora-shell-status-'))
const command = 'node tests/kira-injection.test.mjs --mutate'
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'"
const environment = { ...process.env, GIT_NO_LAZY_FETCH: '1' }
for (const key of ['NODE_OPTIONS', 'NODE_TEST_CONTEXT', 'AUKORA_TEST_KIRA_SOURCE', 'AUKORA_TEST_AURA_SOURCE']) delete environment[key]
const footer = (pass = 46, arms = 46, failed = 0, pending = 2, dsh = 'UNPERFORMED') =>
  `  ${pass}/${arms} arms passed, ${failed} failed; ${pending} unperformed checks; DSH source dispatch ${dsh}; installed profile UNPERFORMED.`
const tap = (pass = 0, skipped = 0, todo = 0) =>
  `# tests ${pass + skipped + todo}\n# pass ${pass}\n# fail 0\n# cancelled 0\n# skipped ${skipped}\n# todo ${todo}`
const registrations = text => text.split('\n').filter(line => /^check(?:_tap|_unittest|_darwin|_injection)? '/u.test(line))
assert.equal(registrations(source).length, 269, 'preserve every existing fixed registration')
assert.equal(registrations(source).filter(line => line.includes(command)).length, 1)

function fragments(text) {
  const collector = text.match(/(^collect_checks\(\) \{[\s\S]*?^\})\n\n# Formats/mu)?.[1]
  const launcher = text.match(/(^run_check\(\) \{[\s\S]*?^\})\n# The precard/mu)?.[1]
  const end = text.lastIndexOf('\ncollect_checks\nperl -MTime::HiRes=time')
  assert(collector && launcher && end >= 0, 'use actual production runner/collector/aggregate')
  return { collector, launcher, aggregate: text.slice(end) }
}

let sequence = 0
function run(rows, text = source) {
  const directory = join(root, `case-${++sequence}`)
  mkdirSync(join(directory, 'tests'), { recursive: true, mode: 0o700 })
  const work = join(directory, 'reports')
  mkdirSync(work, { mode: 0o700 })
  const { collector, launcher, aggregate } = fragments(text)
  const calls = []
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index]
    const file = row.file ?? (row.court ? 'tests/kira-injection.test.mjs' : `tests/producer-${index}.mjs`)
    writeFileSync(join(directory, file), row.body ??
      `console.log(${JSON.stringify(row.output ?? '')});process.exit(${row.exit ?? 0});\n`, { mode: 0o600 })
    const runCommand = row.runCommand ?? (row.court ? command : `node ${file}`)
    const courtFormat = text.includes(`check_injection '${command}'`) ? 'injection' : 'plain'
    calls.push(`run_check ${quote(row.label ?? runCommand)} ${quote(runCommand)} ${quote(row.format ?? (row.court ? courtFormat : 'plain'))}`)
  }
  const driver = `set -eu\nwork=${quote(work)}\nstarted=$(perl -MTime::HiRes=time -e 'print time')\npids=\nactive=0\nindex=0\ncount=0\npassed=0\nfailed=0\nskipped=0\nplatform_skipped=0\nunperformed=0\n${collector}\n${launcher}\n${calls.join('\n')}\n${aggregate}`
  const script = join(directory, 'runner.sh')
  writeFileSync(script, driver, { mode: 0o600 })
  const child = spawnSync('/bin/sh', [script], { cwd: directory, env: environment, encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 })
  assert.equal(child.error, undefined, 'actual extracted runner must finish')
  assert.equal(child.signal, null)
  writeFileSync(join(directory, 'stdout.txt'), child.stdout, { mode: 0o600 })
  writeFileSync(join(directory, 'stderr.txt'), child.stderr, { mode: 0o600 })
  const match = child.stdout.match(/^TOTAL [^|]+\| (\d+)\/(\d+) passed \| (\d+) failed \| (\d+) skipped \((\d+) platform\) \| (\d+) unperformed/mu)
  assert(match, 'actual aggregate must report all dispositions')
  return { ...child, counts: match.slice(1).map(Number), output: child.stdout }
}

const cases = [
  ['46-arm missing DSH remains unperformed', { court: true, output: footer(), exit: 2 }, 'UNPERFORMED', 2],
  ['54-arm source dispatch remains unperformed', { court: true, output: footer(54, 54, 0, 1, 'RAN'), exit: 2 }, 'UNPERFORMED', 2],
  ['incorrect exit zero cannot green an open profile', { court: true, output: footer(), exit: 0 }, 'UNPERFORMED', 2],
  ['failed arm exit one remains failure', { court: true, output: '  FAIL synthetic arm: assertion\n' + footer(45, 46, 1), exit: 1 }, 'FAIL', 1],
  ['failed footer wins incorrect exit two', { court: true, output: footer(45, 46, 1), exit: 2 }, 'FAIL', 1],
  ['failed footer wins incorrect exit zero', { court: true, output: footer(45, 46, 1), exit: 0 }, 'FAIL', 1],
  ['failure line wins passing footer', { court: true, output: '  FAIL synthetic arm: assertion\n' + footer(), exit: 2 }, 'FAIL', 1],
  ['TAP failure cannot hide behind court footer', { court: true, output: '# fail 1\n' + footer(), exit: 2 }, 'FAIL', 1],
  ['expected failure control is not an arm failure', { court: true, output: '  EXPECTED FAIL synthetic mutation: rejected\n' + footer(), exit: 2 }, 'UNPERFORMED', 2],
  ['missing footer fails closed', { court: true, output: 'incomplete output', exit: 2 }, 'FAIL', 1],
  ['duplicate footer fails closed', { court: true, output: footer() + '\n' + footer(), exit: 2 }, 'FAIL', 1],
  ['malformed footer fails closed', { court: true, output: footer().replace('46/46', 'x/46'), exit: 2 }, 'FAIL', 1],
  ['contradictory arm arithmetic fails closed', { court: true, output: footer(45, 46, 0), exit: 2 }, 'FAIL', 1],
  ['zero arms cannot establish a result', { court: true, output: footer(0, 0), exit: 2 }, 'FAIL', 1],
  ['installed unperformed requires a pending count', { court: true, output: footer(46, 46, 0, 0, 'RAN'), exit: 2 }, 'FAIL', 1],
  ['missing dispatch plus profile requires two gaps', { court: true, output: footer(46, 46, 0, 1), exit: 2 }, 'FAIL', 1],
  ['other child exits remain failure', { court: true, output: footer(), exit: 3 }, 'FAIL', 1],
  ['signal remains failure', { court: true, body: "process.kill(process.pid,'SIGTERM');\n" }, 'FAIL', 1],
  ['generic exit two gets no exemption', { output: footer(), exit: 2 }, 'FAIL', 1],
  ['literal command binding refuses a different label', { court: true, label: 'node tests/another-court.mjs', output: footer(), exit: 2 }, 'FAIL', 1],
  ['ordinary completed child stays pass', { output: 'completed synthetic assertions', exit: 0 }, 'PASS', 0],
  ['exact label cannot authorize different execution argv', { court: true, label: command, runCommand: 'node tests/kira-injection.test.mjs --source-only --mutate', output: footer(), exit: 2 }, 'FAIL', 1],
  ['plain named exit two remains unperformed', { output: 'UNPERFORMED: sandbox loopback listen refused (EPERM)', exit: 2 }, 'UNPERFORMED', 2],
  ['named arm exit two remains unperformed', { output: 'FRESH BIND: UNPERFORMED approval round trip: Unix socket listen unavailable (EPERM)', exit: 2 }, 'UNPERFORMED', 2],
  ['reasonless exit two remains failure', { output: 'UNPERFORMED:', exit: 2 }, 'FAIL', 1],
  ['plain failure outranks a named gap', { output: 'FAIL actual assertion\nUNPERFORMED: unavailable socket', exit: 2 }, 'FAIL', 1],
  ['plain TAP failure outranks a named gap', { output: 'not ok 1 - failed\nUNPERFORMED: unavailable socket', exit: 2 }, 'FAIL', 1],
  ['named nested-sandbox refusal remains unperformed', { output: 'CAGED WORKER: NOT RUN (nested sandbox - denials here would prove nothing; exit 2)', exit: 2 }, 'UNPERFORMED', 2],
  ['empty parenthesized reason remains failure', { output: 'CAGED WORKER: NOT RUN ()', exit: 2 }, 'FAIL', 1],
  ['unperformed marker must be a complete word', { output: 'UNPERFORMEDNESS: fixture', exit: 2 }, 'FAIL', 1],
  ['missing TAP totals cannot pass', { format: 'tap', output: 'completed' }, 'UNPERFORMED', 2],
  ['zero TAP tests cannot pass', { format: 'tap', output: tap() }, 'UNPERFORMED', 2],
  ['all skipped TAP tests remain unperformed', { format: 'tap', output: tap(0, 1) }, 'UNPERFORMED', 2],
  ['all todo TAP tests remain unperformed', { format: 'tap', output: tap(0, 0, 1) }, 'UNPERFORMED', 2],
]

function checkCase(name, row, status, exit, text = source) {
  const result = run([row], text)
  assert.equal(result.status, exit, name)
  assert.match(result.output, new RegExp(`^${status}\\s`, 'mu'), name)
  const count = status === 'PASS' ? [1, 1, 0, 0, 0, 0] : status === 'FAIL' ? [0, 1, 1, 0, 0, 0] : [0, 1, 0, 0, 0, 1]
  assert.deepEqual(result.counts, count, name)
}
for (const args of cases) {
  checkCase(...args)
  console.log(`PASS ${args[0]}`)
}
assert.equal(source.split(`check_injection '${command}'`).length, 2, 'only the literal court uses the governed format')

const timeoutAnchor = 'alarm 55;'
assert.equal(source.split(timeoutAnchor).length, 2)
checkCase('watchdog failure stays failure', { court: true, body: 'setInterval(()=>{},1000);\n' }, 'FAIL', 1, source.replace(timeoutAnchor, 'alarm 1;'))
console.log('PASS watchdog failure stays failure (one-second fixture timer; production remains 55 seconds)')

function checkAggregate(text = source) {
  let result = run([{ court: true, output: footer(), exit: 2 }, { output: 'completed', exit: 0 }], text)
  assert.equal(result.status, 2, 'unperformed aggregate must not be green')
  assert.deepEqual(result.counts, [1, 2, 0, 0, 0, 1])
  result = run([{ court: true, output: footer(), exit: 2 }, { output: 'synthetic failed assertion', exit: 1 }, { output: 'completed', exit: 0 }], text)
  assert.equal(result.status, 1, 'real failure must outrank unperformed')
  assert.deepEqual(result.counts, [1, 3, 1, 0, 0, 1])
}
checkAggregate()
console.log('PASS aggregate: one gap remains exit 2; mixed failure remains exit 1')

function checkMutationDispatch(text = source) {
  const rows = registrations(text)
  assert.equal(rows.some(line => /\bnode --test(?: |$).*\.mjs\s+--/u.test(line)), false,
    'Node test-runner file arguments do not reach process.argv')
  const lane = rows.filter(line => line.includes('tests/lane-send.test.mjs'))
  assert.equal(lane.length, 1)
  const invocation = lane[0].match(/^check_tap '([^']+)'$/u)?.[1]
  assert(invocation, 'retain the TAP mutation registration')
  const result = run([{ file: 'tests/lane-send.test.mjs', runCommand: invocation, format: 'tap',
    body: "import test from 'node:test'; import assert from 'node:assert/strict'; test('mutation requested', () => assert.equal(process.env.AUKORA_LANE_SEND_MUTATE, '1'));\n" }], text)
  assert.equal(result.status, 0, 'the actual shell registration must request mutations')
}
checkMutationDispatch()
console.log('PASS mutation dispatch: actual lane registration requests mutations; no swallowed file flags')

function checkTapRegistrations(text = source) {
  const rows = registrations(text)
  const row = rows.find(line => line.includes('tests/aukora-buzz-door-receipt.test.mjs'))
  const match = row?.match(/^check(_tap)? '([^']+)'$/u)
  assert(match, 'retain the receipt test registration')
  for (const directive of ['skip', 'todo']) {
    const result = run([{ file: 'tests/aukora-buzz-door-receipt.test.mjs', runCommand: match[2],
      format: match[1] ? 'tap' : 'plain',
      body: `import test from 'node:test'; test('unavailable fixture', { ${directive}: 'fixture dependency unavailable' }, () => {});\n` }], text)
    assert.equal(result.status, 2, `actual ${directive}-only Node registration must be unperformed`)
    assert.deepEqual(result.counts, [0, 1, 0, 0, 0, 1])
    assert.match(result.output, /fixture dependency unavailable/u, 'preserve the reported gap reason')
  }
  for (const row of rows.filter(line => /\bnode --test(?: |$)/u.test(line))) {
    assert.match(row, /^check_tap '/u, 'every Node test registration requires totals')
    assert.match(row, /\bnode --test --test-reporter=tap /u, 'every Node test registration emits readable totals')
  }
}
checkTapRegistrations()
console.log('PASS TAP registrations: actual skipped/todo-only children remain unperformed with their reason')

function checkRecallControl(text = source) {
  const rows = registrations(text).filter(line => line.includes('tests/kira-openviking-recall.test.mjs'))
  assert.equal(rows.length, 1)
  const invocation = rows[0].match(/^check '([^']+)'$/u)?.[1]
  assert(invocation, 'retain the recall control registration')
  const marker = '  FAIL retry counter saturation at 20: successful retry must reset the failure counter'
  for (const [name, baseline, mutant, output, expected] of [
    ['expected assertion fails', 0, 1, marker, 0],
    ['negative control stays green', 0, 0, marker, 1],
    ['unrelated control failure', 0, 1, 'FAIL unrelated fixture failure', 1],
    ['baseline failure', 1, 1, marker, 1],
  ]) {
    const result = run([{ file: 'tests/kira-openviking-recall.test.mjs', runCommand: invocation,
      body: `const args = process.argv.slice(2); const mutant = args[0] === '--mutant' && args[1] === 'retry-success-reset'; console.log(mutant ? ${JSON.stringify(output)} : 'baseline fixture'); process.exit(mutant ? ${mutant} : ${baseline});\n` }], text)
    assert.equal(result.status, expected, name)
  }
}
checkRecallControl()
console.log('PASS recall control: expected assertion must fail; green, unrelated failure and failed baseline are rejected')

const laneSource = readFileSync(new URL('./lane-send.test.mjs', import.meta.url), 'utf8')
const laneHere = new URL('.', import.meta.url).pathname
const guard = "if (mutationRequested && mutationsCaught === 0) {\n    process.exitCode = 1\n    assert.fail('LANE_SEND_MUTATIONS_NOT_RUN')\n  }"
assert.equal(laneSource.split(guard).length, 2)
const zeroCourt = laneSource.replace('const HERE = dirname(fileURLToPath(import.meta.url))', `const HERE = ${JSON.stringify(laneHere)}`)
  .replace("if (mutationRequested) test('each removed protection", "if (false) test('each removed protection")
function checkEmptyMutationCourt(text) {
  const child = spawnSync(process.execPath, ['--test-reporter=tap', '--test-name-pattern=goal examples', '--input-type=module', '--eval', text], {
    env: { ...environment, AUKORA_LANE_SEND_MUTATE: '1' }, encoding: 'utf8', timeout: 10000,
  })
  assert.equal(child.error, undefined)
  assert.equal(child.status, 1, 'an explicitly requested empty mutation court must fail')
  assert.match(child.stdout, /LANE_SEND_MUTATIONS_NOT_RUN/u)
}
checkEmptyMutationCourt(zeroCourt)
assert.throws(() => checkEmptyMutationCourt(zeroCourt.replace(guard, '')), { code: 'ERR_ASSERTION' })
console.log('KILLED zero-mutation guard removal (empty requested court otherwise exits zero)')

const uncoveredRegistrations = [
  "check '/usr/bin/python3 scripts/phase0/selfcheck.py'",
  "check '/usr/bin/python3 scripts/composition/composition-selfcheck.py'",
  "check '/usr/bin/python3 scripts/composition/subject-digest-court.py'",
  "check '/usr/bin/python3 scripts/composition/grant-rule-court.py'",
  "check '/usr/bin/python3 scripts/composition/spent-store-race-test.py'",
  "check '/usr/bin/python3 scripts/composition/ed25519.py'",
  "check '/usr/bin/python3 scripts/composition/ceilings.py'",
  "check '/usr/bin/python3 scripts/check-stage-pg-acceptance.py'",
  "check 'node scripts/aumlok/check-vendor-closure.mjs'",
  "check 'node scripts/aura/verify-append-only.mjs --selftest'",
  "check 'node scripts/check-next-composition.mjs'",
  "check 'node scripts/verify-aukora-render.mjs'",
  "check 'node scripts/face-parse-check.mjs'",
  "check 'node scripts/kira/she-remembers-check.mjs'",
  "check 'node scripts/kira/verify-memory.mjs'",
  "check '/usr/bin/python3 scripts/composition/receipt-closure-test.py'",
  "check 'bash scripts/aura/post-relaunch-check.sh'",
  "check 'node tests/unregistered-checks.test.mjs'",
  "check 'node packages/ui/scripts/check-foundation.mjs'",
  "check 'node packages/ui/scripts/check-owner-build.mjs'",
  "check 'node packages/ui/scripts/check-owner-types.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/ui/scripts/check-prerequisites.test.mjs'",
  "check 'node packages/ui/scripts/check-provider-settings.mjs'",
  "check 'node packages/ui/scripts/verify-baseline.mjs'",
  "check 'node packages/ui/scripts/verify-owner-build.mjs'",
  "check 'node packages/ui/prime-authority/checks/css-provenance.mjs'",
  "check 'node packages/ui/prime-authority/checks/css-reproduction.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/ui/prime-authority/checks/inference-controller.mjs'",
  "check 'node packages/ui/prime-authority/checks/inference-native-join.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/ui/prime-authority/checks/native-connection.mjs'",
  "check 'node packages/ui/prime-authority/checks/native-join.mjs'",
  "check 'node packages/ui/prime-authority/checks/ordinary-lifecycle.mjs'",
  "check 'node packages/ui/prime-authority/checks/ordinary-render.mjs'",
  "check 'node packages/ui/prime-authority/checks/pilot-render.mjs'",
  "check 'node packages/ui/prime-authority/checks/provider-controller.mjs'",
  "check 'node packages/ui/prime-authority/checks/render-fixture.mjs'",
  "check 'node packages/ui/prime-authority/checks/render.mjs'",
  "check 'node packages/ui/prime-authority/checks/serve-fixture.mjs'",
  "check_tap 'node --test --test-reporter=tap host/relay/test/prerequisites.test.mjs'",
  "check 'node host/aura-interim/verify.mjs'",
  "check 'node plugins/aukora-action-gate/check.mjs'",
  "check_tap 'node --test --test-reporter=tap plugins/aukora-action-gate/file-fence-race.test.mjs'",
  "check_tap 'node --test --test-reporter=tap plugins/aukora-action-gate/prerequisites.test.mjs'",
  "check 'AUKORA_PYTHON=/usr/bin/python3 bash plugins/aukora-composition-gate/test/declared-id-regression.sh \"$TMPDIR/declared-id\"'",
  "check 'node plugins/aukora-face/apps/scripts/check-vendor-tests.mjs'",
  "check 'node packages/authority/check-execution-receipt.mjs'",
  "check 'node packages/authority/check-inference-evidence.mjs'",
  "check 'node packages/authority/check-inference-mapper.mjs'",
  "check 'node packages/authority/check-inference-service.mjs'",
  "check_unittest '/usr/bin/python3 -I -S packages/boundary-gate/host/openshell/checks/private_proc_observer.py'",
  "check_tap 'node --test --test-reporter=tap packages/boundary-gate/host/systemd/hardening.test.mjs'",
  "check 'node packages/desktop/check.cjs'",
  "check 'node packages/evolution-lab/checks/check.mjs'",
  "check 'node packages/execution/checks/configuration.mjs'",
  "check 'node packages/execution/checks/effective-policy.mjs'",
  "check 'node packages/execution/checks/guardian-boundary.mjs'",
  "check 'node packages/ops/check-unregistered.mjs packages/execution/checks/guardian-process.mjs'",
  "check 'node packages/execution/checks/lifecycle.mjs'",
  "check 'node packages/execution/checks/lifetime-safety.mjs'",
  "check 'node packages/execution/checks/profile-sdk.mjs'",
  "check 'node packages/execution/checks/readiness.mjs'",
  "check 'node packages/execution/checks/timeout.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/inference/check-dispatch-expiry.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/inference/check-dispatch.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/inference/check-dsh-cancellation.mjs'",
  "check 'node packages/inference/check-types.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/inference/check-private-transport.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/inference/check-reserve-attempt.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/inference/check-total-budget.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/inference/check-worker-continuation.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/inference/check-worker-outbox.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/memory/test/new-lineage-bootstrap-source.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/memory/test/new-pilot-lineage-source.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/memory/test/new-pilot-memory-store-source.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/memory/test/reduced-pilot-scope.test.mjs'",
  "check 'node packages/ops/check-unregistered.mjs packages/ops/check-external-state.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/ops/check-unregistered.test.mjs'",
  "check 'node packages/ops/owner-save-pilot/v1/check-metadata.mjs'",
  "check 'node packages/ops/owner-save-pilot/v1/check-source.mjs --contracts-root \"$PWD/packages/contracts/src\"'",
  "check 'node packages/ops/pilot/check-pg-pool.mjs'",
  "check_unittest '/usr/bin/python3 packages/ops/pilot/check.py'",
  "check_unittest '/usr/bin/python3 packages/ops/pilot/check_preview_stage.py'",
  "check_unittest '/usr/bin/python3 packages/ops/pilot/check_verify.py'",
  "check_tap 'node --test --test-reporter=tap packages/owner-key/checks/authorization.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/owner-key/checks/gate-caller.test.mjs'",
  "check 'node packages/owner-key/checks/mutants.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/owner-key/checks/software-signer.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/runtime-bridge/checks/closure-v2.test.mjs'",
  "check 'node packages/ops/check-unregistered.mjs packages/runtime-bridge/checks/inference-boundary.test.mjs'",
  "check 'node packages/ops/check-unregistered.mjs packages/runtime-bridge/checks/inference-real-authority.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/runtime-bridge/checks/retained-adapter.test.mjs'",
  "check 'node packages/runtime-bridge/checks/retained-journal-restore.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/runtime-bridge/checks/retained-journal-sql.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/runtime-bridge/checks/retained-restore-forwarder.test.mjs'",
  "check 'node packages/ops/check-unregistered.mjs packages/runtime-bridge/test/inference-ipc.test.mjs'",
  "check_tap 'node --test --test-reporter=tap packages/runtime-bridge/test/inference-unmounted.test.mjs'",
  "check 'node packages/runtime-bridge/test/verify-owner-memory-source-join.mjs'",
  "check 'node packages/runtime-bridge/test/verify-owner-recovery-source-join.mjs'",
  "check '/usr/bin/python3 scripts/kira/experience-court.py --selftest'",
  "check 'node packages/authority/upstream/vendor/authority/conformance.mjs'",
  "check 'node scripts/aura/release-boot-smoke.mjs'",
  "check 'node scripts/aukora/airlock-probe.mjs'",
  "check 'AUKORA_LIVE_STATE=/dev/null/unselected-launch bash scripts/organism-live.sh'",
  "check 'bash scripts/organism-accept.sh --release /dev/null/unselected-release'",
  "check 'bash scripts/aura/organism-breath.sh --state /dev/null/unselected-store'",
  "check 'node scripts/aura/echo-head.mjs /dev/null/unselected-aura.jsonl'",
  "check_tap 'node --test --test-reporter=tap scripts/aura/late-prerequisites.test.mjs'",
  "check 'node harness/check-memory-retention-boundary.mjs'",
  "check 'node harness/check-static-csp.mjs'",
  "check 'node harness/check-deployment-manifest.mjs'",
  "check_unittest '/usr/bin/python3 -I -S -B tests/openviking-llama-pin.test.py'"
]
function checkUncoveredRegistrations(text = source) {
  const rows = registrations(text)
  for (const row of uncoveredRegistrations) assert.equal(rows.filter(value => value === row).length, 1,
    'every uncovered check keeps its fixed runner command: ' + row)
}
checkUncoveredRegistrations()
console.log(`PASS uncovered check registrations: ${uncoveredRegistrations.length} fixed commands retained`)
if (process.argv.includes('--mutate')) {
  for (const row of uncoveredRegistrations) {
    assert.throws(() => checkUncoveredRegistrations(source.replace(row, '')), { code: 'ERR_ASSERTION' })
  }
  console.log(`KILLED ${uncoveredRegistrations.length} uncovered registration removals`)
}

const controls = [
  ['green unperformed row', '$disposition = "UNPERFORMED"; $reason = "reported unperformed injection checks";', '$disposition = "PASS"; $reason = "reported unperformed injection checks";', text => checkCase(...cases[0], text)],
  ['drop aggregate unperformed', 'if [ "$skipped" -ne 0 ] || [ "$unperformed" -ne 0 ]; then exit 2; fi', 'if [ "$skipped" -ne 0 ]; then exit 2; fi', checkAggregate],
  ['drop aggregate failure precedence', 'if [ "$failed" -ne 0 ]; then exit 1; fi', 'if false; then exit 1; fi', checkAggregate],
  ['drop reported failure guard', 'if ($court_failure || $reported_failure) {', 'if (0) {', text => checkCase(...cases[6], text)],
  ['drop unique footer guard', '$court_reports != 1 || $court_invalid', '0 || $court_invalid', text => checkCase(...cases[10], text)],
  ['drop explicit command binding', 'die "injection command" unless $command eq "node tests/kira-injection.test.mjs --mutate" && $run eq $command;', '# removed command binding', text => checkCase(...cases[19], text)],
  ['drop execution argv binding', '$run eq $command', '1', text => checkCase(...cases[21], text)],
  ['drop mutation request', 'AUKORA_LANE_SEND_MUTATE=1 ', '', checkMutationDispatch],
  ['drop plain reason requirement', '$named_unperformed && ', '', text => checkCase(...cases[24], text)],
  ['drop plain failure precedence', '!$plain_failure && ', '', text => checkCase(...cases[25], text)],
  ['drop exact marker', String.raw`UNPERFORMED\b`, 'UNPERFORMED', text => checkCase(...cases[29], text)],
  ['drop parenthesized reason', String.raw`[^) \t][^)\n]*`, String.raw`[^)\n]*`, text => checkCase(...cases[28], text)],
  ['restore default reporter registration', "check_tap 'node --test --test-reporter=tap tests/aukora-buzz-door-receipt.test.mjs'", "check 'node --test tests/aukora-buzz-door-receipt.test.mjs'", checkTapRegistrations],
  ['drop zero TAP guard', '$totals{tests} == 0', '0', text => checkCase(...cases[31], text)],
  ['drop skipped/todo TAP guard', '$totals{skipped} > 0 || $totals{todo} > 0', '0', text => checkCase(...cases[32], text)],
  ['drop TAP gap reason', '$reason .= ": $tap_gap" if $tap_gap ne "";', '', checkTapRegistrations],
  ['restore ignored recall flag', '--mutant retry-success-reset', '--red', checkRecallControl],
  ['drop recall control exit check', '[ "$code" -eq 1 ]', 'true', checkRecallControl],
  ['drop recall control assertion check', 'grep -q "^  FAIL retry counter saturation at 20"', 'cat >/dev/null', checkRecallControl],
]
if (process.argv.includes('--mutate')) {
  for (const [name, before, after, inspect] of controls) {
    assert.equal(source.split(before).length, 2, `${name}: exact unique production anchor`)
    const mutated = source.replace(before, after)
    let caught = false
    try {
      inspect(mutated)
    } catch (error) {
      assert.equal(error.code, 'ERR_ASSERTION', 'mutant must be killed by its disposition assertion, not an execution accident')
      caught = true
    }
    assert(caught, `${name}: removal survived`)
    console.log(`KILLED ${name}`)
  }
}
console.log(`check-shell-status: ${cases.length + 3} cases PASS; ${process.argv.includes('--mutate') ? controls.length : 0} controls killed; 269 registrations retained; synthetic child/actual runner only; no fixture deletes`)
