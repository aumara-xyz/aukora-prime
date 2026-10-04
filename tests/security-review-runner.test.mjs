// SPDX-License-Identifier: AGPL-3.0-or-later
// Runner contracts only: disposable children/reporters, no live stores, keys,
// enrollment, deployment, OpenShell or product-acceptance claim.
import test, { after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { REVIEW_PROFILE, reviewCommand, classifyCheckResult, summarizeReview, runReviewChecks } from '../scripts/audit/security-review.mjs'

const scratch = mkdtempSync(join(tmpdir(), 'aukora-runner-check-'))
after(() => rmSync(scratch, { recursive: true, force: true }))
const fixtures = new Map([
  ['pass', "require('node:test')('completed',()=>{})"],
  ['skip', "require('node:test')('unavailable',{skip:true},()=>{})"],
  ['partial', "const t=require('node:test');t('completed',()=>{});t('unavailable',{skip:true},()=>{})"],
  ['todo', "require('node:test')('unfinished',{todo:true},()=>{})"],
  ['fail', "require('node:test')('failed',()=>{throw Error('synthetic runner failure')})"],
])
const fixturePaths = new Map()
for (const [name, source] of fixtures) {
  const path = join(scratch, `${name}.cjs`)
  writeFileSync(path, source, { mode: 0o600 }); fixturePaths.set(name, path)
}
const nodeArgs = name => ['--test', '--test-reporter=tap', fixturePaths.get(name)]
// Each disposable child must have its own test runner, rather than inheriting
// Node's internal context for this parent node --test process.
const fixtureEnvironment = source => {
  const env = { ...source }; delete env.NODE_TEST_CONTEXT; return env
}
const nodeChild = name => spawnSync(process.execPath, nodeArgs(name), { timeout: 10000, env: fixtureEnvironment(process.env) })
const runnerSource = readFileSync(new URL('../scripts/audit/security-review.mjs', import.meta.url), 'utf8')
function disposableRunner(name) {
  const root = join(scratch, name), path = join(root, 'scripts/audit/security-review.mjs')
  mkdirSync(join(root, 'scripts/audit'), { recursive: true }); writeFileSync(path, runnerSource)
  return { root, path, run: args => spawnSync(process.execPath, [path, ...args], { timeout: 10000, env: fixtureEnvironment(process.env) }) }
}
const tap = counts => Buffer.from('TAP version 13\n' + Object.entries({ tests: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0, ...counts })
  .map(([key, count]) => `# ${key} ${count}`).join('\n') + '\n')

test('fixed profile wires the named checks with the actual Node/Python runtimes', () => {
  const byId = new Map(REVIEW_PROFILE.map(row => [row.id, row]))
  assert.equal(byId.size, REVIEW_PROFILE.length)
  for (const [id, path] of [
    ['sequence-floor', 'packages/boundary-gate/src/vendor/check-sequence-floor.mjs'],
    ['ordered-approval', 'packages/boundary-gate/src/vendor/check-ordered-approval.mjs'],
    ['preview-policy', 'packages/boundary-gate/src/vendor/check-preview-policy.mjs'],
    ['owner-card-clarity', 'tests/aukora-owner-card-clarity.test.mjs'],
    ['plugin-set-floor-card', 'tests/aukora-plugin-set-floor-card.test.mjs'],
    ['owner-key', 'packages/owner-key/checks/owner-key.test.mjs'],
    ['aura-lifecycle-citation', 'scripts/aura/checks/collector.mjs'],
    ['kira-aura-recall', 'tests/kira-aura-recall.test.mjs'],
    ['containment-verdict-firewall', 'tests/aukora-containment.test.mjs'],
  ]) {
    const row = byId.get(id); assert(row, `${id} must run`)
    assert(row.args.includes(path)); assert.equal(reviewCommand(row)[0], process.execPath)
  }
  const bootstrap = byId.get('protected-bootstrap')
  assert.deepEqual(reviewCommand(bootstrap), ['/usr/bin/python3', '-I', '-S', 'packages/boundary-gate/host/install/check-bootstrap.py'])
  assert.equal(bootstrap.report, 'unittest')
  for (const row of REVIEW_PROFILE) {
    assert(Object.isFrozen(row)); assert(Object.isFrozen(row.args))
    if (row.report === 'tap') assert(row.args.includes('--test-reporter=tap'))
  }
  assert.throws(() => reviewCommand({ ...bootstrap, executable: '/candidate/executable' }))
})

test('actual completed, skipped, partial, todo and failed TAP children remain distinct', () => {
  const expected = { pass: 'PASS', skip: 'SKIP', partial: 'UNPERFORMED', todo: 'UNPERFORMED', fail: 'FAIL' }
  for (const [name, status] of Object.entries(expected)) {
    const child = nodeChild(name)
    assert.equal(child.error, undefined)
    const row = classifyCheckResult(child, 'tap')
    assert.equal(row.status, status, name)
    assert(row.reported_test_totals.tests > 0)
    if (name === 'partial') {
      assert.equal(row.reported_test_totals.pass, 1)
      assert.equal(row.reported_test_totals.skipped, 1)
    }
    if (name === 'todo') assert.equal(row.reported_test_totals.todo, 1)
  }
})

test('absent, zero, incomplete and contradictory test reports never become PASS', () => {
  for (const stdout of [Buffer.alloc(0), tap({}), Buffer.from('# tests 1\n# pass 1\n'), tap({ tests: 2, pass: 1 })]) {
    assert.equal(classifyCheckResult({ status: 0, stdout }, 'tap').status, 'UNPERFORMED')
  }
  const duplicateFailure = Buffer.concat([tap({ tests: 1, fail: 1 }), Buffer.from('# fail 0\n')])
  assert.equal(classifyCheckResult({ status: 0, stdout: duplicateFailure }, 'tap').status, 'FAIL')
  assert.equal(classifyCheckResult({ status: 0, stdout: tap({ tests: 1, cancelled: 1 }) }, 'tap').status, 'FAIL')
  assert.throws(() => classifyCheckResult({ status: 0 }, 'candidate-format'))
})

test('missing programs, timeouts, signals and nonzero assertion scripts fail', () => {
  const missing = spawnSync(join(scratch, 'missing-executable'), [], { timeout: 1000 })
  assert.equal(missing.error?.code, 'ENOENT')
  assert.equal(classifyCheckResult(missing).status, 'FAIL')
  const timeout = spawnSync(process.execPath, ['--eval', 'setInterval(()=>{},1000)'], { timeout: 150 })
  assert.equal(timeout.error?.code, 'ETIMEDOUT')
  assert.equal(classifyCheckResult(timeout).status, 'FAIL')
  const signalled = spawnSync(process.execPath, ['--eval', "process.kill(process.pid,'SIGTERM')"], { timeout: 1000 })
  assert.equal(signalled.signal, 'SIGTERM')
  assert.equal(classifyCheckResult(signalled).status, 'FAIL')
  const plain = spawnSync(process.execPath, ['--eval', 'process.exit(1)'], { timeout: 1000 })
  assert.equal(classifyCheckResult(plain).status, 'FAIL')
  assert.equal(classifyCheckResult({ status: 0, stdout: Buffer.from('completed source assertions\n') }).status, 'PASS')
})

function pythonChild(name, body) {
  const path = join(scratch, `${name}.py`)
  writeFileSync(path, 'import unittest\nclass Checks(unittest.TestCase):\n' + body + '\nunittest.main()\n', { mode: 0o600 })
  return spawnSync('/usr/bin/python3', ['-I', '-S', path], { timeout: 10000 })
}
test('actual unittest skip and expected-failure work stays unperformed', () => {
  for (const [name, body, expected] of [
    ['python-pass', ' def test_ok(self): self.assertTrue(True)', 'PASS'],
    ['python-skip', ' @unittest.skip("synthetic missing prerequisite")\n def test_skip(self): pass', 'SKIP'],
    ['python-partial', ' def test_ok(self): pass\n @unittest.skip("synthetic missing prerequisite")\n def test_skip(self): pass', 'UNPERFORMED'],
    ['python-todo', ' @unittest.expectedFailure\n def test_todo(self): self.fail("synthetic unfinished check")', 'UNPERFORMED'],
    ['python-unexpected-success', ' @unittest.expectedFailure\n def test_todo(self): pass', 'FAIL'],
  ]) {
    const child = pythonChild(name, body); assert.equal(child.error, undefined)
    const row = classifyCheckResult(child, 'unittest'); assert.equal(row.status, expected, name)
    if (name === 'python-todo') assert.equal(row.reported_test_totals.todo, 1)
  }
  assert.equal(classifyCheckResult({ status: 0, stderr: Buffer.from('Ran 2 tests in 0.01s\n\nOK (unknown=2)\n') }, 'unittest').status, 'UNPERFORMED')
  assert.equal(classifyCheckResult({ status: 0, stderr: Buffer.from('Ran 2 tests in 0.01s\n\nFAILED\n') }, 'unittest').status, 'FAIL')
})

test('aggregate failure wins; skips/gaps survive; no empty profile or declared gap becomes PASS', () => {
  const pass = classifyCheckResult(nodeChild('pass'), 'tap')
  const skip = classifyCheckResult(nodeChild('skip'), 'tap')
  const partial = classifyCheckResult(nodeChild('partial'), 'tap')
  const fail = classifyCheckResult(nodeChild('fail'), 'tap')
  assert.equal(summarizeReview([pass]).exit_code, 0)
  const declared = summarizeReview([pass], [{ reason: 'protected join remains unperformed' }])
  assert.equal(declared.profile_result, 'PASS'); assert.equal(declared.result, 'UNPERFORMED'); assert.equal(declared.exit_code, 2)
  const gaps = summarizeReview([pass, skip, partial])
  assert.equal(gaps.pass, 1); assert.equal(gaps.skipped, 1); assert.equal(gaps.unperformed, 1)
  assert.equal(gaps.reported_test_totals.skipped, 2); assert.equal(gaps.exit_code, 2)
  assert.equal(summarizeReview([pass, skip, partial, fail], [{}]).exit_code, 1)
  assert.equal(summarizeReview([]).exit_code, 2)
})

test('list mode names every check without running the profile and clears positive mutation/source overrides', () => {
  const names = ['SYNTHETIC_RUNNER_MUTANT', 'AUKORA_RECORDS_MODULE', 'AUKORA_PRIME_CHECK_GIT', 'AUKORA_AURA_CHECK_GIT', 'AUKORA_AURA_CITATION_BASE', 'NODE_TEST_CONTEXT']
  const previous = new Map(names.map(name => [name, process.env[name]]))
  try {
    for (const name of names) process.env[name] = 'synthetic candidate override'
    const result = runReviewChecks({ list: true })
    assert.equal(result.checks.length, REVIEW_PROFILE.length)
    assert(result.checks.every(row => row.status === 'UNPERFORMED' && !Object.hasOwn(row, 'exit')))
    for (const name of names) assert(result.cleared_mutation_selectors.includes(name))
  } finally {
    for (const [name, value] of previous) if (value === undefined) delete process.env[name]; else process.env[name] = value
  }
})

test('actual CLI reports failed preconditions and every unexecuted check without a false PASS', () => {
  const fixture = disposableRunner('missing-prerequisites'), child = fixture.run(['--list'])
  assert.equal(child.status, 1)
  const report = JSON.parse(child.stdout)
  assert.equal(report.summary.pass, 0); assert.equal(report.summary.fail, 1)
  assert.equal(report.summary.unperformed, REVIEW_PROFILE.length)
  assert.equal(report.checks[0].id, 'review-preconditions')
  assert(report.checks.slice(1).every(row => row.status === 'UNPERFORMED'))
  const alias = join(fixture.root, 'scripts/audit/review-alias.mjs')
  symlinkSync('security-review.mjs', alias)
  const aliased = spawnSync(process.execPath, ['--preserve-symlinks-main', alias, '--list'],
    { timeout: 10000, env: fixtureEnvironment(process.env) })
  assert.equal(aliased.status, 1); assert.equal(JSON.parse(aliased.stdout).summary.fail, 1)
})

test('current physical closure is required even when removed tracked files remain available in Git', () => {
  const fixture = disposableRunner('physical-prerequisites')
  const paths = ['package.json', 'packages/contracts/package.json', 'packages/boundary-gate/package.json',
    'packages/contracts/src/json.mjs', 'plugins/aukora-nostr/lib/records.mjs', 'plugins/aukora-nostr/lib/event.mjs',
    'plugins/aukora-nostr/lib/identity.mjs', 'plugins/aukora-nostr/lib/vendor/fixture.mjs',
    'plugins/aukora-aumlok/fixture.mjs', 'scripts/aura/collect-gate.mjs', 'scripts/aura/gate-snapshot.mjs',
    'scripts/aura/verify-collected.mjs', 'packages/boundary-gate/host/aura/context.mjs',
    'packages/boundary-gate/host/aura/entry.mjs', 'packages/boundary-gate/host/aura/records-provider.mjs',
    'plugins/aukora-kira/lib/index.js', 'plugins/aukora-kira/lib/tracked-memory.mjs',
    'plugins/aukora-kira/lib/aura-recall.mjs', 'plugins/aukora-kira/lib/aura-association.mjs']
  for (const path of paths) {
    mkdirSync(join(fixture.root, path, '..'), { recursive: true })
    writeFileSync(join(fixture.root, path), path.endsWith('.json') ? '{}\n' : '// synthetic presence fixture only\n')
  }
  const git = args => {
    const child = spawnSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Runner Fixture',
      '-c', 'user.email=runner@aukora.invalid', ...args], { cwd: fixture.root, timeout: 10000, env: fixtureEnvironment(process.env) })
    assert.equal(child.status, 0, child.stderr?.toString()); return child
  }
  git(['init', '--quiet']); git(['add', '--', ...paths]); git(['commit', '--quiet', '-m', 'Synthetic runner presence fixture'])
  for (const profile of ['aura', 'kira']) {
    const child = fixture.run(['--source-prerequisite', profile])
    assert.equal(child.status, 0); assert.equal(JSON.parse(child.stdout).status, 'PASS')
  }
  const vendor = join(fixture.root, 'plugins/aukora-nostr/lib/vendor/fixture.mjs')
  rmSync(vendor)
  assert.equal(git(['cat-file', '-e', 'HEAD:plugins/aukora-nostr/lib/vendor/fixture.mjs']).status, 0)
  let child = fixture.run(['--source-prerequisite', 'aura'])
  assert.equal(child.status, 1); assert.equal(JSON.parse(child.stdout).missing_files, 1)
  symlinkSync('../records.mjs', vendor)
  child = fixture.run(['--source-prerequisite', 'kira'])
  assert.equal(child.status, 1); assert.equal(JSON.parse(child.stdout).missing_files, 1)
  assert.equal(fixture.run(['--source-prerequisite', 'candidate-selected-root']).status, 1)
})

const shell = readFileSync(new URL('../scripts/check.sh', import.meta.url), 'utf8')
const perl = shell.match(/run_check\(\) \{[\s\S]*?perl -MTime::HiRes=time -e '([\s\S]*?)' "\$work\/\$count" /u)?.[1]
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'"
function shellChild(name, command, report = 'plain', source = perl, env = process.env) {
  assert.equal(typeof source, 'string', 'exercise the actual shell runner, not a copied classifier')
  const prefix = join(scratch, `shell-${name}`)
  const child = spawnSync('perl', ['-MTime::HiRes=time', '-e', source, prefix, 'synthetic runner fixture', command, report], { timeout: 12000, env: fixtureEnvironment(env) })
  assert.equal(child.error, undefined, child.stderr?.toString())
  return { child, status: readFileSync(`${prefix}.status`, 'utf8').trim(), row: readFileSync(`${prefix}.row`, 'utf8') }
}
test('shell runner executes the same mandatory checks exactly once', () => {
  for (const path of ['check-sequence-floor.mjs', 'check-ordered-approval.mjs', 'check-preview-policy.mjs',
    'host/install/check-bootstrap.py', 'tests/aukora-owner-card-clarity.test.mjs', 'packages/owner-key/checks/owner-key.test.mjs',
    'tests/aukora-plugin-set-floor-card.test.mjs',
    'tests/aukora-containment.test.mjs', 'tests/aukora-auma-firewall.test.mjs',
    'scripts/aura/checks/collector.mjs', 'tests/kira-aura-recall.test.mjs', 'tests/security-review-runner.test.mjs']) {
    const rows = shell.split('\n').filter(line => /^check(?:_tap|_unittest)? /u.test(line) && line.includes(path))
    assert.equal(rows.length, 1, path)
  }
  assert(/\/usr\/bin\/python3 -I -S packages\/boundary-gate\/host\/install\/check-bootstrap\.py/u.test(shell), 'fixed isolated Python bootstrap invocation')
  assert(/24\.11\.1/u.test(shell), 'runtime floor supports current Node source')
})

test('actual extracted shell child classifies performed, skipped, partial, todo and failed TAP', () => {
  for (const [name, status, code] of [['pass', 'PASS', 0], ['skip', 'SKIP', 3], ['partial', 'UNPERFORMED', 2], ['todo', 'UNPERFORMED', 2], ['fail', 'FAIL', 1]]) {
    const command = [process.execPath, ...nodeArgs(name)].map(quote).join(' ')
    const result = shellChild(name, command, 'tap')
    assert.equal(result.status, status, name); assert.equal(result.child.status, code, result.row)
  }
})

test('shell watchdog only times out its own fixture and redacts failure output/source overrides', () => {
  assert.equal((perl.match(/alarm 55;/gu) ?? []).length, 1)
  const shortened = perl.replace('alarm 55;', 'alarm 1;') // scoped timer oracle; production duration unchanged
  const command = [process.execPath, '--eval', 'setInterval(()=>{},1000)'].map(quote).join(' ')
  const timed = shellChild('timeout', command, 'plain', shortened)
  assert.equal(timed.status, 'FAIL'); assert.equal(timed.child.status, 1)
  assert.match(timed.row, /timeout/u)
  const privacyCode = "console.log('authorization=synthetic-private-sentinel');process.exit(1)"
  const privateResult = shellChild('privacy', [process.execPath, '--eval', privacyCode].map(quote).join(' '))
  assert.equal(privateResult.status, 'FAIL'); assert(!privateResult.row.includes('synthetic-private-sentinel'))
  const envCode = "process.exit(['FIXTURE_MUTANT','AUKORA_RECORDS_MODULE','AUKORA_PRIME_CHECK_GIT','AUKORA_AURA_CHECK_GIT','AUKORA_AURA_CITATION_BASE','NODE_TEST_CONTEXT'].some(k=>k in process.env)||process.env.GIT_NO_LAZY_FETCH!=='1'?1:0)"
  const cleared = shellChild('environment', [process.execPath, '--eval', envCode].map(quote).join(' '), 'plain', perl,
    { ...process.env, FIXTURE_MUTANT: 'synthetic', AUKORA_RECORDS_MODULE: 'synthetic', AUKORA_PRIME_CHECK_GIT: 'synthetic', AUKORA_AURA_CHECK_GIT: 'synthetic', AUKORA_AURA_CITATION_BASE: 'synthetic' })
  assert.equal(cleared.status, 'PASS', cleared.row)
})
