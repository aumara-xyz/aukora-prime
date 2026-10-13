// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic results and disposable children test CI refusals without running repository suites.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import test from 'node:test';
import {fileURLToPath, pathToFileURL} from 'node:url';
import * as checks from './checks.mjs';
import {summarizeReview} from '../audit/security-review.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const helper = join(root, 'scripts/ci/checks.mjs');
const source = readFileSync(helper, 'utf8');
const workflow = readFileSync(join(root, '.github/workflows/checks.yml'), 'utf8');
const groups = {'security-review': ['security-review', 'packages/boundary-gate/checks/a.mjs'],
  'check-shell': ['scripts/check.sh'], tests: ['tests/a.test.mjs', 'tests/b.test.mjs']};
const empty = new Map();
const result = (stdout = '', extra = {}) => ({status: 0, signal: null, stdout, stderr: '', ...extra});
const tap = (extra = {}) => Object.entries({tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 0, todo: 0,
  ...extra}).map(([key, value]) => `# ${key} ${value}`).join('\n') + '\n';
const shell = (pass, total, fail = 0, skipped = 0, platform = 0, unperformed = 0) =>
  `${skipped + unperformed ? 'UNPERFORMED fixture: named missing dependency\n' : ''}TOTAL checks | ${pass}/${total} passed | ${fail} failed | ${skipped} skipped (${platform} platform) | ${unperformed} unperformed\n`;
const redLine = 'tests/a.test.mjs | 2026-10-12 | waiting for synthetic fixture';
const review = (rows = [{status: 'PASS'}], unperformed = []) => ({schema: 'aukora-security-review/v1',
  checks: rows, unperformed, summary: summarizeReview(rows, unperformed)});

function replace(text, before, after) {
  assert.equal(text.split(before).length, 2, `mutation must have one target: ${before}`);
  return text.replace(before, after);
}
function moduleURL(text, fixtureRoot = root) {
  return 'data:text/javascript;base64,' + Buffer.from(text
    .replace("'../audit/security-review.mjs'", JSON.stringify(pathToFileURL(join(root, 'scripts/audit/security-review.mjs')).href))
    .replace("const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');", `const root = ${JSON.stringify(fixtureRoot)};`)
    .replaceAll('fileURLToPath(import.meta.url)', JSON.stringify(helper))).toString('base64');
}
function scratch(fn) {
  const directory = mkdtempSync(join(root, '.prime-check-ci-tests-'));
  try {return fn(directory);} finally {rmSync(directory, {recursive: true, force: true});}
}

const protections = [
  ['exact known-red syntax is required', api => {
    for (const line of ['tests/a.test.mjs', '# tolerated', 'tests/a.test.mjs | 2026-10-12 | ',
      'tests/a.test.mjs | 2026-10-12 | reason | extra'])
      assert.throws(() => api.parseKnownRed(line, groups), /CI_INVALID_EXCEPTION/);
  }, "requireValue(match, 'CI_INVALID_EXCEPTION');", ''],
  ['unknown paths cannot create exceptions', api => {
    for (const path of ['tests/*.test.mjs', 'tests/missing.test.mjs', '../tests/a.test.mjs'])
      assert.throws(() => api.parseKnownRed(`${path} | 2026-10-12 | fixture`, groups), /CI_UNKNOWN_EXCEPTION_PATH/);
  }, "requireValue(paths.has(path), 'CI_UNKNOWN_EXCEPTION_PATH');", ''],
  ['duplicate paths cannot replace reasons', api => {
    assert.throws(() => api.parseKnownRed(`${redLine}\n${redLine}`, groups), /CI_DUPLICATE_EXCEPTION/);
  }, "requireValue(!exceptions.has(path), 'CI_DUPLICATE_EXCEPTION');", ''],
  ['calendar dates must exist', api => {
    for (const date of ['2026-02-29', '2026-13-01', '2026-04-31'])
      assert.throws(() => api.parseKnownRed(`tests/a.test.mjs | ${date} | fixture`, groups), /CI_INVALID_EXCEPTION_DATE/);
  }, "requireValue(!Number.isNaN(Date.parse(date)) && new Date(date).toISOString().slice(0, 10) === date,\n      'CI_INVALID_EXCEPTION_DATE');", ''],
  ['unlisted commands remain required beside an exception', api => {
    const exceptions = api.parseKnownRed(redLine, groups);
    assert.deepEqual(api.plan(groups, exceptions).include, [
      {group: 'security-review', partition: 'required', continue_on_error: false},
      {group: 'check-shell', partition: 'required', continue_on_error: false},
      {group: 'tests', partition: 'required', continue_on_error: false},
      {group: 'tests', partition: 'known-red', continue_on_error: true}]);
  }, 'continue_on_error: tolerated', 'continue_on_error: true'],
  ['only the exact listed command enters its tolerated partition', api => {
    const exceptions = api.parseKnownRed(redLine, groups);
    assert.deepEqual(api.selectPaths(groups, exceptions, 'tests', 'known-red'), ['tests/a.test.mjs']);
    assert.deepEqual(api.selectPaths(groups, exceptions, 'tests', 'required'), ['tests/b.test.mjs']);
  }, "return groups[group].filter(path => exceptions.has(path) === (partition === 'known-red'));", 'return groups[group];'],
  ['nonexistent partitions cannot launch commands', api => {
    for (const [group, partition] of [['tests', 'known-red'], ['tests', 'typo'], ['missing', 'required']])
      assert.throws(() => api.selectPaths(groups, empty, group, partition), /CI_UNKNOWN_JOB/);
  }, "requireValue(plan(groups, exceptions).include.some(row => row.group === group && row.partition === partition),\n    'CI_UNKNOWN_JOB');", ''],
  ['test scripts execute directly without Node test isolation', api => {
    assert.deepEqual(api.command('tests/a.test.mjs', 'logs'), [process.execPath, '--test-reporter=tap', 'tests/a.test.mjs']);
    assert.deepEqual(api.command('scripts/check.sh', 'logs'), ['sh', 'scripts/check.sh']);
    assert.deepEqual(api.command('security-review', 'logs'), ['./security-review', '--logs', 'logs/security-review-children']);
  }, "return [process.execPath, '--test-reporter=tap', path];", "return [process.execPath, '--test', '--test-reporter=tap', path];"],
  ['exit errors and interruptions never pass', api => {
    for (const extra of [{status: 1}, {status: null}, {signal: 'SIGTERM'}, {error: {code: 'ETIMEDOUT'}}])
      assert.equal(api.classify('tests/a.test.mjs', result('', extra)), 'FAIL');
  }, "if (result.error || result.signal || ![0, 2].includes(result.status)) return 'FAIL';", ''],
  ['security review summary must match its rows and exit', api => {
    assert.equal(api.classify('security-review', result(JSON.stringify(review()))), 'PASS');
    for (const change of [r => {r.schema = 'unrelated';}, r => {r.summary.pass++;}, r => {r.checks = [];}]) {
      const report = review(); change(report);
      assert.equal(api.classify('security-review', result(JSON.stringify(report))), 'FAIL');
    }
    assert.equal(api.classify('security-review', result(JSON.stringify(review()), {status: 2})), 'FAIL');
    assert.equal(api.classify('security-review', result('not JSON')), 'FAIL');
  }, "requireValue(report.schema === 'aukora-security-review/v1' && report.checks.length > 0 &&\n        JSON.stringify(report.summary) === JSON.stringify(expected) && result.status === expected.exit_code,\n      'CI_INVALID_REVIEW_SUMMARY');", ''],
  ['shell totals must appear exactly once', api => {
    for (const out of ['', shell(1, 1) + shell(1, 1)])
      assert.equal(api.classify('scripts/check.sh', result(out)), 'FAIL');
  }, "if (totals.length !== 1) return 'FAIL';", ''],
  ['shell totals reject failures and inconsistent counts', api => {
    for (const out of [shell(0, 0), shell(2, 1), shell(1, 2, 1), shell(1, 1, 0, 0, 1)])
      assert.equal(api.classify('scripts/check.sh', result(out)), 'FAIL');
  }, "if (!total || pass + fail + skipped + unperformed !== total || platform > skipped || fail) return 'FAIL';", ''],
  ['shell exit must agree with incomplete evidence', api => {
    assert.equal(api.classify('scripts/check.sh', result(shell(1, 1), {status: 2})), 'FAIL');
    assert.equal(api.classify('scripts/check.sh', result(shell(0, 1, 0, 1))), 'FAIL');
  }, "if (result.status !== (incomplete ? 2 : 0)) return 'FAIL';", ''],
  ['shell skipped work stays unperformed', api => {
    for (const out of [shell(1, 2, 0, 1, 1), shell(0, 1, 0, 0, 0, 1)])
      assert.equal(api.classify('scripts/check.sh', result(out, {status: 2})), 'UNPERFORMED');
    assert.equal(api.classify('scripts/check.sh', result(shell(1, 1))), 'PASS');
  }, "return incomplete ? 'UNPERFORMED' : 'PASS';", "return 'PASS';"],
  ['TAP skips never become passes', api => {
    assert.equal(api.classify('tests/a.test.mjs', result(tap({pass: 0, skipped: 1}))), 'UNPERFORMED');
    assert.equal(api.classify('tests/a.test.mjs', result(tap({tests: 2, skipped: 1}))), 'UNPERFORMED');
  }, "return status === 'SKIP' || (status === 'PASS' && result.status === 2) ? 'UNPERFORMED' : status;", "return 'PASS';"],
  ['Kira injection limits remain unperformed', api => {
    const out = '  3/3 arms passed, 0 failed; 1 unperformed checks; DSH source dispatch RAN; installed profile UNPERFORMED.\n';
    assert.equal(api.classify('tests/kira-injection.test.mjs', result(out)), 'UNPERFORMED');
    assert.equal(api.classify('tests/kira-injection.test.mjs', result(out.replace('3/3', '2/3'))), 'FAIL');
    assert.equal(api.classify('tests/kira-injection.test.mjs', result('')), 'FAIL');
    assert.equal(api.classify('tests/kira-injection.test.mjs', result(out, {stderr: 'FAIL synthetic'})), 'FAIL');
  }, "if (path === 'tests/kira-injection.test.mjs') {", 'if (false) {'],
  ['exit 2 with a stated reason is unperformed for every command', api => {
    for (const path of ['tests/aukora-contact-migration.test.mjs', 'tests/kira-aura-association.test.mjs',
      'tests/kira-memory-live-path.test.mjs', 'tests/a.test.mjs']) {
      for (const stream of ['stdout', 'stderr'])
        assert.equal(api.classify(path, result('', {status: 2, [stream]: 'UNPERFORMED: fixture dependency missing'})), 'UNPERFORMED');
    }
  }, "if (result.status === 2) return 'UNPERFORMED';", "if (result.status === 2) return 'FAIL';"],
  ['exit 2 requires a printed reason', api => {
    for (const stdout of ['', 'UNPERFORMED', 'UNPERFORMED: ', tap(), 'ok 1 - missing fixture # SKIP\n' + tap({pass: 0, skipped: 1})])
      assert.equal(api.classify('tests/a.test.mjs', result(stdout, {status: 2})), 'FAIL');
  }, "if (result.status === 2 && unperformedReasons(path, result).length === 0) return 'FAIL';", ''],
  ['reported failures take precedence over named unperformed work', api => {
    for (const failure of ['FAIL fixture', 'not ok 1 - fixture', '# fail 1', '# cancelled 1'])
      assert.equal(api.classify('tests/a.test.mjs', result(`UNPERFORMED: absent fixture\n${failure}\n`, {status: 2})), 'FAIL');
  }, "if (/^\\s*(?:FAIL\\b|not ok\\b)|^# (?:fail|cancelled) [1-9]\\d*\\s*$/m.test(out + '\\n' + err)) return 'FAIL';", ''],
  ['security review incomplete rows require reasons', api => {
    for (const reason of [undefined, '', ' ']) {
      const report = review([{status: 'PASS'}], [{reason}]);
      assert.equal(api.classify('security-review', result(JSON.stringify(report), {status: 2})), 'FAIL');
    }
  }, "requireValue(incomplete.every(row => typeof row.reason === 'string' && row.reason.trim()), 'CI_UNPERFORMED_REASON_REQUIRED');", ''],
  ['shell incomplete rows require printed reasons', api => {
    assert.equal(api.classify('scripts/check.sh', result(shell(0, 1, 0, 0, 0, 1).replace(/^UNPERFORMED[^\n]*\n/, ''), {status: 2})), 'FAIL');
  }, "if (incomplete && unperformedReasons(path, result).length === 0) return 'FAIL';", ''],
  ['named unperformed arms retain their printed reason', api => {
    const output = result('UNPERFORMED release closure: no built harness found\n', {status: 2});
    assert.equal(api.classify('tests/a.test.mjs', output), 'UNPERFORMED');
    assert.deepEqual(api.unperformedReasons('tests/a.test.mjs', output), ['release closure: no built harness found']);
  }, '|[ \\t]+(?=[^:\\n]+:[ \\t]*\\S)', ''],
  ['TAP reporting fallback cannot qualify an unexplained exit 2', api => {
    const output = result('ok 1 - missing fixture # SKIP\n' + tap({pass: 0, skipped: 1}), {status: 2});
    assert.deepEqual(api.unperformedReasons('tests/a.test.mjs', output), []);
    assert.deepEqual(api.unperformedReasons('tests/a.test.mjs', output, true), ['TAP check skipped without a stated reason: missing fixture']);
    assert.equal(api.classify('tests/a.test.mjs', output), 'FAIL');
  }, 'reportedFallback = false', 'reportedFallback = true'],
  ['TAP reporting explains unnamed skips and incomplete totals', api => {
    const unnamed = result('ok 1 - missing fixture # SKIP\n' + tap({pass: 0, skipped: 1}));
    assert.deepEqual(api.unperformedReasons('tests/a.test.mjs', unnamed, true), ['TAP check skipped without a stated reason: missing fixture']);
    const mixed = result('ok 1 - one # SKIP absent dependency\nok 2 - two # SKIP\n' + tap({tests: 2, pass: 0, skipped: 2}));
    assert.deepEqual(api.unperformedReasons('tests/a.test.mjs', mixed, true), ['absent dependency', 'TAP check skipped without a stated reason: two']);
    assert.deepEqual(api.unperformedReasons('tests/a.test.mjs', result('# tests 1\n'), true), ['missing or inconsistent completed test totals']);
  }, "if (reportedFallback && /^# (tests|pass|fail|cancelled|skipped|todo) /m.test(out)) {", 'if (false) {'],
  ['a failed command always fails the aggregate', api => {
    assert.equal(api.summarize([{status: 'PASS'}, {status: 'FAIL'}, {status: 'UNPERFORMED'}]).exitCode, 1);
  }, "['PASS', 'UNPERFORMED'].includes(row.status)", "['PASS', 'FAIL', 'UNPERFORMED'].includes(row.status)"],
  ['recall source NOT RUN remains unperformed', api => {
    for (const out of ['  ----  NOT RUN: the host validator is absent...', '  ----  NOT RUN: actual host ToolRuntime/Cordis is absent...'])
      assert.equal(api.classify('tests/kira-recall-output-seam.test.mjs', result(out)), 'UNPERFORMED');
  }, "if (path === 'tests/kira-recall-output-seam.test.mjs' && /^  ----  NOT RUN:/m.test(out)) return 'UNPERFORMED';", ''],
  ['owner protocol named skips remain unperformed', api => {
    assert.equal(api.classify('tests/aukora-owner-protocol.test.mjs', result('(0 red, 2 skipped with a named ceiling)')), 'UNPERFORMED');
  }, "if (path === 'tests/aukora-owner-protocol.test.mjs' && /\\(0 red, [1-9]\\d* skipped with a named ceiling\\)/.test(out)) return 'UNPERFORMED';", ''],
  ['an empty run cannot succeed', api => {
    assert.deepEqual(api.summarize([]), {counts: {PASS: 0, FAIL: 0, UNPERFORMED: 0}, exitCode: 1});
  }, 'rows.length > 0 && rows.every', 'rows.every'],
  ['aggregate failure fails; named unperformed work does not fail the job', api => {
    for (const status of ['FAIL', 'UNPERFORMED']) {
      const summary = api.summarize([{status: 'PASS'}, {status}]);
      assert.deepEqual(summary.counts, {PASS: 1, FAIL: Number(status === 'FAIL'), UNPERFORMED: Number(status === 'UNPERFORMED')});
      assert.equal(summary.exitCode, status === 'FAIL' ? 1 : 0);
    }
    assert.equal(api.summarize([{status: 'UNPERFORMED'}]).exitCode, 0);
    assert.equal(api.summarize([{status: 'invalid'}]).exitCode, 1);
  }, "rows.every(row => ['PASS', 'UNPERFORMED'].includes(row.status))", "rows.every(row => row.status === 'PASS')"],
];

for (const [name, check] of protections) test(name, () => check(checks));

test('empty known-red list produces only required jobs and covers every path', () => {
  const exceptions = checks.parseKnownRed('\n\r\n', groups);
  assert.equal(exceptions.size, 0);
  const matrix = checks.plan(groups, exceptions).include;
  assert.deepEqual(matrix.map(row => row.group), Object.keys(groups));
  assert.ok(matrix.every(row => row.partition === 'required' && row.continue_on_error === false));
  assert.deepEqual(matrix.flatMap(row => checks.selectPaths(groups, exceptions, row.group, row.partition)), Object.values(groups).flat());
  assert.deepEqual(checks.parseKnownRed(redLine, groups).get('tests/a.test.mjs'),
    {date: '2026-10-12', reason: 'waiting for synthetic fixture'});
});

test('TAP missing, contradictory, todo, cancelled and zero counts never pass', () => {
  for (const out of [tap({tests: 0, pass: 0}), tap({tests: 2}), tap({pass: 0, todo: 1}),
    tap({pass: 0, cancelled: 1}), '# tests 1\n', tap() + '# tests 1\n'])
    assert.notEqual(checks.classify('tests/a.test.mjs', result(out)), 'PASS');
  assert.equal(checks.classify('tests/a.test.mjs', result(tap())), 'PASS');
  const incomplete = review([{status: 'PASS'}], [{reason: 'synthetic missing host'}]);
  assert.equal(checks.classify('security-review', result(JSON.stringify(incomplete), {status: 2})), 'UNPERFORMED');
});

function runnerCheck(api) {
  scratch(directory => {
    const paths = ['failed', 'passed', 'skipped'].map(name => relative(root, join(directory, `${name}.mjs`)));
    writeFileSync(join(root, paths[0]), "console.log('synthetic stdout'); console.error('synthetic stderr'); process.exitCode = 1;\n");
    writeFileSync(join(root, paths[1]), "if ('CI_TEST_PRIVATE_SENTINEL' in process.env) throw Error('environment inherited'); console.log('child after failure');\n");
    writeFileSync(join(root, paths[2]), `console.log(${JSON.stringify('ok 1 - source fixture # SKIP fixture dependency absent\n' + tap({pass: 0, skipped: 1}))});\n`);
    const output = join(directory, 'output');
    const previous = process.env.CI_TEST_PRIVATE_SENTINEL;
    process.env.CI_TEST_PRIVATE_SENTINEL = 'synthetic-only';
    try {assert.equal(api.run(paths, new Map([[paths[0], {date: '2026-10-12', reason: 'synthetic failure'}]]), output), 1);}
    finally {
      if (previous === undefined) delete process.env.CI_TEST_PRIVATE_SENTINEL;
      else process.env.CI_TEST_PRIVATE_SENTINEL = previous;
    }
    const rows = JSON.parse(readFileSync(join(output, 'results.json'), 'utf8'));
    assert.deepEqual(rows.map(row => row.status), ['FAIL', 'PASS', 'UNPERFORMED']);
    assert.deepEqual(rows.map(row => row.exit), [1, 0, 0]);
    assert.equal(rows[0].exception.reason, 'synthetic failure');
    assert.equal(rows[1].exception, null);
    for (const row of rows) assert.deepEqual(row.command, [process.execPath, '--test-reporter=tap', row.path]);
    const log = (path, stream) => readFileSync(join(output, `${path.replaceAll('/', '__')}.${stream}.log`), 'utf8');
    assert.equal(log(paths[0], 'stdout'), 'synthetic stdout\n');
    assert.equal(log(paths[0], 'stderr'), 'synthetic stderr\n');
    assert.equal(log(paths[1], 'stdout'), 'child after failure\n');
    assert.deepEqual(rows[2].reasons, ['fixture dependency absent']);
    const summary = readFileSync(join(output, 'summary.md'), 'utf8');
    assert.match(summary, /^PASS 1 \/ FAIL 1 \/ UNPERFORMED 1\n/);
    assert.ok(summary.includes('| UNPERFORMED | fixture dependency absent |'));
  });
}
test('raw runner captures both streams and continues after a failed command', () => runnerCheck(checks));

function incompleteRunCheck(api) {
  scratch(directory => {
    const child = join(directory, 'incomplete.mjs');
    writeFileSync(child, "console.error('UNPERFORMED: required fixture absent'); process.exitCode = 2;\n");
    const output = join(directory, 'output');
    assert.equal(api.run([relative(root, child)], empty, output), 0);
    const rows = JSON.parse(readFileSync(join(output, 'results.json'), 'utf8'));
    assert.deepEqual(rows.map(row => [row.status, row.exit, row.reasons]), [['UNPERFORMED', 2, ['required fixture absent']]]);
    assert.match(readFileSync(join(output, 'summary.md'), 'utf8'), /\| UNPERFORMED \| required fixture absent \|/);
  });
}
test('a named exit 2 succeeds as a job and retains its reason', () => incompleteRunCheck(checks));

test('reason extraction retains each source reason and ignores bare status totals', () => {
  assert.deepEqual(checks.unperformedReasons('tests/a.test.mjs', result('UNPERFORMED:\n# tests 1\n# todo 0\n')), []);
  assert.deepEqual(checks.unperformedReasons('tests/kira-memory-live-path.test.mjs', result('  UNPERFORMED 1. release: no built harness found\n')),
    ['release: no built harness found']);
  assert.deepEqual(checks.unperformedReasons('tests/aukora-owner-protocol.test.mjs', result('  SKIP fixture\n        NAMED CEILING: missing owner account\n')),
    ['missing owner account']);
  assert.deepEqual(checks.unperformedReasons('tests/a.test.mjs', result('UNPERFORMED release closure: no built harness found\n')), ['release closure: no built harness found']);
  const report = review([{status: 'SKIP', reason: 'namespaces unavailable'}], [{reason: 'owner custody unperformed'}]);
  assert.deepEqual(checks.unperformedReasons('security-review', result(JSON.stringify(report))), ['namespaces unavailable', 'owner custody unperformed']);
});

function homeEnvironmentCheck(api) {
  scratch(directory => {
    const child = join(directory, 'home.mjs');
    writeFileSync(child, `if (process.env.HOME !== ${JSON.stringify(directory)} || process.env.RUNNER_TEMP !== ${JSON.stringify(directory)}) process.exitCode = 1;`);
    const previous = {HOME: process.env.HOME, RUNNER_TEMP: process.env.RUNNER_TEMP};
    process.env.HOME = directory; process.env.RUNNER_TEMP = directory;
    try {assert.equal(api.run([relative(root, child)], empty, join(directory, 'output')), 0);}
    finally {for (const [key, value] of Object.entries(previous)) {if (value === undefined) delete process.env[key]; else process.env[key] = value;}}
  });
}
test('children retain HOME and RUNNER_TEMP; both removal mutants die', async () => {
  homeEnvironmentCheck(checks);
  for (const field of ['HOME', 'RUNNER_TEMP']) {
    const mutant = replace(source, `${field}: process.env.${field}, `, '');
    const mutated = await import(moduleURL(mutant));
    assert.throws(() => homeEnvironmentCheck(mutated));
  }
  console.log('CI home-environment mutations: 2/2 killed');
});

function workflowCheck(text) {
  assert.match(text, /permissions:\n  contents: read\n/);
  assert.match(text, /concurrency:\n  group: checks-\$\{\{ github.workflow \}\}-\$\{\{ github.ref \}\}\n  cancel-in-progress: true/);
  assert.equal((text.match(/continue-on-error:/g) ?? []).length, 1);
  assert.match(text, /continue-on-error: \$\{\{ matrix.continue_on_error \}\}/);
  assert.match(text, /fail-fast: false/);
  for (const use of text.matchAll(/uses: (\S+)/g)) assert.match(use[1], /^actions\/[a-z-]+@[a-f0-9]{40}$/);
  assert.equal((text.match(/persist-credentials: false/g) ?? []).length, 3);
  assert.equal((text.match(/node-version: '24\.11\.1'/g) ?? []).length, 3);
  assert.equal((text.match(/runs-on: ubuntu-latest/g) ?? []).length, 3);
  assert.equal((text.match(/if: always\(\)/g) ?? []).length, 5);
  assert.equal((text.match(/if-no-files-found: error/g) ?? []).length, 3);
  assert.match(text, /node --test scripts\/ci\/checks.test.mjs/);
  assert.match(text, /node scripts\/ci\/checks.mjs plan/);
  assert.match(text, /node scripts\/ci\/checks.mjs run "\$CHECK_GROUP" "\$CHECK_PARTITION"/);
  assert.match(text, /PASS 0 \/ FAIL 0 \/ UNPERFORMED 1/);
  assert.doesNotMatch(text, /\$\{\{\s*secrets\./);
  assert.match(text, /on:\n  push:\n/);
  const fresh = text.match(/\n  fresh_clone:\n([\s\S]*?)\n  policy:\n/)?.[1];
  assert.ok(fresh, 'fresh clone job required');
  assert.match(fresh, /name: fresh clone boots\n/);
  assert.match(fresh, /timeout-minutes: 15\n/);
  assert.match(fresh, /echo "archive=\$\(node -p '[^\n]+\.archiveSha256'\)" >> "\$GITHUB_OUTPUT"/);
  assert.match(fresh, /npm install --global "\$\(node -p '[^\n]+\.packageManager'\)"/);
  assert.match(fresh, /path: \.cache\/fresh-clone\n/);
  assert.match(fresh, /key: fresh-clone-\$\{\{ runner.os \}\}-\$\{\{ runner.arch \}\}-node-24\.11\.1-\$\{\{ steps.harness.outputs.archive \}\}-\$\{\{ hashFiles\(/);
  for (const path of ['upstream-dsh.json', 'patches/**', 'scripts/build-dsh.py',
    'scripts/artifact-record.mjs', 'scripts/artifacts-coverage.json', 'scripts/lib/artifact-integrity.mjs'])
    assert.ok(fresh.includes(`'${path}'`), `cache input required: ${path}`);
  assert.match(fresh, /run: \.\/scripts\/fresh-clone-check\.sh \. --cache \.cache\/fresh-clone > "\$RUNNER_TEMP\/fresh-clone.log" 2>&1\n/);
  assert.doesNotMatch(fresh, /--built\b|restore-keys:|continue-on-error:|\n    if:/);
  assert.match(fresh, /UNPERFORMED: setup did not reach the fresh clone check\./);
}
test('workflow requires pinned actions, exact Node, read-only permissions and retained failure output', () => workflowCheck(workflow));


function cliCheck(text, args, version) {
  const code = `Object.defineProperty(process, 'version', {value: ${JSON.stringify(version)}});
` +
    `process.argv = [process.execPath, ${JSON.stringify(helper)}, ...${JSON.stringify(args)}];
` +
    `await import(${JSON.stringify(moduleURL(text))});`;
  return spawnSync(process.execPath, ['--input-type=module', '--eval', code],
    {cwd: root, encoding: 'utf8', timeout: 5000, env: {PATH: process.env.PATH}});
}
test('CLI refuses wrong Node and invalid arguments before execution; both removal mutants die', () => {
  // Only this disposable harness injects process.version; the real CLI has no override.
  const plan = cliCheck(source, ['plan'], 'v24.11.1');
  assert.equal(plan.status, 0);
  assert.ok(JSON.parse(plan.stdout).include.length > 0);
  const bothWrong = cliCheck(source, ['invalid'], 'v24.11.0');
  assert.equal(bothWrong.status, 1);
  assert.equal(bothWrong.stderr.trim(), 'CI_NODE_24_11_1_REQUIRED');
  const cases = [
    ['plan', 'v24.11.0', 'CI_NODE_24_11_1_REQUIRED',
      "requireValue(process.version === 'v24.11.1', 'CI_NODE_24_11_1_REQUIRED');"],
    ['invalid', 'v24.11.1', 'CI_INVALID_ARGUMENTS',
      "requireValue(mode === 'run' && process.argv.length === 6, 'CI_INVALID_ARGUMENTS');"],
  ];
  for (const [mode, version, refusal, guard] of cases) {
    const check = text => {
      const outcome = cliCheck(text, mode === 'plan' ? ['plan'] : ['invalid', 'missing', 'required', '.unused'], version);
      assert.equal(outcome.status, 1);
      assert.equal(outcome.stderr.trim(), refusal);
    };
    check(source);
    assert.throws(() => check(replace(source, guard, '')));
  }
  console.log('CI CLI mutations: 2/2 killed');
});

test('empty source inventory refuses execution and its removal mutant dies', async () => {
  const directory = mkdtempSync(join(root, '.prime-check-ci-tests-'));
  try {
    mkdirSync(join(directory, 'tests'));
    mkdirSync(join(directory, 'packages/boundary-gate/checks'), {recursive: true});
    const check = api => assert.throws(() => api.inventory(), /CI_EMPTY_INVENTORY/);
    check(await import(moduleURL(source, directory)));
    const mutant = replace(source, "requireValue(tests.length > 0 && boundary.length > 0, 'CI_EMPTY_INVENTORY');", '');
    const mutated = await import(moduleURL(mutant, directory));
    assert.throws(() => check(mutated));
    console.log('CI inventory mutations: 1/1 killed');
  } finally {rmSync(directory, {recursive: true, force: true});}
});

async function descendantCheck(api) {
  const directory = mkdtempSync(join(root, '.prime-check-ci-tests-'));
  try {
    const marker = join(directory, 'descendant-marker');
    const grandchild = `import {writeFileSync} from 'node:fs'; setTimeout(() => writeFileSync(${JSON.stringify(marker)}, 'synthetic'), 200);`;
    const child = join(directory, 'child.mjs');
    writeFileSync(child, `import {spawn} from 'node:child_process'; spawn(process.execPath, ['--input-type=module', '-e', ${JSON.stringify(grandchild)}], {stdio: 'ignore'}).unref();`);
    assert.equal(api.run([relative(root, child)], empty, join(directory, 'output')), 0);
    await new Promise(resolve => setTimeout(resolve, 700));
    assert.equal(existsSync(marker), false, 'descendant must be terminated before it writes');
  } finally {rmSync(directory, {recursive: true, force: true});}
}
test('finished child process groups are terminated and the removal mutant dies', async () => {
  await descendantCheck(checks);
  const mutant = replace(source, "if (result.pid) {try {process.kill(-result.pid, 'SIGTERM');} catch (error) {if (error.code !== 'ESRCH') throw error;}}", '');
  const mutated = await import(moduleURL(mutant));
  await assert.rejects(() => descendantCheck(mutated), /descendant must be terminated/);
  console.log('CI process-group mutations: 1/1 killed');
});

test('removed protections are caught by the same assertions', async () => {
  let killed = 0;
  for (const [name, check, before, after] of protections) {
    const mutant = await import(moduleURL(replace(source, before, after)));
    assert.throws(() => check(mutant), undefined, `survived: ${name}`);
    killed++;
  }
  for (const [before, after] of [
    ['for (const row of rows) {', 'for (const row of rows.slice(0, 1)) {'],
    ["env: {PATH: process.env.PATH,", "env: {...process.env, PATH: process.env.PATH,"],
    ["reasons: unperformedReasons(row.path, captured, true)", "reasons: []"],
  ]) {
    const mutant = await import(moduleURL(replace(source, before, after)));
    assert.throws(() => runnerCheck(mutant), undefined, `survived: ${before}`);
    killed++;
  }
  for (const [before, after] of [
    ['contents: read', 'contents: write'],
    ['cancel-in-progress: true', 'cancel-in-progress: false'],
    ['matrix.continue_on_error', 'true'],
    ['fail-fast: false', 'fail-fast: true'],
    ['actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803', 'actions/checkout@main'],
    ['actions/cache@5a3ec84eff668545956fd18022155c47e93e2684', 'actions/cache@main'],
    ["node-version: '24.11.1'", "node-version: '24'"],
    ['persist-credentials: false', 'persist-credentials: true'],
    ['if: always()', 'if: success()'],
    ['if-no-files-found: error', 'if-no-files-found: ignore'],
    ['PASS 0 / FAIL 0 / UNPERFORMED 1', 'PASS 1 / FAIL 0 / UNPERFORMED 0'],
    ['  push:\n', '  workflow_dispatch:\n'],
    ['name: fresh clone boots', 'name: source checks'],
    ['timeout-minutes: 15', 'timeout-minutes: 210'],
    ['.packageManager', '.unverifiedPackageManager'],
    ['.archiveSha256', '.unverifiedArchiveSha256'],
    ['path: .cache/fresh-clone', 'path: .cache/unverified'],
    ['-${{ steps.harness.outputs.archive }}-', '-'],
    ["'patches/**'", "'ignored-patches/**'"],
    ["'upstream-dsh.json'", "'ignored-pin.json'"],
    ["'scripts/build-dsh.py'", "'ignored-build.py'"],
    ["'scripts/artifact-record.mjs'", "'ignored-record.mjs'"],
    ["'scripts/artifacts-coverage.json'", "'ignored-coverage.json'"],
    ["'scripts/lib/artifact-integrity.mjs'", "'ignored-integrity.mjs'"],
    ['path: .cache/fresh-clone\n', 'path: .cache/fresh-clone\n          restore-keys: unverified\n'],
    ['name: fresh clone boots\n', "name: fresh clone boots\n    if: github.event_name == 'pull_request'\n"],
    ['./scripts/fresh-clone-check.sh . --cache', './scripts/fresh-clone-check.sh . --built vendor/dsh --cache'],
    ['UNPERFORMED: setup did not reach the fresh clone check.', 'PASS: setup completed.'],
  ]) {
    assert.ok(workflow.includes(before));
    assert.throws(() => workflowCheck(workflow.replace(before, after)), undefined, `survived: ${before}`);
    killed++;
  }
  const hiddenReasons = replace(source, "${cell((row.reasons ?? []).join('; ')) || 'none'}", 'none');
  const hiddenReasonsModule = await import(moduleURL(hiddenReasons));
  assert.throws(() => incompleteRunCheck(hiddenReasonsModule));
  killed++;
  console.log(`CI mutations: ${killed}/${killed} killed`);
});
