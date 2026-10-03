// SPDX-License-Identifier: AGPL-3.0-or-later
// CI accepts one reviewed source profile, never exit 2 by itself.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {closeSync, copyFileSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {CASES, UNPERFORMED} from '../../packages/ops/fast-verify/manifest.mjs';

export const PROFILE = Object.freeze({
  engine: 'da653d511ebf30c821e07d4bf63c0731ce5f046a2eacaf694f66710fc3006535',
  manifest: 'd6c5a126c8aa527b86c2c9318410bdfa0bf6e800f26ba9385e07e6751e3ab678',
  externalId: 'memory-memory',
  externalTitle: 'PostgreSQL acceptance on an explicitly supplied disposable database',
  externalReason: 'UNPERFORMED: no disposable PostgreSQL runtime supplied'
});
const requireValue = (ok, reason) => {if (!ok) throw new Error(reason);};
const equal = (actual, expected, reason) => {
  try {assert.deepEqual(actual, expected);} catch {throw new Error(reason);}
};
const hash = path => createHash('sha256').update(readFileSync(realpathSync(path))).digest('hex');
const nonnegative = value => Number.isSafeInteger(value) && value >= 0;

export function validateSummary(s, invocation) {
  requireValue(invocation.exitCode === 2, 'EXPECTED_EXIT_2_WITH_COMPLETE_SOURCE_EVIDENCE');
  requireValue(s?.schema === 'prime-fast-verify/v1' && s.status === 'UNPERFORMED' &&
    s.functional_status === 'PASS' && s.exit_code === 2 && !s.reason, 'INVALID_OVERALL_RESULT');
  requireValue(s.qualification === 'UNPERFORMED' && s.g1 === 'PENDING', 'QUALIFICATION_MUST_REMAIN_UNPERFORMED');
  requireValue(/^[a-f0-9]{64}$/.test(invocation.nodeSha256) && /^[a-f0-9]{64}$/.test(invocation.pythonSha256),
    'TOOL_BYTE_OBSERVATIONS_REQUIRED');
  requireValue(s.node?.version === 'v24.11.1' && s.node.observed_sha256 === invocation.nodeSha256,
    'NODE_VERSION_OR_BYTES_MISMATCH');
  requireValue(s.python?.path === '/usr/bin/python3' && s.python.major === 3 && Number.isSafeInteger(s.python.minor) && s.python.minor >= 9 &&
    s.python.observed_sha256 === invocation.pythonSha256, 'PYTHON_PREREQUISITE_MISMATCH');
  requireValue(s.evaluator?.engine_sha256 === PROFILE.engine && s.evaluator.manifest_sha256 === PROFILE.manifest,
    'REVIEWED_EVALUATOR_MISMATCH');
  requireValue(/^[a-f0-9]{40}$/.test(invocation.commit) && s.source_invocation_commit === invocation.commit &&
    s.source_invocation?.status === 'MATCHED_BEFORE_AFTER' &&
    s.source_invocation.before?.commit === invocation.commit && s.source_invocation.after?.commit === invocation.commit,
    'INVOCATION_COMMIT_MISMATCH');
  requireValue(nonnegative(s.duration_ms) && s.duration_ms > 0, 'MISSING_ACTUAL_DURATION');
  equal(s.unperformed, UNPERFORMED, 'QUALIFICATION_EXCLUSIONS_CHANGED');
  requireValue(CASES.length === 66 && s.configured_case_count === 66 && s.case_count === 66 &&
    Array.isArray(s.cases) && s.cases.length === 66, 'REQUIRED_66_JOB_INVENTORY_MISSING');
  equal(s.counts, {pass: 65, fail: 0, unperformed: 1}, 'EXPECTED_65_PASS_0_FAIL_1_EXTERNAL_UNPERFORMED');
  equal(s.cases.map(row => row.id), CASES.map(row => row.id), 'JOB_INVENTORY_MISMATCH');
  equal(CASES.flatMap(row => (row.externalSkips ?? []).map(skip => ({id: row.id, ...skip}))),
    [{id: PROFILE.externalId, title: PROFILE.externalTitle, reason: PROFILE.externalReason}], 'EXTERNAL_ALLOWLIST_CHANGED');
  for (let index = 0; index < CASES.length; index++) {
    const spec = CASES[index], row = s.cases[index], external = spec.id === PROFILE.externalId ? 1 : 0;
    const check = (ok, reason) => requireValue(ok, `${spec.id}: ${reason}`);
    check(row.status === (external ? 'UNPERFORMED' : 'PASS') && row.functional_status === 'PASS', 'FAILED_OR_INCOMPLETE');
    check(row.reason === (external ? 'DECLARED_EXTERNAL_TESTS_UNPERFORMED' : 'ASSERTIONS_COMPLETED'), 'UNEXPECTED_REASON');
    check(row.completion === 'DIRECT_CHILD_CLOSED' && row.child_exit_code === 0 &&
      nonnegative(row.duration_ms) && row.entry_sha256 === spec.expectedSha256, 'EXECUTION_OR_SOURCE_PIN_INCOMPLETE');
    for (const key of ['required_skipped_count', 'unknown_title_count', 'unknown_failed_count', 'todo_count', 'cancelled_count']) {
      check(row[key] === undefined || row[key] === 0, 'UNEXPECTED_INCOMPLETE_ASSERTIONS');
    }
    check(row.skipped_count === undefined || row.skipped_count === external, 'UNEXPECTED_SKIP');
    check(row.external_unperformed_count === undefined || row.external_unperformed_count === external, 'UNEXPECTED_EXTERNAL_WORK');
    if (!external && row.external_skips !== undefined) equal(row.external_skips, [], `${spec.id}: UNEXPECTED_EXTERNAL_SKIP`);
    if (row.failed_titles !== undefined) equal(row.failed_titles, [], `${spec.id}: FAILED_TITLES`);
    if (spec.protocol !== 'assert-script') {
      equal(row.failed_titles, [], `${spec.id}: FAILED_TITLES`);
      check(row.unknown_failed_count === 0, 'UNKNOWN_FAILURES');
    }
    if (spec.protocol === 'tap' || spec.protocol === 'pass-lines') {
      const required = (spec.requiredTitles ?? spec.requiredLabels).length;
      check(required > 0 && row.test_count === required && row.required_test_count === required &&
        row.observed_test_count === required + external && row.unknown_title_count === 0, 'ASSERTION_COUNTS_MISMATCH');
      if (spec.protocol === 'tap') {
        check(row.expected_test_count === required + external && row.skipped_count === external &&
          row.required_skipped_count === 0 && row.external_unperformed_count === external, 'UNEXPECTED_SKIP');
        equal(row.tap_summary, {tests: required + external, pass: required, fail: 0, cancelled: 0,
          skipped: external, todo: 0}, `${spec.id}: TAP_COUNTS_MISMATCH`);
        equal(row.external_skips, external ? [{title: PROFILE.externalTitle, reason: PROFILE.externalReason,
          reason_matches: true, status: 'UNPERFORMED', count: 1}] : [], `${spec.id}: EXTERNAL_SKIP_MISMATCH`);
      }
    }
    if (spec.protocol === 'assert-json') {
      equal(row.counter, {key: spec.counter.key, expected: spec.counter.value, observed: spec.counter.value},
        `${spec.id}: JSON_COUNTER_MISMATCH`);
      check(spec.counter.value > 0 && row.test_count === spec.counter.value &&
        row.observed_test_count === spec.counter.value, 'ZERO_OR_MISSING_ASSERTIONS');
    }
    if (spec.hookController) {
      check(row.hook_controller?.preflight === 'PASS' && row.hook_controller.completion === 'DIRECT_CHILD_CLOSED' &&
        row.hook_controller.exit_code === 0 && row.hook_controller.path === spec.hookController.path &&
        row.hook_controller.expected_sha256 === spec.hookController.sha256 &&
        row.hook_controller.observed_sha256 === spec.hookController.sha256, 'HOOK_PREFLIGHT_INCOMPLETE');
    }
  }
  return {functional_status: 'PASS', overall_status: 'UNPERFORMED', qualification: 'UNPERFORMED',
    g1: 'PENDING', counts: s.counts};
}

function run(outputDirectory) {
  const root = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
  const output = resolve(outputDirectory);
  mkdirSync(output, {mode: 0o700});
  writeFileSync(join(output, 'stdout.log'), '', {flag: 'wx', mode: 0o600});
  writeFileSync(join(output, 'stderr.log'), '', {flag: 'wx', mode: 0o600});
  const invocation = {schema: 'prime-ci-invocation/v1', command: ['node', 'packages/ops/verify-fast.mjs',
    '--root', root, '--evidence-dir', 'NEW_PRIVATE_EXTERNAL_DIRECTORY', '--json', 'true'],
    expected_commit: process.env.PRIME_CI_EXPECTED_COMMIT ?? null, node_version: process.version,
    platform: process.platform, architecture: process.arch, umask: process.umask().toString(8).padStart(4, '0'),
    qualification: 'UNPERFORMED', g1: 'PENDING'};
  let summary, result = {ci_status: 'FAIL', functional_status: 'INCOMPLETE', overall_status: 'UNPERFORMED', qualification: 'UNPERFORMED', g1: 'PENDING'};
  let failed = true;
  const textCommand = (command, args) => {
    const p = spawnSync(command, args, {cwd: root, encoding: 'utf8'});
    requireValue(p.status === 0 && !p.error, 'INVOCATION_PREREQUISITE_FAILED');
    return p.stdout.trim();
  };
  try {
    invocation.commit = textCommand('git', ['rev-parse', 'HEAD']);
    invocation.git_version = textCommand('git', ['--version']);
    requireValue(invocation.commit === invocation.expected_commit, 'EVENT_CHECKOUT_COMMIT_MISMATCH');
    requireValue(textCommand('git', ['status', '--porcelain']) === '', 'CHECKOUT_MUST_BE_CLEAN');
    requireValue(process.version === 'v24.11.1' && invocation.umask === '0022', 'PINNED_NODE_AND_UMASK_REQUIRED');
    invocation.nodeSha256 = hash(process.execPath);
    invocation.pythonSha256 = hash('/usr/bin/python3');
    invocation.python_version = textCommand('/usr/bin/python3', ['-c',
      'import sys, json, hashlib, pathlib, tarfile, tempfile; assert sys.version_info[:2] >= (3,9); print(sys.version.split()[0])']);
    equal(hash(join(root, 'packages/ops/fast-verify/runner.mjs')), PROFILE.engine, 'REVIEWED_ENGINE_BYTES_REQUIRED');
    equal(hash(join(root, 'packages/ops/fast-verify/manifest.mjs')), PROFILE.manifest, 'REVIEWED_MANIFEST_BYTES_REQUIRED');
    const parent = mkdtempSync(join(realpathSync(tmpdir()), 'prime-ci-'));
    const evidence = join(parent, 'evidence');
    const out = openSync(join(output, 'stdout.log'), 'w', 0o600);
    const err = openSync(join(output, 'stderr.log'), 'w', 0o600);
    let p;
    try {
      p = spawnSync(process.execPath, [join(root, 'packages/ops/verify-fast.mjs'), '--root', root,
        '--evidence-dir', evidence, '--json', 'true'], {cwd: root, timeout: 780_000, stdio: ['ignore', out, err]});
    } finally {closeSync(out); closeSync(err);}
    invocation.exitCode = p.status;
    invocation.signal = p.signal;
    invocation.process_error = p.error?.code ?? null;
    const raw = readFileSync(join(output, 'stdout.log'), 'utf8');
    try {summary = JSON.parse(raw);} catch {throw new Error('MISSING_OR_INVALID_MACHINE_SUMMARY');}
    writeFileSync(join(output, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
    copyFileSync(join(evidence, 'summary.json'), join(output, 'engine-summary.json'));
    equal(JSON.parse(readFileSync(join(output, 'engine-summary.json'), 'utf8')), summary, 'STDOUT_EVIDENCE_SUMMARY_MISMATCH');
    requireValue(!p.error && !p.signal, 'PROFILE_EXECUTION_INCOMPLETE');
    requireValue(textCommand('git', ['rev-parse', 'HEAD']) === invocation.commit &&
      textCommand('git', ['status', '--porcelain']) === '', 'CHECKOUT_CHANGED_DURING_RUN');
    result = {ci_status: 'PASS', ...validateSummary(summary, invocation)};
    failed = false;
  } catch (error) {
    result.error = error.message;
    if (summary?.status === 'FAIL') result.overall_status = 'FAIL';
    if (summary?.functional_status === 'FAIL') result.functional_status = 'FAIL';
  }
  writeFileSync(join(output, 'invocation.json'), JSON.stringify(invocation, null, 2) + '\n');
  writeFileSync(join(output, 'ci-result.json'), JSON.stringify(result, null, 2) + '\n');
  const lines = [failed ? '## FAILED OR INCOMPLETE — source checks' : '## Functional source checks PASS — qualification UNPERFORMED',
    '', `**Overall source result: ${result.overall_status}. Runtime qualification: UNPERFORMED. G1: PENDING.**`, '',
    failed ? `CI refused the result: \`${result.error}\`.` : '65 jobs PASS, 0 FAIL, 1 declared external PostgreSQL arm UNPERFORMED; verifier exit 2.',
    '', `Tested commit: \`${invocation.commit ?? 'UNOBSERVED'}\`.`,
    `Node: \`${invocation.node_version}\`; /usr/bin/python3: \`${invocation.python_version ?? 'UNPERFORMED'}\`; umask: \`${invocation.umask}\`.`, '',
    'Raw verifier stdout/stderr, the actual machine summary and tool hashes are retained in the run artifact.',
    'The existing evaluator withholds child stdout/stderr; CI does not claim those were retained.',
    'IPC bind refusal, missing prerequisites, failed assertions, altered pins and unexpected skips fail this check.',
    'This run establishes source fixture coverage only; owner enrollment, live PostgreSQL, cross-UID/guest containment and other declared qualifications remain unperformed.'];
  if (Array.isArray(summary?.cases)) {
    lines.push('', '| Job | Observed status | Reason |', '| --- | --- | --- |');
    for (const row of summary.cases) {
      if (CASES.some(c => c.id === row.id)) lines.push(`| ${row.id} | ${row.status} | ${row.reason ?? 'UNPERFORMED'} |`);
    }
  }
  writeFileSync(join(output, 'ci-summary.md'), lines.join('\n') + '\n');
  console.log(lines.slice(0, 5).join('\n'));
  return failed ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  requireValue(process.argv.length === 3, 'ONE_NEW_ARTIFACT_DIRECTORY_REQUIRED');
  process.exitCode = run(process.argv[2]);
}
