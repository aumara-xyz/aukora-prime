// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic validator fixtures only: these do not execute or qualify any source job.
import assert from 'node:assert/strict';
import test from 'node:test';
import {CASES, UNPERFORMED} from '../../packages/ops/fast-verify/manifest.mjs';
import {PROFILE, validateSummary} from './source-profile.mjs';

function fixture() {
  const invocation = {exitCode: 2, commit: 'a'.repeat(40),
    nodeSha256: '1'.repeat(64), pythonSha256: '2'.repeat(64)};
  const cases = CASES.map(spec => {
    const external = spec.id === PROFILE.externalId ? 1 : 0;
    const row = {id: spec.id, status: external ? 'UNPERFORMED' : 'PASS', functional_status: 'PASS',
      reason: external ? 'DECLARED_EXTERNAL_TESTS_UNPERFORMED' : 'ASSERTIONS_COMPLETED',
      completion: 'DIRECT_CHILD_CLOSED', child_exit_code: 0, duration_ms: 1,
      entry_sha256: spec.expectedSha256};
    if (spec.protocol !== 'assert-script') Object.assign(row, {failed_titles: [], unknown_failed_count: 0});
    if (spec.protocol === 'tap' || spec.protocol === 'pass-lines') {
      const required = (spec.requiredTitles ?? spec.requiredLabels).length;
      Object.assign(row, {test_count: required, required_test_count: required,
        observed_test_count: required + external, unknown_title_count: 0});
      if (spec.protocol === 'tap') Object.assign(row, {expected_test_count: required + external,
        skipped_count: external, required_skipped_count: 0, external_unperformed_count: external,
        tap_summary: {tests: required + external, pass: required, fail: 0, cancelled: 0, skipped: external, todo: 0},
        external_skips: external ? [{title: PROFILE.externalTitle, reason: PROFILE.externalReason,
          reason_matches: true, status: 'UNPERFORMED', count: 1}] : []});
    }
    if (spec.protocol === 'assert-json') Object.assign(row, {test_count: spec.counter.value,
      observed_test_count: spec.counter.value,
      counter: {key: spec.counter.key, expected: spec.counter.value, observed: spec.counter.value}});
    if (spec.hookController) row.hook_controller = {preflight: 'PASS', completion: 'DIRECT_CHILD_CLOSED',
      exit_code: 0, path: spec.hookController.path, expected_sha256: spec.hookController.sha256,
      observed_sha256: spec.hookController.sha256};
    return row;
  });
  const summary = {schema: 'prime-fast-verify/v1', status: 'UNPERFORMED', functional_status: 'PASS', exit_code: 2,
    qualification: 'UNPERFORMED', g1: 'PENDING', duration_ms: 66,
    configured_case_count: 66, case_count: 66, cases, counts: {pass: 65, fail: 0, unperformed: 1},
    node: {version: 'v24.11.1', observed_sha256: invocation.nodeSha256},
    python: {path: '/usr/bin/python3', major: 3, minor: 9, observed_sha256: invocation.pythonSha256},
    evaluator: {engine_sha256: PROFILE.engine, manifest_sha256: PROFILE.manifest},
    source_invocation_commit: invocation.commit, source_invocation: {status: 'MATCHED_BEFORE_AFTER',
      before: {commit: invocation.commit}, after: {commit: invocation.commit}},
    unperformed: structuredClone(UNPERFORMED)};
  return {summary, invocation};
}

const caseFor = (summary, protocol) => summary.cases.find((_, index) => CASES[index].protocol === protocol);
const hookFor = summary => summary.cases.find((_, index) => CASES[index].hookController);
const externalFor = summary => summary.cases.find(row => row.id === PROFILE.externalId);

test('accepts only the complete 65 PASS / 0 FAIL / 1 declared PostgreSQL UNPERFORMED profile', () => {
  const {summary, invocation} = fixture();
  assert.equal(summary.cases.length, 66);
  assert.deepEqual(validateSummary(summary, invocation), {functional_status: 'PASS', overall_status: 'UNPERFORMED',
    qualification: 'UNPERFORMED', g1: 'PENDING', counts: {pass: 65, fail: 0, unperformed: 1}});
});

const refusals = [
  ['exit 0 cannot substitute for reviewed exit 2', (_, i) => {i.exitCode = 0;}, /EXPECTED_EXIT_2/],
  ['exit 1 remains a failure', (_, i) => {i.exitCode = 1;}, /EXPECTED_EXIT_2/],
  ['missing process exit is incomplete', (_, i) => {i.exitCode = null;}, /EXPECTED_EXIT_2/],
  ['reported code failures are refused even with process exit 2', s => {s.functional_status = 'FAIL';}, /INVALID_OVERALL_RESULT/],
  ['all green overall claim is refused', s => {s.status = 'PASS';}, /INVALID_OVERALL_RESULT/],
  ['unexpected engine prerequisite reason is refused', s => {s.reason = 'ENGINE_PREREQUISITE_UNAVAILABLE';}, /INVALID_OVERALL_RESULT/],
  ['runtime qualification cannot become PASS', s => {s.qualification = 'PASS';}, /QUALIFICATION_MUST_REMAIN_UNPERFORMED/],
  ['G1 cannot become PASS', s => {s.g1 = 'PASS';}, /QUALIFICATION_MUST_REMAIN_UNPERFORMED/],
  ['zero jobs cannot pass', s => {s.cases = []; s.case_count = 0;}, /REQUIRED_66_JOB_INVENTORY_MISSING/],
  ['one missing job cannot pass', s => {s.cases.pop();}, /REQUIRED_66_JOB_INVENTORY_MISSING/],
  ['missing configured count cannot pass', s => {delete s.configured_case_count;}, /REQUIRED_66_JOB_INVENTORY_MISSING/],
  ['wrong actual case count cannot pass', s => {s.case_count = 65;}, /REQUIRED_66_JOB_INVENTORY_MISSING/],
  ['reported failed jobs cannot pass', s => {s.counts = {pass: 64, fail: 1, unperformed: 1};}, /EXPECTED_65_PASS_0_FAIL_1/],
  ['an additional unperformed job cannot pass', s => {s.counts = {pass: 64, fail: 0, unperformed: 2};}, /EXPECTED_65_PASS_0_FAIL_1/],
  ['replacement job cannot pass', s => {s.cases[0].id = 'unexpected-job';}, /JOB_INVENTORY_MISMATCH/],
  ['duplicate job cannot pass', s => {s.cases[1].id = s.cases[0].id;}, /JOB_INVENTORY_MISMATCH/],
  ['failed case cannot hide behind overall counts', s => {s.cases[0].status = 'FAIL';}, /FAILED_OR_INCOMPLETE/],
  ['environment bind block stays incomplete', s => {s.cases[0].functional_status = 'UNPERFORMED'; s.cases[0].reason = 'IPC_BIND_UNAVAILABLE';}, /FAILED_OR_INCOMPLETE/],
  ['missing child completion cannot pass', s => {delete s.cases[0].completion;}, /EXECUTION_OR_SOURCE_PIN_INCOMPLETE/],
  ['missing child exit cannot pass', s => {delete s.cases[0].child_exit_code;}, /EXECUTION_OR_SOURCE_PIN_INCOMPLETE/],
  ['nonzero child exit cannot pass', s => {s.cases[0].child_exit_code = 1;}, /EXECUTION_OR_SOURCE_PIN_INCOMPLETE/],
  ['failed required title cannot pass', s => {caseFor(s, 'tap').failed_titles = ['synthetic required failure'];}, /FAILED_TITLES/],
  ['unknown failure cannot pass', s => {caseFor(s, 'pass-lines').unknown_failed_count = 1;}, /UNEXPECTED_INCOMPLETE_ASSERTIONS/],
  ['missing required count cannot pass', s => {delete caseFor(s, 'tap').required_test_count;}, /ASSERTION_COUNTS_MISMATCH/],
  ['zero TAP assertions cannot pass', s => {caseFor(s, 'tap').test_count = 0;}, /ASSERTION_COUNTS_MISMATCH/],
  ['missing pass line assertion cannot pass', s => {caseFor(s, 'pass-lines').observed_test_count--;}, /ASSERTION_COUNTS_MISMATCH/],
  ['unexpected title cannot pass', s => {caseFor(s, 'tap').unknown_title_count = 1;}, /UNEXPECTED_INCOMPLETE_ASSERTIONS/],
  ['required skip cannot pass', s => {caseFor(s, 'tap').required_skipped_count = 1;}, /UNEXPECTED_INCOMPLETE_ASSERTIONS/],
  ['undeclared skip cannot pass', s => {caseFor(s, 'tap').skipped_count = 1;}, /UNEXPECTED_SKIP/],
  ['optional pass line skip cannot pass', s => {caseFor(s, 'pass-lines').skipped_count = 1;}, /UNEXPECTED_SKIP/],
  ['assert script TODO cannot pass', s => {caseFor(s, 'assert-script').todo_count = 1;}, /UNEXPECTED_INCOMPLETE_ASSERTIONS/],
  ['TODO cannot pass', s => {caseFor(s, 'tap').tap_summary.todo = 1;}, /TAP_COUNTS_MISMATCH/],
  ['cancelled assertion cannot pass', s => {caseFor(s, 'tap').tap_summary.cancelled = 1;}, /TAP_COUNTS_MISMATCH/],
  ['TAP count disagreement cannot pass', s => {caseFor(s, 'tap').tap_summary.tests++;}, /TAP_COUNTS_MISMATCH/],
  ['external PostgreSQL qualification stays UNPERFORMED', s => {externalFor(s).status = 'PASS';}, /FAILED_OR_INCOMPLETE/],
  ['wrong external skip reason cannot pass', s => {externalFor(s).external_skips[0].reason = 'UNPERFORMED: unrelated dependency';}, /EXTERNAL_SKIP_MISMATCH/],
  ['unmatched external skip cannot pass', s => {externalFor(s).external_skips[0].reason_matches = false;}, /EXTERNAL_SKIP_MISMATCH/],
  ['missing external skip evidence cannot pass', s => {externalFor(s).external_skips = [];}, /EXTERNAL_SKIP_MISMATCH/],
  ['additional external skip cannot pass', s => {externalFor(s).external_skips.push({...externalFor(s).external_skips[0]});}, /EXTERNAL_SKIP_MISMATCH/],
  ['zero JSON assertions cannot pass', s => {caseFor(s, 'assert-json').test_count = 0;}, /ZERO_OR_MISSING_ASSERTIONS/],
  ['missing JSON counter cannot pass', s => {delete caseFor(s, 'assert-json').counter;}, /JSON_COUNTER_MISMATCH/],
  ['wrong JSON observed counter cannot pass', s => {caseFor(s, 'assert-json').counter.observed--;}, /JSON_COUNTER_MISMATCH/],
  ['changed entry source pin cannot pass', s => {s.cases[0].entry_sha256 = '3'.repeat(64);}, /EXECUTION_OR_SOURCE_PIN_INCOMPLETE/],
  ['changed engine pin cannot pass', s => {s.evaluator.engine_sha256 = '3'.repeat(64);}, /REVIEWED_EVALUATOR_MISMATCH/],
  ['changed manifest pin cannot pass', s => {s.evaluator.manifest_sha256 = '3'.repeat(64);}, /REVIEWED_EVALUATOR_MISMATCH/],
  ['missing evaluator pins cannot pass', s => {delete s.evaluator;}, /REVIEWED_EVALUATOR_MISMATCH/],
  ['wrong invocation commit cannot pass', (_, i) => {i.commit = 'b'.repeat(40);}, /INVOCATION_COMMIT_MISMATCH/],
  ['non-SHA invocation commit cannot pass', (_, i) => {i.commit = 'main';}, /INVOCATION_COMMIT_MISMATCH/],
  ['changed after commit cannot pass', s => {s.source_invocation.after.commit = 'b'.repeat(40);}, /INVOCATION_COMMIT_MISMATCH/],
  ['missing before commit cannot pass', s => {delete s.source_invocation.before;}, /INVOCATION_COMMIT_MISMATCH/],
  ['unobserved commit cannot pass', s => {s.source_invocation.status = 'UNOBSERVED';}, /INVOCATION_COMMIT_MISMATCH/],
  ['wrong Node version cannot pass', s => {s.node.version = 'v24.11.0';}, /NODE_VERSION_OR_BYTES_MISMATCH/],
  ['wrong Node bytes cannot pass', s => {s.node.observed_sha256 = '3'.repeat(64);}, /NODE_VERSION_OR_BYTES_MISMATCH/],
  ['missing Node byte observation cannot pass', (_, i) => {delete i.nodeSha256;}, /TOOL_BYTE_OBSERVATIONS_REQUIRED/],
  ['missing Python byte observation cannot pass', (_, i) => {delete i.pythonSha256;}, /TOOL_BYTE_OBSERVATIONS_REQUIRED/],
  ['missing Node evidence cannot pass', s => {delete s.node;}, /NODE_VERSION_OR_BYTES_MISMATCH/],
  ['wrong Python path cannot pass', s => {s.python.path = '/synthetic/python3';}, /PYTHON_PREREQUISITE_MISMATCH/],
  ['old Python cannot pass', s => {s.python.minor = 8;}, /PYTHON_PREREQUISITE_MISMATCH/],
  ['wrong Python major cannot pass', s => {s.python.major = 2;}, /PYTHON_PREREQUISITE_MISMATCH/],
  ['wrong Python bytes cannot pass', s => {s.python.observed_sha256 = '3'.repeat(64);}, /PYTHON_PREREQUISITE_MISMATCH/],
  ['missing Python prerequisite cannot pass', s => {delete s.python;}, /PYTHON_PREREQUISITE_MISMATCH/],
  ['missing hook controller cannot pass', s => {delete hookFor(s).hook_controller;}, /HOOK_PREFLIGHT_INCOMPLETE/],
  ['missing hook completion cannot pass', s => {delete hookFor(s).hook_controller.completion;}, /HOOK_PREFLIGHT_INCOMPLETE/],
  ['failed hook preflight cannot pass', s => {hookFor(s).hook_controller.preflight = 'FAIL';}, /HOOK_PREFLIGHT_INCOMPLETE/],
  ['failed hook process cannot pass', s => {hookFor(s).hook_controller.exit_code = 1;}, /HOOK_PREFLIGHT_INCOMPLETE/],
  ['changed hook pin cannot pass', s => {hookFor(s).hook_controller.observed_sha256 = '3'.repeat(64);}, /HOOK_PREFLIGHT_INCOMPLETE/],
  ['changed qualification exclusions cannot pass', s => {s.unperformed.pop();}, /QUALIFICATION_EXCLUSIONS_CHANGED/],
  ['zero actual duration cannot pass', s => {s.duration_ms = 0;}, /MISSING_ACTUAL_DURATION/],
];

for (const [name, mutate, reason] of refusals) test(name, () => {
  const {summary, invocation} = fixture();
  mutate(summary, invocation);
  assert.throws(() => validateSummary(summary, invocation), reason);
});

test('missing machine summary cannot pass', () => {
  assert.throws(() => validateSummary(undefined, fixture().invocation), /INVALID_OVERALL_RESULT/);
});
