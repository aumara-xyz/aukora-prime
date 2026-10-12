// SPDX-License-Identifier: AGPL-3.0-or-later
// Only exact dated exceptions enter tolerated jobs; named incomplete work never hides failure.
import {spawnSync} from 'node:child_process';
import {closeSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {classifyCheckResult, summarizeReview} from '../audit/security-review.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const requireValue = (ok, reason) => {if (!ok) throw Error(reason);};

export function inventory() {
  const files = (directory, suffix) => readdirSync(join(root, directory)).filter(name => name.endsWith(suffix))
    .sort().map(name => `${directory}/${name}`);
  const tests = files('tests', '.test.mjs');
  const boundary = files('packages/boundary-gate/checks', '.mjs');
  requireValue(tests.length > 0 && boundary.length > 0, 'CI_EMPTY_INVENTORY');
  return {'security-review': ['security-review', ...boundary], 'check-shell': ['scripts/check.sh'], tests};
}

// Each nonempty line is: repository/path | YYYY-MM-DD | reason.
export function parseKnownRed(text, groups) {
  const paths = new Set(Object.values(groups).flat()), exceptions = new Map();
  for (const line of text.split(/\r?\n/).filter(line => line.trim())) {
    const match = /^([^|\s]+) \| (\d{4}-\d{2}-\d{2}) \| ([^\s|][^|]*)$/.exec(line);
    requireValue(match, 'CI_INVALID_EXCEPTION');
    const [, path, date, reason] = match;
    requireValue(paths.has(path), 'CI_UNKNOWN_EXCEPTION_PATH');
    requireValue(!exceptions.has(path), 'CI_DUPLICATE_EXCEPTION');
    requireValue(!Number.isNaN(Date.parse(date)) && new Date(date).toISOString().slice(0, 10) === date,
      'CI_INVALID_EXCEPTION_DATE');
    exceptions.set(path, {date, reason: reason.trim()});
  }
  return exceptions;
}

export function plan(groups, exceptions) {
  const include = [];
  for (const [group, paths] of Object.entries(groups)) {
    for (const tolerated of [false, true]) {
      if (paths.some(path => exceptions.has(path) === tolerated)) include.push({group,
        partition: tolerated ? 'known-red' : 'required', continue_on_error: tolerated});
    }
  }
  return {include};
}

export function selectPaths(groups, exceptions, group, partition) {
  requireValue(plan(groups, exceptions).include.some(row => row.group === group && row.partition === partition),
    'CI_UNKNOWN_JOB');
  return groups[group].filter(path => exceptions.has(path) === (partition === 'known-red'));
}

export function command(path, output) {
  if (path === 'security-review') return ['./security-review', '--logs', join(output, 'security-review-children')];
  if (path === 'scripts/check.sh') return ['sh', 'scripts/check.sh'];
  return [process.execPath, '--test-reporter=tap', path];
}

export function unperformedReasons(path, result, reportedFallback = false) {
  const out = result.stdout ?? '', text = `${out}\n${result.stderr ?? ''}`;
  if (path === 'security-review') {
    try {
      const report = JSON.parse(out);
      return [...report.checks.filter(row => ['SKIP', 'UNPERFORMED'].includes(row.status)), ...(report.unperformed ?? [])]
        .map(row => row.reason).filter(reason => typeof reason === 'string' && reason.trim());
    } catch {return [];}
  }
  const reasons = path === 'scripts/check.sh' ? [...out.matchAll(/^(?:UNPERFORMED|SKIP)\s+(.+)$/gm)].map(match => match[1]) : [
    ...[...text.matchAll(/^[ \t]*(?:#[ \t]*)?UNPERFORMED(?:[ \t]*:[ \t]*|[ \t]+\d+\.[ \t]*|[ \t]+(?=[^:\n]+:[ \t]*\S))(\S.*)$/gm)].map(match => match[1]),
    ...[...text.matchAll(/^[ \t]*(?:ok|not ok)\b[^\n]*# (?:SKIP|TODO)[ \t]+(\S.*)$/gmi)].map(match => match[1]),
    ...[...text.matchAll(/^\s*----\s+NOT RUN:\s*(\S.*)$/gm)].map(match => match[1]),
    ...[...text.matchAll(/^[ \t]*NAMED CEILING:[ \t]*(\S.*)$/gm)].map(match => match[1]),
  ];
  if (reportedFallback && /^# (tests|pass|fail|cancelled|skipped|todo) /m.test(out)) {
    const unnamed = [...out.matchAll(/^[ \t]*(?:ok|not ok)[ \t]+\d+[ \t]*-[ \t]*(.*?)[ \t]+#[ \t]+(SKIP|TODO)[ \t]*$/gmi)]
      .map(match => `TAP check ${match[2].toUpperCase() === 'SKIP' ? 'skipped' : 'marked todo'} without a stated reason: ${match[1]}`);
    reasons.push(...unnamed);
    if (!reasons.length) {
      const reason = classifyCheckResult({...result, status: 0}, 'tap').reason;
      if (reason) reasons.push(reason);
    }
  }
  return [...new Set(reasons)];
}

export function classify(path, result) {
  const out = result.stdout ?? '', err = result.stderr ?? '';
  if (result.error || result.signal || ![0, 2].includes(result.status)) return 'FAIL';
  if (path === 'security-review') {
    try {
      const report = JSON.parse(out), expected = summarizeReview(report.checks, report.unperformed);
      requireValue(report.schema === 'aukora-security-review/v1' && report.checks.length > 0 &&
        JSON.stringify(report.summary) === JSON.stringify(expected) && result.status === expected.exit_code,
      'CI_INVALID_REVIEW_SUMMARY');
      const incomplete = [...report.checks.filter(row => ['SKIP', 'UNPERFORMED'].includes(row.status)), ...(report.unperformed ?? [])];
      requireValue(incomplete.every(row => typeof row.reason === 'string' && row.reason.trim()), 'CI_UNPERFORMED_REASON_REQUIRED');
      return expected.result;
    } catch {return 'FAIL';}
  }
  if (path === 'scripts/check.sh') {
    const totals = [...out.matchAll(/^TOTAL [^|]+\| (\d+)\/(\d+) passed \| (\d+) failed \| (\d+) skipped \((\d+) platform\) \| (\d+) unperformed(?: \| logs: .+)?$/gm)];
    if (totals.length !== 1) return 'FAIL';
    const [pass, total, fail, skipped, platform, unperformed] = totals[0].slice(1).map(Number);
    if (!total || pass + fail + skipped + unperformed !== total || platform > skipped || fail) return 'FAIL';
    const incomplete = skipped + unperformed > 0;
    if (result.status !== (incomplete ? 2 : 0)) return 'FAIL';
    if (incomplete && unperformedReasons(path, result).length === 0) return 'FAIL';
    return incomplete ? 'UNPERFORMED' : 'PASS';
  }
  if (/^\s*(?:FAIL\b|not ok\b)|^# (?:fail|cancelled) [1-9]\d*\s*$/m.test(out + '\n' + err)) return 'FAIL';
  if (result.status === 2 && unperformedReasons(path, result).length === 0) return 'FAIL';
  if (/^# (tests|pass|fail|cancelled|skipped|todo) /m.test(out)) {
    const status = classifyCheckResult({...result, status: 0, stdout: out, stderr: err}, 'tap').status;
    return status === 'SKIP' || (status === 'PASS' && result.status === 2) ? 'UNPERFORMED' : status;
  }
  if (path === 'tests/kira-injection.test.mjs') {
    const totals = [...out.matchAll(/^  (\d+)\/(\d+) arms passed, (\d+) failed; (\d+) unperformed checks; DSH source dispatch (RAN|UNPERFORMED); installed profile UNPERFORMED\.$/gm)];
    if (totals.length !== 1 || /^\s*FAIL\b/m.test(out + '\n' + err)) return 'FAIL';
    const [, pass, arms, fail, unperformed] = totals[0];
    if (+arms === 0 || +pass !== +arms || +fail !== 0 || +unperformed === 0) return 'FAIL';
    return 'UNPERFORMED';
  }
  if (result.status === 2) return 'UNPERFORMED';
  if (path === 'tests/kira-recall-output-seam.test.mjs' && /^  ----  NOT RUN:/m.test(out)) return 'UNPERFORMED';
  if (path === 'tests/aukora-owner-protocol.test.mjs' && /\(0 red, [1-9]\d* skipped with a named ceiling\)/.test(out)) return 'UNPERFORMED';
  return 'PASS';
}

export function summarize(rows) {
  const counts = Object.fromEntries(['PASS', 'FAIL', 'UNPERFORMED'].map(status => [status,
    rows.filter(row => row.status === status).length]));
  return {counts, exitCode: rows.length > 0 && rows.every(row => ['PASS', 'UNPERFORMED'].includes(row.status)) ? 0 : 1};
}

function save(output, rows) {
  const {counts} = summarize(rows);
  const lines = [`PASS ${counts.PASS} / FAIL ${counts.FAIL} / UNPERFORMED ${counts.UNPERFORMED}`, '',
    'Counts are command outcomes, not assertion totals. Source fixtures do not establish installed behavior.',
    'Raw command output retains child counts and limits. FAIL fails the job; named UNPERFORMED work is counted separately.', '',
    '| Command path | Outcome | Reason | Dated exception |', '| --- | --- | --- | --- |'];
  const cell = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('|', '&#124;').replaceAll('\n', ' ');
  for (const row of rows) lines.push(`| ${row.path} | ${row.status} | ${cell((row.reasons ?? []).join('; ')) || 'none'} | ${row.exception ?
    `${row.exception.date}: ${cell(row.exception.reason)}` : 'none'} |`);
  writeFileSync(join(output, 'results.json'), JSON.stringify(rows, null, 2) + '\n');
  writeFileSync(join(output, 'summary.md'), lines.join('\n') + '\n');
}

export function run(paths, exceptions, output) {
  mkdirSync(output, {recursive: true});
  const rows = paths.map(path => ({path, status: 'UNPERFORMED', reasons: ['command has not completed'], exception: exceptions.get(path) ?? null}));
  save(output, rows);
  for (const row of rows) {
    const name = row.path.replaceAll('/', '__');
    const stdout = join(output, `${name}.stdout.log`), stderr = join(output, `${name}.stderr.log`);
    const out = openSync(stdout, 'w'), err = openSync(stderr, 'w');
    const argv = command(row.path, output);
    const timeout = row.path === 'security-review' ? 1_500_000 : row.path === 'scripts/check.sh' ? 1_800_000 : 120_000;
    let result;
    try {
      result = spawnSync(argv[0], argv.slice(1), {cwd: root, stdio: ['ignore', out, err], timeout, detached: true,
        killSignal: 'SIGKILL', env: {PATH: process.env.PATH, HOME: process.env.HOME, RUNNER_TEMP: process.env.RUNNER_TEMP, TMPDIR: process.env.TMPDIR ?? '/tmp',
          LANG: 'C.UTF-8', PYTHONDONTWRITEBYTECODE: '1', GIT_NO_LAZY_FETCH: '1',
          GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', AUKORA_BUZZ_LIVE: '0'}});
    } finally {closeSync(out); closeSync(err);}
    // Terminate lingering group members, including shell watchdogs that clean up their own children.
    if (result.pid) {try {process.kill(-result.pid, 'SIGTERM');} catch (error) {if (error.code !== 'ESRCH') throw error;}}
    const captured = {...result, stdout: readFileSync(stdout, 'utf8'), stderr: readFileSync(stderr, 'utf8')};
    Object.assign(row, {command: argv, exit: result.status, signal: result.signal,
      error: result.error?.code ?? null, timeout_ms: timeout,
      status: classify(row.path, captured), reasons: unperformedReasons(row.path, captured, true)});
    save(output, rows);
    console.log(`${row.status} ${row.path}`);
  }
  const {counts, exitCode} = summarize(rows);
  console.log(`PASS ${counts.PASS} / FAIL ${counts.FAIL} / UNPERFORMED ${counts.UNPERFORMED}`);
  return exitCode;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireValue(process.version === 'v24.11.1', 'CI_NODE_24_11_1_REQUIRED');
    const groups = inventory(), exceptions = parseKnownRed(readFileSync(join(root, 'scripts/ci/known-red.txt'), 'utf8'), groups);
    const [mode, group, partition, output] = process.argv.slice(2);
    if (mode === 'plan' && process.argv.length === 3) console.log(JSON.stringify(plan(groups, exceptions)));
    else {
      requireValue(mode === 'run' && process.argv.length === 6, 'CI_INVALID_ARGUMENTS');
      process.exitCode = run(selectPaths(groups, exceptions, group, partition), exceptions, resolve(output));
    }
  } catch (error) {
    console.error(/^CI_[A-Z0-9_]+$/.test(error.message) ? error.message : 'CI_EXECUTION_INCOMPLETE');
    process.exitCode = 1;
  }
}
