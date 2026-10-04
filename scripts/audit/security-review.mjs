#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync, mkdirSync, writeFileSync, lstatSync, realpathSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const nodeCheck = (id, args, limit, report = 'exit') => Object.freeze({ id,
  executable: 'node', args: Object.freeze(args), limit, report })
const tapCheck = (id, path, limit, options = []) => nodeCheck(id,
  [...options, '--test', '--test-reporter=tap', path], limit, 'tap')

// The two historical fixture loaders can read missing modules from older Git
// objects. Candidate checks require the current physical closure first; this
// reads only selected HEAD tree metadata, never missing blobs or other repos.
const auraRoots = Object.freeze(['plugins/aukora-nostr', 'plugins/aukora-aumlok',
  'packages/contracts/src', 'scripts/aura', 'packages/boundary-gate/host/aura'])
const auraMandatory = Object.freeze(['package.json', 'packages/contracts/package.json',
  'packages/boundary-gate/package.json', 'packages/contracts/src/json.mjs',
  'plugins/aukora-nostr/lib/records.mjs', 'plugins/aukora-nostr/lib/event.mjs', 'plugins/aukora-nostr/lib/identity.mjs',
  'scripts/aura/collect-gate.mjs', 'scripts/aura/gate-snapshot.mjs', 'scripts/aura/verify-collected.mjs',
  'packages/boundary-gate/host/aura/context.mjs', 'packages/boundary-gate/host/aura/entry.mjs',
  'packages/boundary-gate/host/aura/records-provider.mjs'])
const SOURCE_PROFILES = Object.freeze({
  aura: Object.freeze({ roots: auraRoots, mandatory: auraMandatory }),
  kira: Object.freeze({ roots: Object.freeze([...auraRoots, 'plugins/aukora-kira']),
    mandatory: Object.freeze([...auraMandatory, 'plugins/aukora-kira/lib/index.js',
      'plugins/aukora-kira/lib/tracked-memory.mjs', 'plugins/aukora-kira/lib/aura-recall.mjs',
      'plugins/aukora-kira/lib/aura-association.mjs']) }),
})
export function verifyPhysicalSource(profile) {
  if (!Object.hasOwn(SOURCE_PROFILES, profile)) throw Error('review:source-profile-invalid')
  const { roots, mandatory } = SOURCE_PROFILES[profile]
  const r = spawnSync('git', ['ls-tree', '-r', '-z', '--full-tree', 'HEAD', '--', ...roots, ...mandatory],
    { cwd: root, encoding: 'utf8', env: { ...process.env, GIT_NO_LAZY_FETCH: '1' }, timeout: 10000, maxBuffer: 8 * 1024 * 1024 })
  if (r.status !== 0 || r.error || r.signal) return { status: 'FAIL', reason: 'review:source-metadata-unavailable', files_checked: 0 }
  const paths = new Set()
  for (const entry of r.stdout.split('\0').filter(Boolean)) {
    const match = /^(100644|100755) blob [0-9a-f]{40}\t(.+)$/u.exec(entry)
    if (!match || match[2].startsWith('/') || match[2].split('/').some(part => !part || part === '.' || part === '..'))
      return { status: 'FAIL', reason: 'review:source-metadata-invalid', files_checked: 0 }
    paths.add(match[2])
  }
  const missing = new Set(mandatory.filter(path => !paths.has(path)))
  for (const path of paths) {
    const parts = path.split('/')
    try {
      for (let i = 1; i <= parts.length; i++) {
        const info = lstatSync(resolve(root, ...parts.slice(0, i)))
        if (i === parts.length ? !info.isFile() : !info.isDirectory()) throw Error('missing physical source')
      }
    } catch { missing.add(path) }
  }
  const emptyRoots = roots.filter(prefix => ![...paths].some(path => path.startsWith(prefix + '/'))).length
  return { status: missing.size || emptyRoots ? 'FAIL' : 'PASS',
    ...(missing.size || emptyRoots ? { reason: 'review:physical-source-incomplete' } : {}),
    files_checked: paths.size, missing_files: missing.size, empty_roots: emptyRoots,
    qualification: 'physical selected HEAD closure present; dirty bytes are separately reported, no child or runtime acceptance' }
}

// Only source-owned literal argv can launch checks. Evidence data is never argv.
export const REVIEW_PROFILE = Object.freeze([
  tapCheck('trusted-bootstrap', 'packages/boundary-gate/src/vendor/check-trusted-verifier.mjs',
    'VM fixture; synthetic root metadata/Unix replies, no installed custody. Baseline only, no --mutations.', ['--experimental-vm-modules']),
  tapCheck('trusted-release-verifier', 'tests/aukora-plugin-set-trusted-verifier.test.mjs',
    'Synthetic releases; service assertions do not observe installed units.'),
  tapCheck('gate-plugin-set-signer', 'tests/aukora-plugin-set-gate-signer.test.mjs',
    'Synthetic gate/keys; no owner enrollment or installed approval.'),
  tapCheck('host-capture-retention', 'tests/kira-gate-capture-host.test.mjs',
    'Actual host capture source with synthetic receipts and local pinned helpers; no installed host, owner or private custody.'),
  tapCheck('sequence-floor', 'packages/boundary-gate/src/vendor/check-sequence-floor.mjs',
    'Source ordering/filesystem fixtures; no live floor migration or release activation.'),
  tapCheck('ordered-approval', 'packages/boundary-gate/src/vendor/check-ordered-approval.mjs',
    'Actual source with disposable SQLite/synthetic keys; no protected owner custody.'),
  nodeCheck('preview-policy', ['packages/boundary-gate/src/vendor/check-preview-policy.mjs'],
    'Source assertions and isolated Python launcher-prefix checks; no desktop launch or installed policy.'),
  Object.freeze({ id: 'protected-bootstrap', executable: '/usr/bin/python3',
    args: Object.freeze(['-I', '-S', 'packages/boundary-gate/host/install/check-bootstrap.py']), report: 'unittest',
    limit: 'stdlib source fixtures and synthetic root metadata; no installed bootstrap, permissions or deployment.' }),
  tapCheck('owner-card-model-fence', 'tests/aukora-owner-card-model-fence.test.mjs',
    'Disposable IPC/source/VM card checks; no rendered desktop or human attendance.'),
  tapCheck('owner-card-no-friction', 'tests/aukora-owner-card-no-friction.test.mjs',
    'Disposable IPC/source checks; no measured comprehension.'),
  tapCheck('owner-card-clarity', 'tests/aukora-owner-card-clarity.test.mjs',
    'Source gate/adapter/VM renderer checks; no human comprehension or installed card.'),
  tapCheck('plugin-set-floor-card', 'tests/aukora-plugin-set-floor-card.test.mjs',
    'Synthetic floor/card and gate refusal fixtures; no installed floor or rendered desktop.'),
  tapCheck('owner-key', 'packages/owner-key/checks/owner-key.test.mjs',
    'Published synthetic P256 fixture; no key generation, enrollment, Touch ID or protected native join.'),
  nodeCheck('aura-lifecycle-citation', ['scripts/aura/checks/collector.mjs'],
    'Synthetic source/anchors and actual record verifier; final-candidate evidence requires its current physical dependency closure.'),
  tapCheck('kira-aura-recall', 'tests/kira-aura-recall.test.mjs',
    'Synthetic host association/provider and actual source recall; no installed completion delivery or private-memory import.'),
  tapCheck('selfcheck-contract', 'packages/boundary-gate/checks/selfcheck-bin.mjs',
    'Stubbed runner/RPC; no sandbox egress or host probes.'),
  tapCheck('review-runner-contract', 'tests/security-review-runner.test.mjs',
    'Runner outcome/dispatch regressions with disposable children; no product qualification.'),
  nodeCheck('containment-verdict-firewall', ['--test', '--test-reporter=tap', 'tests/aukora-containment.test.mjs', 'tests/aukora-auma-firewall.test.mjs', 'tests/aukora-openshell-confinement.test.mjs'],
    'Offline pure/mock verdict and firewall checks only; no live probe, rootless Podman, guest userns-root or detecting-control qualification.', 'tap'),
  nodeCheck('l2-signed-export', ['docs/evidence/l2-demo-2026-10-04/verify.mjs'],
    'Historical signed prefix only; no fetched anchor/current tip/human identity proof.'),
  nodeCheck('face-copy-equality', ['scripts/audit/check-face-copies.mjs'],
    'Source byte equality only; no build or served-byte observation.'),
  nodeCheck('current-evidence-tables', ['scripts/audit/render-evidence.mjs', '--check'],
    'Documentation consistency only; claim sources are not independently attested.'),
])

const COUNT_KEYS = ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']
function tapCounts(text) {
  const totals = {}, duplicate = new Set()
  let failureReported = false
  for (const match of text.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)\s*$/gm)) {
    if (Object.hasOwn(totals, match[1])) duplicate.add(match[1])
    totals[match[1]] = Number(match[2])
    if (['fail', 'cancelled'].includes(match[1]) && Number(match[2]) > 0) failureReported = true
  }
  const valid = duplicate.size === 0 && COUNT_KEYS.every(key => Number.isSafeInteger(totals[key]) && totals[key] >= 0)
    && COUNT_KEYS.slice(1).reduce((sum, key) => sum + totals[key], 0) === totals.tests
  return { totals, valid, failureReported }
}
function unittestCounts(text) {
  const matches = [...text.matchAll(/^Ran (\d+) tests? in .+$/gm)]
  const result = [...text.matchAll(/^(OK|FAILED)(?: \(([^\n]*)\))?\s*$/gm)]
  const tests = Number(matches[0]?.[1])
  const annotations = {}, allowed = ['skipped', 'failures', 'errors', 'expected failures', 'unexpected successes']
  let annotationsValid = true
  for (const field of result[0]?.[2]?.split(', ') ?? []) {
    const match = /^([a-z ]+)=(\d+)$/u.exec(field)
    if (!match || !allowed.includes(match[1]) || Object.hasOwn(annotations, match[1])) annotationsValid = false
    else annotations[match[1]] = Number(match[2])
  }
  const skipped = annotations.skipped ?? 0, todo = annotations['expected failures'] ?? 0
  const fail = (annotations.failures ?? 0) + (annotations.errors ?? 0) + (annotations['unexpected successes'] ?? 0)
  const totals = { tests, pass: tests - skipped - fail - todo, fail, cancelled: 0, skipped, todo }
  const valid = matches.length === 1 && result.length === 1 && COUNT_KEYS.every(key => Number.isSafeInteger(totals[key]) && totals[key] >= 0)
    && annotationsValid && (result[0][1] !== 'FAILED' || fail > 0)
  return { totals, valid, failureReported: result.some(match => match[1] === 'FAILED') || fail > 0 }
}

/** Classify actual child results; importing this module does not run the profile. */
export function classifyCheckResult(result, report = 'exit') {
  if (!['exit', 'tap', 'unittest'].includes(report)) throw Error('review:report-invalid')
  const out = result.stdout?.toString('utf8') ?? '', err = result.stderr?.toString('utf8') ?? ''
  const parsed = report === 'tap' ? tapCounts(out) : report === 'unittest' ? unittestCounts(`${out}\n${err}`) : null
  const reported = parsed && Object.fromEntries(Object.entries(parsed.totals).filter(([, value]) => Number.isSafeInteger(value) && value >= 0))
  const details = reported && Object.keys(reported).length ? { reported_test_totals: reported } : {}
  if (result.status !== 0 || result.error || result.signal || parsed?.failureReported)
    return { status: 'FAIL', reason: 'child failed, was interrupted, or reported failed/cancelled tests', ...details }
  if (parsed && !parsed.valid) return { status: 'UNPERFORMED', reason: 'missing or inconsistent completed test totals', ...details }
  if (parsed && parsed.totals.tests === 0) return { status: 'UNPERFORMED', reason: 'no tests completed', ...details }
  if (parsed && parsed.totals.skipped === parsed.totals.tests) return { status: 'SKIP', reason: 'all reported tests skipped', ...details }
  if (parsed && (parsed.totals.skipped > 0 || parsed.totals.todo > 0))
    return { status: 'UNPERFORMED', reason: 'reported tests include skipped or todo work', ...details }
  return { status: 'PASS', ...details }
}

export function summarizeReview(checks, declaredUnperformed = []) {
  if (checks.some(row => !['PASS', 'FAIL', 'SKIP', 'UNPERFORMED'].includes(row.status))) throw Error('review:status-invalid')
  const pass = checks.filter(row => row.status === 'PASS').length
  const fail = checks.filter(row => row.status === 'FAIL').length
  const skipped = checks.filter(row => row.status === 'SKIP').length
  const checkUnperformed = checks.filter(row => row.status === 'UNPERFORMED').length + (checks.length === 0 ? 1 : 0)
  const reported = Object.fromEntries(COUNT_KEYS.map(key => [key,
    checks.reduce((sum, row) => sum + (row.reported_test_totals?.[key] ?? 0), 0)]))
  const profileResult = fail ? 'FAIL' : skipped || checkUnperformed ? 'UNPERFORMED' : 'PASS'
  const outcome = fail ? 'FAIL' : skipped || checkUnperformed || declaredUnperformed.length ? 'UNPERFORMED' : 'PASS'
  return { pass, fail, skipped, unperformed: declaredUnperformed.length + checkUnperformed,
    reported_test_totals: reported, profile_result: profileResult, result: outcome,
    exit_code: outcome === 'FAIL' ? 1 : outcome === 'UNPERFORMED' ? 2 : 0,
    scope: 'offline source/evidence checks; not whole-product acceptance' }
}

export function reviewCommand(row) {
  if (!REVIEW_PROFILE.includes(row)) throw Error('review:profile-entry-invalid')
  return Object.freeze([row.executable === 'node' ? process.execPath : row.executable, ...row.args])
}

function assertReviewEnvironment() {
  // This rejects direct/imported acceptance after startup. The shell launchers
  // provide the separate guard that prevents NODE_OPTIONS preloads executing.
  if (Object.hasOwn(process.env, 'NODE_OPTIONS')) throw Error('review:node-options-forbidden')
  if (['AUKORA_TEST_KIRA_SOURCE', 'AUKORA_TEST_AURA_SOURCE'].some(name => Object.hasOwn(process.env, name)))
    throw Error('review:source-override-forbidden')
}

export function runReviewChecks({ list = false, logs = null } = {}) {
  assertReviewEnvironment()
  const env = { ...process.env, PYTHONDONTWRITEBYTECODE: '1', GIT_NO_LAZY_FETCH: '1' }
  const cleared = Object.keys(env).filter(key => key.endsWith('_MUTANT')
    || ['AUKORA_RECORDS_MODULE', 'AUKORA_PRIME_CHECK_GIT', 'AUKORA_AURA_CHECK_GIT', 'AUKORA_AURA_CITATION_BASE', 'NODE_TEST_CONTEXT', 'NODE_OPTIONS', 'AUKORA_TEST_KIRA_SOURCE', 'AUKORA_TEST_AURA_SOURCE'].includes(key))
  for (const key of cleared) delete env[key]
  if (logs) mkdirSync(logs, { recursive: true, mode: 0o700 })
  const checks = REVIEW_PROFILE.map(entry => {
    const command = reviewCommand(entry)
    const row = { id: entry.id, command: [entry.executable, ...entry.args], limit: entry.limit, report: entry.report }
    if (list) return { ...row, status: 'UNPERFORMED', reason: 'list-only; no check child executed' }
    const started = Date.now()
    const profile = entry.id === 'aura-lifecycle-citation' ? 'aura' : entry.id === 'kira-aura-recall' ? 'kira' : null
    const sourcePrerequisite = profile && verifyPhysicalSource(profile)
    if (sourcePrerequisite?.status === 'FAIL') return { ...row, status: 'FAIL', reason: sourcePrerequisite.reason,
      source_prerequisite: sourcePrerequisite, child_executed: false, duration_ms: Date.now() - started }
    const r = spawnSync(command[0], command.slice(1), { cwd: root, env, timeout: 60000, maxBuffer: 8 * 1024 * 1024 })
    const out = r.stdout ?? Buffer.alloc(0), err = r.stderr ?? Buffer.alloc(0)
    let logError = null
    if (logs) {
      try {
        writeFileSync(resolve(logs, `${entry.id}.stdout`), out, { mode: 0o600 })
        writeFileSync(resolve(logs, `${entry.id}.stderr`), err, { mode: 0o600 })
        writeFileSync(resolve(logs, `${entry.id}.exit.json`), JSON.stringify({ exit: r.status, signal: r.signal, error: r.error?.code ?? null }) + '\n', { mode: 0o600 })
      } catch { logError = 'review:logs-unavailable' }
    }
    const classified = classifyCheckResult(r, entry.report)
    return { ...row, ...classified, ...(logError ? { status: 'FAIL', reason: logError } : {}),
      exit: r.status, signal: r.signal, error: r.error?.code ?? null,
      duration_ms: Date.now() - started, stdout: { bytes: out.length, sha256: hash(out) },
      stderr: { bytes: err.length, sha256: hash(err) },
      ...(classified.reported_test_totals && entry.report === 'tap' ? { reported_tap_totals: classified.reported_test_totals } : {}) }
  })
  return { checks, cleared_mutation_selectors: cleared }
}

function git(args) {
  const r = spawnSync('git', args, { cwd: root, encoding: 'utf8', env: { ...process.env, GIT_NO_LAZY_FETCH: '1' } })
  if (r.status !== 0 || r.error || r.signal) throw Error('review:source-identity-unavailable')
  return r.stdout.trim()
}
function main(argv) {
  assertReviewEnvironment()
  if (argv.length === 2 && argv[0] === '--source-prerequisite') {
    const result = verifyPhysicalSource(argv[1])
    console.log(JSON.stringify({ scope: 'physical current source prerequisite only; no check child executed', ...result }))
    return result.status === 'PASS' ? 0 : 1
  }
  if (argv.length === 1 && argv[0] === '--help') {
    console.log('Usage: ./security-review [--list] [--logs DIRECTORY]\n       ./security-review --source-prerequisite aura|kira\nJSON stdout; exit 1 for failures, 2 for skipped/unperformed work, 0 only for a completed profile with no declared gaps. Source-prerequisite mode verifies physical selected closure only. No installs, network, deployment, live probes or full source-profile run.')
    return 0
  }
  let list = false, logs = null
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--list') list = true
    else if (argv[i] === '--logs' && argv[i + 1]) logs = resolve(argv[++i])
    else throw Error('review:argument-invalid')
  }
  const evidenceBytes = readFileSync(resolve(root, 'evidence/current.json'))
  const evidence = JSON.parse(evidenceBytes)
  if (!Array.isArray(evidence.unperformed) || !evidence.unperformed.every(value => typeof value === 'string')
    || !Array.isArray(evidence.boundary_files) || !evidence.boundary_files.every(value => typeof value === 'string'
      && value.length > 0 && !value.startsWith('/') && !value.split('/').includes('..')) || !evidence.revisions)
    throw Error('review:evidence-invalid')
  const head = git(['rev-parse', 'HEAD']), dirty = git(['status', '--porcelain', '--untracked-files=normal']) !== ''
  const boundaryFiles = evidence.boundary_files.map(path => ({ path, sha256: hash(readFileSync(resolve(root, path))) }))
  const started = new Date().toISOString()
  const { checks, cleared_mutation_selectors } = runReviewChecks({ list, logs })
  // Fixture PASS never removes separately declared deployment/custody gaps.
  const unperformed = evidence.unperformed.map(reason => ({ status: 'UNPERFORMED', reason }))
  const summary = summarizeReview(checks, unperformed)
  console.log(JSON.stringify({ schema: 'aukora-security-review/v1', profile: 'offline-critical-v2',
    started_at: started, completed_at: new Date().toISOString(),
    source: { sha: head, working_tree_dirty: dirty, qualification: dirty ? 'HEAD plus working changes; HEAD alone does not identify checked bytes' : 'clean source checkout', node: process.versions.node },
    claim_snapshot: { sha256: hash(evidenceBytes), source_revision: evidence.revisions.source, main_observed: evidence.revisions.main_observed, deployment: evidence.revisions.deployment },
    boundary_files: boundaryFiles, cleared_mutation_selectors, checks, unperformed,
    raw_output: logs ? 'Private raw stdout, stderr and exit files requested in the chosen directory; each logging failure marks its row FAIL; paths omitted from JSON'
      : 'Only output byte counts and digests retained; use --logs for private raw output', summary }, null, 2))
  return summary.exit_code
}

let invokedAsMain = false
try { invokedAsMain = !!process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]) }
catch { /* An imported module has no executable invocation to qualify. */ }
if (invokedAsMain) {
  try { process.exitCode = main(process.argv.slice(2)) }
  catch (error) {
    const reason = typeof error?.message === 'string' && /^review:[a-z-]+$/u.test(error.message)
      ? error.message : 'review:required-source-unavailable'
    const checks = [{ id: 'review-preconditions', status: 'FAIL', reason },
      ...REVIEW_PROFILE.map(row => ({ id: row.id, status: 'UNPERFORMED', reason: 'review did not produce a completed check result' }))]
    console.log(JSON.stringify({ schema: 'aukora-security-review/v1', profile: 'offline-critical-v2',
      status: 'FAIL', reason, checks, summary: summarizeReview(checks) }, null, 2))
    process.exitCode = 1
  }
}
