#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const git = args => {
  const r = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
  if (r.status !== 0) throw new Error('git source identity unavailable')
  return r.stdout.trim()
}
// Invariant: only this fixed offline profile can run. Threat: a mutable claim file
// could become a command launcher. Reason: evidence data supplies no executable argv.
const profile = [
  ['trusted-release-verifier', ['--test', 'tests/aukora-plugin-set-trusted-verifier.test.mjs'], 'Synthetic releases; service-template assertions do not observe an installed unit.'],
  ['gate-plugin-set-signer', ['--test', 'tests/aukora-plugin-set-gate-signer.test.mjs'], 'Synthetic gate and keys; no owner enrollment or installed-release approval.'],
  ['owner-card-model-fence', ['--test', 'tests/aukora-owner-card-model-fence.test.mjs'], 'Disposable IPC and source/VM card checks; no rendered desktop or human attendance.'],
  ['owner-card-no-friction', ['--test', 'tests/aukora-owner-card-no-friction.test.mjs'], 'Disposable IPC/source checks; no measured comprehension.'],
  ['selfcheck-contract', ['--test', 'packages/boundary-gate/checks/selfcheck-bin.mjs'], 'Stubbed runner/RPC; no sandbox egress or host probes run.'],
  ['l2-signed-export', ['docs/evidence/l2-demo-2026-10-04/verify.mjs'], 'Historical signed prefix only; no fetched anchor, current tip or human identity proof.'],
  ['face-copy-equality', ['scripts/audit/check-face-copies.mjs'], 'Source byte equality only; no build or served-byte observation.'],
  ['current-evidence-tables', ['scripts/audit/render-evidence.mjs', '--check'], 'Documentation consistency only; claim sources are not independently attested.'],
]
const argv = process.argv.slice(2)
if (argv.includes('--help')) {
  console.log('Usage: ./security-review [--list] [--logs DIRECTORY]\nJSON stdout; exit 1 for failures, 2 when only declared live checks remain unperformed. No installs, network, deployment, live probes or full source-profile run.')
  process.exit(0)
}
let list = false, logs = null
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--list') list = true
  else if (argv[i] === '--logs' && argv[i + 1]) logs = resolve(argv[++i])
  else throw new Error('unknown or incomplete review argument')
}
const evidence = JSON.parse(readFileSync(resolve(root, 'evidence/current.json'), 'utf8'))
const head = git(['rev-parse', 'HEAD'])
const dirty = git(['status', '--porcelain', '--untracked-files=normal']) !== ''
const started = new Date().toISOString()
const env = { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
const clearedMutationSelectors = Object.keys(env).filter(k => k.endsWith('_MUTANT'))
for (const key of clearedMutationSelectors) delete env[key]
if (logs) mkdirSync(logs, { recursive: true, mode: 0o700 })
const checks = []
for (const [id, args, limit] of profile) {
  const row = { id, command: ['node', ...args], limit }
  if (list) checks.push({ ...row, status: 'UNPERFORMED', reason: 'list-only; no child executed' })
  else {
    const t = Date.now()
    const r = spawnSync(process.execPath, args, { cwd: root, env, timeout: 60000, maxBuffer: 8 * 1024 * 1024 })
    const out = r.stdout ?? Buffer.alloc(0), err = r.stderr ?? Buffer.alloc(0)
    if (logs) {
      writeFileSync(resolve(logs, `${id}.stdout`), out, { mode: 0o600 })
      writeFileSync(resolve(logs, `${id}.stderr`), err, { mode: 0o600 })
      writeFileSync(resolve(logs, `${id}.exit.json`), JSON.stringify({ exit: r.status, signal: r.signal, error: r.error?.code ?? null }) + '\n', { mode: 0o600 })
    }
    const totals = {}
    for (const m of out.toString('utf8').matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)\s*$/gm)) totals[m[1]] = Number(m[2])
    const skippedOnly = totals.tests > 0 && totals.pass === 0 && totals.skipped === totals.tests
    const status = r.status !== 0 || r.error || totals.fail > 0 || totals.cancelled > 0 ? 'FAIL' : skippedOnly ? 'UNPERFORMED' : 'PASS'
    checks.push({ ...row, status, ...(skippedOnly ? { reason: 'all reported tests skipped' } : {}), exit: r.status, signal: r.signal, error: r.error?.code ?? null,
      duration_ms: Date.now() - t, stdout: { bytes: out.length, sha256: hash(out) }, stderr: { bytes: err.length, sha256: hash(err) },
      ...(Object.keys(totals).length ? { reported_tap_totals: totals } : {}) })
  }
}
// Invariant: fixture success never changes deployment qualification. Threat:
// source PASS could be read as a live proof. Reason: missing arms stay explicit.
const unperformed = evidence.unperformed.map(reason => ({ status: 'UNPERFORMED', reason }))
const failures = checks.filter(r => r.status === 'FAIL').length
const result = {
  schema: 'aukora-security-review/v1', profile: 'offline-critical-v1', started_at: started, completed_at: new Date().toISOString(),
  source: { sha: head, working_tree_dirty: dirty, qualification: dirty ? 'HEAD plus working changes; HEAD alone does not identify checked bytes' : 'clean source checkout', node: process.versions.node },
  claim_snapshot: { sha256: hash(readFileSync(resolve(root, 'evidence/current.json'))), source_revision: evidence.revisions.source, main_observed: evidence.revisions.main_observed, deployment: evidence.revisions.deployment },
  boundary_files: evidence.boundary_files.map(path => ({ path, sha256: hash(readFileSync(resolve(root, path))) })),
  cleared_mutation_selectors: clearedMutationSelectors, checks, unperformed,
  raw_output: logs ? 'Private raw stdout, stderr and exit files retained in the requested directory; paths omitted from JSON' : 'Only output byte counts and digests retained; use --logs for private raw output',
  summary: { pass: checks.filter(r => r.status === 'PASS').length, fail: failures, unperformed: unperformed.length + checks.filter(r => r.status === 'UNPERFORMED').length,
    result: failures ? 'FAIL' : 'UNPERFORMED', scope: 'offline source/evidence checks; not whole-product acceptance' },
}
console.log(JSON.stringify(result, null, 2))
process.exitCode = failures ? 1 : 2
