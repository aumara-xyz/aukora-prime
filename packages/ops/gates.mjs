import { createHash, randomUUID } from 'node:crypto'
import { lstatSync, readdirSync, readFileSync, readlinkSync, mkdirSync, writeFileSync, realpathSync } from 'node:fs'
import { dirname, join, resolve, relative, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'
import { treeDigest } from './vendor/release-digest.mjs'
import { runOwned, sanitized } from './owned-process.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
export const CASES = Object.freeze({
  G1: ['harness-ui-boot', 'unavailable-executor', 'prime-only-build'],
  G2: ['owner-scope', 'origin-ipc', 'approval-presentation', 'denial-expiry'],
  G3: ['owned-bash-typed-drained', 'backend-absence', 'weak-marker-provenance', 'host-fallback', 'owned-cleanup'],
  G4: ['unauthorized-signing', 'changed-digest', 'replay', 'revocation', 'restore-consumption', 'durable-prepared'],
  G5: ['synthetic-save-restart-recall', 'save-index-ack', 'prime-only-export-cold-restore', 'owner-forget'],
  G6: ['useful-ui-workflow', 'token-leak', 'origin-ipc', 'outage', 'cancel', 'approved-budget']
})

/** Covers regular bytes/modes and contained links; no weak installation markers. */
export function fullTreeDigest(root) {
  root = realpathSync(root)
  const rows = []
  const visit = rel => {
    for (const name of readdirSync(join(root, rel)).sort()) {
      const path = rel ? `${rel}/${name}` : name
      const stat = lstatSync(join(root, path))
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(join(root, path))
        if (isAbsolute(target)) throw new Error('ABSOLUTE_RELEASE_LINK')
        const actual = realpathSync(join(root, path))
        const relTarget = relative(root, actual)
        if (relTarget.startsWith('..') || isAbsolute(relTarget)) throw new Error('RELEASE_LINK_ESCAPES_ROOT')
        rows.push(`l ${path}\0${target}`)
      } else if (stat.isDirectory()) visit(path)
      else if (stat.isFile()) rows.push(`${stat.mode & 0o111 ? 'x' : 'f'} ${path}\0${sha(readFileSync(join(root, path)))}`)
      else throw new Error('NONREGULAR_RELEASE_FILE')
    }
  }
  visit('')
  rows.sort()
  return { algorithm: 'aukora-prime:full-release:v1', digest: sha(`aukora-prime:full-release:v1\0${rows.join('\n')}`), files: rows.length }
}

export function evaluatorDigest() {
  const files = ['cli.mjs', 'gates.mjs', 'owned-process.mjs', 'archive.py', 'deployment.mjs', 'vendor/release-digest.mjs']
  return sha(files.map(file => `${file}\0${sha(readFileSync(join(here, file)))}`).join('\n'))
}
const nested = (value, path) => path.split('.').reduce((v, k) => v?.[k], value)
function assertProbe(result, probe) {
  const findings = []
  if (result.token_leak) findings.push('TOKEN_IN_OUTPUT')
  if (result.timed_out || result.cancelled || result.output_overflow || result.error) findings.push('PROBE_INCOMPLETE')
  if (result.exit_code !== probe.exit_code) findings.push('EXIT_CODE_MISMATCH')
  let observation
  try { observation = JSON.parse(result.stdout) } catch { findings.push('INVALID_JSON_OUTPUT'); return findings }
  // Evaluator compares externally supplied observations. Candidate pass flags are inadmissible.
  if ('passed' in observation || 'gate_status' in observation) findings.push('CANDIDATE_VERDICT_NOT_EVIDENCE')
  for (const assertion of probe.assertions) {
    if (JSON.stringify(nested(observation, assertion.path)) !== JSON.stringify(assertion.equals)) findings.push(`OBSERVATION_MISMATCH:${assertion.path}`)
  }
  return findings
}

async function observeG1(root, options) {
  const command = join(root, 'prime')
  let entry
  try { entry = lstatSync(command) } catch { return { status: 'PENDING', blocker: 'ROOT_PRIME_ENTRY_UNAVAILABLE' } }
  if (!entry.isFile() || !(entry.mode & 0o111)) return { status: 'PENDING', blocker: 'ROOT_PRIME_ENTRY_NOT_EXECUTABLE' }
  const result = await runOwned(command, ['status', '--json'], { cwd: root, timeoutMs: 10_000, home: options.disposableHome, tmpdir: options.disposableHome })
  if (result.error || result.timed_out) return { status: 'PENDING', blocker: 'ROOT_STATUS_UNAVAILABLE', execution: result }
  if (result.token_leak) return { status: 'FAIL', blocker: 'TOKEN_IN_STATUS_OUTPUT', execution: result }
  let status
  try { status = JSON.parse(result.stdout) } catch { return { status: 'FAIL', blocker: 'INVALID_STATUS_JSON', execution: result } }
  if (status.status !== 'running') return { status: 'PENDING', blocker: 'PRIME_NOT_RUNNING', observation: status }
  const required = ['pid', 'version', 'ui_url', 'release_dir', 'release_digest', 'unavailable_capabilities']
  if (required.some(k => !(k in status))) return { status: 'FAIL', blocker: 'STATUS_CONTRACT_MISMATCH' }
  if (!Number.isSafeInteger(status.pid) || status.pid < 1) return { status: 'FAIL', blocker: 'INVALID_RUNNING_PID' }
  try { process.kill(status.pid, 0) } catch { return { status: 'PENDING', blocker: 'RUNNING_PROCESS_NOT_OBSERVABLE' } }
  let current
  try {
    current = status.release_digest_algorithm === 'aukora:release-tree:v1' ?
      { algorithm: 'aukora:release-tree:v1', ...treeDigest(status.release_dir) } : fullTreeDigest(status.release_dir)
  } catch { return { status: 'PENDING', blocker: 'RUNNING_TREE_UNAVAILABLE_OR_UNQUALIFIED' } }
  if (current.digest !== status.release_digest.replace(/^sha256:/, '')) return { status: 'FAIL', blocker: 'RUNNING_DIGEST_MISMATCH', recomputed: current }
  let url
  try { url = new URL(status.ui_url) } catch { return { status: 'FAIL', blocker: 'INVALID_UI_URL' } }
  // This local source-stage probe does not widen network access or use public endpoints.
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname) || url.username || url.password) return { status: 'PENDING', blocker: 'LOCAL_UI_URL_REQUIRED' }
  let http
  try {
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000) })
    http = { status: response.status, content_type: response.headers.get('content-type') }
    await response.body?.cancel()
  } catch { return { status: 'PENDING', blocker: 'UI_ENDPOINT_NOT_REACHABLE', running: current } }
  if (http.status !== 200 || !http.content_type?.includes('text/html')) return { status: 'FAIL', blocker: 'UI_ENDPOINT_MISMATCH', http }
  return { status: 'PENDING', blocker: 'G1_BASELINE_BUILD_UI_AND_UNAVAILABLE_EXECUTOR_PROBES_REQUIRED',
    running: current, observation: status, http, loaded_bytes: 'HOST_REPORTED_PATH_PLUS_RECOMPUTED_DISK_BYTES',
    same_uid_boundary: 'NOT_ENFORCED', source_stage_only: true }
}

/**
 * Probe plan stays OUTSIDE candidate, has an independently retained SHA, and defines
 * argv + exact observed fields. Unconfigured/unqualified cases stay PENDING.
 * Run this evaluator from a separately owned read-only tree for acceptance.
 */
export async function runGate(gate, options) {
  if (!(gate in CASES)) throw new Error('UNKNOWN_GATE')
  const root = realpathSync(options.root)
  const evidenceDir = resolve(options.evidenceDir)
  const inRoot = p => { const r = relative(root, p); return r === '' || (!r.startsWith('..') && !isAbsolute(r)) }
  if (inRoot(evidenceDir)) throw new Error('EVIDENCE_MUST_BE_OUTSIDE_CANDIDATE')
  const initial = evaluatorDigest()
  const evidence = { schema: 'prime-gate-evidence-v1', gate, created_at: new Date().toISOString(),
    evaluator_digest: initial, candidate_root: root, status: 'PENDING', cases: [],
    environment: { platform: process.platform, arch: process.arch, node: process.version },
    paid_inference: 'NOT_PERFORMED', candidate_policy_changed: false,
    evaluator_os_isolation: 'NOT_ESTABLISHED_BY_THIS_RUNNER' }
  try {
  if (gate === 'G1') {
    evidence.running_observation = await observeG1(root, options)
    if (evidence.running_observation.status === 'FAIL') evidence.status = 'FAIL'
  }
  if (options.expectedEvaluatorDigest !== initial) evidence.blocker = 'INDEPENDENT_EVALUATOR_PIN_REQUIRED'
  else if (inRoot(here)) evidence.blocker = 'EVALUATOR_MUST_RUN_OUTSIDE_CANDIDATE'
  else if (!options.probePlan || !options.expectedProbeDigest) evidence.blocker = 'FROZEN_EXTERNAL_PROBE_PLAN_REQUIRED'
  else {
    const path = realpathSync(options.probePlan)
    if (inRoot(path)) throw new Error('PROBE_PLAN_MUST_BE_OUTSIDE_CANDIDATE')
    const bytes = readFileSync(path)
    const planHash = sha(bytes)
    if (planHash !== options.expectedProbeDigest) throw new Error('PROBE_PLAN_DIGEST_MISMATCH')
    const plan = JSON.parse(bytes)
    if (plan.schema !== 'prime-probes-v1' || plan.gate !== gate || plan.candidate_digest !== options.expectedCandidateDigest) throw new Error('INVALID_OR_UNBOUND_PROBE_PLAN')
    evidence.probe_digest = planHash
    if (!options.releaseDir || !options.expectedCandidateDigest) evidence.blocker = 'FROZEN_CANDIDATE_RELEASE_REQUIRED'
    else {
      const releaseDir = realpathSync(options.releaseDir)
      evidence.candidate = fullTreeDigest(releaseDir)
      if (evidence.candidate.digest !== options.expectedCandidateDigest) throw new Error('CANDIDATE_DIGEST_MISMATCH')
      for (const name of CASES[gate]) {
        const probe = plan.probes?.find(p => p.case === name)
        if (!probe) { evidence.cases.push({ case: name, status: 'PENDING', reason: 'PROBE_UNAVAILABLE' }); continue }
        if (probe.qualification !== 'actual-prime-adapter' || !Array.isArray(probe.assertions) || !probe.assertions.length) {
          evidence.cases.push({ case: name, status: 'PENDING', reason: 'ACTUAL_ADAPTER_REQUIRED' }); continue
        }
        // Entry point is confined to the frozen release; no command selected from a sibling repo.
        const executable = realpathSync(resolve(releaseDir, probe.executable))
        const rel = relative(releaseDir, executable)
        if (rel.startsWith('..') || isAbsolute(rel) || !Array.isArray(probe.args)) throw new Error('PROBE_ENTRY_OUTSIDE_RELEASE')
        if (['ssh', 'sudo', 'curl', 'wget', 'docker'].includes(probe.executable)) throw new Error('REMOTE_OR_SYSTEM_PROBE_NOT_ALLOWED')
        const result = await runOwned(executable, probe.args, { cwd: releaseDir, home: options.disposableHome,
          tmpdir: options.disposableHome, timeoutMs: probe.timeout_ms ?? 30_000, signal: options.signal })
        const findings = assertProbe(result, probe)
        evidence.cases.push({ case: name, status: findings.length ? 'FAIL' : 'PASS', findings, execution: result })
      }
      if (fullTreeDigest(releaseDir).digest !== options.expectedCandidateDigest) throw new Error('CANDIDATE_CHANGED_DURING_EVALUATION')
      if (sha(readFileSync(path)) !== planHash || evaluatorDigest() !== initial) throw new Error('EVALUATOR_OR_PLAN_CHANGED')
      evidence.status = evidence.running_observation?.status === 'FAIL' || evidence.cases.some(c => c.status === 'FAIL') ? 'FAIL' : evidence.cases.some(c => c.status === 'PENDING') ? 'PENDING' : 'PASS'
      if (gate === 'G1' && !evidence.running_observation?.running && evidence.status === 'PASS') { evidence.status = 'PENDING'; evidence.blocker = 'RUNNING_BYTES_NOT_OBSERVED' }
      // A probe qualification is not an OS boundary, trusted display, paid inference approval,
      // or third-party independence. Integrator must supply those gate prerequisites.
      const missing = (plan.required_prerequisites ?? []).filter(p => !(options.prerequisites ?? []).includes(p))
      if (missing.length && evidence.status !== 'FAIL') { evidence.status = 'PENDING'; evidence.blocker = `PREREQUISITES:${missing.join(',')}` }
      if (evidence.status === 'PASS') {
        evidence.status = 'PENDING'
        evidence.blocker = 'OBSERVATION_PROBES_ONLY_FULL_GATE_ADAPTER_PENDING'
      }
    }
  }
  } catch (error) {
    evidence.status = 'FAIL'
    evidence.blocker = /^[A-Z0-9_:.,-]+$/.test(error.message) ? error.message : error.name
  }
  mkdirSync(evidenceDir, { recursive: true, mode: 0o700 })
  const evidencePath = join(evidenceDir, `${gate}-${randomUUID()}.json`)
  writeFileSync(evidencePath, sanitized(JSON.stringify(evidence, null, 2)), { mode: 0o600, flag: 'wx' })
  return { gate, status: evidence.status, evidence_path: evidencePath, blocker: evidence.blocker,
    evaluator_digest: initial, candidate_digest: evidence.candidate?.digest,
    running_status: evidence.running_observation?.observation?.status,
    running_blocker: evidence.running_observation?.blocker }
}
