import { createHash, randomUUID } from 'node:crypto'
import { lstatSync, readdirSync, readFileSync, readlinkSync, mkdirSync, writeFileSync, realpathSync, openSync, fstatSync, closeSync, constants } from 'node:fs'
import { dirname, basename, join, resolve, relative, isAbsolute } from 'node:path'
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

function safeUiBase(value) {
  const url = new URL(value)
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname)
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('LOCAL_SAFE_UI_BASE_REQUIRED')
  return url
}

function statusObservation(status) {
  let ui_url = null
  try { ui_url = safeUiBase(status.ui_url).href } catch {}
  // Never retain unrecognized status fields or a query-bearing launch URL.
  return { status: status.status, pid: status.pid, version: status.version, ui_url,
    release_dir: status.release_dir, release_digest: status.release_digest,
    release_digest_algorithm: status.release_digest_algorithm,
    unavailable_capabilities: status.unavailable_capabilities }
}

function readNamedLaunch(root, status, expectedFile) {
  const named = resolve(expectedFile ?? join(root, '.prime-state', 'launch-url.json'))
  if (basename(named) !== 'launch-url.json' || typeof status.ui_access_file !== 'string'
    || resolve(status.ui_access_file) !== named) throw new Error('UI_ACCESS_FILE_NOT_NAMED')
  const parent = lstatSync(dirname(named))
  const uid = process.getuid?.()
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o077)
    || uid === undefined || parent.uid !== uid) throw new Error('UI_ACCESS_DIRECTORY_NOT_PRIVATE')
  let fd
  try {
    fd = openSync(named, constants.O_RDONLY | constants.O_NOFOLLOW)
    const stat = fstatSync(fd)
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) || stat.uid !== uid
      || stat.size < 1 || stat.size > 16384) throw new Error('UI_ACCESS_FILE_NOT_PRIVATE')
    const bytes = readFileSync(fd)
    try {
      if (bytes.length > 16384) throw new Error('UI_ACCESS_FILE_BUDGET')
      const launch = JSON.parse(bytes.toString('utf8'))
      if (!launch || typeof launch !== 'object' || Array.isArray(launch)
        || Object.keys(launch).sort().join(',') !== 'pid,url'
        || launch.pid !== status.pid || typeof launch.url !== 'string') throw new Error('UI_ACCESS_PID_OR_FORMAT_MISMATCH')
      return launch.url
    } finally { bytes.fill(0) }
  } finally { if (fd !== undefined) closeSync(fd) }
}

/** Disposable DSH launch access only. Cookie and launch URL never enter returned evidence. */
export async function observeLocalUi(root, status, options = {}) {
  let base
  try { base = safeUiBase(status.ui_url) } catch { return { status: 'FAIL', blocker: 'LOCAL_SAFE_UI_BASE_REQUIRED' } }
  let cookie, auth
  try {
    if (options.uiLaunchAccess === true || options.uiLaunchAccess === 'true') {
      let launch
      try { launch = new URL(readNamedLaunch(root, status, options.uiAccessFile)) }
      catch (error) { return { status: 'FAIL', blocker: /^[A-Z0-9_]+$/.test(error.message) ? error.message : 'UI_ACCESS_FILE_UNAVAILABLE_OR_INVALID' } }
      if (launch.origin !== base.origin || launch.username || launch.password || launch.pathname !== '/' || launch.hash
        || [...launch.searchParams.keys()].join(',') !== 'token' || !launch.searchParams.get('token')) {
        return { status: 'FAIL', blocker: 'UI_LAUNCH_ORIGIN_OR_FORMAT_MISMATCH' }
      }
      const response = await fetch(launch, { redirect: 'manual', signal: AbortSignal.timeout(5000) })
      await response.body?.cancel()
      // Do not follow the Location supplied by the candidate or copy Set-Cookie into evidence.
      if (response.status !== 303 || response.headers.get('location') !== '/') return { status: 'FAIL', blocker: 'UI_LAUNCH_HANDSHAKE_MISMATCH' }
      const cookies = response.headers.getSetCookie?.() ?? [response.headers.get('set-cookie')].filter(Boolean)
      if (cookies.length !== 1 || cookies[0].length > 8192) return { status: 'FAIL', blocker: 'UI_LAUNCH_COOKIE_MISMATCH' }
      const [pair, ...attrs] = cookies[0].split(';').map(v => v.trim())
      const expectedName = 'dsh-auth-' + createHash('sha256').update(base.host).digest('base64url')
      if (!pair.startsWith(expectedName + '=') || !/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(pair.slice(expectedName.length + 1))
        || !attrs.some(v => /^HttpOnly$/i.test(v)) || !attrs.some(v => /^SameSite=Strict$/i.test(v))
        || !attrs.some(v => /^Path=\/$/i.test(v)) || attrs.some(v => /^Domain=/i.test(v))) {
        return { status: 'FAIL', blocker: 'UI_LAUNCH_COOKIE_SCOPE_MISMATCH' }
      }
      cookie = pair
      auth = { method: 'DSH_DISPOSABLE_LAUNCH', launch_status: 303, credential_persisted: false, owner_passkey: 'NOT_VERIFIED' }
    }
    const response = await fetch(base, { redirect: 'manual', headers: cookie ? { Cookie: cookie } : undefined,
      signal: AbortSignal.timeout(5000) })
    const http = { status: response.status, content_type: response.headers.get('content-type') }
    await response.body?.cancel()
    if (http.status !== 200 || !http.content_type?.includes('text/html')) return { status: 'FAIL', blocker: 'UI_ENDPOINT_MISMATCH', http, auth }
    return { status: 'OBSERVED', http, auth }
  } catch { return { status: 'PENDING', blocker: 'UI_ENDPOINT_NOT_REACHABLE' } }
  finally { cookie = undefined }
}

async function observeG1(root, options) {
  const command = join(root, 'prime')
  let entry
  try { entry = lstatSync(command) } catch { return { status: 'PENDING', blocker: 'ROOT_PRIME_ENTRY_UNAVAILABLE' } }
  if (!entry.isFile() || !(entry.mode & 0o111)) return { status: 'PENDING', blocker: 'ROOT_PRIME_ENTRY_NOT_EXECUTABLE' }
  const result = await runOwned(command, ['status', '--json'], { cwd: root, timeoutMs: 10_000, home: options.disposableHome, tmpdir: options.disposableHome })
  const execution = { exit_code: result.exit_code, completion: result.completion, timed_out: result.timed_out,
    output_overflow: result.output_overflow, token_leak: result.token_leak, error: result.error, status_output: 'NOT_RETAINED' }
  if (result.error || result.timed_out) return { status: 'PENDING', blocker: 'ROOT_STATUS_UNAVAILABLE', execution }
  if (result.token_leak) return { status: 'FAIL', blocker: 'TOKEN_IN_STATUS_OUTPUT', execution }
  let status
  try { status = JSON.parse(result.stdout) } catch { return { status: 'FAIL', blocker: 'INVALID_STATUS_JSON', execution: result } }
  const observation = statusObservation(status)
  if (status.status !== 'running') return { status: 'PENDING', blocker: 'PRIME_NOT_RUNNING', observation }
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
  const ui = await observeLocalUi(root, status, options)
  if (ui.status !== 'OBSERVED') return { ...ui, running: current, observation }
  return { status: 'PENDING', blocker: 'G1_BASELINE_BUILD_UI_AND_UNAVAILABLE_EXECUTOR_PROBES_REQUIRED',
    running: current, observation, http: ui.http, auth: ui.auth, loaded_bytes: 'HOST_REPORTED_PATH_PLUS_RECOMPUTED_DISK_BYTES',
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
