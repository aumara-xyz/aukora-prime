// SPDX-License-Identifier: AGPL-3.0-or-later
// Ordinary source assertions only. This runner establishes no OS isolation.
import {spawn} from 'node:child_process'
import {createHash, randomUUID} from 'node:crypto'
import {constants, lstatSync, realpathSync, mkdirSync, writeFileSync} from 'node:fs'
import {open} from 'node:fs/promises'
import {dirname, isAbsolute, join, relative, sep} from 'node:path'
import {performance} from 'node:perf_hooks'
import {fileURLToPath} from 'node:url'
import {CASES, NODE_VERSION, SOURCE_REVIEW_COMMIT, HISTORY, UNPERFORMED} from './manifest.mjs'

const CONTROLS = /[\x00-\x1f\x7f]/
const SUITE_MS = 150_000, OUTPUT_BYTES = 65_536, ENTRY_BYTES = 1_048_576
const outside = value => value === '..' || value.startsWith('..' + sep) || isAbsolute(value)
const reject = reason => {throw new Error(reason)}
const same = (a, b) => ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key])
const sameDirectory = (a, b) => ['dev', 'ino', 'uid', 'gid', 'mode'].every(key => a[key] === b[key])
const safePath = value => typeof value === 'string' && value.length > 0 && !CONTROLS.test(value)
const version = String(NODE_VERSION).replace(/^v/, '')

async function filePin(path, limit) {
  const before = lstatSync(path, {bigint: true})
  if (!before.isFile() || before.size > BigInt(limit)) reject('SOURCE_FILE_NOT_REGULAR_OR_BOUNDED')
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    if (!same(before, await handle.stat({bigint: true}))) reject('SOURCE_CHANGED')
    const hash = createHash('sha256'), buffer = Buffer.alloc(65_536)
    let size = 0
    for (;;) {
      const {bytesRead} = await handle.read(buffer, 0, buffer.length, null)
      if (!bytesRead) break
      size += bytesRead
      if (size > limit) reject('SOURCE_FILE_NOT_REGULAR_OR_BOUNDED')
      hash.update(buffer.subarray(0, bytesRead))
    }
    if (!same(before, await handle.stat({bigint: true})) || !same(before, lstatSync(path, {bigint: true}))) reject('SOURCE_CHANGED')
    return {digest: hash.digest('hex'), identity: before}
  } finally {await handle.close()}
}

function sourceRoot(root) {
  if (!safePath(root) || !isAbsolute(root) || root !== realpathSync(root) || !lstatSync(root).isDirectory()) reject('CANONICAL_SOURCE_ROOT_REQUIRED')
  return root
}

function compiledCases(root) {
  if (!Array.isArray(CASES) || CASES.length < 1 || CASES.length > 32) reject('INVALID_COMPILED_MANIFEST')
  const ids = new Set()
  return CASES.map(row => {
    if (!row || typeof row !== 'object' || typeof row.id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,79}$/.test(row.id) || ids.has(row.id) ||
        typeof row.property !== 'string' || !row.property.length || row.property.length > 200 || CONTROLS.test(row.property)) reject('INVALID_COMPILED_MANIFEST')
    ids.add(row.id)
    if (Object.hasOwn(row, 'unsupportedReason')) {
      if (Object.keys(row).some(key => !['id', 'property', 'unsupportedReason', 'args', 'nodeArgs', 'pins'].includes(key)) ||
          ['args', 'nodeArgs', 'pins'].some(key => row[key] !== undefined && (!Array.isArray(row[key]) || row[key].length)) ||
          !/^[A-Z][A-Z0-9_]{0,119}$/.test(row.unsupportedReason)) reject('INVALID_COMPILED_MANIFEST')
      return {...row}
    }
    const allowed = ['id', 'property', 'entry', 'args', 'nodeArgs', 'expectedSha256', 'timeoutMs', 'protocol', 'expectedTitle', 'minTests', 'pins', 'requiresPython', 'requireComplete']
    if (Object.keys(row).some(key => !allowed.includes(key)) || !safePath(row.entry) || isAbsolute(row.entry) ||
        row.entry.split('/').some(part => !part || part === '.' || part === '..') || row.entry.includes('\\') ||
        !Array.isArray(row.args) || row.args.some(value => !safePath(value)) ||
        (row.nodeArgs !== undefined && (!Array.isArray(row.nodeArgs) || row.nodeArgs.some(value => !safePath(value)))) ||
        !/^[0-9a-f]{64}$/.test(row.expectedSha256) || !Number.isInteger(row.timeoutMs) || row.timeoutMs < 1 || row.timeoutMs > 30_000 ||
        !['assert-script', 'tap', 'json-assertions'].includes(row.protocol) ||
        (row.requiresPython !== undefined && typeof row.requiresPython !== 'boolean') ||
        (row.requireComplete !== undefined && typeof row.requireComplete !== 'boolean') ||
        (row.requireComplete && (row.protocol === 'assert-script' || row.nodeArgs.some(value =>
          /^--test-(?:name-pattern|skip-pattern|only)(?:=|$)/.test(value))))) reject('INVALID_COMPILED_MANIFEST')
    if (row.protocol === 'tap' && (typeof row.expectedTitle !== 'string' || !row.expectedTitle.length ||
        CONTROLS.test(row.expectedTitle) || !Number.isInteger(row.minTests) || row.minTests < 1 || row.minTests > 10_000)) reject('INVALID_COMPILED_MANIFEST')
    const entry = join(root, row.entry)
    if (outside(relative(root, entry))) reject('INVALID_COMPILED_MANIFEST')
    if (row.pins !== undefined && (!Array.isArray(row.pins) || row.pins.length > 8)) reject('INVALID_COMPILED_MANIFEST')
    const pins = (row.pins ?? []).map(pin => {
      if (!pin || Object.keys(pin).sort().join(',') !== 'path,sha256' || !safePath(pin.path) || isAbsolute(pin.path) ||
          pin.path.split('/').some(part => !part || part === '.' || part === '..') || pin.path.includes('\\') ||
          !/^[0-9a-f]{64}$/.test(pin.sha256)) reject('INVALID_COMPILED_MANIFEST')
      return {...pin, absolutePath: join(root, pin.path)}
    })
    return {...row, absoluteEntry: entry, pins}
  })
}

function newEvidence(root, path) {
  if (!safePath(path) || !isAbsolute(path)) reject('CANONICAL_NEW_EVIDENCE_DIRECTORY_REQUIRED')
  const parent = dirname(path), metadata = lstatSync(parent)
  if (parent !== realpathSync(parent) || !metadata.isDirectory() || metadata.uid !== process.getuid() || (metadata.mode & 0o022) ||
      path !== join(parent, path.slice(parent.length + 1)) || !outside(relative(root, path))) reject('PRIVATE_EXTERNAL_EVIDENCE_PARENT_REQUIRED')
  try {lstatSync(path); reject('EVIDENCE_DIRECTORY_MUST_BE_NEW')} catch (error) {if (error.code !== 'ENOENT') throw error}
  const parentIdentity = lstatSync(parent, {bigint: true})
  mkdirSync(path, {mode: 0o700})
  const current = lstatSync(path)
  if (realpathSync(path) !== path || current.uid !== process.getuid() || (current.mode & 0o077)) reject('PRIVATE_EXTERNAL_EVIDENCE_DIRECTORY_REQUIRED')
  const binding = {path, parent, parentIdentity, identity: lstatSync(path, {bigint: true})}
  assertEvidence(binding)
  return binding
}

function assertEvidence(binding) {
  try {
    const parent = lstatSync(binding.parent, {bigint: true}), current = lstatSync(binding.path, {bigint: true})
    if (!parent.isDirectory() || !current.isDirectory() || realpathSync(binding.parent) !== binding.parent ||
        realpathSync(binding.path) !== binding.path || !sameDirectory(parent, binding.parentIdentity) ||
        !sameDirectory(current, binding.identity) || parent.uid !== BigInt(process.getuid()) || current.uid !== BigInt(process.getuid()) ||
        (parent.mode & 0o022n) || (current.mode & 0o077n)) reject('EVIDENCE_CHANGED')
  } catch {reject('EVIDENCE_CHANGED')}
}

function runChild(command, args, {cwd, home, tmp, timeoutMs, signal, requiresPython}) {
  return new Promise(resolve => {
    let child, done = false, reason, exit, total = 0, stdout = [], stderr = [], timer, escalation, drain
    const finish = completion => {
      if (done) return
      done = true
      clearTimeout(timer); clearTimeout(escalation); clearTimeout(drain)
      signal?.removeEventListener('abort', cancel)
      child?.stdout?.destroy(); child?.stderr?.destroy()
      resolve({completion, reason, code: exit?.code ?? null, signal: exit?.signal ?? null,
        stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8')})
    }
    const terminate = why => {
      if (done) return
      reason ??= why
      if (exit) {finish('OUTPUT_DRAIN_UNKNOWN'); return}
      child?.kill('SIGTERM')
      if (done) return
      escalation ??= setTimeout(() => {
        if (done) return
        if (!exit) child?.kill('SIGKILL')
        if (done) return
        drain ??= setTimeout(() => finish(exit ? 'OUTPUT_DRAIN_UNKNOWN' : 'DIRECT_CHILD_EXIT_UNCONFIRMED'), 500)
      }, 500)
    }
    const cancel = () => terminate('CANCELLED')
    if (signal?.aborted) {reason = 'CANCELLED'; finish('NOT_STARTED'); return}
    const capture = (parts, chunk) => {
      const remaining = OUTPUT_BYTES - total, copied = chunk.subarray(0, Math.max(0, remaining))
      if (copied.length) {parts.push(Buffer.from(copied)); total += copied.length}
      if (chunk.length > remaining) terminate('OUTPUT_LIMIT_EXCEEDED')
    }
    try {
      child = spawn(command, args, {cwd, shell: false, detached: false,
        env: {PATH: dirname(realpathSync(process.execPath)) + ':/usr/bin:/bin:/usr/local/bin', HOME: home, TMPDIR: tmp,
          LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', AUKORA_PRIME_PAID_INFERENCE: 'disabled', AUKORA_PRIME_GPU: 'disabled',
          ...(requiresPython ? {PRIME_OPS_PYTHON: '/usr/bin/python3'} : {})},
        stdio: ['ignore', 'pipe', 'pipe']})
    } catch {reason = 'SPAWN_UNAVAILABLE'; finish('NOT_STARTED'); return}
    child.stdout.on('data', chunk => capture(stdout, chunk)); child.stderr.on('data', chunk => capture(stderr, chunk))
    child.on('error', () => {
      if (child.pid) {reason ??= 'OWNED_CHILD_SIGNAL_UNCONFIRMED'; finish('DIRECT_CHILD_EXIT_UNCONFIRMED')}
      else {reason = 'SPAWN_UNAVAILABLE'; finish('NOT_STARTED')}
    })
    child.on('exit', (code, signal) => {
      exit = {code, signal}
      drain ??= setTimeout(() => {reason ??= 'OUTPUT_DRAIN_INCOMPLETE'; finish('OUTPUT_DRAIN_UNKNOWN')}, 500)
    })
    child.on('close', () => finish('DIRECT_CHILD_CLOSED'))
    signal?.addEventListener('abort', cancel, {once: true})
    timer = setTimeout(() => terminate('CASE_TIMEOUT'), timeoutMs)
    if (signal?.aborted) cancel()
  })
}

function tapResult(text, row) {
  const lines = text.split(/\r?\n/), leaves = [], plans = []
  for (const line of lines) {
    const assertion = /^(\s*)(not ok|ok) (\d+)(?: -)? (.*)$/.exec(line)
    if (assertion && !assertion[1]) leaves.push({number: Number(assertion[3]), passed: assertion[2] === 'ok', title: assertion[4], skipped: /\s#\s*(?:SKIP|TODO)\b/i.test(assertion[4])})
    const plan = /^1\.\.(\d+)\s*$/.exec(line)
    if (plan) plans.push(Number(plan[1]))
  }
  if (lines.some(line => /^\s*Bail out!/i.test(line))) return {status: 'FAIL', reason: 'TAP_BAIL_OUT'}
  if (row.requireComplete) {
    if (lines.some(line => /^\s*(?:not ok|ok) \d+.*\s#\s*(?:SKIP|TODO)\b/i.test(line)))
      return {status: 'FAIL', reason: 'TAP_REQUIRED_TEST_SKIPPED_OR_TODO'}
    if (lines.some(line => /^\s*not ok \d+(?: -)? /.test(line)))
      return {status: 'FAIL', reason: 'TAP_ASSERTION_FAILED'}
    const counts = {}
    for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
      const values = lines.map(line => new RegExp('^# ' + name + ' (\\d+)$').exec(line)).filter(Boolean)
      if (values.length !== 1) return {status: 'FAIL', reason: 'TAP_REQUIRED_COUNTS_MISSING'}
      counts[name] = Number(values[0][1])
      if (!Number.isSafeInteger(counts[name]) || counts[name] < 0)
        return {status: 'FAIL', reason: 'TAP_REQUIRED_COUNTS_MISSING'}
    }
    if (counts.skipped || counts.todo) return {status: 'FAIL', reason: 'TAP_REQUIRED_TEST_SKIPPED_OR_TODO'}
    if (counts.fail || counts.cancelled || !counts.tests || counts.tests < leaves.length || counts.pass !== counts.tests)
      return {status: 'FAIL', reason: 'TAP_REQUIRED_TESTS_INCOMPLETE'}
  }
  if (plans.length !== 1 || plans[0] !== leaves.length || !leaves.length ||
      leaves.some((value, index) => value.number !== index + 1)) return {status: 'FAIL', reason: 'TAP_INCOMPLETE'}
  if (leaves.some(value => !value.passed && !value.skipped)) return {status: 'FAIL', reason: 'TAP_ASSERTION_FAILED'}
  const completed = leaves.filter(value => value.passed && !value.skipped)
  if (completed.length < row.minTests || !completed.some(value => value.title === row.expectedTitle)) return {status: 'FAIL', reason: 'TAP_SELECTED_TEST_MISSING'}
  return {status: 'PASS', reason: 'ASSERTIONS_COMPLETED', test_count: completed.length}
}

function jsonAssertionsResult(text) {
  let value
  try {value = JSON.parse(text.trim().split(/\r?\n/).at(-1))}
  catch {return {status: 'FAIL', reason: 'ASSERTION_SUMMARY_MISSING'}}
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !['result', 'status'].some(key => value[key] === 'PASS') ||
      ['result', 'status'].some(key => value[key] !== undefined && value[key] !== 'PASS') ||
      !['checks', 'cases', 'groups', 'assertions'].some(key => Number.isSafeInteger(value[key]) && value[key] > 0))
    return {status: 'FAIL', reason: 'ASSERTION_SUMMARY_INCOMPLETE'}
  if (['skip', 'skipped', 'todo', 'fail', 'failed', 'cancelled'].some(key => value[key] !== undefined && value[key] !== 0) ||
      (value.failures !== undefined && (!Array.isArray(value.failures) || value.failures.length)))
    return {status: 'FAIL', reason: 'ASSERTION_REQUIRED_TESTS_INCOMPLETE'}
  return {status: 'PASS', reason: 'ASSERTIONS_COMPLETED'}
}

/** Uses only the reviewed compiled manifest. Raw output is neither returned nor saved. */
export async function runFastVerify(options) {
  const started = performance.now(), records = []
  const result = {schema: 'prime-fast-verify/v1', status: 'UNPERFORMED', exit_code: 2, cases: records,
    qualification: 'UNPERFORMED', g1: 'PENDING', historical: HISTORY, unperformed: UNPERFORMED,
    source_review_commit: SOURCE_REVIEW_COMMIT, source_review_attribution: 'LITERAL_ENTRY_PINS_NOT_CHECKOUT_ATTESTATION',
    node: {version: process.version, executable: process.execPath, pin_verification: 'OBSERVED_ONLY'},
    budget: {suite_ms: SUITE_MS, wall_target_ms: 180_000, wall_limit_enforcement: 'COOPERATIVE_NOT_KERNEL_ENFORCED', cleanup_guarantee: 'COOPERATIVE_DIRECT_CHILD_ONLY'},
    descendant_cleanup: 'UNPERFORMED', source_pin_scope: 'COMPILED_ENTRYPOINTS_AND_LITERAL_SUPPORT_PINS',
    scratch_retention: 'PRIVATE_DISPOSABLE_DIRECTORIES_RETAINED'}
  let evidence, evidenceBinding, codeBefore, plan = []
  try {
    if (!options || Object.keys(options).some(key => !['root', 'evidenceDir', 'json', 'signal'].includes(key)) ||
        (options.json !== undefined && typeof options.json !== 'boolean') ||
        (options.signal !== undefined && !(options.signal instanceof AbortSignal))) reject('CLOSED_ENGINE_OPTIONS_REQUIRED')
    if (version !== '24.11.1' || process.version !== 'v' + version) reject('PINNED_NODE_VERSION_REQUIRED')
    const root = sourceRoot(options.root), cases = compiledCases(root)
    plan = cases
    result.configured_case_count = cases.length
    const enginePath = fileURLToPath(import.meta.url), manifestPath = join(dirname(enginePath), 'manifest.mjs')
    codeBefore = await Promise.all([filePin(enginePath, ENTRY_BYTES), filePin(manifestPath, ENTRY_BYTES)])
    result.evaluator = {engine_sha256: codeBefore[0].digest, manifest_sha256: codeBefore[1].digest,
      identity_scope: 'OBSERVED_DISK_BYTES', os_independence: 'NOT_ESTABLISHED'}
    result.node.observed_sha256 = (await filePin(realpathSync(process.execPath), 268_435_456)).digest
    evidenceBinding = newEvidence(root, options.evidenceDir)
    evidence = evidenceBinding.path
    const deadline = started + SUITE_MS
    let stop = false
    for (const row of cases) {
      const record = {id: row.id, property: row.property, required_full_file: row.requireComplete === true, status: 'UNPERFORMED', descendant_cleanup: 'UNPERFORMED'}
      records.push(record)
      if (row.unsupportedReason) {record.reason = row.unsupportedReason; continue}
      if (stop || options.signal?.aborted || performance.now() >= deadline) {
        record.reason = options.signal?.aborted ? 'CANCELLED' : stop ? 'EARLIER_EXECUTION_INCOMPLETE' : 'SUITE_BUDGET_EXHAUSTED'; continue
      }
      let before, supportPins
      try {
        if (realpathSync(row.absoluteEntry) !== row.absoluteEntry) reject('CHECK_ENTRY_MUST_BE_PHYSICAL')
        before = await filePin(row.absoluteEntry, ENTRY_BYTES)
        record.entry_sha256 = before.digest
        if (before.digest !== row.expectedSha256) reject('UNREVIEWED_CHECK_SOURCE')
        supportPins = []
        for (const pin of row.pins) {
          if (realpathSync(pin.absolutePath) !== pin.absolutePath) reject('CHECK_ENTRY_MUST_BE_PHYSICAL')
          const observed = await filePin(pin.absolutePath, ENTRY_BYTES)
          if (observed.digest !== pin.sha256) reject('UNREVIEWED_SUPPORT_SOURCE')
          supportPins.push({...pin, identity: observed.identity})
        }
      } catch (error) {
        record.reason = ['CHECK_ENTRY_MUST_BE_PHYSICAL', 'UNREVIEWED_CHECK_SOURCE', 'UNREVIEWED_SUPPORT_SOURCE', 'SOURCE_CHANGED', 'SOURCE_FILE_NOT_REGULAR_OR_BOUNDED'].includes(error.message) ? error.message : 'CHECK_SOURCE_UNAVAILABLE'; continue
      }
      if (options.signal?.aborted || performance.now() >= deadline) {record.reason = options.signal?.aborted ? 'CANCELLED' : 'SUITE_BUDGET_EXHAUSTED'; stop = true; continue}
      const scratch = join(evidence, row.id), home = join(scratch, 'home'), tmp = join(scratch, 'tmp')
      assertEvidence(evidenceBinding); mkdirSync(scratch, {mode: 0o700})
      assertEvidence(evidenceBinding); mkdirSync(home, {mode: 0o700})
      assertEvidence(evidenceBinding); mkdirSync(tmp, {mode: 0o700})
      const caseStarted = performance.now()
      if (row.requiresPython) {
        let probe
        try {
          const path = '/usr/bin/python3', physical = realpathSync(path)
          if (CONTROLS.test(physical)) reject('PYTHON_STDLIB_PREREQUISITE_MISSING')
          const observed = await filePin(physical, 268_435_456)
          if (options.signal?.aborted || performance.now() >= deadline) {
            record.reason = options.signal?.aborted ? 'CANCELLED' : 'SUITE_BUDGET_EXHAUSTED'; stop = true; continue
          }
          assertEvidence(evidenceBinding)
          probe = await runChild(path, ['-I', '-B', '-c',
            'import json,sys;print(json.dumps([sys.version_info.major,sys.version_info.minor]));sys.exit(0 if sys.version_info >= (3,9) else 1)'],
            {cwd: root, home, tmp, timeoutMs: Math.max(1, Math.min(2000, Math.floor(deadline - performance.now()))), signal: options.signal})
          assertEvidence(evidenceBinding)
          if (probe.reason || probe.completion !== 'DIRECT_CHILD_CLOSED' || probe.code !== 0) reject('PYTHON_STDLIB_PREREQUISITE_MISSING')
          const numbers = JSON.parse(probe.stdout)
          if (!Array.isArray(numbers) || numbers.length !== 2 || numbers.some(value => !Number.isInteger(value)) ||
              numbers[0] < 3 || (numbers[0] === 3 && numbers[1] < 9)) reject('PYTHON_STDLIB_PREREQUISITE_MISSING')
          result.python = {path, major: numbers[0], minor: numbers[1], observed_sha256: observed.digest, pin_verification: 'OBSERVED_ONLY'}
        } catch (error) {
          if (error.message === 'EVIDENCE_CHANGED') throw error
          record.reason = 'PYTHON_STDLIB_PREREQUISITE_MISSING'
          if (probe && (probe.reason || probe.completion !== 'DIRECT_CHILD_CLOSED')) stop = true
          continue
        }
      }
      if (options.signal?.aborted || performance.now() >= deadline) {record.reason = options.signal?.aborted ? 'CANCELLED' : 'SUITE_BUDGET_EXHAUSTED'; stop = true; continue}
      assertEvidence(evidenceBinding)
      const execution = await runChild(process.execPath, [...(row.nodeArgs ?? []), row.absoluteEntry, ...row.args], {cwd: root, home, tmp,
        timeoutMs: Math.max(1, Math.min(row.timeoutMs, Math.floor(deadline - performance.now()))), signal: options.signal, requiresPython: row.requiresPython})
      assertEvidence(evidenceBinding)
      record.duration_ms = Math.round(performance.now() - caseStarted); record.completion = execution.completion
      if (execution.reason || execution.completion !== 'DIRECT_CHILD_CLOSED') {
        record.reason = execution.reason ?? 'EXECUTION_INCOMPLETE'; stop = true; continue
      }
      try {
        const after = await filePin(row.absoluteEntry, ENTRY_BYTES)
        if (after.digest !== row.expectedSha256 || !same(before.identity, after.identity)) reject('SOURCE_CHANGED')
        for (const pin of supportPins) {
          const observed = await filePin(pin.absolutePath, ENTRY_BYTES)
          if (observed.digest !== pin.sha256 || !same(pin.identity, observed.identity)) reject('SOURCE_CHANGED')
        }
      } catch {record.reason = 'SOURCE_CHANGED'; stop = true; continue}
      if (execution.code !== 0) {
        if (!execution.stderr.includes('AssertionError') &&
            /(?:^|\n)Error(?: \[ERR_MODULE_NOT_FOUND\])?: Cannot find (?:module|package)\b/.test(execution.stderr) &&
            /\bcode: ['"](?:ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND)['"]/.test(execution.stderr)) {
          record.reason = 'DEPENDENCY_UNAVAILABLE'; continue
        }
        record.status = 'FAIL'; record.reason = 'ASSERTION_PROCESS_FAILED'; continue
      }
      Object.assign(record, row.protocol === 'tap' ? tapResult(execution.stdout, row) : row.protocol === 'json-assertions' ? jsonAssertionsResult(execution.stdout) : {status: 'PASS', reason: 'ASSERTIONS_COMPLETED'})
    }
    result.status = records.some(row => row.status === 'FAIL') ? 'FAIL' : records.every(row => row.status === 'PASS') ? 'PASS' : 'UNPERFORMED'
    result.exit_code = result.status === 'PASS' ? 0 : result.status === 'FAIL' ? 1 : 2
    const codeAfter = await Promise.all([filePin(enginePath, ENTRY_BYTES), filePin(manifestPath, ENTRY_BYTES)])
    if (codeAfter.some((value, index) => value.digest !== codeBefore[index].digest || !same(value.identity, codeBefore[index].identity))) reject('EVALUATOR_SOURCE_CHANGED')
  } catch (error) {
    const known = ['CLOSED_ENGINE_OPTIONS_REQUIRED', 'PINNED_NODE_VERSION_REQUIRED', 'CANONICAL_SOURCE_ROOT_REQUIRED', 'INVALID_COMPILED_MANIFEST',
      'CANONICAL_NEW_EVIDENCE_DIRECTORY_REQUIRED', 'PRIVATE_EXTERNAL_EVIDENCE_PARENT_REQUIRED', 'EVIDENCE_DIRECTORY_MUST_BE_NEW',
      'PRIVATE_EXTERNAL_EVIDENCE_DIRECTORY_REQUIRED', 'SOURCE_CHANGED', 'SOURCE_FILE_NOT_REGULAR_OR_BOUNDED', 'EVALUATOR_SOURCE_CHANGED', 'EVIDENCE_CHANGED']
    result.reason = known.includes(error.message) ? error.message : 'ENGINE_PREREQUISITE_UNAVAILABLE'
    result.status = 'UNPERFORMED'; result.exit_code = 2
    if (error.message === 'EVIDENCE_CHANGED' && records.at(-1)?.status === 'UNPERFORMED') records.at(-1).reason = 'EVIDENCE_CHANGED'
    for (const row of plan) {
      if (!records.some(record => record.id === row.id)) records.push({id: row.id, property: row.property,
        status: 'UNPERFORMED', reason: row.unsupportedReason ?? 'EARLIER_EXECUTION_INCOMPLETE', descendant_cleanup: 'UNPERFORMED'})
    }
    if (error.message !== 'EVIDENCE_CHANGED' && records.some(row => row.status === 'FAIL')) {result.status = 'FAIL'; result.exit_code = 1}
  }
  result.duration_ms = Math.round(performance.now() - started)
  result.case_count = records.length
  result.counts = {pass: records.filter(row => row.status === 'PASS').length, fail: records.filter(row => row.status === 'FAIL').length,
    unperformed: records.filter(row => row.status === 'UNPERFORMED').length}
  result.run_id = randomUUID()
  if (evidence && result.reason !== 'EVIDENCE_CHANGED') {
    try {
      assertEvidence(evidenceBinding)
      result.evidence_path = join(evidence, 'summary.json')
      writeFileSync(result.evidence_path, JSON.stringify(result, null, 2) + '\n', {flag: 'wx', mode: 0o600})
      assertEvidence(evidenceBinding)
    } catch (error) {
      result.status = error.message !== 'EVIDENCE_CHANGED' && result.status === 'FAIL' ? 'FAIL' : 'UNPERFORMED'
      result.exit_code = result.status === 'FAIL' ? 1 : 2
      result.reason = error.message === 'EVIDENCE_CHANGED' ? 'EVIDENCE_CHANGED' : 'EVIDENCE_WRITE_INCOMPLETE'
      delete result.evidence_path
    }
  }
  return result
}
