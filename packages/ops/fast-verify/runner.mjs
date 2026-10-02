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
const SUITE_MS = 600_000, CASE_MS = 120_000, ORDINARY_CASE_MS = 60_000, AUTHORITY_CORE_MS = 180_000, OUTPUT_BYTES = 65_536, ENTRY_BYTES = 1_048_576
const outside = value => value === '..' || value.startsWith('..' + sep) || isAbsolute(value)
const reject = reason => {throw new Error(reason)}
const same = (a, b) => ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key])
const sameDirectory = (a, b) => ['dev', 'ino', 'uid', 'gid', 'mode'].every(key => a[key] === b[key])
const safePath = value => typeof value === 'string' && value.length > 0 && !CONTROLS.test(value)
const relativePath = value => safePath(value) && !isAbsolute(value) && !value.includes('\\') &&
  value.split('/').every(part => part && part !== '.' && part !== '..')
const literal = value => safePath(value) && value.length <= 1000 && value.trim() === value
const reasonCode = value => typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,119}$/.test(value)
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const exactKeys = (value, keys) => object(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',')
const titles = value => Array.isArray(value) && value.length > 0 && value.length <= 10_000 &&
  value.every(literal) && new Set(value).size === value.length
const version = String(NODE_VERSION).replace(/^v/, '')
// This fixed probe receives only the compiled, byte-verified controller path.
const HOOK_ASSERTION = "import assert from 'node:assert/strict';import {pathToFileURL} from 'node:url';" +
  "const mod=await import(pathToFileURL(process.argv[1]).href);assert.equal(typeof mod.createPrimeOwnerController,'function');" +
  "let controller;try{controller=mod.createPrimeOwnerController({schedule:()=>null,unschedule:()=>{}});" +
  "assert.equal(typeof controller?.setApprovalAction,'function');assert.equal(typeof controller?.submitApproval,'function');" +
  "assert.equal(typeof controller?.dispose,'function')}finally{if(typeof controller?.dispose==='function')controller.dispose()}"

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

const authorityCoreBudget = row => row.id === 'authority-core-only' && row.entry === 'packages/authority/check.mjs' &&
  row.expectedSha256 === 'a745a3b8ab6b8ebb182a6322577b10ec845f0af027120cc7dbd15d41a7666cfe' &&
  row.protocol === 'assert-json' && row.args?.length === 1 && row.args[0] === 'core-only' &&
  row.nodeArgs?.length === 1 && row.nodeArgs[0] === '--max-old-space-size=512' &&
  exactKeys(row.counter, ['key', 'value']) && row.counter.key === 'checks' && row.counter.value === 125

// Test-only socket binding for one reviewed job; never inherited from callers.
const workerSocketBinding = row => row.id === 'bridge-worker' &&
  row.entry === 'packages/runtime-bridge/test/worker.test.mjs' &&
  row.expectedSha256 === '5618b402ba9abdfbbc7389d512997f3d7efef5d13220994a3b5717dd66ec3289' &&
  row.protocol === 'tap' && row.args?.length === 0 &&
  JSON.stringify(row.nodeArgs) === JSON.stringify(['--max-old-space-size=512', '--test', '--test-isolation=none', '--test-reporter=tap']) &&
  JSON.stringify(row.requiredTitles) === JSON.stringify([
    'worker and synthetic client refuse readable secret-bearing config before importing it',
    'actual separate C/D worker processes preserve real passkey + locked observation + save/settle/cited restart; no PG or UID proof']) &&
  row.pins?.length === 1 && row.pins[0].path === 'packages/runtime-bridge/test/worker-fixture-paths.mjs' &&
  row.pins[0].sha256 === '1ae49843e6a11de817ba3100a2a152081332f6a2c07c67d81aa77d0d25a4b105'

function compiledCases(root) {
  if (!Array.isArray(CASES) || CASES.length < 1 || CASES.length > 66) reject('INVALID_COMPILED_MANIFEST')
  const ids = new Set()
  return CASES.map(row => {
    if (!object(row) || typeof row.id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,79}$/.test(row.id) || ids.has(row.id) ||
        typeof row.property !== 'string' || !row.property.length || row.property.length > 200 || CONTROLS.test(row.property)) reject('INVALID_COMPILED_MANIFEST')
    ids.add(row.id)
    if (Object.hasOwn(row, 'unsupportedReason')) {
      if (Object.keys(row).some(key => !['id', 'property', 'unsupportedReason', 'args', 'nodeArgs', 'pins'].includes(key)) ||
          ['args', 'nodeArgs', 'pins'].some(key => row[key] !== undefined && (!Array.isArray(row[key]) || row[key].length)) ||
          !reasonCode(row.unsupportedReason)) reject('INVALID_COMPILED_MANIFEST')
      return {...row}
    }
    const protocolKeys = {'assert-script': [], tap: ['requiredTitles', 'externalSkips'],
      'pass-lines': ['requiredLabels', 'summaryLine'], 'assert-json': ['counter']}
    if (typeof row.protocol !== 'string' || !Object.hasOwn(protocolKeys, row.protocol)) reject('INVALID_COMPILED_MANIFEST')
    const allowed = ['id', 'property', 'entry', 'args', 'nodeArgs', 'expectedSha256', 'timeoutMs', 'protocol', 'pins',
      'requiresPython', 'hookController', 'hostRoot', 'syntheticSourcePin', ...(protocolKeys[row.protocol] ?? [])]
    if (Object.keys(row).some(key => !allowed.includes(key)) || !relativePath(row.entry) ||
        !Array.isArray(row.args) || row.args.length > 64 || row.args.some(value => !literal(value)) ||
        (row.nodeArgs !== undefined && (!Array.isArray(row.nodeArgs) || row.nodeArgs.length > 64 || row.nodeArgs.some(value => !literal(value)))) ||
        [...row.args, ...(row.nodeArgs ?? [])].some(value => /^--test-(?:(?:name|skip)-pattern|only)(?:=|$)/.test(value)) ||
        !digest(row.expectedSha256) || !Number.isInteger(row.timeoutMs) || row.timeoutMs < 1 ||
        row.timeoutMs > (authorityCoreBudget(row) ? AUTHORITY_CORE_MS : row.protocol === 'tap' ? CASE_MS : ORDINARY_CASE_MS) ||
        (row.requiresPython !== undefined && typeof row.requiresPython !== 'boolean') ||
        (row.hostRoot !== undefined && row.hostRoot !== true) ||
        (row.syntheticSourcePin !== undefined && row.syntheticSourcePin !== true)) reject('INVALID_COMPILED_MANIFEST')
    if (row.protocol === 'tap') {
      if (!titles(row.requiredTitles) || (row.externalSkips !== undefined && (!Array.isArray(row.externalSkips) ||
          row.externalSkips.length + row.requiredTitles.length > 10_000))) reject('INVALID_COMPILED_MANIFEST')
      const declared = new Set(row.requiredTitles)
      for (const skip of row.externalSkips ?? []) {
        if (!exactKeys(skip, ['title', 'reason']) || !literal(skip.title) || !literal(skip.reason) || declared.has(skip.title)) reject('INVALID_COMPILED_MANIFEST')
        declared.add(skip.title)
      }
    }
    if (row.protocol === 'pass-lines' && (!titles(row.requiredLabels) ||
        (row.summaryLine !== undefined && (!literal(row.summaryLine) || /^FAIL(?:[ \t]|$)/.test(row.summaryLine) ||
          row.requiredLabels.some(label => row.summaryLine === 'PASS ' + label))))) reject('INVALID_COMPILED_MANIFEST')
    if (row.protocol === 'assert-json' && (!exactKeys(row.counter, ['key', 'value']) ||
        !['checks', 'cases', 'assertions', 'groups'].includes(row.counter.key) ||
        !Number.isInteger(row.counter.value) || row.counter.value < 1 || row.counter.value > 10_000)) reject('INVALID_COMPILED_MANIFEST')
    const entry = join(root, row.entry)
    if (outside(relative(root, entry))) reject('INVALID_COMPILED_MANIFEST')
    if (row.pins !== undefined && (!Array.isArray(row.pins) || row.pins.length > 12)) reject('INVALID_COMPILED_MANIFEST')
    const pins = (row.pins ?? []).map(pin => {
      if (!exactKeys(pin, ['path', 'sha256']) || !relativePath(pin.path) || !digest(pin.sha256)) reject('INVALID_COMPILED_MANIFEST')
      return {...pin, absolutePath: join(root, pin.path)}
    })
    let hookController
    if (row.hookController !== undefined) {
      if (!exactKeys(row.hookController, ['path', 'sha256']) || !relativePath(row.hookController.path) || !digest(row.hookController.sha256)) reject('INVALID_COMPILED_MANIFEST')
      hookController = {...row.hookController, absolutePath: join(root, row.hookController.path)}
    }
    return {...row, absoluteEntry: entry, pins, ...(hookController ? {hookController} : {})}
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

function runChild(command, args, {cwd, home, tmp, timeoutMs, signal, requiresPython, hookControllerPath, hostRoot, syntheticSourcePin, workerSocketRoot}) {
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
          ...(requiresPython ? {PRIME_OPS_PYTHON: '/usr/bin/python3'} : {}),
          ...(hookControllerPath ? {PRIME_OWNER_HOOK_CONTROLLER: hookControllerPath} : {}),
          ...(hostRoot ? {PRIME_OWNER_MEMORY_HOST_ROOT: hostRoot} : {}),
          ...(syntheticSourcePin ? {PRIME_OWNER_MEMORY_SOURCE_PIN: '0'.repeat(40)} : {}),
          ...(workerSocketRoot ? {PRIME_BRIDGE_WORKER_SOCKET_ROOT: workerSocketRoot} : {})},
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
  const lines = text.split(/\r?\n/), assertions = [], plans = [], external = row.externalSkips ?? []
  let nested = false, malformed = false, planDirective = false
  for (const line of lines) {
    const assertion = /^([ \t]*)(not ok|ok) (\d+)(?:(?: -)? (.*))?$/.exec(line)
    if (assertion) {
      const title = assertion[4] ?? ''
      const directive = /^(?:(.*?)\s+)?#\s*(SKIP|TODO)\b(?:[ \t]+(.*))?$/i.exec(title)
      assertions.push({number: Number(assertion[3]), passed: assertion[2] === 'ok',
        title: directive ? directive[1] ?? '' : title, directive: directive?.[2].toUpperCase(),
        directiveReason: directive?.[3] ?? '', nested: Boolean(assertion[1])})
      nested ||= Boolean(assertion[1])
    } else if (/^[ \t]*(?:not ok|ok)(?:[ \t]|$)/.test(line)) malformed = true
    const plan = /^([ \t]*)1\.\.(\d+)(?:[ \t]+(.*))?$/.exec(line)
    if (plan) {
      nested ||= Boolean(plan[1]); planDirective ||= /#\s*(?:SKIP|TODO)\b/i.test(plan[3] ?? '')
      if (plan[3]?.trim() && !plan[3].startsWith('#')) malformed = true
      if (!plan[1]) plans.push(Number(plan[2]))
    } else if (/^[ \t]*1\.\./.test(line)) malformed = true
  }
  const known = [...row.requiredTitles, ...external.map(value => value.title)], knownSet = new Set(known)
  const requiredSet = new Set(row.requiredTitles), externalSet = new Set(external.map(value => value.title))
  const externalByTitle = new Map(external.map(value => [value.title, value]))
  const occurrences = title => assertions.filter(value => value.title === title)
  const failed = assertions.filter(value => !value.passed || value.directive === 'TODO' ||
    (value.directive === 'SKIP' && !externalSet.has(value.title)) ||
    (externalSet.has(value.title) && (value.directive !== 'SKIP' || value.directiveReason !== externalByTitle.get(value.title).reason)))
  const externalSkips = external.flatMap(value => {
    const skipped = occurrences(value.title).filter(assertion => assertion.directive === 'SKIP')
    return skipped.length ? [{title: value.title, reason: value.reason, reason_matches: skipped.every(assertion => assertion.directiveReason === value.reason),
      status: 'UNPERFORMED', count: skipped.length}] : []
  })
  const passedRequired = assertions.filter(value => requiredSet.has(value.title) && value.passed && !value.directive).length
  const report = {status: 'FAIL', functional_status: 'FAIL', observed_test_count: assertions.length,
    test_count: passedRequired, expected_test_count: known.length, required_test_count: row.requiredTitles.length,
    failed_titles: known.filter(title => failed.some(value => value.title === title)),
    unknown_title_count: assertions.filter(value => !knownSet.has(value.title)).length,
    unknown_failed_count: failed.filter(value => !knownSet.has(value.title)).length,
    skipped_count: assertions.filter(value => value.directive === 'SKIP').length,
    required_skipped_count: assertions.filter(value => value.directive === 'SKIP' && requiredSet.has(value.title)).length,
    external_unperformed_count: externalSkips.reduce((count, value) => count + value.count, 0), external_skips: externalSkips}
  const fail = reason => ({...report, reason})
  if (lines.some(line => /^[ \t]*Bail out!/i.test(line))) return fail('TAP_BAIL_OUT')
  if (assertions.some(value => value.directive === 'TODO')) return fail('TAP_TODO_FORBIDDEN')
  if (assertions.some(value => value.directive === 'SKIP' && (!value.passed || !externalSet.has(value.title)))) return fail('TAP_UNDECLARED_SKIP')
  if (assertions.some(value => value.directive === 'SKIP' && externalSet.has(value.title) && value.directiveReason !== externalByTitle.get(value.title).reason)) return fail('TAP_EXTERNAL_SKIP_REASON_MISMATCH')
  if (planDirective) return fail('TAP_PLAN_DIRECTIVE_FORBIDDEN')
  // The reviewed profile is flat TAP. Nested assertions/plans cannot disappear.
  if (nested) return fail('TAP_NESTING_UNSUPPORTED')
  if (malformed) return fail('TAP_MALFORMED_ASSERTION_OR_PLAN')
  if (plans.length !== 1 || plans[0] !== assertions.length || !assertions.length ||
      assertions.some((value, index) => value.number !== index + 1)) return fail('TAP_INCOMPLETE')
  if (new Set(assertions.map(value => value.title)).size !== assertions.length) return fail('TAP_DUPLICATE_TITLE')
  if (assertions.length !== known.length || report.unknown_title_count || known.some(title => occurrences(title).length !== 1)) return fail('TAP_TITLE_INVENTORY_MISMATCH')
  if (assertions.some(value => externalSet.has(value.title) && value.directive !== 'SKIP')) return fail('TAP_EXTERNAL_TEST_NOT_SKIPPED')
  if (failed.length) return fail('TAP_ASSERTION_FAILED')
  const summary = {}
  for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const selected = lines.filter(line => new RegExp('^# ' + name + '(?:[ \\t]|$)').test(line))
    if (selected.length !== 1) return fail('TAP_REQUIRED_COUNTS_MISSING')
    const match = new RegExp('^# ' + name + ' (\\d+)$').exec(selected[0])
    const count = match ? Number(match[1]) : null
    if (count === null || !Number.isSafeInteger(count) || count < 0 || count > 10_000) return fail('TAP_REQUIRED_COUNTS_MISSING')
    summary[name] = count
  }
  report.tap_summary = summary
  if (summary.fail || summary.cancelled || summary.todo) return fail('TAP_REQUIRED_TESTS_INCOMPLETE')
  if (summary.tests !== known.length || summary.pass !== known.length - report.skipped_count ||
      summary.skipped !== report.skipped_count || summary.skipped !== report.external_unperformed_count) return fail('TAP_SUMMARY_COUNTS_MISMATCH')
  return {...report, status: report.external_unperformed_count ? 'UNPERFORMED' : 'PASS', functional_status: 'PASS',
    reason: report.external_unperformed_count ? 'DECLARED_EXTERNAL_TESTS_UNPERFORMED' : 'ASSERTIONS_COMPLETED'}
}

function passLinesResult(text, row) {
  const passed = [], failed = [], lines = text.split(/\r?\n/)
  let summaries = 0
  for (const line of lines) {
    if (line === row.summaryLine) {summaries++; continue}
    const assertion = /^(PASS|FAIL)(?:[ \t]+(.*))?$/.exec(line)
    if (assertion) (assertion[1] === 'PASS' ? passed : failed).push(assertion[2] ?? '')
  }
  const known = new Set(row.requiredLabels)
  const report = {status: 'FAIL', functional_status: 'FAIL', observed_test_count: passed.length + failed.length,
    test_count: passed.filter(label => known.has(label)).length, required_test_count: row.requiredLabels.length,
    failed_titles: row.requiredLabels.filter(label => failed.includes(label)),
    unknown_title_count: [...passed, ...failed].filter(label => !known.has(label)).length,
    unknown_failed_count: failed.filter(label => !known.has(label)).length}
  if (failed.length) return {...report, reason: 'PASS_LABEL_ASSERTION_FAILED'}
  if ((row.summaryLine !== undefined && summaries !== 1) || passed.length !== row.requiredLabels.length ||
      new Set(passed).size !== passed.length || report.unknown_title_count || row.requiredLabels.some(label => !passed.includes(label))) return {...report, reason: 'PASS_LABEL_INVENTORY_MISMATCH'}
  return {...report, status: 'PASS', functional_status: 'PASS', reason: 'ASSERTIONS_COMPLETED'}
}

function jsonResult(text, row) {
  let values
  try {values = [JSON.parse(text)]} catch {
    values = text.split(/\r?\n/).flatMap(line => {try {return [JSON.parse(line)]} catch {return []}})
  }
  const candidates = values.filter(value => object(value) && Object.hasOwn(value, row.counter.key))
  const observed = candidates.length === 1 && Number.isInteger(candidates[0][row.counter.key]) &&
    candidates[0][row.counter.key] >= 0 && candidates[0][row.counter.key] <= 10_000 ? candidates[0][row.counter.key] : null
  const report = {status: 'FAIL', functional_status: 'FAIL', counter: {key: row.counter.key, expected: row.counter.value, observed},
    observed_test_count: observed ?? 0, test_count: observed ?? 0, failed_titles: [], unknown_failed_count: 0}
  if (candidates.length !== 1 || observed !== row.counter.value) return {...report, reason: 'ASSERT_JSON_COUNTER_MISMATCH'}
  const summaries = values.filter(value => object(value) && ['result', 'status', 'checks', 'cases', 'assertions', 'groups'].some(key => Object.hasOwn(value, key)))
  if (summaries.length !== 1) return {...report, reason: 'ASSERT_JSON_SUMMARY_AMBIGUOUS'}
  const value = candidates[0]
  if (!['result', 'status'].some(key => value[key] === 'PASS') ||
      ['result', 'status'].some(key => value[key] !== undefined && value[key] !== 'PASS')) return {...report, reason: 'ASSERT_JSON_RESULT_NOT_PASS'}
  const pending = [...values]
  const negativeCounts = ['skip', 'skipped', 'todo', 'fail', 'failed', 'cancelled', 'canceled']
  const counters = ['checks', 'cases', 'groups', 'assertions', 'tests', 'pass', 'passed', ...negativeCounts]
  let visited = 0
  while (pending.length) {
    const item = pending.pop()
    if (++visited > 10_000) return {...report, reason: 'ASSERT_JSON_SUMMARY_UNBOUNDED'}
    if (['FAIL', 'FAILED', 'SKIP', 'SKIPPED', 'TODO', 'CANCELLED', 'CANCELED', 'UNPERFORMED'].includes(item)) return {...report, reason: 'ASSERT_JSON_REQUIRED_TESTS_INCOMPLETE'}
    if (!item || typeof item !== 'object') continue
    // Nested helper group names are annotations; the selected summary counter stays numeric.
    const ancillaryGroups = !values.includes(item) && Array.isArray(item.groups) &&
      item.groups.length > 0 && item.groups.length <= 1000 && item.groups.every(label => literal(label) &&
        !/^(?:#\s*)?(?:FAIL(?:ED)?|SKIP(?:PED)?|TODO|CANCEL(?:L)?ED|UNPERFORMED)(?:$|[\s:])/i.test(label))
    if (!Array.isArray(item) && (counters.some(key => Object.hasOwn(item, key) &&
        !(key === 'groups' && ancillaryGroups) &&
        (!Number.isSafeInteger(item[key]) || item[key] < 0 || item[key] > 10_000)) ||
        negativeCounts.some(key => Object.hasOwn(item, key) && item[key] !== 0) ||
        (Object.hasOwn(item, 'failures') && (!Array.isArray(item.failures) || item.failures.length)))) return {...report, reason: 'ASSERT_JSON_REQUIRED_TESTS_INCOMPLETE'}
    pending.push(...Object.values(item))
  }
  return {...report, status: 'PASS', functional_status: 'PASS', reason: 'ASSERTIONS_COMPLETED'}
}

function assertionResult(text, row) {
  if (row.protocol === 'tap') return tapResult(text, row)
  if (row.protocol === 'pass-lines') return passLinesResult(text, row)
  if (row.protocol === 'assert-json') return jsonResult(text, row)
  return {status: 'PASS', functional_status: 'PASS', reason: 'ASSERTIONS_COMPLETED'}
}

async function assertSources(row, before, supportPins, controllerPin) {
  const after = await filePin(row.absoluteEntry, ENTRY_BYTES)
  if (after.digest !== row.expectedSha256 || !same(before.identity, after.identity)) reject('SOURCE_CHANGED')
  for (const pin of supportPins) {
    const observed = await filePin(pin.absolutePath, ENTRY_BYTES)
    if (observed.digest !== pin.sha256 || !same(pin.identity, observed.identity)) reject('SOURCE_CHANGED')
  }
  if (controllerPin) {
    const observed = await filePin(row.hookController.absolutePath, ENTRY_BYTES)
    if (observed.digest !== row.hookController.sha256 || !same(controllerPin.identity, observed.identity)) reject('SOURCE_CHANGED')
  }
}

/** Uses only the reviewed compiled manifest. Raw output is neither returned nor saved. */
export async function runFastVerify(options) {
  const started = performance.now(), records = []
  const result = {schema: 'prime-fast-verify/v1', status: 'UNPERFORMED', exit_code: 2, cases: records,
    qualification: 'UNPERFORMED', g1: 'PENDING', historical: HISTORY, unperformed: UNPERFORMED,
    source_review_commit: SOURCE_REVIEW_COMMIT,
    source_review_attribution: 'LITERAL_ENTRY_PINS_NOT_CHECKOUT_ATTESTATION',
    node: {version: process.version, executable: process.execPath, pin_verification: 'OBSERVED_ONLY'},
    budget: {suite_ms: SUITE_MS, case_max_ms: AUTHORITY_CORE_MS, tap_case_max_ms: CASE_MS,
      authority_core_only_max_ms: AUTHORITY_CORE_MS, ordinary_case_max_ms: ORDINARY_CASE_MS,
      wall_target_ms: null, expected_full_profile_duration_ms: null, expected_full_profile_duration_status: 'NOT_MEASURED',
      wall_limit_enforcement: 'COOPERATIVE_NOT_KERNEL_ENFORCED', cleanup_guarantee: 'COOPERATIVE_DIRECT_CHILD_ONLY'},
    descendant_cleanup: 'UNPERFORMED', source_pin_scope: 'COMPILED_ENTRYPOINTS_LITERAL_SUPPORT_AND_HOOK_CONTROLLER_PINS',
    duration_scope: 'ENGINE_START_TO_SUMMARY_PREPARATION_EXCLUDES_FINAL_EVIDENCE_WRITE',
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
      const record = {id: row.id, property: row.property, status: 'UNPERFORMED', functional_status: 'UNPERFORMED', descendant_cleanup: 'UNPERFORMED'}
      records.push(record)
      if (row.unsupportedReason) {record.reason = row.unsupportedReason; continue}
      if (stop || options.signal?.aborted || performance.now() >= deadline) {
        record.reason = options.signal?.aborted ? 'CANCELLED' : stop ? 'EARLIER_EXECUTION_INCOMPLETE' : 'SUITE_BUDGET_EXHAUSTED'; continue
      }
      const caseStarted = performance.now(), caseDeadline = Math.min(deadline, caseStarted + row.timeoutMs)
      record.timeout_ms = row.timeoutMs
      if (row.syntheticSourcePin) record.synthetic_source_pin = 'FIXTURE_ONLY_ZERO_METADATA_NOT_CHECKOUT_ATTESTATION'
      const remaining = () => Math.floor(caseDeadline - performance.now())
      const budgetReason = () => options.signal?.aborted ? 'CANCELLED' : performance.now() >= deadline ? 'SUITE_BUDGET_EXHAUSTED' : remaining() < 1 ? 'CASE_TIMEOUT' : null
      try {
        let before, supportPins, controllerPin, sourceStage = 'entry'
        try {
          if (realpathSync(row.absoluteEntry) !== row.absoluteEntry) reject('CHECK_ENTRY_MUST_BE_PHYSICAL')
          before = await filePin(row.absoluteEntry, ENTRY_BYTES)
          record.entry_sha256 = before.digest
          if (before.digest !== row.expectedSha256) reject('UNREVIEWED_CHECK_SOURCE')
          supportPins = []; sourceStage = 'support'
          for (const pin of row.pins) {
            if (realpathSync(pin.absolutePath) !== pin.absolutePath) reject('CHECK_ENTRY_MUST_BE_PHYSICAL')
            const observed = await filePin(pin.absolutePath, ENTRY_BYTES)
            if (observed.digest !== pin.sha256) reject('UNREVIEWED_SUPPORT_SOURCE')
            supportPins.push({...pin, identity: observed.identity})
          }
        } catch (error) {
          record.reason = ['CHECK_ENTRY_MUST_BE_PHYSICAL', 'UNREVIEWED_CHECK_SOURCE', 'UNREVIEWED_SUPPORT_SOURCE', 'SOURCE_CHANGED', 'SOURCE_FILE_NOT_REGULAR_OR_BOUNDED'].includes(error.message) ? error.message : 'CHECK_SOURCE_UNAVAILABLE'
          if (row.hookController && sourceStage === 'support') {
            record.status = 'FAIL'; record.functional_status = 'FAIL'; record.reason = 'HOOK_CONTROLLER_SUPPORT_PIN_FAILED'
          }
          continue
        }
        if (row.hookController) {
          record.hook_controller = {path: row.hookController.path, expected_sha256: row.hookController.sha256, preflight: 'UNPERFORMED'}
          try {
            if (realpathSync(row.hookController.absolutePath) !== row.hookController.absolutePath) reject('HOOK_CONTROLLER_PIN_UNAVAILABLE')
            controllerPin = await filePin(row.hookController.absolutePath, ENTRY_BYTES)
            record.hook_controller.observed_sha256 = controllerPin.digest
            if (controllerPin.digest !== row.hookController.sha256) reject('HOOK_CONTROLLER_PIN_MISMATCH')
          } catch (error) {
            record.status = 'FAIL'; record.functional_status = 'FAIL'
            record.reason = error.message === 'HOOK_CONTROLLER_PIN_MISMATCH' ? error.message : 'HOOK_CONTROLLER_PIN_UNAVAILABLE'; continue
          }
        }
        if (budgetReason()) {record.reason = budgetReason(); stop = true; continue}
        const scratch = join(evidence, row.id), home = join(scratch, 'home'), tmp = join(scratch, 'tmp')
        assertEvidence(evidenceBinding); mkdirSync(scratch, {mode: 0o700})
        assertEvidence(evidenceBinding); mkdirSync(home, {mode: 0o700})
        assertEvidence(evidenceBinding); mkdirSync(tmp, {mode: 0o700})
        if (row.requiresPython) {
          let probe
          try {
            const path = '/usr/bin/python3', physical = realpathSync(path)
            if (CONTROLS.test(physical)) reject('PYTHON_STDLIB_PREREQUISITE_MISSING')
            const observed = await filePin(physical, 268_435_456)
            if (budgetReason()) {record.reason = budgetReason(); stop = true; continue}
            assertEvidence(evidenceBinding)
            probe = await runChild(path, ['-I', '-B', '-c',
              'import json,sys;print(json.dumps([sys.version_info.major,sys.version_info.minor]));sys.exit(0 if sys.version_info >= (3,9) else 1)'],
              {cwd: root, home, tmp, timeoutMs: Math.max(1, Math.min(2000, remaining())), signal: options.signal})
            assertEvidence(evidenceBinding)
            if (probe.reason || probe.completion !== 'DIRECT_CHILD_CLOSED' || probe.code !== 0) reject('PYTHON_STDLIB_PREREQUISITE_MISSING')
            const numbers = JSON.parse(probe.stdout)
            if (!Array.isArray(numbers) || numbers.length !== 2 || numbers.some(value => !Number.isInteger(value)) ||
                numbers[0] < 3 || (numbers[0] === 3 && numbers[1] < 9)) reject('PYTHON_STDLIB_PREREQUISITE_MISSING')
            result.python = {path, major: numbers[0], minor: numbers[1], observed_sha256: observed.digest, pin_verification: 'OBSERVED_ONLY'}
          } catch (error) {
            if (error.message === 'EVIDENCE_CHANGED') throw error
            record.reason = options.signal?.aborted ? 'CANCELLED' : probe?.reason === 'CASE_TIMEOUT' ? 'CASE_TIMEOUT' : 'PYTHON_STDLIB_PREREQUISITE_MISSING'
            if (probe && (probe.reason || probe.completion !== 'DIRECT_CHILD_CLOSED')) stop = true
            continue
          }
        }
        if (row.hookController) {
          if (budgetReason()) {record.reason = budgetReason(); stop = true; continue}
          assertEvidence(evidenceBinding)
          const probe = await runChild(process.execPath, ['--max-old-space-size=512', '--input-type=module', '--eval', HOOK_ASSERTION, row.hookController.absolutePath],
            {cwd: root, home, tmp, timeoutMs: Math.max(1, remaining()), signal: options.signal})
          assertEvidence(evidenceBinding)
          record.hook_controller.completion = probe.completion
          record.hook_controller.exit_code = probe.code
          if (probe.reason || probe.completion !== 'DIRECT_CHILD_CLOSED') {
            record.reason = probe.reason ?? 'HOOK_CONTROLLER_PREFLIGHT_INCOMPLETE'; stop = true; continue
          }
          try {await assertSources(row, before, supportPins, controllerPin)} catch {
            record.status = 'FAIL'; record.functional_status = 'FAIL'; record.reason = 'HOOK_CONTROLLER_SOURCE_CHANGED'; stop = true; continue
          }
          if (probe.code !== 0) {
            record.status = 'FAIL'; record.functional_status = 'FAIL'; record.reason = 'HOOK_CONTROLLER_INTERFACE_FAILED'
            record.hook_controller.preflight = 'FAIL'; continue
          }
          record.hook_controller.preflight = 'PASS'
        }
        if (budgetReason()) {record.reason = budgetReason(); stop = true; continue}
        assertEvidence(evidenceBinding)
        const execution = await runChild(process.execPath, [...(row.nodeArgs ?? []), row.absoluteEntry, ...row.args], {cwd: root, home, tmp,
          timeoutMs: Math.max(1, remaining()), signal: options.signal, requiresPython: row.requiresPython,
          hookControllerPath: row.hookController?.absolutePath, hostRoot: row.hostRoot ? root : undefined,
          syntheticSourcePin: row.syntheticSourcePin === true,
          workerSocketRoot: workerSocketBinding(row) ? evidenceBinding.path : undefined})
        assertEvidence(evidenceBinding)
        record.completion = execution.completion
        record.child_exit_code = execution.code
        if (execution.reason || execution.completion !== 'DIRECT_CHILD_CLOSED') {
          record.reason = execution.reason ?? 'EXECUTION_INCOMPLETE'; stop = true; continue
        }
        try {await assertSources(row, before, supportPins, controllerPin)} catch {
          record.reason = row.hookController ? 'HOOK_CONTROLLER_SOURCE_CHANGED' : 'SOURCE_CHANGED'
          if (row.hookController) {record.status = 'FAIL'; record.functional_status = 'FAIL'}
          stop = true; continue
        }
        Object.assign(record, assertionResult(execution.stdout, row))
        if (execution.code !== 0) {
          const observedFailure = record.failed_titles?.length || record.unknown_failed_count ||
            (record.status === 'FAIL' && record.observed_test_count > 0)
          if (!observedFailure && !execution.stderr.includes('AssertionError') &&
              /(?:^|\n)Error(?: \[ERR_MODULE_NOT_FOUND\])?: Cannot find (?:module|package)\b/.test(execution.stderr) &&
              /\bcode: ['"](?:ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND)['"]/.test(execution.stderr)) {
            record.status = 'UNPERFORMED'; record.functional_status = 'UNPERFORMED'; record.reason = 'DEPENDENCY_UNAVAILABLE'; continue
          }
          if (record.status !== 'FAIL') record.reason = 'ASSERTION_PROCESS_FAILED'
          record.status = 'FAIL'; record.functional_status = 'FAIL'
        }
      } finally {record.duration_ms = Math.round(performance.now() - caseStarted)}
    }
    result.status = records.some(row => row.status === 'FAIL') ? 'FAIL' : records.every(row => row.status === 'PASS') ? 'PASS' : 'UNPERFORMED'
    result.functional_status = records.some(row => row.functional_status === 'FAIL') ? 'FAIL' : records.every(row => row.functional_status === 'PASS') ? 'PASS' : 'UNPERFORMED'
    result.exit_code = result.status === 'PASS' ? 0 : result.status === 'FAIL' ? 1 : 2
    const codeAfter = await Promise.all([filePin(enginePath, ENTRY_BYTES), filePin(manifestPath, ENTRY_BYTES)])
    if (codeAfter.some((value, index) => value.digest !== codeBefore[index].digest || !same(value.identity, codeBefore[index].identity))) reject('EVALUATOR_SOURCE_CHANGED')
  } catch (error) {
    const known = ['CLOSED_ENGINE_OPTIONS_REQUIRED', 'PINNED_NODE_VERSION_REQUIRED', 'CANONICAL_SOURCE_ROOT_REQUIRED', 'INVALID_COMPILED_MANIFEST',
      'CANONICAL_NEW_EVIDENCE_DIRECTORY_REQUIRED', 'PRIVATE_EXTERNAL_EVIDENCE_PARENT_REQUIRED', 'EVIDENCE_DIRECTORY_MUST_BE_NEW',
      'PRIVATE_EXTERNAL_EVIDENCE_DIRECTORY_REQUIRED', 'SOURCE_CHANGED', 'SOURCE_FILE_NOT_REGULAR_OR_BOUNDED', 'EVALUATOR_SOURCE_CHANGED', 'EVIDENCE_CHANGED']
    result.reason = known.includes(error.message) ? error.message : 'ENGINE_PREREQUISITE_UNAVAILABLE'
    result.status = 'UNPERFORMED'; result.functional_status = 'UNPERFORMED'; result.exit_code = 2
    if (error.message === 'EVIDENCE_CHANGED' && records.at(-1)?.status === 'UNPERFORMED') records.at(-1).reason = 'EVIDENCE_CHANGED'
    for (const row of plan) {
      if (!records.some(record => record.id === row.id)) records.push({id: row.id, property: row.property,
        status: 'UNPERFORMED', functional_status: 'UNPERFORMED', reason: row.unsupportedReason ?? 'EARLIER_EXECUTION_INCOMPLETE', descendant_cleanup: 'UNPERFORMED'})
    }
    if (error.message !== 'EVIDENCE_CHANGED' && records.some(row => row.status === 'FAIL')) {result.status = 'FAIL'; result.functional_status = 'FAIL'; result.exit_code = 1}
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
      result.functional_status = result.status === 'FAIL' ? 'FAIL' : 'UNPERFORMED'
      delete result.evidence_path
    }
  }
  return result
}
