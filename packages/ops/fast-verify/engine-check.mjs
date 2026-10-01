// SPDX-License-Identifier: AGPL-3.0-or-later
// Tests a disposable engine copy and closed synthetic manifest, never core checks.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {mkdtempSync, realpathSync, mkdirSync, readFileSync, writeFileSync, symlinkSync, existsSync, lstatSync, rmSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {tmpdir} from 'node:os'
import {fileURLToPath, pathToFileURL} from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const temp = realpathSync(mkdtempSync(join(tmpdir(), 'prime-fast-engine-check-')))
const runnerBytes = readFileSync(join(here, 'runner.mjs'))
const checks = []
let fixtureNumber = 0
const sources = {
  pass: "import assert from 'node:assert/strict';assert.equal(process.env.TEST_OWNED_SHOULD_NOT_PROPAGATE,undefined);assert.notEqual(process.env.HOME,process.env.TMPDIR);console.log('secret=fixture-do-not-retain');console.error('fixture-stack-do-not-retain');\n",
  fail: "import assert from 'node:assert/strict';console.error('incidental ERR_MODULE_NOT_FOUND diagnostic');assert.equal(1,2);\n",
  tap: "import test from 'node:test';import assert from 'node:assert/strict';test('synthetic selected',()=>assert.equal(3,3));\n",
  skip: "import test from 'node:test';test('synthetic selected',{skip:true},()=>{});\n",
  zero: "console.log('TAP version 13\\n1..0');\n",
  duplicate: "console.log('TAP version 13\\nok 1 - synthetic selected\\nok 1 - duplicate\\n1..2');\n",
  timeout: "setInterval(()=>{},1000);\n",
  overflow: "process.stdout.write('Q'.repeat(70000));\n",
  mutate: "import {appendFileSync} from 'node:fs';appendFileSync(new URL(import.meta.url),'// changed\\n');\n",
  rebind: "import {renameSync,symlinkSync} from 'node:fs';import {dirname} from 'node:path';const evidence=dirname(dirname(process.env.TMPDIR));renameSync(evidence,evidence+'-retained');symlinkSync(process.cwd(),evidence,'dir');\n"
}
// Retained literal pins for these fixed synthetic bytes; not derived from roots.
const pins = {
  pass: '970e6753788a2afc7bccf9d167965440251f9689e07f8bc463b63196903c5900',
  fail: '0ddd201cfb14f4ee27d1113126f4ac7771fa4a866b8d2291333739294a8051dc',
  tap: 'c71120c70a733aa903e4bb12cdc49e6507ea6f1ad8a5859ab0c8f22d7e9a53d5',
  skip: '715a71a3f0f73cc53efcf8c63a5d9a340f55523b22909a7bea351488a7cf114a',
  zero: '76410797d3b0e8cb56d58fbe360944c29cf0037f6275ca994d8dc4c7ffa2779a',
  duplicate: '883bf4fe15c7fc8b63c1801ae4e31304318c86e5fcbc679c4e2bee17ae4b72ef',
  timeout: 'ecd0835b4e2198ba6874b86a435cc0211780c30759bdf31cbc55476499b7ccef',
  overflow: '45648a1b5e849b17af5b059b79ab69bad0474c1e188b2b300aebb9e733264da3',
  mutate: '42682108a6a18355417a8f45bdfad0b39d19168b047ec7e31ee092dcbfdcfe83',
  rebind: 'ca5df18b46af50f2c482e1e1dadcbfdac2e8947ed782570cd00283ec3e058295'
}
const supportBytes = '{"synthetic":true}\n'
const supportPin = 'cb8daed7b30399a1c3c8b83b3b7bee4b774a30fc389afc1d375e4c23a3cc4ae8'
const row = (kind, extra = {}) => ({id: kind, property: 'Synthetic orchestration fixture', entry: 'checks/' + kind + '.mjs',
  args: [], nodeArgs: [], expectedSha256: pins[kind], protocol: 'assert-script', timeoutMs: 2000, ...extra})
const tapRow = (kind, extra = {}) => row(kind, {nodeArgs: ['--test', '--test-isolation=none', '--test-reporter=tap'], protocol: 'tap',
  expectedTitle: 'synthetic selected', minTests: 1, ...extra})
const sentinel = {id: 'unsupported', property: 'Synthetic unconfigured short entry', unsupportedReason: 'SYNTHETIC_ENTRY_NOT_CONFIGURED', args: [], nodeArgs: [], pins: []}

async function fixture(rows, configure = () => {}, nodeVersion = 'v24.11.1') {
  const base = join(temp, 'fixture-' + fixtureNumber++)
  mkdirSync(base, {mode: 0o700})
  const root = join(base, 'source'), engine = join(base, 'engine'), evidenceDir = join(base, 'evidence')
  mkdirSync(root, {mode: 0o700}); mkdirSync(join(root, 'checks'), {mode: 0o700}); mkdirSync(engine, {mode: 0o700})
  for (const [kind, body] of Object.entries(sources)) {
    if (rows.some(row => row.entry === 'checks/' + kind + '.mjs')) writeFileSync(join(root, 'checks', kind + '.mjs'), body, {mode: 0o600})
  }
  if (rows.some(row => row.pins?.length)) writeFileSync(join(root, 'checks/support.json'), supportBytes, {mode: 0o600})
  writeFileSync(join(engine, 'runner.mjs'), runnerBytes, {mode: 0o600})
  writeFileSync(join(engine, 'manifest.mjs'),
    'export const CASES=' + JSON.stringify(rows) + ';\nexport const NODE_VERSION=' + JSON.stringify(nodeVersion) + ';\n' +
    'export const SOURCE_REVIEW_COMMIT="' + '0'.repeat(40) + '";\n' +
    'export const HISTORY=[{status:"HISTORICAL_ONLY",current_verification:"UNPERFORMED"}];\n' +
    'export const UNPERFORMED=[{id:"live-pg",status:"UNPERFORMED"}];\n', {mode: 0o600})
  const context = {root, evidenceDir, base}
  configure(context)
  const {runFastVerify} = await import(pathToFileURL(join(engine, 'runner.mjs')).href)
  return {...context, run: options => runFastVerify({root, evidenceDir, ...options})}
}

const check = async (name, action) => {await action(); checks.push(name)}
const cleanSummary = result => {
  const text = JSON.stringify(result)
  assert.ok(!text.includes('fixture-do-not-retain')); assert.ok(!text.includes('fixture-stack-do-not-retain'))
  assert.ok(!text.includes('incidental ERR_MODULE_NOT_FOUND diagnostic'))
  assert.equal(result.qualification, 'UNPERFORMED'); assert.equal(result.g1, 'PENDING')
  assert.equal(result.descendant_cleanup, 'UNPERFORMED'); assert.equal(result.node.pin_verification, 'OBSERVED_ONLY')
  if (result.evidence_path) {
    const retained = readFileSync(result.evidence_path, 'utf8')
    assert.deepEqual(JSON.parse(retained), result)
    assert.ok(!retained.includes('fixture-do-not-retain')); assert.ok(!retained.includes('fixture-stack-do-not-retain'))
    assert.equal(lstatSync(result.evidence_path).mode & 0o777, 0o600)
  }
}

try {
  await check('static-fixture-pins-match-retained-bytes', async () => {
    for (const [kind, body] of Object.entries(sources)) assert.equal(createHash('sha256').update(body).digest('hex'), pins[kind])
    assert.equal(createHash('sha256').update(supportBytes).digest('hex'), supportPin)
  })
  await check('pass-is-ordinary-only-output-private-env-scrubbed', async () => {
    const own = await fixture([row('pass')]), saved = process.env.TEST_OWNED_SHOULD_NOT_PROPAGATE
    process.env.TEST_OWNED_SHOULD_NOT_PROPAGATE = 'synthetic-caller-credential'
    try {
      const result = await own.run(); cleanSummary(result)
      assert.equal(result.status, 'PASS'); assert.equal(result.exit_code, 0)
      assert.deepEqual(result.counts, {pass: 1, fail: 0, unperformed: 0})
      for (const path of [own.evidenceDir, join(own.evidenceDir, 'pass/home'), join(own.evidenceDir, 'pass/tmp')]) assert.equal(lstatSync(path).mode & 0o777, 0o700)
      assert.equal(result.historical[0].status, 'HISTORICAL_ONLY')
      assert.equal(result.unperformed[0].status, 'UNPERFORMED')
    } finally {if (saved === undefined) delete process.env.TEST_OWNED_SHOULD_NOT_PROPAGATE; else process.env.TEST_OWNED_SHOULD_NOT_PROPAGATE = saved}
  })
  await check('tap-exact-selected-test-and-count', async () => {
    const own = await fixture([tapRow('tap')]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'PASS'); assert.equal(result.cases[0].test_count, 1)
  })
  await check('real-assertion-failure-takes-precedence-over-missing-case', async () => {
    const own = await fixture([row('fail'), sentinel]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'FAIL'); assert.equal(result.exit_code, 1)
    assert.equal(result.cases[0].reason, 'ASSERTION_PROCESS_FAILED'); assert.equal(result.cases[1].status, 'UNPERFORMED')
  })
  await check('sentinel-alone-is-incomplete-and-never-spawned', async () => {
    const own = await fixture([sentinel]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'UNPERFORMED'); assert.equal(result.exit_code, 2)
    assert.equal(result.cases[0].reason, sentinel.unsupportedReason); assert.equal(existsSync(join(own.evidenceDir, sentinel.id)), false)
  })
  await check('unreviewed-check-and-support-pins-refuse-before-spawn', async () => {
    const own = await fixture([row('pass', {expectedSha256: '0'.repeat(64)}), row('tap', {pins: [{path: 'checks/support.json', sha256: '0'.repeat(64)}]})])
    const result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 2)
    assert.deepEqual(result.cases.map(value => value.reason), ['UNREVIEWED_CHECK_SOURCE', 'UNREVIEWED_SUPPORT_SOURCE'])
    assert.equal(existsSync(join(own.evidenceDir, 'pass')), false); assert.equal(existsSync(join(own.evidenceDir, 'tap')), false)
  })
  await check('literal-support-pin-is-required-and-accepted', async () => {
    const own = await fixture([row('pass', {pins: [{path: 'checks/support.json', sha256: supportPin}]})])
    const result = await own.run(); cleanSummary(result); assert.equal(result.status, 'PASS')
  })
  await check('physical-entry-symlink-is-not-an-approved-source-file', async () => {
    const own = await fixture([row('pass')], ({root}) => {
      writeFileSync(join(root, 'checks/tap.mjs'), sources.tap, {mode: 0o600})
      rmSync(join(root, 'checks/pass.mjs')); symlinkSync('tap.mjs', join(root, 'checks/pass.mjs'))
    })
    const result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 2); assert.equal(result.cases[0].reason, 'CHECK_ENTRY_MUST_BE_PHYSICAL')
  })
  await check('missing-source-is-incomplete-not-an-assertion-failure', async () => {
    const own = await fixture([row('pass')], ({root}) => rmSync(join(root, 'checks/pass.mjs')))
    const result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 2); assert.equal(result.cases[0].reason, 'CHECK_SOURCE_UNAVAILABLE')
  })
  await check('zero-tap-tests-cannot-pass', async () => {
    const own = await fixture([tapRow('zero', {nodeArgs: []})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.equal(result.cases[0].reason, 'TAP_INCOMPLETE')
  })
  await check('duplicate-tap-test-numbers-cannot-satisfy-plan', async () => {
    const own = await fixture([tapRow('duplicate', {nodeArgs: []})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.equal(result.cases[0].reason, 'TAP_INCOMPLETE')
  })
  await check('skipped-or-wrong-selected-title-cannot-pass', async () => {
    const own = await fixture([tapRow('skip'), tapRow('tap', {expectedTitle: 'unselected title'})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.ok(result.cases.every(value => value.reason === 'TAP_SELECTED_TEST_MISSING'))
  })
  await check('timeout-stops-following-case-and-signals-only-owned-child', async () => {
    const own = await fixture([row('timeout', {timeoutMs: 50}), row('pass')]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 2); assert.equal(result.cases[0].reason, 'CASE_TIMEOUT')
    assert.equal(result.cases[1].reason, 'EARLIER_EXECUTION_INCOMPLETE'); assert.equal(existsSync(join(own.evidenceDir, 'pass')), false)
  })
  await check('overflow-stops-suite-and-retains-no-output', async () => {
    const own = await fixture([row('overflow'), row('pass')]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 2); assert.equal(result.cases[0].reason, 'OUTPUT_LIMIT_EXCEEDED')
    assert.equal(result.cases[1].reason, 'EARLIER_EXECUTION_INCOMPLETE'); assert.ok(!JSON.stringify(result).includes('Q'.repeat(20)))
  })
  await check('cancellation-stops-suite-without-acceptance', async () => {
    const own = await fixture([row('timeout'), row('pass')]), controller = new AbortController()
    const running = own.run({signal: controller.signal}), timer = setTimeout(() => controller.abort(), 100)
    try {
      const result = await running; cleanSummary(result)
      assert.equal(result.exit_code, 2); assert.equal(result.cases[0].reason, 'CANCELLED')
      assert.equal(result.cases[1].status, 'UNPERFORMED')
    } finally {clearTimeout(timer)}
  })
  await check('source-mutation-after-execution-is-incomplete', async () => {
    const own = await fixture([row('mutate'), row('pass')]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 2); assert.equal(result.cases[0].reason, 'SOURCE_CHANGED')
    assert.equal(result.cases[1].reason, 'EARLIER_EXECUTION_INCOMPLETE')
  })
  await check('evidence-rebinding-stops-writes-and-later-checks', async () => {
    const own = await fixture([row('rebind'), row('pass')]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'UNPERFORMED'); assert.equal(result.exit_code, 2)
    assert.equal(result.reason, 'EVIDENCE_CHANGED'); assert.equal(result.cases[0].reason, 'EVIDENCE_CHANGED')
    assert.equal(result.cases.length, 2); assert.equal(result.cases[1].reason, 'EARLIER_EXECUTION_INCOMPLETE')
    assert.equal(result.evidence_path, undefined)
    assert.equal(existsSync(join(own.root, 'summary.json')), false)
    assert.equal(existsSync(join(own.evidenceDir + '-retained', 'summary.json')), false)
    assert.equal(existsSync(join(own.root, 'pass')), false)
  })
  await check('closed-options-no-caller-environment-or-command-injection', async () => {
    const own = await fixture([row('pass')]), result = await own.run({env: {TEST: 'disallowed'}})
    cleanSummary(result); assert.equal(result.reason, 'CLOSED_ENGINE_OPTIONS_REQUIRED'); assert.equal(existsSync(own.evidenceDir), false)
  })
  await check('evidence-inside-source-is-refused-before-writes', async () => {
    const own = await fixture([row('pass')]), path = join(own.root, 'evidence')
    const result = await own.run({evidenceDir: path}); cleanSummary(result)
    assert.equal(result.exit_code, 2); assert.equal(existsSync(path), false)
  })
  await check('existing-evidence-directory-is-never-reused', async () => {
    const own = await fixture([row('pass')], ({evidenceDir}) => mkdirSync(evidenceDir, {mode: 0o700}))
    const result = await own.run(); cleanSummary(result)
    assert.equal(result.reason, 'EVIDENCE_DIRECTORY_MUST_BE_NEW')
  })
  await check('escaped-compiled-path-and-wrong-node-version-refuse', async () => {
    const own = await fixture([row('pass', {entry: '../outside.mjs'})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.reason, 'INVALID_COMPILED_MANIFEST'); assert.equal(existsSync(own.evidenceDir), false)
    const wrong = await fixture([row('pass')], () => {}, 'v0.0.0'), other = await wrong.run(); cleanSummary(other)
    assert.equal(other.reason, 'PINNED_NODE_VERSION_REQUIRED'); assert.equal(existsSync(wrong.evidenceDir), false)
  })
  console.log(JSON.stringify({status: 'PASS', checks: checks.length, scope: 'disposable engine orchestration only',
    core_checks: 'NOT_RUN', network: 'NOT_USED', host_mutations: 'NOT_PERFORMED', qualification: 'UNPERFORMED', g1: 'PENDING'}))
} finally {rmSync(temp, {recursive: true, force: true})}
