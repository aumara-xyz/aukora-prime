// SPDX-License-Identifier: AGPL-3.0-or-later
// Tests a disposable engine copy and closed synthetic manifest, never core checks.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {mkdtempSync, realpathSync, mkdirSync, readFileSync, writeFileSync, symlinkSync, existsSync, lstatSync, rmSync} from 'node:fs'
import {dirname, join} from 'node:path'
import {tmpdir} from 'node:os'
import {fileURLToPath, pathToFileURL} from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const requested = process.argv.slice(2)
assert.ok(requested.length === 0 || (requested.length === 1 && requested[0] === '--accounting-regressions'), 'CLOSED_ENGINE_CHECK_ARGUMENTS_REQUIRED')
const focused = requested.length === 1
const focusedChecks = new Set([
  'static-fixture-pins-match-retained-bytes', 'required-extra-and-nested-skip-or-todo-fail',
  'external-title-must-skip-with-exact-compiled-reason', 'unnamed-malformed-and-directive-plans-cannot-disappear',
  'hook-prerequisite-and-main-execution-share-case-deadline', 'tap-summary-cannot-hide-failure-cancellation-skip-or-todo',
  'json-summary-must-be-unambiguous-pass-with-no-required-incomplete-counts',
  'only-compiled-hook-and-host-bindings-propagate-and-provider-env-is-scrubbed',
  'closed-protocol-schemas-and-reviewed-case-caps-refuse-before-spawn',
  'support-pin-cap-accepts-nine-and-refuses-thirteen', 'main-child-controller-mutation-fails-post-execution-source-guard'
])
const temp = realpathSync(mkdtempSync(join(tmpdir(), 'prime-fast-engine-check-')))
const runnerBytes = readFileSync(join(here, 'runner.mjs'))
const checks = []
let lastSummary
let lastBudgetTrace
let configuredChecks = 0
const focusedObservations = []
let fixtureNumber = 0
const emit = (text, code = 0) => 'process.stdout.write(' + JSON.stringify(text) + ');process.exitCode=' + code + ';\n'
const tapFooter = (text, counts = {tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 0, todo: 0}) =>
  text + ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'].map(key => '# ' + key + ' ' + counts[key] + '\n').join('')
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
  rebind: "import {renameSync,symlinkSync} from 'node:fs';import {dirname} from 'node:path';const evidence=dirname(dirname(process.env.TMPDIR));renameSync(evidence,evidence+'-retained');symlinkSync(process.cwd(),evidence,'dir');\n",
  tapTwo: "import test from 'node:test';test('synthetic selected',()=>{});test('synthetic second',()=>{});\n",
  tapExternal: "import test from 'node:test';test('synthetic selected',()=>{});test('synthetic external PG',{skip:'NO_EXTERNAL_PG'},()=>{});\n",
  tapExternalWrongReason: emit('TAP version 13\nok 1 - synthetic selected\nok 2 - synthetic external PG # SKIP secret=fixture-do-not-retain\n1..2\n'),
  tapRequiredSkip: "import test from 'node:test';test('synthetic selected',()=>{});test('synthetic second',{skip:true},()=>{});\n",
  tapDuplicateTitle: emit('TAP version 13\nok 1 - synthetic selected\nok 2 - synthetic selected\n1..2\n'),
  tapTodo: emit('TAP version 13\nok 1 - synthetic selected\nnot ok 2 - synthetic second # TODO fixture\n1..2\n', 1),
  tapNested: emit('TAP version 13\n# Subtest: synthetic selected\n    ok 1 - synthetic selected\n    1..1\nok 1 - synthetic selected\n1..1\n'),
  tapNestedSkip: emit('TAP version 13\n# Subtest: synthetic selected\n    ok 1 - synthetic second # SKIP fixture\n    1..1\nok 1 - synthetic selected\n1..1\n'),
  tapUnnamedNested: emit('TAP version 13\n    not ok 1\nok 1 - synthetic selected\n1..1\n'),
  tapMalformed: emit('TAP version 13\n    not ok malformed # TODO fixture\nok 1 - synthetic selected\n1..1\n'),
  tapDirectivePlan: emit('TAP version 13\n    1..0 # SKIP fixture\nok 1 - synthetic selected\n1..1\n'),
  tapKnownFail: emit('TAP version 13\nnot ok 1 - synthetic selected\nok 2 - synthetic second\n1..2\n', 1) +
    "console.error(\"Error [ERR_MODULE_NOT_FOUND]: Cannot find module 'synthetic-fixture'\\ncode: 'ERR_MODULE_NOT_FOUND'\");\n",
  tapUnknownFail: emit('TAP version 13\nok 1 - synthetic selected\nnot ok 2 - secret=fixture-do-not-retain\n1..2\n', 1),
  tapProcessFail: emit(tapFooter('TAP version 13\nok 1 - synthetic selected\n1..1\n'), 1),
  tapSummaryMissing: emit('TAP version 13\nok 1 - synthetic selected\n1..1\n'),
  tapSummaryFailed: emit(tapFooter('TAP version 13\nok 1 - synthetic selected\n1..1\n', {tests: 1, pass: 1, fail: 1, cancelled: 0, skipped: 0, todo: 0})),
  tapSummaryCancelled: emit(tapFooter('TAP version 13\nok 1 - synthetic selected\n1..1\n', {tests: 1, pass: 1, fail: 0, cancelled: 1, skipped: 0, todo: 0})),
  tapSummarySkipped: emit(tapFooter('TAP version 13\nok 1 - synthetic selected\n1..1\n', {tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 1, todo: 0})),
  tapSummaryTodo: emit(tapFooter('TAP version 13\nok 1 - synthetic selected\n1..1\n', {tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 0, todo: 1})),
  tapSummaryWrongCount: emit(tapFooter('TAP version 13\nok 1 - synthetic selected\n1..1\n', {tests: 2, pass: 2, fail: 0, cancelled: 0, skipped: 0, todo: 0})),
  tapSummaryMalformedDuplicate: emit(tapFooter('TAP version 13\nok 1 - synthetic selected\n1..1\n') + '# fail -1\n'),
  passLines: emit('PASS synthetic first\nPASS synthetic second\nSynthetic 2 groups complete\nsecret=fixture-do-not-retain\n'),
  passLinesDuplicate: emit('PASS synthetic first\nPASS synthetic first\n'),
  passLinesFail: emit('PASS synthetic first\nFAIL synthetic second\n', 1),
  passLinesUnknown: emit('PASS synthetic first\nPASS secret=fixture-do-not-retain\n'),
  jsonExact: emit('{"status":"FAIL","checks":2,"secret":"fixture-do-not-retain"}\n'),
  jsonPass: emit('{"status":"PASS","checks":2,"secret":"fixture-do-not-retain"}\n'),
  jsonConflict: emit('{"result":"PASS","status":"FAIL","checks":2}\n'),
  jsonSkipped: emit('{"result":"PASS","checks":2,"skipped":1}\n'),
  jsonTodo: emit('{"status":"PASS","checks":2,"todo":1}\n'),
  jsonFailed: emit('{"status":"PASS","checks":2,"failed":1}\n'),
  jsonCancelled: emit('{"status":"PASS","checks":2,"cancelled":1}\n'),
  jsonNestedFailure: emit('{"status":"PASS","checks":2,"nested":{"result":"FAIL"}}\n'),
  jsonConflictingSummary: emit('{"status":"FAIL"}\n{"status":"PASS","checks":2}\n'),
  jsonEarlierFailure: emit('{"fail":1}\n{"status":"PASS","checks":2}\n'),
  jsonNegativePass: emit('{"status":"PASS","checks":2,"pass":-1}\n'),
  jsonWrong: emit('{"status":"PASS","checks":1}\n'),
  jsonZero: emit('{"status":"PASS","cases":0}\n'),
  jsonClaim: emit('{"status":"PASS"}\n'),
  jsonProcessFail: emit('{"status":"PASS","checks":2}\n', 1),
  jsonAmbiguous: emit('{"checks":2}\n{"checks":2}\n'),
  jsonPrivate: emit('{"checks":"secret=fixture-do-not-retain"}\n'),
  envScrub: "import assert from 'node:assert/strict';for(const key of ['TEST_OWNED_SHOULD_NOT_PROPAGATE','NODE_OPTIONS','NODE_PATH','PGHOST','PGPASSWORD','PRIME_OWNER_HOOK_CONTROLLER','PRIME_OWNER_MEMORY_HOST_ROOT','PRIME_OWNER_MEMORY_SOURCE_PIN','OPENAI_API_KEY'])assert.equal(process.env[key],undefined);\n",
  sourcePin: "import assert from 'node:assert/strict';assert.equal(process.env.PRIME_OWNER_MEMORY_SOURCE_PIN,'0'.repeat(40));assert.equal(process.env.PRIME_OWNER_MEMORY_HOST_ROOT,undefined);assert.equal(process.env.PRIME_OWNER_HOOK_CONTROLLER,undefined);\n",
  hostRoot: "import assert from 'node:assert/strict';import {realpathSync} from 'node:fs';assert.equal(process.env.PRIME_OWNER_MEMORY_HOST_ROOT,realpathSync(process.cwd()));assert.equal(process.env.PRIME_OWNER_HOOK_CONTROLLER,undefined);assert.equal(process.env.PGHOST,undefined);\n",
  hookMain: "import assert from 'node:assert/strict';import {writeFileSync} from 'node:fs';import {dirname,join} from 'node:path';writeFileSync(join(dirname(process.env.TMPDIR),'main-ran'),'synthetic');assert.equal(process.env.PRIME_OWNER_HOOK_CONTROLLER,join(process.cwd(),'checks/controllerGood.mjs'));assert.equal(process.env.PRIME_OWNER_MEMORY_HOST_ROOT,undefined);\n",
  hookMutateMain: "import {appendFileSync} from 'node:fs';appendFileSync(process.env.PRIME_OWNER_HOOK_CONTROLLER,'// changed\\n');\n",
  hookSlowMain: "await new Promise(resolve=>setTimeout(resolve,180));\n"
}
const controllers = {
  controllerGood: "import assert from 'node:assert/strict';import {writeFileSync} from 'node:fs';export function createPrimeOwnerController({schedule,unschedule}){assert.equal(schedule(),null);assert.equal(unschedule(),undefined);return {setApprovalAction(){},submitApproval(){},dispose(){writeFileSync(process.env.TMPDIR+'/controller-disposed','synthetic')}}}\n",
  controllerBadExport: "export function anotherController(){return {}}\n",
  controllerBadInterface: "import {writeFileSync} from 'node:fs';export function createPrimeOwnerController(){return {setApprovalAction(){},dispose(){writeFileSync(process.env.TMPDIR+'/controller-disposed','synthetic')}}}\n",
  controllerMutate: "import {appendFileSync} from 'node:fs';export function createPrimeOwnerController(){appendFileSync(new URL(import.meta.url),'// changed\\n');return {setApprovalAction(){},submitApproval(){},dispose(){}}}\n",
  controllerSlow: "await new Promise(resolve=>setTimeout(resolve,100));export function createPrimeOwnerController(){return {setApprovalAction(){},submitApproval(){},dispose(){}}}\n"
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
  rebind: 'ca5df18b46af50f2c482e1e1dadcbfdac2e8947ed782570cd00283ec3e058295',
  tapTwo: '4a3edd8c46e44e0e11651ab81325f94601ec3761b10a1189ec1af4d43eb0ac92',
  tapExternal: '359928bfe3d641edb3cb52499a51b6681a6145857a21c9db68d59e515ce28a95',
  tapExternalWrongReason: '40cfabd4a8c1b44a19158e958900d25ca677b04457f598011e1360f89b7e453e',
  tapRequiredSkip: '385f8f85f57c3b4280f62539e77baa68e3f8c8fedfc27d3f953a7c1cee585962',
  tapDuplicateTitle: '5308222475cec7f690ae1404d0ffe3107d16bb60a6e41e9e96ab027f9f2531be',
  tapTodo: '2539ed229f2fed1a9b045e0cf86374e13f9dbbad2a055144154d4211a032948c',
  tapNested: 'e7e743b854f89eb9945dbd72ff6800cee2755dab9c7303efa0c825d8ccd82b01',
  tapNestedSkip: '9c3191ebd96f6f1f1984870217ae5538e4abd3ccd310cc76035da8be6ebba18c',
  tapUnnamedNested: '93debcf615ca27a3168e9134a36396c9f1a3e1f2459e4c28e0403bdb5581fff6',
  tapMalformed: '40d3bd04929bd975de421d5c82072a695052612fdd39269cfe820be76ba9a974',
  tapDirectivePlan: 'a90928c282caef601c960b8d8b33e82662be00a543c568b458d925a0cf533357',
  tapKnownFail: '2a1dfd63c9481d8015efe9fb2c268128cca60561d29fff02405b9f75c91d13ff',
  tapUnknownFail: '7ddb02de4c2ce0aa8ea69c8f86c71ba56fc1a411e50732fe5fdebec7a05389ce',
  tapProcessFail: 'a95d5588763ead965104ff6d549d8e60f127ac61fc247787ca764f4347e72d66',
  tapSummaryMissing: '9e106e1a774e2705b9905454d2382ca6ca0b79918d5ecc4337be9fad3ba6866d',
  tapSummaryFailed: 'f5c8c6885014144c2006a36889d4c9efdc2c31521f45919ebbfb7f0e8eb19bce',
  tapSummaryCancelled: '268334b6034c5ac5ca680096a09c6976711349e3d42aae6b268319a3236241a0',
  tapSummarySkipped: '002ec309936dd1d75ed6723154d6741e25175d2e5929fa32f3205ff3258509e2',
  tapSummaryTodo: '80eb43c825b1bf60a497b461c85fe9c3043f59f3c463a63e4a30fc4dd5f3897b',
  tapSummaryWrongCount: '23c3eb47da7fc89f63beb546569cfdd5e8e394334ea5711ad3c34300f2769a2c',
  tapSummaryMalformedDuplicate: '25c59c55710f65500a1d4b2505cafa0c335c6ccf31917253582ab80d94becff3',
  passLines: 'e897135106d8252fedf73f03903e99a3ee2823e443600da63b53f01873aa3cea',
  passLinesDuplicate: 'd0cc163e1902cf180faac345a3dfd0ede7dcd47d3d9b1fdcabdf64bcbfdcf1fa',
  passLinesFail: 'ad943b9d7dd63319579bf671a2e6565c3b548dde421e6f6b00ef97b3e4ce5346',
  passLinesUnknown: '9a6ef43ca16ff3c2792f2017b9218ba77ef640e35bf1f189962475c6540bdcb7',
  jsonExact: '718cd442aef87985863fc41382a21316da6a365d667e72aa2c0c9fcff241da96',
  jsonPass: 'f812a42c4e916810835c2a418331167533591f119074cf4877ff93dce275b3cf',
  jsonConflict: 'fcdbf0f20f314a7d1e8b4d370a6404a9e6c90b82adef62e84bd5017f4f50959b',
  jsonSkipped: 'e5945779bfe96bd3f163db02a64179820034f62bef73f53c7b0d3729157ddf12',
  jsonTodo: 'fb9b9c614dfc20a437737c5ccc6672e1bc12a8c9b4597b35377b2e21f1bef1e6',
  jsonFailed: 'd4ce54483df2c62f30396e319a78fb4c1a87390e76e903f2948ec46d62bb0cdd',
  jsonCancelled: '965878ae51059ce45ced00f0fabee913795b1a6f8a5d34962acd97dcbc699362',
  jsonNestedFailure: '2a2e6591f6d995c670e55a8757458eabbb2ed34a6d04fd8bbbf0ae16e0d712ea',
  jsonConflictingSummary: '5feccfaef2cac51e4f6d76e48afab7629f1dfc4adb99922e7e2ed4eacb3daa8d',
  jsonEarlierFailure: '3c8985e57228ab9bf9a67d03027fe0328ec7cab0f52f25da185dc916e679dc79',
  jsonNegativePass: '3930a8d59a2a91a7ea8a72dc7bb896e4a75b3224b3973fdfb2c6463ceadb52db',
  jsonWrong: 'b7660b9fad5b22bdccc7d64f9ecc49fb1d3cdf0fa69cb2427ec720d74e330f3f',
  jsonZero: '46cf818d22be927ea8b2212f0ebb83f5502082fad75bd759a8a090377421077a',
  jsonClaim: 'deda11f5177a4b7bacb51fd76a6e4abe04cc27f53f12425623c04f25aea2c338',
  jsonProcessFail: '8456ad0697d123885f7e7aa096d9cb52bebb5bf5a235cd85fc6a3a4afb1edf54',
  jsonAmbiguous: '6f36bc05ce454b422a350bfba9d98d1a794a76de75192e6298ff91222a04bf1e',
  jsonPrivate: '6f9694d719b3e84a8c6d5238c2c27df531ce42e5b84ea38d39d3cd3e8878658b',
  envScrub: '77ade3fea7f66296837b6d04a8e028a45949f4883370d5a1924ca9687d0ace2a',
  sourcePin: '401f73951931b916c0d1b593c164251c7134e56e9881564770d1daee7fbf8a14',
  hostRoot: '71ea99f8ea49acd5a00eb7db1ab64157cd209a1e631f44d03155aef9da0a4d1f',
  hookMain: 'ea8f0b9216577b6523764362ba46d3af901f116ff1a7299dcf7e2fa149869783',
  hookMutateMain: '8dcb47338e0dac2eb9288570244c1f234272c7832183dd37ff7d4f0a08f61224',
  hookSlowMain: 'bb698bdbd5823dc419c11af67e4df4638d2c65482df098eb267e5df40d6fedeb'
}
const controllerPins = {
  controllerGood: '7231d66038e55882fdd729b5f4158a7a1af3b3af73ee7365393785efbccbf302',
  controllerBadExport: 'aba9c9c5b4cafa4c3a0cbd010ae4cf4beaf836074e4f359a75b51f96fb42b1e0',
  controllerBadInterface: '4ebd5893abc79bd114bea1bf98ca2dffcc6fe0f5cedf30808cd8335b4f5003a9',
  controllerMutate: 'a15fbbec82d495012bfdce69f8d1484c8ffc75a189457a45d444bbcbb4670d89',
  controllerSlow: '5acc6e97ac3b7aa9b4950f3f622136336a1724131576ffb6ffc029eb89cc638b'
}
const supportBytes = '{"synthetic":true}\n'
const supportPin = 'cb8daed7b30399a1c3c8b83b3b7bee4b774a30fc389afc1d375e4c23a3cc4ae8'
const row = (kind, extra = {}) => ({id: kind.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase()), property: 'Synthetic orchestration fixture', entry: 'checks/' + kind + '.mjs',
  args: [], nodeArgs: [], expectedSha256: pins[kind], protocol: 'assert-script', timeoutMs: 2000, ...extra})
const tapRow = (kind, extra = {}) => row(kind, {nodeArgs: ['--test', '--test-isolation=none', '--test-reporter=tap'], protocol: 'tap',
  requiredTitles: ['synthetic selected'], externalSkips: [], ...extra})
const labelsRow = (kind, extra = {}) => row(kind, {protocol: 'pass-lines', requiredLabels: ['synthetic first', 'synthetic second'], ...extra})
const jsonRow = (kind, extra = {}) => row(kind, {protocol: 'assert-json', counter: {key: 'checks', value: 2}, ...extra})
const hookRow = (kind = 'controllerGood', extra = {}) => row('hookMain', {hookController: {path: 'checks/' + kind + '.mjs', sha256: controllerPins[kind]}, ...extra})
const sentinel = {id: 'unsupported', property: 'Synthetic unconfigured short entry', unsupportedReason: 'SYNTHETIC_ENTRY_NOT_CONFIGURED', args: [], nodeArgs: [], pins: []}

// Fixed simulation in this one disposable copy, never a production clock option.
// Startup timing is covered elsewhere by real-child interface/timeout fixtures.
function instrumentDeadline({base}) {
  const path = join(base, 'engine/runner.mjs')
  const replaceOnce = (text, needle, replacement) => {
    assert.equal(text.split(needle).length - 1, 1)
    return text.replace(needle, replacement)
  }
  let text = readFileSync(path, 'utf8')
  text = replaceOnce(text, "import {performance} from 'node:perf_hooks'", "const syntheticClock={ms:0};const performance={now:()=>syntheticClock.ms}")
  text = replaceOnce(text, 'function runChild(', 'function unusedRealRunChild(')
  text += `\nimport assert from 'node:assert/strict'
export const syntheticBudgetTrace=[]
async function runChild(command,args,{timeoutMs}) {
  assert.equal(command,process.execPath)
  const preflight=args.includes(HOOK_ASSERTION)
  syntheticBudgetTrace.push({phase:preflight?'controller-preflight':'main',timeout_ms:timeoutMs})
  assert.ok(syntheticBudgetTrace.length<=2)
  if(preflight){syntheticClock.ms+=100;return {completion:'DIRECT_CHILD_CLOSED',code:0,stdout:'',stderr:''}}
  const exhausted=timeoutMs<180
  syntheticClock.ms+=exhausted?timeoutMs:180
  return {completion:'DIRECT_CHILD_CLOSED',code:exhausted?null:0,reason:exhausted?'CASE_TIMEOUT':undefined,stdout:'',stderr:''}
}\n`
  writeFileSync(path, text, {mode: 0o600})
}

async function fixture(rows, configure = () => {}, nodeVersion = 'v24.11.1') {
  const base = join(temp, 'fixture-' + fixtureNumber++)
  mkdirSync(base, {mode: 0o700})
  const root = join(base, 'source'), engine = join(base, 'engine'), evidenceDir = join(base, 'evidence')
  mkdirSync(root, {mode: 0o700}); mkdirSync(join(root, 'checks'), {mode: 0o700}); mkdirSync(engine, {mode: 0o700})
  for (const [kind, body] of Object.entries(sources)) {
    if (rows.some(row => row.entry === 'checks/' + kind + '.mjs')) writeFileSync(join(root, 'checks', kind + '.mjs'), body, {mode: 0o600})
  }
  for (const [kind, body] of Object.entries(controllers)) {
    if (rows.some(row => row.hookController?.path === 'checks/' + kind + '.mjs')) writeFileSync(join(root, 'checks', kind + '.mjs'), body, {mode: 0o600})
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
  const {runFastVerify, syntheticBudgetTrace} = await import(pathToFileURL(join(engine, 'runner.mjs')).href)
  return {...context, budgetTrace: syntheticBudgetTrace, run: options => runFastVerify({root, evidenceDir, ...options})}
}

const check = async (name, action) => {
  configuredChecks++
  if (focused && !focusedChecks.has(name)) return
  lastSummary = undefined
  lastBudgetTrace = undefined
  try {
    await action(); checks.push(name)
    if (focused && lastSummary) focusedObservations.push({check: name, cases: lastSummary.cases.map(({id, status, reason, duration_ms, child_exit_code, skipped_count, required_skipped_count}) =>
      ({id, status, reason, duration_ms, child_exit_code, skipped_count, required_skipped_count})),
      ...(lastBudgetTrace ? {budget_trace: lastBudgetTrace, timing_source: 'FIXED_SYNTHETIC_CLOCK_AND_CHILD_SIMULATION'} : {})})
  } catch (error) {
    const safe = value => typeof value === 'boolean' || (Number.isInteger(value) && Math.abs(value) <= 10_000) || ['PASS', 'FAIL', 'UNPERFORMED'].includes(value)
    console.log(JSON.stringify({status: 'FAIL', check: name, reason: 'SYNTHETIC_FIXTURE_ASSERTION_FAILED',
      ...(safe(error.actual) ? {actual: error.actual} : {}), ...(safe(error.expected) ? {expected: error.expected} : {}),
      ...(lastSummary ? {case_results: lastSummary.cases.map(({id, status, reason}) => ({id, status, reason}))} : {})}))
    throw error
  }
}
const cleanSummary = result => {
  lastSummary = result
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
    for (const [kind, body] of Object.entries(controllers)) assert.equal(createHash('sha256').update(body).digest('hex'), controllerPins[kind])
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
  await check('tap-exact-required-title-and-count', async () => {
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
  await check('skipped-or-wrong-required-title-cannot-pass', async () => {
    const own = await fixture([tapRow('skip'), tapRow('tap', {requiredTitles: ['unselected title']})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1)
    assert.deepEqual(result.cases.map(value => value.reason), ['TAP_UNDECLARED_SKIP', 'TAP_TITLE_INVENTORY_MISMATCH'])
  })
  await check('full-file-title-inventory-requires-exact-nonzero-count', async () => {
    const own = await fixture([tapRow('tapTwo', {requiredTitles: ['synthetic selected', 'synthetic second']})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'PASS'); assert.equal(result.cases[0].test_count, 2)
    assert.equal(result.cases[0].expected_test_count, 2); assert.equal(result.cases[0].required_test_count, 2)
    const missing = await fixture([tapRow('tap', {requiredTitles: ['synthetic selected', 'synthetic second']})]), absent = await missing.run(); cleanSummary(absent)
    assert.equal(absent.exit_code, 1); assert.equal(absent.cases[0].reason, 'TAP_TITLE_INVENTORY_MISMATCH')
    const extra = await fixture([tapRow('tapTwo')]), unexpected = await extra.run(); cleanSummary(unexpected)
    assert.equal(unexpected.exit_code, 1); assert.equal(unexpected.cases[0].unknown_title_count, 1)
  })
  await check('required-extra-and-nested-skip-or-todo-fail', async () => {
    const own = await fixture([
      tapRow('tapRequiredSkip', {requiredTitles: ['synthetic selected', 'synthetic second']}),
      tapRow('tapExternal'), tapRow('tapNestedSkip', {nodeArgs: []}),
      tapRow('tapTodo', {nodeArgs: [], requiredTitles: ['synthetic selected', 'synthetic second']}),
      tapRow('tapNested', {nodeArgs: []})
    ]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.ok(result.cases.every(value => value.status === 'FAIL'))
    assert.deepEqual(result.cases.map(value => value.reason), ['TAP_UNDECLARED_SKIP', 'TAP_UNDECLARED_SKIP', 'TAP_UNDECLARED_SKIP', 'TAP_TODO_FORBIDDEN', 'TAP_NESTING_UNSUPPORTED'])
    assert.deepEqual(result.cases[0].failed_titles, ['synthetic second'])
    assert.equal(result.cases[0].skipped_count, 1); assert.equal(result.cases[0].required_skipped_count, 1)
  })
  await check('duplicate-titles-fail-even-with-valid-numbering', async () => {
    const own = await fixture([tapRow('tapDuplicateTitle', {nodeArgs: [], requiredTitles: ['synthetic selected', 'synthetic second']})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.equal(result.cases[0].reason, 'TAP_DUPLICATE_TITLE')
  })
  await check('unnamed-malformed-and-directive-plans-cannot-disappear', async () => {
    const own = await fixture([tapRow('tapUnnamedNested', {nodeArgs: []}), tapRow('tapMalformed', {nodeArgs: []}),
      tapRow('tapDirectivePlan', {nodeArgs: []})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.ok(result.cases.every(value => value.status === 'FAIL'))
    assert.deepEqual(result.cases.map(value => value.reason), ['TAP_NESTING_UNSUPPORTED', 'TAP_MALFORMED_ASSERTION_OR_PLAN', 'TAP_PLAN_DIRECTIVE_FORBIDDEN'])
    assert.equal(result.cases[0].unknown_failed_count, 1)
  })
  await check('declared-external-skip-is-counted-unperformed-and-never-qualification', async () => {
    const own = await fixture([tapRow('tapExternal', {externalSkips: [{title: 'synthetic external PG', reason: 'NO_EXTERNAL_PG'}]})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'UNPERFORMED'); assert.equal(result.exit_code, 2); assert.equal(result.functional_status, 'PASS')
    assert.equal(result.cases[0].functional_status, 'PASS'); assert.equal(result.cases[0].test_count, 1)
    assert.equal(result.cases[0].external_unperformed_count, 1)
    assert.equal(result.cases[0].skipped_count, 1); assert.equal(result.cases[0].required_skipped_count, 0)
    assert.deepEqual(result.cases[0].external_skips, [{title: 'synthetic external PG', reason: 'NO_EXTERNAL_PG', reason_matches: true, status: 'UNPERFORMED', count: 1}])
  })
  await check('external-title-must-skip-with-exact-compiled-reason', async () => {
    const own = await fixture([
      tapRow('tapTwo', {externalSkips: [{title: 'synthetic second', reason: 'NO_EXTERNAL_PG'}]}),
      tapRow('tapExternalWrongReason', {nodeArgs: [], externalSkips: [{title: 'synthetic external PG', reason: 'NO_EXTERNAL_PG'}]})
    ]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1)
    assert.deepEqual(result.cases.map(value => value.reason), ['TAP_EXTERNAL_TEST_NOT_SKIPPED', 'TAP_EXTERNAL_SKIP_REASON_MISMATCH'])
    assert.equal(result.cases[1].skipped_count, 1); assert.equal(result.cases[1].external_unperformed_count, 1)
    assert.equal(result.cases[1].external_skips[0].reason_matches, false)
  })
  await check('tap-summary-cannot-hide-failure-cancellation-skip-or-todo', async () => {
    const own = await fixture(['tapSummaryMissing', 'tapSummaryFailed', 'tapSummaryCancelled', 'tapSummarySkipped', 'tapSummaryTodo', 'tapSummaryWrongCount', 'tapSummaryMalformedDuplicate']
      .map(kind => tapRow(kind, {nodeArgs: []}))), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.ok(result.cases.every(value => value.status === 'FAIL'))
    assert.deepEqual(result.cases.map(value => value.reason), ['TAP_REQUIRED_COUNTS_MISSING', 'TAP_REQUIRED_TESTS_INCOMPLETE',
      'TAP_REQUIRED_TESTS_INCOMPLETE', 'TAP_SUMMARY_COUNTS_MISMATCH', 'TAP_REQUIRED_TESTS_INCOMPLETE', 'TAP_SUMMARY_COUNTS_MISMATCH', 'TAP_REQUIRED_COUNTS_MISSING'])
  })
  await check('nonzero-tap-process-retains-only-known-failing-titles-and-failure-precedence', async () => {
    const own = await fixture([
      tapRow('tapKnownFail', {nodeArgs: [], requiredTitles: ['synthetic selected', 'synthetic second']}),
      tapRow('tapUnknownFail', {nodeArgs: []}), tapRow('tapProcessFail', {nodeArgs: []}),
      tapRow('tapExternal', {externalSkips: [{title: 'synthetic external PG', reason: 'NO_EXTERNAL_PG'}]})
    ]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'FAIL'); assert.equal(result.exit_code, 1)
    assert.equal(result.cases[0].reason, 'TAP_ASSERTION_FAILED'); assert.deepEqual(result.cases[0].failed_titles, ['synthetic selected'])
    assert.deepEqual(result.cases[1].failed_titles, []); assert.equal(result.cases[1].unknown_failed_count, 1)
    assert.equal(result.cases[2].reason, 'ASSERTION_PROCESS_FAILED'); assert.equal(result.cases[2].test_count, 1)
    assert.equal(result.cases[3].status, 'UNPERFORMED')
  })
  await check('pass-lines-require-exact-labels-and-optional-summary', async () => {
    const own = await fixture([labelsRow('passLines', {summaryLine: 'Synthetic 2 groups complete'})]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'PASS'); assert.equal(result.cases[0].test_count, 2)
    const bad = await fixture([labelsRow('passLinesDuplicate'), labelsRow('passLinesFail'), labelsRow('passLinesUnknown'),
      labelsRow('passLines', {summaryLine: 'Missing synthetic summary'})]), refusal = await bad.run(); cleanSummary(refusal)
    assert.equal(refusal.exit_code, 1); assert.ok(refusal.cases.every(value => value.status === 'FAIL'))
    assert.deepEqual(refusal.cases[1].failed_titles, ['synthetic second']); assert.equal(refusal.cases[2].unknown_title_count, 1)
  })
  await check('assert-json-requires-pass-exact-counter-and-process-zero', async () => {
    const own = await fixture([jsonRow('jsonPass')]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'PASS'); assert.deepEqual(result.cases[0].counter, {key: 'checks', expected: 2, observed: 2})
    const bad = await fixture([jsonRow('jsonWrong'), jsonRow('jsonZero', {counter: {key: 'cases', value: 2}}),
      jsonRow('jsonClaim'), jsonRow('jsonProcessFail'), jsonRow('jsonAmbiguous'), jsonRow('jsonPrivate')]), refusal = await bad.run(); cleanSummary(refusal)
    assert.equal(refusal.exit_code, 1); assert.ok(refusal.cases.every(value => value.status === 'FAIL'))
    assert.equal(refusal.cases[3].reason, 'ASSERTION_PROCESS_FAILED'); assert.equal(refusal.cases[3].counter.observed, 2)
    assert.equal(refusal.cases[5].counter.observed, null)
  })
  await check('json-summary-must-be-unambiguous-pass-with-no-required-incomplete-counts', async () => {
    const own = await fixture(['jsonExact', 'jsonConflict', 'jsonSkipped', 'jsonTodo', 'jsonFailed', 'jsonCancelled', 'jsonNestedFailure', 'jsonConflictingSummary', 'jsonEarlierFailure', 'jsonNegativePass']
      .map(kind => jsonRow(kind))), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.ok(result.cases.every(value => value.status === 'FAIL'))
    assert.equal(result.cases[0].reason, 'ASSERT_JSON_RESULT_NOT_PASS'); assert.equal(result.cases[1].reason, 'ASSERT_JSON_RESULT_NOT_PASS')
    assert.ok(result.cases.slice(2, 7).every(value => value.reason === 'ASSERT_JSON_REQUIRED_TESTS_INCOMPLETE'))
    assert.equal(result.cases[7].reason, 'ASSERT_JSON_SUMMARY_AMBIGUOUS')
    assert.equal(result.cases[8].reason, 'ASSERT_JSON_REQUIRED_TESTS_INCOMPLETE'); assert.equal(result.cases[9].reason, 'ASSERT_JSON_REQUIRED_TESTS_INCOMPLETE')
  })
  await check('compiled-hook-pin-export-interface-and-disposal-precede-main-child', async () => {
    const own = await fixture([hookRow()]), result = await own.run(); cleanSummary(result)
    assert.equal(result.status, 'PASS'); assert.equal(result.cases[0].hook_controller.preflight, 'PASS')
    assert.equal(existsSync(join(own.evidenceDir, 'hook-main/tmp/controller-disposed')), true)
    assert.equal(existsSync(join(own.evidenceDir, 'hook-main/main-ran')), true)
    for (const kind of ['controllerBadExport', 'controllerBadInterface']) {
      const bad = await fixture([hookRow(kind)]), refusal = await bad.run(); cleanSummary(refusal)
      assert.equal(refusal.exit_code, 1); assert.equal(refusal.cases[0].reason, 'HOOK_CONTROLLER_INTERFACE_FAILED')
      assert.equal(existsSync(join(bad.evidenceDir, 'hook-main/main-ran')), false)
      if (kind === 'controllerBadInterface') assert.equal(existsSync(join(bad.evidenceDir, 'hook-main/tmp/controller-disposed')), true)
    }
  })
  await check('hook-controller-missing-mismatched-support-or-mutated-bytes-fail-coverage', async () => {
    const fixtures = [
      await fixture([hookRow('controllerGood', {hookController: {path: 'checks/controllerGood.mjs', sha256: '0'.repeat(64)}})]),
      await fixture([hookRow()], ({root}) => rmSync(join(root, 'checks/controllerGood.mjs'))),
      await fixture([hookRow('controllerGood', {pins: [{path: 'checks/support.json', sha256: '0'.repeat(64)}]})]),
      await fixture([hookRow('controllerMutate'), row('pass')])
    ]
    for (const own of fixtures) {
      const result = await own.run(); cleanSummary(result); assert.equal(result.exit_code, 1)
      assert.equal(existsSync(join(own.evidenceDir, 'hook-main/main-ran')), false)
    }
  })
  await check('hook-prerequisite-and-main-execution-share-case-deadline', async () => {
    const own = await fixture([row('hookSlowMain', {timeoutMs: 250, hookController: {path: 'checks/controllerSlow.mjs', sha256: controllerPins.controllerSlow}}), row('pass')], instrumentDeadline)
    const result = await own.run(); cleanSummary(result); lastBudgetTrace = own.budgetTrace
    assert.deepEqual(own.budgetTrace, [{phase: 'controller-preflight', timeout_ms: 250}, {phase: 'main', timeout_ms: 150}])
    assert.equal(result.exit_code, 2); assert.equal(result.cases[0].hook_controller.preflight, 'PASS')
    assert.equal(result.cases[0].reason, 'CASE_TIMEOUT'); assert.equal(result.cases[1].reason, 'EARLIER_EXECUTION_INCOMPLETE')
    assert.equal(result.cases[0].duration_ms, 250); assert.equal(own.budgetTrace.length, 2)
  })
  await check('main-child-controller-mutation-fails-post-execution-source-guard', async () => {
    const own = await fixture([row('hookMutateMain', {hookController: {path: 'checks/controllerGood.mjs', sha256: controllerPins.controllerGood}}), row('pass')]), result = await own.run(); cleanSummary(result)
    assert.equal(result.exit_code, 1); assert.equal(result.cases[0].hook_controller.preflight, 'PASS')
    assert.equal(result.cases[0].reason, 'HOOK_CONTROLLER_SOURCE_CHANGED'); assert.equal(result.cases[1].reason, 'EARLIER_EXECUTION_INCOMPLETE')
  })
  await check('only-compiled-hook-and-host-bindings-propagate-and-provider-env-is-scrubbed', async () => {
    const keys = ['TEST_OWNED_SHOULD_NOT_PROPAGATE', 'NODE_OPTIONS', 'NODE_PATH', 'PGHOST', 'PGPASSWORD', 'PRIME_OWNER_HOOK_CONTROLLER', 'PRIME_OWNER_MEMORY_HOST_ROOT', 'PRIME_OWNER_MEMORY_SOURCE_PIN', 'OPENAI_API_KEY']
    const saved = keys.map(key => process.env[key])
    for (const key of keys) process.env[key] = 'synthetic-caller-credential'
    try {
      const own = await fixture([row('envScrub'), row('hostRoot', {hostRoot: true}), row('sourcePin', {syntheticSourcePin: true}), hookRow()]), result = await own.run(); cleanSummary(result)
      assert.equal(result.status, 'PASS')
      assert.equal(result.source_review_attribution, 'LITERAL_ENTRY_PINS_NOT_CHECKOUT_ATTESTATION')
      assert.equal(result.cases[2].synthetic_source_pin, 'FIXTURE_ONLY_ZERO_METADATA_NOT_CHECKOUT_ATTESTATION')
    } finally {
      keys.forEach((key, index) => {if (saved[index] === undefined) delete process.env[key]; else process.env[key] = saved[index]})
    }
  })
  await check('closed-protocol-schemas-and-reviewed-case-caps-refuse-before-spawn', async () => {
    const invalid = [tapRow('tap', {requiredTitles: []}), tapRow('tap', {requiredTitles: ['synthetic selected', 'synthetic selected']}),
      tapRow('tap', {externalSkips: [{title: 'synthetic selected', reason: 'NO_EXTERNAL_PG'}]}),
      tapRow('tap', {externalSkips: [{title: 'synthetic external PG', reason: 'NO_EXTERNAL_PG', extra: true}]}),
      row('pass', {requiredTitles: ['synthetic selected']}), jsonRow('jsonExact', {counter: {key: 'status', value: 1}}),
      row('pass', {protocol: '__proto__'}), row('pass', {protocol: ['tap']}),
      row('pass', {nodeArgs: ['--test-name-pattern', 'synthetic']}), row('pass', {nodeArgs: ['--test-name-pattern=synthetic']}),
      row('pass', {nodeArgs: ['--test-skip-pattern', 'synthetic']}), row('pass', {nodeArgs: ['--test-skip-pattern=synthetic']}),
      row('pass', {args: ['--test-name-pattern=synthetic']}), row('pass', {nodeArgs: ['--test-only']}),
      jsonRow('jsonExact', {counter: {key: 'checks', value: 0}}), labelsRow('passLines', {requiredLabels: []}),
      labelsRow('passLines', {summaryLine: 'FAIL synthetic first'}),
      hookRow('controllerGood', {hookController: {path: '../controller.mjs', sha256: controllerPins.controllerGood}}),
      hookRow('controllerGood', {hookController: {path: 'checks/controllerGood.mjs', sha256: controllerPins.controllerGood, export: 'other'}}),
      row('hostRoot', {hostRoot: false}), row('sourcePin', {syntheticSourcePin: false}),
      tapRow('tap', {timeoutMs: 120_001}), row('pass', {timeoutMs: 60_001}),
      jsonRow('jsonPass', {timeoutMs: 120_000}), labelsRow('passLines', {timeoutMs: 120_000})]
    for (const testRow of invalid) {
      const own = await fixture([testRow]), result = await own.run(); cleanSummary(result)
      assert.equal(result.reason, 'INVALID_COMPILED_MANIFEST'); assert.equal(existsSync(own.evidenceDir), false)
    }
    const accepted = await fixture([tapRow('tap', {timeoutMs: 120_000}), row('pass', {timeoutMs: 60_000})]), result = await accepted.run(); cleanSummary(result)
    assert.equal(result.status, 'PASS'); assert.equal(result.budget.case_max_ms, 180_000)
    assert.equal(result.budget.ordinary_case_max_ms, 60_000); assert.equal(result.budget.suite_ms, 600_000)
    assert.equal(result.budget.wall_target_ms, null); assert.equal(result.budget.expected_full_profile_duration_ms, null)
    assert.equal(result.budget.expected_full_profile_duration_status, 'NOT_MEASURED')
    assert.ok(Number.isInteger(result.duration_ms)); assert.match(result.duration_scope, /EXCLUDES_FINAL_EVIDENCE_WRITE/)
  })
  await check('authority-core-budget-exception-is-exact-and-finite-before-spawn', async () => {
    const core = jsonRow('jsonExact', {id: 'authority-core-only', entry: 'packages/authority/check.mjs',
      expectedSha256: 'a745a3b8ab6b8ebb182a6322577b10ec845f0af027120cc7dbd15d41a7666cfe',
      args: ['core-only'], nodeArgs: ['--max-old-space-size=512'], counter: {key: 'checks', value: 125}, timeoutMs: 180_000})
    const controller = new AbortController(); controller.abort()
    const own = await fixture([core]), accepted = await own.run({signal: controller.signal}); cleanSummary(accepted)
    assert.equal(accepted.cases[0].reason, 'CANCELLED'); assert.equal(existsSync(join(own.evidenceDir, core.id)), false)
    assert.equal(accepted.budget.authority_core_only_max_ms, 180_000); assert.equal(accepted.budget.tap_case_max_ms, 120_000)
    for (const change of [{timeoutMs: 180_001}, {id: 'other-core'}, {entry: 'checks/jsonExact.mjs'},
      {expectedSha256: '0'.repeat(64)}, {args: []}, {args: ['extended']}, {nodeArgs: []},
      {counter: {key: 'checks', value: 124}}, {counter: {key: 'checks', value: 125, extra: true}}]) {
      const bad = await fixture([{...core, ...change}]), refused = await bad.run({signal: controller.signal}); cleanSummary(refused)
      assert.equal(refused.reason, 'INVALID_COMPILED_MANIFEST'); assert.equal(existsSync(bad.evidenceDir), false)
    }
  })
  await check('compiled-case-population-accepts-sixty-six-and-refuses-sixty-seven-before-spawn', async () => {
    const rows = Array.from({length: 66}, (_, index) => row('pass', {id: 'reviewed-' + index}))
    const own = await fixture(rows), controller = new AbortController()
    controller.abort()
    const accepted = await own.run({signal: controller.signal}); cleanSummary(accepted)
    assert.equal(accepted.configured_case_count, 66); assert.equal(accepted.case_count, 66)
    assert.equal(accepted.status, 'UNPERFORMED'); assert.equal(accepted.exit_code, 2)
    assert.deepEqual(accepted.counts, {pass: 0, fail: 0, unperformed: 66})
    assert.ok(accepted.cases.every(value => value.status === 'UNPERFORMED' && value.reason === 'CANCELLED' && value.child_exit_code === undefined))
    assert.ok(rows.every(value => !existsSync(join(own.evidenceDir, value.id))))
    const tooMany = await fixture([...rows, row('pass', {id: 'unreviewed-67'})])
    const refused = await tooMany.run({signal: controller.signal}); cleanSummary(refused)
    assert.equal(refused.reason, 'INVALID_COMPILED_MANIFEST'); assert.equal(refused.cases.length, 0)
    assert.equal(existsSync(tooMany.evidenceDir), false)
  })
  await check('support-pin-cap-accepts-nine-and-refuses-thirteen', async () => {
    const nine = Array.from({length: 9}, (_, index) => ({path: 'checks/support-' + index + '.json', sha256: supportPin}))
    const own = await fixture([row('pass', {pins: nine})], ({root}) => {
      for (const pin of nine) writeFileSync(join(root, pin.path), supportBytes, {mode: 0o600})
    }), accepted = await own.run(); cleanSummary(accepted)
    assert.equal(accepted.status, 'PASS')
    const thirteen = Array.from({length: 13}, (_, index) => ({path: 'checks/support-' + index + '.json', sha256: supportPin}))
    const invalid = await fixture([row('pass', {pins: thirteen})]), refused = await invalid.run(); cleanSummary(refused)
    assert.equal(refused.reason, 'INVALID_COMPILED_MANIFEST'); assert.equal(existsSync(invalid.evidenceDir), false)
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
    for (const options of [{env: {TEST: 'disallowed'}}, {suiteMs: 600_000}, {timeoutMs: 120_000}]) {
      const own = await fixture([row('pass')]), result = await own.run(options)
      cleanSummary(result); assert.equal(result.reason, 'CLOSED_ENGINE_OPTIONS_REQUIRED'); assert.equal(existsSync(own.evidenceDir), false)
    }
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
  console.log(JSON.stringify({status: 'PASS', checks: checks.length, configured_checks: configuredChecks, unperformed_checks: configuredChecks - checks.length,
    scope: focused ? 'fixed accounting regressions only' : 'disposable engine orchestration only',
    ...(focused ? {observations: focusedObservations} : {}),
    core_checks: 'NOT_RUN', network: 'NOT_USED', host_mutations: 'NOT_PERFORMED', qualification: 'UNPERFORMED', g1: 'PENDING'}))
} finally {rmSync(temp, {recursive: true, force: true})}
