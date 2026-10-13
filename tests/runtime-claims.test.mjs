// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic evidence controls exercise status, binding, bounds and generated-byte refusals.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, symlinkSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as audit from '../scripts/audit/runtime-claims.mjs'
import { gateEntryBody } from '../scripts/aura/gate-snapshot.mjs'
import { pluginSetApprovalText, PLUGIN_SET_TARGET } from '../packages/boundary-gate/src/vendor/operator-data.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const sourceUrl = new URL('../scripts/audit/runtime-claims.mjs', import.meta.url)
const source = readFileSync(sourceUrl, 'utf8')
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const clone = value => structuredClone(value)
const base = { id: 'example', statement: 'A dated observation.', where: 'pilot', date: '2026-10-13',
  commit: '1'.repeat(40), verification: 'reported', source: 'plan/NORTH-STAR.md', evidence: 'reported-only',
  upgrade: 'Publish evidence.', limit: 'No runtime attestation.' }
const doc = row => ({ schema: 'aukora-runtime-claims/v1', claims: [row] })
const ci = { ...base, where: 'ci', verification: 'verified', evidence: {
  kind: 'ci', runId: 42, attempt: 1, job: 'fresh clone boots', artifact: 'fresh-clone-example-1' } }
const page = '<!-- BEGIN GENERATED runtime-claims -->\nold\n<!-- END GENERATED runtime-claims -->\n'
const work = mkdtempSync(join(root, '.runtime-claims-test-'))
mkdirSync(join(work, 'evidence'))
mkdirSync(join(work, 'scripts/aura'), { recursive: true })
mkdirSync(join(work, 'docs'))
writeFileSync(join(work, 'evidence/runtime-claims.json'), JSON.stringify(doc(base)))
writeFileSync(join(work, 'docs/CLAIMS.md'), page)
writeFileSync(join(work, 'ok.mjs'), "console.log('synthetic probe')\n")
writeFileSync(join(work, 'hang.mjs'), 'setInterval(()=>{},1000)\n')
const fromClone = { ...base, verification: 'verified', evidence: {
  kind: 'clone', command: ['node', 'ok.mjs'], stdoutSha256: sha('synthetic probe\n'), timeoutMs: 500 } }
const originalEntries = readFileSync(new URL('../docs/evidence/l2-demo-2026-10-04/ledger-entries.json', import.meta.url))
const key = readFileSync(new URL('../docs/evidence/l2-demo-2026-10-04/gate-ed25519.pub', import.meta.url))
writeFileSync(join(work, 'evidence/ledger.json'), originalEntries)
writeFileSync(join(work, 'evidence/public.pem'), key)
writeFileSync(join(work, 'scripts/aura/verify-export.mjs'),
  `import {main} from ${JSON.stringify(new URL('../scripts/aura/verify-export.mjs', import.meta.url).href)};process.exitCode=main();\n`)
const entries = JSON.parse(originalEntries)
const ledger = { ...base, verification: 'verified', evidence: { kind: 'ledger', file: 'evidence/ledger.json',
  sha256: sha(originalEntries), publicKey: 'evidence/public.pem', keySha256: sha(key), anchor: null, approval: null,
  sequence: entries.length, entryHash: entries.at(-1).hash } }
symlinkSync(resolve(root, 'package.json'), join(work, 'outside.mjs'))
const responses = () => [
  { id: 42, head_sha: ci.commit, run_attempt: 1, repository: { full_name: 'aumara-xyz/aukora-prime' } },
  { total_count: 1, jobs: [{ name: ci.evidence.job, run_id: 42, head_sha: ci.commit, status: 'completed', conclusion: 'success' }] },
  { total_count: 1, artifacts: [{ name: ci.evidence.artifact, expired: false, size_in_bytes: 8,
    workflow_run: { id: 42, head_sha: ci.commit } }] },
]
const request = values => async url => {
  assert.match(url, /^https:\/\/api.github.com\/repos\/aumara-xyz\/aukora-prime\/actions\/runs\/42\//u)
  return values.shift()
}
const good = { directory: work, clean: () => '2'.repeat(40), committed: () => true }
const cases = []
const pair = generateKeyPairSync('ed25519')
const approvalText = pluginSetApprovalText({ release: base.commit, release_dir: 'release-' + base.commit.slice(0, 7),
  record: '3'.repeat(64), operation: '4'.repeat(64), plugin_set: '5'.repeat(64) })
const approvalEntry = { seq: 1, at: '2026-10-13T00:00:00.000Z', event: 'apply', proposal: null,
  target: PLUGIN_SET_TARGET, base_sha: null, new_sha: sha(approvalText), detail: null, prev: 'GENESIS' }
approvalEntry.hash = sha(gateEntryBody(approvalEntry))
approvalEntry.sig = sign(null, Buffer.from(approvalEntry.hash, 'hex'), pair.privateKey).toString('base64')
const approvalKey = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString()
const approvalBytes = JSON.stringify([approvalEntry])
writeFileSync(join(work, 'evidence/approval-ledger.json'), approvalBytes)
writeFileSync(join(work, 'evidence/approval-public.pem'), approvalKey)
writeFileSync(join(work, 'evidence/release-approval.json'), approvalText)
const approved = { ...ledger, evidence: { ...ledger.evidence, file: 'evidence/approval-ledger.json', sha256: sha(approvalBytes),
  publicKey: 'evidence/approval-public.pem', keySha256: sha(approvalKey), sequence: 1, entryHash: approvalEntry.hash,
  approval: 'evidence/release-approval.json' } }
protection('approval-not-committed', async module => assert.equal((await module.verifyClaim(approved,
  { ...good, committed: file => file !== 'evidence/release-approval.json' })).status, 'FAILED'))
protection('ledger-release-approval-binding', async module => assert.equal((await module.verifyClaim({ ...approved,
  commit: '6'.repeat(40) }, good)).status, 'FAILED'))
function protection(name, body) { cases.push({ name, body }) }
function invalid(name, edit) {
  protection(name, module => { const value = doc(clone(base)); edit(value); assert.throws(() => module.validateDocument(value), { message: `runtime-claims:${name}` }) })
}
invalid('schema-fields', value => { value.extra = true })
invalid('schema-inventory', value => { value.claims = [] })
invalid('schema-id', value => { value.claims.push(clone(base)) })
invalid('schema-text', value => { value.claims[0].source = '../private' })
invalid('schema-location', value => { value.claims[0].where = 'unknown' })
invalid('schema-date', value => { value.claims[0].date = '2026-02-30' })
invalid('schema-commit', value => { value.claims[0].commit = '1234567' })
invalid('schema-verification', value => { value.claims[0].verification = 'pass' })
invalid('reported-cannot-be-verified', value => { value.claims[0].verification = 'verified' })
invalid('evidence-needs-commit-and-verification', value => { value.claims = [{ ...ci, commit: null }] })
invalid('schema-clone', value => { value.claims = [{ ...fromClone, evidence: { ...fromClone.evidence, command: ['node', '-e'] } }] })
invalid('schema-ci', value => { value.claims = [{ ...ci, evidence: { ...ci.evidence, runId: 0 } }] })
invalid('schema-ledger', value => { value.claims = [{ ...ledger, evidence: { ...ledger.evidence, file: 'docs/ledger.json' } }] })
invalid('schema-evidence', value => { value.claims = [{ ...ci, evidence: { kind: 'other' } }] })
async function withFetch(value, body) {
  const original = globalThis.fetch
  globalThis.fetch = async (_url, options) => {
    assert.equal(options.headers.Authorization, undefined)
    assert.equal(options.redirect, 'error')
    assert(options.signal instanceof AbortSignal)
    return value
  }
  try { return await body() } finally { globalThis.fetch = original }
}
protection('ci-api-response', async module => withFetch(new Response('{}', { status: 404 }), async () => {
  assert.equal((await module.verifyClaim(ci)).reason, 'runtime-claims:ci-api-response')
}))
protection('ci-response-bound', async module => withFetch(new Response('x'.repeat(1024 * 1024 + 1)), async () => {
  assert.equal((await module.verifyClaim(ci)).reason, 'runtime-claims:ci-response-bound')
}))
protection('file-type-or-size', async module => {
  writeFileSync(join(work, 'evidence/oversize.pem'), Buffer.alloc(8193))
  assert.equal((await module.verifyClaim({ ...ledger, evidence: { ...ledger.evidence,
    publicKey: 'evidence/oversize.pem' } }, good)).reason, 'runtime-claims:file-type-or-size')
})
protection('path-outside-clone', async module => assert.equal((await module.verifyClaim({ ...fromClone,
  evidence: { ...fromClone.evidence, command: ['node', 'outside.mjs'] } }, { ...good,
  run: () => ({ status: 0, signal: null, stdout: 'synthetic probe\n' }) })).status, 'FAILED'))
protection('time-budget-exhausted', async module => assert.equal((await module.verifyClaim(ci,
  { remaining: () => 0, request: request(responses()) })).status, 'UNPERFORMED'))
for (const [name, change] of [
  ['ci-run-binding', values => { values[0].head_sha = '2'.repeat(40) }],
  ['ci-job-inventory', values => { values[1].total_count = 101 }],
  ['ci-job-not-successful', values => { values[1].jobs[0].conclusion = 'failure' }],
  ['ci-artifact-inventory', values => { values[2].total_count = 101 }],
  ['ci-artifact-unavailable', values => { values[2].artifacts[0].expired = true }],
]) protection(name, async module => {
  const values = responses(); change(values)
  assert.equal((await module.verifyClaim(ci, { request: request(values) })).status, 'FAILED')
})
protection('clone-dirty-tree', async module => assert.equal((await module.verifyClaim(fromClone, { ...good, clean: () => false })).status, 'FAILED'))
protection('clone-output-mismatch', async module => assert.equal((await module.verifyClaim({ ...fromClone,
  evidence: { ...fromClone.evidence, stdoutSha256: '0'.repeat(64) } }, good)).status, 'FAILED'))
protection('ledger-file-digest', async module => assert.equal((await module.verifyClaim({ ...ledger,
  evidence: { ...ledger.evidence, sha256: '0'.repeat(64) } }, good)).status, 'FAILED'))
protection('ledger-key-digest', async module => assert.equal((await module.verifyClaim({ ...ledger,
  evidence: { ...ledger.evidence, keySha256: '0'.repeat(64) } }, good)).status, 'FAILED'))
protection('ledger-not-committed', async module => assert.equal((await module.verifyClaim(ledger,
  { ...good, committed: () => false })).status, 'FAILED'))
const anchor = { seq: entries.length, head: entries.at(-1).hash, gate_fp: '6cdce2bbeb7b725c' }
writeFileSync(join(work, 'evidence/anchor.json'), JSON.stringify(anchor))
const anchored = { ...ledger, evidence: { ...ledger.evidence, anchor: 'evidence/anchor.json' } }
protection('anchor-not-committed', async module => assert.equal((await module.verifyClaim(anchored,
  { ...good, committed: file => file !== 'evidence/anchor.json' })).status, 'FAILED'))
protection('ledger-entry-binding', async module => assert.equal((await module.verifyClaim({ ...ledger,
  evidence: { ...ledger.evidence, entryHash: '0'.repeat(64) } }, good)).status, 'FAILED'))
protection('ledger-verification-failed', async module => assert.equal((await module.verifyClaim(ledger,
  { ...good, run: () => ({ status: 1, stdout: 'NOT VERIFIED\n', signal: null }) })).status, 'FAILED'))
protection('generated-markers', module => assert.throws(() => module.generatedPage(page + page, doc(base)), /generated-markers/u))
protection('offline-does-not-pass', async module => {
  const result = await module.verifyClaim(ci, { offline: true, request: () => { throw Error('network must not run') } })
  assert.equal(result.status, 'UNPERFORMED')
  // Unreachable is unperformed (exit 2): never a pass, and not a failure that turns every offline run red.
  assert.equal(module.resultCode([result], [ci]), 2)
  // Reachable evidence that does not hold for a claim recorded as verified is still a failure.
  assert.equal(module.resultCode([{ status: 'REPORTED', reason: 'x' }], [ci]), 1)
})
protection('network-unavailable-does-not-pass', async module => {
  const result = await module.verifyClaim(ci, { request: () => { throw Error('runtime-claims:network-unavailable') } })
  assert.equal(result.status, 'UNPERFORMED')
  assert.equal(module.resultCode([result], [ci]), 2)
})
protection('failed-always-nonzero', module => assert.equal(module.resultCode([{ status: 'FAILED' }], [base]), 1))

test('reported rows, exact clone output, signed historical prefix and CI attempt metadata', async () => {
  for (const row of [base, ci, fromClone, ledger]) audit.validateDocument(doc(row))
  assert.equal((await audit.verifyClaim(base)).status, 'REPORTED')
  assert.equal((await audit.verifyClaim(fromClone, good)).status, 'VERIFIED')
  assert.equal((await audit.verifyClaim(ledger, good)).status, 'VERIFIED')
  assert.equal((await audit.verifyClaim(anchored, good)).status, 'VERIFIED')
  assert.equal((await audit.verifyClaim(approved, good)).status, 'VERIFIED')
  const urls = [], values = responses()
  assert.equal((await audit.verifyClaim(ci, { request: async url => { urls.push(url); return values.shift() } })).status, 'VERIFIED')
  assert.match(urls[0], /\/attempts\/1$/u, 'historical attempt stays selected after a rerun')
  assert.match(urls[1], /\/attempts\/1\/jobs\?per_page=100$/u)
  assert.equal(audit.resultCode([{ status: 'REPORTED' }], [base]), 0)
  assert.match(audit.renderTable(doc(base)), /\*\*REPORTED\*\*/u)
  assert.doesNotMatch(audit.renderTable(doc(ci)), /\*\*VERIFIED\*\*/u)
  const generated = audit.generatedPage(page, doc(base))
  assert.notEqual(page, generated)
  assert.equal(audit.generatedPage(generated, doc(base)), generated)
})
test('every refusal control', async () => { for (const { body } of cases) await body(audit) })
test('actual child timeout and a tampered signature never verify', async () => {
  const started = Date.now()
  assert.equal((await audit.verifyClaim({ ...fromClone, evidence: { ...fromClone.evidence, command: ['node', 'hang.mjs'], timeoutMs: 50 } }, good)).status, 'FAILED')
  assert(Date.now() - started < 2000)
  const tampered = clone(entries); tampered.at(-1).sig = Buffer.alloc(64).toString('base64')
  const bytes = JSON.stringify(tampered)
  writeFileSync(join(work, 'evidence/tampered.json'), bytes)
  assert.equal((await audit.verifyClaim({ ...ledger, evidence: { ...ledger.evidence,
    file: 'evidence/tampered.json', sha256: sha(bytes) } }, good)).status, 'FAILED')
})
test('CI run, job and artifact conjuncts all bind the selected evidence', async () => {
  for (const edit of [
    values => { values[0].id++ }, values => { values[0].run_attempt++ },
    values => { values[0].repository.full_name = 'other/repo' },
    values => { values[1].jobs[0].status = 'queued' }, values => { values[1].jobs[0].run_id++ },
    values => { values[1].jobs[0].head_sha = '0'.repeat(40) },
    values => { values[1].jobs.push(clone(values[1].jobs[0])); values[1].total_count++ },
    values => { values[2].artifacts[0].size_in_bytes = 0 },
    values => { values[2].artifacts[0].workflow_run.id++ },
    values => { values[2].artifacts[0].workflow_run.head_sha = '0'.repeat(40) },
    values => { values[2].artifacts.push(clone(values[2].artifacts[0])); values[2].total_count++ },
  ]) {
    const values = responses(); edit(values)
    assert.equal((await audit.verifyClaim(ci, { request: request(values) })).status, 'FAILED')
  }
  await withFetch(new Response('{}', { status: 429 }), async () => {
    assert.equal((await audit.verifyClaim(ci)).status, 'UNPERFORMED')
  })
})

async function imported(bytes, directory = root) {
  const rebased = bytes.replace("const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')", `const root = ${JSON.stringify(directory)}`)
    .replaceAll("'../aura/verify-collected.mjs'", JSON.stringify(new URL('../scripts/aura/verify-collected.mjs', import.meta.url).href))
    .replaceAll("'../../packages/boundary-gate/src/vendor/operator-data.mjs'", JSON.stringify(new URL('../packages/boundary-gate/src/vendor/operator-data.mjs', import.meta.url).href))
  return import(`data:text/javascript;base64,${Buffer.from(rebased).toString('base64')}`)
}
test('removing each protection makes its real control fail', async () => {
  let killed = 0
  for (const { name, body } of cases.filter(row => source.includes(`, '${row.name}')`))) {
    const end = source.indexOf(`, '${name}')`) + `, '${name}')`.length
    const start = source.lastIndexOf('requireValue(', end)
    assert(start >= 0, name)
    const mutant = await imported(source.slice(0, start) + `requireValue(true, '${name}')` + source.slice(end))
    await assert.rejects(async () => body(mutant), { code: 'ERR_ASSERTION' }, name)
    killed++
  }
  for (const [guard, replacement, name] of [
    ["else refuse('schema-evidence')", 'else void 0', 'schema-evidence'],
    ["if (offline) return { status: 'UNPERFORMED', reason: 'runtime-claims:network-disabled' }", '', 'offline-does-not-pass'],
    ["? 'UNPERFORMED' : 'FAILED', reason }", "? 'VERIFIED' : 'FAILED', reason }", 'network-unavailable-does-not-pass'],
    ["(claims[index].verification === 'verified' && !['VERIFIED', 'UNPERFORMED'].includes(row.status))", 'false', 'offline-does-not-pass'],
    ["row.status === 'FAILED' ||", 'false ||', 'failed-always-nonzero'],
  ]) {
    assert.equal(source.split(guard).length, 2, name)
    const mutant = await imported(source.replace(guard, replacement))
    await assert.rejects(async () => cases.find(row => row.name === name).body(mutant), { code: 'ERR_ASSERTION' }, name)
    killed++
  }
  console.log(`runtime-claims mutations: ${killed} killed / 0 survived`)
})
test('actual CLI refuses stale output and invalid argv; removing each guard fails the control', async () => {
  async function silentMain(module, args) {
    const original = console.log, logs = []; console.log = value => logs.push(value)
    try { return { code: await module.main(args), logs } } finally { console.log = original }
  }
  const module = await imported(source, work)
  const stale = await silentMain(module, ['--check', '--offline'])
  assert.equal(stale.code, 1)
  assert(stale.logs.includes('FAILED runtime-claims:stale-generated-table'))
  for (const [before, after, args, reason] of [
    ["if (argv.includes('--check') && source !== expected)", 'if (false)', ['--check', '--offline'], 'runtime-claims:stale-generated-table'],
    ["requireValue(process.versions.node === '24.11.1', 'node-version')", "requireValue(true, 'node-version')", [], 'runtime-claims:node-version'],
  ]) {
    const initial = reason.endsWith('node-version') ? source.replace("process.versions.node === '24.11.1'", "'24.11.0' === '24.11.1'") : source
    const target = reason.endsWith('node-version') ? before.replace('process.versions.node', "'24.11.0'") : before
    const control = async api => {
      const result = await silentMain(api, args)
      assert.equal(result.code, 1)
      assert(result.logs.includes('FAILED ' + reason))
    }
    await control(await imported(initial, work))
    const mutant = await imported(initial.replace(target, after), work)
    await assert.rejects(() => control(mutant), { code: 'ERR_ASSERTION' })
  }
  const invalid = await silentMain(module, ['--check', '--write'])
  assert.equal(invalid.code, 1)
  assert(invalid.logs.includes('FAILED runtime-claims:usage'))
  const end = source.indexOf(", 'usage')") + ", 'usage')".length
  const start = source.lastIndexOf('requireValue(', end)
  const noUsage = await imported(source.slice(0, start) + "requireValue(true, 'usage')" + source.slice(end), work)
  assert(!(await silentMain(noUsage, ['--check', '--write'])).logs.includes('FAILED runtime-claims:usage'))
  const written = await silentMain(module, ['--write'])
  assert.equal(written.code, 0)
  assert.equal((await silentMain(module, ['--check', '--offline'])).code, 0)
  console.log('runtime-claims CLI mutations: 3 killed / 0 survived')
})
test('child bounds, clean-source identity and private environment survive guard removals', async () => {
  const shim = source.replace("import { spawnSync } from 'node:child_process'", 'const spawnSync = (...args) => globalThis.__runtimeSpawn(...args)')
  async function childControl(module) {
    globalThis.__runtimeSpawn = (_program, args, options) => {
      assert(options.timeout > 0 && options.timeout <= 5000)
      assert.equal(options.killSignal, 'SIGKILL')
      assert.equal(options.maxBuffer, 1024 * 1024)
      assert.equal(options.env.AUKORA_RUNTIME_SYNTHETIC_SECRET, undefined)
      if (args[0] === 'rev-parse') return { status: 0, stdout: '2'.repeat(40) + '\n' }
      if (args[0] === 'status') return { status: 0, stdout: '' }
      return { status: 0, signal: null, stdout: 'synthetic probe\n' }
    }
    const result = await module.verifyClaim(fromClone, { directory: work })
    assert.equal(result.status, 'VERIFIED')
    assert.equal(result.checkedCommit, '2'.repeat(40))
    globalThis.__runtimeSpawn = (_program, args) => ({ status: 0, signal: null,
      stdout: args[0] === 'rev-parse' ? '2'.repeat(40) + '\n' : args[0] === 'status' ? ' M ok.mjs\n' : 'synthetic probe\n' })
    assert.equal((await module.verifyClaim(fromClone, { directory: work })).status, 'FAILED')
  }
  const previous = process.env.AUKORA_RUNTIME_SYNTHETIC_SECRET
  process.env.AUKORA_RUNTIME_SYNTHETIC_SECRET = 'synthetic-private-canary'
  try {
    await childControl(await imported(shim))
    for (const [before, after] of [
      ['encoding: \'utf8\', timeout, killSignal:', "encoding: 'utf8', killSignal:"],
      ["killSignal: 'SIGKILL',", ''], ['maxBuffer: 1024 * 1024,', ''],
      ["env: { PATH: process.env.PATH, LANG: 'C', TZ: 'UTC', GIT_NO_LAZY_FETCH: '1' }", 'env: process.env'],
      ["status.stdout === ''", 'true'],
    ]) {
      assert.equal(shim.split(before).length, 2)
      await assert.rejects(() => imported(shim.replace(before, after)).then(childControl), { code: 'ERR_ASSERTION' }, before)
    }
    console.log('runtime-claims child mutations: 5 killed / 0 survived')
  } finally {
    delete globalThis.__runtimeSpawn
    if (previous === undefined) delete process.env.AUKORA_RUNTIME_SYNTHETIC_SECRET
    else process.env.AUKORA_RUNTIME_SYNTHETIC_SECRET = previous
  }
})
test('public document and headline inventory agree and quote their source', () => {
  const document = audit.validateDocument(JSON.parse(readFileSync(new URL('../evidence/runtime-claims.json', import.meta.url))))
  const markdown = readFileSync(new URL('../docs/CLAIMS.md', import.meta.url), 'utf8')
  assert.equal(audit.generatedPage(markdown, document), markdown)
  for (const row of document.claims) {
    const words = value => value.replace(/\s+/gu, ' ').trim()
    assert(words(readFileSync(resolve(root, row.source), 'utf8')).includes(words(row.statement)), row.id)
  }
})
test.after(() => rmSync(work, { recursive: true, force: true }))
