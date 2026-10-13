// Example commands refuse changed receipts, stale refusal rows and unsafe readiness metadata.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import * as commands from '../scripts/example-commands.mjs'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { loadOwnerSecret } from '../packages/boundary-gate/src/secrets.mjs'
import { gateStore } from '../packages/boundary-gate/src/wiring.mjs'
import * as targets from '../packages/boundary-gate/src/targets.mjs'
import * as receipts from '../packages/boundary-gate/src/receipts.mjs'
import * as ledger from '../packages/boundary-gate/src/ledger.mjs'
import { OWNER_SOCKET_APPROVER } from '../packages/boundary-gate/src/server.mjs'

const repository = fileURLToPath(new URL('../', import.meta.url))
const source = fs.readFileSync(new URL('../scripts/example-commands.mjs', import.meta.url), 'utf8')
const reject = (call, code) => assert.throws(call, error => error.code === code)
function temporary(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync('/tmp'), 'aukora-example-test-'))
  fs.chmodSync(root, 0o700)
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return root
}
async function mutant(before, after) {
  assert.equal(source.split(before).length, 2, 'mutation anchor ' + before)
  const code = source.replace(before, after).replace("'./fresh-clone-runtime.mjs'",
    JSON.stringify(pathToFileURL(path.join(repository, 'scripts/fresh-clone-runtime.mjs')).href))
  return import('data:text/javascript;base64,' + Buffer.from(code).toString('base64'))
}

test('example arguments require exactly one action and a root; missing action protection is mutation tested', async t => {
  assert.deepEqual(commands.parseExampleArgs(['approve', '--root', '/private/state']), { command: 'approve', root: '/private/state' })
  for (const args of [[], ['verify'], ['up', '--root', '/s'], ['verify', 'approve', '--root', '/s']])
    reject(() => commands.parseExampleArgs(args), 'example-arguments-invalid')
  assert.throws(() => commands.parseExampleArgs(['verify', '--token', 'SYNTHETIC_PRIVATE_TOKEN']))
  const changed = await mutant("positionals.length !== 1 || !['approve', 'refuse', 'verify'].includes(positionals[0]) || !values.root", 'false')
  assert.throws(() => reject(() => changed.parseExampleArgs(['up', '--root', '/s']), 'example-arguments-invalid'), assert.AssertionError)
  t.diagnostic('KILLED example-argument-contract')
})

function readiness(t) {
  const root = temporary(t), checkout = path.join(root, 'clone'), release = path.join(root, 'release-1234567')
  const launchFile = path.join(root, 'support/state/launch-url.json')
  for (const dir of [checkout, release, path.dirname(launchFile)]) fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  fs.writeFileSync(launchFile, JSON.stringify({ url: 'http://127.0.0.1:1234/?token=SYNTHETIC_PRIVATE_TOKEN', pid: 12 }), { mode: 0o600 })
  const ready = { version: 1, kind: 'aukora-prime-example/v1', root, checkout, release, launchFile,
    origin: 'http://127.0.0.1:1234', supervisorPid: 42, controlPort: 12345, controlToken: 'a'.repeat(64) }
  const write = value => fs.writeFileSync(path.join(root, 'example-ready.json'), JSON.stringify(value), { mode: 0o600 })
  write(ready)
  return { root, ready, write }
}

test('readiness rejects other roots, external launch paths and nonloopback origins; removals fail regressions', async t => {
  const f = readiness(t)
  assert.deepEqual(commands.readExample(f.root), f.ready)
  for (const [name, change, code, before] of [
    ['ready-root', { root: f.root + '-other' }, 'example-readiness-invalid',
      "ready.version !== 1 || ready.kind !== 'aukora-prime-example/v1' || ready.root !== root"],
    ['ready-loopback', { origin: 'http://example.invalid:1234' }, 'example-origin-not-loopback',
      "url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.origin !== ready.origin"],
    ['ready-launch-path', { launchFile: path.join(f.root, 'example-ready.json') }, 'example-launch-path-invalid',
      "ready.launchFile !== path.join(root, 'support/state/launch-url.json')"],
  ]) {
    f.write({ ...f.ready, ...change })
    reject(() => commands.readExample(f.root), code)
    const changed = await mutant(before, 'false')
    assert.throws(() => reject(() => changed.readExample(f.root), code), assert.AssertionError)
    t.diagnostic('KILLED ' + name)
  }
  f.write({ ...f.ready, launchFile: path.join(path.dirname(f.root), 'outside.json') })
  reject(() => commands.readExample(f.root), 'example-path-outside-root')
})

function applicationCases(module) {
  const receipt = { proposal: 'one', new_sha: 'hash' }, applied = { applied: true, receipt, receipt_sig: 'sig' }
  const entry = { event: 'apply', proposal: 'one', detail: { receipt, receipt_sig: 'sig' } }
  const content = '{"accent": "#FFD700"}'
  module.assertApplied(applied, entry, content)
  for (const [a, e, c] of [[{ ...applied, applied: false }, entry, content], [applied, { ...entry, event: 'reject' }, content],
    [applied, { ...entry, proposal: 'another' }, content], [applied, { ...entry, detail: { ...entry.detail, receipt_sig: 'other' } }, content],
    [applied, { ...entry, detail: { ...entry.detail, receipt: { ...receipt, new_sha: 'other' } } }, content], [applied, entry, '{"accent": "default"}']])
    reject(() => module.assertApplied(a, e, c), 'example-approved-bytes-mismatch')
}

function refusalCases(module) {
  const entry = { sequence: 2, op: 'tool.decision', tool: 'fresh_clone_unapproved_action', callId: 'fresh-clone-denial',
    decision: 'deny', rule: 'authority:tool-not-approved' }
  module.assertRefusalEntry(entry, 1)
  for (const change of [{ sequence: 1 }, { op: 'other' }, { tool: 'other' }, { callId: 'other' }, { decision: 'allow' }, { rule: 'UNKNOWN_TOOL' }])
    reject(() => module.assertRefusalEntry({ ...entry, ...change }, 1), 'example-refusal-entry-missing')
}

test('approval and refusal evidence must match exact bytes and a fresh deny entry; each guard removal fails', async t => {
  applicationCases(commands); refusalCases(commands)
  for (const [name, before, exercise] of [
    ['effect-applied', 'applied?.applied !== true', applicationCases],
    ['effect-event', "entry?.event !== 'apply'", applicationCases],
    ['effect-proposal', 'entry.proposal !== applied.receipt?.proposal', applicationCases],
    ['effect-signature', 'entry.detail?.receipt_sig !== applied.receipt_sig', applicationCases],
    ['effect-receipt', 'JSON.stringify(entry.detail?.receipt) !== JSON.stringify(applied.receipt)', applicationCases],
    ['effect-bytes', 'content !== themeContent', applicationCases],
    ['refusal-freshness', 'entry.sequence <= previousSequence', refusalCases],
    ['refusal-op', "entry.op !== 'tool.decision'", refusalCases],
    ['refusal-tool', "entry.tool !== 'fresh_clone_unapproved_action'", refusalCases],
    ['refusal-call', "entry.callId !== 'fresh-clone-denial'", refusalCases],
    ['refusal-decision', "entry.decision !== 'deny'", refusalCases],
    ['refusal-rule', "entry.rule !== 'authority:tool-not-approved'", refusalCases],
  ]) {
    const changed = await mutant(before, 'false')
    assert.throws(() => exercise(changed), assert.AssertionError)
    t.diagnostic('KILLED ' + name)
  }
})

function signedFixture(t) {
  const root = temporary(t), home = path.join(root, 'gate-home')
  fs.mkdirSync(home, { mode: 0o700 })
  const gate = createGate({ home, owner: loadOwnerSecret(home), targets: {
    [targets.THEME_TARGET]: targets.themeTarget(path.join(root, 'targets')), [targets.NOTE_TARGET]: targets.noteTarget(path.join(root, 'targets')),
  }, store: gateStore() })
  t.after(() => gate.close())
  assert.equal(gate.startup({ pid: 1 }).ok, true)
  const proposed = gate.proposeOps.propose({ target: targets.THEME_TARGET, content: '{"accent": "#FFD700"}',
    claimed_base: 'absent', why: 'Synthetic example theme test', session: 'test' })
  const reviewed = gate.ownerOps.review({ id: proposed.id })
  const applied = gate.ownerOps.decide_review({ id: proposed.id, base_sha: reviewed.base_sha, new_sha: reviewed.new_sha,
    review_challenge: reviewed.review_challenge, outcome: 'allowed-once' }, OWNER_SOCKET_APPROVER)
  assert.equal(applied.applied, true)
  const { proposal, target, base_sha, new_sha } = applied.receipt
  return { gate, evidence: { receipt: applied.receipt, receipt_sig: applied.receipt_sig }, expected: { proposal, target, base_sha, new_sha },
    api: { targets, receipts, ledger }, root }
}

function checked(module, fixture, evidence = fixture.evidence, db = fixture.gate.db, expected = fixture.expected) {
  const lines = [], original = console.log
  console.log = line => lines.push(line)
  let error
  try { module.verifySignedEvidence(db, evidence, fixture.gate.pubPem, fixture.api, expected) } catch (failure) { error = failure }
  finally { console.log = original }
  return { lines, error }
}

test('repository verifiers reject receipt tampering, ledger tampering and absent receipt inclusion; refusal removal is detected', async t => {
  const f = signedFixture(t)
  assert.equal(checked(commands, f).error, undefined)
  const badSignature = { ...f.evidence, receipt_sig: Buffer.alloc(64).toString('base64') }
  const failed = checked(commands, f, badSignature)
  assert.equal(failed.error?.code, 'example-verification-failed')
  assert.equal(failed.lines.at(-1), 'FAIL | example receipt signature')
  const wrongTarget = { ...f.evidence, receipt: { ...f.evidence.receipt, target: targets.PLUGIN_SET_TARGET } }
  assert.equal(checked(commands, f, wrongTarget).lines.at(-1), 'FAIL | example receipt names exact theme change')
  const wrongProposal = { ...f.evidence, receipt: { ...f.evidence.receipt, proposal: 'different proposal' } }
  assert.equal(checked(commands, f, wrongProposal).lines.at(-1), 'FAIL | example receipt names exact theme change')
  const changed = await mutant("if (!ok) throw refuse('example-verification-failed')", 'if (false) throw refuse(\'example-verification-failed\')')
  assert.equal(checked(changed, f, badSignature).error, undefined)
  t.diagnostic('KILLED verification-failure-refusal')
  const db = ledger.openDb(path.join(f.root, 'empty.db'))
  try { assert.equal(checked(commands, f, f.evidence, db).lines.at(-1), 'FAIL | example receipt in signed ledger') }
  finally { db.close() }
  f.gate.db.exec('DROP TRIGGER ledger_no_update')
  f.gate.db.prepare('UPDATE ledger SET sig=? WHERE seq=1').run(Buffer.alloc(64).toString('base64'))
  assert.equal(checked(commands, f).lines.at(-1), 'FAIL | example signed ledger')
})

test('valid signed alternate operations and changed tour metadata cannot substitute for the exact approved theme; each binding mutation is killed', async t => {
  const f = signedFixture(t)
  function sign(target, content) {
    const current = f.gate.proposeOps.read({ target })
    const proposed = f.gate.proposeOps.propose({ target, content, claimed_base: current.sha256, why: 'Synthetic alternate operation', session: 'test' })
    const reviewed = f.gate.ownerOps.review({ id: proposed.id })
    const applied = f.gate.ownerOps.decide_review({ id: proposed.id, base_sha: reviewed.base_sha, new_sha: reviewed.new_sha,
      review_challenge: reviewed.review_challenge, outcome: 'allowed-once' }, OWNER_SOCKET_APPROVER)
    assert.equal(applied.applied, true)
    const { proposal, base_sha, new_sha } = applied.receipt
    return { evidence: { receipt: applied.receipt, receipt_sig: applied.receipt_sig }, expected: { proposal, target, base_sha, new_sha } }
  }
  const note = sign(targets.NOTE_TARGET, '{"accent": "#FFD700"}'), otherColour = sign(targets.THEME_TARGET, '{"accent": "#7F00FF"}')
  for (const [name, before, evidence, expected] of [
    ['receipt-theme-target', 'evidence.receipt?.target === api.targets.THEME_TARGET', note.evidence, note.expected],
    ['receipt-theme-bytes', "evidence.receipt.new_sha === createHash('sha256').update(themeContent).digest('hex')", otherColour.evidence, otherColour.expected],
    ['receipt-expected-proposal', 'evidence.receipt.proposal === expected?.proposal', f.evidence, { ...f.expected, proposal: 'other proposal' }],
    ['receipt-expected-base', 'evidence.receipt.base_sha === expected.base_sha', f.evidence, { ...f.expected, base_sha: 'a'.repeat(64) }],
    ['receipt-expected-new', 'evidence.receipt.new_sha === expected.new_sha', f.evidence, { ...f.expected, new_sha: 'b'.repeat(64) }],
    ['receipt-expected-target', 'evidence.receipt.target === expected.target', f.evidence, { ...f.expected, target: targets.NOTE_TARGET }],
  ]) {
    assert.equal(checked(commands, f, evidence, f.gate.db, expected).error?.code, 'example-verification-failed')
    const changed = await mutant(before, 'true')
    assert.equal(checked(changed, f, evidence, f.gate.db, expected).error, undefined)
    t.diagnostic('KILLED ' + name)
  }
})

test('CLI argument failures print refusal codes without supplied token or link; printing the parser error loses secrecy', t => {
  const secret = 'SYNTHETIC_PRIVATE_TOKEN', link = 'http://127.0.0.1:1234/?token=' + secret
  const root = temporary(t)
  function privateFailure(file) {
    const result = spawnSync(process.execPath, [file, '--unknown-' + secret, link],
      { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 10000 })
    assert.equal(result.status, 1)
    assert.equal((result.stdout + result.stderr).includes(secret), false)
    assert.equal((result.stdout + result.stderr).includes(link), false)
  }
  for (const file of ['scripts/example-commands.mjs', 'scripts/fresh-clone-runtime.mjs']) {
    privateFailure(path.join(repository, file))
    const original = fs.readFileSync(path.join(repository, file), 'utf8'), before = /error\.code \?\? '[a-z-]+'/u
    assert.equal(original.match(new RegExp(before.source, 'gu')).length, 1)
    const changed = original.replace(before, 'error.message').replace("'./fresh-clone-runtime.mjs'",
      JSON.stringify(pathToFileURL(path.join(repository, 'scripts/fresh-clone-runtime.mjs')).href))
    const mutantFile = path.join(root, path.basename(file))
    fs.writeFileSync(mutantFile, changed, { mode: 0o600 })
    assert.throws(() => privateFailure(mutantFile), assert.AssertionError)
    t.diagnostic('KILLED no-token-output ' + path.basename(file))
  }
})
