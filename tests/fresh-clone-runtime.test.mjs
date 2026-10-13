// Temporary development authority refuses insecure paths and unsuccessful runtime observations.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHash, createPublicKey } from 'node:crypto'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import * as runtime from '../scripts/fresh-clone-runtime.mjs'
import { recordPluginSet } from '../plugins/aukora-composition-gate/src/plugin-set.mjs'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { loadOwnerSecret } from '../packages/boundary-gate/src/secrets.mjs'
import { pluginSetTarget, PLUGIN_SET_TARGET, pluginSetApprovalText, installedRelease } from '../packages/boundary-gate/src/targets.mjs'
import { gateStore } from '../packages/boundary-gate/src/wiring.mjs'
import { OWNER_SOCKET_APPROVER } from '../packages/boundary-gate/src/server.mjs'
import * as canon from '../packages/boundary-gate/src/plugin-set-canon.mjs'
import { advanceFloor } from '../packages/boundary-gate/src/release-floor.mjs'

const source = fs.readFileSync(new URL('../scripts/fresh-clone-runtime.mjs', import.meta.url), 'utf8')
const repository = fileURLToPath(new URL('../', import.meta.url))
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
function temporary(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync('/tmp'), 'aukora-fresh-clone-'))
  fs.chmodSync(root, 0o700)
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return root
}
const rejected = (call, code) => assert.throws(call, error => error.code === code)
function pathCases(t, module) {
  const root = temporary(t), file = path.join(root, 'data.json')
  fs.writeFileSync(file, '{}', { mode: 0o600 })
  assert.equal(module.developmentPath(root, file), file)
  rejected(() => module.developmentPath(root, root + '-outside'), 'development-path-outside-root')
  fs.chmodSync(root, 0o770)
  rejected(() => module.developmentPath(root, file), 'development-root-not-private')
  fs.chmodSync(root, 0o700)
  fs.chmodSync(file, 0o660)
  rejected(() => module.developmentPath(root, file), 'development-path-unprotected')
  fs.chmodSync(file, 0o600)
  const originalStat = fs.lstatSync
  fs.lstatSync = (p, ...args) => {
    const value = originalStat(p, ...args)
    if (p === file) Object.defineProperty(value, 'uid', { value: process.getuid() + 1 })
    return value
  }
  try { rejected(() => module.developmentPath(root, file), 'development-path-unprotected') } finally { fs.lstatSync = originalStat }
  fs.chmodSync(file, 0o644)
  rejected(() => module.developmentPath(root, file, { privateRoot: true }), 'development-path-not-private')
  fs.chmodSync(file, 0o600)
  const link = path.join(root, 'link'); fs.symlinkSync(file, link)
  rejected(() => module.developmentPath(root, link), 'development-path-unprotected')
  fs.unlinkSync(link)
  const directory = path.join(root, 'directory'); fs.mkdirSync(directory, { mode: 0o700 })
  fs.symlinkSync(directory, link); fs.writeFileSync(path.join(directory, 'nested'), '{}', { mode: 0o600 })
  rejected(() => module.developmentPath(root, path.join(link, 'nested')), 'development-path-unprotected')
  fs.unlinkSync(link); fs.linkSync(file, link)
  rejected(() => module.developmentPath(root, file), 'development-path-unprotected')
}
test('private current-user development paths refuse aliases, writable paths and linked files', t => pathCases(t, runtime))

function observationCases(module) {
  module.assertNoPluginErrors('aukora-face-apps loaded')
  rejected(() => module.assertNoPluginErrors('aukora-face-apps (file:///synthetic/lib/index.js): Error: missing'), 'face-plugin-load-error')
  module.assertFaceEntries(['@aukora/face-layout'], { entries: [{ id: '@aukora/face-layout' }] })
  rejected(() => module.assertFaceEntries(['@aukora/face-layout'], { entries: [] }), 'face-plugin-not-loaded')
  rejected(() => module.assertFaceEntries([], { entries: [] }), 'face-plugin-not-loaded')
  const denied = { bodyRan: false, result: { isError: true, failure: { message: 'authority:tool-not-approved' } } }
  module.assertActionRefusal(denied)
  for (const result of [{ ...denied, bodyRan: true }, { ...denied, result: { ...denied.result, isError: false } },
    { bodyRan: false, result: { isError: true, failure: { message: 'UNKNOWN_TOOL' } } }])
    rejected(() => module.assertActionRefusal(result), 'action-gate-did-not-refuse')
  module.assertHttpStatus({ status: 401 }, 401, 'unauthenticated-request-not-refused')
  rejected(() => module.assertHttpStatus({ status: 200 }, 401, 'unauthenticated-request-not-refused'), 'unauthenticated-request-not-refused')
  module.assertUiBody('<html>'); rejected(() => module.assertUiBody(''), 'release-ui-not-served')
  module.assertProbeExit({ status: 0, stdout: 'UI PROBE: all served' })
  rejected(() => module.assertProbeExit({ status: 1, stdout: 'UI PROBE: all served' }), 'release-ui-probe-failed')
  rejected(() => module.assertProbeExit({ status: 0, stdout: 'UI PROBE: 2 not served' }), 'release-ui-probe-failed')
}
test('runtime observations cannot pass missing faces, load errors, allowed action, empty UI or a failed stock-app probe', () => observationCases(runtime))

test('runtime path and observation guard-removal mutations are killed by the focused assertions', async t => {
  const mutations = [
    ['root-private', '(rootInfo.mode & 0o077)', 'false', module => pathCases(t, module)],
    ['outside-root', '!under(file, root)', 'false', module => pathCases(t, module)],
    ['writable-path', '(info.mode & 0o022)', 'false', module => pathCases(t, module)],
    ['current-user-path', 'info.uid !== process.getuid()', 'false', module => pathCases(t, module)],
    ['private-admission-file', 'privateRoot && fs.lstatSync(file).mode & 0o077', 'false', module => pathCases(t, module)],
    ['symlink-no-follow', 'const info = fs.lstatSync(current)', 'const info = fs.statSync(current)', module => pathCases(t, module)],
    ['hardlink', 'info.nlink !== 1', 'false', module => pathCases(t, module)],
    ['plugin-error', 'if (/^aukora-', 'if (false && /^aukora-', observationCases],
    ['face-loaded', 'expected.some(id => !present.has(id))', 'false', observationCases],
    ['action-body', 'result?.bodyRan !== false', 'false', observationCases],
    ['action-error', 'result?.result?.isError !== true', 'false', observationCases],
    ['action-reason', "!JSON.stringify(result.result).includes('authority:tool-not-approved')", 'false', observationCases],
    ['http-status', 'response.status !== expected', 'false', observationCases],
    ['ui-body', 'body.length === 0', 'false', observationCases],
    ['probe-exit', 'result.status !== 0', 'false', observationCases],
    ['probe-result', "!result.stdout?.includes('UI PROBE: all served')", 'false', observationCases],
  ]
  for (const [name, before, after, exercise] of mutations) {
    assert.equal(source.split(before).length, 2, 'mutation preimage: ' + name)
    const module = await import('data:text/javascript;base64,' + Buffer.from(source.replace(before, after)).toString('base64'))
    assert.throws(() => exercise(module), assert.AssertionError, name + ' survived')
    t.diagnostic('KILLED ' + name)
  }
})

test('owned backend process group receives termination and is reaped; suppressing termination loses graceful cleanup', async t => {
  const root = temporary(t), marker = path.join(root, 'stopped')
  async function childProcess(module, output) {
    const child = spawn(process.execPath, ['-e', "const fs = require('node:fs'); process.on('SIGTERM', () => { fs.writeFileSync(process.argv[1], 'stopped'); process.exit(0) }); fs.writeFileSync(process.argv[1] + '.ready', 'ready'); setInterval(() => {}, 1000)", output],
      { detached: true, stdio: 'ignore' })
    t.after(() => { try { process.kill(-child.pid, 'SIGKILL') } catch {} })
    for (let i = 0; i < 100 && !fs.existsSync(output + '.ready'); i++) await new Promise(resolve => setTimeout(resolve, 10))
    assert.equal(fs.existsSync(output + '.ready'), true)
    await module.terminate(child.pid)
    await new Promise(resolve => setTimeout(resolve, 25))
    return fs.existsSync(output)
  }
  assert.equal(await childProcess(runtime, marker), true)
  const before = "process.kill(-pid, 'SIGTERM')"
  assert.equal(source.split(before).length, 2)
  const changed = await import('data:text/javascript;base64,' + Buffer.from(source.replace(before, 'void pid')).toString('base64'))
  assert.equal(await childProcess(changed, marker + '-mutant'), false)
  t.diagnostic('KILLED backend-termination (graceful cleanup disappeared)')
})

test('temporary probe authenticates before tool dispatch and exposes only fixed denial control', async () => {
  const module = await import('data:text/javascript;base64,' + Buffer.from(runtime.probeSource).toString('base64'))
  let handler, executions = 0
  module.apply({ tools: { register() {}, async execute() { executions++; return { isError: true, message: 'authority:tool-not-approved' } } },
    effect(effect) { effect() }, webServer: { register(route) { handler = route.handler } },
    connection: { requestRejection() { return 401 } }, clientModules: { graph() { return { entries: [] } } } })
  const response = { status: null, writeHead(status) { this.status = status }, end() {} }
  await handler({ method: 'GET' }, response)
  assert.equal(response.status, 401); assert.equal(executions, 0)
  const mutant = runtime.probeSource.replace('if (rejection !== undefined)', 'if (false)')
  const changed = await import('data:text/javascript;base64,' + Buffer.from(mutant).toString('base64'))
  changed.apply({ tools: { register() {}, async execute() { executions++; return {} } }, effect(effect) { effect() },
    webServer: { register(route) { handler = route.handler } }, connection: { requestRejection() { return 401 } }, clientModules: { graph() { return {} } } })
  await handler({ method: 'GET' }, response)
  assert.notEqual(executions, 0, 'guard removal must reach the body')
})

test('temporary probe refuses absent authentication service and methods other than GET; both guard removals are detected', async t => {
  async function run(text, connection, method) {
    const module = await import('data:text/javascript;base64,' + Buffer.from(text).toString('base64'))
    let handler, executions = 0
    module.apply({ tools: { register() {}, async execute() { executions++; return {} } }, effect(effect) { effect() },
      webServer: { register(route) { handler = route.handler } }, connection, clientModules: { graph() { return {} } } })
    const response = { status: null, writeHead(status) { this.status = status }, end() {} }
    await handler({ method }, response)
    return { status: response.status, executions }
  }
  assert.deepEqual(await run(runtime.probeSource, undefined, 'GET'), { status: 403, executions: 0 })
  assert.deepEqual(await run(runtime.probeSource, { requestRejection() {} }, 'POST'), { status: 405, executions: 0 })
  for (const [name, before, after, connection, method] of [
    ['missing-auth-service', 'ctx.connection.requestRejection(req) : 403', 'ctx.connection.requestRejection(req) : undefined', undefined, 'GET'],
    ['probe-method', "req.method !== 'GET'", 'false', { requestRejection() {} }, 'POST'],
  ]) {
    assert.equal(runtime.probeSource.split(before).length, 2)
    const result = await run(runtime.probeSource.replace(before, after), connection, method)
    assert.equal(result.executions, 1, name + ' required refusal must disappear')
    t.diagnostic('KILLED ' + name)
  }
})

function admissionFixture(t) {
  const root = temporary(t), checkout = path.join(root, 'checkout'), release = path.join(root, 'release-1111111')
  const gateState = path.join(root, 'support/state/gate-state'), home = path.join(root, 'gate-home')
  for (const directory of [checkout, release, gateState, home, path.join(release, 'plugins/demo/lib'), path.join(release, '.dsh-build')])
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
  for (const directory of ['packages/boundary-gate/src', 'packages/owner-key/src'])
    fs.cpSync(path.join(repository, directory), path.join(checkout, directory), { recursive: true })
  fs.writeFileSync(path.join(release, 'plugins/demo/lib/index.mjs'), 'export const value = 1\n', { mode: 0o600 })
  const record = recordPluginSet({ root: release, rows: [{ id: 'demo', entry: 'plugins/demo/lib/index.mjs' }] })
  const write = (file, value) => fs.writeFileSync(file, JSON.stringify(value), { mode: 0o600 })
  write(path.join(release, '.dsh-build/plugin-set.json'), record)
  write(path.join(release, '.dsh-build/aukora-release.json'), { tipSha: '1'.repeat(40) })
  write(path.join(release, '.dsh-build/genesis-artifacts.json'), { entries: [] })
  const installed = installedRelease(root, path.basename(release)), floorFile = path.join(gateState, 'release-floor.json')
  const content = pluginSetApprovalText({ ...installed, operation: canon.operationDigestOf(canon.setOperationContent(record)) })
  const gate = createGate({ home, owner: loadOwnerSecret(home),
    targets: { [PLUGIN_SET_TARGET]: pluginSetTarget(path.join(root, 'targets'), { releasesRoot: root, floorFile }) }, store: gateStore() })
  t.after(() => gate.close())
  gate.startup({ pid: 1 })
  const pending = gate.ownerOps.raise({ target: PLUGIN_SET_TARGET, content, why: 'Synthetic clone fixture' })
  const review = gate.ownerOps.review({ id: pending.id })
  const applied = gate.ownerOps.decide_review({ id: pending.id, base_sha: review.base_sha, new_sha: review.new_sha,
    review_challenge: review.review_challenge, outcome: 'allowed-once' }, OWNER_SOCKET_APPROVER)
  assert.equal(applied.applied, true)
  const entry = gate.ownerOps.log({ target: PLUGIN_SET_TARGET, limit: 200 }).entries.find(row => row.event === 'apply')
  const approval = { kind: 'aukora-plugin-set-gate-approval/v1', content, receipt: applied.receipt,
    receipt_sig: applied.receipt_sig, ledger_entry: entry.signed_entry }
  const pin = { kind: 'aukora-boundary-gate-owner/v1', gatePubkeyPem: gate.pubPem, gatePubkeyFp: gate.fp,
    target: PLUGIN_SET_TARGET, approver: OWNER_SOCKET_APPROVER }
  const keyHash = sha(createPublicKey(gate.pubPem).export({ type: 'spki', format: 'der' }))
  const epochs = { version: 1, kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1, gate_pubkey_sha256: keyHash }] }
  const verified = canon.verifyOrderedGateApproval({ record, approval, pin, epochs })
  write(floorFile, advanceFloor(null, verified))
  write(path.join(gateState, 'boundary-approval.json'), approval)
  write(path.join(gateState, 'boundary-approver.json'), pin)
  write(path.join(gateState, 'signer-epochs.json'), epochs)
  return { input: { root, checkout, release }, gateState, floorFile, approval, write }
}

test('signed admission refuses changed signatures, another release and an uncommitted newer floor', async t => {
  const fixture = admissionFixture(t)
  await runtime.checkAdmission(fixture.input)
  const file = path.join(fixture.gateState, 'boundary-approval.json')
  fixture.write(file, { ...fixture.approval, receipt_sig: Buffer.alloc(64).toString('base64') })
  await assert.rejects(runtime.checkAdmission(fixture.input), error => error.code === 'plugin-set-approval-signature-invalid')
  fixture.write(file, fixture.approval)
  const manifest = path.join(fixture.input.release, '.dsh-build/aukora-release.json')
  fixture.write(manifest, { tipSha: '2'.repeat(40) })
  await assert.rejects(runtime.checkAdmission(fixture.input), error => error.code === 'development-approval-for-other-release')
  fixture.write(manifest, { tipSha: '1'.repeat(40) })
  fixture.write(fixture.floorFile, { ...JSON.parse(fs.readFileSync(fixture.floorFile, 'utf8')), ledger_seq: 999 })
  await assert.rejects(runtime.checkAdmission(fixture.input), error => error.code === 'release-below-floor')
})

test('removing ordered signature, exact release or exact floor checks loses the admission refusal', async t => {
  for (const [name, before, after, breakFixture, code] of [
    ['ordered-approval', 'canon.verifyOrderedGateApproval({ record, approval, pin, epochs: readJson(path.join(gateState, \'signer-epochs.json\')) })',
      `({ ...targets.installedRelease(path.dirname(release), path.basename(release)), signerEpoch: 1, signerKeySha256: readJson(path.join(gateState, 'signer-epochs.json')).epochs[0].gate_pubkey_sha256, ledgerSeq: approval.ledger_entry.seq, ledgerHash: approval.ledger_entry.hash })`,
      f => f.write(path.join(f.gateState, 'boundary-approval.json'), { ...f.approval, receipt_sig: Buffer.alloc(64).toString('base64') }), 'plugin-set-approval-signature-invalid'],
    ['exact-floor', "floor.checkFloor(floor.readFloor(path.join(gateState, 'release-floor.json')), verified)", 'void verified',
      f => f.write(f.floorFile, { ...JSON.parse(fs.readFileSync(f.floorFile, 'utf8')), ledger_seq: 999 }), 'release-below-floor'],
    ['exact-release', 'verified.release !== installed.release || verified.record !== installed.record', 'false',
      f => f.write(path.join(f.input.release, '.dsh-build/aukora-release.json'), { tipSha: '2'.repeat(40) }), 'development-approval-for-other-release'],
  ]) {
    const fixture = admissionFixture(t)
    breakFixture(fixture)
    await assert.rejects(runtime.checkAdmission(fixture.input), error => error.code === code)
    assert.equal(source.split(before).length, 2, 'mutation preimage ' + name)
    const module = await import('data:text/javascript;base64,' + Buffer.from(source.replace(before, after)).toString('base64'))
    await module.checkAdmission(fixture.input)
    t.diagnostic('KILLED ' + name + ' (required refusal vanished)')
  }
})
