/** One focused disposable check of ops capability; no Prime security gate claim. */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readlinkSync, symlinkSync, chmodSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { fullTreeDigest, runGate, evaluatorDigest, observeLocalUi } from './gates.mjs'
import { runOwned } from './owned-process.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const temp = mkdtempSync(join(tmpdir(), 'prime-ops-regression-'))
const sha = b => createHash('sha256').update(b).digest('hex')
const python = process.env.PRIME_OPS_PYTHON ?? 'python3'
function archive(...argv) {
  const result = spawnSync(python, [join(here, 'archive.py'), ...argv], { encoding: 'utf8' })
  assert.equal(result.error, undefined)
  return { code: result.status, ...JSON.parse(result.stdout) }
}
try {
  const source = join(temp, 'export'), restored = join(temp, 'restored')
  mkdirSync(source); mkdirSync(restored)
  writeFileSync(join(source, 'synthetic.json'), '{"record_id":"synthetic-only","grants_authority":false}\n')
  const recipe = join(temp, 'recipe.json')
  writeFileSync(recipe, JSON.stringify({ fixture: 'synthetic-ops-only', node: process.version, python: 'stdlib' }))
  const common = ['--root', source, '--kind', 'memory-export', '--version', 'ops-regression', '--commit', '0'.repeat(40), '--recipe', recipe]
  const a = archive('package', ...common, '--out', join(temp, 'a.tar'))
  const b = archive('package', ...common, '--out', join(temp, 'b.tar'))
  assert.equal(a.code, 0); assert.equal(a.archive_sha256, b.archive_sha256)
  assert.equal(archive('verify', '--archive', a.artifact, '--expected-digest', a.artifact_digest).status, 'VERIFIED')
  assert.equal(archive('verify', '--archive', a.artifact, '--expected-digest', 'f'.repeat(64)).reason, 'ARTIFACT_DIGEST_MISMATCH')
  const staged = archive('restore', '--archive', a.artifact, '--expected-digest', a.artifact_digest, '--into', restored)
  assert.equal(staged.status, 'STAGED'); assert.equal(staged.authority_restored, false)
  assert.equal(readFileSync(join(restored, 'synthetic.json'), 'utf8'), readFileSync(join(source, 'synthetic.json'), 'utf8'))
  assert.equal(archive('restore', '--archive', a.artifact, '--expected-digest', a.artifact_digest, '--into', restored).reason, 'RESTORE_TARGET_MUST_BE_EXISTING_EMPTY_DIRECTORY')
  writeFileSync(join(source, '.env'), 'SYNTHETIC_ONLY=true')
  assert.equal(archive('package', ...common, '--out', join(temp, 'denied.tar')).reason, 'SENSITIVE_OR_AUTHORITY_PATH')
  rmSync(join(source, '.env'))
  const release = join(temp, 'release'), releaseStage = join(temp, 'release-stage')
  mkdirSync(release); mkdirSync(releaseStage); mkdirSync(join(release, 'node_modules')); mkdirSync(join(release, 'node_modules/.pnpm'))
  writeFileSync(join(release, 'node_modules/.pnpm/owned.js'), 'export const value = 1\n')
  symlinkSync('.pnpm/owned.js', join(release, 'node_modules/owned.js'))
  const linked = archive('package', '--root', release, '--kind', 'release', '--version', 'fixture', '--commit', '0'.repeat(40), '--recipe', recipe, '--out', join(temp, 'links.tar'))
  assert.equal(linked.code, 0)
  assert.equal(archive('stage-release', '--archive', linked.artifact, '--expected-digest', linked.artifact_digest, '--into', releaseStage).status, 'STAGED')
  assert.equal(readlinkSync(join(releaseStage, 'node_modules/owned.js')), '.pnpm/owned.js')
  assert.equal(fullTreeDigest(release).digest, fullTreeDigest(releaseStage).digest)
  symlinkSync('../../recipe.json', join(release, 'node_modules/escape'))
  assert.throws(() => fullTreeDigest(release), /RELEASE_LINK_ESCAPES_ROOT/)
  assert.equal(archive('package', '--root', release, '--kind', 'release', '--version', 'fixture', '--commit', '0'.repeat(40), '--recipe', recipe, '--out', join(temp, 'escape.tar')).reason, 'RELEASE_LINK_ESCAPES_ROOT')
  const damaged = join(temp, 'damaged.tar')
  const bytes = readFileSync(a.artifact)
  const index = bytes.indexOf(Buffer.from('synthetic-only'))
  assert.ok(index > 0); bytes[index] = 'X'.charCodeAt(0); writeFileSync(damaged, bytes)
  assert.equal(archive('verify', '--archive', damaged, '--expected-digest', a.artifact_digest).reason, 'FILE_DIGEST_MISMATCH')
  // Installation markers cannot substitute for covering changed bytes.
  const before = fullTreeDigest(source).digest
  writeFileSync(join(source, 'synthetic.json'), 'changed')
  assert.notEqual(fullTreeDigest(source).digest, before)
  mkdirSync(join(source, '.dsh-build')); writeFileSync(join(source, '.dsh-build/plugin-set.json'), '{}')
  const markerBefore = fullTreeDigest(source).digest
  writeFileSync(join(source, '.dsh-build/plugin-set.json'), '{"changed":true}')
  assert.notEqual(fullTreeDigest(source).digest, markerBefore)
  const leak = await runOwned(process.execPath, ['-e', 'console.log("authorization=synthetic-ops-test")'], { cwd: temp, timeoutMs: 2000 })
  assert.equal(leak.token_leak, true); assert.ok(!leak.stdout.includes('synthetic-ops-test'))
  const jsonLeak = await runOwned(process.execPath, ['-e', 'console.log(JSON.stringify({api_key:"synthetic-json-token"}))'], { cwd: temp, timeoutMs: 2000 })
  assert.equal(jsonLeak.token_leak, true); assert.ok(!jsonLeak.stdout.includes('synthetic-json-token'))
  const controller = new AbortController()
  const owned = runOwned(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { cwd: temp, signal: controller.signal, timeoutMs: 2000 })
  setTimeout(() => controller.abort(), 50)
  const cancelled = await owned
  assert.equal(cancelled.cancelled, true); assert.equal(cancelled.descendant_cleanup, 'NOT_VERIFIED')
  // A dummy candidate cannot force acceptance by emitting PASS or a weak marker.
  const candidate = join(temp, 'candidate'), evidence = join(temp, 'evidence')
  mkdirSync(candidate); const executable = join(candidate, 'probe')
  writeFileSync(executable, '#!/bin/sh\nprintf \'{"passed":true,"marker":"ok"}\\n\'\n'); chmodSync(executable, 0o755)
  const candidateDigest = fullTreeDigest(candidate).digest
  const probePlan = join(temp, 'probes.json')
  const planBytes = JSON.stringify({ schema: 'prime-probes-v1', gate: 'G4', candidate_digest: candidateDigest,
    probes: [{ case: 'unauthorized-signing', qualification: 'actual-prime-adapter', executable: 'probe', args: [], exit_code: 0,
      assertions: [{ path: 'marker', equals: 'ok' }] }] })
  writeFileSync(probePlan, planBytes)
  const result = await runGate('G4', { root: candidate, evidenceDir: evidence, probePlan, expectedProbeDigest: sha(planBytes),
    releaseDir: candidate, expectedCandidateDigest: candidateDigest, expectedEvaluatorDigest: evaluatorDigest(), disposableHome: temp })
  assert.equal(result.status, 'FAIL')
  const ev = JSON.parse(readFileSync(result.evidence_path, 'utf8'))
  assert.ok(ev.cases[0].findings.includes('CANDIDATE_VERDICT_NOT_EVIDENCE'))
  assert.equal(ev.cases[1].status, 'PENDING')
  // Disposable local DSH-shaped exchange: verifies evaluator cookie handling, not DSH/owner authority.
  const state = join(candidate, '.prime-state'); mkdirSync(state, { mode: 0o700 })
  const access = join(state, 'launch-url.json')
  let requests = 0, cookie, redirect = '/'
  const server = createServer((req, res) => {
    requests++
    if (req.url === '/?token=synthetic-launch-token') {
      res.writeHead(303, { location: redirect, 'set-cookie': `${cookie}; Max-Age=60; Path=/; HttpOnly; SameSite=Strict` }); res.end(); return
    }
    if (req.url === '/' && req.headers.cookie === cookie) {
      res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><title>Disposable ops fixture</title>'); return
    }
    res.writeHead(401); res.end()
  })
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
    const base = `http://127.0.0.1:${server.address().port}/`
    cookie = `dsh-auth-${createHash('sha256').update(new URL(base).host).digest('base64url')}=v1.syntheticbody.syntheticsignature`
    const uiStatus = { pid: process.pid, ui_url: base, ui_access_file: access }
    const save = (value) => writeFileSync(access, JSON.stringify(value), { mode: 0o600 })
    save({ url: base + '?token=synthetic-launch-token', pid: process.pid })
    assert.equal((await observeLocalUi(candidate, uiStatus)).http.status, 401)
    const observed = await observeLocalUi(candidate, uiStatus, { uiLaunchAccess: true })
    assert.equal(observed.status, 'OBSERVED'); assert.equal(observed.http.status, 200)
    assert.equal(observed.auth.owner_passkey, 'NOT_VERIFIED')
    assert.ok(!JSON.stringify(observed).includes('synthetic-launch-token')); assert.ok(!JSON.stringify(observed).includes(cookie))
    assert.equal((await observeLocalUi(candidate, uiStatus)).http.status, 401)
    const beforeWrongPid = requests
    save({ url: base + '?token=synthetic-launch-token', pid: process.pid + 1 })
    assert.equal((await observeLocalUi(candidate, uiStatus, { uiLaunchAccess: true })).blocker, 'UI_ACCESS_PID_OR_FORMAT_MISMATCH')
    assert.equal(requests, beforeWrongPid)
    save({ url: 'http://127.0.0.1:1/?token=synthetic-launch-token', pid: process.pid })
    assert.equal((await observeLocalUi(candidate, uiStatus, { uiLaunchAccess: true })).blocker, 'UI_LAUNCH_ORIGIN_OR_FORMAT_MISMATCH')
    assert.equal(requests, beforeWrongPid)
    save({ url: base + '?token=synthetic-launch-token', pid: process.pid }); chmodSync(access, 0o644)
    assert.equal((await observeLocalUi(candidate, uiStatus, { uiLaunchAccess: true })).blocker, 'UI_ACCESS_FILE_NOT_PRIVATE')
    assert.equal(requests, beforeWrongPid); chmodSync(access, 0o600)
    redirect = 'http://127.0.0.1:1/'
    assert.equal((await observeLocalUi(candidate, uiStatus, { uiLaunchAccess: true })).blocker, 'UI_LAUNCH_HANDSHAKE_MISMATCH')
    assert.equal(requests, beforeWrongPid + 1)
    const g1 = await runGate('G1', { root: candidate, evidenceDir: evidence, uiLaunchAccess: true, disposableHome: temp })
    assert.equal(g1.status, 'PENDING')
    assert.ok(!readFileSync(g1.evidence_path, 'utf8').includes('synthetic-launch-token'))
  } finally {
    server.closeAllConnections()
    await new Promise(resolve => server.close(resolve))
  }
  console.log(JSON.stringify({ status: 'PASS', scope: 'ops packaging/digest/data-staging/redaction/owned-cancel/evaluator refusal only',
    launch_handshake: 'DISPOSABLE_LOCAL_FIXTURE_PASS', prime_gates: 'NOT_PERFORMED', other_repos: 'NOT_ACCESSED',
    network: 'DISPOSABLE_LOOPBACK_ONLY', live_app_changed: false }))
} finally {
  // Delete only the disposable directory created by this invocation.
  rmSync(temp, { recursive: true, force: true })
}
