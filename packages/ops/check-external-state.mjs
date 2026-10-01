// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable evaluator protocol fixtures; never targets an actual Prime/DSH process.
import assert from 'node:assert/strict'
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync, realpathSync, chmodSync, symlinkSync, rmSync} from 'node:fs'
import {join, relative} from 'node:path'
import {tmpdir} from 'node:os'
import {createHash} from 'node:crypto'
import {createServer} from 'node:http'
import {CASES, evaluatorDigest, fullTreeDigest, runGate} from './gates.mjs'

const temporary = realpathSync(mkdtempSync(join(tmpdir(), 'prime-external-state-check-')))
const candidate = join(temporary, 'candidate'), release = join(temporary, 'release')
const state = join(temporary, 'external-state'), evidenceDir = join(temporary, 'evidence')
const home = join(temporary, 'disposable-home'), access = join(state, 'launch-url.json')
const checks = []
const sha = value => createHash('sha256').update(value).digest('hex')
let server, requests = 0, cookie, record, base
const token = 'synthetic-external-state-launch'
const check = async (name, action) => {await action(); checks.push(name)}
const saveRecord = () => writeFileSync(join(state, 'running.json'), JSON.stringify(record), {mode: 0o600})
const saveLaunch = (value = {url: base + '?token=' + token, pid: process.pid}) =>
  writeFileSync(access, JSON.stringify(value), {mode: 0o600})
const cleanEvidence = evidence => {
  const bytes = readFileSync(evidence.evidence_path, 'utf8')
  assert.ok(!bytes.includes(token), 'launch token must not be retained in evidence')
  assert.ok(!bytes.includes(cookie), 'cookie must not be retained in evidence')
  assert.ok(!JSON.stringify(evidence).includes(token), 'launch token must not be returned')
  assert.ok(!JSON.stringify(evidence).includes(cookie), 'cookie must not be returned')
  return JSON.parse(bytes)
}

try {
  for (const directory of [candidate, release, state, home]) mkdirSync(directory, {mode: 0o700})
  mkdirSync(join(candidate, 'harness'), {mode: 0o755})
  mkdirSync(join(candidate, '.prime-state'), {mode: 0o700})
  writeFileSync(join(candidate, '.prime-state/running.json'), JSON.stringify({status: 'stopped', pid: null,
    version: 'default-fixture-stopped', ui_url: null, release_dir: null, release_digest: null,
    unavailable_capabilities: []}), {mode: 0o600})
  writeFileSync(join(release, 'owned-fixture.mjs'), '// Bytes-only closure fixture; never imported.\n', {mode: 0o644})
  const releaseDigest = fullTreeDigest(release).digest
  const fixtureCli = `import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const args=process.argv.slice(2),root=fileURLToPath(new URL('..',import.meta.url));
const named=${JSON.stringify(state)},release=${JSON.stringify(release)};
const expected=[['status','--json'],['status','--state-dir',named,'--json'],
 ['status','--state-dir',named,'--release-dir',release,'--json']];
if(!expected.some(value=>JSON.stringify(value)===JSON.stringify(args)))process.exit(73);
const chosen=args.includes('--state-dir')?args[args.indexOf('--state-dir')+1]:join(root,'.prime-state');
console.log(readFileSync(join(chosen,'running.json'),'utf8'));
`
  writeFileSync(join(candidate, 'harness/cli.mjs'), fixtureCli, {mode: 0o644})
  server = createServer((request, response) => {
    requests++
    if (request.url === '/?token=' + token) {
      response.writeHead(303, {location: '/', 'set-cookie': cookie + '; Path=/; HttpOnly; SameSite=Strict'})
      response.end(); return
    }
    if (request.url === '/' && request.headers.cookie === cookie) {
      response.writeHead(200, {'content-type': 'text/html'})
      response.end('<!doctype html><title>Disposable external-state fixture</title>'); return
    }
    response.writeHead(401); response.end()
  })
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve)})
  base = `http://127.0.0.1:${server.address().port}/`
  cookie = `dsh-auth-${createHash('sha256').update(new URL(base).host).digest('base64url')}=v1.fixturebody.fixturesignature`
  record = {status: 'running', pid: process.pid, version: 'external-state-fixture', ui_url: base,
    release_dir: release, release_digest: releaseDigest, release_digest_algorithm: 'aukora-prime:full-release:v1',
    unavailable_capabilities: ['fixture-executor-unavailable'], ui_access_file: access}
  saveRecord(); saveLaunch()
  const common = {root: candidate, evidenceDir, disposableHome: home,
    expectedEvaluatorDigest: evaluatorDigest(), stateDir: state, releaseDir: release, uiLaunchAccess: true}
  const run = async (options = {}) => {
    const result = await runGate('G1', {...common, ...options})
    return {result, evidence: cleanEvidence(result)}
  }
  const expectedArgs = [process.execPath, join(candidate, 'harness/cli.mjs'), 'status',
    '--state-dir', state, '--release-dir', release, '--json']
  const failBeforeHttp = async (options, expectedBlocker) => {
    const count = requests
    const {result, evidence} = await run(options)
    assert.equal(result.status, 'FAIL')
    if (expectedBlocker) assert.equal(evidence.running_observation?.blocker ?? evidence.blocker, expectedBlocker)
    assert.equal(requests, count, 'invalid named state/access must fail before HTTP')
  }

  await check('external-state-status-digest-auth-and-pending', async () => {
    const {result, evidence} = await run()
    assert.equal(result.status, 'PENDING'); assert.equal(result.blocker, 'FROZEN_EXTERNAL_PROBE_PLAN_REQUIRED')
    assert.equal(result.running_status, 'running')
    assert.deepEqual(evidence.status_command, expectedArgs)
    assert.equal(evidence.running_observation.observation.version, 'external-state-fixture')
    assert.equal(evidence.running_observation.observation.pid, process.pid)
    assert.equal(evidence.running_observation.running.digest, releaseDigest)
    assert.equal(evidence.running_observation.http.status, 200)
    assert.equal(evidence.running_observation.auth.method, 'DSH_DISPOSABLE_LAUNCH')
    assert.equal(evidence.running_observation.auth.owner_passkey, 'NOT_VERIFIED')
    assert.equal(evidence.running_observation.auth.credential_persisted, false)
    assert.equal(evidence.running_observation.same_uid_boundary, 'NOT_ENFORCED')
    assert.equal(requests, 2)
  })
  await check('explicit-access-name-and-state-without-release', async () => {
    const {result, evidence} = await run({releaseDir: undefined, uiAccessFile: access})
    assert.equal(result.status, 'PENDING')
    assert.deepEqual(evidence.status_command, [process.execPath, join(candidate, 'harness/cli.mjs'),
      'status', '--state-dir', state, '--json'])
    assert.equal(evidence.running_observation.http.status, 200)
  })
  await check('default-status-remains-stopped-with-old-argv', async () => {
    const count = requests
    const {result, evidence} = await run({stateDir: undefined, releaseDir: undefined})
    assert.equal(result.running_status, 'stopped'); assert.equal(result.status, 'PENDING')
    assert.equal(result.running_blocker, 'PRIME_NOT_RUNNING')
    assert.deepEqual(evidence.status_command, [process.execPath, join(candidate, 'harness/cli.mjs'), 'status', '--json'])
    assert.equal(requests, count)
  })
  await check('three-g1-probe-names-remain-pending', async () => {
    assert.deepEqual(CASES.G1, ['harness-ui-boot', 'unavailable-executor', 'prime-only-build'])
    const probePlan = join(temporary, 'empty-probe-plan.json')
    const bytes = JSON.stringify({schema: 'prime-probes-v1', gate: 'G1', candidate_digest: releaseDigest, probes: []})
    writeFileSync(probePlan, bytes, {mode: 0o600})
    const {result, evidence} = await run({probePlan, expectedProbeDigest: sha(bytes), expectedCandidateDigest: releaseDigest})
    assert.equal(result.status, 'PENDING')
    assert.deepEqual(evidence.cases.map(value => value.case), CASES.G1)
    assert.ok(evidence.cases.every(value => value.status === 'PENDING' && value.reason === 'PROBE_UNAVAILABLE'))
    assert.deepEqual(evidence.status_command, expectedArgs)
  })
  await check('other-private-launch-file-cannot-substitute', async () => {
    const other = join(temporary, 'other-private'); mkdirSync(other, {mode: 0o700})
    const wrong = join(other, 'launch-url.json')
    writeFileSync(wrong, JSON.stringify({url: base + '?token=' + token, pid: process.pid}), {mode: 0o600})
    record.ui_access_file = wrong; saveRecord()
    try {await failBeforeHttp({uiAccessFile: wrong}, 'UI_ACCESS_FILE_NOT_NAMED')}
    finally {record.ui_access_file = access; saveRecord()}
  })
  await check('resolve-equivalent-launch-names-are-refused', async () => {
    const alias = state + '/./launch-url.json'
    await failBeforeHttp({uiAccessFile: alias}, 'UI_ACCESS_FILE_NOT_NAMED')
    record.ui_access_file = alias; saveRecord()
    try {await failBeforeHttp({}, 'UI_ACCESS_FILE_NOT_NAMED')}
    finally {record.ui_access_file = access; saveRecord()}
  })
  await check('launch-pid-must-match-status', async () => {
    saveLaunch({url: base + '?token=' + token, pid: process.pid + 1})
    try {await failBeforeHttp({}, 'UI_ACCESS_PID_OR_FORMAT_MISMATCH')}
    finally {saveLaunch()}
  })
  await check('launch-file-private-mode-and-byte-bound', async () => {
    chmodSync(access, 0o644)
    try {await failBeforeHttp({}, 'UI_ACCESS_FILE_NOT_PRIVATE')}
    finally {chmodSync(access, 0o600)}
    writeFileSync(access, 'x'.repeat(16385), {mode: 0o600})
    try {await failBeforeHttp({}, 'UI_ACCESS_FILE_NOT_PRIVATE')}
    finally {saveLaunch()}
  })
  await check('launch-file-symlink-is-not-followed', async () => {
    const target = join(state, 'fixture-target.json')
    writeFileSync(target, JSON.stringify({url: base + '?token=' + token, pid: process.pid}), {mode: 0o600})
    rmSync(access); symlinkSync('fixture-target.json', access)
    try {await failBeforeHttp({})}
    finally {rmSync(access); saveLaunch()}
  })
  await check('state-directory-private-mode-is-required', async () => {
    chmodSync(state, 0o755)
    try {await failBeforeHttp({}, 'STATE_DIRECTORY_NOT_PRIVATE_OR_OWNED')}
    finally {chmodSync(state, 0o700)}
  })
  await check('state-directory-symlink-and-relative-name-are-refused', async () => {
    const alias = join(temporary, 'state-alias'); symlinkSync('external-state', alias)
    await failBeforeHttp({stateDir: alias}, 'STATE_DIRECTORY_SYMLINK_OR_ALIAS')
    await failBeforeHttp({stateDir: relative(process.cwd(), state)}, 'STATE_DIRECTORY_MUST_BE_CANONICAL_ABSOLUTE')
    await failBeforeHttp({stateDir: state + '/.'}, 'STATE_DIRECTORY_MUST_BE_CANONICAL_ABSOLUTE')
  })
  await check('release-alias-and-returned-path-substitution-are-refused', async () => {
    const alias = join(temporary, 'release-alias'); symlinkSync('release', alias)
    await failBeforeHttp({releaseDir: alias}, 'RELEASE_DIRECTORY_SYMLINK_OR_ALIAS')
    record.release_dir = alias; saveRecord()
    try {await failBeforeHttp({}, 'STATUS_RELEASE_DIRECTORY_MISMATCH')}
    finally {record.release_dir = release; saveRecord()}
  })
  console.log(JSON.stringify({status: 'PASS', checks: checks.length, scope: 'disposable external-state G1 protocol fixtures',
    prime_acceptance: 'PENDING', actual_dsh: 'NOT_PERFORMED', network: 'OWNED_DISPOSABLE_LOOPBACK_ONLY',
    same_uid_fixture: 'NOT_ISOLATION_EVIDENCE', live_app_targets: 'NONE'}))
} finally {
  if (server?.listening) {
    server.closeAllConnections()
    await new Promise(resolve => server.close(resolve))
  }
  rmSync(temporary, {recursive: true, force: true})
}
