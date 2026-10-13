#!/usr/bin/env node
// Boot a verified release with disposable same-user gate authority and probe its authenticated routes.
import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { createHash, createPublicKey } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'

const refuse = code => Object.assign(new Error(code), { code })
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'))
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
const under = (file, root) => file === root || file.startsWith(root + path.sep)

export function developmentPath(root, file, { privateRoot = false } = {}) {
  if (!path.isAbsolute(root) || path.resolve(root) !== root || fs.realpathSync(root) !== root
    || !path.basename(root).startsWith('aukora-fresh-clone-')
    || ![fs.realpathSync(tmpdir()), fs.realpathSync('/tmp')].some(parent => under(root, parent) && root !== parent))
    throw refuse('development-root-invalid')
  const rootInfo = fs.lstatSync(root)
  if (!rootInfo.isDirectory() || rootInfo.uid !== process.getuid() || (rootInfo.mode & 0o077))
    throw refuse('development-root-not-private')
  if (!path.isAbsolute(file) || path.resolve(file) !== file || !under(file, root))
    throw refuse('development-path-outside-root')
  let current = file
  while (true) {
    const info = fs.lstatSync(current)
    if (info.isSymbolicLink() || info.uid !== process.getuid() || (info.mode & 0o022)
      || (!info.isDirectory() && (!info.isFile() || info.nlink !== 1)))
      throw refuse('development-path-unprotected')
    if (current === root) break
    current = path.dirname(current)
  }
  if (privateRoot && fs.lstatSync(file).mode & 0o077) throw refuse('development-path-not-private')
  return file
}

function writePrivate(root, file, value) {
  developmentPath(root, path.dirname(file))
  if (fs.existsSync(file)) developmentPath(root, file)
  const temporary = file + '.tmp-' + process.pid
  const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600)
  try { fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
  fs.renameSync(temporary, file)
  const directory = fs.openSync(path.dirname(file), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW)
  try { fs.fsyncSync(directory) } finally { fs.closeSync(directory) }
}

async function gateModules(checkout) {
  const load = relative => import(pathToFileURL(path.join(checkout, relative)).href)
  const [canon, floor, targets, gate, server, secrets, wiring] = await Promise.all([
    load('packages/boundary-gate/src/plugin-set-canon.mjs'), load('packages/boundary-gate/src/release-floor.mjs'),
    load('packages/boundary-gate/src/targets.mjs'), load('packages/boundary-gate/src/gate.mjs'),
    load('packages/boundary-gate/src/server.mjs'), load('packages/boundary-gate/src/secrets.mjs'),
    load('packages/boundary-gate/src/wiring.mjs'),
  ])
  return { canon, floor, targets, gate, server, secrets, wiring }
}

export async function checkAdmission({ checkout, release, root }) {
  developmentPath(root, checkout); developmentPath(root, release)
  const gateState = path.join(root, 'support/state/gate-state')
  for (const name of ['boundary-approval.json', 'boundary-approver.json', 'signer-epochs.json', 'release-floor.json'])
    developmentPath(root, path.join(gateState, name), { privateRoot: true })
  const { canon, floor, targets } = await gateModules(checkout)
  const record = readJson(path.join(release, '.dsh-build/plugin-set.json'))
  const approval = readJson(path.join(gateState, 'boundary-approval.json'))
  const pin = readJson(path.join(gateState, 'boundary-approver.json'))
  const verified = canon.verifyOrderedGateApproval({ record, approval, pin, epochs: readJson(path.join(gateState, 'signer-epochs.json')) })
  const installed = targets.installedRelease(path.dirname(release), path.basename(release))
  if (verified.release !== installed.release || verified.record !== installed.record)
    throw refuse('development-approval-for-other-release')
  floor.checkFloor(floor.readFloor(path.join(gateState, 'release-floor.json')), verified)
  return installed
}

export function assertNoPluginErrors(log) {
  if (/^aukora-[a-z-]+ \(file:\/\/.*\): Error/mu.test(log)) throw refuse('face-plugin-load-error')
}
export function assertFaceEntries(expected, graph) {
  const present = new Set((graph?.entries ?? []).map(row => row.id))
  if (expected.length === 0 || expected.some(id => !present.has(id))) throw refuse('face-plugin-not-loaded')
}
export function assertActionRefusal(result) {
  if (result?.bodyRan !== false || result?.result?.isError !== true
    || !JSON.stringify(result.result).includes('authority:tool-not-approved')) throw refuse('action-gate-did-not-refuse')
}
export function assertHttpStatus(response, expected, code) {
  if (response.status !== expected) throw refuse(code)
}
export function assertUiBody(body) {
  if (body.length === 0) throw refuse('release-ui-not-served')
}
export function assertProbeExit(result) {
  if (result.status !== 0 || !result.stdout?.includes('UI PROBE: all served')) throw refuse('release-ui-probe-failed')
}

export const probeSource = `// Temporary authenticated inspection of the running tool guard and client graph.
export const name = 'fresh-clone-probe'
export const inject = ['tools', 'webServer', 'connection', 'clientModules']
export function apply(ctx) {
  let bodyRan = false
  ctx.tools.register({ name: 'fresh_clone_unapproved_action', description: 'Fresh clone denial control', parameters: {},
    output: { schema: { type: 'null' }, render: () => [] }, async execute() { bodyRan = true; return null } })
  ctx.effect(() => ctx.webServer.register({ kind: 'exact', path: '/api/fresh-clone-probe', handler: async (req, res) => {
    const rejection = typeof ctx.connection?.requestRejection === 'function' ? ctx.connection.requestRejection(req) : 403
    if (rejection !== undefined) { res.writeHead(rejection); res.end(); return }
    if (req.method !== 'GET') { res.writeHead(405); res.end(); return }
    const result = await ctx.tools.execute({ name: 'fresh_clone_unapproved_action', arguments: {},
      callId: 'fresh-clone-denial', signal: new AbortController().signal })
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ bodyRan, result, graph: ctx.clientModules.graph() }))
  } }), 'fresh-clone temporary diagnostic route')
}
`

async function unusedPort() {
  const server = net.createServer()
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  const port = server.address().port
  await new Promise(resolve => server.close(resolve))
  return port
}

export async function terminate(pid) {
  if (!pid) return
  try { process.kill(-pid, 'SIGTERM') } catch (error) {
    if (error.code !== 'ESRCH') throw error
    try { process.kill(pid, 'SIGTERM') } catch (failure) { if (failure.code === 'ESRCH') return; throw failure }
  }
  for (let i = 0; i < 100; i++) {
    try { process.kill(pid, 0) } catch (error) { if (error.code === 'ESRCH') return }
    await delay(50)
  }
  try { process.kill(-pid, 'SIGKILL') } catch (error) {
    if (error.code !== 'ESRCH') throw error
    try { process.kill(pid, 'SIGKILL') } catch (failure) { if (failure.code !== 'ESRCH') throw failure }
  }
}

export async function bootAndProbe({ checkout, release, root }) {
  developmentPath(root, checkout); developmentPath(root, release)
  process.umask(0o077)
  const support = path.join(root, 'support'), state = path.join(support, 'state'), gateState = path.join(state, 'gate-state')
  for (const directory of [support, state, gateState, ...['home', 'agents', 'workspace', 'logs'].map(name => path.join(state, name)),
    path.join(root, 'gate-home'), path.join(root, 'gate-run'), path.join(root, 'targets')]) fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
  const modules = await gateModules(checkout)
  const { canon, floor, targets, gate: gateApi, server: serverApi, secrets, wiring } = modules
  const floorFile = path.join(gateState, 'release-floor.json'), targetRoot = path.join(root, 'targets')
  const registry = { ...wiring.gateTargets(targetRoot, { releasesRoot: path.dirname(release) }),
    [targets.PLUGIN_SET_TARGET]: targets.pluginSetTarget(targetRoot, { releasesRoot: path.dirname(release), floorFile }) }
  const home = path.join(root, 'gate-home'), owner = secrets.loadOwnerSecret(home)
  const boundary = gateApi.createGate({ home, owner, targets: registry, store: wiring.gateStore() })
  let sockets, child, signer, backendPid, interrupted = false
  const stop = () => { interrupted = true }
  process.on('SIGTERM', stop); process.on('SIGINT', stop)
  try {
    const startup = boundary.startup({ bearerInfo: secrets.rotateBearer(home, owner) })
    if (startup.ok !== true) throw refuse('development-gate-ledger-invalid')
    sockets = await serverApi.serveGate(boundary, { runDir: path.join(root, 'gate-run') })
    const record = readJson(path.join(release, '.dsh-build/plugin-set.json'))
    const installed = targets.installedRelease(path.dirname(release), path.basename(release))
    const content = targets.pluginSetApprovalText({ ...installed, operation: canon.operationDigestOf(canon.setOperationContent(record)) })
    const pending = await serverApi.call(sockets.ownerSocket, 'raise', { target: targets.PLUGIN_SET_TARGET, content, why: 'Disposable fresh clone boot check' })
    const review = await serverApi.call(sockets.ownerSocket, 'review', { id: pending.id })
    const applied = await serverApi.call(sockets.ownerSocket, 'decide_review', { id: pending.id, base_sha: review.base_sha,
      new_sha: review.new_sha, review_challenge: review.review_challenge, outcome: 'allowed-once' })
    if (applied.applied !== true) throw refuse('development-owner-review-not-applied')
    const ledger = await serverApi.call(sockets.ownerSocket, 'log', { target: targets.PLUGIN_SET_TARGET, limit: 200 })
    if (ledger.verify?.ok !== true) throw refuse('development-gate-ledger-invalid')
    const entry = ledger.entries.find(row => row.event === 'apply' && row.proposal === pending.id)
    if (!entry?.signed_entry || fs.readFileSync(path.join(targetRoot, targets.PLUGIN_SET_TARGET), 'utf8') !== content)
      throw refuse('development-applied-bytes-mismatch')
    const ping = await serverApi.call(sockets.proposeSocket, 'ping')
    const keyHash = sha(createPublicKey(ping.pubkey_pem).export({ format: 'der', type: 'spki' }))
    const approval = { kind: 'aukora-plugin-set-gate-approval/v1', content, receipt: entry.detail.receipt,
      receipt_sig: entry.detail.receipt_sig, ledger_entry: entry.signed_entry }
    const pin = { kind: 'aukora-boundary-gate-owner/v1', gatePubkeyPem: ping.pubkey_pem, gatePubkeyFp: keyHash.slice(0, 16),
      target: targets.PLUGIN_SET_TARGET, approver: approval.receipt.approver }
    const epochs = { version: 1, kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1, gate_pubkey_sha256: keyHash }] }
    const verified = canon.verifyOrderedGateApproval({ record, approval, pin, epochs })
    writePrivate(root, floorFile, floor.advanceFloor(floor.readFloor(floorFile), verified))
    writePrivate(root, path.join(gateState, 'boundary-approval.json'), approval)
    writePrivate(root, path.join(gateState, 'boundary-approver.json'), pin)
    writePrivate(root, path.join(gateState, 'signer-epochs.json'), epochs)
    await checkAdmission({ checkout, release, root })
    console.log('PASS | signed owner.sock review and exact release floor with throwaway same-user authority')
    const identityDirectory = path.join(state, 'aumlok')
    const generated = spawnSync(process.execPath, [path.join(checkout, 'scripts/aumlok/make-disposable-identity.mjs'),
      '--directory', identityDirectory], { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 30000 })
    if (generated.status !== 0) throw refuse('disposable-identity-generation-failed')
    const identity = readJson(path.join(identityDirectory, 'local-control.json'))
    const aumlok = await import(pathToFileURL(path.join(checkout, 'plugins/aukora-aumlok/lib/index.mjs')).href)
    const projection = aumlok.projectPublicControl({ genesis: identity.genesis, activeControl: identity.activeControl, custodyClass: identity.custodyClass })
    const keyFile = path.join(identityDirectory, 'owner.pem')
    fs.writeFileSync(keyFile, identity.ed25519PrivateKeyPem, { mode: 0o600, flag: 'wx' })
    const registered = identity.activeControl.publicKeys.ed25519
    fs.writeFileSync(path.join(support, 'kira-deployment-overlay.patch.yml'),
      `subject: ${projection.subject}\nactiveControlDigest: ${projection.activeControlDigest}\napproverDid: ${projection.approvalKeyDid}\n`, { mode: 0o600, flag: 'wx' })
    const signerSocket = path.join(state, 'aumlok-signer.sock')
    signer = spawn(process.execPath, [path.join(checkout, 'scripts/aumlok/signer.mjs'), '--socket', signerSocket,
      '--key-file', keyFile, '--registered-key-hex', registered, '--approve', 'test-all'],
      { env: { PATH: process.env.PATH }, stdio: ['ignore', 'pipe', 'pipe'], detached: true })
    let signerOutput = ''
    signer.stdout.on('data', bytes => { signerOutput += bytes }); signer.stderr.on('data', bytes => { signerOutput += bytes })
    for (let i = 0; i < 100 && !fs.existsSync(signerSocket) && signer.exitCode === null; i++) await delay(50)
    if (!fs.existsSync(signerSocket)) throw refuse(signerOutput.includes('EPERM') ? 'listen-EPERM' : 'disposable-owner-signer-unavailable')
    const admitted = spawnSync(process.execPath, [path.join(checkout, 'scripts/aukora/plugin-set.mjs'), 'approve', '--release', release,
      '--support', support, '--approval-class', 'scripted', '--out', path.join(support, 'approval-evidence')],
      { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 30000 })
    if (admitted.status !== 0) throw refuse('disposable-plugin-set-approval-failed')
    const check = spawnSync(process.execPath, [path.join(checkout, 'scripts/aukora/plugin-set.mjs'), 'check', '--release', release,
      '--support', support], { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 30000 })
    if (check.status !== 0) throw refuse('disposable-plugin-set-verification-failed')
    console.log('PASS | real plugin-set approval command with disposable Aumlok signer')
    console.log('MODE | supported unprivileged scripted signer and temporary diagnostic plugin')
    console.log('LIMIT | no human ceremony enrolled owner key root custody or containment proof')
    const probe = path.join(support, 'probe.mjs'), overlay = path.join(support, 'probe.patch.yml')
    const kiraOverlay = path.join(support, 'kira-runtime.patch.yml')
    const kiraTemplate = fs.readFileSync(path.join(release, 'aukora-deployment-overlay.patch.yml'), 'utf8')
    const kiraConfig = kiraTemplate.replaceAll('${KIRA_STATE_DIR}', JSON.stringify(path.join(state, 'kira')))
      .replaceAll('${SUBJECT}', projection.subject).replaceAll('${CONTROL_DIGEST}', projection.activeControlDigest)
      .replaceAll('${APPROVER_DID}', projection.approvalKeyDid)
    if (/\$\{[A-Z_]+\}/u.test(kiraConfig)) throw refuse('deployment-template-unresolved')
    fs.writeFileSync(kiraOverlay, kiraConfig, { mode: 0o600, flag: 'wx' })
    fs.writeFileSync(probe, probeSource, { mode: 0o600, flag: 'wx' })
    fs.writeFileSync(overlay, '- insert:\n    - id: fresh-clone-probe\n      name: ./probe.mjs\n', { mode: 0o600, flag: 'wx' })
    const port = await unusedPort()
    const processProbe = spawnSync('ps', ['-ax', '-o', 'pid=', '-o', 'ppid=', '-o', 'command='], { encoding: 'utf8' })
    if (processProbe.status !== 0) throw refuse('process-observation-unavailable')
    child = spawn('python3', [path.join(checkout, 'scripts/launch-dsh.py'), '--release', release, '--state-root', state,
      '--port', String(port), '--approved-record-sha', installed.record,
      '--patch', path.join(release, 'aukora-composition.patch.yml'), '--patch', kiraOverlay, '--patch', overlay],
    { env: { PATH: process.env.PATH, HOME: path.join(state, 'home'), TMPDIR: root, AUKORA_SUPPORT_ROOT: support,
      AUKORA_LAUNCH_STARTUP_TIMEOUT: '30' }, cwd: checkout, stdio: ['ignore', 'pipe', 'pipe'] })
    let output = ''
    child.stdout.on('data', bytes => { output += bytes }); child.stderr.on('data', bytes => { output += bytes })
    const observeChildren = () => {
      const observed = spawnSync('ps', ['-ax', '-o', 'pid=', '-o', 'ppid=', '-o', 'command='], { encoding: 'utf8' })
      for (const line of observed.stdout?.split('\n') ?? []) {
        const match = /^\s*(\d+)\s+(\d+)\s+(.*)$/u.exec(line)
        if (match && Number(match[2]) === child.pid && match[3].includes(path.join(release, 'apps/cli/lib/bin.js'))) backendPid = Number(match[1])
      }
    }
    const observer = setInterval(observeChildren, 100)
    let exitCode
    try { exitCode = await new Promise(resolve => child.on('close', resolve)) } finally { clearInterval(observer); observeChildren() }
    const launchRecord = path.join(state, 'launch.json')
    if (fs.existsSync(launchRecord)) backendPid = readJson(launchRecord).pid
    if (interrupted) throw refuse('fresh-clone-interrupted')
    if (exitCode !== 0) throw refuse(output.includes('Operation not permitted') || output.includes('EPERM') ? 'listen-EPERM' : 'release-launch-refused')
    const launchFile = path.join(state, 'launch-url.json')
    for (let i = 0; i < 600 && !fs.existsSync(launchFile) && !interrupted; i++) await delay(100)
    if (interrupted) throw refuse('fresh-clone-interrupted')
    if (!fs.existsSync(launchFile)) throw refuse('release-startup-timeout')
    const launch = readJson(launchFile), url = new URL(launch.url)
    backendPid = launch.pid
    const signedIn = await fetch(launch.url, { redirect: 'manual', signal: AbortSignal.timeout(10000) })
    const cookieName = 'dsh-auth-' + createHash('sha256').update(url.host).digest('base64url')
    const cookie = signedIn.headers.getSetCookie().map(row => row.split(';')[0]).find(row => row.startsWith(cookieName + '='))
    if (!cookie) throw refuse('release-launch-token-signin-failed')
    const headers = { cookie, origin: url.origin }
    const ui = await fetch(url.origin + '/', { headers, signal: AbortSignal.timeout(10000) })
    assertHttpStatus(ui, 200, 'release-ui-not-served'); assertUiBody(await ui.text())
    console.log('PASS | UI answers using its own launch token')
    const unauthenticated = await fetch(url.origin + '/api/fresh-clone-probe', { redirect: 'manual', signal: AbortSignal.timeout(10000) })
    assertHttpStatus(unauthenticated, 401, 'unauthenticated-request-not-refused')
    console.log('PASS | unauthenticated request returns 401')
    const response = await fetch(url.origin + '/api/fresh-clone-probe', { headers, signal: AbortSignal.timeout(10000) })
    assertHttpStatus(response, 200, 'runtime-diagnostic-unavailable')
    const result = await response.json()
    assertActionRefusal(result)
    console.log('PASS | running action gate refuses unapproved action before its body')
    const faces = fs.readdirSync(path.join(release, 'plugins')).filter(name => name.startsWith('aukora-face-'))
      .map(name => readJson(path.join(release, 'plugins', name, 'package.json')).name)
    assertFaceEntries(faces, result.graph)
    assertNoPluginErrors(fs.readFileSync(path.join(state, 'logs/server.log'), 'utf8'))
    console.log('PASS | every shipped face is in the running client graph with no plugin Error line')
    const probeResult = spawnSync(process.execPath, [path.join(checkout, 'ops/pilot/ui-probe.mjs'), launchFile, '--release', release],
      { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 30000 })
    assertProbeExit(probeResult)
    console.log((probeResult.stdout ?? '').trim())
    console.log('PASS | thread icon and stock apps served through ops/pilot/ui-probe.mjs')
  } finally {
    process.off('SIGTERM', stop); process.off('SIGINT', stop)
    if (!backendPid && fs.existsSync(path.join(state, 'launch.json'))) backendPid = readJson(path.join(state, 'launch.json')).pid
    await terminate(backendPid)
    if (child && child.exitCode === null) await terminate(child.pid)
    if (signer && signer.exitCode === null) await terminate(signer.pid)
    await sockets?.close(); boundary.close()
  }
}

if (import.meta.url.startsWith('file:') && process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const { values } = parseArgs({ options: { checkout: { type: 'string' }, release: { type: 'string' }, root: { type: 'string' },
    'check-admission': { type: 'boolean' } } })
  try {
    for (const name of ['checkout', 'release', 'root']) if (!values[name]) throw refuse('runtime-option-missing')
    if (values['check-admission']) await checkAdmission(values)
    else await bootAndProbe(values)
  } catch (error) {
    const unavailable = ['EPERM', 'listen-EPERM', 'EACCES', 'process-observation-unavailable'].includes(error.code)
    console.error((unavailable ? 'UNPERFORMED: ' : 'FAIL  ') + (error.code ?? 'fresh-clone-runtime-failed'))
    process.exitCode = unavailable ? 2 : 1
  }
}
