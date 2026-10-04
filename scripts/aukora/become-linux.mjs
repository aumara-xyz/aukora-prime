#!/usr/bin/env node
/** Consume an existing approved Linux release. No build, signing, provisioning or sudo fallback. */
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { closeSync, constants, existsSync, fchownSync, fchmodSync, fstatSync, fsyncSync, lstatSync,
  openSync, readFileSync, readdirSync, readlinkSync, realpathSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const SHA = /^[a-f0-9]{40}$/u, HASH = /^[a-f0-9]{64}$/u
const fail = code => { throw Object.assign(new Error(code), { code }) }
const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex')
const keys = (value, expected) => {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) fail('CLOSED_FIELDS_REQUIRED')
}
function absolute(value) {
  if (typeof value !== 'string' || !isAbsolute(value) || /[\r\n\0]/u.test(value)
    || resolve(value) !== value || realpathSync(value) !== value) fail('CANONICAL_PATH_REQUIRED')
  return value
}
function protectedPath(path) {
  for (let current = path; ; current = dirname(current)) {
    const info = lstatSync(current)
    if (info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022)) fail('ROOT_PROTECTED_PATH_REQUIRED')
    if (current === '/') break
  }
}
function protectedTree(root) {
  const pending = [root], seen = new Set()
  while (pending.length) {
    const path = pending.pop(), info = lstatSync(path)
    if (info.uid !== 0 || (!info.isSymbolicLink() && (info.mode & 0o022))) fail('ROOT_PROTECTED_TREE_REQUIRED')
    if (info.isSymbolicLink()) {
      const target = realpathSync(path)
      if (target !== root && !target.startsWith(root + '/')) fail('TREE_LINK_ESCAPES')
      if (!seen.has(target)) { seen.add(target); pending.push(target) }
    } else if (info.isDirectory()) {
      for (const name of readdirSync(path)) pending.push(join(path, name))
    } else if (!info.isFile()) fail('SPECIAL_FILE_REFUSED')
  }
}
function json(path, uid) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const info = fstatSync(fd)
    if (!info.isFile() || info.uid !== uid || info.nlink !== 1 || info.size > 65536
      || (info.mode & 0o027)) fail('PRIVATE_JSON_REQUIRED')
    return JSON.parse(readFileSync(fd, 'utf8'))
  } finally { closeSync(fd) }
}
function command(executable, argv) {
  const result = spawnSync(executable, argv, { encoding: 'utf8', maxBuffer: 1048576, timeout: 30000,
    env: { PATH: '/usr/bin:/bin', HOME: '/root', LANG: 'C' }, cwd: REPO })
  if (result.error || result.status !== 0) fail('REQUIRED_COMMAND_REFUSED')
  return result.stdout
}
// Writes occur only below the separately protected operator root, never host-owned ancestors.
function atomic(path, value, gid, mode = 0o600) {
  protectedPath(dirname(path))
  if (existsSync(path)) protectedPath(path)
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try { fchownSync(fd, 0, gid); fchmodSync(fd, mode); writeFileSync(fd, `${JSON.stringify(value)}\n`); fsyncSync(fd) }
  finally { closeSync(fd) }
  renameSync(temporary, path)
  const directory = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
  try { fsyncSync(directory) } finally { closeSync(directory) }
}
function config(path) {
  absolute(path); protectedPath(path)
  const value = json(path, 0)
  keys(value, ['version', 'service', 'source_root', 'source_commit', 'runtime_root', 'node_path', 'node_sha256',
    'support_root', 'state_root', 'releases_root', 'control_root', 'active_file', 'port', 'startup_timeout_seconds'])
  if (value.version !== 1 || value.service !== 'aukora-host.service' || !SHA.test(value.source_commit)
    || !HASH.test(value.node_sha256)) fail('HOST_CONFIG_INVALID')
  for (const name of ['source_root', 'runtime_root', 'node_path', 'support_root', 'state_root', 'releases_root', 'control_root']) absolute(value[name])
  for (const name of ['source_root', 'runtime_root', 'node_path', 'releases_root', 'control_root']) protectedPath(value[name])
  protectedTree(value.source_root)
  if (value.source_root !== REPO || process.execPath !== value.node_path || hash(value.node_path) !== value.node_sha256
    || !value.node_path.startsWith(value.runtime_root + '/') || !lstatSync(value.node_path).isFile()
    || !(lstatSync(value.node_path).mode & 0o111) || value.state_root !== join(value.support_root, 'state')
    || value.control_root.startsWith(value.support_root + '/') || value.control_root === value.support_root
    || value.active_file !== join(value.control_root, 'deployment.json')
    || !Number.isSafeInteger(value.port) || value.port < 1024 || value.port > 65535
    || !Number.isSafeInteger(value.startup_timeout_seconds) || value.startup_timeout_seconds < 1
    || value.startup_timeout_seconds > 180) fail('HOST_CONFIG_BINDING_INVALID')
  return value
}
const deploymentKeys = ['version', 'commit', 'release', 'approval_state', 'approved_record_sha', 'plugin_set_sha256', 'approval_sha256', 'pin_sha256']
function deployment(value, cfg) {
  keys(value, deploymentKeys)
  if (value.version !== 2 || !SHA.test(value.commit)
    || ['approved_record_sha', 'plugin_set_sha256', 'approval_sha256', 'pin_sha256'].some(key => !HASH.test(value[key]))) fail('DEPLOYMENT_PIN_INVALID')
  absolute(value.release); absolute(value.approval_state)
  protectedPath(value.release); protectedPath(value.approval_state)
  if (!value.release.startsWith(cfg.releases_root + '/') || value.release === cfg.runtime_root
    || cfg.state_root === value.release || cfg.state_root.startsWith(value.release + '/')
    || value.approval_state !== join(cfg.control_root, 'approvals', value.commit, 'state')) fail('RELEASE_FENCE_INVALID')
  const files = { approved_record_sha: join(value.release, '.dsh-build/genesis-artifacts.json'),
    plugin_set_sha256: join(value.release, '.dsh-build/plugin-set.json'),
    approval_sha256: join(value.approval_state, 'gate-state/plugin-set-approval.json'),
    pin_sha256: join(value.approval_state, 'gate-state/plugin-set-approver.json') }
  for (const [key, path] of Object.entries(files)) {
    protectedPath(path)
    if (!lstatSync(path).isFile() || hash(path) !== value[key]) fail('APPROVED_RECORD_CHANGED')
  }
  return value
}
async function approval(cfg, selected) {
  const git = (...args) => command('/usr/bin/git', ['-C', REPO, ...args]).trim()
  if (git('rev-parse', 'HEAD') !== cfg.source_commit
    || git('--no-optional-locks', 'status', '--porcelain', '--', 'scripts', 'apps', 'plugins', 'upstream-dsh.json')) fail('APPROVED_MACHINERY_REQUIRED')
  command('/usr/bin/git', ['-C', REPO, 'merge-base', '--is-ancestor', selected.commit, 'origin/main'])
  const { auditCommits } = await import(pathToFileURL(join(REPO, 'scripts/aukora/witness.mjs')).href)
  for (const commit of new Set([cfg.source_commit, selected.commit])) {
    const row = auditCommits({ repo: REPO, support: cfg.support_root, commit }).rows[0]
    if (row?.commit !== commit || row.verdict !== 'MATCH') fail('CODE_AURA_MATCH_REQUIRED')
    command('/usr/bin/git', ['-C', REPO, 'merge-base', '--is-ancestor', commit, 'origin/main'])
  }
  protectedTree(selected.release); protectedTree(cfg.runtime_root)
  const { releaseBinding, sameBinding } = await import(pathToFileURL(join(REPO, 'scripts/aukora/release-digest.mjs')).href)
  const record = JSON.parse(readFileSync(join(selected.release, '.dsh-build/plugin-set.json'), 'utf8'))
  const binding = releaseBinding({ commit: selected.commit, release: selected.release, shell: cfg.runtime_root })
  if (!sameBinding(record.release, binding)) fail('LINUX_RUNTIME_APPROVAL_BINDING_REQUIRED')
  command(cfg.node_path, [join(REPO, 'scripts/aukora/plugin-set.mjs'), 'check', '--release', selected.release,
    '--shell', cfg.runtime_root, '--support', cfg.support_root, '--state-root', selected.approval_state])
  return () => {
    deployment(selected, cfg)
    if (!sameBinding(binding, releaseBinding({ commit: selected.commit, release: selected.release, shell: cfg.runtime_root }))) fail('APPROVED_BYTES_CHANGED')
  }
}
async function ownerProtocol() {
  const { readOwnerDaemonConfig } = await import(pathToFileURL(join(REPO, 'apps/aukora-desktop/aumlok-airlock-config.mjs')).href)
  const { assertOwnerDaemonProtocol } = await import(pathToFileURL(join(REPO, 'apps/aukora-desktop/aumlok-signer-airlock.mjs')).href)
  const ownerApproval = await import(pathToFileURL(join(REPO, 'plugins/aukora-aumlok/lib/owner-approval.mjs')).href)
  const owner = readOwnerDaemonConfig()
  if (!owner) fail('LINUX_OWNER_DAEMON_REQUIRED')
  await assertOwnerDaemonProtocol(owner, ownerApproval)
}
async function ready(cfg, expected, uid) {
  // Includes the separate startup proof verifier's 180-second bound before launcher readiness.
  const deadline = Date.now() + (180 + cfg.startup_timeout_seconds) * 1000
  while (Date.now() < deadline) {
    try {
      const group = command('/usr/bin/systemctl', ['show', cfg.service, '--property=ControlGroup', '--value']).trim()
      const state = command('/usr/bin/systemctl', ['show', cfg.service, '--property=ActiveState', '--value']).trim()
      const descriptor = json(join(cfg.state_root, 'launch-url.json'), uid)
      keys(descriptor, ['url', 'pid'])
      const url = new URL(descriptor.url)
      if (state !== 'active' || !group || !Number.isSafeInteger(descriptor.pid) || descriptor.pid <= 1
        || url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || Number(url.port) !== cfg.port
        || url.username || url.password || url.pathname !== '/' || url.hash
        || [...url.searchParams].length !== 1 || !url.searchParams.get('token')) throw new Error()
      const cgroups = readFileSync(`/proc/${descriptor.pid}/cgroup`, 'utf8').trim().split('\n')
      if (!cgroups.some(line => line.split(':').slice(2).join(':') === group)) throw new Error()
      const ids = readFileSync(`/proc/${descriptor.pid}/status`, 'utf8').match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/mu)
      if (!ids || ids.slice(1).some(id => Number(id) !== uid) || realpathSync(`/proc/${descriptor.pid}/exe`) !== cfg.node_path) throw new Error()
      const argv = readFileSync(`/proc/${descriptor.pid}/cmdline`, 'utf8').split('\0').filter(Boolean)
      if (argv[0] !== cfg.node_path || !argv.includes(join(expected.release, 'apps/cli/lib/bin.js'))) throw new Error()
      const launch = json(join(cfg.state_root, 'launch.json'), uid)
      if (launch.pid !== descriptor.pid || launch.release !== expected.release || JSON.stringify(launch.command) !== JSON.stringify(argv)) throw new Error()
      const exchanged = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(3000) })
      const cookies = exchanged.headers.getSetCookie()
      if (exchanged.status !== 303 || exchanged.headers.get('location') !== '/' || cookies.length !== 1
        || !/;\s*HttpOnly(?:;|$)/iu.test(cookies[0]) || !/;\s*SameSite=Strict(?:;|$)/iu.test(cookies[0])
        || !/;\s*Path=\/(?:;|$)/iu.test(cookies[0]) || /;\s*Domain=/iu.test(cookies[0])) throw new Error()
      await exchanged.body?.cancel()
      const visible = await fetch(new URL('/', url), { redirect: 'manual', headers: { cookie: cookies[0].split(';')[0] }, signal: AbortSignal.timeout(3000) })
      const accepted = visible.status === 200
      await visible.body?.cancel()
      if (accepted) return descriptor.pid
    } catch { /* No raw URL, cookie, body or descriptor enters evidence. */ }
    await new Promise(resolve => setTimeout(resolve, 250))
  }
  fail('PRIVATE_COOKIE_READINESS_TIMEOUT')
}
function requireLease(lock) {
  protectedPath(lock)
  for (const fd of readdirSync('/proc/self/fdinfo')) {
    try {
      if (readlinkSync(`/proc/self/fd/${fd}`) === lock
        && new RegExp(`lock:\\s+\\d+:\\s+FLOCK\\s+ADVISORY\\s+WRITE\\s+${process.pid}\\s`, 'u').test(readFileSync(`/proc/self/fdinfo/${fd}`, 'utf8'))) return
    } catch { /* A disappearing fd is not a lease. */ }
  }
  fail('OS_RELEASED_LEASE_REQUIRED')
}
export async function becomeLinux(argv = process.argv.slice(2)) {
  if (argv.includes('--help')) {
    console.log('become-linux --config ROOT_CONFIG --commit FULL_SHA --release EXISTING_RELEASE --approval-state ROOT_APPROVED_STATE [--plan] | --config ROOT_CONFIG --rollback | --config ROOT_CONFIG --verify-start')
    return
  }
  if (process.platform !== 'linux') fail('LINUX_REQUIRED')
  const flags = {}
  for (let index = 0; index < argv.length; index++) {
    const name = argv[index]
    if (['--plan', '--rollback', '--detach', '--verify-start', '--leased'].includes(name)) { if (flags[name]) fail('DUPLICATE_ARGUMENT'); flags[name] = true; continue }
    if (!['--config', '--commit', '--release', '--approval-state', '--why'].includes(name)
      || flags[name] !== undefined || !argv[index + 1] || argv[index + 1].startsWith('--')) fail('ARGUMENT_INVALID')
    flags[name] = argv[++index]
  }
  const cfg = config(flags['--config'])
  const uid = Number(command('/usr/bin/id', ['-u', 'aukora-host']).trim())
  const gid = Number(command('/usr/bin/id', ['-g', 'aukora-host']).trim())
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid <= 0) fail('HOST_IDENTITY_REQUIRED')
  if (flags['--verify-start']) {
    if (Object.keys(flags).some(key => !['--config', '--verify-start'].includes(key))
      || process.getuid() !== uid || process.geteuid() !== uid) fail('HOST_START_ROLE_REQUIRED')
    await ownerProtocol()
    const selected = deployment(json(cfg.active_file, 0), cfg)
    const recheck = await approval(cfg, selected); recheck()
    console.log(JSON.stringify({ status: 'START_PROOF_VERIFIED', commit: selected.commit }))
    return
  }
  if (process.getuid() !== 0 || process.geteuid() !== 0) fail('EXTERNAL_OWNER_OPERATOR_REQUIRED')
  if (readFileSync('/proc/self/cgroup', 'utf8').includes('/aukora-host.service')) fail('INDEPENDENT_CONTROLLER_REQUIRED')
  const lock = join(cfg.control_root, 'transition.lock'), last = join(cfg.control_root, 'transition.json')
  if (!flags['--plan'] && !flags['--leased']) {
    if (!existsSync(lock)) {
      const fd = openSync(lock, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
      try { fsyncSync(fd) } finally { closeSync(fd) }
    }
    protectedPath(lock)
    const info = lstatSync(lock)
    if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o077)) fail('PRIVATE_LEASE_FILE_REQUIRED')
    const result = spawnSync('/usr/bin/flock', ['-n', '-F', lock, cfg.node_path, fileURLToPath(import.meta.url), ...argv, '--leased'],
      { stdio: 'inherit', env: { PATH: '/usr/bin:/bin', HOME: '/root', LANG: 'C' }, cwd: REPO })
    if (result.error || result.signal) fail('LEASED_CONTROLLER_INTERRUPTED')
    process.exitCode = result.status ?? 2
    return
  }
  if (flags['--leased']) requireLease(lock)
  await ownerProtocol()
  let saved, selected
  if (flags['--rollback']) {
    if (flags['--commit'] || flags['--release'] || flags['--approval-state']) fail('ROLLBACK_ARGUMENT_INVALID')
    saved = json(last, 0); keys(saved, ['version', 'status', 'previous', 'next'])
    if (saved.version !== 1 || !['PREPARED', 'STOP_INTENT', 'STOPPED', 'APPLIED', 'CONFIRMED', 'OUTCOME_UNKNOWN'].includes(saved.status)) fail('ROLLBACK_RECORD_INVALID')
    selected = deployment(saved.previous, cfg)
  } else {
    if (!SHA.test(flags['--commit'] ?? '')) fail('EXACT_COMMIT_REQUIRED')
    const release = absolute(flags['--release']), approvalState = absolute(flags['--approval-state'])
    selected = deployment({ version: 2, commit: flags['--commit'], release, approval_state: approvalState,
      approved_record_sha: hash(join(release, '.dsh-build/genesis-artifacts.json')),
      plugin_set_sha256: hash(join(release, '.dsh-build/plugin-set.json')),
      approval_sha256: hash(join(approvalState, 'gate-state/plugin-set-approval.json')),
      pin_sha256: hash(join(approvalState, 'gate-state/plugin-set-approver.json')) }, cfg)
  }
  const recheck = await approval(cfg, selected)
  if (flags['--plan']) {
    console.log(JSON.stringify({ status: 'PLAN_VALIDATED', commit: selected.commit, service: cfg.service, live_changed: false }))
    return
  }
  let previousRecheck
  if (!flags['--rollback']) {
    if (existsSync(last) && ['PREPARED', 'STOP_INTENT', 'STOPPED', 'APPLIED', 'OUTCOME_UNKNOWN'].includes(json(last, 0).status)) fail('PREVIOUS_TRANSITION_UNRESOLVED')
    const previous = deployment(json(cfg.active_file, 0), cfg)
    previousRecheck = await approval(cfg, previous)
    saved = { version: 1, status: 'PREPARED', previous, next: selected }
  }
  const writeStatus = status => { saved.status = status; atomic(last, saved, 0) }
  let interrupted = false
  const interrupt = () => { interrupted = true }
  const checkSignal = () => { if (interrupted) fail('OPERATOR_INTERRUPTED') }
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(signal, interrupt)
  try {
    writeStatus('PREPARED'); recheck(); checkSignal()
    writeStatus('STOP_INTENT'); command('/usr/bin/systemctl', ['stop', cfg.service]); writeStatus('STOPPED'); checkSignal()
    recheck(); atomic(cfg.active_file, selected, gid, 0o440); writeStatus('APPLIED'); checkSignal()
    command('/usr/bin/systemctl', ['start', cfg.service])
    const pid = await ready(cfg, selected, uid); checkSignal(); recheck()
    writeStatus(flags['--rollback'] ? 'ROLLED_BACK' : 'CONFIRMED')
    console.log(JSON.stringify({ status: flags['--rollback'] ? 'ROLLED_BACK' : 'LIVE', commit: selected.commit, pid }))
  } catch (error) {
    if (['STOP_INTENT', 'STOPPED', 'APPLIED'].includes(saved.status)) {
      if (!flags['--rollback']) {
        try {
          command('/usr/bin/systemctl', ['stop', cfg.service]); previousRecheck()
          atomic(cfg.active_file, saved.previous, gid, 0o440)
          command('/usr/bin/systemctl', ['start', cfg.service]); await ready(cfg, saved.previous, uid)
          previousRecheck(); writeStatus('ROLLED_BACK')
        } catch { writeStatus('OUTCOME_UNKNOWN') }
      } else writeStatus('OUTCOME_UNKNOWN')
    }
    throw error
  } finally { for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.removeListener(signal, interrupt) }
}
export function linuxRefused(error) {
  console.error(`Linux become refused: ${/^[A-Z_]+$/u.test(error.code ?? '') ? error.code : 'UNAVAILABLE'}; no approval or privileged fallback`)
  process.exitCode = 2
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) becomeLinux().catch(linuxRefused)
