// SPDX-License-Identifier: AGPL-3.0-or-later
// Stop the harness, rotate its browser signing secret and restart its configured service.
import { randomBytes } from 'node:crypto'
import { closeSync, constants, existsSync, fchmodSync, fchownSync, fstatSync, fsyncSync, lstatSync,
  openSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'
import { isDeepStrictEqual } from 'node:util'

const RECORD = 'client-connection/browser-session'
const UNITS = ['aukora-browser.service', 'aukora-genesis.service']
const STATE_ROOT = '/home/aukora-host/genesis/state'
const refuse = code => { throw new Error(code) }

export function protectedPath(path, privateFile = false, rootOnly = true, linked = false) {
  if (!isAbsolute(path) || realpathSync(path) !== path) refuse('SESSION_PATH_REFUSED')
  const info = lstatSync(path)
  // pnpm hard-links a built harness's dependencies from its root-private store (seen on a real node);
  // code-tree files may therefore have several links. Owner and mode are still required of them.
  if (!info.isFile() || info.isSymbolicLink() || (!linked && info.nlink !== 1)
    || (privateFile && (info.mode & 0o077)) || (info.mode & 0o022)) refuse('SESSION_FILE_REFUSED')
  if (rootOnly) {
    if (!privateFile && info.uid !== 0) refuse('SESSION_PATH_REFUSED')
    for (let directory = dirname(path);;) {
      const ancestor = lstatSync(directory)
      if (!ancestor.isDirectory() || ancestor.isSymbolicLink() || (ancestor.mode & 0o022)
        || ![0, privateFile ? info.uid : 0].includes(ancestor.uid)) refuse('SESSION_PATH_REFUSED')
      if (directory === dirname(directory)) break
      directory = dirname(directory)
    }
  }
  return info
}

export function protectedCodeTree(directory, rootOnly = true) {
  const info = lstatSync(directory)
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o022)
    || (rootOnly && info.uid !== 0) || realpathSync(directory) !== directory) refuse('SESSION_CODE_TREE_REFUSED')
  for (const name of readdirSync(directory)) {
    const path = join(directory, name)
    if (lstatSync(path).isDirectory()) protectedCodeTree(path, rootOnly)
    else protectedPath(path, false, rootOnly, true)
  }
}

export function rotateSecret(path, parseDocument, rootOnly = true) {
  const original = protectedPath(path, true, rootOnly)
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  let source
  try {
    const opened = fstatSync(descriptor)
    if (opened.ino !== original.ino || opened.dev !== original.dev || opened.size > 1024 * 1024) {
      refuse('SESSION_FILE_CHANGED')
    }
    source = readFileSync(descriptor, 'utf8')
  } finally { closeSync(descriptor) }
  const document = parseDocument(source, { uniqueKeys: true })
  if (document.errors.length) refuse('SESSION_DOCUMENT_INVALID')
  const data = document.toJS()
  const record = data?.records?.[RECORD]
  if (data?.version !== 1 || !record || Object.keys(record).sort().join(',') !== 'kind,payload'
    || record.kind !== 'grant' || !record.payload
    || Object.keys(record.payload).sort().join(',') !== 'secret,version' || record.payload.version !== 1
    || typeof record.payload.secret !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(record.payload.secret)
    || Buffer.from(record.payload.secret, 'base64url').toString('base64url') !== record.payload.secret) {
    refuse('SESSION_RECORD_INVALID')
  }
  const secret = randomBytes(32).toString('base64url')
  const expected = JSON.parse(JSON.stringify(data))
  expected.records[RECORD].payload.secret = secret
  document.setIn(['records', RECORD, 'payload', 'secret'], secret)
  if (!isDeepStrictEqual(document.toJS(), expected)) refuse('SESSION_OTHER_CREDENTIALS_CHANGED')
  const temporary = join(dirname(path), '.browser-secret-' + randomBytes(16).toString('hex'))
  const output = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    fchmodSync(output, 0o600)
    if (rootOnly) fchownSync(output, original.uid, original.gid)
    writeFileSync(output, String(document))
    fsyncSync(output)
    const current = protectedPath(path, true, rootOnly)
    if (current.ino !== original.ino || current.dev !== original.dev) refuse('SESSION_FILE_CHANGED')
    renameSync(temporary, path)
    const directory = openSync(dirname(path), constants.O_RDONLY)
    try { fsyncSync(directory) } finally { closeSync(directory) }
  } finally {
    closeSync(output)
    if (existsSync(temporary)) unlinkSync(temporary)
  }
}

export function revokeAll(path, parseDocument, lifecycle, rootOnly = true) {
  protectedPath(path, true, rootOnly)
  if (!lifecycle.stop()) refuse('SESSION_HARNESS_STOP_FAILED')
  if (!lifecycle.inactive()) refuse('SESSION_HARNESS_STILL_RUNNING')
  rotateSecret(path, parseDocument, rootOnly)
  if (!lifecycle.start()) refuse('SESSION_HARNESS_RESTART_FAILED')
  if (!lifecycle.active()) refuse('SESSION_HARNESS_RESTART_UNVERIFIED')
}

export function validateInvocation(version, platform, uid, arguments_) {
  if (version !== 'v24.11.1') refuse('SESSION_NODE_VERSION_REFUSED')
  if (platform !== 'linux' || uid !== 0) refuse('SESSION_ROOT_LINUX_REQUIRED')
  if (arguments_.length !== 2 || arguments_[0] !== '--harness-root') {
    refuse('SESSION_ARGUMENTS_REFUSED')
  }
}

export function credentialsForUnit(source) {
  const argv = /argv\[\]=([^;]+);/u.exec(source)?.[1].trim().split(/ +/u) ?? []
  const index = argv.indexOf('--state-root')
  if (argv[0] !== '/usr/bin/python3' || argv[1] !== 'scripts/launch-dsh.py'
    || argv.filter(value => value === '--state-root').length !== 1 || argv[index + 1] !== STATE_ROOT) {
    refuse('SESSION_SERVICE_CONFIG_REFUSED')
  }
  return join(STATE_ROOT, 'home/.credentials.yaml')
}

export function harnessService(run) {
  const targets = []
  for (const unit of UNITS) {
    const result = run(['show', '--property=LoadState,ActiveState,ExecStart', unit])
    if (result.status !== 0) refuse('SESSION_SERVICE_CONFIG_UNVERIFIED')
    const rows = result.stdout.trim().split('\n')
    const properties = Object.fromEntries(rows.map(row => {
      const equals = row.indexOf('=')
      return [row.slice(0, equals), row.slice(equals + 1)]
    }))
    // systemd 255 omits ExecStart entirely for a unit that does not exist (seen on a real node), so an
    // absent unit is exactly two rows; any other shape must carry all three properties.
    const names = Object.keys(properties).sort().join(',')
    if (rows.length === 2 && names === 'ActiveState,LoadState'
      && properties.LoadState === 'not-found' && properties.ActiveState === 'inactive') continue
    if (rows.length !== 3 || names !== 'ActiveState,ExecStart,LoadState') {
      refuse('SESSION_SERVICE_STATE_UNVERIFIED')
    }
    if (properties.LoadState === 'not-found' && properties.ActiveState === 'inactive' && properties.ExecStart === '') continue
    if (properties.LoadState !== 'loaded' || !['active', 'inactive', 'failed'].includes(properties.ActiveState)) {
      refuse('SESSION_SERVICE_STATE_UNVERIFIED')
    }
    if (properties.ActiveState === 'active') {
      targets.push({ unit, credentialsFile: credentialsForUnit(properties.ExecStart) })
    }
  }
  if (targets.length !== 1) refuse('SESSION_SERVICE_ACTIVE_UNIT_REFUSED')
  const { unit, credentialsFile } = targets[0]
  const lifecycle = {
    stop: () => run(['stop', unit]).status === 0,
    inactive: () => { const result = run(['is-active', unit]); return result.status === 3 && result.stdout.trim() === 'inactive' },
    start: () => run(['start', unit]).status === 0,
    active: () => { const result = run(['is-active', unit]); return result.status === 0 && result.stdout.trim() === 'active' },
  }
  return { unit, credentialsFile, lifecycle }
}

function main() {
  const arguments_ = process.argv.slice(2)
  validateInvocation(process.version, process.platform, process.geteuid(), arguments_)
  const harnessRoot = resolve(arguments_[1])
  const packageFile = join(harnessRoot, 'packages/credentials/credentials-local/package.json')
  protectedPath(packageFile, false, true, true)
  const require = createRequire(packageFile)
  const yamlPath = realpathSync(require.resolve('yaml'))
  protectedPath(yamlPath, false, true, true)
  protectedCodeTree(dirname(dirname(yamlPath)))
  const { parseDocument } = require(yamlPath)
  const run = arguments_ => spawnSync('/usr/bin/systemctl', arguments_, {
    encoding: 'utf8', timeout: 30000, env: { PATH: '/usr/bin:/bin', LANG: 'C' },
  })
  const { credentialsFile, lifecycle } = harnessService(run)
  revokeAll(credentialsFile, parseDocument, lifecycle)
  process.stdout.write('SESSION_SECRET_ROTATED_HARNESS_RESTARTED\n')
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { main() } catch (error) {
    process.stderr.write(/^SESSION_[A-Z_]+$/u.test(error.message) ? error.message + '\n' : 'SESSION_REVOCATION_FAILED\n')
    process.exitCode = 1
  }
}
