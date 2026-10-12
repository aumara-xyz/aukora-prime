#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Read legacy note scopes and exclusively write an explicit project alias map. */
import { createHash } from 'node:crypto'
import { closeSync, constants, existsSync, fchmodSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, readdirSync, writeSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, normalize, sep } from 'node:path'
import { createProjectIdentityResolver } from '../../plugins/aukora-kira/lib/project-identity.mjs'
import { parseStrictText } from '../../plugins/aukora-kira/lib/strict-read.mjs'
import { isMainModule } from '../lib/is-main.mjs'

const MAX_BYTES = 1024 * 1024, MAX_RECORDS = 100_000
const RECORD_ID = /^(?:rem|kira):[0-9a-f]{64}$/u
const LEGACY_SCOPE = /^project:[0-9a-f]{64}$/u
const refuse = code => { throw Object.assign(new Error(`kira.build-project-map:${code}`), { code: `kira.build-project-map:${code}` }) }
const same = (before, after, keys) => keys.every(key => before[key] === after[key])
const pathOf = path => {
  if (typeof path !== 'string' || !isAbsolute(path) || normalize(path) !== path
    || /[\u0000-\u001f\u007f]/u.test(path)) refuse('path-invalid')
  return path
}
const hashScope = value => `project:${createHash('sha256').update(value).digest('hex')}`

function heldDirectories(path, protectedOutput = false) {
  const parents = [], descriptorPaths = process.platform === 'linux' && existsSync('/proc/self/fd')
  try {
    for (const component of ['/', ...path.split('/').filter(Boolean)]) {
      const previous = parents.at(-1), nominal = previous ? join(previous.path, component) : '/'
      const source = previous && descriptorPaths ? `/proc/self/fd/${previous.fd}/${component}` : nominal
      let fd
      try { fd = openSync(source, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW) }
      catch { refuse('directory-unavailable') }
      const parent = { fd, path: nominal, stat: fstatSync(fd) }
      parents.push(parent)
      if (!parent.stat.isDirectory()) refuse('directory-invalid')
      if (protectedOutput && (parent.stat.uid !== 0 && parent.stat.uid !== process.getuid?.()
        || (parent.stat.mode & 0o022) !== 0)) refuse('output-parent-unprotected')
    }
    const verify = () => {
      for (const parent of parents) if (!same(parent.stat, fstatSync(parent.fd), ['dev', 'ino', 'uid', 'mode'])
        || !same(parent.stat, lstatSync(parent.path), ['dev', 'ino', 'uid', 'mode'])) refuse('directory-changed')
    }
    verify()
    return { source: descriptorPaths ? `/proc/self/fd/${parents.at(-1).fd}` : path,
      fd: parents.at(-1).fd, verify, close: () => { for (const parent of parents.reverse()) closeSync(parent.fd) } }
  } catch (error) { for (const parent of parents.reverse()) closeSync(parent.fd); throw error }
}

function readNote(path) {
  let fd
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const before = fstatSync(fd)
    if (!before.isFile() || before.nlink !== 1) refuse('note-file-invalid')
    if (before.size > MAX_BYTES) refuse('note-too-large')
    const bytes = Buffer.alloc(MAX_BYTES + 1)
    let used = 0, count
    while (used < bytes.length && (count = readSync(fd, bytes, used, bytes.length - used, null)) > 0) used += count
    if (used > MAX_BYTES) refuse('note-too-large')
    if (used !== before.size || !same(before, fstatSync(fd), ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']))
      refuse('note-changed')
    try { return parseStrictText(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, used)), 'note') }
    catch { refuse('note-json-invalid') }
  } catch (error) {
    if (error?.code?.startsWith('kira.build-project-map:')) throw error
    refuse('note-unavailable')
  } finally { if (fd !== undefined) closeSync(fd) }
}

export function projectMapArgs(argv) {
  const args = { stateDir: argv[0], projects: [] }
  if (!args.stateDir || args.stateDir.startsWith('--')) refuse('usage')
  for (let i = 1; i < argv.length; i += 2) {
    const flag = argv[i], value = argv[i + 1]
    if (!['--project', '--out', '--owner-reviewed'].includes(flag) || !value || value.startsWith('--')) refuse('usage')
    if (flag === '--project') {
      const split = value.indexOf('=')
      if (split < 1) refuse('usage')
      args.projects.push({ project_id: value.slice(0, split), workspace_roots: [value.slice(split + 1)] })
    } else {
      const key = flag === '--out' ? 'out' : 'reviewId'
      if (args[key] !== undefined) refuse('usage')
      args[key] = value
    }
  }
  if (!args.out || args.projects.length === 0) refuse('usage')
  return args
}

export function buildProjectMap({ stateDir, projects, out, reviewId }) {
  pathOf(stateDir); pathOf(out)
  if (out === stateDir || out.startsWith(stateDir.endsWith(sep) ? stateDir : `${stateDir}${sep}`)) refuse('output-in-state')
  const grouped = new Map()
  if (!Array.isArray(projects)) refuse('projects-invalid')
  for (const entry of projects) {
    if (!entry || !Array.isArray(entry.workspace_roots)) refuse('projects-invalid')
    const roots = grouped.get(entry.project_id) ?? []
    roots.push(...entry.workspace_roots); grouped.set(entry.project_id, roots)
  }
  let config = { version: 1, projects: [...grouped].map(([project_id, workspace_roots]) => ({ project_id, workspace_roots })),
    alias_table: { version: 1, status: reviewId === undefined ? 'draft' : 'owner-reviewed',
      ...(reviewId === undefined ? {} : { review_id: reviewId }), entries: [] } }
  let resolver
  try { resolver = createProjectIdentityResolver(config) } catch { refuse('projects-invalid') }
  if (resolver.description.projects.length === 0) refuse('projects-invalid')
  config.projects = resolver.description.projects
  const store = heldDirectories(join(stateDir, 'remembered')), byScope = new Map()
  let noteCount = 0
  try {
    const names = readdirSync(store.source).filter(name => name.endsWith('.json') && !['ack.json', 'retry.json'].includes(name)).sort()
    if (names.length > MAX_RECORDS) refuse('too-many-notes')
    for (const name of names) {
      if (!/^[0-9a-f]{64}\.json$/u.test(name)) refuse('note-name-invalid')
      const note = readNote(join(store.source, name))
      if (!note || typeof note !== 'object' || Array.isArray(note) || !RECORD_ID.test(note.id)
        || note.id.slice(note.id.indexOf(':') + 1) !== name.slice(0, -5)) refuse('note-id-invalid')
      if (typeof note.scope !== 'string' || !/^(?:owner|agent|project:unresolved|project:[0-9a-f]{64}|project:id:[a-z0-9][a-z0-9._-]{0,79})$/u.test(note.scope))
        refuse('note-scope-invalid')
      noteCount++
      if (LEGACY_SCOPE.test(note.scope) || note.scope === 'project:unresolved') {
        const ids = byScope.get(note.scope) ?? []; ids.push(note.id); byScope.set(note.scope, ids)
      }
    }
    store.verify()
    if (names.join('\n') !== readdirSync(store.source).filter(name => name.endsWith('.json') && !['ack.json', 'retry.json'].includes(name)).sort().join('\n'))
      refuse('store-changed')
  } finally { store.close() }
  const matched = new Map()
  for (const project of config.projects) {
    let found = false
    for (const root of project.workspace_roots) for (const scope of [hashScope(root), hashScope(join(root, '.git'))]) {
      if (!byScope.has(scope)) continue
      if (matched.has(scope) && matched.get(scope) !== project.project_id) refuse('legacy-scope-ambiguous')
      matched.set(scope, project.project_id); found = true
    }
    if (!found) refuse('project-unmatched')
  }
  config.alias_table.entries = [...matched].sort(([a], [b]) => a.localeCompare(b)).map(([legacy_scope, project_id]) => ({
    legacy_scope, project_id, record_ids: byScope.get(legacy_scope).sort(),
  }))
  try { createProjectIdentityResolver(config) } catch { refuse('mapping-invalid') }
  const bytes = Buffer.from(`${JSON.stringify(config, null, 2)}\n`)
  if (bytes.length > MAX_BYTES) refuse('output-too-large')
  const parent = heldDirectories(dirname(out), true)
  let fd
  try {
    parent.verify()
    try { fd = openSync(join(parent.source, basename(out)), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600) }
    catch (error) { refuse(error?.code === 'EEXIST' ? 'output-exists' : 'output-unavailable') }
    let written = 0
    while (written < bytes.length) {
      const count = writeSync(fd, bytes, written, bytes.length - written)
      if (count <= 0) refuse('output-write-failed')
      written += count
    }
    fsyncSync(fd); fchmodSync(fd, 0o644); fsyncSync(fd); fsyncSync(parent.fd); parent.verify()
  } finally { if (fd !== undefined) closeSync(fd); parent.close() }
  return { notes: noteCount, projects: config.projects.length, scopes: matched.size,
    mapped: [...matched.keys()].reduce((sum, scope) => sum + byScope.get(scope).length, 0),
    unmatched: [...byScope].filter(([scope]) => !matched.has(scope)).sort(([a], [b]) => a.localeCompare(b))
      .map(([scope, ids]) => ({ scope, notes: ids.length })) }
}

export function formatProjectMapReport(report) {
  return `kira-build-project-map: notes=${report.notes} projects=${report.projects} scopes=${report.scopes} mapped=${report.mapped} unmatched=${report.unmatched.reduce((sum, row) => sum + row.notes, 0)}\n`
    + report.unmatched.map(row => `unmatched scope=${row.scope} notes=${row.notes}\n`).join('')
}

if (isMainModule(import.meta.url)) {
  try { process.stdout.write(formatProjectMapReport(buildProjectMap(projectMapArgs(process.argv.slice(2))))) }
  catch (error) { process.stderr.write(`${error?.code?.startsWith('kira.build-project-map:') ? error.code : 'kira.build-project-map:failed'}\n`); process.exitCode = 1 }
}
