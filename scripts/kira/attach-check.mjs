#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Recall checks use copied notes, held scratch paths and no network transport.
import { fork } from 'node:child_process'
import { createHash } from 'node:crypto'
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync, writeFileSync, mkdirSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { acquireScratch, bindScratchIO, readReleaseConfig, validateHeldScratch, validateScratch } from './release-recall-probe.mjs'
import { isMainModule } from '../lib/is-main.mjs'

const fail = code => { throw Object.assign(new Error(code), { code: `kira.attach-check:${code}` }) }
const codeOf = error => /^kira\.(?:attach-check|release-probe|project-map|project-identity|config):[a-z-]+$/u.test(error?.code)
  || /^memory\.identity:[a-z-]+$/u.test(error?.code) ? error.code : 'kira.attach-check:operation-failed'
const same = (left, right, fields) => fields.every(field => left[field] === right[field])
const identityFields = ['dev', 'ino', 'uid', 'mode']
const fileFields = [...identityFields, 'nlink', 'size', 'mtimeMs', 'ctimeMs']
const MAX_FILE = 64 * 1024 * 1024
const MAX_COPY = 512 * 1024 * 1024
const REASONS = new Set(['scope-not-attached', 'content-hash-mismatch', 'missing-object', 'unchained', 'unreadable',
  'forgotten', 'hidden', 'subject-out-of-scope', 'privacy-out-of-scope', 'session-out-of-scope', 'containment-quarantine'])
const hash = value => createHash('sha256').update(value, 'utf8').digest('hex')

export function attachArgs(argv) {
  if (argv.length !== 3 || argv[1] !== '--scratch-copy') fail('usage')
  if (!isAbsolute(argv[0])) fail('release-not-absolute')
  if (!isAbsolute(argv[2])) fail('scratch-not-absolute')
  return { release: argv[0], scratch: argv[2] }
}

// No source path is opened for writing; no link or special file is copied.
export function copyNoteStore(stateDir, scratch, held, { descriptorPaths = process.platform === 'linux' } = {}) {
  validateScratch(scratch, stateDir)
  validateHeldScratch(scratch, held)
  const source = realpathSync(stateDir)
  const root = openSync(source, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
  const rootInfo = fstatSync(root), restore = bindScratchIO(scratch, held, { descriptorPaths })
  let copied = 0, bytes = 0
  const checked = (path, fd, before) => {
    if (!same(fstatSync(fd), before, identityFields) || !same(lstatSync(path), before, identityFields)) fail('source-replaced')
  }
  const copyDirectory = (path, fd, target) => {
    const before = fstatSync(fd)
    checked(path, fd, before)
    mkdirSync(target, { mode: 0o700 })
    const names = readdirSync(descriptorPaths ? `/proc/self/fd/${fd}/.` : path)
    checked(path, fd, before)
    for (const name of names) {
      const from = join(path, name), anchored = descriptorPaths ? `/proc/self/fd/${fd}/${name}` : from
      let input
      try { input = openSync(anchored, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK) }
      catch { fail('source-entry-unavailable') }
      try {
        const info = fstatSync(input)
        if (info.isDirectory()) copyDirectory(from, input, join(target, name))
        else {
          if (!info.isFile() || info.nlink !== 1) fail('source-entry-invalid')
          if (info.size > MAX_FILE || bytes + info.size > MAX_COPY) fail('source-too-large')
          const data = readFileSync(input)
          if (data.length !== info.size || !same(info, fstatSync(input), fileFields)) fail('source-changed')
          checked(path, fd, before)
          writeFileSync(join(target, name), data, { flag: 'wx', mode: 0o600 })
          copied++; bytes += data.length
        }
      } finally { closeSync(input) }
    }
    checked(path, fd, before)
    if (!same(before, fstatSync(fd), ['mtimeMs', 'ctimeMs'])) fail('source-changed')
  }
  try {
    checked(source, root, rootInfo)
    const path = join(source, 'remembered')
    let notes
    try { notes = openSync(descriptorPaths ? `/proc/self/fd/${root}/remembered` : path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW) } catch { fail('source-notes-unavailable') }
    try { copyDirectory(path, notes, join(scratch, 'remembered')) } finally { closeSync(notes) }
    checked(source, root, rootInfo)
    return { copied, bytes }
  } finally { restore(); closeSync(root) }
}

export function countSummary(answer) {
  const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0
  const reasons = {}
  for (const [reason, value] of Object.entries(answer?.memory?.reasons ?? {})) {
    const safe = REASONS.has(reason) ? reason : 'unclassified-refusal'
    reasons[safe] = (reasons[safe] ?? 0) + count(value)
  }
  return { eligible: count(answer?.eligibleRecords), dropped: count(answer?.memory?.dropped), reasons }
}

// Only counts cross the child boundary; the release still makes the policy decision.
export async function recallAttachment(input) {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => fail('network-disabled')
  try { return await mountedAttachment(input) } finally { globalThis.fetch = originalFetch }
}

async function mountedAttachment(input) {
  const kira = await import(input.kiraUrl)
  const { createGateCaptureHostPlugin } = await import(input.hostUrl)
  const { readTrackedMemory } = await import(new URL('./tracked-memory.mjs', input.kiraUrl).href)
  const { filterMemoryRecords } = await import(new URL('./recall-filter/filter.mjs', input.kiraUrl).href)
  const normalized = kira.readConfig(input.config), resolver = normalized.projectIdentity
  const tools = new Map(), services = new Map(), disposers = [], agent = { session: { id: 'kira-attachment-check', header: { cwd: input.workspace } } }
  const web = { get: name => name === 'webServer' ? { register: () => () => {} }
    : name === 'connection' ? { requestRejection: () => false } : undefined,
  effect: make => { const dispose = make(); if (typeof dispose === 'function') disposers.push(dispose); return dispose } }
  const ctx = { tools: { register: tool => tools.set(tool.name, tool) }, sessions: new Map(),
    on: () => () => {}, inject: (_names, mount) => mount(web), emit() {}, logger: { info() {}, warn() {} },
    effect: web.effect, provide: (name, value) => services.set(name, value), reflect: { get: name => services.get(name) } }
  try {
    await createGateCaptureHostPlugin({ platform: 'probe', preflight: async () => false,
      loadKira: async () => kira, loadAura: async () => ({}), loadCapture: async () => ({}), gateCall: async () => ({}) }).apply(ctx, input.config)
    const tool = tools.get('kira_recall')
    if (!tool) fail('recall-unavailable')
    const answer = await tool.execute({ text: 'attachment inspection', lexical: true }, { agent })
    if (answer.remembered?.reason === 'memory-store-unavailable') fail('memory-store-unavailable')
    const live = readTrackedMemory(normalized.memoryOwner.stateDir), context = resolver.contextFor(agent)
    const scope = resolver.scopeOf(agent), aliases = context.projectAliases.filter(alias => alias.canonical_scope === scope)
    const ids = new Set(aliases.flatMap(alias => alias.record_ids))
    const scopes = new Set([scope, ...aliases.map(alias => alias.legacy_scope), ...(input.legacyScopes ?? [])])
    const projectNotes = [...live.notes, ...live.withheld].filter(note => scopes.has(note.scope) || ids.has(note.id))
    const policy = { subject: normalized.memoryOwner.subject, permittedPrivacy: normalized.memoryOwner.permittedPrivacy,
      ...context, nowMs: Date.now(), forgotten: live.forgotten, states: live.states }
    const report = { dropped: 0, reasons: {} }, all = { dropped: 0, reasons: {} }
    filterMemoryRecords(projectNotes, policy, report)
    const eligible = filterMemoryRecords([...live.notes, ...live.withheld], policy, all)
    return { ...countSummary({ eligibleRecords: eligible.length, memory: all }), returned: answer.returnedRecords ?? 0, mappedScopeDropped: report.reasons['scope-not-attached'] ?? 0,
      mappingStatus: resolver.description.alias_status }
  } finally { for (const dispose of disposers.reverse()) dispose() }
}

async function scratchStep(input) {
  const restore = bindScratchIO(input.scratch, 4)
  try { return await recallAttachment(input) } finally { restore() }
}

function freshAttachment(input, scratch, held) {
  validateHeldScratch(scratch, held)
  const env = { ...process.env, AUKORA_ROOM_LOG: join(scratch, 'absent-room.log') }
  delete env.AUKORA_STATE; delete env.AUKORA_SUPPORT_ROOT; delete env.NODE_OPTIONS
  return new Promise((done, reject) => {
    const child = fork(fileURLToPath(import.meta.url), ['--child'], { execArgv: [], env, cwd: input.release,
      stdio: ['ignore', 'ignore', 'ignore', 'ipc', held] })
    let result, reason, timer
    const timeout = setTimeout(() => { reason = 'kira.attach-check:child-timeout'; child.kill('SIGTERM')
      timer = setTimeout(() => child.kill('SIGKILL'), 250) }, 15_000)
    child.once('message', value => { result = value.result; reason = value.reason })
    child.once('error', () => { reason = 'kira.attach-check:child-failed'; child.kill('SIGKILL') })
    child.once('close', status => {
      clearTimeout(timeout); clearTimeout(timer)
      if (status !== 0 || !result) reject(Object.assign(new Error('child-failed'), { code: reason }))
      else done(result)
    })
    child.send({ ...input, scratch })
  })
}

export async function checkAttachment({ release, scratch }) {
  if (process.platform !== 'linux' || !existsSync('/proc/self/fd')) return { unperformed: 'attachment check needs Linux /proc/self/fd for descriptor-anchored scratch' }
  const loaded = await readReleaseConfig(release)
  const { readConfig } = await import(loaded.kiraUrl)
  const effective = readConfig(loaded.config), resolver = effective.projectIdentity
  const projects = resolver?.description?.projects ?? []
  if (!projects.length) fail('projects-unavailable')
  const acquired = acquireScratch(scratch, effective.memoryOwner.stateDir)
  try {
    const copied = copyNoteStore(effective.memoryOwner.stateDir, acquired.path, acquired.held)
    const config = { ...loaded.config, memoryOwner: { ...loaded.config.memoryOwner,
      subject: effective.memoryOwner.subject, stateDir: acquired.path } }
    const before = { ...config, projectIdentity: { version: 1, projects } }
    delete before.projectIdentityFile
    const rows = []
    for (const [projectIndex, project] of projects.entries()) {
      const aliases = resolver.contextFor({ session: { header: { cwd: project.workspace_roots[0] } } }).projectAliases
        .filter(alias => alias.canonical_scope === `project:id:${project.project_id}`).map(alias => alias.legacy_scope)
      const legacyScopes = [...aliases, ...project.workspace_roots.flatMap(root => [`project:${hash(root)}`, `project:${hash(join(root, '.git'))}`])]
      for (const [workspaceIndex, workspace] of project.workspace_roots.entries()) {
        const input = { ...loaded, config, workspace, legacyScopes }
        const previous = await freshAttachment({ ...input, config: before }, acquired.path, acquired.held)
        const current = await freshAttachment(input, acquired.path, acquired.held)
        rows.push({ project: projectIndex + 1, workspace: workspaceIndex + 1, before: previous, after: current })
      }
    }
    return { copied: copied.copied, rows, ok: attachmentSucceeded(rows) }
  } finally { closeSync(acquired.held) }
}

export function attachmentSucceeded(rows) {
  return rows.length > 0 && rows.every(row => row.after.mappedScopeDropped === 0 && row.after.mappingStatus !== 'draft')
}

export function attachmentLines(report) {
  const lines = [`copied-files=${report.copied} record-counts=unique`]
  for (const row of report.rows) for (const phase of ['before', 'after']) {
    const result = row[phase], reasons = Object.entries(result.reasons).sort(([left], [right]) => left.localeCompare(right))
      .map(([reason, count]) => `${reason}=${count}`).join(' ')
    lines.push(`project=${row.project} workspace=${row.workspace} ${phase}: eligible=${result.eligible} returned=${result.returned ?? 0} dropped=${result.dropped} mapped-scope-dropped=${result.mappedScopeDropped}${reasons ? ` ${reasons}` : ''}`)
  }
  lines.push(`kira-attach-check: ${report.ok ? 'PASS' : 'FAIL'}`)
  return lines
}

if (isMainModule(import.meta.url)) {
  if (process.argv[2] === '--child' && process.send) process.once('message', async input => {
    try { const result = await scratchStep(input); process.send({ result }, () => process.disconnect()) }
    catch (error) { process.exitCode = 1; process.send({ reason: codeOf(error) }, () => process.disconnect()) }
  })
  else try {
    const report = await checkAttachment(attachArgs(process.argv.slice(2)))
    if (report.unperformed) { process.stdout.write(`UNPERFORMED: ${report.unperformed}\n`); process.exitCode = 2 }
    else { process.stdout.write(`${attachmentLines(report).join('\n')}\n`); process.exitCode = report.ok ? 0 : 1 }
  } catch (error) { process.stderr.write(`FAIL ${codeOf(error)}\n`); process.exitCode = 1 }
}
