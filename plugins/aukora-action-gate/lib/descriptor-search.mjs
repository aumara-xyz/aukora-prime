// SPDX-License-Identifier: AGPL-3.0-or-later
// The trusted host reads accepted descriptors; ripgrep receives copied bytes,
// never a pathname in the mutable workspace. This is Linux procfs custody, not
// a new sandbox/service or a fallback to the stock path-based grep body.
import * as fs from 'node:fs'
import { basename, isAbsolute, join, matchesGlob, relative, resolve } from 'node:path'
import { performance } from 'node:perf_hooks'

export const SEARCH_BOUNDS = Object.freeze({ depth: 32, entries: 16384, files: 2048,
  bytes: 20_000_000, rawBytes: 20_000_000, metadataMs: 1000, timeoutMs: 30_000 })

export class DescriptorSearchError extends Error {
  constructor(rule, message) {
    super(`AUKORA action gate refused this search [${rule}]: ${message}`)
    this.name = 'DescriptorSearchError'
    this.code = rule === 'search:aborted' ? 'SEARCH_ABORTED'
      : rule === 'search:invalid-pattern' ? 'SEARCH_INVALID_PATTERN'
      : rule === 'search:output-overflow' ? 'SEARCH_RAW_OUTPUT_OVERFLOW' : 'SEARCH_FAILED'
    this.rule = rule
  }
}
const refuse = (message, rule = 'search:unqualified') => { throw new DescriptorSearchError(rule, message) }

const fdPath = fd => `/proc/self/fd/${fd}`
const flags = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK

// The procfs link to an OWNED descriptor is the sole deliberate magic link.
// Each following component is exactly one readdir name and O_NOFOLLOW. A root
// opened in one syscall with only a leaf no-follow flag would leave its parents
// replaceable by symlinks, so anchor every absolute component from '/'.
export const LINUX_DESCRIPTOR_IO = Object.freeze({
  openRoot(path) {
    if (process.platform !== 'linux' || !isAbsolute(path) || resolve(path) !== path || path.includes('\0')) {
      refuse('the Linux no-follow descriptor reader is unavailable')
    }
    let fd = fs.openSync('/', flags | fs.constants.O_DIRECTORY)
    try {
      const components = path.split('/').filter(Boolean)
      for (let i = 0; i < components.length; i++) {
        const child = fs.openSync(`${fdPath(fd)}/${components[i]}`,
          flags | (i < components.length - 1 ? fs.constants.O_DIRECTORY : 0))
        fs.closeSync(fd)
        fd = child
      }
      const owned = fd
      fd = undefined
      return owned
    } finally { if (fd !== undefined) fs.closeSync(fd) }
  },
  openChild(fd, name) {
    if (typeof name !== 'string' || name === '' || name === '.' || name === '..' || name.includes('/') || name.includes('\0')) {
      refuse('a directory entry is not one ordinary component')
    }
    return fs.openSync(`${fdPath(fd)}/${name}`, flags)
  },
  names(fd, check, limit) {
    const directory = fs.opendirSync(fdPath(fd), { encoding: 'utf8' })
    const names = []
    try {
      for (let entry; (entry = directory.readSync()) !== null;) {
        check()
        if (names.length >= limit) refuse('the descriptor tree exceeds its entry budget')
        names.push(entry.name)
      }
    }
    finally { directory.closeSync() }
    return names.sort()
  },
  physical: fd => fs.readlinkSync(fdPath(fd)),
  mountId(fd) {
    // Device/inode equality cannot identify a same-filesystem bind mount.
    // fdinfo is a fixed kernel record for OUR retained descriptor, not a file
    // selected by the guest. Refuse descendant mount crossings as aliases.
    const info = fs.openSync(`/proc/self/fdinfo/${fd}`, flags)
    try {
      const bytes = Buffer.alloc(4097)
      const count = fs.readSync(info, bytes, 0, bytes.length, 0)
      if (count > 4096) refuse('descriptor mount identity exceeds its metadata budget')
      const fields = bytes.subarray(0, count).toString('utf8').split('\n').filter(line => line.startsWith('mnt_id:'))
      if (fields.length !== 1 || !/^mnt_id:\s+[1-9][0-9]*$/u.test(fields[0])) refuse('descriptor mount identity is unavailable')
      return BigInt(fields[0].slice(7).trim())
    } finally { fs.closeSync(info) }
  },
  stat: fd => fs.fstatSync(fd, { bigint: true }),
  read: (fd, buffer, offset, length, position) => fs.readSync(fd, buffer, offset, length, position),
  close: fd => fs.closeSync(fd),
})

function stamp(st) {
  const fields = [st.dev, st.ino, st.mode, st.nlink, st.size, st.mtimeNs, st.ctimeNs]
  if (fields.some(value => typeof value !== 'bigint') || st.dev < 0n || st.ino < 1n || st.nlink < 1n || st.size < 0n) {
    refuse('the descriptor metadata is incomplete')
  }
  return fields.map(String).join(':')
}

function budget(state) {
  if (state.signal?.aborted) refuse('the call was cancelled', 'search:aborted')
  if (state.now() >= state.deadline) refuse('the descriptor observation exceeded its metadata budget')
}

function inspect(fd, logicalPath, state) {
  budget(state)
  const st = state.io.stat(fd)
  stamp(st)
  const physicalPath = state.io.physical(fd)
  const mountId = state.io.mountId(fd)
  if (typeof mountId !== 'bigint' || mountId < 1n) refuse('descriptor mount identity is unavailable')
  state.rootMount ??= mountId
  if (mountId !== state.rootMount) refuse('a descendant crosses the accepted root mount')
  const kind = st.isFile() ? 'file' : st.isDirectory() ? 'directory' : null
  if (kind === null) refuse('only ordinary directories and regular files are qualified')
  const verdict = state.policy.judgeReadDescriptor({ logicalPath, physicalPath, kind, nlink: st.nlink }, state.call)
  if (verdict?.decision !== 'allow') refuse(verdict?.message ?? 'the descriptor could not be judged', verdict?.rule)
  return { st, physicalPath, kind, mountId }
}

function unchanged(fd, initial, state) {
  budget(state)
  if (stamp(state.io.stat(fd)) !== stamp(initial.st) || state.io.physical(fd) !== initial.physicalPath ||
      state.io.mountId(fd) !== initial.mountId) {
    refuse('an accepted descriptor changed during observation')
  }
}

// Exported for scoped checks; all I/O capabilities are trusted-host parameters,
// never plugin config or tool arguments. No content read takes a pathname.
export function readAcceptedDescriptor(fd, logicalPath, state) {
  const initial = inspect(fd, logicalPath, state)
  if (initial.kind !== 'file') refuse('the accepted object is not a regular file')
  if (initial.st.size < 0n || initial.st.size > BigInt(state.bounds.bytes - state.bytes)) {
    refuse('the accepted content exceeds the search byte budget')
  }
  const chunks = []
  let position = 0
  for (;;) {
    budget(state)
    const room = state.bounds.bytes - state.bytes
    const chunk = Buffer.allocUnsafe(Math.min(65536, room + 1))
    const count = state.io.read(fd, chunk, 0, chunk.length, position)
    if (!Number.isSafeInteger(count) || count < 0 || count > chunk.length) refuse('descriptor read returned an invalid count')
    if (count === 0) break
    if (count > room) refuse('the accepted content exceeds the search byte budget')
    position += count
    state.bytes += count
    chunks.push(Buffer.from(chunk.subarray(0, count)))
  }
  unchanged(fd, initial, state)
  if (BigInt(position) !== initial.st.size) refuse('the descriptor byte count differs from its accepted size')
  return Buffer.concat(chunks, position)
}

// This reader deliberately accepts a narrow ignore/filter dialect rather than
// interpreting unsupported syntax as permission. No config/ignore file is
// reopened by ripgrep. Negation, escapes, character classes and extglobs remain
// unqualified; ordinary literal/*/**/?/{a,b} positive globs are supported.
function qualifiedGlob(pattern) {
  if (typeof pattern !== 'string' || pattern === '' || pattern.includes('\0') ||
      /[!\\\[\]()+@\s]/u.test(pattern) || pattern.includes('..')) refuse('the search filter uses unqualified glob syntax')
  try { matchesGlob('qualification-probe', pattern) } catch { refuse('the search filter is not a usable glob') }
  return pattern
}

function ignored(logicalPath, kind, rules) {
  return rules.some(({ base, pattern, directoryOnly, anchored }) => {
    const rel = relative(base, logicalPath)
    if (rel.startsWith('../') || rel === '..' || isAbsolute(rel)) return false
    const parts = rel.split('/')
    const count = directoryOnly && kind !== 'directory' ? parts.length - 1 : parts.length
    for (let i = 1; i <= count; i++) {
      const candidate = anchored || pattern.includes('/') ? parts.slice(0, i).join('/') : parts[i - 1]
      if (matchesGlob(candidate, pattern)) return true
    }
    return false
  })
}

function ignoreRules(bytes, base) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  const out = []
  for (let pattern of text.split(/\r?\n/u)) {
    if (pattern === '' || pattern.startsWith('#')) continue
    const anchored = pattern.startsWith('/')
    const directoryOnly = pattern.endsWith('/')
    if (anchored) pattern = pattern.slice(1)
    if (directoryOnly) pattern = pattern.slice(0, -1)
    out.push({ base, pattern: qualifiedGlob(pattern), directoryOnly, anchored })
  }
  return out
}

/** Freeze a bounded, fully judged page of bytes before any matcher can run. */
export function snapshotSearchTree(root, { policy, call = {}, signal, include, workdir = root,
  io = LINUX_DESCRIPTOR_IO, bounds = SEARCH_BOUNDS, now = () => performance.now() } = {}) {
  if (typeof policy?.judgeReadDescriptor !== 'function') refuse('the descriptor policy is unavailable')
  const filter = include === undefined ? undefined : qualifiedGlob(include)
  const state = { policy, call, signal, io, bounds, now, deadline: now() + bounds.metadataMs, bytes: 0, entries: 0 }
  const files = []
  function visit(fd, logicalPath, depth, visible, inheritedRules) {
    if (++state.entries > bounds.entries || depth > bounds.depth) refuse('the descriptor tree exceeds its metadata budget')
    const initial = inspect(fd, logicalPath, state)
    if (initial.kind === 'file') {
      if (!visible || ignored(logicalPath, 'file', inheritedRules)) return
      const display = relative(workdir, logicalPath) || basename(logicalPath)
      if (filter !== undefined && !matchesGlob(filter.includes('/') ? display : basename(logicalPath), filter)) return
      if (files.length >= bounds.files) refuse('the descriptor tree exceeds its file budget')
      files.push({ path: display, bytes: readAcceptedDescriptor(fd, logicalPath, state) })
      return
    }
    const names = io.names(fd, () => budget(state), bounds.entries - state.entries)
    if (names.length + state.entries > bounds.entries) refuse('the descriptor tree exceeds its entry budget')
    let rules = inheritedRules
    if (visible && !ignored(logicalPath, 'directory', rules)) {
      for (const name of ['.gitignore', '.ignore', '.rgignore']) {
        if (!names.includes(name)) continue
        const child = io.openChild(fd, name)
        try { rules = [...rules, ...ignoreRules(readAcceptedDescriptor(child, join(logicalPath, name), state), logicalPath)] }
        finally { io.close(child) }
      }
    }
    for (const name of names) {
      const child = io.openChild(fd, name)
      try {
        const selected = visible && !name.startsWith('.') && !ignored(logicalPath, 'directory', rules)
        visit(child, join(logicalPath, name), depth + 1, selected, rules)
      } finally { io.close(child) }
    }
    unchanged(fd, initial, state)
  }
  const fd = io.openRoot(root)
  try { visit(fd, root, 0, true, []) }
  finally { io.close(fd) }
  return files
}

async function joinFailedMatcher(handle) {
  // A provider anomaly still owns its started work. Wrap each method call so
  // one synchronous cleanup exception cannot skip the other completion joins.
  // Missing or failed completion remains a refusal, never quiescence evidence.
  return Promise.allSettled([
    Promise.resolve().then(() => handle?.terminate?.()),
    Promise.resolve().then(() => handle?.done),
    Promise.resolve().then(() => handle?.waitForExit?.()),
  ])
}

async function matchAcceptedBytes(ctx, exec, module, pattern, file, remaining, signal) {
  if (signal.aborted) refuse('the call was cancelled', 'search:aborted')
  const handle = ctx.subprocess.spawn({
    argv: [await module.resolveRgPath(), '--no-config', '--json', `--regexp=${pattern}`, '--', '-'],
    cwd: '/',
    stdio: { stdin: { data: Buffer.from(file.bytes) }, stdout: { maxBytes: remaining }, stderr: { maxBytes: 65536 } },
    graceMs: 3000, signal,
  })
  if (typeof handle?.terminate !== 'function' || typeof handle?.waitForExit !== 'function') {
    await joinFailedMatcher(handle)
    refuse('the matcher provider lacks an owned completion boundary')
  }
  let outcome
  try {
    outcome = await handle.done
    if (await handle.waitForExit() !== true) refuse('the matcher range has no confirmed completion')
  } catch (error) {
    await joinFailedMatcher(handle)
    throw error
  }
  if (signal.aborted) refuse('the call was cancelled', 'search:aborted')
  if (outcome?.signal !== null || ![0, 1].includes(outcome?.exitCode)) {
    const stderr = handle.collected?.stderr?.readFrom(0)
    if (outcome?.signal === null && outcome?.exitCode === 2 && stderr?.lossy === false &&
        typeof stderr.text === 'string' && /regex parse error|error parsing glob/iu.test(stderr.text)) {
      refuse('the matcher rejected the pattern', 'search:invalid-pattern')
    }
    refuse('the matcher did not report a successful typed exit')
  }
  const stdout = handle.collected?.stdout?.readFrom(0)
  if (stdout === undefined || stdout.lossy !== false || typeof stdout.text !== 'string' || Buffer.byteLength(stdout.text) > remaining) {
    refuse('the matcher output is incomplete or exceeds its byte budget', 'search:output-overflow')
  }
  const matches = module.parseGrepMatches(stdout.text)
  for (const match of matches) {
    if (!['<stdin>', '-'].includes(match.path) || !Number.isSafeInteger(match.lineNumber) || match.lineNumber < 1 || typeof match.line !== 'string') {
      refuse('the matcher output is not bound to the accepted stdin object')
    }
  }
  if (outcome.exitCode === 1 && matches.length !== 0) refuse('the matcher exit and results conflict')
  return { bytes: Buffer.byteLength(stdout.text), matches: matches.map(match => ({ ...match, path: file.path })) }
}

/** DSH's around-dispatch seam normalizes this value through the ORIGINAL tool's
 * output schema/render/meta and keeps its post-execute/spill policies. The old
 * grep body is never invoked. Other tools still pass through their next(). */
export function createDescriptorSearch({ ctx, settings, policy, lookupPreset = () => null,
  recordDenial, loadSearch, io = LINUX_DESCRIPTOR_IO, now } = {}) {
  return async function descriptorSearch(exec, next) {
    if (exec.name !== 'grep') return next()
    const controller = new AbortController()
    let timer
    try {
      const signal = AbortSignal.any([exec.signal, controller.signal])
      const registeredTimeout = ctx.tools.get('grep', exec.agent)?.timeoutMs
      const timeout = Number.isFinite(registeredTimeout) && registeredTimeout > 0
        ? Math.min(registeredTimeout, SEARCH_BOUNDS.timeoutMs) : SEARCH_BOUNDS.timeoutMs
      timer = setTimeout(() => controller.abort(), timeout)
      timer.unref?.()
      const module = await loadSearch()
      const input = module.parseGrepArgs(exec.arguments)
      if (signal.aborted) refuse('the call was cancelled', 'search:aborted')
      const workspace = exec.agent?.session?.header?.cwd
      const workdir = workspace ?? settings.defaultWorkspace
      const call = { workspace, agent: exec.agent, presetOf: () => lookupPreset(exec.agent) }
      const files = snapshotSearchTree(resolve(workdir, input.path ?? '.'), {
        policy, call, signal, include: input.include, workdir, io, ...(now === undefined ? {} : { now }),
      })
      const matches = []
      let remaining = SEARCH_BOUNDS.rawBytes
      if (files.length === 0) {
        // Even an empty selected page must compile the pattern in the actual
        // engine. The probe carries no workspace pathname or content.
        const probe = await matchAcceptedBytes(ctx, exec, module, input.pattern,
          { path: '<empty-page>', bytes: Buffer.alloc(0) }, remaining, signal)
        if (probe.matches.length !== 0) refuse('the empty-input matcher returned content results')
      }
      for (const file of files) {
        if (remaining < 1) refuse('the matcher output exceeds its aggregate byte budget', 'search:output-overflow')
        const found = await matchAcceptedBytes(ctx, exec, module, input.pattern, file, remaining, signal)
        remaining -= found.bytes
        for (const match of found.matches) matches.push(match)
      }
      return { isError: false, value: { matches }, content: [] }
    } catch (error) {
      const refusal = error instanceof DescriptorSearchError ? error
        : new DescriptorSearchError('search:unqualified', 'the descriptor reader or matcher could not establish a complete result')
      try { recordDenial(exec, refusal) } catch { refusal.message = 'AUKORA action gate refused this search [receipt:failed]: execution evidence could not be recorded' }
      return { isError: true, error: { message: refusal.message, info: { name: refusal.name, code: refusal.code } },
        content: [{ type: 'text', text: `Error: ${refusal.message}` }] }
    } finally { if (timer !== undefined) clearTimeout(timer) }
  }
}
