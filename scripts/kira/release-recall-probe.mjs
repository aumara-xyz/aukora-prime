#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise release Kira in fresh processes using a caller-owned scratch store.
import { fork } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { constants, closeSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { createRequire, syncBuiltinESMExports } from 'node:module'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isMainModule } from '../lib/is-main.mjs'

const fs = createRequire(import.meta.url)('node:fs')
const JOURNAL = 'release-probe.json'
const CHILD_FD = 4
const QUESTION = 'Where was my red two-wheeler left?'
const LEXICAL = 'scarlet bicycle maple'
const fail = code => { throw Object.assign(new Error(code), { code: `kira.release-probe:${code}` }) }
// Refusal codes from Kira itself (memory.identity:field-mismatch, kira.config:...) are names, not data: pass them
// through so an operator sees why, instead of one opaque code. Anything else stays opaque.
const codeOf = error => /^kira\.release-probe:[a-z-]+$/u.test(error?.code) ? error.code
  : /^(?:memory\.identity|kira\.[a-z-]+):[a-z-]+$/u.test(error?.code) ? `kira.release-probe:operation-failed (${error.code})`
    : 'kira.release-probe:operation-failed'
const within = (child, parent) => { const path = relative(parent, child); return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path)) }

// Resolve missing state roots through their existing ancestors, including symlink aliases.
function canonical(path) {
  try { return realpathSync(path) }
  catch (error) {
    if (error.code !== 'ENOENT' || dirname(path) === path) throw error
    return join(canonical(dirname(path)), basename(path))
  }
}

export function probeArgs(argv) {
  if (argv.length === 2 && argv[0] === '--cleanup') {
    if (!isAbsolute(argv[1])) fail('scratch-not-absolute')
    return { scratch: argv[1], cleanup: true }
  }
  if (argv.length !== 3 || argv[1] !== '--scratch-state') fail('usage')
  if (!isAbsolute(argv[0])) fail('release-not-absolute')
  if (!isAbsolute(argv[2])) fail('scratch-not-absolute')
  return { release: argv[0], scratch: argv[2] }
}

export function validateScratch(scratch, realState, { uid = process.getuid(), cleanup = false } = {}) {
  if (typeof scratch !== 'string' || !isAbsolute(scratch)) fail('scratch-not-absolute')
  let info, path
  try { path = realpathSync(scratch); info = lstatSync(path) } catch { fail('scratch-not-directory') }
  if (!info.isDirectory()) fail('scratch-not-directory')
  if (info.uid !== uid) fail('scratch-not-owned')
  if ((info.mode & 0o077) !== 0) fail('scratch-not-private')
  if (within(path, canonical(resolve(realState)))) fail('scratch-real-state')
  if (!cleanup && readdirSync(path).length !== 0) fail('scratch-not-empty')
  let component = resolve(scratch)
  while (component !== dirname(component)) {
    if (lstatSync(component).isSymbolicLink()) fail('scratch-symlink')
    component = dirname(component)
  }
  return path
}

function releaseFile(release, path) {
  const file = realpathSync(join(release, path))
  if (!within(file, release)) fail('release-file-outside')
  return pathToFileURL(file).href
}

export async function readReleaseConfig(selected) {
  if (typeof selected !== 'string' || !isAbsolute(selected)) fail('release-not-absolute')
  const release = realpathSync(selected)
  const includeUrl = releaseFile(release, 'vendor/include/lib/index.js')
  const { entryListSchema, applyEntryPatches } = await import(includeUrl)
  const { interpolate } = await import(releaseFile(release, 'vendor/loader/lib/index.js'))
  const { dshHomePath } = await import(releaseFile(release, 'packages/util/home-paths/lib/index.js'))
  const yaml = createRequire(includeUrl)('js-yaml')
  let rows
  try {
    const patches = yaml.load(readFileSync(fileURLToPath(releaseFile(release, 'aukora-composition.patch.yml')), 'utf8'), { schema: entryListSchema })
    if (!Array.isArray(patches) || patches.some(row => !row || typeof row !== 'object' || Array.isArray(row))) fail('composition-invalid')
    rows = applyEntryPatches([], patches, () => {})
  } catch { fail('composition-invalid') }
  const matches = rows.filter(row => row.id === 'aukora-kira')
  if (matches.length !== 1 || Boolean(interpolate({ dshHomePath }, matches[0].disabled))
    || matches[0].name !== './plugins/aukora-kira/lib/gate-capture-host.mjs'
    || !matches[0].config?.memoryOwner) fail('kira-row-invalid')
  const config = interpolate({ dshHomePath }, matches[0].config)
  const kiraUrl = releaseFile(release, 'plugins/aukora-kira/lib/index.js')
  const hostUrl = releaseFile(release, 'plugins/aukora-kira/lib/gate-capture-host.mjs')
  const bridgeUrl = releaseFile(release, 'plugins/aukora-kira/lib/recall-openviking.mjs')
  return { release, config, kiraUrl, hostUrl, bridgeUrl }
}

// Every scratch operation resolves beneath held directories; opens recheck their path identity.
export function bindScratchIO(scratch, held, { descriptorPaths = process.platform === 'linux' } = {}) {
  const original = Object.fromEntries(['openSync', 'readFileSync', 'writeFileSync', 'appendFileSync', 'existsSync', 'lstatSync', 'statSync',
    'readdirSync', 'mkdirSync', 'chmodSync', 'renameSync', 'linkSync', 'unlinkSync', 'rmdirSync'].map(name => [name, fs[name]]))
  const opened = fs.fstatSync(held), initialCwd = process.cwd()
  const sameDirectory = fd => {
    const current = original.openSync('.', constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
    try { const info = fs.fstatSync(current), retained = fs.fstatSync(fd); if (info.dev !== retained.dev || info.ino !== retained.ino) fail('scratch-replaced') }
    finally { fs.closeSync(current) }
  }
  if (!descriptorPaths) {
    try { process.chdir(scratch); sameDirectory(held) } catch (error) { process.chdir(initialCwd); throw error }
  }
  const verify = () => {
    let current
    try { current = original.lstatSync(scratch) } catch { fail('scratch-replaced') }
    if (!current.isDirectory() || current.dev !== opened.dev || current.ino !== opened.ino) fail('scratch-replaced')
  }
  const relativePath = path => typeof path === 'string' && within(resolve(path), scratch) ? relative(scratch, resolve(path)) : null
  const traverse = (path, { create = false, directory = false } = {}) => {
    verify()
    if (!descriptorPaths) sameDirectory(held)
    const suffix = relativePath(path), names = suffix ? suffix.split(sep) : []
    const parents = directory ? names : names.slice(0, -1), descriptors = [], ancestors = [{ path: scratch, fd: held }]
    let fd = held, current = scratch
    try {
      for (const name of parents) {
        current = join(current, name)
        const target = descriptorPaths ? `/proc/self/fd/${fd}/${name}` : name
        if (create) { try { original.mkdirSync(target, { mode: 0o700 }) } catch (error) { if (error.code !== 'EEXIST') throw error } }
        fd = original.openSync(target, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
        descriptors.push(fd); ancestors.push({ path: current, fd })
        if (!descriptorPaths) { process.chdir(name); sameDirectory(fd); if (original.lstatSync(current).isSymbolicLink()) fail('scratch-symlink') }
      }
      const check = () => {
        verify()
        for (const ancestor of ancestors) {
          const info = original.lstatSync(ancestor.path), retained = fs.fstatSync(ancestor.fd)
          if (!info.isDirectory() || info.dev !== retained.dev || info.ino !== retained.ino) fail('scratch-replaced')
        }
      }
      check()
      return { target: directory || !names.length ? (descriptorPaths ? `/proc/self/fd/${fd}/.` : '.')
        : descriptorPaths ? `/proc/self/fd/${fd}/${names.at(-1)}` : names.at(-1), check,
      close: () => {
        try { if (!descriptorPaths) { process.chdir(scratch); sameDirectory(held) } }
        finally { descriptors.reverse().forEach(fd => fs.closeSync(fd)) }
      } }
    } catch (error) { descriptors.reverse().forEach(fd => fs.closeSync(fd)); throw error }
  }
  const guarded = (path, action, options) => {
    if (relativePath(path) === null) return action(path, () => {})
    const parent = traverse(path, options)
    try {
      try { if (original.lstatSync(parent.target).isSymbolicLink()) fail('scratch-symlink') }
      catch (error) { if (error.code !== 'ENOENT') throw error }
      const result = action(parent.target, parent.check)
      parent.check(); return result
    } finally { parent.close() }
  }
  const flagsOf = flags => typeof flags === 'number' ? flags : ({ r: constants.O_RDONLY, 'r+': constants.O_RDWR,
    w: constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC, wx: constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
    a: constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND, ax: constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | constants.O_EXCL })[flags]
  fs.openSync = (path, flags, mode) => {
    let opened, accepted = false
    try {
      const result = guarded(path, (target, check) => {
        const value = relativePath(path) === null ? flags : flagsOf(flags) | constants.O_NOFOLLOW | constants.O_NONBLOCK
        check()
        const fd = original.openSync(target, typeof value === 'number' ? value & ~constants.O_TRUNC : value, mode)
        try { check(); if (typeof value === 'number' && (value & constants.O_TRUNC)) fs.ftruncateSync(fd); opened = fd; return fd }
        catch (error) { fs.closeSync(fd); throw error }
      })
      accepted = true; return result
    } finally { if (!accepted && opened !== undefined) fs.closeSync(opened) }
  }
  fs.readFileSync = (path, options) => relativePath(path) === null ? original.readFileSync(path, options)
    : (() => { const fd = fs.openSync(path, constants.O_RDONLY); try { return original.readFileSync(fd, options) } finally { fs.closeSync(fd) } })()
  for (const name of ['writeFileSync', 'appendFileSync']) fs[name] = (path, data, options) => relativePath(path) === null
    ? original[name](path, data, options) : (() => {
      const fd = fs.openSync(path, options?.flag ?? (name === 'appendFileSync' ? 'a' : 'w'), options?.mode ?? 0o600)
      try { return original[name](fd, data, options) } finally { fs.closeSync(fd) }
    })()
  fs.mkdirSync = (path, options) => relativePath(path) === null ? original.mkdirSync(path, options)
    : guarded(path, () => undefined, { create: true, directory: true })
  fs.chmodSync = (path, mode) => relativePath(path) === null ? original.chmodSync(path, mode)
    : (() => { const fd = fs.openSync(path, constants.O_RDONLY); try { fs.fchmodSync(fd, mode) } finally { fs.closeSync(fd) } })()
  fs.existsSync = path => { try { fs.lstatSync(path); return true } catch (error) { if (error.code === 'ENOENT') return false; throw error } }
  for (const name of ['lstatSync', 'statSync', 'readdirSync', 'unlinkSync', 'rmdirSync']) fs[name] = (path, ...args) =>
    guarded(path, target => original[name](target, ...args), { directory: name === 'readdirSync' })
  for (const name of ['renameSync', 'linkSync']) fs[name] = (from, to) => {
    if (relativePath(from) === null && relativePath(to) === null) return original[name](from, to)
    if (dirname(from) !== dirname(to) || relativePath(from) === null || relativePath(to) === null) fail('scratch-path-unavailable')
    return guarded(from, source => {
      const target = join(dirname(source), basename(to))
      try { if (original.lstatSync(target).isSymbolicLink()) fail('scratch-symlink') } catch (error) { if (error.code !== 'ENOENT') throw error }
      return original[name](source, target)
    })
  }
  syncBuiltinESMExports()
  return () => { Object.assign(fs, original); syncBuiltinESMExports(); if (!descriptorPaths) process.chdir(initialCwd) }
}

// Probe URIs are siblings of normal Kira memory; tenant headers and credentials stay unchanged.
export function probeTransport(config, run, transport = globalThis.fetch) {
  const normal = `viking://user/${config.user}/memories/kira`, isolated = `viking://user/${config.user}/memories/kira-release-probe/${run}`
  const map = (value, from, to) => typeof value === 'string' && (value === from || value.startsWith(`${from}/`)) ? to + value.slice(from.length) : value
  const translate = (value, from, to) => Array.isArray(value) ? value.map(item => translate(item, from, to))
    : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, translate(item, from, to)])) : map(value, from, to)
  const controller = new AbortController(), pending = new Set()
  const track = async action => {
    const request = Promise.resolve().then(action)
    pending.add(request)
    try { return await request } finally { pending.delete(request) }
  }
  const fetch = async (url, options = {}) => {
    if (!String(url).startsWith(`${config.url}/`)) return transport(url, options)
    const mapped = new URL(url), uri = mapped.searchParams.get('uri')
    if (uri) mapped.searchParams.set('uri', map(uri, normal, isolated))
    const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal
    const response = await track(() => transport(mapped.href, { ...options, signal,
      ...(options.body ? { body: JSON.stringify(translate(JSON.parse(options.body), normal, isolated)) } : {}) }))
    return { ok: response.ok, status: response.status, json: () => track(async () => translate(await response.json(), isolated, normal)) }
  }
  fetch.abort = () => controller.abort()
  fetch.close = async () => { fetch.abort(); await Promise.allSettled([...pending]) }
  return fetch
}

// Delete once, then establish content and index absence twice before releasing recovery state.
async function cleanupIndex(input, bridge) {
  const config = bridge.readBridgeConfig(input.config.openVikingHome)
  if (!config.configured || config.user !== input.user || config.account !== input.account || config.url !== input.url) return { cleaned: false }
  const options = { redirect: 'error', headers: { 'content-type': 'application/json', 'x-api-key': config.key,
    'x-openviking-account': config.account, 'x-openviking-user': config.user }, signal: AbortSignal.timeout(Math.max(1, Math.min(30_000, config.timeoutMs))) }
  try {
    const deleted = await fetch(`${config.url}/api/v1/fs?uri=${encodeURIComponent(input.uri)}`, { ...options, method: 'DELETE' })
    if (deleted.status !== 404 && (!deleted.ok || (await deleted.json()).status !== 'ok')) return { cleaned: false }
    for (let observation = 0; observation < 2; observation++) {
      if (observation) await new Promise(resolveDelay => setTimeout(resolveDelay, 250))
      const absent = await fetch(`${config.url}/api/v1/content/read?uri=${encodeURIComponent(input.uri)}`, { ...options, signal: AbortSignal.timeout(Math.max(1, Math.min(30_000, config.timeoutMs))) })
      if (absent.status !== 404) return { cleaned: false }
      const searched = await fetch(`${config.url}/api/v1/search/find`, { ...options, method: 'POST',
        body: JSON.stringify({ query: input.sentence, target_uri: input.uri.slice(0, input.uri.lastIndexOf('/')), limit: 50 }),
        signal: AbortSignal.timeout(Math.max(1, Math.min(30_000, config.timeoutMs))) })
      const result = await searched.json()
      if (!searched.ok || result.status !== 'ok' || !Array.isArray(result.result?.memories)
        || result.result.memories.length !== 0 || !Array.isArray(result.result?.resources) || result.result.resources.length !== 0) return { cleaned: false }
    }
    return { cleaned: true }
  } catch { return { cleaned: false } }
}

async function childStep(input) {
  if (input.action === 'cleanup') return cleanupIndex(input, await import(input.bridgeUrl))
  const restore = bindScratchIO(input.scratch, CHILD_FD)
  try { return await childOperation(input) } finally { restore() }
}

async function childOperation(input) {
  const bridge = await import(input.bridgeUrl)
  if (input.action === 'cleanup') return cleanupIndex(input, bridge)
  if (input.action === 'preflight') {
    const { readBridgeConfig, createOpenVikingRecall } = await import(input.bridgeUrl)
    const config = readBridgeConfig(input.config.openVikingHome)
    if (!config.configured) return { ok: false, reason: 'bridge-configuration-unavailable' }
    const status = await createOpenVikingRecall({ config }).available()
    return { ok: status.ok, reason: status.ok ? null : status.reason }
  }
  const bridgeConfig = bridge.readBridgeConfig(input.config.openVikingHome)
  globalThis.fetch = probeTransport(bridgeConfig, input.run)
  const transport = globalThis.fetch
  const abort = () => transport.abort()
  process.once('SIGTERM', abort)
  try {
    const kira = await import(input.kiraUrl)
    const { createGateCaptureHostPlugin } = await import(input.hostUrl)
    const tools = new Map(), services = new Map(), routes = new Map(), disposers = []
    const web = { get: name => name === 'webServer' ? { register: route => { routes.set(route.path, route.handler); return () => routes.delete(route.path) } }
      : name === 'connection' ? { requestRejection: () => false } : undefined,
    effect: create => { const dispose = create(); if (typeof dispose === 'function') disposers.push(dispose); return dispose } }
    const ctx = { tools: { register: tool => tools.set(tool.name, tool) }, sessions: new Map(),
      on: () => () => {}, inject: (_names, mount) => mount(web), emit() {}, logger: { info() {}, warn() {} },
      effect: web.effect, provide: (name, value) => services.set(name, value), reflect: { get: name => services.get(name) } }
    try {
      await createGateCaptureHostPlugin({ platform: 'probe', preflight: async () => false,
        loadKira: async () => kira, loadAura: async () => ({}), loadCapture: async () => ({}), gateCall: async () => ({}) }).apply(ctx, input.config)
      if (input.action === 'remember') {
        const result = await tools.get('kira_remember').execute({ text: input.sentence }, {})
        return { remembered: result.remembered, ids: result.ids, index: result.index }
      }
      if (input.action === 'forget') {
        const handler = routes.get('/api/kira/memories/forget')
        if (!handler) fail('forget-route-unavailable')
        const request = Readable.from([JSON.stringify({ id: input.id })])
        request.method = 'POST'; request.url = '/api/kira/memories/forget'
        let result
        const response = { statusCode: 200, setHeader() {}, end: bytes => { result = JSON.parse(bytes) } }
        await handler(request, response)
        return { forgotten: result?.forgotten === true, removed: result?.openviking?.removed === true, status: response.statusCode }
      }
      const answer = await tools.get('kira_recall').execute({ text: input.lexical ? LEXICAL : QUESTION, ...(input.lexical ? { lexical: true } : {}) }, {})
      return { method: answer.remembered?.method, degraded: answer.remembered?.degraded === true,
        state: answer.remembered?.state, sentence: answer.snippets?.some(note => note.text === input.sentence) === true,
        ids: answer.snippets?.map(note => note.id), project: answer.project?.state }
    } finally { for (const dispose of disposers.reverse()) dispose() }
  } finally { try { await transport.close() } finally { process.removeListener('SIGTERM', abort) } }
}

export function validateHeldScratch(scratch, held) {
  const current = lstatSync(scratch), opened = fstatSync(held)
  if (!current.isDirectory() || current.dev !== opened.dev || current.ino !== opened.ino) fail('scratch-replaced')
}

export function fresh(input, scratch, held) {
  if (input.action !== 'cleanup') validateHeldScratch(scratch, held)
  const env = { ...process.env, AUKORA_ROOM_LOG: join(scratch, 'absent-room.log') }
  delete env.AUKORA_STATE; delete env.AUKORA_SUPPORT_ROOT
  return new Promise((resolveStep, reject) => {
    const child = fork(fileURLToPath(import.meta.url), ['--child'], { execArgv: [], env, cwd: input.release, stdio: ['ignore', 'ignore', 'ignore', 'ipc', held] })
    let timedOut = false, childFailed = false, killTimeout
    const stop = () => { child.kill('SIGTERM'); killTimeout ??= setTimeout(() => child.kill('SIGKILL'), 1000) }
    const timeout = setTimeout(() => { timedOut = true; stop() }, 120_000)
    let response
    child.once('message', value => { response = value })
    child.once('error', () => { childFailed = true; stop() })
    child.once('close', code => {
      clearTimeout(timeout); clearTimeout(killTimeout)
      const operationFinished = response?.finished === true && !childFailed
      if (timedOut) reject(Object.assign(new Error('child-timeout'), { code: 'kira.release-probe:child-timeout', operationFinished }))
      else if (childFailed || code !== 0 || !response?.result) reject(Object.assign(new Error('child-failed'), { code: response?.reason, operationFinished }))
      else resolveStep({ ...response.result, pid: child.pid })
    })
    try { child.send({ ...input, scratch }, error => { if (error) { childFailed = true; stop() } }) }
    catch { childFailed = true; stop() }
  })
}

function journalInput(loaded, scratch, saved) {
  if (!saved || typeof saved !== 'object' || typeof saved.sentence !== 'string') fail('cleanup-journal-invalid')
  const { run, sentence, user, account, url, uri } = saved
  const hash = createHash('sha256').update(sentence).digest('hex')
  if (!/^[0-9a-f-]{36}$/u.test(run) || !/^[a-zA-Z0-9_-]{1,64}$/u.test(user)
    || !/^[a-zA-Z0-9_-]{1,64}$/u.test(account) || typeof url !== 'string'
    || sentence !== `Scarlet bicycle ${run} parked beneath maple foliage.`
    || uri !== `viking://user/${user}/memories/kira-release-probe/${run}/content/${hash}.md`
    || saved.release !== loaded.release) fail('cleanup-journal-invalid')
  return { ...loaded, scratch, run, sentence, user, account, url, uri }
}

function scratchJournal(scratch, held, saved) {
  const restore = bindScratchIO(scratch, held)
  try {
    const path = join(scratch, JOURNAL)
    if (saved) { const fd = fs.openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600)
      try { fs.writeFileSync(fd, `${JSON.stringify(saved)}\n`); fs.fsyncSync(fd) } finally { fs.closeSync(fd) }
      fs.fsyncSync(held); return saved
    }
    return JSON.parse(fs.readFileSync(path, 'utf8'))
  } finally { restore() }
}

function clearScratch(scratch, held) {
  const restore = bindScratchIO(scratch, held)
  const remove = path => {
    const info = fs.lstatSync(path)
    if (info.isDirectory()) { for (const name of fs.readdirSync(path)) remove(join(path, name)); fs.rmdirSync(path) }
    else fs.unlinkSync(path)
  }
  try {
    for (const name of fs.readdirSync(scratch).filter(name => name !== JOURNAL)) remove(join(scratch, name))
    fs.fsyncSync(held); remove(join(scratch, JOURNAL)); fs.fsyncSync(held)
  }
  finally { restore() }
}

export function acquireScratch(scratch, realState, { cleanup = false } = {}) {
  if (!isAbsolute(scratch)) fail('scratch-not-absolute')
  validateScratch(scratch, realState, { cleanup: true })
  let held
  try { held = openSync(scratch, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY) }
  catch { fail('scratch-not-directory') }
  try {
    const path = validateScratch(scratch, realState, { cleanup: true }), info = fstatSync(held)
    validateHeldScratch(path, held)
    if (info.uid !== process.getuid()) fail('scratch-not-owned')
    if ((info.mode & 0o077) !== 0) fail('scratch-not-private')
    if (!cleanup) {
      const restore = bindScratchIO(path, held)
      try { if (fs.readdirSync(path).length !== 0) fail('scratch-not-empty') } finally { restore() }
    }
    return { path, held }
  } catch (error) { closeSync(held); throw error }
}

export async function probeRelease({ release: selected, scratch, cleanup = false }) {
  let saved, acquired
  // The scratch directory is held by descriptor and every path beneath it is resolved through /proc/self/fd, so a
  // swapped directory cannot redirect a write. Without /proc there is no equally strict way; this is a node tool.
  if (process.platform !== 'linux') return { unperformed: 'this probe runs on a Linux node (descriptor-anchored scratch needs /proc/self/fd)', steps: [] }
  if (cleanup) {
    acquired = acquireScratch(scratch, '/nonexistent-release-probe-real-state', { cleanup: true })
    try { saved = scratchJournal(acquired.path, acquired.held); selected = saved.release }
    catch (error) { closeSync(acquired.held); throw error }
  }
  let loaded, config
  try {
    loaded = await readReleaseConfig(selected)
    const rawState = loaded.config.memoryOwner.stateDir
    acquired ??= acquireScratch(scratch, rawState)
    if (!loaded.config.openVikingHome) { closeSync(acquired.held); return { unperformed: 'release has no OpenViking home configured', steps: [] } }
    const { readConfig } = await import(loaded.kiraUrl)
    const effective = readConfig(loaded.config)
    validateScratch(acquired.path, effective.memoryOwner.stateDir, { cleanup: true })
    validateHeldScratch(acquired.path, acquired.held)
    config = { ...loaded.config, memoryOwner: { ...loaded.config.memoryOwner,
      subject: effective.memoryOwner.subject, stateDir: acquired.path } }
  } catch (error) { if (acquired) closeSync(acquired.held); throw error }
  const { path, held } = acquired
  const steps = [], report = { steps, ok: false }
  let input, needsCleanup = false, ambiguousWrite = false
  const step = async (name, action, check) => {
    try { const result = await fresh({ ...input, ...action }, path, held); steps.push({ name, ok: check(result), ...result }); return result }
    catch (error) {
      if (action.action === 'remember') ambiguousWrite = error.operationFinished !== true
      steps.push({ name, ok: false, reason: codeOf(error) }); return null
    }
  }
  try {
    if (cleanup) { input = journalInput({ ...loaded, config }, path, saved); needsCleanup = true }
    else {
      const available = await fresh({ ...loaded, config, action: 'preflight' }, path, held)
      if (!available.ok) return { unperformed: available.reason === 'openviking-unreachable'
        ? 'OpenViking unreachable (openviking-unreachable)' : 'OpenViking unavailable (bridge configuration or health)', steps: [] }
      const bridge = await import(loaded.bridgeUrl), bridgeConfig = bridge.readBridgeConfig(config.openVikingHome)
      if (!bridgeConfig.configured) fail('bridge-configuration-unavailable')
      const run = randomUUID(), sentence = `Scarlet bicycle ${run} parked beneath maple foliage.`
      const hash = createHash('sha256').update(sentence).digest('hex'), { user, account, url } = bridgeConfig
      saved = { release: loaded.release, run, sentence, user, account, url, uri: `viking://user/${user}/memories/kira-release-probe/${run}/content/${hash}.md` }
      input = journalInput({ ...loaded, config }, path, scratchJournal(path, held, saved))
      needsCleanup = true
      const remembered = await step('remember', { action: 'remember' }, result => result.remembered === 1 && result.ids?.length === 1)
      await step('semantic-recall', { action: 'recall' }, result => result.method === 'openviking-semantic' && result.degraded === false && result.sentence)
      await step('lexical-recall', { action: 'recall', lexical: true }, result => result.method === 'lexical-bm25-bigram' && result.degraded === false && result.sentence)
      await step('forget', { action: 'forget', id: remembered?.ids?.[0] }, result => result.forgotten && result.removed && result.status === 200)
      await step('absent-semantic', { action: 'recall' }, result => result.method === 'openviking-semantic' && result.degraded === false && result.state === 'empty' && !result.sentence)
      await step('absent-lexical', { action: 'recall', lexical: true }, result => result.method === 'lexical-bm25-bigram' && result.degraded === false && result.state === 'empty' && !result.sentence)
      report.ok = steps.every(row => row.ok)
    }
  } finally {
    try {
      if (needsCleanup) {
        let confirmed = false
        try { confirmed = (await fresh({ ...input, action: 'cleanup' }, path, held)).cleaned === true } catch {}
        if (confirmed && !ambiguousWrite) { try { clearScratch(path, held); if (cleanup) report.ok = true } catch { confirmed = false } }
        if (!confirmed || ambiguousWrite) { report.ok = false; report.cleanupIncomplete = saved.uri }
      }
    } finally { closeSync(held) }
  }
  return report
}

if (isMainModule(import.meta.url)) {
  if (process.argv[2] === '--child' && process.send) {
    process.once('message', async input => {
      try { const result = await childStep(input); process.send({ result, finished: true }, () => process.disconnect()) }
      catch (error) { process.exitCode = 1; process.send({ failed: true, reason: codeOf(error), finished: true }, () => process.disconnect()) }
    })
  } else {
    try {
      const report = await probeRelease(probeArgs(process.argv.slice(2)))
      if (report.unperformed) { process.stdout.write(`UNPERFORMED: ${report.unperformed}\n`); process.exitCode = 2 }
      else {
        for (const row of report.steps) process.stdout.write(`${row.ok ? 'PASS' : 'FAIL'} ${row.name}: ${row.reason ?? (row.method
          ? `method=${row.method} degraded=${row.degraded} sentence=${row.sentence}` : row.name === 'remember'
            ? `remembered=${row.remembered}` : `forgotten=${row.forgotten} index-removed=${row.removed}`)} process=${row.pid ?? 'unavailable'}\n`)
        const passed = report.steps.filter(row => row.ok).length
        process.stdout.write(`kira-release-recall-probe: ${passed} passed, ${report.steps.length - passed} failed\n`)
        if (report.cleanupIncomplete) process.stderr.write(`CLEANUP INCOMPLETE: ${report.cleanupIncomplete}\n`)
        process.exitCode = report.cleanupIncomplete ? 3 : report.ok ? 0 : 1
      }
    } catch (error) { process.stderr.write(`FAIL configuration: ${codeOf(error)}\nkira-release-recall-probe: FAIL\n`); process.exitCode = 1 }
  }
}
