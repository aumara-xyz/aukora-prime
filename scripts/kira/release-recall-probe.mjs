#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise release Kira in fresh processes using a caller-owned scratch store.
import { fork } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { constants, closeSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isMainModule } from '../lib/is-main.mjs'

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
  if (argv.length !== 3 || argv[1] !== '--scratch-state') fail('usage')
  if (!isAbsolute(argv[0])) fail('release-not-absolute')
  if (!isAbsolute(argv[2])) fail('scratch-not-absolute')
  return { release: argv[0], scratch: argv[2] }
}

export function validateScratch(scratch, realState, { uid = process.getuid() } = {}) {
  if (typeof scratch !== 'string' || !isAbsolute(scratch)) fail('scratch-not-absolute')
  let info, path
  try { path = realpathSync(scratch); info = lstatSync(path) } catch { fail('scratch-not-directory') }
  if (!info.isDirectory()) fail('scratch-not-directory')
  if (info.uid !== uid) fail('scratch-not-owned')
  if ((info.mode & 0o077) !== 0) fail('scratch-not-private')
  if (within(path, canonical(resolve(realState)))) fail('scratch-real-state')
  if (readdirSync(path).length !== 0) fail('scratch-not-empty')
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

async function childStep(input) {
  if (input.action === 'preflight') {
    const { readBridgeConfig, createOpenVikingRecall } = await import(input.bridgeUrl)
    const config = readBridgeConfig(input.config.openVikingHome)
    if (!config.configured) return { ok: false, reason: 'bridge-configuration-unavailable' }
    const status = await createOpenVikingRecall({ config }).available()
    return { ok: status.ok, reason: status.ok ? null : status.reason }
  }
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
      return { remembered: result.remembered, ids: result.ids }
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
}

export function validateHeldScratch(scratch, held) {
  const current = lstatSync(scratch), opened = fstatSync(held)
  if (!current.isDirectory() || current.dev !== opened.dev || current.ino !== opened.ino) fail('scratch-replaced')
}

function fresh(input, scratch, held) {
  validateHeldScratch(scratch, held)
  const env = { ...process.env, AUKORA_ROOM_LOG: join(scratch, 'absent-room.log') }
  delete env.AUKORA_STATE; delete env.AUKORA_SUPPORT_ROOT
  return new Promise((resolveStep, reject) => {
    const child = fork(fileURLToPath(import.meta.url), ['--child'], { execArgv: [], env, cwd: input.release, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] })
    const timeout = setTimeout(() => { child.kill(); reject(Object.assign(new Error('child-timeout'), { code: 'kira.release-probe:child-timeout' })) }, 120_000)
    let response
    child.once('message', value => { response = value })
    child.once('error', () => { clearTimeout(timeout); reject(new Error('child-failed')) })
    child.once('exit', code => {
      clearTimeout(timeout)
      if (code !== 0 || !response?.result) reject(new Error('child-failed'))
      else resolveStep({ ...response.result, pid: child.pid })
    })
    child.send(input)
  })
}

export async function probeRelease({ release: selected, scratch }) {
  const loaded = await readReleaseConfig(selected)
  const rawState = loaded.config.memoryOwner.stateDir
  const path = validateScratch(scratch, rawState)
  if (!loaded.config.openVikingHome) return { unperformed: 'release has no OpenViking home configured', steps: [] }
  // Resolve the same existing deployment identity before replacing only the store path.
  const { readConfig } = await import(loaded.kiraUrl)
  const effective = readConfig(loaded.config)
  validateScratch(path, effective.memoryOwner.stateDir)
  const config = { ...loaded.config, memoryOwner: { ...loaded.config.memoryOwner,
    subject: effective.memoryOwner.subject, stateDir: path } }
  const input = { ...loaded, config, sentence: `Scarlet bicycle ${randomUUID()} parked beneath maple foliage.` }
  const held = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY)
  const steps = []
  const step = async (name, action, check) => {
    try { const result = await fresh({ ...input, ...action }, path, held); steps.push({ name, ok: check(result), ...result }); return result }
    catch (error) { steps.push({ name, ok: false, reason: codeOf(error) }); return null }
  }
  try {
    const available = await fresh({ ...input, action: 'preflight' }, path, held)
    if (!available.ok) return { unperformed: available.reason === 'openviking-unreachable'
      ? 'OpenViking unreachable (openviking-unreachable)' : 'OpenViking unavailable (bridge configuration or health)', steps: [] }
    const remembered = await step('remember', { action: 'remember' }, result => result.remembered === 1 && result.ids?.length === 1)
    await step('semantic-recall', { action: 'recall' }, result => result.method === 'openviking-semantic' && result.degraded === false && result.sentence)
    await step('lexical-recall', { action: 'recall', lexical: true }, result => result.method === 'lexical-bm25-bigram' && result.degraded === false && result.sentence)
    await step('forget', { action: 'forget', id: remembered?.ids?.[0] }, result => result.forgotten && result.removed && result.status === 200)
    await step('absent-semantic', { action: 'recall' }, result => result.method === 'openviking-semantic' && result.degraded === false && result.state === 'empty' && !result.sentence)
    await step('absent-lexical', { action: 'recall', lexical: true }, result => result.method === 'lexical-bm25-bigram' && result.degraded === false && result.state === 'empty' && !result.sentence)
    return { steps, ok: steps.every(row => row.ok) }
  } finally { closeSync(held) }
}

if (isMainModule(import.meta.url)) {
  if (process.argv[2] === '--child' && process.send) {
    process.once('message', async input => {
      try { const result = await childStep(input); process.send({ result }, () => process.disconnect()) }
      catch { process.exitCode = 1; process.send({ failed: true }, () => process.disconnect()) }
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
        process.exitCode = report.ok ? 0 : 1
      }
    } catch (error) { process.stderr.write(`FAIL configuration: ${codeOf(error)}\nkira-release-recall-probe: FAIL\n`); process.exitCode = 1 }
  }
}
