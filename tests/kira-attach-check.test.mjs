#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic release attachment counts preserve source bytes and refuse output data.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { closeSync, constants, cpSync, ftruncateSync, chmodSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, symlinkSync, linkSync, writeFileSync } from 'node:fs'
import { createRequire, registerHooks, syncBuiltinESMExports } from 'node:module'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const toolFile = join(root, 'scripts/kira/attach-check.mjs')
const originalUmask = process.umask(0o002)
const work = mkdtempSync(join(root, 'tests/.attach-check-'))
const subject = `aukora:1:${'42'.repeat(32)}`
const sentinel = 'Synthetic attachment private wording should never leave this copied memory object.'
const workspace = '/synthetic/observatory', elsewhere = '/synthetic/other-project'
const hash = text => createHash('sha256').update(text).digest('hex')
const legacy = `project:${hash(workspace + '/.git')}`, otherLegacy = `project:${hash(elsewhere)}`
const mutations = {
  'release-absolute': ["if (!isAbsolute(argv[0])) fail('release-not-absolute')", 'void 0'],
  'scratch-absolute': ["if (!isAbsolute(argv[2])) fail('scratch-not-absolute')", 'void 0'],
  'source-readonly': ['const root = openSync(source, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)', 'const root = openSync(source, constants.O_RDWR | constants.O_DIRECTORY | constants.O_NOFOLLOW)'],
  'source-no-follow': ['constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK', 'constants.O_RDONLY | constants.O_NONBLOCK'],
  'source-regular': ["if (!info.isFile() || info.nlink !== 1) fail('source-entry-invalid')", "if (!info.isFile()) fail('source-entry-invalid')"],
  'source-bounds': ["if (info.size > MAX_FILE || bytes + info.size > MAX_COPY) fail('source-too-large')", 'void 0'],
  'draft-refusal': [" && row.after.mappingStatus !== 'draft'", ''],
  'scope-refusal': ['row.after.mappedScopeDropped === 0', 'true'],
  'output-reasons': ["REASONS.has(reason) ? reason : 'unclassified-refusal'", 'reason'],
  'source-changed': ["if (data.length !== info.size || !same(info, fstatSync(input), fileFields)) fail('source-changed')", 'void 0'],
  'source-replaced': ["if (!same(fstatSync(fd), before, identityFields) || !same(lstatSync(path), before, identityFields)) fail('source-replaced')", 'void 0'],
  'network-refusal': ["globalThis.fetch = async () => fail('network-disabled')", 'globalThis.fetch = globalThis.fetch'],
}
const mutant = process.env.KIRA_ATTACH_MUTANT
let mutated = 0
const hook = registerHooks({ load(url, context, next) {
  const loaded = next(url, context)
  if (!mutant || url !== pathToFileURL(toolFile).href) return loaded
  const source = String(loaded.source), [before, after] = mutations[mutant]
  assert.ok(source.includes(before), 'production mutation site exists')
  mutated++
  return { ...loaded, source: source.replaceAll(before, after) }
} })
const tool = await import(pathToFileURL(toolFile).href)
const { createTrackedMemory } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
let passed = 0
const check = async (name, run) => { await run(); passed++; console.log(`PASS ${name}`) }
const empty = name => { const path = join(work, name); mkdirSync(path, { recursive: true, mode: 0o700 }); return path }
const held = path => openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
const refused = (fn, code) => assert.throws(fn, error => error.code === `kira.attach-check:${code}` || error.code === `kira.release-probe:${code}`)
const snapshot = path => Object.fromEntries(readdirSync(path).sort().flatMap(name => {
  const file = join(path, name), stat = lstatSync(file)
  return stat.isDirectory() ? Object.entries(snapshot(file)).map(([child, digest]) => [name + '/' + child, digest]) : [[name, hash(readFileSync(file))]]
}))
function releaseFixture(stateDir, mapping) {
  const release = empty('release')
  for (const path of ['plugins/aukora-kira', 'plugins/aukora-aumlok', 'vendor/aukora-packages', 'vendor/authority', 'packages/contracts'])
    cpSync(join(root, path), join(release, path), { recursive: true, dereference: true })
  const entry = join(release, 'plugins/aukora-kira/lib/index.js')
  writeFileSync(entry, readFileSync(entry, 'utf8').replace('export async function apply(ctx, config, gateCaptureHost, browserMemory)', 'async function originalApply(ctx, config, gateCaptureHost, browserMemory)')
    + `\nexport async function apply(...args) { await originalApply(...args); try { await globalThis.fetch('http://127.0.0.1:1/synthetic', { method: 'POST', body: ${JSON.stringify(sentinel)} }) } catch {} }\n`)
  writeFileSync(join(release, 'package.json'), '{"type":"module"}\n')
  for (const path of ['vendor/include/lib', 'vendor/loader/lib', 'packages/util/home-paths/lib', 'node_modules/js-yaml'])
    mkdirSync(join(release, path), { recursive: true, mode: 0o700 })
  writeFileSync(join(release, 'vendor/include/lib/index.js'), 'export const entryListSchema = {}; export const applyEntryPatches = (_, rows) => rows;\n')
  writeFileSync(join(release, 'vendor/loader/lib/index.js'), 'export const interpolate = (_, value) => value;\n')
  writeFileSync(join(release, 'packages/util/home-paths/lib/index.js'), 'export const dshHomePath = (...parts) => parts.join("/");\n')
  writeFileSync(join(release, 'node_modules/js-yaml/package.json'), '{"name":"js-yaml","main":"index.cjs"}\n')
  writeFileSync(join(release, 'node_modules/js-yaml/index.cjs'), 'exports.load = JSON.parse;\n')
  const config = { retrieval: 'lexical', memoryOwner: { stateDir, subject, permittedPrivacy: ['local'] }, projectIdentity: mapping,
    openVikingHome: empty('openviking') }
  writeFileSync(join(config.openVikingHome, 'aukora-bridge.json'), JSON.stringify({ url: 'http://127.0.0.1:1', allowRemoteModels: true }))
  writeFileSync(join(config.openVikingHome, 'root.key'), 'synthetic-credential-only')
  writeFileSync(join(release, 'aukora-composition.patch.yml'), JSON.stringify([{ id: 'aukora-kira', name: './plugins/aukora-kira/lib/gate-capture-host.mjs', config }]))
  return { release, config, kiraUrl: pathToFileURL(join(release, 'plugins/aukora-kira/lib/index.js')).href,
    hostUrl: pathToFileURL(join(release, 'plugins/aukora-kira/lib/gate-capture-host.mjs')).href }
}

try {
  await check('arguments and source/scratch separation refuse unsafe destinations', async () => {
    assert.deepEqual(tool.attachArgs(['/release', '--scratch-copy', '/scratch']), { release: '/release', scratch: '/scratch' })
    refused(() => tool.attachArgs(['relative', '--scratch-copy', '/scratch']), 'release-not-absolute')
    refused(() => tool.attachArgs(['/release', '--scratch-copy', 'relative']), 'scratch-not-absolute')
    refused(() => tool.attachArgs(['/release']), 'usage')
    const source = empty('overlap/source'), ancestor = dirname(source), fd = held(ancestor)
    try { refused(() => tool.copyNoteStore(source, ancestor, fd), 'scratch-not-empty') } finally { closeSync(fd) }
    const inside = empty('overlap/source/child'), insideFd = held(inside)
    try { refused(() => tool.copyNoteStore(source, inside, insideFd), 'scratch-real-state') } finally { closeSync(insideFd) }
  })
  await check('copied state rejects symbolic links, hard links and oversized source files', async () => {
    for (const kind of ['symbolic', 'hard', 'oversized']) {
      const source = empty('unsafe-' + kind), notes = empty('unsafe-' + kind + '/remembered'), scratch = empty('copy-' + kind)
      const outside = join(work, kind + '-outside'); writeFileSync(outside, sentinel)
      const file = join(notes, 'slot.json')
      if (kind === 'symbolic') symlinkSync(outside, file)
      else if (kind === 'hard') linkSync(outside, file)
      else { const oversized = openSync(file, 'wx', 0o600); try { ftruncateSync(oversized, 64 * 1024 * 1024 + 1) } finally { closeSync(oversized) } }
      const fd = held(scratch)
      try { refused(() => tool.copyNoteStore(source, scratch, fd), kind === 'symbolic' ? 'source-entry-unavailable'
        : kind === 'hard' ? 'source-entry-invalid' : 'source-too-large') } finally { closeSync(fd) }
    }
  })
  await check('source changes and replaced parents refuse a mixed copy', () => {
    const fs = createRequire(import.meta.url)('node:fs'), originalRead = fs.readFileSync, originalList = fs.readdirSync
    for (const kind of ['changed', 'replaced']) {
      const source = empty('race-' + kind), notes = empty('race-' + kind + '/remembered'), scratch = empty('race-copy-' + kind)
      const file = join(notes, 'slot.json'); writeFileSync(file, '{}')
      const fd = held(scratch)
      let touched = false
      try {
        if (kind === 'changed') fs.readFileSync = (...args) => {
          const result = originalRead(...args)
          if (!touched && typeof args[0] === 'number') { touched = true; writeFileSync(file, '{} changed') }
          return result
        }
        else fs.readdirSync = (...args) => {
          const result = originalList(...args)
          if (!touched && result.includes('slot.json')) {
            touched = true
            fs.renameSync(notes, notes + '-moved'); mkdirSync(notes, { mode: 0o700 })
          }
          return result
        }
        syncBuiltinESMExports()
        refused(() => tool.copyNoteStore(source, scratch, fd), kind === 'changed' ? 'source-changed' : 'source-replaced')
        assert.equal(touched, true, 'synthetic source race must occur')
      } finally { fs.readFileSync = originalRead; fs.readdirSync = originalList; syncBuiltinESMExports(); closeSync(fd) }
    }
  })
  await check('untrusted reason labels and notes are reduced to counts only', () => {
    const summary = tool.countSummary({ eligibleRecords: 4, memory: { dropped: 2, reasons: { [sentinel]: 1, 'scope-not-attached': 1 } },
      snippets: [{ text: sentinel, subject, key: sentinel }] })
    assert.deepEqual(summary, { eligible: 4, dropped: 2, reasons: { 'unclassified-refusal': 1, 'scope-not-attached': 1 } })
    assert.ok(!JSON.stringify(summary).includes(sentinel)); assert.ok(!JSON.stringify(summary).includes(subject))
    const output = tool.attachmentLines({ copied: 2, ok: true, rows: [{ project: 1, workspace: 1,
      before: { ...summary, mappedScopeDropped: 1 }, after: { ...summary, mappedScopeDropped: 0 } }] }).join('\n')
    assert.ok(!output.includes(sentinel)); assert.ok(!output.includes(subject))
  })
  await check('mapped scope failures and unreviewed aliases cannot pass the release check', () => {
    const row = after => [{ after }]
    assert.equal(tool.attachmentSucceeded([]), false)
    assert.equal(tool.attachmentSucceeded(row({ mappedScopeDropped: 0, mappingStatus: 'owner-reviewed' })), true)
    assert.equal(tool.attachmentSucceeded(row({ mappedScopeDropped: 1, mappingStatus: 'owner-reviewed' })), false)
    assert.equal(tool.attachmentSucceeded(row({ mappedScopeDropped: 0, mappingStatus: 'draft' })), false)
  })
  const state = empty('real-node/kira-memory'), memory = createTrackedMemory({ stateDir: state, subject })
  const ownIds = []
  for (let index = 0; index < 4; index++) ownIds.push((await memory.remember({ text: `${sentinel} Synthetic own observation ${index}.`, scope: legacy })).ids[0])
  await memory.remember({ text: `${sentinel} Synthetic unrelated project observation.`, scope: otherLegacy })
  await memory.remember({ text: `${sentinel} Synthetic owner observation.`, scope: 'owner' })
  const damaged = join(state, 'remembered', ownIds[2].slice(4) + '.json'), note = JSON.parse(readFileSync(damaged, 'utf8'))
  note.statement += ' Synthetic changed bytes.'; writeFileSync(damaged, JSON.stringify(note))
  rmSync(join(state, 'remembered', ownIds[3].slice(4) + '.json'))
  const map = { version: 1, projects: [{ project_id: 'observatory', workspace_roots: [workspace] }, { project_id: 'other', workspace_roots: [elsewhere] }],
    alias_table: { version: 1, status: 'owner-reviewed', review_id: 'synthetic-review', entries: [
      { legacy_scope: legacy, project_id: 'observatory', record_ids: ownIds },
    ] } }
  const loaded = releaseFixture(state, map), scratch = empty('synthetic-recall-copy'), fd = held(scratch), prior = snapshot(state)
  try {
    await check('source opens stay read-only and copied files stay private under umask 002', () => {
      const fs = createRequire(import.meta.url)('node:fs'), originalOpen = fs.openSync
      let sourceOpened = false
      fs.openSync = (path, flags, mode) => {
        if (path === state) { sourceOpened = true; assert.equal(flags & (constants.O_WRONLY | constants.O_RDWR), constants.O_RDONLY, 'source root must open read-only') }
        return originalOpen(path, flags, mode)
      }
      syncBuiltinESMExports()
      try { tool.copyNoteStore(state, scratch, fd) } finally { fs.openSync = originalOpen; syncBuiltinESMExports() }
      assert.equal(sourceOpened, true)
      const checkModes = path => {
        assert.equal(lstatSync(path).mode & 0o777, 0o700)
        for (const name of readdirSync(path)) { const file = join(path, name), info = lstatSync(file)
          if (info.isDirectory()) checkModes(file); else assert.equal(info.mode & 0o777, 0o600) }
      }
      checkModes(scratch)
    })
    const config = { ...loaded.config, memoryOwner: { ...loaded.config.memoryOwner, stateDir: scratch } }
    const before = { ...config, projectIdentity: { version: 1, projects: map.projects } }
    const originalState = process.env.AUKORA_STATE, originalSupport = process.env.AUKORA_SUPPORT_ROOT, originalFetch = globalThis.fetch
    delete process.env.AUKORA_STATE; delete process.env.AUKORA_SUPPORT_ROOT
    let networkRequests = 0
    globalThis.fetch = async () => { networkRequests++; throw new Error(sentinel) }
    try {
      await check('copied release Kira issues real governed recalls and keeps other projects detached', async () => {
        const input = { ...loaded, workspace, config, legacyScopes: [legacy] }
        const previous = await tool.recallAttachment({ ...input, config: before })
        const current = await tool.recallAttachment(input)
        assert.equal(previous.eligible, 1); assert.equal(previous.mappedScopeDropped, 2)
        assert.equal(current.eligible, 3); assert.equal(current.mappedScopeDropped, 0)
        assert.equal(current.reasons['scope-not-attached'], 1, 'the unrelated project stays detached')
        assert.equal(current.reasons['content-hash-mismatch'], 1); assert.equal(current.reasons['missing-object'], 1)
        const draft = { ...config, projectIdentity: { ...map, alias_table: { ...map.alias_table, status: 'draft' } } }
        const heldBack = await tool.recallAttachment({ ...input, config: draft })
        assert.equal(heldBack.eligible, 1); assert.equal(heldBack.mappedScopeDropped, 2)
        assert.equal(tool.attachmentSucceeded([{ after: heldBack }]), false)
        assert.equal(networkRequests, 0, 'no fetch may escape the scratch recall')
        assert.deepEqual(snapshot(state), prior, 'source note bytes remain untouched')
        assert.ok(!JSON.stringify(current).includes(sentinel)); assert.ok(!JSON.stringify(current).includes(subject))
      })
    } finally {
      globalThis.fetch = originalFetch
      if (originalState === undefined) delete process.env.AUKORA_STATE; else process.env.AUKORA_STATE = originalState
      if (originalSupport === undefined) delete process.env.AUKORA_SUPPORT_ROOT; else process.env.AUKORA_SUPPORT_ROOT = originalSupport
    }
  } finally { closeSync(fd) }
  await check('actual CLI reports its descriptor availability and never emits synthetic note data', async () => {
    const dest = empty('cli-copy'), env = { ...process.env }
    delete env.NODE_TEST_CONTEXT; delete env.AUKORA_STATE; delete env.AUKORA_SUPPORT_ROOT
    const run = spawnSync(process.execPath, [toolFile, loaded.release, '--scratch-copy', dest], { encoding: 'utf8', env, timeout: 20_000 })
    if (process.platform === 'linux') {
      assert.equal(run.status, 1, run.stderr)
      assert.match(run.stdout, /project=1 workspace=1 after: eligible=3/u)
      assert.match(run.stdout, /project=2 workspace=1 after:.*mapped-scope-dropped=1/u)
      assert.deepEqual(snapshot(state), prior)
    } else { assert.equal(run.status, 2); assert.match(run.stdout, /UNPERFORMED:.*Linux/u) }
    assert.ok(!run.stdout.includes(sentinel)); assert.ok(!run.stderr.includes(sentinel))
    assert.ok(!run.stdout.includes(subject)); assert.ok(!run.stderr.includes(subject))
  })
  if (mutant) assert.equal(mutated, 1)
  if (!mutant) for (const name of ['release-absolute', 'scratch-absolute', 'source-readonly', 'source-no-follow', 'source-regular', 'source-bounds', 'draft-refusal', 'scope-refusal', 'output-reasons', 'source-changed', 'source-replaced', 'network-refusal']) {
    const env = { ...process.env, KIRA_ATTACH_MUTANT: name }; delete env.NODE_TEST_CONTEXT
    const run = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], { encoding: 'utf8', env, timeout: 20_000 })
    assert.equal(run.status, 1, `mutation ${name} must fail`)
    assert.match(run.stderr, /AssertionError/u, `mutation ${name} must fail an assertion`)
    console.log(`MUTATION ${name}: CAUGHT`)
  }
  console.log(`kira-attach-check: ${passed} passed, 0 failed${process.platform === 'linux' ? '' : '; Linux descriptor CLI UNPERFORMED'}`)
} finally { hook.deregister(); rmSync(work, { recursive: true, force: true }); process.umask(originalUmask) }
