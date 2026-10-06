#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Mounted Kira read-time aliases through the actual pinned DSH registry.
 * Synthetic files are retained under a private per-user temporary parent.
 * No installed state, credentials, provider calls, or process restart is used.
 * --mutant read-context-decorator removes the production alias decoration in
 * memory; the unchanged mounted acceptance assertions must then fail. */
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { createHash } from 'node:crypto'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const option = name => {
  const at = process.argv.indexOf(name)
  return at === -1 ? undefined : process.argv[at + 1]
}
const mutant = option('--mutant')
assert.ok(mutant === undefined || mutant === 'read-context-decorator', 'unknown removal control')
let mutationApplied = 0
if (mutant) {
  const target = pathToFileURL(join(ROOT, 'plugins/aukora-kira/lib/project-identity.mjs')).href
  const guard = 'return approvedScopeAliases.contextFor(context)'
  registerHooks({ load(url, context, nextLoad) {
    const loaded = nextLoad(url, context)
    if (url !== target) return loaded
    const source = String(loaded.source)
    assert.equal(source.split(guard).length - 1, 1, 'removal control must match one production decoration')
    mutationApplied++
    return { ...loaded, source: source.replace(guard, 'return context') }
  } })
}

const dsh = option('--dsh') ?? process.env.AUKORA_DSH_SOURCE
const unperformed = reason => { process.stderr.write(`UNPERFORMED: ${reason}\n`); process.exit(2) }
if (typeof dsh !== 'string' || dsh === '' || !existsSync(dsh))
  unperformed('set --dsh or AUKORA_DSH_SOURCE to the allocated pinned build')
const dshRoot = realpathSync(dsh)
const toolsPath = join(dshRoot, 'packages/core/tools/lib/index.js')
const cordisPath = join(dshRoot, 'vendor/cordis/lib/index.js')
const agentPath = join(dshRoot, 'packages/core/agent/lib/index.js')
for (const file of [toolsPath, cordisPath, agentPath]) if (!existsSync(file))
  unperformed('required actual DSH built module absent')
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const pin = JSON.parse(readFileSync(join(ROOT, 'upstream-dsh.json'), 'utf8'))
assert.equal(sha(readFileSync(join(dshRoot, 'pnpm-lock.yaml'))), pin.lockfileSha256, 'actual DSH lock must match this candidate')
const build = JSON.parse(readFileSync(join(dshRoot, '.dsh-build/pinned-harness-build.json'), 'utf8'))
for (const field of ['commit', 'archiveSha256', 'lockfileSha256', 'packageManager'])
  assert.equal(build.inputs.upstream[field], pin[field], `actual DSH build ${field} differs from candidate pin`)
const buildPatches = new Map(build.inputs.localPatches.map(patch => [patch.file, patch.sha256]))
const missingPatches = pin.localPatches.filter(patch => buildPatches.get(patch.file) !== patch.sha256).map(patch => patch.file)
process.stdout.write(`SOURCE actual DSH base=${pin.commit}; ToolRuntime SHA256=${sha(readFileSync(toolsPath))}\n`)
process.stdout.write(`UNPERFORMED candidate complete-artifact qualification: declared patches=${pin.localPatches.length}, build receipt patches=${buildPatches.size}; missing=${missingPatches.join(',') || 'none'}\n`)

const temporaryParent = realpathSync(tmpdir()), uid = process.getuid?.()
const parentStat = lstatSync(temporaryParent)
if (uid === undefined || parentStat.uid !== uid || (parentStat.mode & 0o777) !== 0o700)
  unperformed('no allocated private per-user temporary parent')
for (let path = temporaryParent;; path = dirname(path)) {
  const stat = lstatSync(path)
  if ((stat.mode & 0o022) !== 0 || (stat.uid !== uid && stat.uid !== 0))
    unperformed('temporary ancestor is writable by another owner')
  if (dirname(path) === path) break
}
const fixture = mkdtempSync(join(temporaryParent, 'kira-scope-alias-dsh-'))
assert.equal(lstatSync(fixture).mode & 0o777, 0o700)
process.stdout.write(`SOURCE retained synthetic fixture=${fixture}; private parent verified; Linux protected-UID custody UNPERFORMED\n`)
const envKeys = ['AUKORA_STATE', 'AUKORA_SUPPORT_ROOT', 'AUKORA_OPENVIKING_HOME', 'AUKORA_ROOM_LOG', 'DSH_HOME']
const previousEnv = new Map(envKeys.map(key => [key, process.env[key]]))
process.env.AUKORA_STATE = fixture
process.env.AUKORA_SUPPORT_ROOT = fixture
process.env.AUKORA_OPENVIKING_HOME = join(fixture, 'absent-synthetic-openviking')
process.env.AUKORA_ROOM_LOG = join(fixture, 'synthetic-empty-room.log')
process.env.DSH_HOME = fixture
writeFileSync(process.env.AUKORA_ROOM_LOG, '', { mode: 0o600, flag: 'wx' })
const priorFetch = globalThis.fetch
let networkCalls = 0
globalThis.fetch = async () => { networkCalls++; throw new Error('synthetic fixture prohibits provider/network calls') }

let passed = 0, total = 0, call = 0
const mountedContexts = []
async function arm(name, run) {
  total++
  try { await run(); passed++; process.stdout.write(`PASS ${name}\n`) }
  catch (error) { process.stderr.write(`FAIL ${name}: ${error.message}\n`); process.exitCode = 1 }
}

try {
  const { Context } = await import(pathToFileURL(cordisPath).href)
  const { ToolRuntime, assertObjectJsonSchema, assertSupportedJsonSchema, validateJsonSchemaValue } = await import(pathToFileURL(toolsPath).href)
  const { agentEvents } = await import(pathToFileURL(agentPath).href)
  const { apply } = await import('../plugins/aukora-kira/lib/index.js')
  const { createTrackedMemory } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
  const subject = `aukora:1:${'67'.repeat(32)}`
  const OLD = 'project:982deb07dba176b9f2b8bccaffec69e2f3f6421e13c993374edf9e226da1e45c'
  const TARGET = 'project:ed9da107b1a136deb7876daa6602e67ade729ad169f5f2c4bbfd79745ce2c74b'
  const OTHER = `project:${'41'.repeat(32)}`
  const STABLE = 'project:id:synthetic-project'
  const stateDir = join(fixture, 'kira-memory'), workspace = join(fixture, 'synthetic-workspace')
  mkdirSync(stateDir, { mode: 0o700 }); mkdirSync(workspace, { mode: 0o700 })
  const store = createTrackedMemory({ stateDir, subject, config: { configured: false } })
  const markers = ['APPROVED-OLD-RECORD', 'CURRENT-TARGET-RECORD', 'OTHER-PROJECT-RECORD', 'STABLE-IDENTITY-RECORD']
  const scopes = [OLD, TARGET, OTHER, STABLE]
  const notes = []
  for (const [index, scope] of scopes.entries()) {
    const saved = await store.remember({ text: `The calibration archive retains ${markers[index]}.`,
      from: 'synthetic-test', scope, at: new Date().toISOString() }, { attributedTo: 'owner' })
    assert.equal(saved.remembered, 1, 'synthetic source note must be durably stored')
    notes.push(saved.notes[0])
  }
  const sourceFiles = new Map(notes.map(note => {
    const file = join(stateDir, 'remembered', `${note.id.slice(4)}.json`)
    return [file, readFileSync(file)]
  }))
  const review = { version: 1, status: 'owner-reviewed', review_id: 'synthetic-mount-of-approved-exact-pair',
    entries: [{ from_scope: OLD, to_scope: TARGET }] }
  const baseConfig = { memoryOwner: { stateDir, subject, permittedPrivacy: ['local'] },
    projectIdentity: { version: 1, projects: [{ project_id: 'synthetic-project', workspace_roots: [workspace] }] } }

  async function mount({ alias = true, attached, selected = TARGET } = {}) {
    const ctx = new Context()
    mountedContexts.push(ctx)
    ctx.provide('systemPrompt', { tools: () => () => {}, section: () => () => {} })
    const runtime = new ToolRuntime(ctx, { mode: 'native' })
    const session = { id: `synthetic-session-${mountedContexts.length}`, header: { cwd: workspace } }
    const agent = { id: session.id, session, ctx, status: 'idle' }
    ctx.provide('sessions', { get: id => id === session.id ? session : undefined, flush: async () => true })
    const warnings = []
    const hostCtx = ctx.extend({ logger: { warn: message => warnings.push(message), info: () => {} } })
    let readScope = selected, reads = 0, selections = 0
    const host = attached === undefined ? undefined : {
      contextFor: supplied => { assert.equal(supplied?.session, session); reads++; return { attachedProjects: [...attached] } },
      scopeFor: supplied => { assert.equal(supplied?.session, session); selections++; return readScope },
    }
    await apply(hostCtx, { ...baseConfig, ...(alias ? { approvedScopeAliases: review } : {}) }, undefined, host)
    const definitions = runtime.view(undefined).visible
    assert.deepEqual([...definitions.keys()].sort(), ['kira_recall', 'kira_remember'])
    for (const definition of definitions.values()) {
      assertObjectJsonSchema(definition.parameters)
      assertSupportedJsonSchema(definition.output.schema)
    }
    const execute = async (name, args) => {
      const result = await runtime.execute({ callId: `synthetic-call-${++call}`, name, arguments: args,
        agent, signal: new AbortController().signal })
      if (result.isError && name === 'kira_recall') {
        const raw = await definitions.get(name).execute(args, { agent, signal: new AbortController().signal })
        const invalid = []
        const inspect = (value, path) => {
          if (value === undefined || ['function', 'symbol', 'bigint'].includes(typeof value)) invalid.push(path)
          else if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) inspect(child, `${path}.${key}`)
        }
        inspect(raw, 'value')
        process.stderr.write(`SOURCE output diagnosis: non-JSON paths=${invalid.join(',')}\n`)
      }
      assert.equal(result.isError, false, `actual DSH ${name} dispatch must succeed: ${JSON.stringify(result.error?.info ?? result.error ?? null)}; ${result.content?.find(part => part.type === 'text')?.text ?? ''}`)
      const definition = definitions.get(name)
      assert.deepEqual(validateJsonSchemaValue(definition.output.schema, result.value), [], 'actual DSH output validator must accept returned value')
      return result.value
    }
    const registeredRecallValue = args => definitions.get('kira_recall').execute(args, { agent, signal: new AbortController().signal })
    return { ctx, agent, session, execute, registeredRecallValue, warnings,
      select: scope => { readScope = scope }, counts: () => ({ reads, selections }) }
  }
  const ids = answer => (answer.snippets ?? []).map(note => note.recordId).sort()
  const expected = indices => indices.map(index => notes[index].id).sort()
  let good

  await arm('actual mounted DSH recall returns only old-to-already-attached target and current target', async () => {
    good = await mount({ attached: [TARGET] })
    // Source diagnostic only: this does not replace or normalize runtime.execute.
    // The complete registry pipeline below must independently accept its output.
    const raw = await good.registeredRecallValue({ text: 'calibration archive retains', lexical: true })
    assert.deepEqual(ids(raw), expected([0, 1]), 'production read decorator must expose the exact approved old scope')
    process.stdout.write('SOURCE actual registered callback resolves the exact approved pair; full runtime output qualification still required\n')
    const result = await good.execute('kira_recall', { text: 'calibration archive retains', lexical: true })
    assert.deepEqual(ids(result), expected([0, 1]), 'approved exact old scope must join the current attached target')
    assert.equal(result.grantsAuthority, false)
    assert.ok(result.memory.reasons['scope-not-attached'] > 0, 'other projects must retain named scope refusal')
    assert.ok(good.counts().reads > 0, 'mounted recall must call the direct trusted read context')
    for (const [file, bytes] of sourceFiles) assert.deepEqual(readFileSync(file), bytes, 'read-time alias must preserve canonical stored bytes')
  })
  await arm('actual mounted DSH reverse and detached targets retain refusal', async () => {
    const reverse = await mount({ attached: [OLD], selected: OLD })
    assert.deepEqual(ids(await reverse.execute('kira_recall', { text: 'calibration archive retains', lexical: true })), expected([0]))
    const detached = await mount({ attached: [] })
    const result = await detached.execute('kira_recall', { text: 'calibration archive retains', lexical: true })
    assert.deepEqual(ids(result), [])
    assert.ok(result.memory.reasons['scope-not-attached'] > 0)
  })
  await arm('alias configuration alone stays inactive and default stable identity remains unchanged', async () => {
    const configOnly = await mount()
    assert.deepEqual(ids(await configOnly.execute('kira_recall', { text: 'calibration archive retains', lexical: true })), expected([3]))
    const defaults = await mount({ alias: false })
    assert.deepEqual(ids(await defaults.execute('kira_recall', { text: 'calibration archive retains', lexical: true })), expected([3]))
  })
  await arm('actual pre-turn scope selection uses only host reads while capture retains stable identity', async () => {
    const run = await mount({ attached: [TARGET, OTHER] })
    run.select(OTHER)
    const decision = await agentEvents(run.ctx, run.agent).waterfall('agent/pre-step', {}, async () => ({
      kind: 'enter', messages: [{ role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text: markers[2] }] }],
    }))
    const injected = decision.messages.slice(1).flatMap(message => message.content ?? []).map(part => part.text ?? '').join('\n')
    assert.ok(injected.includes(markers[2]), `host-selected other project must reach pre-turn recall; warnings=${JSON.stringify(run.warnings)}; injected=${injected}`)
    assert.ok(!injected.includes(markers[0]) && !injected.includes(markers[1]), 'pre-turn selection must narrow the attached-project set')
    assert.ok(run.counts().selections > 0, 'actual pre-turn read must call the host selection callback')
    const captured = await run.execute('kira_remember', { text: 'The synthetic capture retains the stable identity.' })
    assert.equal(captured.remembered, 1)
    const saved = store.read().notes.find(note => note.id === captured.ids[0])
    assert.equal(saved.scope, STABLE, 'host read selection must not change capture scope')
  })
  await arm('stored historical note identity, original scope and bytes remain unchanged after all mounted reads', async () => {
    const reread = store.read().notes
    for (const [index, original] of notes.entries()) {
      const current = reread.find(note => note.id === original.id)
      assert.equal(current.scope, scopes[index]); assert.equal(current.statement, original.statement)
      assert.equal(current.contentHash, original.contentHash)
    }
    for (const [file, bytes] of sourceFiles) assert.deepEqual(readFileSync(file), bytes)
    assert.equal(networkCalls, 0, 'no provider or index requests may occur')
  })
  if (mutant) assert.equal(mutationApplied, 1, 'removal must execute in the actual mounted production module')
} finally {
  for (const ctx of mountedContexts.reverse()) await ctx.fiber._unload()
  globalThis.fetch = priorFetch
  for (const [key, value] of previousEnv) {
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
}
process.stdout.write(`${passed}/${total} mounted real-DSH functional groups; network calls=${networkCalls}; fixture retained; installed/staging organism qualification UNPERFORMED\n`)
