// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-path consistency/security regressions over the carried tool registry, action gate, grep body,
// local subprocess provider and packaged ripgrep. Only synthetic files change.
// An exposed canary is a FAILURE, never an accepted window or containment PASS.
// Run directly with `node` to preserve UNPERFORMED exit 2 when vendor/dsh is
// absent. --dsh-root <absolute path> selects a local materialization; its module
// hashes are printed. This does not establish an installed/current DSH build.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import test from 'node:test'
import * as ActionGate from '../plugins/aukora-action-gate/lib/index.mjs'

const supplied = process.argv.slice(2)
if (supplied.length !== 0 && (supplied.length !== 2 || supplied[0] !== '--dsh-root' || !isAbsolute(supplied[1]))) {
  throw new Error('expected only --dsh-root <absolute path>')
}
const dshRoot = supplied[1] ?? fileURLToPath(new URL('../vendor/dsh', import.meta.url))
const paths = {
  tools: 'packages/core/tools/lib/index.js',
  prompt: 'packages/core/system-prompt/lib/index.js',
  subprocess: 'packages/subprocess/subprocess-local/lib/index.js',
  search: 'packages/fs/tool-fs-search/lib/index.js',
}
const missing = Object.values(paths).filter(path => !existsSync(join(dshRoot, path)))
if (missing.length !== 0) {
  console.error(`UNPERFORMED: carried DSH modules unavailable: ${missing.join(', ')}`)
  process.exit(2)
}
const requireDsh = createRequire(join(dshRoot, 'packages/core/tools/package.json'))
const { Context } = await import(pathToFileURL(requireDsh.resolve('@deepseek-ai/cordis')).href)
const loaded = await Promise.all(Object.values(paths).map(path => import(pathToFileURL(join(dshRoot, path)).href)))
const [{ default: ToolRuntime }, { default: SystemPrompt }, { default: LocalSubprocessRuntime }, ToolFsSearch] = loaded
for (const [role, path] of Object.entries(paths)) {
  console.log(`SOURCE module ${role} sha256=${createHash('sha256').update(readFileSync(join(dshRoot, path))).digest('hex')}`)
}

const publicCanary = 'SEARCH_CANARY_PUBLIC'
const secretCanary = 'SEARCH_CANARY_SYNTHETIC_SECRET'
let callId = 0

async function fixture(t, { executionRecheck = false, swapAfterAllow = false } = {}) {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'aukora-search-race-'))
  const workspace = join(root, 'workspace')
  const target = join(workspace, 'search')
  const replacement = join(root, 'replacement')
  for (const path of [target, replacement]) mkdirSync(path, { recursive: true })
  writeFileSync(join(target, 'public.txt'), `${publicCanary}\n`)
  writeFileSync(join(replacement, 'auma.key'), `${secretCanary}\n`)
  const ctx = new Context()
  const fibers = []
  fibers.push(await ctx.plugin(SystemPrompt))
  fibers.push(await ctx.plugin(ToolRuntime))
  fibers.push(await ctx.plugin(LocalSubprocessRuntime))
  fibers.push(await ctx.plugin(ToolFsSearch, { sampleOverCapGlobResults: true }))
  let sameGuard
  const registerGuard = ctx.tools.guard
  ctx.tools.guard = function (guard) { sameGuard = guard; return registerGuard.call(this, guard) }
  t.after(() => { ctx.tools.guard = registerGuard })
  // node:test runs after-hooks in registration order. Disposal is registered
  // AFTER the guard restore above because disposing the ToolRuntime fiber
  // unregisters the `tools` service, and `ctx.tools` then reads as undefined —
  // the original fixture registered disposal first and its restore hook died
  // on that (pinned cordis 4.0.2 service semantics; hook order only, no
  // assertion touched).
  t.after(async () => { for (const fiber of fibers.reverse()) await fiber.dispose() })
  fibers.push(await ctx.plugin(ActionGate, {
    auraDir: join(root, 'aura'), dshHome: join(root, 'state', 'home'), home: root,
    supportRoot: join(root, 'support'), repoRoots: [], releaseRoots: [], readRoots: [],
    defaultWorkspace: workspace, confineReads: true, allowLoopback: false, networkAllow: [],
  }))
  ctx.tools.guard = registerGuard
  assert.equal(typeof sameGuard, 'function', 'capture the actual mounted guard, without substituting a verdict')
  if (executionRecheck) {
    // Minimal defensive candidate, in this disposable registry only: run the
    // SAME production guard/receipt writer again immediately before the body.
    // No production source is changed and no additional policy is invented.
    const definition = ctx.tools.get('grep')
    const execute = definition.execute
    definition.execute = function (args, exec) {
      const reason = sameGuard(exec)
      if (reason !== undefined) throw new Error(reason)
      return execute.call(this, args, exec)
    }
    t.after(() => { definition.execute = execute })
  }
  const agent = { id: 'synthetic-search-agent', session: { header: { id: 'synthetic-search-session', cwd: workspace } } }
  const swap = () => {
    // Two synchronous renames happen in a test-controlled seam before launch;
    // no sleep, scheduling guess, deletion or real credential is involved.
    renameSync(target, join(workspace, 'approved-original'))
    renameSync(replacement, target)
  }
  if (swapAfterAllow) {
    // The owned matcher owns tools/execute now, so the listener seam is gone.
    // Drive the mutation through the registered guard itself: the FIRST call
    // returns the genuine admission decision (a receipted allow), the swap
    // runs immediately after it, and the subsequent owned walk meets the
    // changed tree. No verdict is substituted; later calls pass through.
    const genuine = sameGuard
    let swapped = false
    ctx.tools.guard(function (exec) {
      const decision = genuine(exec)
      if (!swapped) { swapped = true; swap() }
      return decision
    })
  }
  const call = () => ctx.tools.execute({
    signal: new AbortController().signal, callId: `synthetic-search-${++callId}`,
    name: 'grep', arguments: { path: 'search', pattern: 'SEARCH_CANARY_' }, agent,
  })
  const decisions = () => readFileSync(join(root, 'aura', 'aura.jsonl'), 'utf8').trim().split('\n')
    .map(line => JSON.parse(line)).filter(row => row.op === 'tool.decision')
  return { ctx, call, swap, target, decisions }
}

const output = result => JSON.stringify({
  value: result.value, content: result.content, meta: result.meta,
})
const secretAbsent = result => assert.equal(output(result).includes(secretCanary), false,
  'UNRESOLVED grep TOCTOU: synthetic credential canary reached canonical results or presentation')

test('genuine carried grep has an available-target clean control', async t => {
  const f = await fixture(t)
  const result = await f.call()
  assert.equal(result.isError, false, 'clean search must actually execute, not fail because a provider is unavailable')
  assert.equal(f.decisions().at(-1)?.decision, 'allow', 'actual Aura receipt must record admission')
  assert.ok(result.value?.matches.some(match => match.line === publicCanary))
  assert.ok(output(result).includes(publicCanary), 'actual rendered search output must contain the public control')
  secretAbsent(result)
})

test('a credential present before the guard prevents real grep launch', async t => {
  const f = await fixture(t)
  f.swap()
  let launches = 0
  const spawn = f.ctx.subprocess.spawn.bind(f.ctx.subprocess)
  f.ctx.subprocess.spawn = spec => { launches++; return spawn(spec) }
  const result = await f.call()
  assert.equal(result.isError, true)
  assert.match(output(result), /key-material:auma-relay-key/u)
  assert.equal(launches, 0, 'actual guard refusal must prevent subprocess execution')
  assert.equal(f.decisions().at(-1)?.decision, 'deny', 'actual Aura receipt must record refusal')
  secretAbsent(result)
})

test('a concurrent fixture writer after the read-path check must not expose protected bytes', async t => {
  const f = await fixture(t, { swapAfterAllow: true })
  const result = await f.call()
  assert.equal(result.isError, true, 'the owned matcher must refuse the swapped tree at match time')
  const trailing = f.decisions()
  assert.ok(trailing[0]?.decision === 'allow', 'a genuine receipted allow precedes the mutation')
  const execution = trailing.at(-1)
  assert.equal(execution?.decision, 'deny', 'the execution phase must refuse after a genuine allow')
  assert.equal(execution?.phase, 'execution', 'the refusal is the gate\'s own execution-phase denial')
  assert.match(JSON.stringify(execution), /key-material:auma-relay-key/u)
  secretAbsent(result)
})

test('a concurrent fixture writer at the read launch must not expose protected bytes', async t => {
  const f = await fixture(t)
  let launches = 0
  const spawn = f.ctx.subprocess.spawn.bind(f.ctx.subprocess)
  f.ctx.subprocess.spawn = spec => {
    launches++
    assert.ok(spec.argv.includes('--json'), 'interposition must still delegate the carried grep argv')
    f.swap()
    return spawn(spec)
  }
  const result = await f.call()
  assert.equal(launches, 1, 'actual local subprocess provider must receive the launch')
  assert.equal(f.decisions().at(-1)?.decision, 'allow', 'launch follows a genuine receipted allow')
  secretAbsent(result)
})

test('the owned matcher refuses a fixture changed after admission before any reader launch', async t => {
  const f = await fixture(t, { swapAfterAllow: true })
  let launches = 0
  const spawn = f.ctx.subprocess.spawn.bind(f.ctx.subprocess)
  f.ctx.subprocess.spawn = spec => { launches++; return spawn(spec) }
  const result = await f.call()
  assert.equal(result.isError, true)
  assert.equal(launches, 0, 'a descriptor refused at match time never reaches the reader spawn')
  const execution = f.decisions().at(-1)
  assert.equal(execution?.decision, 'deny')
  assert.equal(execution?.phase, 'execution')
  secretAbsent(result)
})

test('a writer at the read launch still exposes nothing and the allow receipt stays truthful', async t => {
  const f = await fixture(t)
  let launches = 0
  const spawn = f.ctx.subprocess.spawn.bind(f.ctx.subprocess)
  f.ctx.subprocess.spawn = spec => { launches++; f.swap(); return spawn(spec) }
  const result = await f.call()
  assert.equal(f.decisions()[0]?.decision, 'allow', 'the genuine allow receipt precedes the mutation')
  secretAbsent(result)
})
