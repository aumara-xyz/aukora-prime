#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Native remember and recall use durable lexical memory; pending proposals stay separate.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const file = fileURLToPath(import.meta.url)
const root = dirname(dirname(file))
const subject = `aukora:1:${'37'.repeat(32)}`
const text = 'The heliotrope cabinet contains the spare compass.'
const pendingText = 'The unreviewed periwinkle proposal remains pending.'
const mutants = {
  tool: ["lexical: normalized.retrieval === 'lexical' || lexical", 'lexical'],
  service: ["{}, lexical: normalized.retrieval === 'lexical' })", '{} })'],
}

if (process.argv[2] === '--child') {
  const [mode, scratch, alternateSubject] = process.argv.slice(3)
  const mutation = process.env.KIRA_LEXICAL_MUTANT
  let applied = false
  const hook = registerHooks({ load(url, context, next) {
    const result = next(url, context)
    if (!mutation || url !== new URL('../plugins/aukora-kira/lib/index.js', import.meta.url).href) return result
    const source = String(result.source), [before, after] = mutants[mutation]
    assert.equal(source.split(before).length, 2, 'the production mutation must match once')
    applied = true
    return { ...result, source: source.replace(before, after) }
  } })
  const { apply } = await import('../plugins/aukora-kira/lib/index.js')
  if (mutation) assert.equal(applied, true)
  const stateDir = join(scratch, 'home/kira-memory')
  const tools = new Map(), services = new Map(), disposers = []
  let requests = 0
  // A configured semantic search that returns nothing must not override lexical selection.
  globalThis.fetch = async () => { requests++; return { ok: true, json: async () => ({ result: { memories: [] } }) } }
  const ctx = {
    tools: { register: tool => tools.set(tool.name, tool) }, sessions: { get: () => undefined },
    provide: (name, service) => services.set(name, service),
    effect: fn => { const dispose = fn(); if (typeof dispose === 'function') disposers.push(dispose) },
    on: () => () => {}, inject: () => {}, reflect: { get: () => undefined },
    logger: { info() {}, warn() {}, debug() {} },
  }
  try {
    await apply(ctx, { retrieval: 'lexical', memoryOwner: { stateDir, subject: alternateSubject ?? subject } })
    let answer
    if (mode === 'remember') {
      answer = await tools.get('kira_remember').execute({ text }, {})
      const { createMemoryOwner } = await import('../plugins/aukora-kira/lib/memory-owner.mjs')
      const { stageTool } = await import('../plugins/aukora-kira/lib/tools.mjs')
      const { KIRA_SETTLEMENT_UNAVAILABLE } = await import('../plugins/aukora-kira/lib/record.mjs')
      const owner = createMemoryOwner({ stateDir, subject, queueDir: join(stateDir, 'queue') })
      const pending = await stageTool({ describe: async () => ({ subject, policyRevision: 'fixture', permittedPrivacy: ['local'] }) },
        KIRA_SETTLEMENT_UNAVAILABLE, undefined, owner).execute({ kind: 'observation',
        content: { note: pendingText }, createdAt: '2026-10-12T00:00:00Z' }, {})
      assert.equal(pending.queued.state, 'queued')
      assert.equal(owner.listPending().pending, 1)
      answer.pendingId = pending.recordId
    } else if (mode === 'service') {
      answer = await services.get('kira.recall').recall('heliotrope')
    } else {
      answer = await tools.get('kira_recall').execute({ text: mode === 'pending' ? 'periwinkle' : 'heliotrope' }, {})
    }
    process.stdout.write(JSON.stringify({ answer, requests, pid: process.pid }) + '\n')
  } finally {
    for (const dispose of disposers.reverse()) dispose()
    hook.deregister()
  }
} else if (process.argv.includes('--mutate')) {
  for (const mutation of Object.keys(mutants)) {
    const child = spawnSync(process.execPath, [file], { cwd: root, encoding: 'utf8', timeout: 60_000,
      env: { ...process.env, KIRA_LEXICAL_MUTANT: mutation } })
    assert.equal(child.status, 1, `mutation ${mutation} must fail an assertion`)
    assert.match(child.stderr, /AssertionError/u)
    assert.match(child.stderr, new RegExp(`selected lexical ${mutation}`, 'u'))
    console.log(`kira-lexical-restart mutation ${mutation}: CAUGHT`)
  }
} else {
  const scratch = mkdtempSync(join(root, '.kira-lexical-'))
  const run = (mode, alternateSubject) => {
    const child = spawnSync(process.execPath, [file, '--child', mode, scratch, ...(alternateSubject ? [alternateSubject] : [])], {
      cwd: root, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, AUKORA_STATE: scratch, AUKORA_ROOM_LOG: join(scratch, 'absent-room.log'),
        AUKORA_OPENVIKING_HOME: join(scratch, 'home/openviking') },
    })
    assert.equal(child.status, 0, child.stderr)
    return JSON.parse(child.stdout)
  }
  const check = (reply, saved, mode) => {
    const answer = reply.answer, recalled = mode === 'service' ? answer : answer.remembered
    assert.equal(recalled.degraded, false, `selected lexical ${mode} must not be a semantic fallback`)
    assert.equal(recalled.method, 'lexical-bm25-bigram')
    assert.equal(reply.requests, 0, `selected lexical ${mode} must not query OpenViking`)
    const note = recalled.notes.find(note => note.id === saved.answer.ids[0])
    assert.ok(note, `selected lexical ${mode} must return the persisted note`)
    assert.equal(note.text, text)
    assert.equal(note.contentHash, saved.answer.notes[0].contentHash)
    assert.equal(note.attributedTo, 'agent')
    assert.equal(note.tier, 'remembered')
    assert.equal(note.grantsAuthority, false)
    assert.deepEqual(note.source, saved.answer.notes[0].source)
    assert.equal(note.source.state, 'UNLINKED', 'native remember does not invent owner approval or a session citation')
    assert.deepEqual(note.rememberedChain, saved.answer.notes[0].aura)
    assert.notEqual(reply.pid, saved.pid, 'recall must run in a new process')
  }
  try {
    const saved = run('remember')
    assert.equal(saved.answer.remembered, 1)
    assert.equal(saved.requests, 0)
    for (const mode of ['tool', 'service']) check(run(mode), saved, mode)
    const pending = run('pending').answer
    assert.equal(pending.remembered.notes.length, 0)
    assert.equal(pending.snippets.length, 0)
    assert.ok(readFileSync(join(scratch, 'home/kira-memory/queue', `${saved.answer.pendingId}.json`), 'utf8').includes(pendingText))
    assert.equal(run('tool', `aukora:1:${'49'.repeat(32)}`).answer.snippets.length, 0)
    // A later local bridge configuration cannot change a composition that selected lexical.
    const viking = join(scratch, 'home/openviking')
    mkdirSync(viking, { recursive: true })
    writeFileSync(join(viking, 'aukora-bridge.json'), JSON.stringify({ url: 'http://127.0.0.1:1933' }))
    writeFileSync(join(viking, 'root.key'), 'synthetic-test-key\n')
    writeFileSync(join(viking, 'ov.conf'), '{}\n')
    for (const mode of ['tool', 'service']) check(run(mode), saved, mode)
    console.log('kira-lexical-restart: 6 passed, 0 failed (fresh processes; unsigned DATA, pending excluded; no OpenViking)')
  } finally { rmSync(scratch, { recursive: true, force: true }) }
}
