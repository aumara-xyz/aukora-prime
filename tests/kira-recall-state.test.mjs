#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Real publication and rendering paths; scratch notes and deterministic fetch only.
// --mutant removes one production guard in memory and runs the same assertions.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, test } from 'node:test'

const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
const mutants = {
  'returned-priority': ['injection.mjs', 'if (snippets.length > 0) {', "if (snippets.length > 0 && availability === 'found') {"],
  'withheld-state': ['recall-state.mjs', "returned > 0 ? 'returned' : withheld > 0 ? 'withheld'", "returned > 0 ? 'returned' : false ? 'withheld'"],
  'final-normalization': ['index.js', 'return normalizeRecallState(final,', 'return ((answer, _facts) => answer)(final,'],
  'final-partial-failure': ['index.js', "partialFailure: answer.partialFailure === true || answer.availability === 'undetermined' || live.complete !== true,", "partialFailure: answer.partialFailure === true || answer.availability === 'undetermined',"],
  'historical-partial-failure': ['index.js', "partialFailure: answer.partialFailure === true || answer.availability === 'undetermined' || live.complete !== true,", 'partialFailure: answer.partialFailure === true || live.complete !== true,'],
  'face-historical-partial-failure': ['index.js', "partialFailure: result.partialFailure === true || result.state === 'undetermined' || !finalRead.readable,", 'partialFailure: result.partialFailure === true || !finalRead.readable,'],
  'face-normalization': ['index.js', 'const final = normalizeRecallState({ ...result, availability: finalRead.readable', 'const final = ((answer, _facts) => answer)({ ...result, availability: finalRead.readable'],
  'recall-count-validation': ['tools.mjs', 'if (answer?.[key] !== undefined && (', 'if (false && ('],
  'recent-return-rendering': ['injection.mjs', 'if (returnedSibling) return', 'if (false) return'],
  'recent-return-header': ['injection.mjs', ": (recent?.snippets ?? []).some(one => String(one?.text ?? '').trim() !== '')\n", ': false\n'],
  'incomplete-leg-survivor': ['injection.mjs', "if (!['found', 'empty'].includes(seenAvailability)) undistinguished = true", "if (!['found', 'empty'].includes(seenAvailability)) { undistinguished = true; continue }"],
}
assert.ok(mutantAt < 0 || Object.hasOwn(mutants, mutant), 'unknown or missing mutant')
let applied = false
const target = file => new URL(`../plugins/aukora-kira/lib/${file}`, import.meta.url).href
const replaceOnce = (source, before, replacement) => {
  assert.equal(source.split(before).length - 1, 1, `production hook must occur once: ${before}`)
  return source.replace(before, replacement)
}
const hooks = registerHooks({ load(url, context, next) {
  const result = next(url, context)
  if (![target('index.js'), target('injection.mjs'), target('recall-state.mjs'), target('tools.mjs')].includes(url)) return result
  let source = typeof result.source === 'string' ? result.source : Buffer.from(result.source).toString('utf8')
  if (url === target('index.js')) {
    source = replaceOnce(source,
      'const policy = readOwnerPolicy(await owner.describe())\n    const live = memoryFor().read()',
      'const policy = readOwnerPolicy(await owner.describe().then(async policy => { await globalThis.__kiraRecallStateAfterPolicy?.(answers); return policy }))\n    const live = memoryFor().read()')
    source = replaceOnce(source,
      "const recallConversation = memoryOwner ? { turn: async () => ({ availability: 'empty', status: 'empty', snippets: [] }) }",
      "const recallConversation = memoryOwner ? { turn: async () => globalThis.__kiraRecallStateMemoryLeg?.() ?? ({ availability: 'empty', status: 'empty', snippets: [] }) }")
    source = replaceOnce(source,
      'const currentPolicy = readOwnerPolicy(await owner.describe())\n              const currentSession',
      'const currentPolicy = readOwnerPolicy(await owner.describe().then(async policy => { await globalThis.__kiraRecallStateFacePolicy?.(result); return policy }))\n              const currentSession')
  }
  if (url === target('injection.mjs')) source = replaceOnce(source,
    'onRecalled?.(reply, recent, { agent })',
    'globalThis.__kiraRecallStateObserved?.(reply, recent, { agent }); onRecalled?.(reply, recent, { agent })')
  if (url === target('recall-state.mjs')) source = replaceOnce(source,
    'export function normalizeRecallState(answer, facts = {}) {',
    'export function normalizeRecallState(answer, facts = {}) { globalThis.__kiraRecallStateNormalizeObserved?.(answer, facts)')
  if (mutant && url === target(mutants[mutant][0])) {
    source = replaceOnce(source, mutants[mutant][1], mutants[mutant][2])
    applied = true
  }
  return { ...result, source }
} })

const { normalizeRecallState } = await import('../plugins/aukora-kira/lib/recall-state.mjs')
const { renderQueryPart, recalledContextLine, registerRecallInjection, MAX_INJECTION_CHARS } = await import('../plugins/aukora-kira/lib/injection.mjs')
const { apply } = await import('../plugins/aukora-kira/lib/index.js')
const { createTrackedMemory } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
const { nextEntry } = await import('../plugins/aukora-kira/lib/memory-journal.mjs')
const { appendJournalLine, readLinesIfPresent } = await import('../plugins/aukora-kira/lib/strict-read.mjs')
const { PARTIAL_FAILURE_SERVICE } = await import('../plugins/aukora-kira/lib/partial-failure.mjs')
const { recallTool } = await import('../plugins/aukora-kira/lib/tools.mjs')
if (mutant) assert.equal(applied, true, 'the mutant must load the production module')
after(() => hooks.deregister())

const subject = `aukora:1:${'6a'.repeat(32)}`
const record = (id = 'synthetic-owner', text = 'SYNTHETIC-OWNER-RETURNED is a local fixture.') => ({ recordId: id, text, attributedTo: 'owner' })
const person = text => ({ role: 'user', source: { kind: 'user' }, content: [{ type: 'text', text }] })
const noContradiction = text => assert.doesNotMatch(text, /memory store could NOT be verified|Query: unavailable/u)

test('final state table distinguishes returned, withheld, query miss, empty and unavailable', () => {
  const cases = [
    [{ availability: 'undetermined', snippets: [record()] }, { readable: false }, 'returned', 'found', 'match'],
    [{ availability: 'found', snippets: [] }, { readable: true, policyWithheldCount: 2 }, 'withheld', 'empty', 'withheld'],
    [{ availability: 'undetermined', snippets: [] }, { readable: false, policyWithheldCount: 2 }, 'withheld', 'undetermined', 'withheld'],
    [{ availability: 'empty', snippets: [] }, { readable: true, eligibleRecords: 3 }, 'query-miss', 'found', 'insufficient'],
    [{ availability: 'empty', snippets: [] }, { readable: true }, 'empty', 'empty', 'empty'],
    [{ availability: 'found', snippets: [] }, { readable: false }, 'unavailable', 'undetermined', 'undetermined'],
  ]
  for (const [answer, facts, recallState, availability, status] of cases) {
    const result = normalizeRecallState(answer, facts)
    assert.equal(result.recallState, recallState)
    assert.equal(result.availability, availability)
    assert.equal(result.status, status)
  }
})

test('normalization counts unique returned records and preserves action and read evidence', () => {
  const retrieval = [{ leg: 'memory', availability: 'undetermined' }, { leg: 'remembered', availability: 'found' }]
  const partialFailure = { action: 'stop', reason: 'synthetic sibling unavailable', outer: 'undetermined', remembered: 'found' }
  const answer = { availability: 'undetermined', snippets: [record(), record(), record('blank', '   ')],
    retrieval, partialFailure, action: 'stop', faults: [], policyWithheldCount: 3 }
  const result = normalizeRecallState(answer, { readable: false, eligibleRecords: 1 })
  assert.equal(result.recallState, 'returned')
  assert.equal(result.returnedRecords, 1)
  assert.equal(result.policyWithheldCount, 3)
  assert.equal(result.action, 'stop')
  assert.equal(result.partialFailure, partialFailure)
  assert.equal(result.retrieval, retrieval)
  assert.equal(result.faults, answer.faults)
  assert.deepEqual(answer.snippets, result.snippets, 'normalization never rewrites returned records')
  assert.equal(answer.availability, 'undetermined', 'the historical supplier object is not mutated')
  assert.equal(normalizeRecallState({ notes: [{ id: 'note-fixture', statement: 'NOTE-ONLY-FIXTURE' }] }).recallState, 'returned')
})

test('renderer trusts nonempty returned snippets before a legacy unavailable status', () => {
  const reply = { availability: 'undetermined', status: 'undetermined', snippets: [record()], retrieval: [
    { leg: 'memory', availability: 'undetermined', diagnostics: [] },
    { leg: 'remembered', availability: 'found', diagnostics: [] },
  ] }
  const text = renderQueryPart(reply)
  assert.match(text, /SYNTHETIC-OWNER-RETURNED/u)
  noContradiction(text)
  const header = recalledContextLine(reply)
  assert.match(header, /Query: eligible returned records=1\./u)
  assert.match(header, /memory: readable\/found attempts=0, readable\/empty attempts=0, unavailable attempts=1/u)
  noContradiction(header)
})

test('withheld has its own line without claiming empty records or exposing their text', () => {
  const reply = normalizeRecallState({ availability: 'found', snippets: [], retrieval: [] },
    { readable: true, policyWithheldCount: 2 })
  const text = renderQueryPart(reply)
  assert.match(text, /Records exist, withheld by policy \(2\)\./u)
  assert.doesNotMatch(text, /holds no record|no visible record|HOLDS RECORDS, but none matched/u)
  noContradiction(text)
  assert.match(recalledContextLine(reply, { availability: 'empty', snippets: [] }), /Policy: records exist, withheld by policy \(2\)\./u)
})

async function mounted(body, { projectScoped = false } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'kira-recall-final-state-'))
  const stateDir = join(home, 'kira-memory'), bridgeHome = join(home, 'openviking'), workspace = join(home, 'project')
  const savedEnv = new Map(['AUKORA_STATE', 'AUKORA_OPENVIKING_HOME', 'AUKORA_ROOM_LOG'].map(name => [name, process.env[name]]))
  const savedFetch = globalThis.fetch, disposers = [], indexed = new Map(), services = new Map(), tools = new Map(), handlers = []
  const fixtureKeys = ['__kiraRecallStateAfterPolicy', '__kiraRecallStateMemoryLeg', '__kiraRecallStateObserved', '__kiraRecallStateNormalizeObserved', '__kiraRecallStateFacePolicy']
  try {
    process.env.AUKORA_STATE = home
    process.env.AUKORA_ROOM_LOG = join(home, 'absent-room.jsonl')
    process.env.AUKORA_OPENVIKING_HOME = bridgeHome
    mkdirSync(workspace)
    const memory = createTrackedMemory({ stateDir, subject, config: { configured: false },
      policyOf: async () => ({ subject, privacy: 'local' }) })
    const answer = await memory.remember({ text: 'SYNTHETIC-POLICY-CONTROL handoff status next step.', from: 'fixture',
      scope: projectScoped ? 'project:id:synthetic-project' : 'owner' }, { attributedTo: 'owner' })
    assert.equal(answer.remembered, 1)
    const note = memory.read().notes[0]
    mkdirSync(bridgeHome)
    writeFileSync(join(bridgeHome, 'aukora-bridge.json'), JSON.stringify({ url: 'http://127.0.0.1:1', user: 'owner', limit: 5 }))
    writeFileSync(join(bridgeHome, 'root.key'), 'synthetic-disposable-value', { mode: 0o600 })
    writeFileSync(join(bridgeHome, 'ov.conf'), '{}')
    globalThis.fetch = async (url, options = {}) => {
      const parsed = new URL(url), path = parsed.pathname
      if (path === '/health') return Response.json({ healthy: true })
      let result = {}
      if (path === '/api/v1/content/write') { const written = JSON.parse(options.body); indexed.set(written.uri, written.content) }
      else if (path === '/api/v1/content/read') result = indexed.get(parsed.searchParams.get('uri'))
      else if (path === '/api/v1/search/find') result = { memories: [...indexed.keys()].map(uri => ({ uri, score: .9 })) }
      else if (options.method === 'DELETE') indexed.delete(parsed.searchParams.get('uri'))
      else assert.fail(`unexpected synthetic fetch path: ${path}`)
      return Response.json({ status: 'ok', result })
    }
    const agent = { session: { id: 'synthetic-recall-session', header: { cwd: workspace } } }
    const ctx = { on: (event, handler) => { handlers.push({ event, handler }); return () => {} },
      inject: (_dependencies, callback) => callback({}), get: () => undefined,
      effect: callback => { const dispose = callback(); if (typeof dispose === 'function') disposers.push(dispose) },
      tools: { register: definition => { tools.set(definition.name, definition); return () => {} } }, provide: (name, service) => services.set(name, service),
      sessions: { get: id => id === agent.session.id ? agent.session : undefined },
      logger: { warn() {}, info() {}, error() {}, debug() {} } }
    await apply(ctx, { memoryOwner: { stateDir, subject, permittedPrivacy: ['local'] },
      ...(projectScoped ? { projectIdentity: { version: 1, projects: [{ project_id: 'synthetic-project', workspace_roots: [workspace] }] } } : {}) })
    await new Promise(setImmediate)
    const listener = handlers.find(one => one.event === 'agent/pre-step')
    assert.ok(listener, 'the actual mounted plugin registers the pre-step path')
    let observed, normalizations = 0, faceNormalizations = 0, toolNormalizations = 0
    globalThis.__kiraRecallStateObserved = reply => { observed = reply }
    globalThis.__kiraRecallStateNormalizeObserved = answer => {
      if (Array.isArray(answer?.retrieval)) normalizations++
      else if (Array.isArray(answer?.records)) faceNormalizations++
      else if (Array.isArray(answer?.snippets) && answer?.retrieval) toolNormalizations++
    }
    const run = async () => {
      normalizations = 0
      const decision = await listener.handler({ agent }, async () => ({ kind: 'continue', messages: [person('handoff status next step')] }))
      assert.equal(decision.kind, 'continue')
      assert.equal(decision.messages.at(-1).source.form, 'snapshot')
      const text = decision.messages.at(-1).content[0].text
      assert.ok(text.length <= MAX_INJECTION_CHARS + 1, 'the complete mounted contribution retains its budget')
      return { text, reply: observed, normalizations, action: services.get(PARTIAL_FAILURE_SERVICE).forAgent(agent) }
    }
    const expire = () => {
      const file = join(stateDir, 'remembered/journal.jsonl')
      const previous = readLinesIfPresent(file).at(-1)
      appendJournalLine({ file, line: JSON.stringify(nextEntry({ previous: previous ? JSON.parse(previous) : null,
        op: 'expire', id: note.id, objectDigest: note.id.slice(4), actor: 'synthetic-fixture', at: new Date().toISOString() })) })
    }
    const face = async () => {
      faceNormalizations = 0
      const service = services.get('kira.recall')
      assert.equal(typeof service?.recall, 'function', 'the actual mounted face recall service is provided')
      const reply = await service.recall('handoff status next step', agent.session)
      return { reply, normalizations: faceNormalizations }
    }
    const toolRecall = async () => {
      toolNormalizations = 0
      const tool = tools.get('kira_recall')
      assert.equal(typeof tool?.execute, 'function', 'the actual native recall tool is registered')
      const reply = await tool.execute({ text: 'handoff status next step' }, { agent })
      return { reply, tool, normalizations: toolNormalizations, action: services.get(PARTIAL_FAILURE_SERVICE).forAgent(agent) }
    }
    await body({ run, face, toolRecall, note, memory, expire, stateDir, agent, home })
  } finally {
    for (const dispose of disposers.reverse()) dispose()
    for (const key of fixtureKeys) delete globalThis[key]
    globalThis.fetch = savedFetch
    for (const [name, value] of savedEnv) { if (value === undefined) delete process.env[name]; else process.env[name] = value }
    rmSync(home, { recursive: true, force: true })
  }
}

test('mounted final publication rechecks an initially returned note after the owner-policy await', async () => {
  await mounted(async ({ run, note, memory, expire }) => {
    let initial, changed = false
    globalThis.__kiraRecallStateAfterPolicy = async answers => {
      assert.equal(changed, false, 'one final policy pass publishes this step')
      initial = { snippets: structuredClone(answers[0].snippets), retrieval: structuredClone(answers[0].retrieval), partialFailure: answers[0].partialFailure }
      await Promise.resolve()
      expire()
      changed = true
    }
    const result = await run()
    assert.equal(changed, true)
    assert.equal(result.normalizations, 1, 'the final query result is normalized once after the last filter')
    assert.ok(initial.snippets.some(one => one.recordId === note.id), 'the note was returned before the final await')
    assert.equal(memory.read().states.get(note.id), 'expired', 'the fixture changes real journal policy state')
    assert.equal(result.reply.recallState, 'withheld')
    assert.equal(result.reply.policyWithheldCount, 1)
    assert.equal(result.reply.returnedRecords, 0)
    assert.equal(result.reply.availability, 'empty')
    assert.equal(result.reply.partialFailure, initial.partialFailure)
    assert.deepEqual(result.reply.retrieval, initial.retrieval, 'historical read outcomes survive final policy filtering')
    assert.match(result.text, /Records exist, withheld by policy \(1\)\./u)
    assert.doesNotMatch(result.text, /SYNTHETIC-POLICY-CONTROL/u)
    noContradiction(result.text)
  })
})

test('mounted successful remembered queries retain unavailable memory attempts and the stop action', async () => {
  await mounted(async ({ run, note }) => {
    globalThis.__kiraRecallStateMemoryLeg = () => ({ availability: 'undetermined', status: 'undetermined', snippets: [] })
    let initial
    globalThis.__kiraRecallStateAfterPolicy = async answers => { initial = structuredClone(answers[0]); await Promise.resolve() }
    const result = await run()
    assert.equal(result.normalizations, 1)
    assert.equal(result.reply.recallState, 'returned')
    assert.equal(result.reply.availability, 'found')
    assert.equal(result.reply.returnedRecords, 1)
    assert.ok(result.reply.snippets.some(one => one.recordId === note.id))
    assert.equal(result.reply.partialFailure, true)
    assert.equal(result.reply.partialFailure, initial.partialFailure)
    assert.deepEqual(result.reply.retrieval, initial.retrieval)
    assert.equal(result.action.action, 'stop', 'presentation success never clears the action decision for an unavailable sibling')
    assert.equal(result.action.outer, 'undetermined')
    const reads = result.reply.retrieval
    assert.ok(reads.some(one => one.leg === 'memory' && one.availability === 'undetermined'))
    assert.ok(reads.some(one => one.leg === 'remembered' && one.availability === 'found'))
    assert.match(result.text, /SYNTHETIC-POLICY-CONTROL/u)
    assert.match(result.text, /Query: eligible returned records=1\./u)
    assert.match(result.text, /unavailable attempts=[1-9][0-9]*; partial failure, absence not established/u)
    noContradiction(result.text)
  })
})

test('mounted final store damage retains a surviving returned record and stops the action', async () => {
  await mounted(async ({ run, note, memory, stateDir }) => {
    const second = await memory.remember({ text: 'SYNTHETIC-MISSING-SIBLING handoff status next step.', from: 'fixture', scope: 'owner' }, { attributedTo: 'owner' })
    assert.equal(second.remembered, 1)
    let initial
    globalThis.__kiraRecallStateAfterPolicy = async answers => {
      initial = structuredClone(answers[0])
      await Promise.resolve()
      rmSync(join(stateDir, 'remembered', `${second.ids[0].slice(4)}.json`))
    }
    const result = await run()
    assert.equal(result.normalizations, 1)
    assert.equal(initial.partialFailure, false, 'initial queries completed before the later object loss')
    assert.equal(memory.read().complete, false, 'the final production reread sees a missing chained object')
    assert.equal(result.reply.recallState, 'returned')
    assert.equal(result.reply.availability, 'found')
    assert.equal(result.reply.returnedRecords, 1)
    assert.equal(result.reply.snippets[0].recordId, note.id)
    assert.equal(result.reply.partialFailure, true, 'a newly unreadable sibling survives positive presentation state')
    assert.equal(result.action.action, 'stop')
    assert.deepEqual(result.reply.retrieval, initial.retrieval, 'the later defect does not rewrite historical attempts')
    assert.match(result.text, /SYNTHETIC-POLICY-CONTROL/u)
    assert.doesNotMatch(result.text, /SYNTHETIC-MISSING-SIBLING/u)
    noContradiction(result.text)
  })
})

for (const repaired of [false, true]) test(`mounted initially unavailable remembered reads retain verified snippets${repaired ? ' after final repair' : ''}`, async () => {
  await mounted(async ({ run, note, memory, stateDir }) => {
    const second = await memory.remember({ text: 'SYNTHETIC-EARLY-MISSING handoff status next step.', from: 'fixture', scope: 'owner' }, { attributedTo: 'owner' })
    const object = join(stateDir, 'remembered', `${second.ids[0].slice(4)}.json`), exactObject = readFileSync(object)
    rmSync(object)
    assert.equal(memory.read().complete, false)
    let initial
    globalThis.__kiraRecallStateAfterPolicy = async answers => {
      initial = structuredClone(answers[0])
      await Promise.resolve()
      if (repaired) writeFileSync(object, exactObject, { mode: 0o600 })
    }
    const result = await run()
    assert.equal(initial.availability, 'undetermined', 'the initial missing sibling has not been presented as a healthy read')
    assert.ok(initial.snippets.some(one => one.recordId === note.id), 'the query merger retains already verified surviving bytes before publication')
    assert.ok(initial.retrieval.some(one => one.leg === 'remembered' && one.availability === 'undetermined'))
    assert.equal(memory.read().complete, repaired)
    assert.equal(result.normalizations, 1)
    assert.equal(result.reply.recallState, 'returned')
    assert.equal(result.reply.availability, 'found')
    assert.equal(result.reply.returnedRecords, 1)
    assert.equal(result.reply.partialFailure, true)
    assert.equal(result.reply.snippets[0].recordId, note.id)
    assert.deepEqual(result.reply.retrieval, initial.retrieval)
    assert.equal(result.action.action, 'stop')
    assert.match(result.text, /SYNTHETIC-POLICY-CONTROL/u)
    assert.doesNotMatch(result.text, /SYNTHETIC-EARLY-MISSING/u)
    noContradiction(result.text)
  })
})

test('direct face recall refreshes expiry as advisory data without changing the record identity', async () => {
  await mounted(async ({ face, note, expire }) => {
    let initial, calls = 0
    globalThis.__kiraRecallStateFacePolicy = async result => {
      initial = structuredClone(result)
      calls++
      await Promise.resolve()
      expire()
    }
    const result = await face()
    assert.equal(calls, 1, 'the fixture changes state at the final service policy await')
    assert.equal(result.normalizations, 1, 'the service normalizes after its last citation and policy filter')
    assert.equal(result.reply.recallState, 'returned')
    assert.equal(result.reply.state, 'found')
    assert.equal(result.reply.availability, 'found')
    assert.equal(result.reply.notes[0].id, note.id)
    assert.equal(result.reply.notes[0].text, initial.notes[0].text)
    assert.deepEqual(result.reply.notes[0].source, initial.notes[0].source)
    assert.equal(initial.notes[0].staleness.flagged, false)
    assert.equal(result.reply.notes[0].staleness.flagged, true, 'explicit expiry refreshes advisory staleness instead of hiding the note')
    assert.equal(result.reply.grantsAuthority, false)
    assert.equal(result.reply.auraCitations[0].recordId, note.id)
    assert.equal(result.reply.auraCitations[0].status, 'undetermined')
    assert.equal(result.reply.auraCitations[0].reason, 'aura-recall:provider-unavailable')
  })
})

test('direct face recall reports final project attachment withdrawal as withheld', async () => {
  await mounted(async ({ face, note, agent, home }) => {
    let initial
    globalThis.__kiraRecallStateFacePolicy = async result => {
      initial = structuredClone(result)
      await Promise.resolve()
      agent.session.header.cwd = join(home, 'unattached-workspace')
    }
    const result = await face()
    assert.ok(initial.notes.some(one => one.id === note.id), 'the explicit attached project initially returned the note')
    assert.equal(result.normalizations, 1)
    assert.equal(result.reply.recallState, 'withheld')
    assert.equal(result.reply.state, 'empty')
    assert.equal(result.reply.status, 'withheld')
    assert.equal(result.reply.policyWithheldCount, 1)
    assert.deepEqual(result.reply.notes, [])
    assert.deepEqual(result.reply.records, [])
    assert.deepEqual(result.reply.auraCitations, [])
    assert.equal(result.reply.reason, 'aura-recall:recall-changed')
    assert.equal(result.reply.grantsAuthority, false)
  }, { projectScoped: true })
})

test('direct face recall retains final unreadability beside a surviving returned note', async () => {
  await mounted(async ({ face, note, memory, stateDir }) => {
    const second = await memory.remember({ text: 'SYNTHETIC-FACE-MISSING handoff status next step.', from: 'fixture', scope: 'owner' }, { attributedTo: 'owner' })
    globalThis.__kiraRecallStateFacePolicy = async () => {
      await Promise.resolve()
      rmSync(join(stateDir, 'remembered', `${second.ids[0].slice(4)}.json`))
    }
    const result = await face()
    assert.equal(result.normalizations, 1)
    assert.equal(memory.read().complete, false)
    assert.equal(result.reply.recallState, 'returned')
    assert.equal(result.reply.state, 'found')
    assert.equal(result.reply.partialFailure, true)
    assert.equal(result.reply.returnedRecords, 1)
    assert.equal(result.reply.notes[0].id, note.id)
    assert.equal(result.reply.records[0].id, note.id)
    assert.equal(result.reply.auraCitations.length, 1)
    assert.equal(result.reply.auraCitations[0].recordId, note.id)
    assert.equal(result.reply.auraCitations[0].status, 'undetermined')
    assert.equal(result.reply.grantsAuthority, false)
  })
})

test('registered native recall preserves final returned bytes, stop decision and its closed schema', async () => {
  await mounted(async ({ toolRecall, note, memory, stateDir }) => {
    const second = await memory.remember({ text: 'SYNTHETIC-TOOL-MISSING handoff status next step.', from: 'fixture', scope: 'owner' }, { attributedTo: 'owner' })
    let initial
    globalThis.__kiraRecallStateAfterPolicy = async answers => {
      initial = structuredClone(answers[0])
      await Promise.resolve()
      rmSync(join(stateDir, 'remembered', `${second.ids[0].slice(4)}.json`))
    }
    const result = await toolRecall()
    assert.ok(initial.snippets.some(one => one.recordId === second.ids[0]))
    assert.equal(result.normalizations, 1)
    assert.equal(result.reply.recallState, 'returned')
    assert.equal(result.reply.availability, 'found')
    assert.equal(result.reply.status, 'match')
    assert.equal(result.reply.returnedRecords, 1)
    assert.equal(result.reply.snippets[0].recordId, note.id)
    assert.equal(result.reply.remembered.notes[0].id, note.id)
    assert.equal(result.reply.partialFailure.action, 'stop')
    assert.equal(result.reply.partialFailure.outer, 'undetermined')
    assert.equal(result.reply.partialFailure.reconciledAvailability, 'found')
    assert.equal(result.action.action, 'stop')
    assert.equal(result.reply.grantsAuthority, false)
    const schema = result.tool.output.schema
    assert.equal(schema.additionalProperties, false)
    assert.ok(schema.properties.recallState.enum.includes(result.reply.recallState))
    assert.deepEqual(schema.properties.recallState.enum, ['returned', 'withheld', 'query-miss', 'empty', 'unavailable'])
    for (const key of ['returnedRecords', 'eligibleRecords', 'policyWithheldCount']) {
      assert.equal(schema.properties[key].type, 'integer', 'the rendered count is explicitly declared')
      assert.ok(Number.isSafeInteger(result.reply[key]) && result.reply[key] >= 0)
    }
    for (const key of schema.required) assert.ok(Object.hasOwn(result.reply, key), `required output field ${key}`)
    for (const key of Object.keys(result.reply)) assert.ok(Object.hasOwn(schema.properties, key), `undeclared output field ${key}`)
    assert.equal(schema.properties.partialFailure.additionalProperties, false)
    for (const key of Object.keys(result.reply.partialFailure)) assert.ok(Object.hasOwn(schema.properties.partialFailure.properties, key))
    for (const key of schema.properties.partialFailure.required) assert.ok(Object.hasOwn(result.reply.partialFailure, key))
    assert.match(result.tool.output.render({}, result.reply)[0].text, /SYNTHETIC-POLICY-CONTROL/u)
    assert.doesNotMatch(result.tool.output.render({}, result.reply)[0].text, /SYNTHETIC-TOOL-MISSING/u)
  })
})

test('native recall rejects invalid final counts before output and accepts the zero boundary', async () => {
  for (const key of ['returnedRecords', 'eligibleRecords', 'policyWithheldCount']) {
    for (const value of [-1, .5, Number.MAX_SAFE_INTEGER + 1, NaN]) {
      const tool = recallTool(async () => ({ [key]: value }))
      await assert.rejects(() => tool.execute({ text: 'synthetic count fixture' }, {}), /recall counts must be non-negative safe integers/u)
    }
    const answer = { [key]: 0 }
    assert.equal(await recallTool(async () => answer).execute({ text: 'synthetic count fixture' }, {}), answer)
  }
})

for (const path of ['tool', 'face']) test(`restored final store preserves the ${path}'s earlier unavailable sibling evidence`, async () => {
  await mounted(async ({ toolRecall, face, note, memory, stateDir }) => {
    const second = await memory.remember({ text: 'SYNTHETIC-RESTORED-SIBLING handoff status next step.', from: 'fixture', scope: 'owner' }, { attributedTo: 'owner' })
    const object = join(stateDir, 'remembered', `${second.ids[0].slice(4)}.json`)
    const exactObject = readFileSync(object)
    rmSync(object)
    assert.equal(memory.read().complete, false)
    let initial
    const restore = async input => {
      initial = structuredClone(path === 'tool' ? input[0] : input)
      await Promise.resolve()
      writeFileSync(object, exactObject, { mode: 0o600 })
    }
    if (path === 'tool') globalThis.__kiraRecallStateAfterPolicy = restore
    else globalThis.__kiraRecallStateFacePolicy = restore
    const result = await (path === 'tool' ? toolRecall() : face())
    assert.equal(memory.read().complete, true, 'the last source reread sees the exact restored synthetic object')
    assert.deepEqual(readFileSync(object), exactObject)
    assert.equal(result.normalizations, 1)
    assert.equal(result.reply.recallState, 'returned')
    assert.equal(result.reply.availability, 'found')
    assert.equal(result.reply.returnedRecords, 1)
    if (path === 'tool') {
      assert.equal(initial.availability, 'undetermined')
      assert.equal(initial.remembered.state, 'undetermined')
      assert.equal(result.reply.snippets[0].recordId, note.id)
      assert.equal(result.reply.remembered.state, 'undetermined', 'current repair does not rewrite the historical ambient read')
      assert.equal(result.reply.partialFailure.action, 'stop')
      assert.equal(result.reply.partialFailure.outer, 'undetermined')
      assert.equal(result.reply.partialFailure.remembered, 'undetermined')
      assert.equal(result.action.action, 'stop')
    } else {
      assert.equal(initial.state, 'undetermined')
      assert.equal(result.reply.notes[0].id, note.id)
      assert.equal(result.reply.partialFailure, true)
      assert.equal(result.reply.state, 'found')
    }
  })
})

test('legacy injection normalizes only after attribution filtering and retains a successful sibling', async () => {
  let listener, observed
  const owner = record('legacy-owner', 'LEGACY-SYNTHETIC-OWNER is returned beside withheld model data.')
  const model = { ...record('legacy-model', 'LEGACY-SYNTHETIC-MODEL must remain withheld.'), attributedTo: 'agent' }
  registerRecallInjection({ on: (_event, handler) => { listener = handler; return () => {} } }, {
    queries: ['unavailable', 'found'],
    conversation: { turn: async ({ text }) => text === 'unavailable'
      ? { availability: 'undetermined', snippets: [] } : { availability: 'found', snippets: [owner, model] } },
    newest: async () => ({ availability: 'empty', snippets: [] }),
    newId: () => 'synthetic-snapshot', onRecalled: reply => { observed = reply },
  })
  const decision = await listener({ agent: { session: {} } }, async () => ({ kind: 'continue', messages: [] }))
  const text = decision.messages.at(-1).content[0].text
  assert.equal(observed.recallState, 'returned')
  assert.equal(observed.availability, 'found')
  assert.equal(observed.policyWithheldCount, 1)
  assert.equal(observed.returnedRecords, 1)
  assert.equal(observed.partialFailure, true)
  assert.equal(observed.retrieval[0].availability, 'undetermined')
  assert.equal(observed.retrieval[1].availability, 'found')
  assert.match(text, /LEGACY-SYNTHETIC-OWNER/u)
  assert.doesNotMatch(text, /LEGACY-SYNTHETIC-MODEL/u)
  assert.match(text, /Policy: records exist, withheld by policy \(1\)\./u)
  noContradiction(text)
})

test('all legacy model snippets have the distinct withheld state and banner', async () => {
  let listener, observed
  registerRecallInjection({ on: (_event, handler) => { listener = handler; return () => {} } }, {
    queries: ['model-only'], conversation: { turn: async () => ({ availability: 'found', snippets: [
      { ...record('model-only', 'MODEL-ONLY-SYNTHETIC must not be automatic context.'), attributedTo: 'agent' },
    ] }) }, newest: async () => ({ availability: 'empty', snippets: [] }),
    newId: () => 'synthetic-snapshot', onRecalled: reply => { observed = reply },
  })
  const decision = await listener({ agent: { session: {} } }, async () => ({ kind: 'continue', messages: [] }))
  const text = decision.messages.at(-1).content[0].text
  assert.equal(observed.recallState, 'withheld')
  assert.equal(observed.policyWithheldCount, 1)
  assert.equal(observed.returnedRecords, 0)
  assert.match(text, /Records exist, withheld by policy \(1\)\./u)
  assert.doesNotMatch(text, /MODEL-ONLY-SYNTHETIC|memory store is readable and holds no record|HOLDS RECORDS, but none matched/u)
  noContradiction(text)
})

test('successful newest records beside unavailable queries do not claim the store could not be verified', async () => {
  let listener, observed
  registerRecallInjection({ on: (_event, handler) => { listener = handler; return () => {} } }, {
    queries: ['unavailable'], conversation: { turn: async () => ({ availability: 'undetermined', snippets: [] }) },
    newest: async () => ({ availability: 'found', snippets: [record('recent-only', 'RECENT-SYNTHETIC-OWNER is verified returned data.')] }),
    newId: () => 'synthetic-snapshot', onRecalled: reply => { observed = reply },
  })
  const decision = await listener({ agent: { session: {} } }, async () => ({ kind: 'continue', messages: [] }))
  const text = decision.messages.at(-1).content[0].text
  assert.equal(observed.partialFailure, true)
  assert.equal(observed.retrieval[0].availability, 'undetermined', 'historical query availability remains unavailable')
  assert.match(text, /RECENT-SYNTHETIC-OWNER/u)
  noContradiction(text)
})
