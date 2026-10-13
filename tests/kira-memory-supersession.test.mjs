#!/usr/bin/env node
// Explicit replacement links stay hashed, scoped, reversible and visible on returned older notes.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { buildRememberedNote, sha256Hex } from '../plugins/aukora-kira/lib/memory-tiers.mjs'
import { AURA_RECORD_DOMAIN } from '../plugins/aukora-kira/lib/memory-owner.mjs'
import { nextEntry, verifyChain as verifyJournal } from '../plugins/aukora-kira/lib/memory-journal.mjs'
import { buildRouteDeps } from '../plugins/aukora-kira/lib/memory-deps.mjs'
import { objectFileName, STORE_PATHS } from '../plugins/aukora-kira/lib/memory-store.mjs'

assert.equal(process.version, 'v24.11.1', 'use the repository-pinned Node version')
const ROOT = fileURLToPath(new URL('..', import.meta.url)), work = mkdtempSync(join(ROOT, '.test-kira-supersession-'))
const trackedFile = join(ROOT, 'plugins/aukora-kira/lib/tracked-memory.mjs')
const semanticFile = join(ROOT, 'plugins/aukora-kira/lib/recall-openviking.mjs')
const mutant = process.argv.includes('--mutant') ? process.argv[process.argv.indexOf('--mutant') + 1] : null
const mutations = {
  'list-type': { file: trackedFile, guard: '!Array.isArray(supersedes)', removed: 'false', groups: ['invalid'] },
  'list-id': { file: trackedFile, guard: "supersedes.some(id => typeof id !== 'string' || !/^rem:[0-9a-f]{64}$/u.test(id))", removed: 'false', groups: ['invalid'] },
  'list-duplicates': { file: trackedFile, guard: 'new Set(supersedes).size !== supersedes.length', removed: 'false', groups: ['invalid'] },
  'self': { file: trackedFile, guard: "if (supersedes.includes(id)) throw new Error('memory-supersedes-self')", removed: 'void 0', groups: ['self'] },
  'missing-newer': { file: trackedFile, guard: "if (!notes.has(id)) throw new Error('memory-supersedes-missing')", removed: 'void 0', groups: ['missing-newer'] },
  'subject-newer': { file: trackedFile, guard: "if (notes.get(id).subject !== subject) throw new Error('memory-supersedes-subject')", removed: 'void 0', groups: ['subject-newer'] },
  'missing-older': { file: trackedFile, guard: "if (!note) throw new Error('memory-supersedes-missing')", removed: 'void 0', groups: ['missing'] },
  'subject-older': { file: trackedFile, guard: "if (note.subject !== subject) throw new Error('memory-supersedes-subject')", removed: 'void 0', groups: ['subject'] },
  'cycle': { file: trackedFile, guard: "if (reaches(older, id)) throw new Error('memory-supersedes-cycle')", removed: 'void 0', groups: ['cycle'] },
  'forget-activation': { file: trackedFile, guard: "entry.op === 'supersede' && entry.supersedes !== undefined && !forgotten.has(entry.id)",
    removed: "entry.op === 'supersede' && entry.supersedes !== undefined", groups: ['forget'] },
  'record-link': { file: trackedFile, guard: 'planned.push(...bodies)', removed: 'void 0', groups: ['append'] },
  'wall-clock': { file: trackedFile, guard: 'planSupersession(ids, supersedes, live, [...candidates, ...notes], supersessions, p.subject, canonicalInstant(now()))',
    removed: 'planSupersession(ids, supersedes, live, [...candidates, ...notes], supersessions, p.subject, canonicalInstant(at))', groups: ['append'] },
  'duplicate-link': { file: trackedFile, guard: 'planSupersession(ids, supersedes, live, candidates, supersessions, p.subject, canonicalInstant(now()))', removed: 'void 0', groups: ['duplicate', 'interrupted'] },
  'hidden-target': { file: trackedFile, guard: '...(live.hiddenNotes ?? []),', removed: '', groups: ['hidden-predecessor'] },
  'hidden-default': { file: trackedFile, guard: 'includeHidden = false', removed: 'includeHidden = true', groups: ['hidden-predecessor'] },
  'hidden-planner': { file: trackedFile, guard: 'const live = readTrackedMemory(stateDir, { includeHidden: true })',
    removed: 'const live = readTrackedMemory(stateDir)', groups: ['hidden-predecessor'] },
  'legacy-replay': { file: trackedFile, guard: "entry.op === 'supersede' && entry.supersedes !== undefined && !forgotten.has(entry.id)",
    removed: "entry.op === 'supersede' && !forgotten.has(entry.id)", groups: ['legacy'] },
  'legacy-plan': { file: trackedFile, guard: "for (const entry of [...live.chain, ...planned]) if (entry.op === 'supersede' && entry.supersedes !== undefined)",
    removed: "for (const entry of [...live.chain, ...planned]) if (entry.op === 'supersede')", groups: ['legacy'] },
  'replay-mark': { file: trackedFile, guard: 'const replacements = supersessionLinks(chain, forgotten)', removed: 'const replacements = new Map()', groups: ['append'] },
  'ledger-graph': { file: trackedFile, guard: 'supersessions: supersessionLinks(live.chain, live.forgotten),', removed: '', groups: ['semantic-govern'] },
  'hide-eligible': { file: trackedFile, guard: 'if (![...(replacements.get(note.id)?.keys() ?? [])].some(id => ids.has(id))) return true', removed: 'return true',
    groups: ['lexical-hide', 'limit-hide', 'semantic-hide'] },
  'eligible-scope': { file: trackedFile, guard: 'const ids = new Set(eligible.map(note => note.id))', removed: 'const ids = new Set(annotated.map(note => note.id))', groups: ['mark', 'semantic-mark'] },
  'mark-returned': { file: semanticFile, guard: '...(note.supersededBy ? { supersededBy: note.supersededBy } : {}),', removed: '', groups: ['mark', 'hidden', 'semantic-mark'] },
  'ledger-authority': { file: trackedFile, guard: 'replacements.get(note.id)?.keys() ?? []',
    removed: 'new Map((note.supersededBy ?? []).map(one => [one.id, one])).keys()', groups: ['forged-metadata'] },
  'final-policy': { file: trackedFile, guard: '      p = await policy()\n      if (paused())', removed: '      if (paused())', groups: ['policy-race'] },
}
const subject = `aukora:1:${'53'.repeat(32)}`, otherSubject = `aukora:1:${'54'.repeat(32)}`
const clock = Date.parse('2026-10-14T02:03:04Z'), stamp = '2026-10-14T02:03:04Z'
const noneDropped = () => ({ unmapped: [], tampered: [], unreadable: [], belowThreshold: 0 })
let passed = 0, fixtureCount = 0, api

function importedSource(file, replacements = new Map()) {
  return readFileSync(file, 'utf8').replace(/(\bfrom\s+|\bimport\s*)(['"])(\.[^'"]+)\2/gu, (_, prefix, quote, target) => {
    const absolute = resolve(dirname(file), target)
    return `${prefix}${quote}${pathToFileURL(replacements.get(absolute) ?? absolute).href}${quote}`
  })
}
async function loadApi() {
  if (!mutant) return import(pathToFileURL(trackedFile).href)
  const mutation = mutations[mutant]
  assert.ok(mutation, 'known mutation required')
  const copies = new Map([[trackedFile, join(work, 'tracked-memory.mjs')], [semanticFile, join(work, 'recall-openviking.mjs')]])
  for (const [file, copy] of copies) {
    let source = importedSource(file, copies)
    if (file === mutation.file) {
      assert.equal(source.split(mutation.guard).length - 1, 1, `one production guard for ${mutant}`)
      source = source.replace(mutation.guard, mutation.removed)
    }
    writeFileSync(copy, source)
  }
  const loaded = await import(pathToFileURL(copies.get(trackedFile)).href)
  process.stdout.write(`MUTATION_APPLIED ${mutant}\n`)
  return loaded
}
async function check(group, action) {
  if (mutant && !mutations[mutant].groups.includes(group)) return
  await action(); passed++
}
function fixture(options = {}) {
  const stateDir = join(work, `store-${++fixtureCount}`)
  const make = (overrides = {}) => api.createTrackedMemory({ stateDir, subject, now: () => clock, ...options, ...overrides })
  return { stateDir, memory: make(), make }
}
const noteIds = result => result.notes.map(note => note.id)
const remember = async (memory, text, options = {}) => {
  const result = await memory.remember({ text, from: 'synthetic', ...options })
  assert.equal(result.ids.length, 1, 'synthetic notes are short single records')
  return result.ids[0]
}
function bytesBelow(path, prefix = '') {
  if (!existsSync(path)) return []
  return readdirSync(path, { withFileTypes: true }).flatMap(entry => {
    const name = `${prefix}${entry.name}`, file = join(path, entry.name)
    return entry.isDirectory() ? bytesBelow(file, `${name}/`) : [[name, readFileSync(file).toString('base64')]]
  }).sort(([a], [b]) => a.localeCompare(b))
}
async function refuses(memory, stateDir, code, input) {
  const before = bytesBelow(stateDir)
  await assert.rejects(memory.remember(input), error => error.message === code || error.code === code, code)
  assert.deepEqual(bytesBelow(stateDir), before, `${code} must not append a note or link`)
}
function move(stateDir, id, op) {
  const file = join(stateDir, STORE_PATHS.journal), lines = readFileSync(file, 'utf8').trim().split('\n')
  const previous = JSON.parse(lines.at(-1))
  const entry = nextEntry({ previous, op, id, objectDigest: id.slice(4), actor: 'synthetic', at: stamp })
  appendFileSync(file, `${JSON.stringify(entry)}\n`)
  assert.equal(verifyJournal(readFileSync(file, 'utf8').trim().split('\n')).ok, true)
}
function semanticClient(hitIds) {
  let memory
  return { bind: value => { memory = value }, configured: true,
    sync: async () => ({ added: 0, requests: 0, pending: 0, failed: [] }),
    recall: async () => ({ available: true, ledgerComplete: true, threshold: .4, dropped: noneDropped(),
      hits: hitIds().map(id => ({ id, score: .99, note: memory.read().notes.find(note => note.id === id), relevance: 'synthetic-semantic' })) }) }
}
function assertMarked(note, id, at = stamp) {
  assert.deepEqual(note.supersededBy, [{ id, at }], 'returned older notes name the successor and its link date')
  assert.equal(note.staleness.reason, 'superseded')
  assert.equal(note.advisoryOnly, true)
  assert.equal(note.grantsAuthority, false)
}
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
  return JSON.stringify(value)
}
function independentlyVerify(entries) {
  let prev = AURA_RECORD_DOMAIN
  for (const entry of entries) {
    const { prev: named, hash, ...fields } = entry
    assert.equal(named, prev)
    assert.equal(hash, createHash('sha256').update(canonical({ prev, ...fields, domain: AURA_RECORD_DOMAIN })).digest('hex'))
    prev = hash
  }
}

try {
  api = await loadApi()
  await check('invalid', async () => {
    const { memory, stateDir } = fixture(), older = await remember(memory, 'The cobalt restriction is written and parked.')
    for (const supersedes of [null, older, {}, [null], [12], ['not-a-note'], [`rem:${'A'.repeat(64)}`], [older, older]]) {
      await refuses(memory, stateDir, 'memory-supersedes-invalid', { text: 'The cobalt restriction has landed.', from: 'synthetic', supersedes })
    }
    assert.equal((await memory.remember({ text: 'A distinct ordinary note is still accepted.', from: 'synthetic', supersedes: [] })).remembered, 1)
  })
  await check('missing', async () => {
    const { memory, stateDir } = fixture(), older = await remember(memory, 'A cobalt memory exists before the rejected replacement.')
    await refuses(memory, stateDir, 'memory-supersedes-missing', { text: 'This successor names an absent note.', from: 'synthetic', supersedes: [`rem:${'1'.repeat(64)}`] })
    await refuses(memory, stateDir, 'memory-supersedes-missing', { text: 'This successor names one real and one absent note.', from: 'synthetic', supersedes: [older, `rem:${'1'.repeat(64)}`] })
  })
  await check('subject', async () => {
    const { memory, stateDir, make } = fixture(), foreign = await remember(make({ subject: otherSubject }), 'The other subject owns the silver restriction.')
    await refuses(memory, stateDir, 'memory-supersedes-subject', { text: 'A cobalt restriction replaces silver.', from: 'synthetic', supersedes: [foreign] })
    assert.equal(memory.read().notes.length, 0)
  })
  await check('subject-newer', async () => {
    const { memory, stateDir, make } = fixture(), text = 'The silver restriction belongs to the other subject.'
    await remember(make({ subject: otherSubject }), text)
    const own = await remember(memory, 'The cobalt restriction belongs to this subject.')
    await refuses(memory, stateDir, 'memory-supersedes-subject', { text, from: 'synthetic', supersedes: [own] })
  })
  await check('missing-newer', async () => {
    const { memory, stateDir } = fixture(), text = 'A cobalt successor was already forgotten.', newer = await remember(memory, text)
    const older = await remember(memory, 'The cobalt predecessor still exists.')
    assert.equal(buildRouteDeps({ stateDir, sessionsRoot: work, now: () => stamp }).forgetNote({ id: newer }).forgotten, true)
    await refuses(memory, stateDir, 'memory-supersedes-missing', { text, from: 'synthetic', supersedes: [older] })
  })
  await check('self', async () => {
    const { memory, stateDir } = fixture(), text = 'The cobalt restriction cannot supersede itself.', id = await remember(memory, text)
    await refuses(memory, stateDir, 'memory-supersedes-self', { text, from: 'synthetic', supersedes: [id] })
  })
  await check('cycle', async () => {
    const { memory, stateDir } = fixture(), text = 'The cobalt restriction was parked.', old = await remember(memory, text)
    const middle = await remember(memory, 'The cobalt restriction has landed.', { supersedes: [old] })
    const newest = await remember(memory, 'The cobalt restriction is deployed.', { supersedes: [middle] })
    await refuses(memory, stateDir, 'memory-supersedes-cycle', { text, from: 'synthetic', supersedes: [newest] })
  })
  await check('append', async () => {
    const { memory, stateDir, make } = fixture()
    const first = await remember(memory, 'The cobalt restriction was parked.'), second = await remember(memory, 'The cobalt restriction was awaiting review.')
    const file = join(stateDir, STORE_PATHS.rememberedAura), prefix = readFileSync(file, 'utf8')
    const objects = memory.read().notes.map(note => [join(stateDir, STORE_PATHS.remembered, objectFileName(note.id)), readFileSync(join(stateDir, STORE_PATHS.remembered, objectFileName(note.id)), 'utf8')])
    const newest = await remember(memory, 'The cobalt restriction has landed.', { at: '2026-08-01T00:00:00Z', supersedes: [first, second] })
    const appended = readFileSync(file, 'utf8')
    assert.equal(appended.slice(0, prefix.length), prefix, 'existing ledger bytes stay untouched')
    for (const [path, bytes] of objects) assert.equal(readFileSync(path, 'utf8'), bytes, 'older note object bytes stay untouched')
    const records = api.memoryChain(stateDir), links = records.filter(entry => entry.op === 'supersede')
    assert.equal(links.length, 1)
    assert.equal(links[0].id, newest)
    assert.deepEqual(links[0].supersedes, [first, second])
    assert.equal(links[0].at, stamp, 'replacement time is the wall clock rather than a historical note date')
    assert.equal(memory.read().notes.find(note => note.id === newest).observedAt, '2026-08-01T00:00:00Z')
    independentlyVerify(records)
    const replay = make().read()
    assert.deepEqual(replay.notes.find(note => note.id === first).supersededBy, [{ id: newest, at: stamp }])
    assert.deepEqual(replay.notes.find(note => note.id === second).supersededBy, [{ id: newest, at: stamp }])
    assert.deepEqual(noteIds(await make().recall({ question: 'cobalt restriction', lexical: true })), [newest])
  })
  await check('duplicate', async () => {
    const { memory, stateDir } = fixture(), old = await remember(memory, 'The cobalt restriction was parked.')
    const text = 'The cobalt restriction has landed.', newer = await remember(memory, text)
    const result = await memory.remember({ text, from: 'synthetic', supersedes: [old] })
    assert.equal(result.remembered, 0, 'a replacement may attach to an already remembered deterministic id')
    assert.deepEqual(result.ids, [newer])
    assert.equal(memory.read().notes.length, 2)
    assert.deepEqual(noteIds(await memory.recall({ question: 'cobalt restriction', lexical: true })), [newer])
    const before = bytesBelow(stateDir)
    await memory.remember({ text, from: 'synthetic', supersedes: [old] })
    assert.deepEqual(bytesBelow(stateDir), before, 'repeating a recorded replacement adds no redundant records')
  })
  await check('interrupted', async () => {
    const { memory, stateDir, make } = fixture(), old = await remember(memory, 'The cobalt restriction was parked.')
    const text = 'The cobalt restriction has landed.', newer = await remember(memory, text, { supersedes: [old] })
    const file = join(stateDir, STORE_PATHS.rememberedAura), lines = readFileSync(file, 'utf8').trim().split('\n')
    assert.equal(JSON.parse(lines.at(-1)).op, 'supersede')
    writeFileSync(file, `${lines.slice(0, -1).join('\n')}\n`)
    assert.equal(make().read().notes.find(note => note.id === old).supersededBy, undefined)
    const prefix = readFileSync(file, 'utf8'), retry = await make().remember({ text, from: 'synthetic', supersedes: [old] })
    assert.equal(retry.remembered, 0); assert.deepEqual(retry.ids, [newer])
    assert.equal(readFileSync(file, 'utf8').slice(0, prefix.length), prefix)
    assert.equal(api.memoryChain(stateDir).filter(entry => entry.op === 'supersede').length, 1)
    independentlyVerify(api.memoryChain(stateDir))
    assert.deepEqual(noteIds(await make().recall({ question: 'cobalt restriction', lexical: true })), [newer])
  })
  await check('forged-metadata', async () => {
    const { memory } = fixture(), newer = await remember(memory, 'A newer cobalt restriction note does not declare a replacement.')
    const old = await remember(memory, 'An older cobalt restriction note carries a caller claim.', { metadata: { supersededBy: [{ id: newer, at: stamp }] } })
    assert.deepEqual(noteIds(await memory.recall({ question: 'cobalt restriction', lexical: true })).sort(), [old, newer].sort(),
      'metadata cannot hide a note without a hashed replacement record')
  })
  await check('lexical-hide', async () => {
    const { memory } = fixture(), old = await remember(memory, 'The cobalt restriction is written and parked.')
    const newer = await remember(memory, 'The cobalt restriction has landed and is enabled.', { supersedes: [old] })
    assert.deepEqual(noteIds(await memory.recall({ question: 'cobalt restriction', lexical: true })), [newer])
    assert.equal((await memory.recall({ question: 'written parked', lexical: true })).notes.length, 0,
      'an eligible successor hides old matching words even when it does not match the query')
  })
  await check('limit-hide', async () => {
    const { memory } = fixture(), old = await remember(memory, 'The cobalt restriction cobalt restriction cobalt restriction was parked.')
    const newer = await remember(memory, 'The cobalt restriction has landed.', { supersedes: [old] })
    const unrelated = await remember(memory, 'Another cobalt restriction was discussed without a replacement link.')
    const answer = await memory.recall({ question: 'cobalt restriction', limit: 1, lexical: true })
    assert.equal(answer.notes.length, 1)
    assert.ok([newer, unrelated].includes(answer.notes[0].id), 'limit cannot return a higher-ranked superseded note')
  })
  await check('semantic-hide', async () => {
    let old
    const client = semanticClient(() => [old]), { memory } = fixture({ client })
    client.bind(memory)
    old = await remember(memory, 'The cobalt restriction is written and parked.')
    await remember(memory, 'The safety limit now operates.', { supersedes: [old] })
    const answer = await memory.recall({ question: 'a synthetic query with no matching words', limit: 1 })
    assert.equal(answer.semantic.available, true)
    assert.equal(answer.notes.length, 0, 'a stale semantic result cannot bypass final replacement filtering')
  })
  await check('semantic-govern', async () => {
    let old, governed
    const client = { configured: true, sync: async () => ({ added: 0, requests: 0, pending: 0, failed: [] }),
      recall: async ({ live, govern }) => {
        const snapshot = live(); governed = govern([...snapshot.entries.values()], snapshot)
        return { available: true, ledgerComplete: true, threshold: .4, dropped: noneDropped(),
          hits: governed.filter(note => note.id === old).map(note => ({ id: note.id, score: .99, note, relevance: 'synthetic-semantic' })) }
      } }
    const { memory } = fixture({ client })
    old = await remember(memory, 'The cobalt restriction was parked.')
    const newer = await remember(memory, 'The safety limit now operates.', { supersedes: [old] })
    const answer = await memory.recall({ question: 'a synthetic query with no matching words' })
    assert.equal(answer.semantic.available, true)
    assert.deepEqual(governed.map(note => note.id), [newer], 'semantic governance sees all eligible successors before ranking')
    assert.equal(answer.notes.length, 0)
  })
  await check('policy-race', async () => {
    let old, memory, armed = false, policyReads = 0
    const client = { configured: true, sync: async () => ({ added: 0, requests: 0, pending: 0, failed: [] }),
      recall: async ({ live, govern }) => {
        const snapshot = live(), initial = govern([...snapshot.entries.values()], snapshot)
        assert.deepEqual(initial.map(note => note.id), [old], 'the initial scope makes the successor ineligible')
        return { available: true, ledgerComplete: true, threshold: .4, dropped: noneDropped(),
          hits: [{ id: old, score: .99, note: memory.read().notes.find(note => note.id === old), relevance: 'synthetic-semantic' }] }
      } }
    const run = fixture({ client, policyOf: async () => !armed ? {} : { sessionId: ++policyReads === 1 ? 'outside' : 'private' } })
    memory = run.memory
    old = await remember(memory, 'The cobalt restriction was parked.')
    await remember(memory, 'The safety limit now operates.', { scope: 'session:private', supersedes: [old] })
    armed = true
    const answer = await memory.recall({ question: 'a synthetic query with no matching words' })
    assert.equal(answer.semantic.available, true)
    assert.equal(policyReads, 2, 'recall refreshes policy after the semantic wait')
    assert.equal(answer.notes.length, 0, 'the newly eligible successor hides the initially eligible older result')
  })
  await check('mark', async () => {
    const { memory } = fixture(), old = await remember(memory, 'The cobalt restriction is written and parked.')
    const newer = await remember(memory, 'The cobalt restriction has landed.', { scope: 'session:private', supersedes: [old] })
    const outside = await memory.recall({ question: 'cobalt restriction', lexical: true })
    assert.deepEqual(noteIds(outside), [old]); assertMarked(outside.notes[0], newer)
    assert.deepEqual(noteIds(await memory.recall({ question: 'cobalt restriction', lexical: true, context: { sessionId: 'private' } })), [newer])
  })
  await check('hidden', async () => {
    const { memory, stateDir } = fixture(), old = await remember(memory, 'The cobalt restriction is written and parked.')
    const newer = await remember(memory, 'The cobalt restriction has landed.', { supersedes: [old] })
    move(stateDir, newer, 'hide')
    const answer = await memory.recall({ question: 'cobalt restriction', lexical: true })
    assert.deepEqual(noteIds(answer), [old]); assertMarked(answer.notes[0], newer)
  })
  await check('hidden-predecessor', async () => {
    const { memory, stateDir, make } = fixture(), old = await remember(memory, 'The cobalt restriction was parked.')
    move(stateDir, old, 'hide')
    assert.equal(make().read().notes.length, 0)
    assert.equal(Object.hasOwn(make().read(), 'hiddenNotes'), false, 'ordinary read does not expose hidden note bodies')
    assert.equal(Object.hasOwn(api.readTrackedMemory(stateDir), 'hiddenNotes'), false)
    const planner = api.readTrackedMemory(stateDir, { includeHidden: true })
    assert.equal(planner.notes.length, 0, 'the planner snapshot still excludes hidden notes from ordinary recall candidates')
    assert.deepEqual(planner.hiddenNotes.map(note => note.id), [old])
    const newer = await remember(make(), 'The cobalt restriction has landed.', { supersedes: [old] })
    assert.deepEqual(noteIds(await make().recall({ question: 'cobalt restriction', lexical: true })), [newer])
    move(stateDir, old, 'unhide')
    assert.deepEqual(noteIds(await make().recall({ question: 'cobalt restriction', lexical: true })), [newer])
    assert.equal(buildRouteDeps({ stateDir, sessionsRoot: work, now: () => stamp }).forgetNote({ id: newer }).forgotten, true)
    assert.deepEqual(noteIds(await make().recall({ question: 'cobalt restriction', lexical: true })), [old])
  })
  await check('semantic-mark', async () => {
    let old
    const client = semanticClient(() => [old]), { memory } = fixture({ client })
    client.bind(memory)
    old = await remember(memory, 'The cobalt restriction was parked.')
    const newer = await remember(memory, 'The safety limit now operates.', { scope: 'session:private', supersedes: [old] })
    const answer = await memory.recall({ question: 'a synthetic query with no matching words' })
    assert.deepEqual(noteIds(answer), [old]); assertMarked(answer.notes[0], newer)
  })
  await check('forget', async () => {
    const { memory, stateDir, make } = fixture(), old = await remember(memory, 'The cobalt restriction was parked.')
    const newer = await remember(memory, 'The cobalt restriction has landed.', { supersedes: [old] })
    const ledgerBefore = readFileSync(join(stateDir, STORE_PATHS.rememberedAura), 'utf8')
    const result = buildRouteDeps({ stateDir, sessionsRoot: work, now: () => stamp }).forgetNote({ id: newer, reason: 'synthetic' })
    assert.equal(result.forgotten, true)
    assert.equal(readFileSync(join(stateDir, STORE_PATHS.rememberedAura), 'utf8'), ledgerBefore)
    const answer = await make().recall({ question: 'cobalt restriction', lexical: true })
    assert.deepEqual(noteIds(answer), [old])
    assert.ok(!answer.notes[0].supersededBy?.length, 'forgetting the successor deactivates its link after restart')
    assert.notEqual(answer.notes[0].staleness?.reason, 'superseded')
    independentlyVerify(api.memoryChain(stateDir))
  })
  await check('chain', async () => {
    const { memory, stateDir, make } = fixture(), old = await remember(memory, 'The cobalt restriction was parked.')
    const middle = await remember(memory, 'The cobalt restriction has landed.', { supersedes: [old] })
    const newest = await remember(memory, 'The cobalt restriction is deployed.', { supersedes: [middle] })
    assert.deepEqual(noteIds(await make().recall({ question: 'cobalt restriction', lexical: true })), [newest])
    buildRouteDeps({ stateDir, sessionsRoot: work, now: () => stamp }).forgetNote({ id: newest })
    assert.deepEqual(noteIds(await make().recall({ question: 'cobalt restriction', lexical: true })), [middle])
    buildRouteDeps({ stateDir, sessionsRoot: work, now: () => stamp }).forgetNote({ id: middle })
    assert.deepEqual(noteIds(await make().recall({ question: 'cobalt restriction', lexical: true })), [old])
  })
  await check('multiple-successors', async () => {
    const { memory, stateDir } = fixture(), old = await remember(memory, 'The cobalt restriction was parked.')
    const privateNewer = await remember(memory, 'The cobalt restriction was reviewed privately.', { scope: 'session:private', supersedes: [old] })
    const publicNewer = await remember(memory, 'The cobalt restriction has landed.', { supersedes: [old] })
    assert.deepEqual(noteIds(await memory.recall({ question: 'cobalt restriction', lexical: true })), [publicNewer])
    buildRouteDeps({ stateDir, sessionsRoot: work, now: () => stamp }).forgetNote({ id: publicNewer })
    const answer = await memory.recall({ question: 'cobalt restriction', lexical: true })
    assert.deepEqual(noteIds(answer), [old]); assertMarked(answer.notes[0], privateNewer)
  })
  await check('legacy', async () => {
    const { memory, stateDir } = fixture(), text = 'A cobalt restriction in the unchanged historical note format.'
    const note = buildRememberedNote({ category: 'observation', statement: text, attributedTo: 'owner',
      evidence: [{ log: 'synthetic', turn: 0, turnDigest: sha256Hex(text), quote: text }], validFrom: '2026-08-01', observedAt: '2026-08-01T00:00:00Z',
      confidence: 1, sensitivity: 'none', privacy: 'local', subject, scope: 'owner', salt: '8'.repeat(64),
      source: { state: 'UNLINKED', cited: false, because: 'historical direct capture' }, origin: { by: 'synthetic', run: '9'.repeat(64) } })
    const stored = { ...note, aura: { index: 0, entryHash: sha256Hex(`${note.id}\0${note.contentHash}`) }, bodyAtCapture: null }
    const fields = { op: 'remember', id: note.id, at: note.observedAt, tier: 'remembered', by: 'kira.capture/v2',
      digest: note.contentHash, contentHash: note.contentHash, index: 0, entryHash: stored.aura.entryHash,
      originKey: note.origin.run, captureKey: note.origin.run, bodyAtCapture: null, sequence: 1 }
    const hash = createHash('sha256').update(canonical({ prev: AURA_RECORD_DOMAIN, ...fields, domain: AURA_RECORD_DOMAIN })).digest('hex')
    const entry = { ...fields, prev: AURA_RECORD_DOMAIN, hash }
    const dir = join(stateDir, STORE_PATHS.remembered); mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, objectFileName(note.id)), `${JSON.stringify(stored)}\n`)
    const legacyFields = { op: 'supersede', id: note.id, at: '2026-08-02T00:00:00Z', by: 'kira.housekeeping/v1',
      because: `exact duplicate of rem:${'7'.repeat(64)}`, sequence: 2 }
    const legacyHash = createHash('sha256').update(canonical({ prev: hash, ...legacyFields, domain: AURA_RECORD_DOMAIN })).digest('hex')
    const legacyMove = { ...legacyFields, prev: hash, hash: legacyHash }
    const aura = `${JSON.stringify(entry)}\n${JSON.stringify(legacyMove)}\n`, file = join(stateDir, STORE_PATHS.rememberedAura)
    writeFileSync(file, aura)
    const journal = nextEntry({ op: 'add', id: note.id, objectDigest: note.contentHash, actor: 'kira.capture/v2', at: note.observedAt })
    const legacyJournal = nextEntry({ previous: journal, op: 'supersede', id: note.id, objectDigest: note.id.slice(4),
      actor: legacyMove.by, reason: legacyMove.because, at: legacyMove.at })
    writeFileSync(join(stateDir, STORE_PATHS.journal), `${JSON.stringify(journal)}\n${JSON.stringify(legacyJournal)}\n`)
    assert.equal(Object.hasOwn(entry, 'supersedes'), false)
    assert.equal(Object.hasOwn(legacyMove, 'supersedes'), false, 'pre-change housekeeping supersede records have no graph array')
    assert.equal(memory.read().complete, true)
    assert.equal(memory.read().notes[0].supersededBy, undefined, 'a legacy move does not invent a successor id')
    independentlyVerify(api.memoryChain(stateDir))
    assert.deepEqual(noteIds(await memory.recall({ question: 'cobalt restriction', lexical: true })), [note.id])
    assert.equal(readFileSync(file, 'utf8'), aura, 'verification and recall do not rewrite a pre-change ledger')
    const newer = await remember(memory, 'The cobalt restriction in the historical note has landed.', { supersedes: [note.id] })
    assert.equal(readFileSync(file, 'utf8').slice(0, aura.length), aura)
    assert.deepEqual(noteIds(await memory.recall({ question: 'cobalt restriction', lexical: true })), [newer])
  })
  console.log(`kira-memory-supersession: ${passed} checks PASS (refusals, hashed links, hide/mark/un-hide, restart and legacy ledger; no sockets)`)
  if (!mutant && process.argv.includes('--mutations')) {
    let killed = 0
    for (const name of Object.keys(mutations)) {
      const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--mutant', name], { cwd: ROOT, encoding: 'utf8', timeout: 30_000 })
      assert.ok(child.stdout.includes(`MUTATION_APPLIED ${name}`), `${name} must load its changed production module`)
      assert.notEqual(child.status, 0, `${name} protection removal must fail its behavior test`)
      killed++
    }
    assert.ok(killed > 0, 'protection mutations are required')
    console.log(`kira-memory-supersession: mutations ${killed}/${Object.keys(mutations).length} killed`)
  }
} finally { rmSync(work, { recursive: true, force: true }) }
