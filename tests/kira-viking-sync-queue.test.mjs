// SPDX-License-Identifier: AGPL-3.0-or-later
// Deferred and unaffordable legacy entries cannot block later bounded writes.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const target = new URL('../plugins/aukora-kira/lib/recall-openviking.mjs', import.meta.url).href
const mutantAt = process.argv.indexOf('--mutant'), mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
const mutations = {
  'affordable-selection': ['candidates.filter(([uri]) => !acknowledged(acknowledgements[uri]) || requests + 2 <= budget)', 'candidates'],
  'legacy-budget-continue': ["if (requests + 2 > budget) {\n            if (budget < 2) failed.push('index-migration-budget-too-small')\n            continue", "if (requests + 2 > budget) {\n            if (budget < 2) failed.push('index-migration-budget-too-small')\n            break"],
  'budget-refusal': ["if (budget > requests && candidates.length && !selected.length) failed.push('index-migration-budget-too-small')", 'void 0'],
  'failed-head-continues': ['recordFailure(uri, notes, error)', 'recordFailure(uri, notes, error); break'],
  'deferred-head-selection': ['acknowledgements[uri].retry.nextRetryAt <= now()', 'true'],
}
let applied = 0
if (mutant) {
  assert.ok(mutations[mutant], 'known queue mutation required')
  registerHooks({ load(url, context, nextLoad) {
    const loaded = nextLoad(url, context)
    if (url !== target) return loaded
    const source = String(loaded.source), [guard, removed] = mutations[mutant]
    assert.equal(source.split(guard).length - 1, 1, 'queue mutation guard must exist exactly once')
    applied++
    return { ...loaded, source: source.replace(guard, removed) }
  } })
}
const { createOpenVikingRecall, contentDocuments } = await import(target)
const { contentHash } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
const config = { configured: true, url: 'http://127.0.0.1:49671', account: 'scratch', user: 'scratch', key: 'inert-synthetic', syncBatch: 1 }
const work = mkdtempSync(join(root, 'tests/.viking-queue-'))
let fixtureCount = 0, passed = 0
function fixture(total, legacy = 1) {
  const stateDir = join(work, String(++fixtureCount)), calls = [], files = new Map()
  const notes = Array.from({ length: total }, (_, index) => {
    const statement = `Synthetic queue record ${index} preserves a distinct observatory calibration measurement.`
    return { id: `rem:${(index + 1).toString(16).padStart(64, '0')}`, statement, contentHash: contentHash(statement) }
  })
  const documents = notes.map(note => contentDocuments(config.user, note)[0])
  const ackPath = join(stateDir, 'remembered/index/ack.json'), acknowledgements = {}
  for (let index = 0; index < legacy; index++) {
    files.set(documents[index].uri, documents[index].content)
    acknowledgements[documents[index].uri] = { ids: [notes[index].id], contentHash: notes[index].contentHash }
  }
  mkdirSync(join(stateDir, 'remembered/index'), { recursive: true })
  writeFileSync(ackPath, JSON.stringify(acknowledgements))
  const fetch = async (url, options = {}) => {
    const parsed = new URL(url), body = options.body ? JSON.parse(options.body) : {}, uri = body.uri ?? parsed.searchParams.get('uri')
    calls.push({ method: options.method ?? 'GET', uri })
    if (parsed.pathname === '/api/v1/content/read') {
      if (!files.has(uri)) return Response.json({ status: 'error' }, { status: 404 })
      return Response.json({ status: 'ok', result: files.get(uri) })
    }
    assert.equal(parsed.pathname, '/api/v1/content/write'); assert.equal(options.method, 'POST')
    files.set(uri, body.content)
    return Response.json({ status: 'ok', result: { vector_status: 'complete' } })
  }
  const live = { entries: new Map(notes.map(note => [note.id, note])), complete: true }, at = 100_000
  const bridge = createOpenVikingRecall({ stateDir, config, fetch, now: () => at })
  return { bridge, live, notes, documents, files, calls, ackPath, at }
}
async function check(name, action) { await action(); passed++; process.stdout.write(`PASS ${name}\n`) }
try {
  await check('legacy mismatch at the head waits for retry while all 217 later entries drain', async () => {
    const run = fixture(218), head = run.documents[0], different = 'Synthetic stored calibration has different bytes.'
    run.files.set(head.uri, different)
    let report = await run.bridge.sync(run.live, { budget: 8, removeStale: false })
    assert.equal(report.indexed, 7); assert.equal(report.pending, 211)
    assert.deepEqual(report.failedIds, [run.notes[0].id])
    assert.equal(report.recordFailures[0].reason, 'index-content-mismatch')
    assert.equal(report.recordFailures[0].nextRetryAt, run.at + 30_000)
    report = await run.bridge.sync(run.live, { budget: 8, removeStale: false })
    assert.equal(report.indexed, 15); assert.equal(report.requests, 8)
    let rounds = 2
    while (report.retryable > 0 && rounds++ < 30) report = await run.bridge.sync(run.live, { budget: 8, removeStale: false })
    assert.equal(report.indexed, 217); assert.equal(report.pending, 1); assert.equal(report.retryable, 0); assert.equal(report.deferred, 1)
    assert.equal(run.calls.filter(call => call.uri === head.uri).length, 1)
    assert.equal(run.calls.filter(call => call.method === 'POST').length, 217)
    assert.equal(run.files.get(head.uri), different)
    assert.equal(JSON.parse(readFileSync(run.ackPath, 'utf8'))[head.uri].retry.attempts, 1)
  })
  await check('one-request batches pass an unaffordable legacy head and name the remaining budget refusal', async () => {
    const run = fixture(4), head = run.documents[0]
    for (let indexed = 1; indexed <= 3; indexed++) {
      const report = await run.bridge.sync(run.live, { budget: 1, removeStale: false })
      assert.equal(report.indexed, indexed); assert.equal(report.requests, 1)
      assert.deepEqual(report.failed, [])
    }
    const blocked = await run.bridge.sync(run.live, { budget: 1, removeStale: false })
    assert.equal(blocked.indexed, 3); assert.equal(blocked.pending, 1); assert.equal(blocked.requests, 0)
    assert.deepEqual(blocked.failed, ['index-migration-budget-too-small'])
    assert.equal(run.calls.some(call => call.uri === head.uri), false)
    assert.equal((await run.bridge.sync(run.live, { budget: 2, removeStale: false })).indexed, 4)
  })
  await check('a legacy entry that no longer fits lets a selected fresh entry use the last request', async () => {
    const run = fixture(3, 2), report = await run.bridge.sync(run.live, { budget: 3, removeStale: false })
    assert.equal(report.indexed, 2); assert.equal(report.pending, 1); assert.equal(report.requests, 3)
    assert.equal(run.calls.some(call => call.uri === run.documents[1].uri), false)
    assert.equal(run.calls.some(call => call.method === 'POST' && call.uri === run.documents[2].uri), true)
  })
  if (mutant) assert.ok(applied > 0, 'queue mutation must load production code')
  else {
    let killed = 0
    for (const name of Object.keys(mutations)) {
      const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--mutant', name], { cwd: root, encoding: 'utf8', timeout: 20_000 })
      assert.equal(result.status, 1, `${name}: mutant must fail its protection assertion`)
      assert.match(result.stderr, /AssertionError/u)
      assert.doesNotMatch(result.stderr, /queue mutation guard must exist|queue mutation must load production code|known queue mutation required/u)
      assert.ok(!result.error, `${name}: mutant must fail without timing out`); killed++
    }
    process.stdout.write(`kira-viking-sync-queue: ${killed}/${Object.keys(mutations).length} protection mutants killed\n`)
  }
  process.stdout.write(`kira-viking-sync-queue: ${passed} passed, 0 failed (synthetic injected transport)\n`)
} finally { rmSync(work, { recursive: true, force: true }) }
