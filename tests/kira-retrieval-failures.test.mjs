#!/usr/bin/env node
/** Actual store -> OpenViking bridge -> header, with disposable deterministic HTTP responses only. */
import assert from 'node:assert/strict'
import { test, after } from 'node:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { registerHooks } from 'node:module'

const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
assert(mutantAt < 0 || ['drop-projection', 'guess-embedding', 'truncate-before-dedup'].includes(mutant), 'unknown or missing mutant')
let applied = false
if (mutant) registerHooks({ load(url, context, next) {
  const loaded = next(url, context)
  const file = mutant === 'drop-projection' ? 'tracked-memory.mjs'
    : mutant === 'guess-embedding' ? 'recall-openviking.mjs' : 'injection.mjs'
  if (url !== new URL(`../plugins/aukora-kira/lib/${file}`, import.meta.url).href) return loaded
  const source = typeof loaded.source === 'string' ? loaded.source : Buffer.from(loaded.source).toString('utf8')
  const before = mutant === 'drop-projection' ? 'failures: answer.failures'
    : mutant === 'guess-embedding' ? "  cause: 'unknown',\n" : 'semantic.failures.slice(0, 64)'
  assert.equal(source.split(before).length - 1, mutant === 'drop-projection' ? 2 : 1, 'actual production anchor must match')
  applied = true
  const replacement = mutant === 'drop-projection' ? 'failures: undefined'
    : mutant === 'guess-embedding' ? "  cause: 'embedding-call',\n" : 'semantic.failures.slice(0, 8)'
  return { ...loaded, source: source.replaceAll(before, replacement) }
} })
const { recallDiagnostics, recalledContextLine } = await import('../plugins/aukora-kira/lib/injection.mjs')
const { createTrackedMemory } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
if (mutant) assert.equal(applied, true, 'mutant must load the real production module')

const root = mkdtempSync(join(tmpdir(), 'kira-retrieval-failures-'))
after(() => rmSync(root, { recursive: true, force: true }))
const canary = 'PRIVATE-ERROR-BODY-DO-NOT-PUBLISH'
let fixtureId = 0
function fixture(syncBatch = 2) {
  const files = new Map(), failures = new Map(), calls = []
  const fetch = async (url, options = {}) => {
    const path = new URL(url).pathname
    calls.push(path)
    if (failures.has(path)) {
      const failure = failures.get(path)
      if (failure instanceof Error) throw failure
      if (failure.invalidJson) return new Response('{invalid-json', { status: failure.status })
      return Response.json(failure.body ?? { status: 'error', error: canary }, { status: failure.status })
    }
    if (path === '/health') return Response.json({ healthy: true })
    const body = options.body ? JSON.parse(options.body) : {}
    let result
    if (path === '/api/v1/content/write') { files.set(body.uri, body.content); result = {} }
    else if (path === '/api/v1/content/read') result = files.get(new URL(url).searchParams.get('uri'))
    else if (path === '/api/v1/search/find') result = { memories: [...files.keys()].map(uri => ({ uri, score: .8 })) }
    else throw new Error(`unexpected fixture route ${path}`)
    return Response.json({ status: 'ok', result })
  }
  const memory = createTrackedMemory({ stateDir: join(root, String(++fixtureId)), subject: `aukora:1:${'3c'.repeat(32)}`,
    config: { configured: true, url: 'http://scratch.invalid', user: 'scratch', account: 'scratch', key: 'inert-fixture', syncBatch }, fetch })
  return { memory, failures, calls }
}
const recall = memory => memory.recall({ question: 'blue telescope' })
const remember = memory => memory.remember({ text: 'The blue telescope stands beside the orchard.', from: 'scratch' })
const header = reply => recalledContextLine({ availability: reply.state, snippets: [], semantic: reply.semantic })
const failure = (call, httpStatus) => ({ call, cause: 'unknown', httpStatus })

test('failed content write survives successful search and tracked-memory projection', async () => {
  const run = fixture()
  run.failures.set('/api/v1/content/write', { status: 500 })
  const stored = await remember(run.memory)
  assert.equal(stored.remembered, 1)
  assert.deepEqual(stored.index.failed, ['index-write-failed'])
  assert.deepEqual(stored.index.failures, [failure('content-write', 500)])
  const answer = await recall(run.memory)
  assert.equal(answer.semantic.available, true)
  assert.deepEqual(answer.semantic.failures, [failure('content-write', 500)])
  assert.equal(run.memory.read().notes.length, 1, 'index failure must preserve the captured note')
  const text = header(answer)
  assert.match(text, /Semantic: available=1, unavailable=0/u)
  assert.match(text, /call=content-write, upstream=unknown, HTTP=500/u)
  assert.doesNotMatch(text, /embedding-call|PRIVATE-ERROR|scratch\.invalid|inert-fixture/u)
})

test('search failure keeps its route while collapsed embedding text remains unknown', async () => {
  const run = fixture()
  await remember(run.memory)
  run.failures.set('/api/v1/search/find', { status: 422, body: { status: 'error',
    error: { type: 'EmbeddingError', message: `${canary}: /v1/embeddings failed`, code: 'embedding_failed' } } })
  const answer = await recall(run.memory)
  assert.equal(answer.semantic.available, false)
  assert.equal(answer.semantic.reason, 'semantic-recall-failed')
  assert.deepEqual(answer.semantic.failures, [failure('search', 422)])
  assert.match(header(answer), /call=search, upstream=unknown, HTTP=422/u)
  assert.doesNotMatch(header(answer), /EmbeddingError|embedding-call|embedding_failed|PRIVATE-ERROR|\/v1\/embeddings/u)
})

test('write and search failures both remain visible without changing request budget', async () => {
  const run = fixture()
  run.failures.set('/api/v1/content/write', { status: 413 })
  await remember(run.memory)
  run.failures.set('/api/v1/search/find', { status: 503 })
  run.calls.length = 0
  const answer = await recall(run.memory)
  assert.deepEqual(answer.semantic.failures, [failure('content-write', 413), failure('search', 503)])
  assert.deepEqual(run.calls, ['/health', '/api/v1/content/write', '/api/v1/search/find'])
  assert.match(header(answer), /call=content-write, upstream=unknown, HTTP=413/u)
  assert.match(header(answer), /call=search, upstream=unknown, HTTP=503/u)
})

test('a full eight-write refusal batch cannot hide the following search failure', async () => {
  const run = fixture(8)
  run.failures.set('/api/v1/content/write', { status: 413 })
  await run.memory.rememberBatch(Array.from({ length: 8 }, (_, i) => ({
    text: `The blue telescope stands beside orchard number ${i}.`, from: 'scratch',
  })))
  assert.equal(run.memory.read().notes.length, 8)
  run.failures.set('/api/v1/search/find', { status: 503 })
  run.calls.length = 0
  const answer = await recall(run.memory)
  assert.equal(answer.semantic.failures.length, 9)
  assert.equal(run.calls.filter(path => path === '/api/v1/content/write').length, 8)
  assert.equal(run.calls.at(-1), '/api/v1/search/find')
  const text = header(answer)
  assert.match(text, /call=content-write, upstream=unknown, HTTP=413/u)
  assert.match(text, /call=search, upstream=unknown, HTTP=503/u)
})

test('content-read outage is other and must not be relabelled as a search failure', async () => {
  const run = fixture()
  await remember(run.memory)
  run.failures.set('/api/v1/content/read', { status: 503 })
  const answer = await recall(run.memory)
  assert.equal(answer.semantic.available, false)
  assert.deepEqual(answer.semantic.failures, [failure('other', 503)])
  assert.match(header(answer), /call=other, upstream=unknown, HTTP=503/u)
  assert.doesNotMatch(header(answer), /call=search/u)
})

test('invalid response JSON retains observed HTTP status; transport failure has no status', async () => {
  const run = fixture()
  await remember(run.memory)
  run.failures.set('/api/v1/search/find', { status: 502, invalidJson: true })
  assert.deepEqual((await recall(run.memory)).semantic.failures, [failure('search', 502)])
  run.failures.set('/api/v1/search/find', new Error(`${canary}: embedding transport`))
  const answer = await recall(run.memory)
  assert.deepEqual(answer.semantic.failures, [failure('search', null)])
  assert.match(header(answer), /call=search, upstream=unknown, HTTP=unknown/u)
  assert.doesNotMatch(header(answer), /PRIVATE-ERROR|embedding-call/u)
})

test('collapsed supplier diagnostics default to unknown, including a healthy sibling read', () => {
  const reply = { availability: 'undetermined', snippets: [], retrieval: [
    { leg: 'remembered', availability: 'undetermined', ...recallDiagnostics({ semantic: { available: false, reason: 'semantic-recall-failed' } }) },
    { leg: 'remembered', availability: 'found', ...recallDiagnostics({ semantic: { available: true } }) },
  ] }
  const text = recalledContextLine(reply)
  assert.match(text, /readable\/found attempts=1, readable\/empty attempts=0, unavailable attempts=1/u)
  assert.match(text, /partial failure, absence not established/u)
  assert.match(text, /call=unknown, upstream=unknown, HTTP=unknown/u)
  assert.doesNotMatch(text, /embedding-call/u)
})

test('header accepts only bounded fixed diagnostic fields and retains shared character limits', () => {
  const values = [{ call: 'search', cause: 'embedding-call', httpStatus: 500, message: canary },
    { call: canary, cause: canary, httpStatus: canary }, null,
    ...Array.from({ length: 30 }, (_, i) => ({ call: 'search', cause: 'unknown', httpStatus: 500 + i }))]
  // This checks the header's closed internal tuple protocol only. It does not
  // qualify any upstream embedding-error schema or a live embedding call.
  const diagnostics = recallDiagnostics({ semantic: { available: false, reason: canary, failures: values } })
  assert.ok(diagnostics.semantic.failures.length <= 8)
  assert.equal(diagnostics.semantic.reason, 'semantic-recall-failed')
  assert.deepEqual(diagnostics.semantic.failures[1], failure('unknown', null))
  const reply = { availability: 'undetermined', snippets: [], retrieval: [
    { leg: 'remembered', availability: 'undetermined', ...diagnostics },
  ] }
  const text = recalledContextLine(reply)
  assert.match(text, /call=search, upstream=embedding-call, HTTP=500/u)
  assert.doesNotMatch(text, /PRIVATE-ERROR/u)
  for (const maxChars of [0, 100, 600, 1200, 2400]) assert.ok(recalledContextLine(reply, undefined, { maxChars }).length <= maxChars)
})

test('healthy semantic recall emits no failed-call header', async () => {
  const run = fixture()
  await remember(run.memory)
  const answer = await recall(run.memory)
  assert.equal(answer.semantic.available, true)
  assert.deepEqual(answer.semantic.failures, [])
  assert.equal(answer.notes.length, 1)
  assert.doesNotMatch(header(answer), /Semantic failed calls/u)
})
