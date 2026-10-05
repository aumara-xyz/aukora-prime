#!/usr/bin/env node
/** Actual production bridge/store; synthetic bytes and a deterministic local
 * provider stand-in. This does not qualify installed tokenization or embeddings. */
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
const mutantAt = process.argv.indexOf('--mutant')
const mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1] ?? 'embedding-document-unbounded'
const mutations = {
  'embedding-document-unbounded': ['uri, content: document.content, mode:', 'uri, content: notes[0].statement, mode:'],
  'embedding-span-unchecked': ['if (matches.some(note => !matchesDocument(note, uri, bytes))) {', 'if (false) {'],
  'refused-document-starves': ['for (const [uri, notes] of selected) {\n      try {', 'for (const [uri, notes] of selected) {\n      if (failed.length) break\n      try {'],
  'outage-continues': ["if (error.code !== 'kira.semantic:refused' || ![400, 413, 422].includes(error.httpStatus)) break", 'if (false) break'],
  'shared-capture-deleted': ['if (remaining.length) ack(uri, remaining, entry?.contentHash ?? null)', 'if (false) ack(uri, remaining, entry?.contentHash ?? null)'],
  'incomplete-shrinks-shared-capture': ['const ids = latest.complete ? liveIds : [...new Set([...idsOf(prior), ...liveIds])]', 'const ids = liveIds'],
  'written-incomplete-shrinks': ['ack(uri, latest.complete ? ids : [...new Set([...idsOf(acknowledgements[uri]), ...ids])]); added++', 'ack(uri, ids); added++'],
}
let mutated = 0
if (mutant) {
  assert.ok(mutations[mutant], 'unknown mutation')
  const target = new URL('../plugins/aukora-kira/lib/recall-openviking.mjs', import.meta.url).href
  registerHooks({ load(url, context, nextLoad) {
    const loaded = nextLoad(url, context)
    if (url !== target) return loaded
    const source = String(loaded.source), [guard, removed] = mutations[mutant]
    assert.equal(source.split(guard).length - 1, 1)
    mutated++
    return { ...loaded, source: source.replace(guard, removed) }
  } })
}
const { createTrackedMemory, memoryChain, contentHash } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
const { createOpenVikingRecall, contentDocuments } = await import('../plugins/aukora-kira/lib/recall-openviking.mjs')
const { embeddingParts, MAX_EMBEDDING_CONTENT_BYTES } = await import('../plugins/aukora-kira/lib/memory-input-bounds.mjs')
const root = mkdtempSync(join(tmpdir(), 'kira-index-parts-'))
const config = { configured: true, url: 'http://fixture.invalid', user: 'scratch', account: 'scratch', key: 'synthetic-only', syncBatch: 8, candidates: 50 }
const subject = `aukora:1:${'4d'.repeat(32)}`
const files = new Map(), calls = [], rejected = new Set()
let offline = false, offlineStatus = 0, hits
const fakeFetch = async (url, options = {}) => {
  const u = new URL(url), body = options.body ? JSON.parse(options.body) : {}, uri = u.searchParams.get('uri')
  calls.push({ method: options.method ?? 'GET', path: u.pathname, uri: body.uri ?? uri, content: body.content })
  if (offline) throw new Error('synthetic outage')
  if (offlineStatus) return Response.json({ status: 'error' }, { status: offlineStatus })
  if (u.pathname === '/health') return Response.json({ healthy: true })
  let result
  if (u.pathname === '/api/v1/content/write') {
    if (Buffer.byteLength(body.content, 'utf8') > MAX_EMBEDDING_CONTENT_BYTES || rejected.has(body.uri))
      return Response.json({ status: 'error' }, { status: 400 })
    files.set(body.uri, body.content); result = {}
  } else if (u.pathname === '/api/v1/content/read') {
    if (!files.has(uri)) return Response.json({ status: 'error' }, { status: 404 })
    result = files.get(uri)
  } else if (options.method === 'DELETE') { files.delete(uri); result = {} }
  else if (u.pathname === '/api/v1/search/find') result = { memories: hits ?? [...files.keys()].map(uri => ({ uri, score: 0.9 })) }
  else throw new Error('unexpected fixture request')
  return Response.json({ status: 'ok', result })
}
let passed = 0
async function arm(name, run) {
  try { await run(); passed++; process.stdout.write(`PASS ${name}\n`) }
  catch (error) { process.stderr.write(`FAIL ${name}: ${error.message}\n`); process.exitCode = 1 }
}
let store, longNote, documents, chainBefore
await arm('bounded Unicode transport preserves the full chained note and resumes durable partial acknowledgements', async () => {
  const text = ('The observatory keeps calibration records for tomorrow. 星🌒\n').repeat(100)
  const parts = embeddingParts(text)
  assert.ok(parts.length > 8)
  assert.equal(parts.map(part => part.content).join(''), text)
  let offset = 0
  for (const part of parts) {
    assert.ok(Buffer.byteLength(part.content, 'utf8') <= MAX_EMBEDDING_CONTENT_BYTES)
    assert.ok(!part.content.includes('\uFFFD'))
    assert.equal(part.start, offset); offset += Buffer.byteLength(part.content, 'utf8'); assert.equal(part.end, offset)
  }
  store = createTrackedMemory({ stateDir: join(root, 'store'), subject, config, fetch: fakeFetch })
  const first = await store.remember({ text, from: 'agent', scope: 'owner', at: '2026-10-05T00:00:00Z' })
  assert.equal(first.remembered, 1)
  longNote = store.read().notes[0]
  assert.equal(longNote.statement, text); assert.equal(longNote.contentHash, contentHash(text))
  chainBefore = memoryChain(join(root, 'store'))
  documents = contentDocuments(config.user, longNote)
  assert.equal(files.size, 8); assert.ok(first.index.pending > 0)
  assert.ok(calls.filter(one => one.path === '/api/v1/content/write').every(one => Buffer.byteLength(one.content, 'utf8') <= MAX_EMBEDDING_CONTENT_BYTES))
  const initialAcks = JSON.parse(readFileSync(join(root, 'store/remembered/index/ack.json'), 'utf8'))
  assert.equal(Object.keys(initialAcks).length, 8)
  assert.ok(Object.values(initialAcks).every(one => one.contentHash === longNote.contentHash && one.ids.includes(longNote.id)))
  assert.ok(Object.values(initialAcks).every(one => one.storageTier === 'content'))
  store = createTrackedMemory({ stateDir: join(root, 'store'), subject, config, fetch: fakeFetch })
  let pending = first.index.pending
  for (let retry = 0; pending && retry < documents.length; retry++) {
    const result = await store.retry({ force: true })
    assert.ok(result.requests <= 8); pending = result.pending
  }
  assert.equal(pending, 0)
  assert.equal(documents.map(document => files.get(document.uri)).join(''), text)
  assert.deepEqual(memoryChain(join(root, 'store')), chainBefore)
  assert.deepEqual(store.read().notes.map(note => note.id), [longNote.id])
})
await arm('chunk hits bind exact span and original identity, reject tampering and foreign spans, and deduplicate the note', async () => {
  assert.ok(store && documents && files.size === documents.length)
  hits = documents.map((document, i) => ({ uri: document.uri, score: 0.99 - i / 1000 }))
  const reply = await store.recall({ question: 'spectrometer calibration' })
  assert.equal(reply.notes.length, 1); assert.equal(reply.notes[0].id, longNote.id)
  assert.equal(reply.notes[0].contentHash, longNote.contentHash)
  assert.equal(reply.notes[0].grantsAuthority, false); assert.equal(reply.notes[0].advisoryOnly, true)
  assert.deepEqual(reply.notes[0].semanticSpan, { start: documents[0].start, end: documents[0].end, unit: 'utf8-bytes', contentHash: documents[0].partHash })
  const original = files.get(documents[0].uri)
  files.set(documents[0].uri, 'A changed indexed fragment is not the authoritative bytes.')
  hits = [{ uri: documents[0].uri, score: 0.99 }]
  const changed = await store.recall({ question: 'calibration' })
  assert.equal(changed.notes.length, 0); assert.ok(changed.droppedTampered > 0)
  files.set(documents[0].uri, original)
  const foreign = documents[0].uri.replace('-part-0-', '-part-1-')
  hits = [{ uri: foreign, score: 1 }, { uri: documents[0].uri.replace('/user/scratch/', '/user/other/'), score: 1 }]
  const forged = await store.recall({ question: 'calibration' })
  assert.equal(forged.notes.length, 0); assert.equal(forged.droppedUnmapped, 2)
  assert.deepEqual(memoryChain(join(root, 'store')), chainBefore)
})
await arm('a refused document does not starve the bounded batch; an outage stops requests and retains pending work', async () => {
  const notes = [...store.ledger().entries.values()]
  const bridgeState = join(root, 'refused'), bridge = createOpenVikingRecall({ stateDir: bridgeState, config, fetch: fakeFetch })
  rejected.add(documents[0].uri)
  const begin = calls.length, first = await bridge.sync({ entries: new Map(notes.map(note => [note.id, note])), complete: true })
  assert.equal(first.requests, 8); assert.equal(first.added, 7); assert.ok(first.failed.includes('index-write-failed'))
  assert.equal(calls.slice(begin).filter(one => one.path === '/api/v1/content/write').length, 8)
  const acksBefore = readFileSync(join(bridgeState, 'remembered/index/ack.json'), 'utf8')
  offline = true
  const offlineStart = calls.length, outage = await bridge.sync({ entries: new Map(notes.map(note => [note.id, note])), complete: true })
  assert.equal(outage.requests, 1); assert.equal(calls.length - offlineStart, 1); assert.ok(outage.pending > 0)
  assert.equal(readFileSync(join(bridgeState, 'remembered/index/ack.json'), 'utf8'), acksBefore)
  offline = false; rejected.clear()
  for (const status of [503, 500, 429, 401, 403]) {
    offlineStatus = status
    const start = calls.length, unavailable = await bridge.sync({ entries: new Map(notes.map(note => [note.id, note])), complete: true })
    assert.equal(unavailable.requests, 1); assert.equal(calls.length - start, 1)
    assert.equal(readFileSync(join(bridgeState, 'remembered/index/ack.json'), 'utf8'), acksBefore)
  }
  offlineStatus = 0
  const recovered = createOpenVikingRecall({ stateDir: bridgeState, config, fetch: fakeFetch })
  let pending = outage.pending
  for (let retry = 0; pending && retry < documents.length; retry++) pending = (await recovered.sync({ entries: new Map(notes.map(note => [note.id, note])), complete: true })).pending
  assert.equal(pending, 0)
  // A removal outage must also stop new writes in the same request budget.
  const other = createTrackedMemory({ stateDir: join(root, 'other'), subject, config, fetch: fakeFetch })
  await other.remember({ text: 'The second observatory keeps independent records of its calibration schedule.', from: 'agent', scope: 'owner' })
  offlineStatus = 503
  const start = calls.length, removalOutage = await recovered.sync(other.ledger())
  assert.equal(removalOutage.requests, 1); assert.equal(calls.length - start, 1)
  assert.equal(calls[start].method, 'DELETE')
  assert.ok(removalOutage.failed.includes('remove-failed'))
  assert.ok(removalOutage.pending > 0)
  offlineStatus = 0
})
await arm('forgetting one shared capture preserves the surviving capture and its exact part acknowledgements', async () => {
  const stateDir = join(root, 'shared'), shared = createTrackedMemory({ stateDir, subject, config, fetch: fakeFetch })
  const text = 'An independent observation of the calibration schedule remains advisory memory. '.repeat(12)
  await shared.remember({ text, from: 'agent-a', scope: 'owner', at: '2026-10-05T00:00:00Z' })
  await shared.remember({ text, from: 'agent-b', scope: 'owner', at: '2026-10-05T00:00:01Z' })
  const notes = shared.read().notes
  assert.equal(notes.length, 2); assert.notEqual(notes[0].id, notes[1].id)
  // Acknowledge both IDs even where the second capture reused existing bytes.
  await shared.bridge.sync(shared.ledger(), { verifyAcknowledged: true })
  const incomplete = { entries: new Map([[notes[0].id, notes[0]]]), complete: false }
  await shared.bridge.sync(incomplete)
  const beforeForget = JSON.parse(readFileSync(join(stateDir, 'remembered/index/ack.json'), 'utf8'))
  assert.ok(Object.values(beforeForget).every(entry => entry.ids.length === 2), 'an incomplete read must not forget the second association')
  // The first content write can race a newly incomplete ledger too.
  const changingState = join(root, 'changing'), changing = createOpenVikingRecall({ stateDir: changingState, config, fetch: fakeFetch })
  let snapshots = 0
  await changing.sync(() => ++snapshots === 1 ? shared.ledger() : incomplete)
  assert.equal(snapshots, 2)
  const changingAcks = JSON.parse(readFileSync(join(changingState, 'remembered/index/ack.json'), 'utf8'))
  assert.ok(Object.values(changingAcks).every(entry => entry.ids.length === 2), 'the final written ack must retain IDs from before an incomplete reread')
  const parts = contentDocuments(config.user, notes[0]), start = calls.length
  await shared.bridge.forget(notes[0].id)
  assert.ok(!calls.slice(start).some(one => parts.some(part => part.uri === one.uri)))
  const acknowledgements = JSON.parse(readFileSync(join(stateDir, 'remembered/index/ack.json'), 'utf8'))
  for (const part of parts) {
    assert.equal(files.get(part.uri), part.content)
    assert.deepEqual(acknowledgements[part.uri].ids, [notes[1].id])
    assert.equal(acknowledgements[part.uri].contentHash, notes[1].contentHash)
  }
})
if (mutant) assert.equal(mutated, 1, 'the control must execute the actual bridge mutation')
process.stdout.write(`kira-openviking-parts: ${passed}/4 PASS; scratch fixture retained at ${root}\n`)
