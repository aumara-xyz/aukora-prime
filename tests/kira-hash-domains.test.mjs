#!/usr/bin/env node
/** Production bridge, current parent-hash acknowledgement shape and generic
 * filter with synthetic multilingual bytes. No installed embedder is exercised. */
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const mutantAt = process.argv.indexOf('--mutant'), mutant = mutantAt < 0 ? null : process.argv[mutantAt + 1]
const mutations = {
  'parent-used-for-part': ['recall-filter/filter.mjs', 'if (!verifyMemoryRecordHashes(note).ok) {', 'if (contentHash(note.statement ?? note.text) !== note.contentHash) {'],
  'part-hash-unchecked': ['memory-quality.mjs', "|| Buffer.byteLength(displayed, 'utf8') !== range.end - range.start || !verifyContentHash(displayed, note.partHash).ok)", "|| Buffer.byteLength(displayed, 'utf8') !== range.end - range.start || false)"],
  'range-length-unchecked': ['memory-quality.mjs', "Buffer.byteLength(displayed, 'utf8') !== range.end - range.start", 'false'],
  'parent-statement-unchecked': ['memory-quality.mjs', 'if (!verifyContentHash(text, statementHash).ok)', 'if (false)'],
  'projection-source-unchecked': ['memory-quality.mjs', "!bytes.subarray(start, start + selected.length).equals(selected)", 'false'],
  'ack-quarantine-removed': ['recall-openviking.mjs', 'if (acknowledgements[uri] && notes.some(note => !acknowledgementMatches(note, uri))) quarantineAcknowledgement(uri, notes)', 'if (false) quarantineAcknowledgement(uri, notes)'],
  'parent-ack-confused-with-part': ['recall-openviking.mjs', '(entry.contentHash == null || entry.contentHash === hashOf(note))', '(entry.contentHash == null || entry.contentHash === document.partHash)'],
  'byte-offset-used-as-character': ['recall-openviking.mjs', "Buffer.from(note.statement, 'utf8').subarray(start, semanticSpan.end).toString('utf8')", 'note.statement.slice(start, semanticSpan.end)'],
  'tools-projection-untyped': ['tools.mjs', "...projectMemoryText(note, String(note.text).slice(0, 600))", "text: String(note.text).slice(0, 600), contentHash: note.contentHash, contentHashScope: 'full-statement'"],
  'legacy-parent-manufactured': ['memory-quality.mjs', "if (checked.domain === 'uncommitted') return { text: shown }", "if (checked.domain === 'uncommitted') return { text: shown, statementHash: contentHash(source), contentHash: contentHash(source), partHash: contentHash(shown), byteRange: { start, end: start + selected.length, unit: 'utf8-bytes' } }"],
  'quarantine-association-release': ['recall-openviking.mjs', "current[uri]?.status === 'quarantined' && !contentWritten", 'false'],
  'aura-part-treated-as-prefix': ['aura-recall.mjs', 'verifyMemoryRecordHashes({ ...left, statement: right.statement }).ok', "typeof left.text === 'string' && left.text === right.statement?.slice(0, left.text.length)"],
}
let mutationApplied = 0
if (mutant) {
  assert.ok(mutations[mutant], 'unknown hash-domain mutation')
  const [module, guard, removed] = mutations[mutant], target = new URL(`../plugins/aukora-kira/lib/${module}`, import.meta.url).href
  registerHooks({ load(url, context, nextLoad) {
    const loaded = nextLoad(url, context)
    if (url !== target) return loaded
    const source = String(loaded.source)
    assert.equal(source.split(guard).length - 1, 1, 'focused control must target exactly one production guard')
    mutationApplied++
    return { ...loaded, source: source.replace(guard, removed) }
  } })
}
const { createTrackedMemory, contentHash, memoryChain } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
const { contentDocuments, semanticNotes, createOpenVikingRecall } = await import('../plugins/aukora-kira/lib/recall-openviking.mjs')
const { filterMemoryRecords } = await import('../plugins/aukora-kira/lib/recall-filter/filter.mjs')
const { projectMemoryText, verifyMemoryRecordHashes } = await import('../plugins/aukora-kira/lib/memory-quality.mjs')
const { recallRemembered } = await import('../plugins/aukora-kira/lib/tools.mjs')
const { sameRecallRecord } = await import('../plugins/aukora-kira/lib/aura-recall.mjs')
const root = mkdtempSync(join(tmpdir(), 'kira-hash-domains-')), stateDir = join(root, 'memory')
process.once('exit', () => rmSync(root, { recursive: true, force: true }))
const subject = `aukora:1:${'72'.repeat(32)}`
const config = { configured: true, url: 'http://fixture.invalid', user: 'scratch', account: 'scratch', key: 'synthetic-only', syncBatch: 8 }
const context = { subject, permittedPrivacy: ['local'], nowMs: Date.parse('2026-10-05T00:00:00Z') }
const files = new Map(), writes = []
let hits = []
const fetch = async (url, options = {}) => {
  const u = new URL(url), body = options.body ? JSON.parse(options.body) : {}, uri = u.searchParams.get('uri')
  if (u.pathname === '/health') return Response.json({ healthy: true })
  let result
  if (u.pathname === '/api/v1/content/write') { files.set(body.uri, body.content); writes.push(body.uri); result = {} }
  else if (u.pathname === '/api/v1/content/read') {
    if (!files.has(uri)) return Response.json({ status: 'error' }, { status: 404 })
    result = files.get(uri)
  } else if (u.pathname === '/api/v1/search/find') result = { memories: hits }
  else if (options.method === 'DELETE') { files.delete(uri); result = {} }
  else throw new Error('unexpected synthetic request')
  return Response.json({ status: 'ok', result })
}
const report = () => ({ dropped: 0, reasons: {} })
let passed = 0, total = 0
async function arm(name, run) {
  total++
  try { await run(); passed++; process.stdout.write(`PASS ${name}\n`) }
  catch (error) { process.stderr.write(`FAIL ${name}: ${error.message}\n`); process.exitCode = 1 }
}
let store, note, documents, selected, answer, projection, originalChain
const ackFile = join(stateDir, 'remembered/index/ack.json')
await arm('current-scheme parent acks and a forced nonzero multibyte part survive the real generic filter', async () => {
  const text = 'The observatory retains calibration notes. 星🌒 café e\u0301\n'.repeat(34)
  store = createTrackedMemory({ stateDir, subject, config, fetch })
  await store.remember({ text, from: 'agent', scope: 'owner', at: '2026-10-05T00:00:00Z' })
  note = store.read().notes[0]; documents = contentDocuments(config.user, note); originalChain = memoryChain(stateDir)
  for (let count = 0; count < documents.length; count++) if ((await store.retry({ force: true })).pending === 0) break
  assert.equal(documents.map(part => files.get(part.uri)).join(''), text)
  // Sanitized current-scheme fixture: every part ack carries the PARENT hash.
  // This shape is valid; a part hash must never be compared to this field.
  writeFileSync(ackFile, `${JSON.stringify(Object.fromEntries(documents.map(part => [part.uri,
    { ids: [note.id], contentHash: note.contentHash, storageTier: 'content' }])))}\n`)
  selected = documents.find(part => part.start >= 384)
  assert.ok(selected)
  assert.notEqual(selected.content, note.statement.slice(selected.start, selected.end), 'UTF8 byte offsets differ from JavaScript character offsets')
  assert.equal(selected.content, Buffer.from(text, 'utf8').subarray(selected.start, selected.end).toString('utf8'))
  hits = [{ uri: selected.uri, score: 0.93 }]
  const before = writes.length
  answer = await store.bridge.recall({ question: 'calibration notes', live: store.ledger,
    govern: notes => filterMemoryRecords(notes, context, report()) })
  assert.equal(writes.length, before, 'correct parent acks must not be quarantined or rewritten')
  assert.equal(answer.hits.length, 1)
  const shown = semanticNotes(answer, 600)
  assert.equal(shown.notes.length, 1); projection = shown.notes[0]
  assert.equal(projection.id, note.id); assert.equal(projection.text, selected.content)
  assert.equal(projection.statementHash, note.contentHash); assert.equal(projection.contentHash, note.contentHash)
  assert.equal(projection.partHash, selected.partHash)
  assert.deepEqual(projection.byteRange, { start: selected.start, end: selected.end, unit: 'utf8-bytes' })
  assert.equal(projection.semanticSpan.start, selected.start)
  assert.equal(filterMemoryRecords([{ ...projection, subject, privacy: 'local' }], context, report()).length, 1)
  assert.equal(verifyMemoryRecordHashes(projection).statementVerified, false, 'part bytes alone do not prove the parent statement')
  const nested = projectMemoryText(projection, projection.text.slice(0, 30))
  assert.equal(nested.statementHash, note.contentHash)
  assert.deepEqual(nested.byteRange, { start: selected.start, end: selected.start + Buffer.byteLength(nested.text, 'utf8'), unit: 'utf8-bytes' })
  assert.equal(filterMemoryRecords([{ ...projection, ...nested, subject, privacy: 'local' }], context, report()).length, 1)
  assert.deepEqual(memoryChain(stateDir), originalChain)
})
await arm('a displayed part rejects changed bytes, wrong part hash, byte range and parent-domain alias', async () => {
  assert.ok(projection)
  const base = { ...projection, subject, privacy: 'local' }
  for (const changed of [
    { ...base, text: `X${base.text.slice(1)}` },
    { ...base, partHash: '00'.repeat(32) },
    { ...base, byteRange: { ...base.byteRange, end: base.byteRange.end + 1 } },
    { ...base, statementHash: '00'.repeat(32) },
  ]) {
    const dropped = report()
    assert.equal(filterMemoryRecords([changed], context, dropped).length, 0)
    assert.equal(dropped.reasons['content-hash-mismatch'], 1)
  }
  assert.equal(filterMemoryRecords([{ ...base, scope: 'project:unattached' }], context, report()).length, 0)
})
await arm('full statement verification and exact projection binding remain mandatory', async () => {
  assert.ok(note && selected)
  const altered = { ...note, statement: `X${note.statement.slice(1)}` }
  assert.equal(filterMemoryRecords([altered], context, report()).length, 0)
  assert.throws(() => projectMemoryText(note, `X${selected.content.slice(1)}`, { start: selected.start }), /memory-byte-range-invalid/u)
  const both = { ...note, ...projectMemoryText(note, selected.content, { start: selected.start }) }
  assert.equal(verifyMemoryRecordHashes(both).statementVerified, true)
  assert.equal(filterMemoryRecords([both], context, report()).length, 1)
  assert.equal(filterMemoryRecords([{ ...both, byteRange: { ...both.byteRange, start: both.byteRange.start - 1, end: both.byteRange.end - 1 } }], context, report()).length, 0)
  const full = semanticNotes(answer, 60_000).notes[0]
  assert.equal(full.text, note.statement)
  assert.deepEqual(full.byteRange, { start: 0, end: Buffer.byteLength(note.statement, 'utf8'), unit: 'utf8-bytes' })
  const split = projectMemoryText(note, note.statement.slice(0, note.statement.indexOf('🌒') + 1))
  assert.ok(!split.text.endsWith('\uD83C'))
  assert.equal(Buffer.from(note.statement, 'utf8').subarray(0, split.byteRange.end).toString('utf8'), split.text)
})
await arm('genuinely mismatched parent ack is durably quarantined and requeued across recreation', async () => {
  const current = JSON.parse(readFileSync(ackFile, 'utf8'))
  current[selected.uri].contentHash = '01'.repeat(32)
  writeFileSync(ackFile, `${JSON.stringify(current)}\n`)
  const before = writes.length
  const deferred = await store.bridge.sync(store.ledger, { budget: 0 })
  assert.equal(deferred.pending, 1); assert.equal(writes.length, before)
  let persisted = JSON.parse(readFileSync(ackFile, 'utf8'))[selected.uri]
  assert.equal(persisted.status, 'quarantined')
  assert.equal(persisted.quarantine.reason, 'acknowledgement-hash-mismatch')
  assert.equal(persisted.quarantine.previous.contentHash, '01'.repeat(32))
  assert.deepEqual(persisted.quarantine.expected, { statementHash: note.contentHash, partHash: selected.partHash, byteRange: selected.byteRange })
  const restarted = createOpenVikingRecall({ stateDir, config, fetch })
  const recovered = await restarted.sync(store.ledger, { budget: 1 })
  assert.equal(recovered.requests, 1); assert.equal(recovered.pending, 0); assert.equal(recovered.added, 1)
  assert.deepEqual(writes.slice(before), [selected.uri]); assert.equal(files.get(selected.uri), selected.content)
  persisted = JSON.parse(readFileSync(ackFile, 'utf8'))[selected.uri]
  assert.notEqual(persisted.status, 'quarantined'); assert.equal(persisted.contentHash, note.contentHash)
  assert.equal(persisted.statementHash, note.contentHash); assert.equal(persisted.partHash, selected.partHash)
  assert.deepEqual(persisted.byteRange, selected.byteRange)
  assert.equal(persisted.quarantine.previous.contentHash, '01'.repeat(32), 'quarantine history survives successful requeue')
  assert.deepEqual(memoryChain(stateDir), originalChain)
})
await arm('genuinely mismatched typed part ack requeues while byte-tampered content stays withheld', async () => {
  const current = JSON.parse(readFileSync(ackFile, 'utf8'))
  current[selected.uri].partHash = '02'.repeat(32)
  writeFileSync(ackFile, `${JSON.stringify(current)}\n`)
  const before = writes.length
  const repaired = await store.bridge.sync(store.ledger, { budget: 1 })
  assert.equal(repaired.pending, 0); assert.deepEqual(writes.slice(before), [selected.uri])
  const ackBefore = readFileSync(ackFile, 'utf8')
  files.set(selected.uri, `X${selected.content.slice(1)}`)
  const changed = await store.bridge.recall({ question: 'calibration', live: store.ledger })
  assert.equal(changed.hits.length, 0); assert.equal(changed.dropped.tampered.length, 1)
  assert.equal(readFileSync(ackFile, 'utf8'), ackBefore, 'changed index bytes do not rewrite a correct acknowledgement')
  assert.equal(writes.length, before + 1, 'tampered index content is not silently overwritten by recall')
  files.set(selected.uri, selected.content)
})
await arm('actual remembered tool projects 600 multilingual characters with distinct parent and display hashes', async () => {
  let reads = 0
  const result = await recallRemembered(async request => {
    reads++
    assert.deepEqual(request.tiers, ['remembered'])
    return [note]
  }, 'observatory calibration', 5, notes => filterMemoryRecords(notes, context, report()))
  assert.equal(reads, 1); assert.equal(result.state, 'found'); assert.equal(result.notes.length, 1)
  const shown = result.notes[0]
  assert.equal(shown.id, note.id); assert.equal(shown.text, note.statement.slice(0, 600).replace(/[\uD800-\uDBFF]$/u, ''))
  assert.ok(shown.text.length <= 600); assert.ok(shown.text.includes('星🌒'))
  assert.equal(shown.statementHash, note.contentHash); assert.equal(shown.contentHash, note.contentHash)
  assert.notEqual(shown.partHash, shown.statementHash)
  assert.equal(shown.partHash, contentHash(shown.text))
  assert.deepEqual(shown.byteRange, { start: 0, end: Buffer.byteLength(shown.text, 'utf8'), unit: 'utf8-bytes' })
  assert.equal(verifyMemoryRecordHashes(shown).statementVerified, false)
  const after = report()
  assert.equal(filterMemoryRecords([{ ...shown, subject, privacy: 'local' }], context, after).length, 1)
  assert.equal(after.dropped, 0)
  assert.equal(note.contentHash, contentHash(note.statement)); assert.deepEqual(memoryChain(stateDir), originalChain)
})
await arm('actual remembered tool leaves hash-absent legacy bytes uncommitted', async () => {
  const legacy = { id: 'legacy-uncommitted', text: 'The observatory retains multilingual calibration notes. 星🌒 café.',
    subject, privacy: 'local', scope: 'owner', observedAt: '2026-10-05T00:00:00Z' }
  const result = await recallRemembered(async () => [legacy], 'calibration', 5,
    notes => filterMemoryRecords(notes, context, report()))
  assert.equal(result.state, 'found'); assert.equal(result.notes.length, 1)
  const shown = result.notes[0]
  assert.equal(shown.text, legacy.text); assert.equal(shown.id, legacy.id)
  for (const key of ['contentHash', 'statementHash', 'partHash', 'byteRange']) assert.equal(shown[key], undefined, `legacy ${key} must not be manufactured`)
  assert.equal(verifyMemoryRecordHashes(shown).domain, 'uncommitted')
  assert.equal(filterMemoryRecords([{ ...shown, subject, privacy: 'local' }], context, report()).length, 1)
})
await arm('shared-ID forget and restart retain quarantine until actual content write succeeds', async () => {
  const sharedDir = join(root, 'shared'), shared = createTrackedMemory({ stateDir: sharedDir, subject, config, fetch })
  const text = 'The second observatory retains shared calibration records. 星🌒 café. '.repeat(15)
  await shared.remember({ text, from: 'agent-a', scope: 'owner', at: '2026-10-05T00:00:00Z' })
  await shared.remember({ text, from: 'agent-b', scope: 'owner', at: '2026-10-05T00:00:01Z' })
  const notes = shared.read().notes, part = contentDocuments(config.user, notes[0]).find(one => one.start >= 384)
  const file = join(sharedDir, 'remembered/index/ack.json'), current = JSON.parse(readFileSync(file, 'utf8'))
  assert.equal(notes.length, 2); assert.ok(part)
  current[part.uri].partHash = '03'.repeat(32)
  writeFileSync(file, `${JSON.stringify(current)}\n`)
  const deferred = await shared.bridge.sync(shared.ledger, { budget: 0 })
  assert.equal(deferred.pending, 1)
  const before = writes.length
  await shared.bridge.forget(notes[0].id)
  const afterForget = JSON.parse(readFileSync(file, 'utf8'))[part.uri]
  assert.deepEqual(afterForget.ids, [notes[1].id])
  assert.equal(afterForget.status, 'quarantined', 'association-only forget must not release quarantine')
  assert.equal(afterForget.quarantine.previous.partHash, '03'.repeat(32))
  assert.equal(writes.length, before)
  const live = { entries: new Map([[notes[1].id, notes[1]]]), complete: true }
  const restarted = createOpenVikingRecall({ stateDir: sharedDir, config, fetch })
  const stillPending = await restarted.sync(live, { budget: 0 })
  assert.equal(stillPending.pending, 1); assert.equal(writes.length, before)
  assert.equal(JSON.parse(readFileSync(file, 'utf8'))[part.uri].status, 'quarantined')
  const recovered = await restarted.sync(live, { budget: 1 })
  assert.equal(recovered.pending, 0); assert.deepEqual(writes.slice(before), [part.uri])
  const repaired = JSON.parse(readFileSync(file, 'utf8'))[part.uri]
  assert.notEqual(repaired.status, 'quarantined'); assert.deepEqual(repaired.ids, [notes[1].id])
  assert.equal(repaired.quarantine.previous.partHash, '03'.repeat(32))
})
await arm('actual Aura comparator binds a nonzero part of a historical statement longer than 60000 characters', async () => {
  // This synthetic historical-size representation exercises the pure comparator
  // and existing 60000-character view boundary, not storage/chain or installed
  // recall qualification. The reread retains identity/source/chain metadata.
  const statement = 'The historical observatory retains multilingual calibration records. 星🌒 café. '.repeat(900)
  assert.ok(statement.length > 60_000)
  const full = { ...note, statement, contentHash: contentHash(statement), source: structuredClone(note.source), aura: structuredClone(note.aura) }
  const part = contentDocuments(config.user, full).find(one => one.start >= 384)
  const longAnswer = { ...answer, hits: [{ ...answer.hits[0], note: full, uri: part.uri,
    semanticSpan: { start: part.start, end: part.end, unit: 'utf8-bytes', contentHash: part.partHash } }] }
  const shown = semanticNotes(longAnswer, 60_000).notes[0]
  assert.equal(shown.text, part.content); assert.equal(shown.byteRange.start, part.start)
  assert.equal(shown.contentHash, full.contentHash); assert.equal(shown.id, full.id)
  assert.equal(sameRecallRecord(shown, full), true)
  assert.equal(sameRecallRecord({ ...shown, statement: 'tampered' }, full), false)
  assert.equal(sameRecallRecord({ ...shown, partHash: '04'.repeat(32) }, full), false)
  assert.equal(sameRecallRecord({ ...shown, byteRange: { ...shown.byteRange, start: part.start + 1, end: part.end + 1 } }, full), false)
  assert.equal(sameRecallRecord(shown, { ...full, id: `${full.id}-changed` }), false)
  assert.equal(sameRecallRecord(shown, { ...full, source: { ...full.source, seq: 99 } }), false)
  assert.equal(sameRecallRecord(shown, { ...full, aura: { ...full.aura, entryHash: '05'.repeat(32) } }), false)
})
if (mutant) assert.equal(mutationApplied, 1, 'the focused control must execute the actual source mutation')
process.stdout.write(`kira-hash-domains: ${passed}/${total} PASS; SOURCE/mock, no installed embedding qualification\n`)
