// SPDX-License-Identifier: AGPL-3.0-or-later
// Release sync drains synthetic state and preserves failure, retry, integrity and transport bounds.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createOpenVikingHttpFixture } from './support/openviking-http.mjs'

const ROOT = fileURLToPath(new URL('..', import.meta.url)), work = mkdtempSync(join(ROOT, 'tests/.viking-sync-'))
const toolUrl = new URL('../scripts/kira/viking-sync.mjs', import.meta.url).href
const bridgeUrl = new URL('../plugins/aukora-kira/lib/recall-openviking.mjs', import.meta.url).href
const mutant = process.argv.includes('--mutant') ? process.argv[process.argv.indexOf('--mutant') + 1] : null
const changes = {
  'delete-transport': [toolUrl, "if ((options.method ?? 'GET').toUpperCase() === 'DELETE') fail('delete-refused')", 'if (false) fail(\'delete-refused\')'],
  'remote-endpoint': [toolUrl, "if (endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname)\n    || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== '/') fail('local-url-required')", "if (false) fail('local-url-required')"],
  'request-outside': [toolUrl, "if (new URL(url).origin !== endpoint.origin) fail('request-outside')", "if (false) fail('request-outside')"],
  'release-absolute': [toolUrl, "if (!isAbsolute(argv[0])) fail('release-not-absolute')", "if (false) fail('release-not-absolute')"],
  'time-bound': [toolUrl, "if (!Number.isFinite(maxMinutes) || maxMinutes <= 0 || maxMinutes > 1440) fail('max-minutes-invalid')", "if (false) fail('max-minutes-invalid')"],
  'usage': [toolUrl, "if (![1, 3].includes(argv.length) || (argv.length === 3 && argv[1] !== '--max-minutes')) fail('usage')", "if (false) fail('usage')"],
  'id-filter': [toolUrl, "typeof id === 'string' && ID.test(id)", 'true'],
  'count-output': [toolUrl, "return `${final ? 'kira-viking-sync' : 'progress'}: indexed=${count(report.indexed)} pending=${count(report.pending)} failed=${ids(report.failedIds).length}`", 'return JSON.stringify(report)'],
  'delete-stale': [bridgeUrl, 'options.removeStale !== false && live.complete', 'live.complete'],
  'delete-race': [bridgeUrl, 'options.removeStale !== false && latest.complete && requests < budget && !failed.length', 'latest.complete && requests < budget && !failed.length'],
  'partial-semantic': [bridgeUrl, '!hits.length && searchableNotes === 0 &&', '!hits.length &&'],
  'partial-state': [bridgeUrl, "answer.coverage?.partial ? 'undetermined' : 'empty'", "'empty'"],
  'partial-ceiling': [bridgeUrl, 'ceiling: answer.coverage?.partial\n', 'ceiling: false\n'],
  'indexed-integrity': [bridgeUrl, 'if (matches.some(note => !matchesDocument(note, uri, bytes))) {', 'if (false) {'],
  'quarantine-preserved': [bridgeUrl, "if (options.preserveQuarantined === true && acknowledgements[uri]?.status === 'quarantined') throw new OpenVikingError('content-mismatch', 'index acknowledgement quarantined')", 'void 0'],
  'store-incomplete': [toolUrl, 'if (!finalStore.complete) {', 'if (false) {'],
  'release-contained': [toolUrl, "if (suffix === '..' || suffix.startsWith(`..${sep}`) || isAbsolute(suffix)) fail('release-file-outside')", "if (false) fail('release-file-outside')"],
  'release-supported': [toolUrl, "if (OPERATOR_SYNC_VERSION !== 2) fail('release-sync-unsupported')", "if (false) fail('release-sync-unsupported')"],
  'complete-note-coverage': [bridgeUrl, 'contentDocuments(config.user, note).every(document => indexed(acknowledgements[document.uri]))', 'contentDocuments(config.user, note).some(document => indexed(acknowledgements[document.uri]))'],
  'audit-failure-ids': [bridgeUrl, 'for (const note of grouped.get(uri) ?? []) failedIds.add(note.id)', 'void 0'],
  'failure-indexed': [bridgeUrl, "const indexed = entry => acknowledged(entry) && entry.vectorStatus === 'complete'", 'const indexed = entry => Boolean(entry)'],
  'retry-backoff': [bridgeUrl, 'acknowledgements[uri].retry.nextRetryAt <= now()', 'true'],
  'retry-cap': [bridgeUrl, 'acknowledgements[uri].retry.attempts < 5', 'true'],
  'interactive-retry': [bridgeUrl, 'retryKnownBad: false', 'retryKnownBad: true'],
  'stop-failure': [toolUrl, 'if (last.audit?.failed?.length || last.audit?.tampered?.length) {', "if (last.failed?.length) { reason = 'index-failed'; break }\n      if (last.audit?.failed?.length || last.audit?.tampered?.length) {"],
  'operator-timeout': [toolUrl, 'timeoutMs: 60_000', 'timeoutMs: 40'],
  'same-run-retry': [toolUrl, 'skipUris: [...skipped]', 'skipUris: []'],
  'invalid-utf8-reason': [toolUrl, "? 'invalid-utf8' : token(value)", "? 'index-failed' : token(value)"],
  'incomplete-coverage': [bridgeUrl, 'partial: !live.complete || synced.pending > 0', 'partial: synced.pending > 0'],
  'failure-token': [toolUrl, "typeof value === 'string' && /^[a-z][a-z0-9._:-]{0,63}$/u.test(value)", "typeof value === 'string'"],
  'failure-http-status': [toolUrl, 'value.httpStatus >= 100 && value.httpStatus <= 599', 'true'],
  'failure-attempts': [toolUrl, 'Number.isSafeInteger(value.attempts) && value.attempts >= 0', 'value.attempts !== undefined'],
  'failure-retry-time': [toolUrl, 'Number.isFinite(value.nextRetryAt) && value.nextRetryAt >= 0', 'value.nextRetryAt !== undefined'],
  'interactive-busy': [bridgeUrl, 'if (turns > 0) {', 'if (false) {'],
  'interactive-busy-audit': [bridgeUrl, 'if (reads.length === 0 && turns === 0) {', 'if (reads.length === 0) {'],
  'shared-retry': [bridgeUrl, '...(acknowledgements[uri]?.retry ? { retry: acknowledgements[uri].retry } : {}),', ''],
  'shared-pending': [bridgeUrl, "...(acknowledgements[uri]?.status === 'pending' ? { status: 'pending' } : {}),", ''],
  'successful-retry-cleared': [bridgeUrl, 'delete value.retry', 'void value.retry'],
  'audit-before-drain': [toolUrl, 'verifyAcknowledged: before === 0', 'verifyAcknowledged: true'],
}
let applied = 0
if (mutant) {
  assert.ok(changes[mutant], 'known mutation required')
  registerHooks({ load(url, context, next) {
    const loaded = next(url, context), [target, guard, removed] = changes[mutant]
    const isBridge = target === bridgeUrl && url.endsWith('/plugins/aukora-kira/lib/recall-openviking.mjs')
    if (url !== target && !isBridge) return loaded
    const source = String(loaded.source)
    assert.ok(source.includes(guard), 'production mutation guard must exist')
    applied++
    return { ...loaded, source: source.replaceAll(guard, removed) }
  } })
}
const { syncArgs, syncTransport, syncLine, syncFailureLine, syncRelease } = await import(toolUrl)
const { createOpenVikingRecall, contentUri, contentDocuments, semanticNotes } = await import(bridgeUrl)
const { createTrackedMemory } = await import('../plugins/aukora-kira/lib/tracked-memory.mjs')
const { MAX_EMBEDDING_CONTENT_BYTES } = await import('../plugins/aukora-kira/lib/memory-input-bounds.mjs')
const subject = `aukora:1:${'35'.repeat(32)}`, canary = 'SYNTHETIC-NOTE-DO-NOT-PRINT'
const config = { configured: true, url: 'http://127.0.0.1:49671', account: 'scratch', user: 'scratch', key: 'inert-synthetic', syncBatch: 1 }
let passed = 0, releaseCount = 0
const transports = new Set()
async function check(name, action) {
  if (mutant) {
    const group = ['release-absolute', 'time-bound', 'usage'].includes(mutant) ? 'arguments'
      : ['delete-transport', 'remote-endpoint', 'request-outside'].includes(mutant) ? 'transport'
        : ['id-filter', 'count-output', 'failure-token', 'failure-http-status', 'failure-attempts', 'failure-retry-time'].includes(mutant) ? 'output'
          : ['delete-stale', 'delete-race'].includes(mutant) ? 'stale'
            : mutant === 'quarantine-preserved' ? 'quarantined'
              : mutant === 'store-incomplete' ? 'incomplete'
                : mutant === 'release-contained' ? 'contained'
                  : mutant === 'release-supported' ? 'unsupported'
                    : mutant === 'audit-failure-ids' ? 'audit'
                      : ['failure-indexed', 'retry-backoff', 'stop-failure'].includes(mutant) ? 'queue'
                        : mutant === 'retry-cap' ? 'retry'
                          : mutant === 'interactive-retry' ? 'interactive'
                            : mutant === 'operator-timeout' ? 'operator'
                              : mutant === 'same-run-retry' ? 'spans'
                                : mutant === 'invalid-utf8-reason' ? 'incomplete'
                                  : mutant === 'incomplete-coverage' ? 'incomplete-coverage'
                                    : ['interactive-busy', 'interactive-busy-audit'].includes(mutant) ? 'interactive-flight'
                                      : ['shared-retry', 'shared-pending', 'successful-retry-cleared'].includes(mutant) ? 'shared'
                                        : mutant === 'audit-before-drain' ? 'audit-drain' : 'partial'
    if (!name.startsWith(group)) return
  }
  await action(); passed++; process.stdout.write(`PASS ${name}\n`)
}
function fixture() {
  const files = new Map(), calls = [], rejected = new Set()
  let writes = 0, down = false, onWrite, searchEmpty = false, vectorStatus = 'complete'
  const fetch = async (url, options = {}) => {
    const parsed = new URL(url), body = options.body ? JSON.parse(options.body) : {}, uri = parsed.searchParams.get('uri')
    calls.push({ method: options.method ?? 'GET', path: parsed.pathname })
    if (down) throw new Error(canary)
    if (parsed.pathname === '/health') return Response.json({ healthy: true })
    let result
    if (parsed.pathname === '/api/v1/content/write') {
      if (rejected.has(body.uri)) return Response.json({ status: 'error', error: canary }, { status: 413 })
      files.set(body.uri, body.content); writes++; await onWrite?.(); result = { vector_status: vectorStatus }
    } else if (parsed.pathname === '/api/v1/content/read') {
      if (!files.has(uri)) return Response.json({ status: 'error' }, { status: 404 })
      result = files.get(uri)
    } else if (options.method === 'DELETE') { files.delete(uri); result = {} }
    else if (parsed.pathname === '/api/v1/search/find') result = { memories: searchEmpty ? [] : [...files.keys()].map(uri => ({ uri, score: .9 })) }
    else throw new Error('unexpected synthetic request')
    return Response.json({ status: 'ok', result })
  }
  return { files, calls, rejected, fetch, get writes() { return writes }, set down(value) { down = value }, set onWrite(value) { onWrite = value }, set searchEmpty(value) { searchEmpty = value }, set vectorStatus(value) { vectorStatus = value } }
}
function syntheticRelease(stateDir, bridgeConfig = config) {
  const release = join(work, `release-${++releaseCount}`)
  const put = (path, text) => { const target = join(release, path); mkdirSync(fileURLToPath(new URL('.', pathToFileURL(target))), { recursive: true, mode: 0o700 }); writeFileSync(target, text) }
  cpSync(join(ROOT, 'plugins/aukora-kira'), join(release, 'plugins/aukora-kira'), { recursive: true })
  for (const path of ['plugins/aukora-aumlok', 'vendor/aukora-packages', 'vendor/authority', 'packages/contracts']) cpSync(join(ROOT, path), join(release, path), { recursive: true })
  put('package.json', '{"type":"module"}\n')
  put('vendor/include/lib/index.js', 'export const entryListSchema = {}; export const applyEntryPatches = (_, rows) => rows;\n')
  put('vendor/loader/lib/index.js', 'export const interpolate = (_, value) => value;\n')
  put('packages/util/home-paths/lib/index.js', 'export const dshHomePath = () => "/synthetic-unused";\n')
  put('node_modules/js-yaml/package.json', '{"name":"js-yaml","main":"index.cjs"}\n')
  put('node_modules/js-yaml/index.cjs', 'exports.load = JSON.parse;\n')
  const home = join(work, `viking-${releaseCount}`); mkdirSync(home, { mode: 0o700 })
  writeFileSync(join(home, 'root.key'), `${bridgeConfig.key}\n`, { mode: 0o600 })
  writeFileSync(join(home, 'aukora-bridge.json'), JSON.stringify({ ...bridgeConfig, key: undefined, allowRemoteModels: true }))
  put('aukora-composition.patch.yml', JSON.stringify([{ id: 'aukora-kira', name: './plugins/aukora-kira/lib/gate-capture-host.mjs',
    config: { memoryOwner: { stateDir, subject }, openVikingHome: home } }]))
  return release
}
const sharedConfig = (run, overrides = {}) => ({ configured: true, url: run.url, account: 'aukora', user: 'owner', key: 'synthetic-key', syncBatch: 8, ...overrides })
async function httpFixture(action) {
  const run = await createOpenVikingHttpFixture({ allowTransportFallback: true, semanticMatch: () => true })
  transports.add(run.transport === 'http' ? 'http' : `injected (listen ${run.listenRefusal})`)
  try { await action(run) } finally { await run.close() }
}
try {
  await check('arguments refuse relative releases, malformed options and unbounded time', async () => {
    assert.deepEqual(syncArgs([ROOT]), { release: ROOT, maxMinutes: 5 })
    for (const argv of [[ROOT, '--wrong', '2'], [ROOT, '--max-minutes', '0'], [ROOT, '--max-minutes', '1441'], [ROOT, '--max-minutes', 'NaN'], ['relative']]) assert.throws(() => syncArgs(argv))
  })
  await check('transport refuses deletion, external endpoints and redirected origins before requests', async () => {
    let requests = 0
    const controller = new AbortController(), fetch = syncTransport(config, controller.signal, async () => { requests++; return Response.json({}) })
    await assert.rejects(fetch(`${config.url}/api/v1/fs`, { method: 'DELETE' }), error => error.code === 'kira.viking-sync:delete-refused')
    await assert.rejects(fetch('http://localhost:9999/api/v1/content/write'), error => error.code === 'kira.viking-sync:request-outside')
    for (const url of ['https://example.invalid', 'http://127.0.0.1/path', 'http://secret@127.0.0.1']) assert.throws(() => syncTransport({ ...config, url }, controller.signal))
    assert.equal(requests, 0)
    controller.abort()
    await fetch(`${config.url}/health`)
    assert.equal(requests, 1)
  })
  await check('output is counts only and refuses invalid failed ids', async () => {
    const value = syncLine({ indexed: 7, pending: 11, failedIds: [canary, `rem:${'a'.repeat(64)}`], statement: canary, subject: canary, key: canary })
    assert.equal(value, 'progress: indexed=7 pending=11 failed=1'); assert.ok(!value.includes(canary))
    const id = `rem:${'a'.repeat(64)}`
    assert.equal(syncFailureLine({ id: canary, reason: 'timeout' }), null)
    assert.equal(syncFailureLine({ id, reason: 'vector-status-failed', httpStatus: 200, vectorStatus: 'failed', attempts: 2, nextRetryAt: 70_000, capped: true, text: canary }),
      `failed-id: ${id} reason=vector-status-failed httpStatus=200 vectorStatus=failed attempts=2 nextRetryAt=70000 capped=true`)
    assert.equal(syncFailureLine({ id, reason: 'content-hash-mismatch' }, true), `skipped-id: ${id} reason=content-hash-mismatch`)
    for (const invalid of [
      { reason: canary, vectorStatus: canary, httpStatus: 999, attempts: -1, nextRetryAt: -1 },
      { reason: canary, vectorStatus: canary, httpStatus: 0, attempts: 1.5, nextRetryAt: Infinity },
    ]) assert.equal(syncFailureLine({ id, ...invalid, statement: canary, key: canary }), `failed-id: ${id} reason=index-failed`)
  })
  await check('contained release store import refuses a symlink escaping the release', async () => {
    const release = syntheticRelease(join(work, 'escape-state')), path = join(release, 'plugins/aukora-kira/lib/tracked-memory.mjs')
    unlinkSync(path); symlinkSync(join(ROOT, 'plugins/aukora-kira/lib/tracked-memory.mjs'), path)
    await assert.rejects(syncRelease({ release }, { request: fixture().fetch }), error => error.code === 'kira.viking-sync:release-file-outside')
  })
  await check('unsupported release sync is refused before any indexing requests', async () => {
    const release = syntheticRelease(join(work, 'old-state')), path = join(release, 'plugins/aukora-kira/lib/recall-openviking.mjs')
    writeFileSync(path, readFileSync(path, 'utf8').replace('export const OPERATOR_SYNC_VERSION = 2', 'export const OPERATOR_SYNC_VERSION = 1'))
    const run = fixture()
    await assert.rejects(syncRelease({ release }, { request: run.fetch }), error => error.code === 'kira.viking-sync:release-sync-unsupported')
    assert.equal(run.calls.length, 0)
  })
  await check('release sync drains eight-request batches and resumes without rewriting acknowledged notes', async () => {
    const run = fixture(), stateDir = join(work, 'drain'), store = createTrackedMemory({ stateDir, subject })
    await store.rememberBatch(Array.from({ length: 19 }, (_, i) => ({ text: `Synthetic telescope calibration record ${i} remains in the observatory.`, from: 'scratch' })))
    const release = syntheticRelease(stateDir), rows = []
    const first = await syncRelease({ release, maxMinutes: 1, onProgress: row => rows.push(row) }, { request: run.fetch })
    assert.equal(first.ok, true); assert.equal(first.indexed, 19); assert.equal(first.pending, 0); assert.equal(first.failedIds.length, 0)
    assert.ok(first.batches >= 3); assert.ok(rows.length >= 3); assert.equal(run.writes, 19)
    const second = await syncRelease({ release, maxMinutes: 1 }, { request: run.fetch })
    assert.equal(second.ok, true); assert.equal(run.writes, 19); assert.equal(run.calls.some(call => call.method === 'DELETE'), false)
  })
  await check('time limit and interruption preserve pending acknowledgements for resumption', async () => {
    const run = fixture(), stateDir = join(work, 'bounded'), store = createTrackedMemory({ stateDir, subject })
    await store.rememberBatch(Array.from({ length: 12 }, (_, i) => ({ text: `Synthetic garden weather station record ${i} was captured before the storm.`, from: 'scratch' })))
    const release = syntheticRelease(stateDir)
    let tick = 0
    const limited = await syncRelease({ release, maxMinutes: .001 }, { request: run.fetch, now: () => tick++ * 100 })
    assert.equal(limited.reason, 'time-limit'); assert.equal(limited.pending, 12); assert.equal(run.writes, 0)
    const controller = new AbortController(); run.onWrite = () => controller.abort()
    const interrupted = await syncRelease({ release, maxMinutes: 1, signal: controller.signal }, { request: run.fetch })
    assert.equal(interrupted.reason, 'interrupted'); assert.ok(interrupted.pending > 0)
    run.onWrite = undefined
    assert.equal((await syncRelease({ release, maxMinutes: 1 }, { request: run.fetch })).ok, true)
    assert.equal(store.read().notes.length, 12); assert.equal(run.files.size, 12)
  })
  await check('per-record refusal lists only ids and continues to the later backlog', async () => {
    const run = fixture(), stateDir = join(work, 'refused'), store = createTrackedMemory({ stateDir, subject })
    await store.rememberBatch(Array.from({ length: 13 }, (_, i) => ({ text: `Synthetic orchard irrigation record ${i} was written beside the blue garden gate.`, from: 'scratch' })))
    const failed = store.read().notes.slice(0, 8)
    for (const note of failed) run.rejected.add(contentUri(config.user, note.contentHash))
    let at = Date.now()
    const release = syntheticRelease(stateDir), report = await syncRelease({ release, maxMinutes: 1 }, { request: run.fetch, now: () => at })
    assert.equal(report.ok, false); assert.equal(report.indexed, 5); assert.equal(report.pending, 8)
    assert.deepEqual(report.failedIds, failed.map(note => note.id).sort()); assert.ok(!JSON.stringify(report).includes(canary))
    run.rejected.clear()
    at += 30_001
    assert.equal((await syncRelease({ release, maxMinutes: 1 }, { request: run.fetch, now: () => at })).ok, true)
  })
  await check('queue indexes forty-seven of fifty, reports three reasons and retries only after back-off', async () => httpFixture(async run => {
    const stateDir = join(work, 'queue'), store = createTrackedMemory({ stateDir, subject }), bridgeConfig = sharedConfig(run)
    await store.rememberBatch(Array.from({ length: 50 }, (_, i) => ({ text: `Synthetic observatory queue record ${i} preserves a distinct measured star position.`, from: 'scratch' })))
    const failed = store.read().notes.slice(0, 3), reasons = ['content-too-large', 'vector-status-failed', 'http-422']
    const refused = [{ httpStatus: 413 }, { vectorStatus: 'failed' }, { httpStatus: 422 }]
    failed.forEach((note, i) => run.controls.writeFailures.set(contentUri(bridgeConfig.user, note.contentHash), refused[i]))
    let at = Date.now()
    const release = syntheticRelease(stateDir, bridgeConfig), request = run.fetch, now = () => at
    const first = await syncRelease({ release, maxMinutes: 1 }, { request, now })
    assert.equal(first.ok, false); assert.equal(first.indexed, 47); assert.equal(first.pending, 3)
    assert.deepEqual(first.failedIds, failed.map(note => note.id).sort())
    for (const [i, note] of failed.entries()) {
      const detail = first.recordFailures.find(row => row.id === note.id)
      assert.equal(detail.reason, reasons[i]); assert.equal(detail.attempts, 1); assert.equal(detail.nextRetryAt, at + 30_000)
      if (i === 1) assert.equal(detail.vectorStatus, 'failed')
      else assert.equal(detail.httpStatus, refused[i].httpStatus)
    }
    const ack = JSON.parse(readFileSync(join(stateDir, 'remembered/index/ack.json'), 'utf8'))
    for (const note of failed) {
      const entry = ack[contentUri(bridgeConfig.user, note.contentHash)]
      assert.equal(entry.status, 'pending'); assert.notEqual(entry.vectorStatus, 'complete'); assert.equal(entry.retry.attempts, 1)
    }
    const writes = run.calls.filter(call => call.path === '/api/v1/content/write').length
    assert.equal(writes, 50)
    const second = await syncRelease({ release, maxMinutes: 1 }, { request, now })
    assert.equal(second.indexed, 47); assert.equal(second.pending, 3); assert.equal(second.ok, false)
    assert.deepEqual(second.failedIds, first.failedIds)
    assert.equal(run.calls.filter(call => call.path === '/api/v1/content/write').length, writes)
    assert.ok(!JSON.stringify(first).includes('synthetic detail'))
    run.controls.writeFailures.clear(); at += 30_001
    const healed = await syncRelease({ release, maxMinutes: 1 }, { request, now })
    assert.equal(healed.ok, true); assert.equal(healed.indexed, 50); assert.equal(healed.pending, 0)
    assert.deepEqual(healed.failedIds, []); assert.equal(run.calls.filter(call => call.path === '/api/v1/content/write').length, 53)
  }))
  await check('retry persists increasing back-off and caps each failed document at five attempts', async () => {
    const run = fixture(), stateDir = join(work, 'retry-cap'), store = createTrackedMemory({ stateDir, subject })
    await store.remember({ text: 'Synthetic failed calibration document remains pending through its bounded retry schedule.', from: 'scratch' })
    const note = store.read().notes[0], uri = contentUri(config.user, note.contentHash), ackPath = join(stateDir, 'remembered/index/ack.json')
    run.rejected.add(uri)
    let at = Date.now()
    const release = syntheticRelease(stateDir), request = run.fetch, now = () => at
    for (let attempts = 1; attempts <= 5; attempts++) {
      const report = await syncRelease({ release, maxMinutes: 1 }, { request, now })
      const detail = report.recordFailures.find(row => row.id === note.id)
      assert.equal(detail.attempts, attempts); assert.equal(report.pending, 1); assert.equal(report.indexed, 0)
      const expected = at + Math.min(900_000, 30_000 * 2 ** (attempts - 1))
      assert.equal(detail.nextRetryAt, expected); assert.equal(detail.capped === true, attempts === 5)
      assert.equal(JSON.parse(readFileSync(ackPath, 'utf8'))[uri].retry.attempts, attempts)
      at = expected + 1
    }
    const before = run.calls.length
    const capped = await syncRelease({ release, maxMinutes: 1 }, { request, now })
    assert.equal(capped.recordFailures[0].attempts, 5); assert.equal(capped.recordFailures[0].capped, true)
    assert.equal(run.calls.length, before)
  })
  await check('shared failed content keeps retry state when one capture is forgotten and clears it only on success', async () => {
    const run = fixture(), stateDir = join(work, 'shared-retry'), store = createTrackedMemory({ stateDir, subject })
    const text = 'Synthetic shared observatory calibration bytes retain the remaining capture after one is forgotten.'
    await store.rememberBatch([{ text, from: 'scratch-a' }, { text, from: 'scratch-b' }])
    const notes = store.read().notes
    assert.equal(notes.length, 2); assert.notEqual(notes[0].id, notes[1].id); assert.equal(notes[0].contentHash, notes[1].contentHash)
    const uri = contentUri(config.user, notes[0].contentHash), ackPath = join(stateDir, 'remembered/index/ack.json'), live = store.ledger()
    let at = Date.now()
    const bridge = createOpenVikingRecall({ stateDir, config, fetch: run.fetch, now: () => at })
    run.vectorStatus = 'failed'
    const failed = await bridge.sync(() => live, { budget: 8 })
    assert.equal(failed.indexed, 0); assert.equal(failed.pending, 1); assert.equal(run.writes, 1)
    const original = JSON.parse(readFileSync(ackPath, 'utf8'))[uri]
    assert.equal(original.status, 'pending'); assert.equal(original.retry.attempts, 1)
    live.entries.delete(notes[0].id)
    assert.equal((await bridge.forget(notes[0].id)).reached, true)
    const remaining = JSON.parse(readFileSync(ackPath, 'utf8'))[uri]
    assert.deepEqual(remaining.ids, [notes[1].id]); assert.deepEqual(remaining.retry, original.retry); assert.equal(remaining.status, 'pending')
    const deferred = await bridge.sync(() => live, { budget: 8 })
    assert.equal(deferred.indexed, 0); assert.equal(deferred.pending, 1); assert.equal(deferred.requests, 0); assert.equal(run.writes, 1)
    assert.deepEqual(deferred.failedIds, [notes[1].id])
    at += 30_001; run.vectorStatus = 'complete'
    const healed = await bridge.sync(() => live, { budget: 8 })
    assert.equal(healed.indexed, 1); assert.equal(healed.pending, 0); assert.equal(run.writes, 2)
    const complete = JSON.parse(readFileSync(ackPath, 'utf8'))[uri]
    assert.deepEqual(complete.ids, [notes[1].id]); assert.equal(complete.vectorStatus, 'complete')
    assert.equal(complete.retry, undefined); assert.equal(complete.status, undefined)
  })
  await check('interactive recall skips known failures even after their retry time and keeps partial coverage', async () => {
    const run = fixture(), stateDir = join(work, 'interactive'), store = createTrackedMemory({ stateDir, subject })
    await store.rememberBatch(Array.from({ length: 4 }, (_, i) => ({ text: `Synthetic interactive recall record ${i} preserves the observatory calibration schedule.`, from: 'scratch' })))
    const note = store.read().notes[0], uri = contentUri(config.user, note.contentHash)
    run.rejected.add(uri)
    let at = Date.now()
    const bridge = createOpenVikingRecall({ stateDir, config: { ...config, syncBatch: 8 }, fetch: run.fetch, now: () => at })
    const first = await bridge.sync(() => store.ledger(), { budget: 8 })
    assert.equal(first.indexed, 3); assert.equal(first.pending, 1)
    const writes = run.calls.filter(call => call.path === '/api/v1/content/write').length
    run.rejected.clear(); at += 900_001
    const answer = await bridge.recall({ question: 'calibration', live: () => store.ledger() })
    assert.equal(run.calls.filter(call => call.path === '/api/v1/content/write').length, writes)
    assert.equal(answer.available, true); assert.equal(answer.hits.length, 3)
    assert.deepEqual(answer.coverage, { indexed: 3, total: 4, partial: true })
  })
  await check('interactive-flight recall and empty searches do not wait behind a slow background retry', async () => {
    const run = fixture(), stateDir = join(work, 'interactive-flight'), store = createTrackedMemory({ stateDir, subject })
    await store.rememberBatch(Array.from({ length: 4 }, (_, i) => ({ text: `Synthetic background retry record ${i} preserves the observatory calibration schedule.`, from: 'scratch' })))
    const note = store.read().notes[0], uri = contentUri(config.user, note.contentHash)
    run.rejected.add(uri)
    let at = Date.now()
    const bridge = createOpenVikingRecall({ stateDir, config: { ...config, syncBatch: 8 }, fetch: run.fetch, now: () => at })
    assert.equal((await bridge.sync(() => store.ledger(), { budget: 8 })).indexed, 3)
    at += 30_001; run.rejected.clear(); run.vectorStatus = 'failed'
    let unblock, entered
    const held = new Promise(resolve => { unblock = resolve }), started = new Promise(resolve => { entered = resolve })
    run.onWrite = () => { entered(); return held }
    const background = bridge.sync(() => store.ledger(), { budget: 8 })
    await started
    try {
      for (const empty of [false, true]) {
        run.searchEmpty = empty
        let timer
        const timeout = new Promise(resolve => { timer = setTimeout(() => resolve(null), 150) })
        const answer = await Promise.race([bridge.recall({ question: 'calibration', live: () => store.ledger() }), timeout])
        clearTimeout(timer)
        assert.notEqual(answer, null, 'interactive recall must settle while the background retry is still held')
        assert.equal(answer.available, true); assert.equal(answer.hits.length, empty ? 0 : 3)
        assert.deepEqual(answer.coverage, { indexed: 3, total: 4, partial: true })
        if (empty) assert.equal(semanticNotes(answer).state, 'undetermined')
      }
    } finally { unblock(); await background }
  })
  await check('operator indexing uses sixty seconds independently from the interactive timeout', async () => httpFixture(async run => {
    run.controls.slow = true
    const stateDir = join(work, 'slow'), store = createTrackedMemory({ stateDir, subject }), bridgeConfig = sharedConfig(run, { timeoutMs: 40 })
    await store.remember({ text: 'Synthetic slow embedder note preserves the observatory calibration result.', from: 'scratch' })
    let at = Date.now()
    const bridge = createOpenVikingRecall({ stateDir, config: bridgeConfig, fetch: run.fetch, now: () => at })
    const fast = await bridge.sync(() => store.ledger(), { budget: 8 })
    assert.equal(fast.indexed, 0); assert.equal(fast.pending, 1); assert.equal(fast.recordFailures[0].reason, 'timeout')
    at += 30_001
    const report = await syncRelease({ release: syntheticRelease(stateDir, bridgeConfig), maxMinutes: 1 }, { request: run.fetch, now: () => at })
    assert.equal(report.ok, true); assert.equal(report.indexed, 1); assert.equal(report.pending, 0)
    assert.deepEqual(run.calls.filter(call => call.path === '/api/v1/content/write').map(call => call.timeout), [1, 60])
  }))
  await check('spans stay within embedder bytes, continue after a failed part and never retry it in the same run', async () => httpFixture(async run => {
    const stateDir = join(work, 'bounded-spans'), store = createTrackedMemory({ stateDir, subject }), bridgeConfig = sharedConfig(run)
    await store.remember({ text: 'Synthetic long telescope record preserves measured Unicode star positions. 星🌒\n'.repeat(20), from: 'scratch' })
    const note = store.read().notes[0], documents = contentDocuments(bridgeConfig.user, note)
    assert.ok(documents.length > 1)
    run.controls.maxContentBytes = MAX_EMBEDDING_CONTENT_BYTES
    run.controls.writeFailures.set(documents[0].uri, { vectorStatus: 'failed' })
    let at = Date.now()
    const release = syntheticRelease(stateDir, bridgeConfig)
    const report = await syncRelease({ release, maxMinutes: 5, onProgress: () => { at += 30_001 } }, { request: run.fetch, now: () => at })
    assert.equal(report.indexed, documents.length - 1); assert.equal(report.pending, 1)
    assert.deepEqual(report.failedIds, [note.id])
    const writes = run.calls.filter(call => call.path === '/api/v1/content/write')
    assert.equal(writes.length, documents.length); assert.equal(writes.filter(call => call.uri === documents[0].uri).length, 1)
    assert.ok(writes.every(call => call.bytes <= MAX_EMBEDDING_CONTENT_BYTES))
    const active = createOpenVikingRecall({ stateDir, config: { ...bridgeConfig, syncBatch: 0 }, fetch: run.fetch })
    const answer = await active.recall({ question: 'stars', live: () => store.ledger() })
    assert.deepEqual(answer.coverage, { indexed: 0, total: 1, partial: true, partialSpans: 1 })
    run.controls.writeFailures.clear()
    const healed = await syncRelease({ release, maxMinutes: 1 }, { request: run.fetch, now: () => at })
    assert.equal(healed.ok, true); assert.equal(healed.indexed, documents.length); assert.equal(healed.pending, 0)
  }))
  await check('audit failures report only the known affected ids without server error text', async () => {
    const run = fixture(), stateDir = join(work, 'audit-failed'), store = createTrackedMemory({ stateDir, subject })
    await store.remember({ text: 'Synthetic harbor lighthouse service record was captured before dawn.', from: 'scratch' })
    const release = syntheticRelease(stateDir)
    assert.equal((await syncRelease({ release }, { request: run.fetch })).ok, true)
    run.down = true
    const report = await syncRelease({ release }, { request: run.fetch })
    assert.equal(report.ok, false); assert.equal(report.reason, 'index-failed')
    assert.deepEqual(report.failedIds, store.read().notes.map(note => note.id)); assert.ok(!JSON.stringify(report).includes(canary))
  })
  await check('audit-drain indexes the healthy backlog before an existing-content audit can stop the run', async () => {
    const run = fixture(), stateDir = join(work, 'audit-drain'), store = createTrackedMemory({ stateDir, subject })
    await store.rememberBatch(Array.from({ length: 21 }, (_, i) => ({ text: `Synthetic audit-order record ${i} preserves a distinct telescope calibration measurement.`, from: 'scratch' })))
    const notes = store.read().notes, bridge = createOpenVikingRecall({ stateDir, config, fetch: run.fetch })
    assert.equal((await bridge.sync(() => store.ledger(), { budget: 1 })).indexed, 1)
    const ackPath = join(stateDir, 'remembered/index/ack.json'), ack = JSON.parse(readFileSync(ackPath, 'utf8'))
    ack[contentUri(config.user, notes[1].contentHash)] = { ids: [notes[1].id], contentHash: notes[1].contentHash, status: 'quarantined' }
    writeFileSync(ackPath, JSON.stringify(ack))
    const request = async (url, options) => {
      if (new URL(url).pathname === '/api/v1/content/read') throw new Error(canary)
      return run.fetch(url, options)
    }
    const report = await syncRelease({ release: syntheticRelease(stateDir), maxMinutes: 1 }, { request })
    assert.equal(report.ok, false); assert.equal(report.reason, 'index-failed'); assert.equal(report.indexed, 20); assert.equal(report.pending, 1)
    assert.equal(run.writes, 20); assert.deepEqual(report.failedIds, notes.slice(0, 2).map(note => note.id).sort())
    assert.equal(report.recordFailures.find(row => row.id === notes[1].id).reason, 'index-content-mismatch')
    assert.ok(!JSON.stringify(report).includes(canary))
  })
  await check('stale and forget-raced index content is retained by nondeleting sync', async () => {
    const run = fixture(), stateDir = join(work, 'retained'), store = createTrackedMemory({ stateDir, subject, config, fetch: run.fetch })
    const captured = await store.remember({ text: 'Synthetic forgotten observatory detail remains unreturned by recall.', from: 'scratch' })
    const live = store.ledger(), uri = contentUri(config.user, store.read().notes[0].contentHash)
    const bridge = createOpenVikingRecall({ stateDir, config, fetch: run.fetch })
    await bridge.sync({ entries: new Map(), complete: true }, { budget: 8, removeStale: false })
    assert.ok(run.files.has(uri)); assert.equal(run.calls.some(call => call.method === 'DELETE'), false)
    const race = createOpenVikingRecall({ config, fetch: run.fetch }), racing = { ...live, entries: new Map(live.entries) }
    run.onWrite = () => { racing.entries.clear() }
    const result = await race.sync(() => racing, { budget: 8, removeStale: false })
    assert.equal(result.removed, 0); assert.ok(run.files.has(uri)); assert.equal(run.calls.some(call => call.method === 'DELETE'), false)
    assert.equal(captured.remembered, 1)
  })
  await check('quarantined acknowledgements cannot overwrite existing index bytes', async () => {
    const run = fixture(), stateDir = join(work, 'quarantined'), store = createTrackedMemory({ stateDir, subject, config, fetch: run.fetch })
    await store.remember({ text: 'Synthetic observatory calibration note must keep its exact captured bytes.', from: 'scratch' })
    const note = store.read().notes[0], uri = contentUri(config.user, note.contentHash), ackPath = join(stateDir, 'remembered/index/ack.json')
    const acknowledgement = JSON.parse(readFileSync(ackPath, 'utf8')); acknowledgement[uri].status = 'quarantined'
    writeFileSync(ackPath, JSON.stringify(acknowledgement)); run.files.set(uri, 'Synthetic changed index bytes require investigation.')
    const bridge = createOpenVikingRecall({ stateDir, config, fetch: run.fetch }), written = run.writes
    const report = await bridge.sync(() => store.ledger(), { budget: 8, removeStale: false, preserveQuarantined: true })
    assert.deepEqual(report.failed, ['index-content-mismatch']); assert.deepEqual(report.failedIds, [note.id])
    assert.equal(run.writes, written); assert.equal(run.files.get(uri), 'Synthetic changed index bytes require investigation.')
  })
  await check('incomplete stores never report complete indexing or expose refused note bodies', async () => {
    const run = fixture(), stateDir = join(work, 'incomplete'), store = createTrackedMemory({ stateDir, subject })
    await store.rememberBatch(Array.from({ length: 5 }, (_, i) => ({ text: `Synthetic lighthouse inspection note ${i} must keep the captured bytes.`, from: 'scratch' })))
    const notes = store.read().notes, paths = notes.map(note => join(stateDir, 'remembered', `${note.id.slice(4)}.json`))
    const changed = JSON.parse(readFileSync(paths[0], 'utf8')); changed.statement = canary; writeFileSync(paths[0], JSON.stringify(changed))
    unlinkSync(paths[1]); writeFileSync(paths[2], Buffer.from([0xff])); writeFileSync(paths[3], `{"statement":"${canary}",`)
    const report = await syncRelease({ release: syntheticRelease(stateDir), maxMinutes: 1 }, { request: run.fetch })
    assert.equal(report.ok, false); assert.equal(report.reason, 'memory-store-incomplete'); assert.equal(report.indexed, 1)
    assert.deepEqual(report.failedIds, notes.slice(0, 4).map(note => note.id).sort())
    assert.deepEqual(report.skippedIds, report.failedIds)
    for (const [i, reason] of ['content-hash-mismatch', 'missing-object', 'invalid-utf8', 'index-failed'].entries()) {
      assert.equal(report.recordFailures.find(row => row.id === notes[i].id).reason, reason)
    }
    assert.equal(run.writes, 1); assert.ok(!JSON.stringify(report).includes(canary)); assert.ok(!JSON.stringify(report).includes(stateDir))
  })
  await check('incomplete-coverage keeps verified hits but never claims a full search of a damaged store', async () => {
    const run = fixture(), stateDir = join(work, 'incomplete-coverage'), store = createTrackedMemory({ stateDir, subject })
    await store.remember({ text: 'Synthetic verified observatory note remains readable beside a damaged store entry.', from: 'scratch' })
    const bridge = createOpenVikingRecall({ stateDir, config: { ...config, syncBatch: 8 }, fetch: run.fetch })
    assert.equal((await bridge.sync(() => store.ledger(), { budget: 8 })).indexed, 1)
    const answer = await bridge.recall({ question: 'observatory', live: () => ({ ...store.ledger(), complete: false }) })
    assert.equal(answer.hits.length, 1); assert.deepEqual(answer.coverage, { indexed: 1, total: 1, partial: true })
    assert.equal(semanticNotes(answer).degraded, true)
  })
  await check('partial semantic recall keeps verified hits and reports empty partial searches as undetermined', async () => {
    const run = fixture(), stateDir = join(work, 'partial'), store = createTrackedMemory({ stateDir, subject })
    await store.rememberBatch(Array.from({ length: 4 }, (_, i) => ({ text: `Synthetic harbor lighthouse maintenance record ${i} was captured before dawn.`, from: 'scratch' })))
    const bridge = createOpenVikingRecall({ stateDir, config, fetch: run.fetch })
    await bridge.sync(() => store.ledger(), { budget: 1 })
    const active = createOpenVikingRecall({ stateDir, config: { ...config, syncBatch: 0 }, fetch: run.fetch })
    const answer = await active.recall({ question: 'meaning', live: () => store.ledger() })
    assert.equal(answer.available, true); assert.equal(answer.hits.length, 1); assert.deepEqual(answer.coverage, { indexed: 1, total: 4, partial: true })
    const projected = semanticNotes(answer)
    assert.equal(projected.degraded, true); assert.ok(projected.ceiling.some(line => line.includes('semantic over 1 of 4 notes')))
    run.searchEmpty = true
    const empty = await active.recall({ question: 'unrelated', live: () => store.ledger() })
    assert.equal(empty.available, true); assert.equal(semanticNotes(empty).state, 'undetermined')
    run.searchEmpty = false
    const uri = run.files.keys().next().value; run.files.set(uri, 'Synthetic index bytes changed after capture.')
    const damaged = await active.recall({ question: 'meaning', live: () => store.ledger() })
    assert.equal(damaged.hits.length, 0); assert.equal(damaged.dropped.tampered.length, 1)
    const excluded = await active.recall({ question: 'meaning', live: () => ({ entries: new Map(), complete: false }) })
    assert.equal(excluded.hits.length, 0)
  })
  await check('partial long-note coverage names incomplete spans and governs each snapshot once', async () => {
    const run = fixture(), stateDir = join(work, 'partial-long'), store = createTrackedMemory({ stateDir, subject })
    await store.remember({ text: 'Synthetic observatory calibration logs preserve the full Unicode measurement record. 星🌒\n'.repeat(30), from: 'scratch' })
    const bridge = createOpenVikingRecall({ stateDir, config, fetch: run.fetch })
    await bridge.sync(() => store.ledger(), { budget: 1 })
    const active = createOpenVikingRecall({ stateDir, config: { ...config, syncBatch: 0 }, fetch: run.fetch })
    let governed = 0
    const answer = await active.recall({ question: 'calibration', live: () => store.ledger(), govern: notes => { governed++; return notes } })
    assert.equal(governed, 1); assert.equal(answer.hits.length, 1)
    assert.deepEqual(answer.coverage, { indexed: 0, total: 1, partial: true, partialSpans: 1 })
    assert.ok(semanticNotes(answer).ceiling.some(line => line.includes('1 additional notes have only some indexed spans')))
  })
  if (mutant) assert.ok(applied > 0, 'mutation must load real production code')
  else {
    let killed = 0
    for (const name of Object.keys(changes)) {
      const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--mutant', name], { cwd: ROOT, encoding: 'utf8', timeout: 20_000 })
      assert.equal(result.status, 1, `${name}: mutant must fail its protection assertion`)
      assert.match(result.stderr, /AssertionError/u, `${name}: mutation must fail an assertion`)
      assert.doesNotMatch(result.stderr, /production mutation guard must exist|mutation must load real production code|known mutation required/u)
      assert.ok(!result.error, `${name}: mutation must fail an assertion, not time out`); killed++
    }
    process.stdout.write(`kira-viking-sync: ${killed}/${Object.keys(changes).length} protection mutants killed\n`)
  }
  process.stdout.write(`kira-viking-sync: ${passed} passed, 0 failed (synthetic state; transport=${[...transports].join(', ') || 'injected'})\n`)
} finally { rmSync(work, { recursive: true, force: true }) }
