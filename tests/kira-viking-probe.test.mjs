#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Scratch probe checks; injected HTTP responses do not qualify a running node. */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { registerHooks } from 'node:module'
import { spawnSync } from 'node:child_process'

const mutants = {
  'local-only': ["if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)\n      || url.username || url.password || url.search || url.hash)", 'if (false)'],
  'auth-status': ["if (status?.initialized !== true || status?.user !== config.user)", 'if (false)'],
  'key-refusal': ["if (response.status === 401 || response.status === 403)", 'if (false)'],
  'index-status': ["if (result?.vector_status !== 'complete')", 'if (false)'],
  'content-match': ["if (await api(`/api/v1/content/read?uri=${encodeURIComponent(uri)}`) !== TEXT)", 'if (false)'],
  'hit-uri': ['row?.uri === uri && Number.isFinite(row.score)', 'Number.isFinite(row.score)'],
  'hit-threshold': ['row.score >= config.scoreThreshold', 'true'],
  'cleanup': ["if (!attempted) return 'no throwaway write attempted'", "if (true) return 'no throwaway write attempted'"],
  'delete-confirmed': ["if (await api(`/api/v1/content/read?uri=${encodeURIComponent(uri)}`, { missing: true }) !== null)", 'if (false)'],
  'bounded-request': ['signal: AbortSignal.timeout(timeout)', 'signal: undefined'],
  'no-redirect': ["redirect: 'error'", "redirect: 'follow'"],
  'write-preflight': ['if (!key || !embedding)', 'if (false)'],
  'error-redaction': ["error instanceof ProbeRefusal ? error.code : 'viking.probe:request-failed'", "error instanceof ProbeRefusal ? error.code : error.message"],
  'create-only': ["mode: 'create'", "mode: 'replace'"],
  'collision-cleanup': ["if (error?.code === 'viking.probe:already-exists') attempted = false", 'if (false) attempted = false'],
}
const at = process.argv.indexOf('--mutant'), mutant = at < 0 ? undefined : process.argv[at + 1]
assert(at < 0 || Object.hasOwn(mutants, mutant), 'unknown focused mutant')
let mutationApplied = false
const moduleUrl = new URL('../scripts/kira/viking-probe.mjs?probe-court', import.meta.url)
if (mutant) registerHooks({ load(url, context, next) {
  const loaded = next(url, context)
  if (url !== moduleUrl.href) return loaded
  const source = Buffer.from(loaded.source).toString('utf8'), [before, after] = mutants[mutant]
  assert.equal(source.split(before).length, 2, 'mutation must match one production guard')
  mutationApplied = true
  return { ...loaded, source: source.replace(before, after) }
} })
const { probeViking, probeArgs } = await import(moduleUrl)
const home = mkdtempSync(join(process.cwd(), '.viking-probe-test-'))
const sentinel = 'synthetic-credential-never-display'
const bridge = { url: 'http://127.0.0.1:1933', account: 'scratch', user: 'owner', timeoutMs: 1000, scoreThreshold: 0.4 }
const conf = { embedding: { dense: { provider: 'openai', api_base: 'http://127.0.0.1:1934/v1', api_key: 'local' } } }
const reset = (config = conf) => {
  writeFileSync(join(home, 'root.key'), sentinel, { mode: 0o600 })
  writeFileSync(join(home, 'aukora-bridge.json'), JSON.stringify(bridge))
  writeFileSync(join(home, 'ov.conf'), JSON.stringify(config))
}
const status = (result, code = 200) => Response.json(code === 200 ? { status: 'ok', result } : { status: 'error', message: sentinel }, { status: code })
function fixture(options = {}) {
  const files = new Map(), calls = []
  const fetch = async (value, init = {}) => {
    assert.equal(init.redirect, 'error')
    assert.ok(init.signal instanceof AbortSignal)
    const url = new URL(value), body = init.body ? JSON.parse(init.body) : undefined, uri = url.searchParams.get('uri')
    calls.push({ path: url.pathname, method: init.method, body, uri })
    if (url.port === '1934') {
      assert.equal(init.headers['x-api-key'], undefined, 'the root key never goes to the embedder')
      return Response.json({ status: options.embedderDown ? 'loading model' : 'ok' }, { status: options.embedderDown ? 503 : 200 })
    }
    if (url.pathname === '/health') return Response.json({ healthy: !options.serverDown })
    assert.equal(init.headers['x-api-key'], sentinel)
    assert.equal(init.headers['x-openviking-account'], 'scratch')
    assert.equal(init.headers['x-openviking-user'], 'owner')
    if (options.wrongKey) return status(null, 401)
    if (url.pathname === '/api/v1/system/status') return status({ initialized: true, user: options.wrongUser ? 'another-user' : 'owner' })
    if (url.pathname === '/api/v1/content/write') {
      assert.equal(body.mode, 'create'); assert.equal(body.wait, true)
      assert.match(body.uri, /^viking:\/\/user\/owner\/memories\/kira\/content\/probe-[0-9a-f-]{36}\.md$/u)
      if (options.collision) return status(null, 409)
      files.set(body.uri, body.content)
      if (options.writeTimeout) throw new DOMException(sentinel, 'TimeoutError')
      return status({ uri: body.uri, content_updated: true, vector_status: options.indexFailed ? 'failed' : 'complete', semantic_status: 'skipped' })
    }
    if (url.pathname === '/api/v1/content/read') return files.has(uri) ? status(options.contentChanged ? 'wrong bytes' : files.get(uri)) : status(null, 404)
    if (url.pathname === '/api/v1/search/find') {
      assert.equal(body.target_uri, 'viking://user/owner/memories/kira/content')
      assert.deepEqual(body.tags, [`probe_id=${[...files.keys()][0].match(/probe-([0-9a-f-]{36})\.md$/u)[1]}`])
      const words = text => new Set(text.toLowerCase().match(/[a-z]+/gu))
      assert.ok([...words(body.query)].every(word => !words([...files.values()][0]).has(word)), 'meaning query has no shared words')
      return status({ memories: [...files.keys()].map(uri => ({ uri: options.foreignHit ? 'viking://user/owner/memories/existing.md' : uri,
        score: options.lowScore ? 0.01 : 0.9 })) })
    }
    if (url.pathname === '/api/v1/fs' && init.method === 'DELETE') {
      if (!options.deleteIgnored) files.delete(uri)
      return status({ uri })
    }
    throw new Error('unexpected probe endpoint')
  }
  return { fetch, files, calls }
}
const row = (report, name) => report.steps.find(one => one.step === name)
let passed = 0, failed = 0
async function check(name, run) {
  reset()
  try { await run(); passed++; console.log(`  ok   ${name}`) }
  catch (error) { failed++; console.log(`  FAIL ${name}: ${error.message}`) }
}
try {
  await check('all steps pass, only the synthetic URI is written and deleted, configuration bytes stay unchanged', async () => {
    const before = ['root.key', 'aukora-bridge.json', 'ov.conf'].map(file => readFileSync(join(home, file), 'utf8'))
    const fake = fixture(), report = await probeViking({ home, fetch: fake.fetch })
    assert.equal(report.ok, true); assert.equal(report.steps.length, 7); assert.equal(fake.files.size, 0)
    assert.equal(fake.calls.filter(call => call.method === 'POST').length, 2)
    assert.deepEqual(['root.key', 'aukora-bridge.json', 'ov.conf'].map(file => readFileSync(join(home, file), 'utf8')), before)
    assert.ok(!JSON.stringify(report).includes(sentinel))
  })
  await check('HTTP refusal names the key failure without copying the body and attempts no write', async () => {
    const fake = fixture({ wrongKey: true }), report = await probeViking({ home, fetch: fake.fetch })
    assert.equal(row(report, 'key').reason, 'viking.probe:key-refused')
    assert.equal(fake.calls.filter(call => call.method === 'POST').length, 0)
    assert.ok(!JSON.stringify(report).includes(sentinel))
  })
  await check('a different authenticated user is refused before indexing', async () => {
    const fake = fixture({ wrongUser: true }), report = await probeViking({ home, fetch: fake.fetch })
    assert.equal(row(report, 'key').reason, 'viking.probe:account-unavailable')
    assert.equal(fake.files.size, 0); assert.equal(fake.calls.filter(call => call.method === 'POST').length, 0)
  })
  await check('an unavailable server or embedder is reported and prevents indexing', async () => {
    for (const options of [{ serverDown: true }, { embedderDown: true }]) {
      const fake = fixture(options), report = await probeViking({ home, fetch: fake.fetch })
      assert.equal(report.ok, false); assert.equal(row(report, 'index').reason, 'viking.probe:index-prerequisite-failed')
      assert.equal(fake.calls.filter(call => call.method === 'POST').length, 0)
    }
  })
  await check('a 200 response with failed vector indexing is a failure and its content is deleted', async () => {
    const fake = fixture({ indexFailed: true }), report = await probeViking({ home, fetch: fake.fetch })
    assert.equal(row(report, 'index').reason, 'viking.probe:index-incomplete')
    assert.equal(row(report, 'delete').ok, true); assert.equal(fake.files.size, 0)
  })
  await check('successful indexing with different content fails and is cleaned up', async () => {
    const fake = fixture({ contentChanged: true }), report = await probeViking({ home, fetch: fake.fetch })
    assert.equal(row(report, 'index').reason, 'viking.probe:content-mismatch'); assert.equal(fake.files.size, 0)
  })
  await check('a foreign URI or a score below the threshold cannot pass semantic recall', async () => {
    for (const options of [{ foreignHit: true }, { lowScore: true }]) {
      const fake = fixture(options), report = await probeViking({ home, fetch: fake.fetch })
      assert.equal(row(report, 'recall').reason, 'viking.probe:semantic-miss'); assert.equal(fake.files.size, 0)
    }
  })
  await check('a write timeout still deletes possibly saved content and never prints its exception', async () => {
    const fake = fixture({ writeTimeout: true }), report = await probeViking({ home, fetch: fake.fetch })
    assert.equal(row(report, 'index').reason, 'viking.probe:timeout'); assert.equal(fake.files.size, 0)
    assert.ok(!JSON.stringify(report).includes(sentinel))
  })
  await check('a create conflict never deletes an existing note', async () => {
    const fake = fixture({ collision: true }), report = await probeViking({ home, fetch: fake.fetch })
    assert.equal(row(report, 'index').reason, 'viking.probe:already-exists')
    assert.equal(fake.calls.filter(call => call.method === 'DELETE').length, 0)
  })
  await check('deletion must be read back; a remaining synthetic URI is reported', async () => {
    const fake = fixture({ deleteIgnored: true }), report = await probeViking({ home, fetch: fake.fetch })
    assert.equal(row(report, 'delete').reason, 'viking.probe:delete-not-confirmed'); assert.equal(report.ok, false)
    assert.equal(report.cleanupUri, [...fake.files.keys()][0])
  })
  await check('off-machine embedder is refused before even a health request', async () => {
    reset({ embedding: { dense: { provider: 'openai', api_base: 'http://remote.invalid/v1' } } })
    writeFileSync(join(home, 'aukora-bridge.json'), JSON.stringify({ ...bridge, allowRemoteModels: true }))
    let requests = 0
    const report = await probeViking({ home, fetch: async () => { requests++; return Response.json({ healthy: true, status: 'ok' }) } })
    assert.equal(report.steps[0].reason, 'viking.probe:local-url-required'); assert.equal(requests, 0)
  })
  await check('malformed local configuration details are suppressed', async () => {
    const invalid = await probeViking({ home, timeoutMs: { valueOf() { throw new Error(sentinel) } } })
    assert.equal(invalid.steps[0].reason, 'viking.probe:timeout-invalid'); assert.ok(!JSON.stringify(invalid).includes(sentinel))
    writeFileSync(join(home, 'ov.conf'), JSON.stringify(conf))
    const report = await probeViking({ home, fetch: async () => ({ ok: true, status: 200, async json() { return { get healthy() { throw new Error(sentinel) } } } }) })
    assert.equal(row(report, 'server').reason, 'viking.probe:request-failed'); assert.ok(!JSON.stringify(report).includes(sentinel))
  })
  await check('explicit home and bounded timeout parse; unknown flags do not leak their values', async () => {
    assert.deepEqual(probeArgs(['--home', home, '--timeout-ms', '30000'], {}), { home, timeoutMs: 30000 })
    for (const timeoutMs of [0, 120001, NaN]) assert.equal((await probeViking({ home, timeoutMs })).steps[0].reason, 'viking.probe:timeout-invalid')
    const child = spawnSync(process.execPath, ['scripts/kira/viking-probe.mjs', `--${sentinel}`], { encoding: 'utf8' })
    assert.equal(child.status, 1); assert.match(child.stderr, /viking\.probe:usage/u); assert.ok(!child.stderr.includes(sentinel))
  })
} finally { rmSync(home, { recursive: true, force: true }) }
if (mutant) assert(mutationApplied, 'focused production mutation must be applied')
console.log(`kira-viking-probe: ${passed} passed, ${failed} failed (scratch only)`)
process.exitCode = failed ? 1 : 0
