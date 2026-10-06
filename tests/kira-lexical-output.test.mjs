// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual tracked-memory save/reopen/recall, with retained synthetic stores only.
// Injected HTTP responses never open a network connection or qualify installed DSH.
import assert from 'node:assert/strict'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { createTrackedMemory } from '../plugins/aukora-kira/lib/tracked-memory.mjs'
import { LEXICAL_METHOD } from '../plugins/aukora-kira/lib/retrieval.mjs'

const memoryUrl = new URL('../plugins/aukora-kira/lib/tracked-memory.mjs', import.meta.url)
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SUBJECT = `aukora:1:${'3'.repeat(64)}`
const OTHER_SUBJECT = `aukora:1:${'4'.repeat(64)}`
const NOW = Date.parse('2026-10-06T04:00:00.000Z')
const TEXT = 'SYNTHETIC-LEXICAL-OUTPUT lighthouse amber compass. Exact whitespace  and Unicode λ.'

function fixtureParent() {
  const directory = resolve(process.env.AUKORA_KIRA_LEXICAL_FIXTURE_PARENT ?? join(homedir(), '.aukora-kira-lexical-fixtures'))
  const fromRepo = relative(repoRoot, directory), fromHome = relative(realpathSync(homedir()), directory)
  assert.ok(fromRepo.startsWith('..' + sep) || isAbsolute(fromRepo), 'fixture parent must be outside the repo checkout')
  assert.ok(fromHome !== '' && !fromHome.startsWith('..' + sep) && !isAbsolute(fromHome), 'fixture parent must be under the caller home')
  if (!existsSync(directory)) mkdirSync(directory, { mode: 0o700 })
  const stat = lstatSync(directory)
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), 'fixture parent must be a real directory')
  assert.equal(stat.mode & 0o777, 0o700, 'existing fixture custody must already be private')
  if (typeof process.getuid === 'function') assert.equal(stat.uid, process.getuid(), 'fixture parent must belong to caller')
  assert.equal(realpathSync(directory), directory, 'fixture parent must not traverse symlinks')
  return directory
}

function fixture(create = createTrackedMemory) {
  const home = mkdtempSync(join(fixtureParent(), 'case-'))
  assert.equal(lstatSync(home).mode & 0o777, 0o700)
  const stateDir = join(home, 'remembered-memory')
  let networkCalls = 0
  const noNetwork = async () => { networkCalls++; throw new Error('synthetic lexical path must not fetch') }
  const open = options => create({ stateDir, subject: SUBJECT, now: () => NOW, fetch: noNetwork, ...options })
  return { home, stateDir, open, memory: open(), networkCalls: () => networkCalls }
}

function assertLossless(value, at = 'value') {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return
  if (typeof value === 'number') {
    assert.ok(Number.isFinite(value) && !Object.is(value, -0), `${at} must be a lossless JSON number`)
    return
  }
  assert.ok(value !== undefined && value && typeof value === 'object', `${at} must not be undefined or non-JSON data`)
  assert.ok([Object.prototype, null, Array.prototype].includes(Object.getPrototypeOf(value)), `${at} must contain JSON data`)
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      assert.ok(Object.hasOwn(value, index), `${at}[${index}] must not be a sparse entry`)
      assertLossless(value[index], `${at}[${index}]`)
    }
    return
  }
  for (const key of Reflect.ownKeys(value)) {
    assert.equal(typeof key, 'string', `${at} must not have symbol keys`)
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    assert.ok(descriptor.enumerable && Object.hasOwn(descriptor, 'value'), `${at}.${key} must be plain JSON data`)
    assertLossless(descriptor.value, `${at}.${key}`)
  }
}

function lexicalFacts(answer, { state = 'found', degraded = false, reason = 'lexical-requested' } = {}) {
  assertLossless(answer)
  assert.deepEqual(JSON.parse(JSON.stringify(answer)), answer, 'the actual return must round-trip without dropped fields')
  assert.equal(answer.state, state)
  assert.equal(answer.method, LEXICAL_METHOD.name)
  assert.equal(answer.degraded, degraded)
  assert.equal(answer.grantsAuthority, false)
  assert.equal(answer.semantic.available, false)
  assert.equal(answer.semantic.reason, reason)
}

async function save(f) {
  const result = await f.memory.remember({ text: TEXT, from: 'synthetic', scope: 'owner' }, { attributedTo: 'owner' })
  assert.equal(result.remembered, 1, 'the fixture must use the actual durable append path')
  return result.ids[0]
}

test('explicit lexical recall is lossless after actual durable save and cold reopen', async () => {
  const f = fixture(), id = await save(f)
  for (const memory of [f.memory, f.open()]) {
    const answer = await memory.recall({ question: 'lighthouse amber compass', lexical: true })
    lexicalFacts(answer)
    assert.equal(Object.hasOwn(answer.semantic, 'failures'), false, 'no semantic failure report was produced on a lexical-only request')
    const note = answer.notes.find(note => note.id === id)
    assert.equal(note.text, TEXT)
    assert.equal(note.scope, 'owner')
    assert.equal(note.attributedTo, 'owner')
    assert.equal(note.source.state, 'UNLINKED')
    assert.equal(note.advisoryOnly, true)
    assert.equal(note.grantsAuthority, false)
    assert.equal(note.containment.kind, 'DATA')
    assert.equal(memory.read().notes[0].privacy, 'local')
  }
  assert.equal(f.networkCalls(), 0)
})

test('empty and cross-owner lexical paths preserve their refusal facts without undefined output', async () => {
  const f = fixture()
  const empty = await f.memory.recall({ question: 'lighthouse amber compass', lexical: true })
  lexicalFacts(empty, { state: 'empty' })
  assert.equal(Object.hasOwn(empty.semantic, 'failures'), false)
  await save(f)
  const foreign = await f.open({ subject: OTHER_SUBJECT }).recall({ question: 'lighthouse amber compass', lexical: true })
  lexicalFacts(foreign, { state: 'empty' })
  assert.deepEqual(foreign.notes, [])
  assert.equal(f.networkCalls(), 0)
})

test('unconfigured semantic fallback omits an absent failure report and remains degraded', async () => {
  const f = fixture()
  await save(f)
  const answer = await f.open().recall({ question: 'lighthouse amber compass' })
  lexicalFacts(answer, { degraded: true, reason: 'openviking-not-configured' })
  assert.equal(Object.hasOwn(answer.semantic, 'failures'), false)
  assert.equal(f.networkCalls(), 0)
})

test('actual bridge search failure reports are retained exactly in lexical fallback', async () => {
  const f = fixture()
  await save(f)
  const indexed = new Map(), calls = []
  const fetch = async (url, options = {}) => {
    const pathname = new URL(url).pathname
    calls.push(pathname)
    if (pathname === '/health') return Response.json({ healthy: true })
    if (pathname === '/api/v1/content/write') {
      const body = JSON.parse(options.body)
      indexed.set(body.uri, body.content)
      return Response.json({ status: 'ok', result: {} })
    }
    if (pathname === '/api/v1/content/read') return Response.json({ status: 'ok', result: indexed.get(new URL(url).searchParams.get('uri')) })
    assert.equal(pathname, '/api/v1/search/find', 'only the actual bridge routes may execute')
    return Response.json({ status: 'error' }, { status: 503 })
  }
  const memory = f.open({ config: { configured: true, url: 'http://synthetic.invalid', user: 'synthetic', account: 'synthetic' }, fetch })
  const answer = await memory.recall({ question: 'lighthouse amber compass' })
  lexicalFacts(answer, { degraded: true, reason: 'semantic-recall-failed' })
  assert.deepEqual(answer.semantic.failures, [{ call: 'search', cause: 'unknown', httpStatus: 503 }])
  assert.ok(calls.includes('/api/v1/search/find'), 'the failure must originate from the actual bridge search path')
})

test('removing only the optional-failures fix reproduces nonlossless actual lexical output', async () => {
  let source = readFileSync(memoryUrl, 'utf8')
  const fixed = '...(answer.failures === undefined ? {} : { failures: answer.failures })'
  assert.equal(source.split(fixed).length - 1, 1, 'the narrow return fix must have one removal site')
  source = source.replace(fixed, 'failures: answer.failures')
  source = source.replace(/from\s+(['"])(\.[^'"]+)\1/g, (_match, quote, specifier) =>
    'from ' + quote + new URL(specifier, memoryUrl).href + quote)
  const create = (await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'))).createTrackedMemory
  const f = fixture(create)
  await save(f)
  const answer = await f.memory.recall({ question: 'lighthouse amber compass', lexical: true })
  assert.equal(answer.state, 'found', 'the removal control must reach an actual successful lexical recall')
  assert.equal(answer.semantic.available, false)
  assert.equal(Object.hasOwn(answer.semantic, 'failures'), true)
  assert.equal(answer.semantic.failures, undefined)
  assert.throws(() => assertLossless(answer), /value\.semantic\.failures must not be undefined/)
})
