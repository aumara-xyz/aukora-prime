// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Viviani / Aumara
// Rewritten from EPSILON 62dc809ce app/lib/continuitySource.test.ts; summary ingestion excluded.
// Apache-2.0 text: ../licenses/upstream/prime-source/packages/execution/licenses/Apache-2.0.txt
/** Check ledger-backed session hints, refusals and concurrent appends with synthetic metadata. */
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as production from '../plugins/aukora-kira/lib/continuity-head.mjs'
import { auraEntryHash, chainAuraEntries } from '../plugins/aukora-kira/lib/memory-owner.mjs'
import { appendJournalLine } from '../plugins/aukora-kira/lib/strict-read.mjs'
import { memoryChain } from '../plugins/aukora-kira/lib/tracked-memory.mjs'

const sourceURL = new URL('../plugins/aukora-kira/lib/continuity-head.mjs', import.meta.url)
const source = readFileSync(sourceURL, 'utf8')
const scratch = fileURLToPath(new URL('../.scratch/', import.meta.url))
mkdirSync(scratch, { recursive: true })
const root = mkdtempSync(join(scratch, 'continuity-test-'))
const at = '2026-04-18T00:00:00.000Z'
const stamp = offset => new Date(Date.parse(at) + offset).toISOString()
let casesRun = 0, killed = 0
const fresh = () => mkdtempSync(join(root, 'state-'))
const ledger = stateDir => join(stateDir, 'remembered/aura.jsonl')
const input = (stateDir, sessionId = 'session_a', offset = 0) => ({ stateDir, sessionId, messageCount: 3, ts: stamp(offset) })
const seed = (api, stateDir) => api.touchContinuityHead(input(stateDir))
const rows = stateDir => readFileSync(ledger(stateDir), 'utf8').trimEnd().split('\n').map(JSON.parse)
const refusal = (fn, code) => assert.throws(fn, error => error.code === `kira.continuity:${code}`)
const checks = []
function check(name, run) { checks.push([name, run]) }

check('first head rereads from the unsigned memory ledger', api => {
  const stateDir = fresh()
  assert.equal(api.readContinuityHead({ stateDir }), null)
  const head = seed(api, stateDir)
  assert.deepEqual(head, { ts: at, sessionId: 'session_a', messageCount: 3, possibleFork: null, grantsAuthority: false })
  assert.deepEqual(api.readContinuityHead({ stateDir }), head)
  assert.equal(memoryChain(stateDir).length, 1)
  assert.deepEqual(readdirSync(stateDir), ['remembered'])
  assert.deepEqual(readdirSync(dirname(ledger(stateDir))), ['aura.jsonl'])
  assert.equal(rows(stateDir)[0].tier, 'remembered')
})

check('another session within five minutes carries the overlap hint', api => {
  const stateDir = fresh()
  seed(api, stateDir)
  const head = api.touchContinuityHead(input(stateDir, 'session_b', 300_000))
  assert.deepEqual(head.possibleFork, { detected: true, previousSessionId: 'session_a', previousTs: at, ageSeconds: 300 })
  assert.deepEqual(api.readContinuityHead({ stateDir }), head)
  assert.equal(rows(stateDir).length, 2)
})

check('same session never flags overlap', api => {
  const stateDir = fresh()
  seed(api, stateDir)
  assert.equal(api.touchContinuityHead(input(stateDir, 'session_a', 1000)).possibleFork, null)
})

check('zero and exact fifteen minutes are inside the window', api => {
  for (const offset of [0, 900_000]) {
    const stateDir = fresh()
    seed(api, stateDir)
    assert.equal(api.touchContinuityHead(input(stateDir, 'session_b', offset)).possibleFork?.detected, true)
  }
})

check('fifteen minutes plus one millisecond is outside the window', api => {
  const stateDir = fresh()
  seed(api, stateDir)
  assert.equal(api.touchContinuityHead(input(stateDir, 'session_b', 900_001)).possibleFork, null)
})

check('state root must be explicit and absolute', api => {
  for (const stateDir of [undefined, '', '.', 'relative', '/bad\0root', '/bad\nroot']) {
    refusal(() => api.readContinuityHead({ stateDir }), 'state-root-invalid')
    refusal(() => api.touchContinuityHead(input(stateDir)), 'state-root-invalid')
  }
})

check('IDs counts and timestamps are bounded canonical metadata', api => {
  const stateDir = fresh()
  seed(api, stateDir)
  const before = readFileSync(ledger(stateDir))
  for (const [field, values, code] of [
    ['sessionId', ['', 'a'.repeat(129), '../session', 'a\nb', 42], 'session-invalid'],
    ['messageCount', [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '3'], 'message-count-invalid'],
    ['ts', [null, 'bad', '2026-02-30T00:00:00.000Z', '2026-04-18', '2026-04-18T00:00:00Z', 42], 'timestamp-invalid'],
  ]) for (const value of values) {
    refusal(() => api.touchContinuityHead({ ...input(stateDir), [field]: value }), code)
    assert.deepEqual(readFileSync(ledger(stateDir)), before)
  }
})

check('backward time refuses without moving the head', api => {
  const stateDir = fresh()
  seed(api, stateDir)
  const before = readFileSync(ledger(stateDir))
  for (const sessionId of ['session_a', 'session_b']) refusal(() => api.touchContinuityHead(input(stateDir, sessionId, -1)), 'timestamp-regressed')
  assert.deepEqual(readFileSync(ledger(stateDir)), before)
})

check('summary persona authority and caller paths are excluded', api => {
  const stateDir = fresh()
  seed(api, stateDir)
  const before = readFileSync(ledger(stateDir))
  for (const field of ['summary', 'worldview', 'persona', 'grantsAuthority', 'headPath', 'journalPath', 'forkWindowMs']) {
    refusal(() => api.touchContinuityHead({ ...input(stateDir), [field]: 'synthetic-excluded' }), 'fields-invalid')
  }
  assert.deepEqual(readFileSync(ledger(stateDir)), before)
})

function damaged(api, damage, code) {
  const stateDir = fresh()
  seed(api, stateDir)
  writeFileSync(ledger(stateDir), damage(readFileSync(ledger(stateDir), 'utf8')))
  const before = readFileSync(ledger(stateDir))
  refusal(() => api.readContinuityHead({ stateDir }), code)
  refusal(() => api.touchContinuityHead(input(stateDir, 'session_b', 1000)), code)
  assert.deepEqual(readFileSync(ledger(stateDir)), before)
}

check('torn malformed duplicate and non-object entries refuse', api => {
  damaged(api, text => text.trimEnd(), 'ledger-torn')
  for (const text of ['{\n', '\n', 'null\n', '[]\n', '{"op":1,"op":2}\n']) damaged(api, () => text, 'ledger-malformed')
  damaged(api, text => text.replace('"messageCount":3', '"messageCount":3,"messageCount":3'), 'ledger-malformed')
})

function rewrite(text, change, rehash = false) {
  const entry = JSON.parse(text)
  change(entry)
  if (rehash) {
    const { prev, hash, ...body } = entry
    entry.hash = auraEntryHash(prev, body)
  }
  return `${JSON.stringify(entry)}\n`
}

check('hash predecessor and sequence corruption refuse', api => {
  damaged(api, text => rewrite(text, entry => { entry.messageCount++ }), 'ledger-broken')
  damaged(api, text => rewrite(text, entry => { entry.prev = 'f'.repeat(64) }), 'ledger-broken')
  damaged(api, text => rewrite(text, entry => { entry.prev = 'f'.repeat(64) }, true), 'ledger-broken')
  damaged(api, text => rewrite(text, entry => { entry.sequence = 9 }, true), 'ledger-broken')
  damaged(api, text => rewrite(text, entry => { entry.sequence = 9; entry.op = 'index-content' }, true), 'ledger-broken')
})

check('rehashed heads cannot invent authority or overlap metadata', api => {
  for (const change of [entry => { entry.grantsAuthority = true }, entry => { entry.tier = 'signed' },
    entry => { entry.possibleFork = { detected: true } }, entry => { entry.summary = 'synthetic-excluded' }]) {
    damaged(api, text => rewrite(text, change, true), 'head-invalid')
  }
})

check('unreadable and symlink ledgers are not empty history', api => {
  for (const symlink of [false, true]) {
    const stateDir = fresh()
    mkdirSync(dirname(ledger(stateDir)))
    if (symlink) {
      const target = join(stateDir, 'target')
      writeFileSync(target, '')
      symlinkSync(target, ledger(stateDir))
    } else mkdirSync(ledger(stateDir))
    refusal(() => api.readContinuityHead({ stateDir }), 'ledger-unreadable')
    refusal(() => api.touchContinuityHead(input(stateDir)), 'ledger-unreadable')
  }
})

check('ordinary memory events and approved ledger are preserved', api => {
  const stateDir = fresh()
  seed(api, stateDir)
  const approved = join(stateDir, 'aura.jsonl')
  writeFileSync(approved, 'synthetic-approved-sentinel\n')
  const [entry] = chainAuraEntries(stateDir, [{ op: 'index-content', tier: 'remembered' }], { file: ledger(stateDir) })
  appendJournalLine({ file: ledger(stateDir), line: JSON.stringify(entry) })
  const before = readFileSync(ledger(stateDir), 'utf8')
  assert.equal(api.readContinuityHead({ stateDir }).sessionId, 'session_a')
  const head = api.touchContinuityHead(input(stateDir, 'session_b', 1000))
  assert.equal(head.possibleFork.previousSessionId, 'session_a')
  assert.ok(readFileSync(ledger(stateDir), 'utf8').startsWith(before))
  assert.equal(memoryChain(stateDir).length, 3)
  assert.equal(readFileSync(approved, 'utf8'), 'synthetic-approved-sentinel\n')
})

check('held ledger lock refuses without appending', api => {
  const stateDir = fresh()
  seed(api, stateDir)
  const before = readFileSync(ledger(stateDir))
  writeFileSync(`${ledger(stateDir)}.lock`, 'synthetic-held-lock')
  assert.throws(() => api.touchContinuityHead(input(stateDir, 'session_b', 1000)), error => error.code === 'lock:busy')
  assert.deepEqual(readFileSync(ledger(stateDir)), before)
})

async function concurrentWriters() {
  const stateDir = fresh()
  const childCode = `import { touchContinuityHead } from ${JSON.stringify(sourceURL.href)};
    touchContinuityHead(JSON.parse(process.argv[1]));`
  const run = sessionId => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', childCode, JSON.stringify(input(stateDir, sessionId))], { stdio: ['ignore', 'ignore', 'pipe'] })
    let stderr = ''
    child.stderr.on('data', data => { stderr += data })
    child.on('error', reject)
    child.on('exit', (code, signal) => {
      try { assert.equal(signal, null); assert.equal(code, 0, stderr); resolve() } catch (error) { reject(error) }
    })
  })
  await Promise.all(['session_a', 'session_b'].map(run))
  const entries = memoryChain(stateDir)
  assert.equal(entries.length, 2)
  assert.deepEqual(new Set(entries.map(entry => entry.sessionId)), new Set(['session_a', 'session_b']))
  assert.deepEqual(entries.map(entry => entry.sequence), [1, 2])
  assert.equal(entries[1].possibleFork.previousSessionId, entries[0].sessionId)
  assert.equal(production.readContinuityHead({ stateDir }).sessionId, entries[1].sessionId)
}

const mutants = [
  ['root guard', "if (typeof stateDir !== 'string' || !isAbsolute(stateDir) || /[\\u0000-\\u001f\\u007f]/u.test(stateDir))", 'if (false)', 5],
  ['ID guard', "if (typeof sessionId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(sessionId))", 'if (false)', 6],
  ['count guard', 'if (!Number.isSafeInteger(messageCount) || messageCount < 0)', 'if (false)', 6],
  ['time guard', 'if (!Number.isFinite(time) || new Date(time).toISOString() !== ts)', 'if (false)', 6],
  ['clock regression guard', 'if (ageMs !== null && ageMs < 0)', 'if (false)', 7],
  ['same-session exclusion', 'previous.sessionId !== sessionId', 'true', 2],
  ['window ceiling', 'ageMs <= WINDOW_MS', 'true', 4],
  ['inclusive window', 'ageMs <= WINDOW_MS', 'ageMs < WINDOW_MS', 3],
  ['overlap detection', 'previous !== null && previous.sessionId !== sessionId', 'false && previous.sessionId !== sessionId', 1],
  ['non-authority', 'possibleFork, grantsAuthority: false', 'possibleFork, grantsAuthority: true', 0],
  ['closed input', "if (Object.keys(input).some(key => !['sessionId', 'messageCount', 'ts'].includes(key)))", 'if (false)', 8],
  ['torn tail guard', "if (!text.endsWith('\\n'))", 'if (false)', 9],
  ['parse refusal', "catch { refuse('ledger-malformed') }", 'catch { return null }', 9],
  ['strict JSON', "parseStrictText(line, 'continuity memory ledger')", 'JSON.parse(line)', 9],
  ['entry object guard', "if (entry === null || typeof entry !== 'object' || Array.isArray(entry))", 'if (false)', 9],
  ['chain hash', 'auraEntryHash(prev, body) !== hash', 'false', 10],
  ['chain predecessor', 'named !== prev', 'false', 10],
  ['chain sequence', 'body.sequence !== ++sequence', '(++sequence, false)', 10],
  ['head shape', "if (canonicalJSON(body) !== canonicalJSON({ op: OP, tier: 'remembered', ...expected, sequence }))", 'if (false)', 11],
  ['read failure refusal', "refuse('ledger-unreadable')", 'return null', 12],
  ['shared ledger lock', 'return withFileLock(file, () => {', 'return ((_file, fn) => fn())(file, () => {', 14],
  ['durable append', 'durableAppend(file,', ';(() => {})(file,', 0],
]

function load(text) {
  const resolved = text.replace(/from '(\.\/[^']+)'/gu, (_, specifier) => `from '${new URL(specifier, sourceURL).href}'`)
  return import(`data:text/javascript;base64,${Buffer.from(resolved).toString('base64')}`)
}

async function defaultClock(text) {
  const api = await load(text.replace('withFileLock }', 'withFileLock as realLock }') + `
    let clock = ${Date.parse(at)};
    const Date = class extends globalThis.Date {
      constructor(...args) { super(...(args.length ? args : [clock])); }
    };
    function withFileLock(file, fn) {
      return realLock(file, () => { clock += 1000; return fn(); });
    }
  `)
  const head = api.touchContinuityHead({ stateDir: fresh(), sessionId: 'session_clock', messageCount: 0 })
  assert.equal(head.ts, stamp(1000), 'default clock is sampled after acquiring the real ledger lock')
}

try {
  for (const [name, run] of checks) {
    await run(production)
    casesRun++
    console.log(`PASS ${name}`)
  }
  await concurrentWriters()
  casesRun++
  console.log('PASS concurrent processes retain both linked events')
  await defaultClock(source)
  casesRun++
  console.log('PASS default timestamp is captured inside the ledger lock')
  if (process.argv.includes('--mutate')) for (const [name, before, after, index] of mutants) {
    assert.equal(source.split(before).length, 2, `${name}: unique mutation anchor`)
    const api = await load(source.replace(before, after))
    await assert.rejects(async () => checks[index][1](api), error => error.code === 'ERR_ASSERTION', `${name}: assertion must kill removed protection`)
    killed++
    console.log(`KILLED ${name}`)
  }
  if (process.argv.includes('--mutate')) {
    const line = '    const snapshot = { ...input, ts: input.ts === undefined ? new Date().toISOString() : input.ts }\n'
    assert.equal(source.split(line).length, 2)
    const early = source.replace(line, '').replace('  return withFileLock(file,', `${line}  return withFileLock(file,`)
    await assert.rejects(() => defaultClock(early), error => error.code === 'ERR_ASSERTION')
    killed++
    console.log('KILLED timestamp captured before lock')
  }
  console.log(`kira-continuity-head: ${casesRun} passed, 0 failed; ${killed} mutants killed; source fixtures only`)
} finally {
  rmSync(root, { recursive: true, force: true })
}
