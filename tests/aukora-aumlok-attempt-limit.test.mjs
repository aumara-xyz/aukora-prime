// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercises persisted presentation limits and removes each guard in disposable imports.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const SUBJECT = `aukora:1:${'a'.repeat(64)}`
const UNKNOWN = `aukora:1:${'c'.repeat(64)}`
const ROOT = 'b'.repeat(64)
const WRONG = 'd'.repeat(64)
const REFUSED = { ok: false, reason: 'aumlok:enrollment-refused' }
const YES = { ok: true, recognized: true, authority: 'none' }
const HOOK = Symbol.for('aumlok.attempt.test.connection')
const here = fileURLToPath(import.meta.url)
const root = fileURLToPath(new URL('../', import.meta.url))
const pause = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)

if (process.argv[2] === '--worker') {
  const [url, file, mode, countText, startText] = process.argv.slice(3)
  const { openAttemptLimiter } = await import(url)
  const limiter = openAttemptLimiter({ file, now: () => 1000,
    ...(mode === 'concurrent' ? { limit: 100 } : {}),
    rootForSubject: subject => {
      if (mode === 'concurrent') pause(20)
      return subject === SUBJECT ? ROOT : undefined
    } })
  while (Date.now() < Number(startText)) pause(5)
  const results = Array.from({ length: Number(countText) }, () => limiter.present({
    subject: SUBJECT, rootId: mode === 'recognize' ? ROOT : WRONG,
  }))
  limiter.close()
  process.stdout.write(JSON.stringify(results))
} else {
  const sourcePath = join(root, 'plugins/aukora-aumlok/lib/attempt-limit.mjs')
  const source = readFileSync(sourcePath, 'utf8')
  const scratch = join(root, '.aumlok-tmp')
  mkdirSync(scratch, { recursive: true })

  function moduleUrl(text) {
    const instrumented = text.replace("'./subject.mjs'", JSON.stringify(pathToFileURL(
      join(root, 'plugins/aukora-aumlok/lib/subject.mjs')).href))
      .replace('db = new DatabaseSync(file)',
        'db = new DatabaseSync(file); globalThis[Symbol.for("aumlok.attempt.test.connection")]?.(db)')
    return `data:text/javascript;base64,${Buffer.from(instrumented).toString('base64')}`
  }

  async function fixture(url, test) {
    const directory = mkdtempSync(join(scratch, 'al-'))
    const file = join(directory, 'attempts.sqlite')
    const { openAttemptLimiter } = await import(url)
    const handles = []
    let clock = 1000
    let lookups = 0
    const context = { file, url,
      at: value => { clock = value },
      get lookups() { return lookups },
      open(options = {}) {
        let db
        globalThis[HOOK] = connection => { db = connection }
        try {
          const limiter = openAttemptLimiter({ file, initialize: true, now: () => clock,
            rootForSubject: subject => { lookups += 1; return subject === SUBJECT ? ROOT : undefined },
            ...options })
          handles.push(limiter)
          return { limiter, db }
        } finally { delete globalThis[HOOK] }
      },
    }
    try { await test(context) } finally {
      for (const handle of handles) { try { handle.close() } catch { /* Already closed. */ } }
      rmSync(directory, { recursive: true, force: true })
    }
  }

  const row = (db, subject = SUBJECT) => {
    const value = db.prepare('SELECT * FROM attempts WHERE subject=?').get(subject)
    return value ? { ...value } : undefined
  }
  const present = (limiter, rootId = WRONG, subject = SUBJECT) => limiter.present({ subject, rootId })
  const refused = value => assert.deepEqual(value, REFUSED)
  const configError = { code: 'aumlok:attempt-config-invalid' }
  const storeError = { code: 'aumlok:attempt-store-unavailable' }
  function worker(url, file, mode, count = 1, start = 0) {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [here, '--worker', url, file, mode, String(count), String(start)],
        { stdio: ['ignore', 'pipe', 'pipe'] })
      let out = '', err = ''
      child.stdout.on('data', chunk => { out += chunk })
      child.stderr.on('data', chunk => { err += chunk })
      child.on('error', reject)
      child.on('close', code => {
        if (code !== 0) return reject(new Error(`worker exited ${code}: ${err}`))
        try { resolve(JSON.parse(out)) } catch (cause) { reject(cause) }
      })
    })
  }

  const cases = new Map([
    ['default fifth failure locks', c => {
      const { limiter, db } = c.open()
      for (let n = 0; n < 4; n++) refused(present(limiter))
      assert.deepEqual(present(limiter, ROOT), YES)
      refused(present(limiter))
      assert.equal(row(db).failures, 5)
      assert.equal(row(db).locked_until, 61_000)
      refused(present(limiter, ROOT))
      c.at(61_000)
      assert.deepEqual(present(limiter, ROOT), YES)
    }],
    ['custom threshold and growing capped interval', c => {
      const { limiter, db } = c.open({ limit: 2, baseMs: 10, maxMs: 25 })
      refused(present(limiter)); assert.equal(row(db).locked_until, 0)
      for (const [at, until] of [[1000, 1010], [1010, 1030], [1030, 1055], [1055, 1080]]) {
        c.at(at); refused(present(limiter)); assert.equal(row(db).locked_until, until)
      }
    }],
    ['locked traffic does not extend or consult roots', c => {
      const { limiter, db } = c.open({ limit: 1, baseMs: 100, maxMs: 400 })
      refused(present(limiter))
      const lookups = c.lookups
      c.at(1050)
      refused(present(limiter)); refused(present(limiter, ROOT))
      assert.equal(c.lookups, lookups)
      assert.equal(row(db).failures, 1)
      assert.equal(row(db).locked_until, 1100)
      c.at(1100); assert.deepEqual(present(limiter, ROOT), YES)
    }],
    ['public root replay does not reset failures', c => {
      const { limiter, db } = c.open()
      for (let n = 0; n < 4; n++) refused(present(limiter))
      for (let n = 0; n < 3; n++) assert.deepEqual(present(limiter, ROOT), YES)
      assert.equal(row(db).failures, 4)
      refused(present(limiter)); refused(present(limiter, ROOT))
    }],
    ['unknown subject and dummy zero have identical refusals and state', c => {
      const { limiter, db } = c.open()
      for (let n = 0; n < 5; n++) {
        refused(present(limiter)); refused(present(limiter, '0'.repeat(64), UNKNOWN))
      }
      const known = row(db), unknown = row(db, UNKNOWN)
      assert.deepEqual({ ...known, subject: UNKNOWN }, unknown)
      refused(present(limiter, ROOT)); refused(present(limiter, ROOT, UNKNOWN))
    }],
    ['each claimed subject has its own allowance', c => {
      const { limiter, db } = c.open({ limit: 1, rootForSubject: () => ROOT })
      refused(present(limiter)); refused(present(limiter, ROOT))
      assert.deepEqual(present(limiter, ROOT, UNKNOWN), YES)
      assert.equal(row(db).failures, 1)
      assert.equal(row(db, UNKNOWN).failures, 0)
    }],
    ['mismatched and malformed roots consume attempts', c => {
      const { limiter, db } = c.open({ rootForSubject: () => '0'.repeat(64) })
      for (const candidate of [ROOT, undefined, null, 42, 'z'.repeat(64)]) refused(present(limiter, candidate))
      assert.equal(row(db).failures, 5)
      refused(present(limiter, '0'.repeat(64)))
    }],
    ['malformed subjects and null never discover a root', c => {
      const { limiter, db } = c.open({ rootForSubject: () => ROOT })
      for (const input of [undefined, null, 1, {}, { subject: SUBJECT.toUpperCase(), rootId: ROOT },
        { subject: `${SUBJECT} `, rootId: ROOT }, { subject: 'owner', rootId: ROOT }]) refused(limiter.present(input))
      assert.equal(db.prepare('SELECT count(*) AS n FROM attempts').get().n, 0)
      const { limiter: tracked } = c.open()
      refused(tracked.present(null)); refused(present(tracked, ROOT, 'owner'))
      assert.equal(c.lookups, 0)
    }],
    ['invalid configuration refuses before opening storage', c => {
      for (const options of [{ file: ':memory:' }, { rootForSubject: null }, { now: null },
        { initialize: 1 }, { limit: 0 }, { limit: 1.5 }, { baseMs: 0 }, { maxMs: 1 },
        { maxMs: Infinity }, { baseMs: Number.MAX_SAFE_INTEGER + 1 }]) {
        assert.throws(() => c.open(options), configError)
      }
      assert.equal(existsSync(c.file), false)
    }],
    ['missing state requires explicit initialization', c => {
      assert.throws(() => c.open({ initialize: false }), storeError)
      assert.equal(existsSync(c.file), false)
      const { limiter } = c.open(); limiter.close()
      const { limiter: reopened } = c.open({ initialize: false })
      assert.deepEqual(present(reopened, ROOT), YES)
    }],
    ['persisted policy cannot be weakened on reopen', c => {
      c.open()
      for (const options of [{ limit: 6 }, { baseMs: 30_000 }, { maxMs: 60_000 }]) {
        assert.throws(() => c.open({ initialize: false, ...options }), configError)
        assert.throws(() => c.open(options), configError)
      }
    }],
    ['corrupt state refuses instead of recognizing', c => {
      const { limiter, db } = c.open()
      refused(present(limiter))
      for (const column of ['failures', 'locked_until', 'last_seen']) {
        db.prepare(`UPDATE attempts SET failures=0, locked_until=0, last_seen=0, ${column}=-1`).run()
        refused(present(limiter, ROOT))
        assert.equal(row(db)[column], -1)
      }
    }],
    ['lookup failures and asynchronous lookups count as failures', c => {
      const { limiter, db } = c.open({ rootForSubject: () => { throw new Error('fixture lookup unavailable') } })
      refused(present(limiter, ROOT)); assert.equal(row(db).failures, 1)
      const { limiter: asynchronous } = c.open({ rootForSubject: () => Promise.resolve(ROOT) })
      refused(present(asynchronous, ROOT)); assert.equal(row(db).failures, 2)
    }],
    ['failed commit never releases recognition', c => {
      const { limiter, db } = c.open()
      const exec = db.exec.bind(db)
      let commits = 0
      db.exec = sql => { if (sql === 'COMMIT') { commits += 1; throw new Error('fixture commit failure') }; return exec(sql) }
      refused(present(limiter, ROOT))
      assert.equal(commits, 1)
      assert.equal(row(db), undefined)
    }],
    ['unavailable storage never releases recognition', c => {
      const { limiter } = c.open(); limiter.close()
      refused(present(limiter, ROOT))
    }],
    ['backward clocks retain the persisted time floor', c => {
      const { limiter, db } = c.open({ limit: 1, baseMs: 100, maxMs: 400 })
      refused(present(limiter)); c.at(1050); refused(present(limiter))
      c.at(950); refused(present(limiter, ROOT))
      assert.equal(row(db).last_seen, 1050)
      assert.equal(row(db).locked_until, 1100)
      c.at(1100); assert.deepEqual(present(limiter, ROOT), YES)
    }],
    ['invalid and overflowing clocks cannot recognize', c => {
      const { limiter, db } = c.open()
      for (const clock of [-1, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER]) {
        c.at(clock); refused(present(limiter, ROOT)); assert.equal(row(db), undefined)
      }
    }],
    ['largest configured cap is reached without arithmetic overflow', c => {
      c.at(0)
      const { limiter, db } = c.open({ limit: 1, baseMs: 1, maxMs: Number.MAX_SAFE_INTEGER })
      refused(present(limiter))
      db.prepare('UPDATE attempts SET failures=53, locked_until=0, last_seen=0').run()
      refused(present(limiter))
      assert.equal(row(db).locked_until, Number.MAX_SAFE_INTEGER)
      refused(present(limiter, ROOT))
    }],
    ['actual connection uses durable SQLite settings', c => {
      const { db } = c.open()
      assert.equal(db.prepare('PRAGMA journal_mode').get().journal_mode, 'delete')
      assert.equal(db.prepare('PRAGMA synchronous').get().synchronous, 3)
    }],
    ['fresh processes retain failed attempts and the lock', async c => {
      const { limiter } = c.open(); limiter.close()
      assert.deepEqual(await worker(c.url, c.file, 'fail', 4), Array(4).fill(REFUSED))
      assert.deepEqual(await worker(c.url, c.file, 'fail'), [REFUSED])
      assert.deepEqual(await worker(c.url, c.file, 'recognize'), [REFUSED])
      const reopened = c.open({ initialize: false })
      assert.equal(row(reopened.db).failures, 5)
      assert.equal(row(reopened.db).locked_until, 61_000)
    }],
    ['concurrent processes cannot lose increments', async c => {
      const { limiter } = c.open({ limit: 100 }); limiter.close()
      const results = await Promise.all(Array.from({ length: 6 }, () =>
        worker(c.url, c.file, 'concurrent', 4, Date.now() + 300)))
      for (const values of results) assert.deepEqual(values, Array(4).fill(REFUSED))
      const reopened = c.open({ initialize: false, limit: 100 })
      assert.equal(row(reopened.db).failures, 24)
    }],
  ])

  const url = moduleUrl(source)
  let passed = 0
  for (const [name, test] of cases) { await fixture(url, test); passed += 1; console.log(`PASS ${name}`) }
  console.log(`AUMLOK_ATTEMPT_LIMIT: ${passed} passed, 0 failed`)

  if (process.argv.includes('--mutate')) {
    const mutations = [
      ['default-five', 'limit = 5', 'limit = 6', 'default fifth failure locks'],
      ['configured-limit', 'state.failures >= limit', 'state.failures >= 5', 'custom threshold and growing capped interval'],
      ['lock', 'if (at >= state.locked_until)', 'if (true)', 'default fifth failure locks'],
      ['growth', '2 ** Math.min(53, state.failures - limit)', '1', 'custom threshold and growing capped interval'],
      ['cap', 'Math.min(maxMs, baseMs * 2 ** Math.min(53, state.failures - limit))', 'baseMs * 2 ** Math.min(53, state.failures - limit)', 'custom threshold and growing capped interval'],
      ['locked-traffic', 'let recognized = false', 'let recognized = false; if (at < state.locked_until) state.locked_until = at + baseMs', 'locked traffic does not extend or consult roots'],
      ['success-reset', 'if (!recognized) {', 'if (recognized) state.failures = 0; if (!recognized) {', 'public root replay does not reset failures'],
      ['unknown-zero', 'known && shaped && equal', 'shaped && equal', 'unknown subject and dummy zero have identical refusals and state'],
      ['per-subject', '.get(subject)', ".get('aukora:1:' + 'a'.repeat(64))", 'each claimed subject has its own allowance'],
      ['root-shape', 'known && shaped && equal', 'known && equal', 'mismatched and malformed roots consume attempts'],
      ['root-equality', 'known && shaped && equal', 'known && shaped', 'mismatched and malformed roots consume attempts'],
      ['subject', 'if (!isSubject(subject)) return REFUSED', '', 'malformed subjects and null never discover a root'],
      ['configuration', /if \(typeof file !== 'string'[\s\S]*?throw error\(ATTEMPT_REFUSE.CONFIG\)/u, '', 'invalid configuration refuses before opening storage'],
      ['missing-store', 'if (!initialize && !existsSync(file)) throw error(ATTEMPT_REFUSE.STORE)', '', 'missing state requires explicit initialization'],
      ['policy', "db.prepare('SELECT policy FROM attempt_policy WHERE id=1').get()?.policy !== policy", 'false', 'persisted policy cannot be weakened on reopen'],
      ['corrupt-state', 'if (![state.failures, state.locked_until, state.last_seen].every(integer)) throw error(ATTEMPT_REFUSE.STORE)', '', 'corrupt state refuses instead of recognizing'],
      ['commit-before-verdict', "db.exec('COMMIT')\n      transaction = false", "if (recognized) return RECOGNIZED\n      db.exec('COMMIT')\n      transaction = false", 'failed commit never releases recognition'],
      ['store-fail-closed', "return REFUSED\n    }\n  }", "return RECOGNIZED\n    }\n  }", 'unavailable storage never releases recognition'],
      ['clock-floor', 'Math.max(clock, state.last_seen)', 'clock', 'backward clocks retain the persisted time floor'],
      ['clock-validity', 'if (!integer(clock)) throw error(ATTEMPT_REFUSE.CONFIG)', '', 'invalid and overflowing clocks cannot recognize'],
      ['clock-overflow', 'if (at > Number.MAX_SAFE_INTEGER - maxMs) throw error(ATTEMPT_REFUSE.CONFIG)', '', 'invalid and overflowing clocks cannot recognize'],
      ['cap-exponent', 'Math.min(53, state.failures - limit)', 'Math.min(52, state.failures - limit)', 'largest configured cap is reached without arithmetic overflow'],
      ['journal-durability', 'PRAGMA journal_mode=DELETE', 'PRAGMA journal_mode=OFF', 'actual connection uses durable SQLite settings'],
      ['sync-durability', 'PRAGMA synchronous=EXTRA', 'PRAGMA synchronous=OFF', 'actual connection uses durable SQLite settings'],
      ['persisted-counters', '.run(subject, state.failures, state.locked_until, at)', '.run(subject, 0, 0, at)', 'fresh processes retain failed attempts and the lock'],
      ['atomic-increments', /BEGIN IMMEDIATE/gu, 'BEGIN DEFERRED', 'concurrent processes cannot lose increments'],
    ]
    let killed = 0
    for (const [name, before, after, caseName] of mutations) {
      const altered = source.replace(before, after)
      assert.notEqual(altered, source, `mutation ${name} still addresses source`)
      let failure
      try { await fixture(moduleUrl(altered), cases.get(caseName)) } catch (cause) { failure = cause }
      assert.ok(failure instanceof assert.AssertionError, `mutation ${name} must fail an assertion, got ${failure ?? 'PASS'}`)
      killed += 1
      console.log(`MUTATION ${name}: KILLED (assertion)`)
    }
    console.log(`AUMLOK_ATTEMPT_MUTATIONS: ${killed} killed, 0 survived`)
  }
}
