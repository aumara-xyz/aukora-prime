// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercises first binding and removes its guards in disposable module imports.
import assert from 'node:assert/strict'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { bindV3 } from '../plugins/aukora-aumlok/lib/bind-v3.mjs'
import { phraseWordList } from '../plugins/aukora-aumlok/lib/ceremony-phrase.mjs'
import { resolveMemoryIdentity } from '../plugins/aukora-kira/lib/memory-identity.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const sourcePath = join(root, 'plugins/aukora-aumlok/lib/browser-binding.mjs')
const source = readFileSync(sourcePath, 'utf8')
const HOOK = Symbol.for('aumlok.browser.test.bind')
const WRITE_HOOK = Symbol.for('aumlok.browser.test.overlay')
const handle = 'fixture-owner'
const scratch = mkdtempSync(join(root, '.aumlok-browser-'))
const recordName = 'local-control.json', seedName = 'machine-seed-v3.json'
const attemptsName = 'browser-binding-attempts.sqlite', lockName = 'browser-first-bind.lock'
const overlayName = 'kira-deployment-overlay.patch.yml'
let sample

function moduleUrl(text) {
  const imports = text.replace(/from '([^']+)'/gu, (all, name) => name.startsWith('.')
    ? `from ${JSON.stringify(new URL(name, pathToFileURL(sourcePath)).href)}` : all)
    .replace('import { bindV3, BIND_REFUSE }', 'import { bindV3 as actualBindV3, BIND_REFUSE }')
    .replace('import { durableWrite, readJsonStrictBytes', 'import { durableWrite as actualDurableWrite, readJsonStrictBytes')
  return `data:text/javascript;base64,${Buffer.from(`${imports}\nconst bindV3 = input => globalThis[Symbol.for('aumlok.browser.test.bind')]?.(input) ?? actualBindV3(input)\nconst durableWrite = (path, text) => globalThis[Symbol.for('aumlok.browser.test.overlay')] ? globalThis[Symbol.for('aumlok.browser.test.overlay')](path, text, actualDurableWrite) : actualDurableWrite(path, text)\n`).toString('base64')}`
}

async function fixture(url, test) {
  const base = mkdtempSync(join(scratch, 'case-'))
  const config = { dir: join(base, 'controller'), supportRoot: join(base, 'support'), stateRoot: join(base, 'state'), now: () => clock }
  let clock = 1_700_000_000_000
  const { createBrowserBinding } = await import(url)
  const services = []
  const c = { ...config, base,
    setTime(value) { clock = value },
    time() { return clock },
    open(overrides = {}) { const service = createBrowserBinding({ ...config, ...overrides }); services.push(service); return service },
    drawn(service, options = {}) {
      const prepared = service.prepare({ handle, ...options })
      assert.equal(prepared.ok, true, prepared.reason)
      return prepared.draw
    },
    submit(service, draw, overrides = {}) {
      return service.bind({ ceremonyId: draw.ceremonyId, typedPhrase: draw.words.join(' '), acknowledged: true, ...overrides })
    },
    hook(fn) { globalThis[HOOK] = fn },
    install(input) {
      copyFileSync(join(sample.directory, recordName), join(input.directory, recordName))
      copyFileSync(join(sample.directory, seedName), join(input.directory, seedName))
      chmodSync(join(input.directory, recordName), 0o600); chmodSync(join(input.directory, seedName), 0o600)
      return sample.bound
    },
  }
  c.hook(input => c.install(input))
  try { await test(c) } finally {
    delete globalThis[HOOK]
    delete globalThis[WRITE_HOOK]
    for (const service of services) service.close()
    rmSync(base, { recursive: true, force: true })
  }
}
const reason = (value, expected) => { assert.equal(value.ok, false); assert.equal(value.reason, expected) }
const noRecord = c => assert.equal(existsSync(join(c.dir, recordName)), false)
const wrongPhrase = draw => {
  const list = phraseWordList(draw.language)
  return [draw.words[0] === list[0] ? list[1] : list[0], ...draw.words.slice(1)].join(' ')
}

const cases = new Map([
  ['configuration and private directory', c => {
    for (const config of [{ dir: 'relative' }, { stateRoot: `${c.stateRoot}/..` }, { supportRoot: `${c.supportRoot}\n` }, { now: null }]) {
      assert.throws(() => c.open(config), { code: 'aumlok:browser-binding-config' })
    }
    mkdirSync(c.dir, { mode: 0o777 }); chmodSync(c.dir, 0o777)
    assert.throws(() => c.open(), { code: 'aumlok:browser-binding-storage' })
  }],
  ['symbolic directory refuses', c => {
    const target = join(c.base, 'target'); mkdirSync(target, { mode: 0o700 }); symlinkSync(target, c.dir)
    assert.throws(() => c.open(), { code: 'aumlok:browser-binding-storage' })
    assert.deepEqual(readdirSync(target), [])
  }],
  ['handle and language refuse before a draw', c => {
    const service = c.open()
    reason(service.prepare({ handle: 'bad handle' }), 'aumlok:kdf-handle-malformed')
    reason(service.prepare({ language: 'en' }), 'aumlok:kdf-handle-absent')
    reason(service.prepare({ handle, language: 'unsupported' }), 'aumlok:phrase-language-unknown')
    noRecord(c)
  }],
  ['one pending draw and exact cancel identifier', c => {
    const service = c.open(), draw = c.drawn(service)
    reason(service.prepare({ handle }), 'aumlok:browser-binding-busy')
    reason(service.cancel({ ceremonyId: 'other' }), 'aumlok:no-pending-draw')
    assert.equal(service.cancel({ ceremonyId: draw.ceremonyId }).ok, true)
    reason(service.cancel({ ceremonyId: draw.ceremonyId }), 'aumlok:no-pending-draw')
  }],
  ['unknown bind identifier cannot spend a draw', async c => {
    const service = c.open(), draw = c.drawn(service)
    const value = await c.submit(service, draw, { ceremonyId: 'other' })
    reason(value, 'aumlok:no-pending-draw'); assert.equal(value.drawSpent, false)
    assert.equal(service.cancel({ ceremonyId: draw.ceremonyId }).ok, true)
    noRecord(c)
  }],
  ['acknowledgement is explicit and spends the draw', async c => {
    const service = c.open(), draw = c.drawn(service)
    reason(await c.submit(service, draw, { acknowledged: 'true' }), 'aumlok:browser-acknowledgement-required')
    reason(await c.submit(service, draw), 'aumlok:no-pending-draw')
    noRecord(c)
  }],
  ['bounded phrase shape refuses without echo', async c => {
    const service = c.open()
    for (const typedPhrase of [null, 'x'.repeat(513), 'unlisted-private-fixture', 'abandon ability']) {
      const draw = c.drawn(service)
      const value = await c.submit(service, draw, { typedPhrase })
      reason(value, 'aumlok:phrase-shape'); assert.equal(value.drawSpent, true)
      assert.deepEqual(Object.keys(value).sort(), ['drawSpent', 'ok', 'reason'])
    }
    const draw = c.drawn(service)
    reason(await c.submit(service, draw, { typedPhrase: draw.words.join(' '.repeat(100)) }), 'aumlok:phrase-shape')
    noRecord(c)
  }],
  ['mismatched valid words spend the draw', async c => {
    const service = c.open(), draw = c.drawn(service)
    reason(await c.submit(service, draw, { typedPhrase: wrongPhrase(draw) }), 'aumlok:phrase-mismatch')
    reason(await c.submit(service, draw), 'aumlok:no-pending-draw')
    noRecord(c)
  }],
  ['expiry and invalid clocks refuse', async c => {
    const service = c.open(), draw = c.drawn(service)
    c.setTime(c.time() + 600_000)
    reason(await c.submit(service, draw), 'aumlok:browser-draw-expired')
    const next = c.drawn(service); c.setTime(NaN)
    reason(await c.submit(service, next), 'aumlok:browser-binding-config')
    reason(service.prepare({ handle }), 'aumlok:browser-binding-config')
    noRecord(c)
  }],
  ['fifth wrong type-back locks the node across reopen', async c => {
    let service = c.open()
    for (let n = 0; n < 5; n++) {
      const draw = c.drawn(service)
      reason(await c.submit(service, draw, { typedPhrase: wrongPhrase(draw) }), 'aumlok:phrase-mismatch')
    }
    reason(service.prepare({ handle }), 'aumlok:enrollment-refused')
    service.close(); service = c.open()
    reason(service.prepare({ handle }), 'aumlok:enrollment-refused')
    c.setTime(c.time() + 60_000)
    assert.equal(service.prepare({ handle }).ok, true)
    noRecord(c)
  }],
  ['already drawn valid words refuse a later limiter lock', async c => {
    const one = c.open(), prepared = c.drawn(one), two = c.open()
    for (let n = 0; n < 5; n++) {
      const draw = c.drawn(two)
      reason(await c.submit(two, draw, { typedPhrase: wrongPhrase(draw) }), 'aumlok:phrase-mismatch')
    }
    reason(await c.submit(one, prepared), 'aumlok:enrollment-refused')
    noRecord(c)
  }],
  ['missing attempt state cannot reset the allowance', c => {
    const service = c.open(), draw = c.drawn(service)
    service.cancel({ ceremonyId: draw.ceremonyId }); service.close()
    unlinkSync(join(c.dir, attemptsName))
    const reopened = c.open()
    reason(reopened.prepare({ handle }), 'aumlok:attempt-store-unavailable')
    noRecord(c)
  }],
  ['restart before the first draw retains usable attempt state', c => {
    const service = c.open()
    assert.deepEqual(service.status(), { ok: true, bound: false })
    service.close()
    assert.equal(c.open().prepare({ handle }).ok, true)
    noRecord(c)
  }],
  ['attempt database symlink refuses', c => {
    const service = c.open(); service.close()
    const path = join(c.dir, attemptsName), target = join(c.base, 'external-attempts.sqlite')
    copyFileSync(path, target); unlinkSync(path); symlinkSync(target, path)
    reason(c.open().prepare({ handle }), 'aumlok:attempt-store-unavailable')
    noRecord(c)
  }],
  ['closed coordinator cannot draw', c => {
    const service = c.open(); service.close()
    reason(service.prepare({ handle }), 'aumlok:browser-binding-storage')
  }],
  ['occupied record and retained lock refuse before derivation', c => {
    const service = c.open()
    writeFileSync(join(c.dir, recordName), 'unreadable existing binding', { mode: 0o600 })
    reason(service.prepare({ handle }), 'aumlok:bind-already-bound')
    assert.equal(service.status().ok, false)
    unlinkSync(join(c.dir, recordName))
    writeFileSync(join(c.dir, lockName), '', { mode: 0o600 })
    reason(service.prepare({ handle }), 'aumlok:browser-binding-busy')
    noRecord(c)
  }],
  ['concurrent bind uses the exclusive persistent lock', async c => {
    const one = c.open(), first = c.drawn(one)
    const two = c.open(), second = c.drawn(two)
    let release, entered
    const reached = new Promise(resolve => { entered = resolve })
    const held = new Promise(resolve => { release = resolve })
    let calls = 0
    c.hook(async input => { calls++; entered(); if (calls === 1) await held; return c.install(input) })
    const pending = c.submit(one, first)
    await reached
    const competing = await c.submit(two, second)
    release(); const completed = await pending
    reason(competing, 'aumlok:browser-binding-busy')
    assert.equal(completed.ok, true, completed.reason); assert.equal(calls, 1)
    assert.equal(existsSync(join(c.dir, lockName)), true)
  }],
  ['saved record must match the binding result', async c => {
    const service = c.open(), draw = c.drawn(service)
    c.hook(input => { const value = c.install(input); return { ...value, projection: { ...value.projection, subject: `aukora:1:${'f'.repeat(64)}` } } })
    reason(await c.submit(service, draw), 'aumlok:bind-record-unreadable')
    assert.equal(existsSync(join(c.supportRoot, overlayName)), false)
    reason(service.prepare({ handle }), 'aumlok:bind-already-bound')
  }],
  ['kept seed must reproduce its registered public key', async c => {
    const service = c.open(), draw = c.drawn(service)
    c.hook(input => {
      const value = c.install(input), path = join(input.directory, seedName)
      const seed = JSON.parse(readFileSync(path, 'utf8')); seed.ed25519SeedHex = '00'.repeat(32)
      writeFileSync(path, JSON.stringify(seed), { mode: 0o600 }); return value
    })
    reason(await c.submit(service, draw), 'aumlok:bind-record-unreadable')
    assert.equal(existsSync(join(c.supportRoot, overlayName)), false)
  }],
  ['existing overlay identity or wrong memory path refuses', c => {
    const service = c.open(), path = join(c.supportRoot, overlayName)
    for (const memory of [
      `subject: "aukora:1:${'f'.repeat(64)}"`,
      'subject: aumlok:subject:owner\n      stateDir: /other/private-memory',
      'subject: aumlok:subject:owner\n      subject: aumlok:subject:owner',
    ]) {
      writeFileSync(path, `- id: aukora-kira\n  config:\n    memoryOwner:\n      ${memory}\n`, { mode: 0o600 })
      reason(service.prepare({ handle }), 'aumlok:browser-memory-overlay-refused')
    }
    writeFileSync(path, '#'.repeat(65 * 1024), { mode: 0o600 })
    reason(service.prepare({ handle }), 'aumlok:browser-memory-overlay-refused')
    noRecord(c)
  }],
  ['placeholder overlay preserves unrelated deployment options', async c => {
    const service = c.open(), path = join(c.supportRoot, overlayName)
    writeFileSync(path, `- id: aukora-kira\n  config:\n    openvikingHome: /private/synthetic-viking\n    memoryOwner:\n      subject: aumlok:subject:owner\n      permittedPrivacy: [local]\n`, { mode: 0o600 })
    const draw = c.drawn(service); c.hook(input => c.install(input))
    const result = await c.submit(service, draw)
    assert.equal(result.ok, true, result.reason)
    assert.match(readFileSync(path, 'utf8'), /openvikingHome: \/private\/synthetic-viking/u)
    assert.deepEqual(resolveMemoryIdentity({ supportRoot: c.supportRoot, installed: true, env: {} }), {
      subject: result.binding.subject, stateDir: join(c.stateRoot, 'kira-memory'),
    })
  }],
  ['changed overlay refuses rather than replacing it', async c => {
    const service = c.open(), draw = c.drawn(service), path = join(c.supportRoot, overlayName)
    const text = '- id: aukora-kira\n  config:\n    memoryOwner:\n      subject: aumlok:subject:owner\n'
    c.hook(input => { const value = c.install(input); writeFileSync(path, text, { mode: 0o600 }); return value })
    reason(await c.submit(service, draw), 'aumlok:browser-memory-overlay-refused')
    assert.equal(readFileSync(path, 'utf8'), text)
    assert.equal(existsSync(join(c.dir, lockName)), true)
  }],
  ['saved memory identity is checked before success', async c => {
    const service = c.open(), draw = c.drawn(service)
    globalThis[WRITE_HOOK] = (path, text, write) => write(path, text.replace(/subject: "aukora:1:[0-9a-f]{64}"/u, `subject: "aukora:1:${'f'.repeat(64)}"`))
    reason(await c.submit(service, draw), 'aumlok:browser-memory-overlay-refused')
    assert.equal(service.status().bound, true)
  }],
  ['unknown exception codes cannot echo phrase material', async c => {
    const service = c.open(), draw = c.drawn(service)
    c.hook(() => { throw Object.assign(new Error(draw.words.join(' ')), { code: `aumlok:${draw.words.join('-')}` }) })
    const value = await c.submit(service, draw)
    reason(value, 'aumlok:bind-write-failed')
    assert.equal(JSON.stringify(value).includes(draw.words.join('-')), false)
    assert.equal(existsSync(join(c.dir, lockName)), false)
    noRecord(c)
  }],
  ['failed bind cannot unlink a replacement lock', async c => {
    const service = c.open(), draw = c.drawn(service), path = join(c.dir, lockName)
    c.hook(() => { unlinkSync(path); writeFileSync(path, 'another in-flight binding', { mode: 0o600 }); throw new Error('fixture failure') })
    reason(await c.submit(service, draw), 'aumlok:bind-write-failed')
    assert.equal(existsSync(path), true)
    assert.equal(readFileSync(path, 'utf8'), 'another in-flight binding')
    noRecord(c)
  }],
])

const mutations = [
  ['configuration', "if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value\n    || /[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]/u.test(value)) fail(BROWSER_BIND_REFUSE.CONFIG)", '', 'configuration and private directory'],
  ['private-directory', '(info.mode & 0o022) !== 0', 'false', 'configuration and private directory'],
  ['plain-directory', '!info.isDirectory() || info.isSymbolicLink()', 'false', 'symbolic directory refuses'],
  ['handle', 'requireHandle(handle)', 'handle', 'handle and language refuse before a draw'],
  ['language', 'generatePhrase({ language })', "generatePhrase({ language: 'en' })", 'handle and language refuse before a draw'],
  ['pending', 'if (pending !== null && at < pending.expiresAt) fail(BROWSER_BIND_REFUSE.BUSY)', '', 'one pending draw and exact cancel identifier'],
  ['cancel-id', 'if (pending === null || ceremonyId !== pending.ceremonyId) return refused(BROWSER_BIND_REFUSE.NO_DRAW)', 'if (pending === null) return refused(BROWSER_BIND_REFUSE.NO_DRAW)', 'one pending draw and exact cancel identifier'],
  ['bind-id', 'expected === null || ceremonyId !== expected.ceremonyId', 'expected === null', 'unknown bind identifier cannot spend a draw'],
  ['ack', "if (acknowledged !== true) { attempts(false); fail(BROWSER_BIND_REFUSE.ACK) }", '', 'acknowledgement is explicit and spends the draw'],
  ['body-bound', 'typedPhrase.length > 512', 'false', 'bounded phrase shape refuses without echo'],
  ['consume', 'pending = null\n    try {', 'try {', 'mismatched valid words spend the draw'],
  ['compare', 'offered.some((word, at) => word !== expected.words[at])', 'false', 'mismatched valid words spend the draw'],
  ['expiry', 'if (at >= expected.expiresAt) fail(BROWSER_BIND_REFUSE.EXPIRED)', '', 'expiry and invalid clocks refuse'],
  ['clock', 'if (!Number.isSafeInteger(at) || at < 0) fail(BROWSER_BIND_REFUSE.CONFIG)', '', 'expiry and invalid clocks refuse'],
  ['limiter', "if (!attempts(true).ok) fail('aumlok:enrollment-refused')", '', 'fifth wrong type-back locks the node across reopen'],
  ['limiter-before-kdf', "if (!attempts(true).ok) fail('aumlok:enrollment-refused')\n      const previousOverlay", 'const previousOverlay', 'already drawn valid words refuse a later limiter lock'],
  ['attempt-accounting', 'attempts(false); fail(BROWSER_BIND_REFUSE.MISMATCH)', 'fail(BROWSER_BIND_REFUSE.MISMATCH)', 'fifth wrong type-back locks the node across reopen'],
  ['lost-state', 'initialize: fresh', 'initialize: true', 'missing attempt state cannot reset the allowance'],
  ['initialize-before-status', 'if (fresh) initializeLimiter()', '', 'restart before the first draw retains usable attempt state'],
  ['attempt-file', /if \(info && \(!info\.isFile\(\)[\s\S]*?fail\('aumlok:attempt-store-unavailable'\)/u, '', 'attempt database symlink refuses'],
  ['closed', 'if (closed) fail(BROWSER_BIND_REFUSE.STORAGE)', '', 'closed coordinator cannot draw'],
  ['occupied', 'if (occupied(dir)) fail(BROWSER_BIND_REFUSE.BOUND)', '', 'occupied record and retained lock refuse before derivation'],
  ['persistent-lock', 'FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | FS.O_NOFOLLOW', 'FS.O_WRONLY | FS.O_CREAT | FS.O_NOFOLLOW', 'concurrent bind uses the exclusive persistent lock'],
  ['record-match', 'projection.subject !== bound.projection.subject', 'false', 'saved record must match the binding result'],
  ['seed-match', 'if (key.publicKeyHex !== machine.ed25519PublicKeyHex) fail(BROWSER_BIND_REFUSE.RECORD)', '', 'kept seed must reproduce its registered public key'],
  ['overlay-identity', 'owner.subject !== UNLINKED_MEMORY_SUBJECT', 'false', 'existing overlay identity or wrong memory path refuses'],
  ['overlay-path', "(owner.stateDir !== undefined && owner.stateDir !== join(stateRoot, 'kira-memory'))", 'false', 'existing overlay identity or wrong memory path refuses'],
  ['overlay-race', 'if (currentOverlay !== previousOverlay) fail(BROWSER_BIND_REFUSE.OVERLAY)', '', 'changed overlay refuses rather than replacing it'],
  ['overlay-read-back', "if (stored.subject !== projection.subject || stored.stateDir !== join(stateRoot, 'kira-memory')) fail(BROWSER_BIND_REFUSE.OVERLAY)", '', 'saved memory identity is checked before success'],
  ['named-errors', 'knownCodes.has(cause.code)', "cause.code.startsWith('aumlok:')", 'unknown exception codes cannot echo phrase material'],
  ['lock-identity', 'if (seen.ino === inode.ino && seen.dev === inode.dev) unlinkSync(path)', 'unlinkSync(path)', 'failed bind cannot unlink a replacement lock'],
]

try {
  const sampleDirectory = join(scratch, 'sample')
  sample = { directory: sampleDirectory, bound: await bindV3({ handle, words: phraseWordList('en').slice(0, 7), directory: sampleDirectory, boundAt: '2026-10-13T00:00:00.000Z' }) }
  const url = moduleUrl(source)
  await fixture(url, async c => {
    delete globalThis[HOOK]
    const service = c.open(), draw = c.drawn(service)
    assert.equal(draw.language, 'en'); assert.equal(draw.entropyBits, 77)
    assert.equal(draw.words.length, 7)
    const phrase = draw.words.join(' ')
    const messages = [], previousLog = console.log
    let result
    console.log = (...values) => messages.push(values.join(' '))
    try { result = await c.submit(service, draw) } finally { console.log = previousLog }
    assert.equal(result.ok, true, result.reason)
    assert.equal(JSON.stringify(result).includes(phrase), false)
    assert.equal(messages.join('\n').includes(phrase), false)
    assert.equal(existsSync(join(c.dir, 'root-seed-v3.json')), false)
    assert.equal(statSync(join(c.dir, attemptsName)).mode & 0o777, 0o600)
    assert.equal(service.status().subject, result.binding.subject)
    assert.equal(service.status().rootId, result.binding.rootId)
    assert.deepEqual(resolveMemoryIdentity({ supportRoot: c.supportRoot, installed: true, env: {} }), {
      subject: result.binding.subject, stateDir: join(c.stateRoot, 'kira-memory'),
    })
    const record = readFileSync(join(c.dir, recordName)), seed = readFileSync(join(c.dir, seedName))
    assert.equal(record.toString().includes(phrase), false); assert.equal(seed.toString().includes(phrase), false)
    service.close(); const reopened = c.open()
    reason(reopened.prepare({ handle }), 'aumlok:bind-already-bound')
    assert.equal(reopened.status().subject, result.binding.subject)
    assert.deepEqual(readFileSync(join(c.dir, recordName)), record); assert.deepEqual(readFileSync(join(c.dir, seedName)), seed)
  })
  console.log('PASS production derive-v3 / bind-v3 / record-v3 and verified Kira overlay; source fixture only')
  let passed = 1
  for (const [name, test] of cases) { await fixture(url, test); passed++; console.log(`PASS ${name}`) }
  console.log(`AUMLOK_BROWSER_BINDING: ${passed} passed, 0 failed`)
  if (process.argv.includes('--mutate')) {
    let killed = 0
    for (const [name, before, after, caseName] of mutations) {
      const altered = source.replace(before, after)
      assert.notEqual(altered, source, `mutation ${name} still addresses source`)
      let failure
      try { await fixture(moduleUrl(altered), cases.get(caseName)) } catch (cause) { failure = cause }
      assert.ok(failure instanceof assert.AssertionError, `mutation ${name} must fail a regression assertion`)
      killed++; console.log(`MUTATION ${name}: KILLED (assertion)`)
    }
    console.log(`AUMLOK_BROWSER_BINDING_MUTATIONS: ${killed} killed, 0 survived`)
  }
} finally { delete globalThis[HOOK]; delete globalThis[WRITE_HOOK]; rmSync(scratch, { recursive: true, force: true }) }
