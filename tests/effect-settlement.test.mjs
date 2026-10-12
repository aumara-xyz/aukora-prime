// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara LLC
// Reconcile recorded objects and latest projections; refuse malformed or moving state.
// Memory cases translated from aukora-cordis 626310e2c test/settled-checker.test.ts.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { appendEntry } from '../plugins/aukora-box/aukora/aura/record.mjs'
import { memoryPut, definitionDigest, MEMORY_PUT } from '../plugins/aukora-box/aukora/broker/effect.mjs'
import { effectBody } from '../plugins/aukora-box/aukora/broker/effect-body.mjs'
import { requestDigest } from '../plugins/aukora-box/aukora/broker/receipt.mjs'

assert.equal(process.version, 'v24.11.1')
const checkerURL = new URL('../scripts/aura/check-settled-state.mjs', import.meta.url)
const checker = fileURLToPath(checkerURL)
const testFile = fileURLToPath(import.meta.url)
const workspace = fs.realpathSync(join(import.meta.dirname, '..'))
const temporary = fs.mkdtempSync(join(workspace, '.effect-settlement-test-'))
const mutation = process.argv[2] === '--mutation' ? process.argv[3] : null
const chosenCase = process.argv[4]
const sha = body => createHash('sha256').update(body).digest('hex')
const confinement = { class: 'state-owned', euid: 1000, stateUid: 1000, stateMode: '0700',
  stateDev: 1, stateIno: 1, platform: 'fixture', sealClass: 'state-owned', peerProof: null }

function replacement(id) {
  const replacements = {
    nofollow: [' | constants.O_NOFOLLOW', ''],
    nonblock: [' | constants.O_NONBLOCK', ''],
    latest: ['newest.set(row.key, row)', 'if (!newest.has(row.key)) newest.set(row.key, row)'],
    history: ['for (const [index, row] of before.entries.entries()) {',
      'for (const [index, row] of before.entries.entries()) {\n' +
      'if (before.entries.slice(index + 1).some(next => next.key === row.key)) continue'],
    initial: ["requireCheck(bytes.equals(Buffer.from(chain.entries.map(row => JSON.stringify(row) + '\\n').join(''))), 'state-changed')", ''],
    final: ["requireCheck(after.count === before.count && after.lastChainHash === before.lastChainHash, 'state-changed')", ''],
    readonly: ['const before = snapshot(root)',
      "process.getBuiltinModule('fs').writeFileSync(join(root, 'unexpected-write'), 'changed'); const before = snapshot(root)"],
    confinement: ['&& classAtLeast(row.confinement.class, CONFINEMENT_CLASS.STATE_OWNED)', ''],
  }
  return replacements[id] ?? ['if (!condition) throw', `if (!condition && code !== ${JSON.stringify(id)}) throw`]
}

function hookSource(id) {
  const [before, after] = replacement(id)
  return `import { registerHooks } from 'node:module'; registerHooks({ load(url, context, next) {
    const loaded = next(url, context); if (url !== ${JSON.stringify(checkerURL.href)}) return loaded;
    const source = String(loaded.source); const before = ${JSON.stringify(before)};
    if (source.split(before).length !== 2) throw new Error('mutation anchor not unique');
    return { ...loaded, source: source.replace(before, ${JSON.stringify(after)}) };
  } });`
}
const hookURL = mutation === null ? null : `data:text/javascript,${encodeURIComponent(hookSource(mutation))}`
if (hookURL !== null) await import(hookURL)
const { checkSettledState } = await import(checkerURL)

function fixture() {
  const root = fs.mkdtempSync(join(temporary, 'state-'))
  const f = { root, rows: [], aura: join(root, 'aura.jsonl'), seq: join(root, 'seq') }
  addRow(f, { key: 'note', value: 'memory 🌱' })
  return f
}

function addRow(f, args, overrides = {}) {
  const evidence = memoryPut(f.root, args)
  const fields = { verdict: 'settled', sequence: f.rows.length + 1, key: args.key,
    requestDigest: requestDigest(MEMORY_PUT, args), definitionId: definitionDigest(MEMORY_PUT),
    nonce: `nonce_${f.rows.length + 1}`, receiptSha256: 'ab'.repeat(32), ...evidence,
    confinement: { ...confinement }, ...overrides }
  f.rows.push(fields)
  const result = appendEntry({ file: f.aura, fields })
  fs.writeFileSync(f.seq, String(f.rows.length))
  return result
}

function rewrite(f) {
  fs.rmSync(f.aura, { force: true })
  for (const fields of f.rows) appendEntry({ file: f.aura, fields })
}

function projection(f, row = f.rows[0]) {
  return join(f.root, 'memory', 'keys', `${row.key}.json`)
}

function replaceBody(f, body) {
  const row = f.rows[0]
  row.contentSha256 = sha(body)
  row.path = join(f.root, 'memory', 'objects', `${row.contentSha256}.json`)
  row.bytes = Buffer.byteLength(body)
  fs.writeFileSync(row.path, body)
  fs.writeFileSync(projection(f), `${JSON.stringify({ key: row.key, contentSha256: row.contentSha256 })}\n`)
  rewrite(f)
}

function cli(args, timeout = 5000) {
  const env = { ...process.env, TMPDIR: temporary }
  delete env.NODE_OPTIONS
  delete env.NODE_PATH
  return spawnSync(process.execPath, [...(hookURL ? ['--import', hookURL] : []), checker, ...args],
    { cwd: workspace, env, encoding: 'utf8', timeout })
}

const cases = []
function test(name, run, kill = null) { cases.push({ name, run, kill }) }
function rejects(name, code, change, kill = code) {
  test(name, () => {
    const f = fixture()
    const root = change(f) ?? f.root
    assert.throws(() => checkSettledState(root), { code: `settled:${code}` })
  }, kill)
}

test('two honest keys', () => {
  const f = fixture()
  const head = addRow(f, { key: 'second', value: { b: 2, a: 1 } }).hash
  assert.deepEqual(checkSettledState(f.root), { rows: 2, keys: 2, head })
})
test('latest projection wins', () => {
  const f = fixture()
  const head = addRow(f, { key: 'note', value: 'newest' }).hash
  assert.deepEqual(checkSettledState(f.root), { rows: 2, keys: 1, head })
}, 'latest')
test('unrecorded objects remain outside scope', () => {
  const f = fixture()
  memoryPut(f.root, { key: 'orphan', value: 'not recorded' })
  assert.equal(checkSettledState(f.root).rows, 1)
})
rejects('every historical object', 'object-digest', f => {
  addRow(f, { key: 'note', value: 'newest' })
  fs.writeFileSync(f.rows[0].path, 'corrupt\n')
}, 'history')
rejects('stale projection', 'projection', f => {
  const old = fs.readFileSync(projection(f))
  addRow(f, { key: 'note', value: 'newest' })
  fs.writeFileSync(projection(f), old)
})
rejects('noncanonical projection', 'projection', f => {
  fs.appendFileSync(projection(f), '\n')
}, null)

for (const [name, code, edits] of [
  ['extra row field', 'row-fields', { extra: true }],
  ['wrong sequence', 'row-order', { sequence: 7 }],
  ['wrong verdict', 'row-order', { verdict: 'refused' }],
  ['key traversal', 'key', { key: '../escape' }],
  ['digest traversal', 'content-digest', { contentSha256: '../../escape' }],
  ['malformed nonce', 'nonce', { nonce: 'not a nonce' }],
  ['wrong definition', 'definition', { definitionId: 'ef'.repeat(32) }],
  ['invalid receipt digest', 'row-metadata', { receiptSha256: 'short' }],
  ['negative inode', 'row-metadata', { inode: -1 }],
  ['unsafe inode', 'row-metadata', { inode: Number.MAX_SAFE_INTEGER + 1 }],
  ['noncanonical timestamp', 'row-metadata', { mtimeNs: '01' }],
  ['invalid confinement', 'row-metadata', { confinement: { class: 'state-owned' } }],
  ['object path traversal', 'object-path', { path: '../../escape' }],
  ['wrong byte length', 'object-size', { bytes: 1 }],
  ['wrong request digest', 'request-digest', { requestDigest: 'cd'.repeat(32) }],
]) rejects(name, code, f => { Object.assign(f.rows[0], edits); rewrite(f) })
rejects('missing row field', 'row-fields', f => { delete f.rows[0].inode; rewrite(f) }, null)
rejects('unconfined metadata cannot be minted', 'row-metadata', f => {
  Object.assign(f.rows[0].confinement, { class: 'unconfined', sealClass: 'unconfined' }); rewrite(f)
}, 'confinement')
rejects('nonce reused', 'nonce-reused', f => {
  addRow(f, { key: 'second', value: 2 }, { nonce: f.rows[0].nonce })
})
rejects('changed object bytes', 'object-digest', f => { fs.writeFileSync(f.rows[0].path, 'corrupt\n') })
for (const [name, body, code] of [
  ['unparseable object', '{', 'object-body'],
  ['array object', '[]\n', 'object-body'],
  ['extra object property', '{"key":"note","value":1,"extra":true}\n', 'object-body'],
  ['missing object value', '{"key":"note"}\n', 'object-body'],
  ['noncanonical object', '{ "key": "note", "value": "memory 🌱" }\n', 'object-canonical'],
  ['duplicate object key', '{"key":"other","key":"note","value":"memory 🌱"}\n', 'object-canonical'],
  ['wrong object key', effectBody({ key: 'other', value: 'memory 🌱' }), 'object-key'],
]) rejects(name, code, f => { replaceBody(f, body) })

for (const [name, change] of [
  ['blank chain line', raw => `${raw}\n`],
  ['unterminated chain', raw => raw.slice(0, -1)],
  ['noncanonical chain', raw => ` ${raw}`],
  ['reserved chain field', raw => `${raw.trimEnd().slice(0, -1)},"domain":"changed"}\n`],
  ['broken chain link', raw => raw.replace('aukora:aura-record:v1', 'wrong')],
  ['tampered chain hash', raw => raw.replace(/"hash":"./, '"hash":"z')],
]) rejects(name, 'invalid-chain', f => { fs.writeFileSync(f.aura, change(fs.readFileSync(f.aura, 'utf8'))) })
rejects('empty chain', 'empty-chain', f => { fs.writeFileSync(f.aura, ''); fs.writeFileSync(f.seq, '0') })
for (const seq of ['2', '01', '1\n']) {
  rejects(`sequence witness ${JSON.stringify(seq)}`, 'sequence-witness', f => { fs.writeFileSync(f.seq, seq) })
}

for (const kind of ['aura', 'seq', 'object', 'projection']) {
  const path = f => kind === 'object' ? f.rows[0].path : kind === 'projection' ? projection(f) : f[kind]
  rejects(`hardlinked ${kind}`, 'unsafe-file', f => { fs.linkSync(path(f), join(f.root, 'alias')) })
  rejects(`symlinked ${kind}`, 'unavailable', f => {
    const real = join(f.root, 'real-file')
    fs.renameSync(path(f), real); fs.symlinkSync(real, path(f))
  }, kind === 'object' ? 'nofollow' : null)
  rejects(`missing ${kind}`, 'unavailable', f => { fs.rmSync(path(f)) }, null)
}
rejects('symlinked state root', 'unsafe-parent', f => {
  const alias = join(temporary, 'root-alias'); fs.symlinkSync(f.root, alias); return alias
}, null)
rejects('symlinked root ancestor', 'unsafe-parent', f => {
  const alias = join(temporary, 'parent-alias'); fs.symlinkSync(dirname(f.root), alias)
  return join(alias, basename(f.root))
}, null)
rejects('symlinked object parent', 'unsafe-parent', f => {
  const source = dirname(f.rows[0].path), real = join(f.root, 'real-objects')
  fs.renameSync(source, real); fs.symlinkSync(real, source)
})
rejects('missing parent', 'unavailable', f => { fs.rmSync(dirname(f.rows[0].path), { recursive: true }) }, null)
rejects('missing root', 'unavailable', f => join(f.root, 'absent'), null)
rejects('directory object', 'unsafe-file', f => { fs.rmSync(f.rows[0].path); fs.mkdirSync(f.rows[0].path) }, null)
test('FIFO refuses without blocking', () => {
  const f = fixture()
  fs.rmSync(f.rows[0].path)
  const made = spawnSync('mkfifo', [f.rows[0].path], { encoding: 'utf8' })
  assert.equal(made.status, 0, made.stderr)
  const result = cli([f.root], 1000)
  assert.equal(result.error, undefined, 'FIFO read blocked')
  assert.equal(result.status, 1)
  assert.equal(result.stderr, 'settled:unsafe-file\n')
}, 'nonblock')

function movedState(trigger) {
  const f = fixture(), original = fs.readFileSync(f.aura)
  addRow(f, { key: 'second', value: 'arrived during check' })
  const next = fs.readFileSync(f.aura)
  fs.writeFileSync(f.aura, original); fs.writeFileSync(f.seq, '1')
  const nativeOpen = fs.openSync, nativeRead = fs.readFileSync, nativeWrite = fs.writeFileSync
  let fired = false, auraFD
  const move = () => {
    nativeWrite(f.aura, next); nativeWrite(f.seq, '2'); fired = true
  }
  fs.openSync = function (path, ...args) {
    const fd = nativeOpen(path, ...args)
    if (path === f.aura) auraFD = fd
    if (!fired && trigger === 'final' && path === projection(f)) move()
    return fd
  }
  fs.readFileSync = function (path, ...args) {
    const body = nativeRead(path, ...args)
    if (!fired && trigger === 'initial' && path === auraFD) move()
    return body
  }
  syncBuiltinESMExports()
  try { assert.throws(() => checkSettledState(f.root), { code: 'settled:state-changed' }) }
  finally {
    fs.openSync = nativeOpen; fs.readFileSync = nativeRead; syncBuiltinESMExports()
  }
  assert.equal(fired, true, 'race injection was not reached')
}
test('initial chain read movement', () => movedState('initial'), 'initial')
test('final chain and witness movement', () => movedState('final'), 'final')
test('checker opens only for reading and calls no writers', () => {
  const f = fixture(), saved = new Map()
  for (const name of ['writeFileSync', 'appendFileSync', 'renameSync', 'unlinkSync', 'rmSync', 'mkdirSync', 'linkSync', 'symlinkSync']) {
    saved.set(name, fs[name]); fs[name] = () => { assert.fail(`checker called ${name}`) }
  }
  const nativeOpen = fs.openSync
  fs.openSync = function (path, flags, ...args) {
    assert.equal(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC), 0)
    return nativeOpen(path, flags, ...args)
  }
  syncBuiltinESMExports()
  try { assert.equal(checkSettledState(f.root).rows, 1) }
  finally {
    for (const [name, fn] of saved) fs[name] = fn
    fs.openSync = nativeOpen; syncBuiltinESMExports()
  }
}, 'readonly')
test('CLI success and scope', () => {
  const f = fixture(); addRow(f, { key: 'second', value: 2 })
  const result = cli([f.root])
  assert.equal(result.error, undefined); assert.equal(result.status, 0); assert.equal(result.stderr, '')
  assert.match(result.stdout, /^rows verified: 2; keys projected: 2\nScope: .*no receipt signatures/)
})
test('CLI empty state and usage', () => {
  const f = fixture(); fs.writeFileSync(f.aura, ''); fs.writeFileSync(f.seq, '0')
  const empty = cli([f.root])
  assert.equal(empty.status, 1); assert.equal(empty.stderr, 'settled:empty-chain\n'); assert.equal(empty.stdout, '')
  for (const args of [[], [f.root, 'extra']]) {
    const result = cli(args)
    assert.equal(result.status, 2); assert.equal(result.stderr, 'usage: check-settled-state.mjs <broker-state-root>\n')
  }
})

let passed = 0, failed = 0, killed = 0
try {
  for (const entry of cases) {
    if (chosenCase !== undefined && entry.name !== chosenCase) continue
    try { entry.run(); passed++ }
    catch (error) { failed++; console.error(`FAIL ${entry.name}: ${error.message}`) }
  }
  if (mutation === null && failed === 0) {
    const probes = new Map()
    for (const entry of cases) if (entry.kill !== null && !probes.has(entry.kill)) probes.set(entry.kill, entry.name)
    for (const [id, name] of probes) {
      const env = { ...process.env, TMPDIR: temporary }
      delete env.NODE_OPTIONS; delete env.NODE_PATH
      const child = spawnSync(process.execPath, [testFile, '--mutation', id, name],
        { cwd: workspace, env, encoding: 'utf8', timeout: 10000 })
      assert.equal(child.error, undefined, `mutation ${id} did not run`)
      assert.equal(child.status, 1, `mutation ${id} survived: ${child.stdout} ${child.stderr}`)
      assert.ok(child.stderr.startsWith(`FAIL ${name}:`), `mutation ${id} failed outside its assertion: ${child.stderr}`)
      killed++
    }
    console.log(`effect-settlement mutations: ${killed} killed, 0 survived`)
  }
} catch (error) { failed++; console.error(error.message) }
finally { fs.rmSync(temporary, { recursive: true, force: true }) }
console.log(`effect-settlement: ${passed} passed, ${failed} failed`)
process.exitCode = failed ? 1 : 0
