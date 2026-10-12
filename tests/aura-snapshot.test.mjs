// SPDX-License-Identifier: AGPL-3.0-or-later
// Snapshot framing, read-only source projection and route refusals survive executable mutations.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { stripTypeScriptTypes } from 'node:module'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import * as snapshot from '../plugins/aukora-face/settings/src/aura/snapshot.ts'
import * as reader from '../plugins/aukora-face/settings/src/aura/snapshot-reader.ts'
import * as client from '../plugins/aukora-face/settings/src/client/aura-snapshot.ts'

const snapshotUrl = new URL('../plugins/aukora-face/settings/src/aura/snapshot.ts', import.meta.url)
const readerUrl = new URL('../plugins/aukora-face/settings/src/aura/snapshot-reader.ts', import.meta.url)
const clientUrl = new URL('../plugins/aukora-face/settings/src/client/aura-snapshot.ts', import.meta.url)
const heads = ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)]
const sources = snapshot.AURA_SNAPSHOT_SOURCES.map((name, index) => ({ name, head: heads[index], entries: index + 1, absence: null }))
const refusal = (fn, code) => assert.throws(fn, error => error.code === code)
const absent = index => ({ ...sources[index], head: null, entries: null, absence: 'fixture-unavailable' })
const response = () => ({ status: null, headers: null, body: null,
  writeHead(status, headers) { this.status = status; this.headers = headers },
  end(body) { this.body = body } })
const checks = []
const add = (name, run) => checks.push({ name, run })

add('fixed framing, order, per-source changes and explicit absence', ({ makeAuraSnapshot }) => {
  const base = makeAuraSnapshot(sources)
  assert.equal(base.head, '769d4bacdaaf6aa7c5d562f5fe86998cfea0f5233ba4835d7083315a8edc383a')
  assert.deepEqual(makeAuraSnapshot([...sources].reverse()), base)
  for (let index = 0; index < sources.length; index += 1) {
    assert.notEqual(makeAuraSnapshot(sources.map((source, i) => i === index ? { ...source, head: '44'.repeat(32) } : source)).head, base.head)
    assert.notEqual(makeAuraSnapshot(sources.map((source, i) => i === index ? absent(i) : source)).head, base.head)
  }
  assert.equal(makeAuraSnapshot(sources.map(source => ({ ...source, entries: 999 }))).head, base.head)
})
add('fixed source set', ({ makeAuraSnapshot }) => {
  refusal(() => makeAuraSnapshot(sources.slice(1)), 'aura-snapshot:source-set-invalid')
  refusal(() => makeAuraSnapshot([sources[0], sources[0], sources[2]]), 'aura-snapshot:source-set-invalid')
})
add('32-byte head', ({ makeAuraSnapshot }) => {
  for (const head of ['deadbeef', 'A'.repeat(64), 'g'.repeat(64)]) {
    refusal(() => makeAuraSnapshot([{ ...sources[0], head }, ...sources.slice(1)]), 'aura-snapshot:head-invalid')
  }
})
add('entry count and availability', ({ makeAuraSnapshot }) => {
  for (const entries of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    refusal(() => makeAuraSnapshot([{ ...sources[0], entries }, ...sources.slice(1)]), 'aura-snapshot:entries-invalid')
  }
  for (const source of [{ ...sources[0], entries: null }, { ...sources[0], entries: 0 }, { ...sources[0], absence: 'missing' },
    { ...absent(0), absence: null }, { ...absent(0), entries: 1 }]) {
    refusal(() => makeAuraSnapshot([source, ...sources.slice(1)]), 'aura-snapshot:availability-invalid')
  }
})
add('only verified gate head, never a partial or malformed one', (_snapshot, { gateLedgerSource }) => {
  assert.deepEqual(gateLedgerSource({ ok: true, head: heads[0], entries: 7 }), { name: 'gate-ledger', head: heads[0], entries: 7, absence: null })
  assert.equal(gateLedgerSource({ ok: false, head: heads[0], entries: 7 }).head, null)
  assert.equal(gateLedgerSource({ ok: true, head: 'deadbeef', entries: 7 }).head, null)
  assert.equal(gateLedgerSource({ ok: true, head: heads[0], entries: 1.5 }).head, null)
  assert.deepEqual(gateLedgerSource({ ok: true, head: 'GENESIS', entries: 0 }), { name: 'gate-ledger', head: null, entries: 0, absence: 'gate-ledger-empty' })
})
add('real signed ledger reads do not move the snapshot; recorded append does', ({ makeAuraSnapshot }, { gateLedgerSource }) => {
  const scratch = mkdtempSync(new URL('.aura-ledger-', import.meta.url))
  let gate
  try {
    gate = createGate({ home: scratch, store: { read: () => null, write: () => { throw Error('unexpected-write') } } })
    const observe = () => makeAuraSnapshot([gateLedgerSource(gate.proposeOps.log({ limit: 1 }).verify), absent(1), absent(2)])
    const empty = observe()
    assert.equal(empty.sources[0].head, null)
    assert.equal(empty.sources[0].entries, 0)
    assert.deepEqual(observe(), empty)
    gate.proposeOps.selfcheck({ result: 'SYNTHETIC_SNAPSHOT_FIXTURE' })
    const changed = observe()
    assert.equal(changed.sources[0].head, gate.verify().head)
    assert.equal(changed.sources[0].entries, 1)
    assert.notEqual(changed.head, empty.head)
    assert.deepEqual(observe(), changed)
  } finally {
    gate?.db.close()
    rmSync(scratch, { recursive: true, force: true })
  }
})
add('owner socket selection does not replace invalid explicit configuration', (_snapshot, { snapshotGateSocket }) => {
  assert.equal(snapshotGateSocket({}, {}), '/run/aukora-gate/gate.sock')
  assert.equal(snapshotGateSocket({}, { AUKORA_GATE_SOCKET: '/fixture/env.sock' }), '/fixture/env.sock')
  assert.equal(snapshotGateSocket({ gateSocket: '/fixture/config.sock' }, { AUKORA_GATE_SOCKET: '/fixture/env.sock' }), '/fixture/config.sock')
  for (const gateSocket of ['relative.sock', '/run/../gate.sock', '/run/gate\0.sock', `/${'x'.repeat(1025)}`, 12, null]) assert.equal(snapshotGateSocket({ gateSocket }, {}), null)
})
add('authentication and GET before source access, response is private', async (_snapshot, { auraSnapshotHandler }) => {
  let reads = 0
  const read = async () => { reads += 1; return snapshot.makeAuraSnapshot(sources) }
  for (const rejection of [401, 403]) {
    for (const method of ['GET', 'POST']) {
      const res = response()
      let authenticated = false
      await auraSnapshotHandler(() => ({ requestRejection: () => { authenticated = true; return rejection } }), read)({ method, headers: {} }, res)
      assert.equal(authenticated, true)
      assert.equal(res.status, rejection); assert.equal(reads, 0); assert.equal(res.body, undefined)
      assert.equal(res.headers['cache-control'], 'no-store')
    }
  }
  const missing = response()
  await auraSnapshotHandler(() => undefined, read)({ method: 'POST', headers: {} }, missing)
  assert.equal(missing.status, 403); assert.equal(reads, 0)
  assert.equal(missing.headers['cache-control'], 'no-store')
  const connection = () => ({ requestRejection: () => undefined })
  const post = response()
  await auraSnapshotHandler(connection, read)({ method: 'POST', headers: {} }, post)
  assert.equal(post.status, 405); assert.equal(post.headers.allow, 'GET'); assert.equal(reads, 0)
  assert.equal(post.headers['cache-control'], 'no-store')
  const res = response()
  await auraSnapshotHandler(connection, read)({ method: 'GET', headers: {} }, res)
  assert.equal(res.status, 200); assert.equal(reads, 1)
  assert.equal(res.headers['cache-control'], 'no-store'); assert.equal(res.headers['x-content-type-options'], 'nosniff')
  assert.deepEqual(JSON.parse(res.body), snapshot.makeAuraSnapshot(sources))
})
add('in-flight and interval cache bound shared ledger verification', async (_snapshot, { createAuraSnapshotReader }) => {
  let time = 0, reads = 0, complete
  const read = createAuraSnapshotReader(() => { reads += 1; return new Promise(resolve => { complete = resolve }) }, () => time)
  const first = read(); time = 3000
  assert.equal(read(), first); assert.equal(reads, 1)
  complete(snapshot.makeAuraSnapshot(sources)); await first
  time = 4499; assert.equal(read(), first); assert.equal(reads, 1)
  time = 4500; const second = read(); assert.notEqual(second, first); assert.equal(reads, 2)
  complete(snapshot.makeAuraSnapshot(sources)); await second
})
add('carried read-only transport, no ledger detail, unexposed sources and read failure', async (_snapshot, { readAuraSnapshot }) => {
  const scratch = mkdtempSync(new URL('.aura-snapshot-', import.meta.url))
  try {
    const clientDir = join(scratch, 'plugins/aukora-buzz-door/lib'); mkdirSync(clientDir, { recursive: true })
    writeFileSync(join(clientDir, 'index.mjs'), `export async function gateCall(socket, op, args, timeout) {
      if (socket !== '/fixture/gate.sock' || op !== 'log' || args.limit !== 1 || timeout !== 3000) throw Error('unexpected-read');
      return { verify: { ok: true, head: '${heads[0]}', entries: 7 }, entries: [{ detail: 'PRIVATE_FIXTURE_DETAIL' }] }
    }`)
    const result = await readAuraSnapshot(scratch, '/fixture/gate.sock')
    assert.equal(result.sources[0].head, heads[0]); assert.equal(result.sources[0].entries, 7)
    assert.deepEqual(result.sources.slice(1), [{ name: 'kira-chain', head: null, entries: null, absence: 'kira-head-not-exposed' },
      { name: 'code-chain', head: null, entries: null, absence: 'code-head-not-exposed' }])
    assert.equal(JSON.stringify(result).includes('PRIVATE_FIXTURE_DETAIL'), false)
    const failure = await readAuraSnapshot(scratch, '/fixture/other.sock')
    assert.equal(failure.sources[0].head, null); assert.equal(failure.sources[0].absence, 'gate-ledger-unavailable')
    const invalid = await readAuraSnapshot(scratch, null)
    assert.equal(invalid.sources[0].head, null); assert.equal(invalid.sources[0].absence, 'gate-socket-invalid')
  } finally { rmSync(scratch, { recursive: true, force: true }) }
})
add('client accepts all server availability states and refuses malformed snapshots', (_snapshot, _reader, { parseAuraSnapshot }) => {
  const base = snapshot.makeAuraSnapshot(sources)
  assert.deepEqual(parseAuraSnapshot(base), base)
  const empty = snapshot.makeAuraSnapshot([{ ...absent(0), entries: 0 }, absent(1), absent(2)])
  assert.deepEqual(parseAuraSnapshot(empty), empty)
  for (const value of [null, [], { ...base, schema: 'wrong' }, { ...base, head: 'aa' },
    { ...base, sources: base.sources.slice(1) }, { ...base, sources: null }]) {
    refusal(() => parseAuraSnapshot(value), 'aura-snapshot:format')
  }
  refusal(() => parseAuraSnapshot({ ...base, sources: [...sources].reverse() }), 'aura-snapshot:source-order')
  for (const source of [{ ...absent(0), entries: 1 }, { ...absent(0), entries: -1 }, { ...absent(0), absence: null }, { ...absent(0), absence: '' }]) {
    refusal(() => parseAuraSnapshot({ ...base, sources: [source, ...sources.slice(1)] }), 'aura-snapshot:absence')
  }
  for (const source of [{ ...sources[0], head: 'AA'.repeat(32) }, { ...sources[0], entries: 0 },
    { ...sources[0], entries: 1.5 }, { ...sources[0], entries: null }, { ...sources[0], absence: 'missing' }]) {
    refusal(() => parseAuraSnapshot({ ...base, sources: [source, ...sources.slice(1)] }), 'aura-snapshot:source-head')
  }
})
add('client counts only observed advances, preserving high water through absence and regression', (_snapshot, _reader, { advanceSourceEntries }) => {
  const initial = advanceSourceEntries(new Map(), sources)
  assert.equal(initial.entries, 0)
  const previous = new Map(initial.counters)
  const grown = advanceSourceEntries(initial.counters, sources.map(source => ({ ...source, entries: source.entries + 3 })))
  assert.equal(grown.entries, 9)
  assert.deepEqual(initial.counters, previous)
  const unavailable = advanceSourceEntries(grown.counters, [absent(0), absent(1), absent(2)])
  assert.equal(unavailable.entries, 0)
  assert.deepEqual(unavailable.counters, grown.counters)
  const regressed = advanceSourceEntries(unavailable.counters, sources)
  assert.equal(regressed.entries, 0)
  assert.deepEqual(regressed.counters, grown.counters)
  const restored = advanceSourceEntries(regressed.counters, sources.map(source => ({ ...source, entries: source.entries + 3 })))
  assert.equal(restored.entries, 0)
  const next = advanceSourceEntries(restored.counters, [{ ...sources[0], entries: sources[0].entries + 4 }, ...sources.slice(1)])
  assert.equal(next.entries, 1)
  const unknown = advanceSourceEntries(new Map(), [absent(0), absent(1), absent(2)])
  assert.equal(advanceSourceEntries(unknown.counters, sources).entries, 0)
})

for (const check of checks) await check.run(snapshot, reader, client)
console.log(`PASS Aura snapshot: ${checks.length} checks`)

const mutations = [
  ['snapshot', "const DOMAIN = 'aukora.aura.snapshot.v1\\0'", "const DOMAIN = 'changed-domain\\0'"],
  ['snapshot', "hash.update(lengthPrefixed(Buffer.from(source.name, 'utf8')))", "hash.update(Buffer.from(source.name, 'utf8'))"],
  ['snapshot', "hash.update(lengthPrefixed(source.head === null ? Buffer.alloc(0) : Buffer.from(source.head, 'hex')))", "hash.update(source.head === null ? Buffer.alloc(0) : Buffer.from(source.head, 'hex'))"],
  ['snapshot', 'if (!Array.isArray(input) || input.length !== AURA_SNAPSHOT_SOURCES.length\n    || AURA_SNAPSHOT_SOURCES.some(name => input.filter(source => source?.name === name).length !== 1))', 'if (false)'],
  ['snapshot', '!HEX64.test(source.head)', 'false'],
  ['snapshot', '!Number.isSafeInteger(source.entries)', 'false'],
  ['snapshot', 'if (source.head === null\n', 'if (false && (source.head === null\n', 'source.entries < 1) {', 'source.entries < 1)) {'],
  ['reader', 'if (verified?.ok !== true)', 'if (false)'],
  ['reader', '!HEX64.test(verified.head)', 'false'],
  ['reader', '!Number.isSafeInteger(verified.entries)', 'false'],
  ['reader', 'normalize(socket) === socket', 'true'],
  ['reader', 'isAbsolute(socket)', 'true'],
  ['reader', 'socket.length <= 1024', 'true'],
  ['reader', '!/[\\u0000-\\u001f\\u007f]/u.test(socket)', 'true'],
  ['reader', "config.gateSocket === undefined ? env['AUKORA_GATE_SOCKET'] ?? DEFAULT_GATE_SOCKET : config.gateSocket", "config.gateSocket ?? env['AUKORA_GATE_SOCKET'] ?? DEFAULT_GATE_SOCKET"],
  ['reader', 'if (rejection !== undefined)', 'if (false)'],
  ['reader', 'const gate = connection()', "if (req.method !== 'GET') { res.writeHead(405, { allow: 'GET', 'cache-control': 'no-store' }); res.end(); return }\n    const gate = connection()"],
  ['reader', "if (req.method !== 'GET')", 'if (false)'],
  ['reader', "'cache-control': 'no-store'", "'cache-control': 'public'"],
  ['reader', "'x-content-type-options': 'nosniff'", "'x-content-type-options': 'sniff'"],
  ['reader', '(reading || now() < expires)', '(now() < expires)'],
  ['reader', '(reading || now() < expires)', '(reading)'],
  ['reader', "'log', { limit: 1 }", "'selfcheck', { limit: 1 }"],
  ['client', "if (value === null || typeof value !== 'object' || Array.isArray(value))", 'if (false)'],
  ['client', "row.schema !== 'aukora-face/aura-snapshot:v1'", 'false'],
  ['client', '!HEAD.test(row.head)', 'false'],
  ['client', 'row.sources.length !== NAMES.length', 'false'],
  ['client', 'source.name !== NAMES[index]', 'false'],
  ['client', 'source.entries !== null && source.entries !== 0', 'false'],
  ['client', "typeof source.absence !== 'string' || !source.absence", 'false'],
  ['client', '!HEAD.test(source.head)', 'false'],
  ['client', '!Number.isSafeInteger(source.entries)', 'false'],
  ['client', '(source.entries as number) < 1', '(source.entries as number) < 0'],
  ['client', 'source.absence !== null', 'false'],
  ['client', 'const counters = new Map(previous)', 'const counters = previous'],
  ['client', 'if (source.entries === null) continue', ''],
  ['client', 'if (before !== undefined)', 'if (true)'],
  ['client', 'Math.max(0, source.entries - before)', 'source.entries - before'],
  ['client', 'Math.max(before ?? source.entries, source.entries)', 'source.entries'],
]
let killed = 0
for (const [file, before, after, secondBefore, secondAfter] of mutations) {
  let source = readFileSync(file === 'snapshot' ? snapshotUrl : file === 'reader' ? readerUrl : clientUrl, 'utf8')
  assert.ok(source.includes(before), `missing mutation seam: ${before}`)
  source = source.replaceAll(before, after)
  if (secondBefore) { assert.ok(source.includes(secondBefore)); source = source.replace(secondBefore, secondAfter) }
  if (file === 'reader') source = source.replaceAll("'./snapshot.ts'", JSON.stringify(snapshotUrl.href))
  const module = await import(`data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source)).toString('base64')}`)
  try {
    for (const check of checks) await check.run(file === 'snapshot' ? module : snapshot, file === 'reader' ? module : reader, file === 'client' ? module : client)
  } catch (error) {
    if (error.code !== 'ERR_ASSERTION') throw error
    killed += 1
  }
}
assert.equal(killed, mutations.length, 'a removed protection survived its regression')
console.log(`PASS Aura snapshot mutation controls: ${killed}/${mutations.length} killed`)
