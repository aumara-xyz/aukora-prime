// SPDX-License-Identifier: AGPL-3.0-or-later
// Snapshot framing, read-only source projection and route refusals survive executable mutations.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { stripTypeScriptTypes } from 'node:module'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { pentoraDigest } from '../apps/aukora-desktop/pentora.mjs'
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
const previousMask = process.umask(0o002)
const digest = value => createHash('sha256').update(value).digest('hex')
const privateNote = 'PRIVATE_KIRA_NOTE_FIXTURE'
const browserWaiting = { active: false, reason: 'kira.memory:aumlok-not-linked' }
const browserActive = { active: true, reason: 'kira.memory:aumlok-linked' }
const kiraSource = value => ({ ...value, browserMemory: null })
let growthFixtureId = 0
function changingHead() {
  let reads = 0
  return { get head() { return ++reads === 1 ? heads[1] : privateNote }, entries: 7, absence: null }
}
function changingAbsence() {
  let reads = 0
  return { head: null, entries: null, get absence() { return ++reads === 1 ? 'kira-ledger-broken' : privateNote } }
}
function writeCodeRecord(root, change = '') {
  const build = join(root, '.dsh-build'); mkdirSync(build, { recursive: true, mode: 0o700 })
  const record = JSON.stringify({ kind: 'genesis-artifact-record', formatVersion: 1, producer: { fixture: change } }) + '\n'
  const head = digest(record)
  writeFileSync(join(build, 'genesis-artifacts.json'), record, { mode: 0o600 })
  writeFileSync(join(build, 'aukora-release.json'), JSON.stringify({ record: { path: '/untrusted/path/ignored', sha256: head } }), { mode: 0o600 })
  return head
}

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
add('canonical Pentora fingerprint changes with any head and stays fixed without a head change', async ({ makeAuraSnapshot }) => {
  const fingerprint = async input => Buffer.from(await pentoraDigest(Buffer.from(makeAuraSnapshot(input).head, 'hex'),
    bytes => createHash('sha256').update(bytes).digest())).toString('hex')
  const base = await fingerprint(sources)
  assert.equal(await fingerprint(sources.map(source => ({ ...source }))), base)
  for (let index = 0; index < sources.length; index += 1) {
    const changed = sources.map((source, i) => i === index ? { ...source, head: '44'.repeat(32) } : source)
    assert.notEqual(await fingerprint(changed), base, `Pentora observes ${sources[index].name}`)
    assert.equal(await fingerprint(changed), await fingerprint(changed))
  }
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
add('Kira service projects only validated head, count and fixed absence codes', (_snapshot, { kiraChainSource }) => {
  assert.deepEqual(kiraChainSource(undefined), kiraSource({ name: 'kira-chain', head: null, entries: null, absence: 'kira-service-unavailable' }))
  assert.deepEqual(kiraChainSource({ head: heads[1], entries: 7, absence: null, note: privateNote,
    subjectId: privateNote, path: privateNote }), kiraSource({ name: 'kira-chain', head: heads[1], entries: 7, absence: null }))
  for (const absence of ['kira-ledger-missing', 'kira-ledger-unreadable', 'kira-ledger-torn', 'kira-ledger-malformed',
    'kira-ledger-broken', 'kira-ledger-unavailable', 'kira-head-invalid', 'kira-ledger-head-invalid', 'kira-ledger-state-root-invalid']) {
    assert.deepEqual(kiraChainSource({ head: null, entries: null, absence }), kiraSource({ name: 'kira-chain', head: null, entries: null, absence }))
  }
  assert.deepEqual(kiraChainSource({ head: null, entries: 0, absence: 'kira-ledger-empty' }),
    kiraSource({ name: 'kira-chain', head: null, entries: 0, absence: 'kira-ledger-empty' }))
  for (const value of [null, [], {}, { head: heads[1], entries: 7, absence: 'kira-ledger-broken' },
    { head: heads[1], entries: 0, absence: null }, { head: heads[1], entries: -1, absence: null },
    { head: heads[1], entries: 1.5, absence: null }, { head: heads[1], entries: Number.MAX_SAFE_INTEGER + 1, absence: null },
    { head: heads[1], entries: null, absence: null }, { head: null, entries: 7, absence: 'kira-ledger-broken' },
    { head: 'AA'.repeat(32), entries: 7, absence: null }, { head: 'deadbeef', entries: 7, absence: null },
    { head: 'g'.repeat(64), entries: 7, absence: null }, { head: null, entries: null, absence: privateNote }]) {
    let projected
    assert.doesNotThrow(() => { projected = kiraChainSource(value) })
    assert.deepEqual(projected, kiraSource({ name: 'kira-chain', head: null, entries: null, absence: 'kira-head-invalid' }))
  }
})
add('Kira browser readiness exposes only fixed active state and named reasons', ({ makeAuraSnapshot }, { kiraChainSource }) => {
  assert.deepEqual(kiraChainSource({ head: null, entries: 0, absence: 'kira-ledger-missing', browserMemory: browserWaiting }),
    { ...kiraSource({ name: 'kira-chain', head: null, entries: 0, absence: 'kira-ledger-missing' }), browserMemory: browserWaiting })
  assert.deepEqual(kiraChainSource({ head: heads[1], entries: 7, absence: null, browserMemory: browserActive,
    subject: privateNote, stateDir: privateNote, note: privateNote }),
  { ...kiraSource({ name: 'kira-chain', head: heads[1], entries: 7, absence: null }), browserMemory: browserActive })
  for (const browserMemory of [{ active: true, reason: browserWaiting.reason }, { active: false, reason: browserActive.reason },
    { active: false, reason: privateNote }, { active: privateNote, reason: browserWaiting.reason }]) {
    assert.equal(kiraChainSource({ head: heads[1], entries: 7, absence: null, browserMemory }).browserMemory, null)
  }
  refusal(() => makeAuraSnapshot(sources.map((source, index) => index === 1
    ? { ...source, browserMemory: { active: false, reason: privateNote } } : source)), 'aura-snapshot:browser-memory-invalid')
  refusal(() => makeAuraSnapshot(sources.map((source, index) => index === 1
    ? { ...source, browserMemory: { active: true, reason: browserWaiting.reason } } : source)), 'aura-snapshot:browser-memory-invalid')
})
add('Kira fields are captured once before validating and projecting them', (_snapshot, { kiraChainSource }) => {
  assert.deepEqual(kiraChainSource(changingHead()), kiraSource({ name: 'kira-chain', head: heads[1], entries: 7, absence: null }))
  assert.deepEqual(kiraChainSource(changingAbsence()), kiraSource({ name: 'kira-chain', head: null, entries: null, absence: 'kira-ledger-broken' }))
  let reads = 0
  assert.deepEqual(kiraChainSource({ head: heads[1], get entries() { return ++reads === 1 ? 7 : privateNote }, absence: null }),
    kiraSource({ name: 'kira-chain', head: heads[1], entries: 7, absence: null }))
})
add('code source reads its own release record, validates its digest, and exposes no record detail', async (_snapshot, { readCodeSource }) => {
  const scratch = mkdtempSync(new URL('.aura-code-', import.meta.url))
  try {
    assert.deepEqual(await readCodeSource(scratch), { name: 'code-chain', head: null, entries: null, absence: 'code-record-missing' })
    const head = writeCodeRecord(scratch, privateNote)
    const base = { name: 'code-chain', head, entries: 1, absence: null }
    assert.deepEqual(await readCodeSource(scratch), base)
    assert.deepEqual(await readCodeSource(scratch), base)
    const manifest = join(scratch, '.dsh-build/aukora-release.json')
    const record = join(scratch, '.dsh-build/genesis-artifacts.json')
    for (const value of ['{', 'null', '[]', '{}', JSON.stringify({ record: { sha256: 'AA'.repeat(32) } }),
      JSON.stringify({ record: { sha256: 'deadbeef' } }), JSON.stringify({ record: { sha256: 7 } })]) {
      writeFileSync(manifest, value)
      assert.deepEqual(await readCodeSource(scratch), { name: 'code-chain', head: null, entries: null, absence: 'code-record-invalid' })
    }
    writeCodeRecord(scratch, privateNote)
    writeFileSync(record, readFileSync(record, 'utf8') + ' ')
    assert.deepEqual(await readCodeSource(scratch), { name: 'code-chain', head: null, entries: null, absence: 'code-record-mismatch' })
    for (const body of ['{', 'null', '[]', '{}', JSON.stringify({ kind: 'wrong', formatVersion: 1 }),
      JSON.stringify({ kind: 'genesis-artifact-record', formatVersion: 2 })]) {
      writeFileSync(record, body)
      writeFileSync(manifest, JSON.stringify({ record: { sha256: digest(body) } }))
      assert.deepEqual(await readCodeSource(scratch), { name: 'code-chain', head: null, entries: null, absence: 'code-record-invalid' })
    }
    const changed = writeCodeRecord(scratch, 'changed-record')
    assert.notEqual(changed, head)
    assert.equal((await readCodeSource(scratch)).head, changed)
    writeFileSync(join(scratch, '.dsh-build/reference.json'), readFileSync(record), { mode: 0o600 })
    rmSync(record)
    symlinkSync(join(scratch, '.dsh-build/reference.json'), record)
    assert.deepEqual(await readCodeSource(scratch), { name: 'code-chain', head: null, entries: null, absence: 'code-record-unreadable' })
    rmSync(record)
    writeCodeRecord(scratch)
    truncateSync(record, 32 * 1024 * 1024 + 1)
    assert.deepEqual(await readCodeSource(scratch), { name: 'code-chain', head: null, entries: null, absence: 'code-record-unreadable' })
    rmSync(record)
    assert.deepEqual(await readCodeSource(scratch), { name: 'code-chain', head: null, entries: null, absence: 'code-record-missing' })
    mkdirSync(record)
    assert.deepEqual(await readCodeSource(scratch), { name: 'code-chain', head: null, entries: null, absence: 'code-record-unreadable' })
  } finally { rmSync(scratch, { recursive: true, force: true }) }
})
add('release FIFOs are refused promptly rather than waiting for a writer', async (_snapshot, _reader, _client, specifier = readerUrl.href) => {
  const scratch = mkdtempSync(new URL('.aura-code-fifo-', import.meta.url))
  try {
    writeCodeRecord(scratch)
    const record = join(scratch, '.dsh-build/genesis-artifacts.json')
    rmSync(record)
    const made = spawnSync('mkfifo', [record], { encoding: 'utf8' })
    if (made.error?.code === 'ENOENT') { console.log('UNPERFORMED: mkfifo is unavailable'); process.exit(2) }
    assert.equal(made.status, 0, 'FIFO fixture must be created')
    const script = `const {readCodeSource}=await import(${JSON.stringify(specifier)}); console.log(JSON.stringify(await readCodeSource(${JSON.stringify(scratch)})))`
    const result = await new Promise(resolve => {
      const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] })
      let out = '', timedOut = false
      child.stdout.on('data', bytes => { out += bytes })
      child.stderr.resume()
      const deadline = setTimeout(() => { timedOut = true; child.kill('SIGKILL') }, 1200)
      child.on('close', status => { clearTimeout(deadline); resolve({ status, out, timedOut }) })
    })
    assert.equal(result.timedOut, false, 'FIFO read must finish without a writer')
    assert.equal(result.status, 0, 'FIFO read must return an absence')
    assert.deepEqual(JSON.parse(result.out), { name: 'code-chain', head: null, entries: null, absence: 'code-record-unreadable' })
  } finally { rmSync(scratch, { recursive: true, force: true }) }
})
add('record growth beyond its captured size is refused and every file handle closes', async (_snapshot, _reader, _client, specifier = readerUrl.href) => {
  const record = JSON.stringify({ kind: 'genesis-artifact-record', formatVersion: 1 }) + '\n'
  const manifest = JSON.stringify({ record: { sha256: digest(record) } })
  let source = specifier.startsWith('data:') ? Buffer.from(specifier.split(',')[1], 'base64').toString('utf8')
    : stripTypeScriptTypes(readFileSync(readerUrl, 'utf8'))
  source = source.replaceAll("'./snapshot.ts'", JSON.stringify(snapshotUrl.href))
  const stub = `export const closedFiles = [];
    const open = async file => {
      const body = Buffer.from(file.endsWith('/aukora-release.json') ? ${JSON.stringify(manifest)} : ${JSON.stringify(record)});
      let at = 0;
      return { async stat() { return { isFile: () => true, size: body.length - 1 } },
        async read(bytes, offset, length) { const count = Math.min(length, body.length - at); body.copy(bytes, offset, at, at + count); at += count; return { bytesRead: count } },
        async close() { closedFiles.push(file) } };
    }`
  assert.ok(source.includes("import { open } from 'node:fs/promises'"), 'growth read stub seam')
  source = source.replace("import { open } from 'node:fs/promises'", stub)
  source += `\nconst testFixtureId = ${++growthFixtureId}\n`
  const module = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
  assert.deepEqual(await module.readCodeSource('/fixture'), { name: 'code-chain', head: null, entries: null, absence: 'code-record-unreadable' })
  assert.deepEqual(module.closedFiles, ['/fixture/.dsh-build/aukora-release.json'])
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
add('carried read-only transport, all source changes, and route never disclose Kira note text', async (_snapshot, { readAuraSnapshot, auraSnapshotHandler }) => {
  const scratch = mkdtempSync(new URL('.aura-snapshot-', import.meta.url))
  try {
    const clientDir = join(scratch, 'plugins/aukora-buzz-door/lib'); mkdirSync(clientDir, { recursive: true })
    writeFileSync(join(clientDir, 'index.mjs'), `export async function gateCall(socket, op, args, timeout) {
      if (socket !== '/fixture/gate.sock' || op !== 'log' || args.limit !== 1 || timeout !== 3000) throw Error('unexpected-read');
      return { verify: { ok: true, head: '${heads[0]}', entries: 7 }, entries: [{ detail: 'PRIVATE_FIXTURE_DETAIL' }] }
    }`)
    const result = await readAuraSnapshot(scratch, '/fixture/gate.sock')
    assert.equal(result.sources[0].head, heads[0]); assert.equal(result.sources[0].entries, 7)
    assert.deepEqual(result.sources.slice(1), [kiraSource({ name: 'kira-chain', head: null, entries: null, absence: 'kira-service-unavailable' }),
      { name: 'code-chain', head: null, entries: null, absence: 'code-record-missing' }])
    assert.equal(JSON.stringify(result).includes('PRIVATE_FIXTURE_DETAIL'), false)
    const codeHead = writeCodeRecord(scratch, privateNote)
    let kiraHead = heads[1], kiraEntries = 9
    const recall = () => ({ head: kiraHead, entries: kiraEntries, absence: null,
      notes: [{ text: privateNote, subjectId: privateNote, path: privateNote }], [privateNote]: privateNote })
    const present = await readAuraSnapshot(scratch, '/fixture/gate.sock', recall)
    assert.deepEqual(present.sources.slice(1), [kiraSource({ name: 'kira-chain', head: kiraHead, entries: 9, absence: null }),
      { name: 'code-chain', head: codeHead, entries: 1, absence: null }])
    assert.deepEqual(await readAuraSnapshot(scratch, '/fixture/gate.sock', recall), present)
    kiraHead = heads[2]; kiraEntries += 1
    const memoryChanged = await readAuraSnapshot(scratch, '/fixture/gate.sock', recall)
    assert.notEqual(memoryChanged.head, present.head)
    writeCodeRecord(scratch, 'changed-running-release')
    const codeChanged = await readAuraSnapshot(scratch, '/fixture/gate.sock', recall)
    assert.notEqual(codeChanged.head, memoryChanged.head)
    const connection = () => ({ requestRejection: () => undefined })
    for (const memory of [recall, changingHead, changingAbsence, () => ({ head: null, entries: null, absence: privateNote }),
      () => { throw Error(privateNote) }, () => Promise.reject(Error(privateNote))]) {
      const res = response()
      await auraSnapshotHandler(connection, () => readAuraSnapshot(scratch, '/fixture/gate.sock', memory))({ method: 'GET', headers: {} }, res)
      assert.equal(res.status, 200)
      assert.equal(res.headers['cache-control'], 'no-store')
      assert.equal(res.body.includes(privateNote), false, 'Kira note text, subject, path and error text never leave this route')
      const payload = JSON.parse(res.body)
      assert.deepEqual(Object.keys(payload).sort(), ['head', 'schema', 'sources'])
      for (const source of payload.sources) assert.deepEqual(Object.keys(source).sort(), source.name === 'kira-chain'
        ? ['absence', 'browserMemory', 'entries', 'head', 'name'] : ['absence', 'entries', 'head', 'name'])
    }
    const failedMemory = await readAuraSnapshot(scratch, '/fixture/gate.sock', () => { throw Error(privateNote) })
    assert.deepEqual(failedMemory.sources[1], kiraSource({ name: 'kira-chain', head: null, entries: null, absence: 'kira-ledger-unreadable' }))
    assert.equal(failedMemory.sources[2].head, codeChanged.sources[2].head, 'Kira read failure does not hide the code source')
    const partialMemory = await readAuraSnapshot(scratch, '/fixture/gate.sock', () => ({ head: heads[1], entries: 9, absence: 'kira-ledger-broken' }))
    assert.deepEqual(partialMemory.sources[1], kiraSource({ name: 'kira-chain', head: null, entries: null, absence: 'kira-head-invalid' }))
    const missingMemory = await readAuraSnapshot(scratch, '/fixture/gate.sock', () => ({ head: null, entries: null, absence: 'kira-ledger-missing' }))
    assert.deepEqual(missingMemory.sources[1], kiraSource({ name: 'kira-chain', head: null, entries: null, absence: 'kira-ledger-missing' }))
    const failure = await readAuraSnapshot(scratch, '/fixture/other.sock')
    assert.equal(failure.sources[0].head, null); assert.equal(failure.sources[0].absence, 'gate-ledger-unavailable')
    const invalid = await readAuraSnapshot(scratch, null)
    assert.equal(invalid.sources[0].head, null); assert.equal(invalid.sources[0].absence, 'gate-socket-invalid')
  } finally { rmSync(scratch, { recursive: true, force: true }) }
})
add('client accepts all server availability states and refuses malformed snapshots', (_snapshot, _reader, { parseAuraSnapshot }) => {
  const base = snapshot.makeAuraSnapshot(sources)
  assert.deepEqual(parseAuraSnapshot(base), base)
  const ready = snapshot.makeAuraSnapshot(sources.map((source, index) => index === 1
    ? { ...source, browserMemory: browserActive } : source))
  assert.deepEqual(parseAuraSnapshot(ready), ready)
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
  for (const browserMemory of [{ active: false, reason: privateNote }, { active: true, reason: browserWaiting.reason },
    { active: privateNote, reason: browserActive.reason }]) {
    const malformed = { ...ready, sources: ready.sources.map((source, index) => index === 1 ? { ...source, browserMemory } : source) }
    refusal(() => parseAuraSnapshot(malformed), 'aura-snapshot:browser-memory')
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
add('client activity records only source heads observed advancing after the baseline', (_snapshot, _reader, { observeSourceAdvances }) => {
  const initial = observeSourceAdvances(new Map(), sources, 100)
  assert.equal(initial.advances.length, 0)
  const unchanged = observeSourceAdvances(initial.heads, sources, 200)
  assert.equal(unchanged.advances.length, 0)
  const changedSources = [{ ...sources[0], head: '44'.repeat(32), entries: 4 }, ...sources.slice(1)]
  const advanced = observeSourceAdvances(unchanged.heads, changedSources, 300)
  assert.deepEqual(advanced.advances, [{ source: 'gate-ledger', head: '44'.repeat(32), entries: 4, observedAt: 300 }])
  assert.equal(observeSourceAdvances(advanced.heads, changedSources, 400).advances.length, 0)
  const unavailable = observeSourceAdvances(advanced.heads, [absent(0), ...changedSources.slice(1)], 500)
  assert.equal(unavailable.advances.length, 0)
  assert.deepEqual(observeSourceAdvances(unavailable.heads, changedSources, 600).advances,
    [{ source: 'gate-ledger', head: '44'.repeat(32), entries: 4, observedAt: 600 }])
})

for (const check of checks) await check.run(snapshot, reader, client)
console.log(`PASS Aura snapshot: ${checks.length} checks`)

const mutations = [
  ['snapshot', "const DOMAIN = 'aukora.aura.snapshot.v1\\0'", "const DOMAIN = 'changed-domain\\0'"],
  ['snapshot', "hash.update(lengthPrefixed(Buffer.from(source.name, 'utf8')))", "hash.update(Buffer.from(source.name, 'utf8'))"],
  ['snapshot', "hash.update(lengthPrefixed(source.head === null ? Buffer.alloc(0) : Buffer.from(source.head, 'hex')))", "hash.update(source.head === null ? Buffer.alloc(0) : Buffer.from(source.head, 'hex'))"],
  ['snapshot', 'for (const source of sources) {', "for (const source of sources.filter(source => source.name !== 'kira-chain')) {"],
  ['snapshot', 'for (const source of sources) {', "for (const source of sources.filter(source => source.name !== 'code-chain')) {"],
  ['snapshot', 'if (!Array.isArray(input) || input.length !== AURA_SNAPSHOT_SOURCES.length\n    || AURA_SNAPSHOT_SOURCES.some(name => input.filter(source => source?.name === name).length !== 1))', 'if (false)'],
  ['snapshot', '!HEX64.test(source.head)', 'false'],
  ['snapshot', '!Number.isSafeInteger(source.entries)', 'false'],
  ['snapshot', '!BROWSER_MEMORY_REASONS.has(state.reason)', 'false'],
  ['snapshot', "state.active !== (state.reason === 'kira.memory:aumlok-linked')", 'false'],
  ['snapshot', 'if (source.head === null\n', 'if (false && (source.head === null\n', 'source.entries < 1) {', 'source.entries < 1)) {'],
  ['reader', 'if (verified?.ok !== true)', 'if (false)'],
  ['reader', '!HEX64.test(verified.head)', 'false'],
  ['reader', '!Number.isSafeInteger(verified.entries)', 'false'],
  ['reader', "if (value === undefined) return absent('kira-chain', 'kira-service-unavailable')", "if (value === undefined) return absent('kira-chain', 'kira-head-invalid')"],
  ['reader', 'KIRA_ABSENCES.has(absence)', 'true'],
  ['reader', '(entries === null || entries === 0)', 'true'],
  ['reader', 'absence !== null', 'false'],
  ['reader', "typeof head !== 'string' || !HEX64.test(head)", 'false'],
  ['reader', '!Number.isSafeInteger(entries)', 'false'],
  ['reader', '(entries as number) < 1', 'false'],
  ['reader', "return { name: 'kira-chain', head, entries: entries as number, absence: null, browserMemory: readiness }",
    "return { ...(value as object), name: 'kira-chain', head, entries: entries as number, absence: null, browserMemory: readiness }"],
  ['reader', "return { name: 'kira-chain', head, entries: entries as number, absence: null, browserMemory: readiness }",
    "return { name: 'kira-chain', head: (value as { head: string }).head, entries: entries as number, absence: null, browserMemory: readiness }"],
  ['reader', "return { name: 'kira-chain', head, entries: entries as number, absence: null, browserMemory: readiness }",
    "return { name: 'kira-chain', head, entries: (value as { entries: number }).entries, absence: null, browserMemory: readiness }"],
  ['reader', "{ ...absent('kira-chain', absence, entries), browserMemory: readiness }",
    "{ ...absent('kira-chain', (value as { absence: string }).absence, entries), browserMemory: readiness }"],
  ['reader', 'BROWSER_MEMORY_REASONS.has(reason)', 'true'],
  ['reader', "active === (reason === 'kira.memory:aumlok-linked')", 'true'],
  ['reader', "typeof digest !== 'string' || !HEX64.test(digest)", 'false'],
  ['reader', 'record?.formatVersion !== 1', 'false'],
  ['reader', "record.kind !== 'genesis-artifact-record'", 'false'],
  ['reader', "if (createHash('sha256').update(recordBytes).digest('hex') !== digest)", 'if (false)'],
  ['reader', "readReleaseFact(join(releaseRoot, '.dsh-build/genesis-artifacts.json'))", "readReleaseFact(join(releaseRoot, '.dsh-build/aukora-release.json'))"],
  ['reader', '!stat.isFile()', 'false'],
  ['reader', 'stat.size > 32 * 1024 * 1024', 'false'],
  ['reader', 'FS.O_NOFOLLOW', '0'],
  ['reader', 'FS.O_NONBLOCK', '0'],
  ['reader', "    throw Object.assign(new Error('code-record-unreadable'), { code: 'code-record-unreadable' })\n  } finally", '    return bytes\n  } finally'],
  ['reader', 'await handle.close()', 'undefined', null, null, 'record growth beyond its captured size is refused and every file handle closes'],
  ['reader', "? 'code-record-missing' : 'code-record-unreadable'", "? 'code-record-missing' : 'code-record-missing'"],
  ['reader', 'await readKira?.()', 'undefined'],
  ['reader', 'await readCodeSource(releaseRoot)', "absent('code-chain', 'code-record-missing')"],
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
  ['client', '!BROWSER_MEMORY_REASONS.has(memory.reason)', 'false'],
  ['client', "memory.active !== (memory.reason === 'kira.memory:aumlok-linked')", 'false'],
  ['client', 'const counters = new Map(previous)', 'const counters = previous'],
  ['client', 'if (source.entries === null) continue', ''],
  ['client', 'if (before !== undefined)', 'if (true)'],
  ['client', 'Math.max(0, source.entries - before)', 'source.entries - before'],
  ['client', 'Math.max(before ?? source.entries, source.entries)', 'source.entries'],
  ['client', 'const seen = heads.has(source.name)', 'const seen = false'],
  ['client', 'source.head !== null && source.head !== before', 'source.head !== null && true'],
  ['client', 'seen && source.head !== null', 'seen && true'],
  ['client', 'heads.set(source.name, source.head)', 'undefined'],
]
let killed = 0
async function runMutation([file, before, after, secondBefore, secondAfter, only]) {
  let source = readFileSync(file === 'snapshot' ? snapshotUrl : file === 'reader' ? readerUrl : clientUrl, 'utf8')
  assert.ok(source.includes(before), `missing mutation seam: ${before}`)
  source = source.replaceAll(before, after)
  if (secondBefore) { assert.ok(source.includes(secondBefore)); source = source.replace(secondBefore, secondAfter) }
  if (file === 'reader') {
    source = source.replaceAll("'./snapshot.ts'", JSON.stringify(snapshotUrl.href))
      .replace("await import(join(releaseRoot, 'plugins/aukora-buzz-door/lib/index.mjs'))",
        "await import(testFileURL(join(releaseRoot, 'plugins/aukora-buzz-door/lib/index.mjs')).href)")
    source = "import { pathToFileURL as testFileURL } from 'node:url'\n" + source
  }
  const specifier = `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source)).toString('base64')}`
  const module = await import(specifier)
  const selected = only === undefined ? checks : checks.filter(check => check.name === only)
  assert.ok(selected.length > 0, 'mutation selects executable checks')
  let checked
  try {
    for (const check of selected) {
      checked = check.name
      await check.run(file === 'snapshot' ? module : snapshot, file === 'reader' ? module : reader,
        file === 'client' ? module : client, file === 'reader' ? specifier : readerUrl.href)
    }
  } catch (error) {
    if (error.code !== 'ERR_ASSERTION') throw error
    if (before === after) throw Object.assign(new Error(`unchanged control failed ${checked}: ${error.message}`), { code: 'ERR_ASSERTION' })
    killed += 1
  }
}
for (let offset = 0; offset < mutations.length; offset += 4) await Promise.all(mutations.slice(offset, offset + 4).map(runMutation))
assert.equal(killed, mutations.length, 'a removed protection survived its regression')
await Promise.all(Array.from({ length: 4 }, () => runMutation(['reader', 'const CACHE_MS = 1500', 'const CACHE_MS = 1500'])))
assert.equal(killed, mutations.length, 'an unchanged control must survive the same concurrent regressions')
console.log(`PASS Aura snapshot mutation controls: ${killed}/${mutations.length} killed`)
console.log('PASS Aura snapshot unchanged controls: 4/4 survived')
process.umask(previousMask)
