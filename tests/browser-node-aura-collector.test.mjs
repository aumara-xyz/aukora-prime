// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise read-only collection, public projection and collector output custody.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { EventEmitter } from 'node:events'
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import * as collector from '../scripts/aura/collect-head.mjs'

const source = readFileSync(new URL('../scripts/aura/collect-head.mjs', import.meta.url), 'utf8')
const summary = { ok: true, entries: 5, head: 'a'.repeat(64) }
const refused = (operation, code) => assert.rejects(operation, error => error.code === 'aura-head:' + code)
mkdirSync(new URL('../.runtime/', import.meta.url), { recursive: true })

function socketFixture(response, { stall = false, error = false } = {}) {
  const connection = new EventEmitter()
  connection.destroy = () => {}
  connection.write = value => {
    connection.request = value
    queueMicrotask(() => {
      if (stall) return
      if (error) return connection.emit('error', new Error('PRIVATE_PATH'))
      connection.emit('data', Buffer.isBuffer(response) ? response : Buffer.from(response))
      connection.emit('end')
    })
  }
  const connect = () => { queueMicrotask(() => connection.emit('connect')); return connection }
  return { connect, connection }
}

async function publicProjection(api) {
  assert.deepEqual(api.projectGateHead({ ...summary, detail: 'PRIVATE_RECORD' }), summary)
  assert.deepEqual(api.projectGateHead({ ok: true, entries: 0, head: 'GENESIS' }), { ok: true, entries: 0, head: 'GENESIS' })
  for (const value of [null, { ...summary, ok: false }, { ...summary, entries: 1.5 }, { ...summary, entries: -1 },
    { ...summary, entries: Number.MAX_SAFE_INTEGER + 1 }, { ...summary, entries: 0 },
    { ...summary, head: 'GENESIS' }, { ...summary, head: 'A'.repeat(64) }, { ...summary, head: null },
    { ...summary, head: summary.head + '\n' },
    { ...summary, head: { toString: () => summary.head } }]) {
    assert.throws(() => api.projectGateHead(value), error => error.code === 'aura-head:unverified')
  }
}

async function socketRead(api) {
  const fixture = socketFixture(JSON.stringify({ ok: true, result: { ...summary, detail: 'PRIVATE_RECORD' } }))
  assert.deepEqual(await api.readGateHead('/fixture/gate.sock', fixture.connect), summary)
  assert.equal(fixture.connection.request, '{"op":"verify","args":{}}\n')
  for (const response of ['bad JSON', JSON.stringify({ ok: false, result: summary }),
    JSON.stringify({ ok: true, result: { ...summary, ok: false } }),
    Buffer.from([0xff, ...Buffer.from(JSON.stringify({ ok: true, result: summary }))]),
    Buffer.concat([Buffer.from('{"ok":true,"result":' + JSON.stringify(summary) + ',"extra":"'),
      Buffer.from([0xff]), Buffer.from('"}')])]) {
    const rejected = socketFixture(response)
    await refused(api.readGateHead('/fixture/gate.sock', rejected.connect), 'reply-invalid')
  }
  const oversized = socketFixture(' '.repeat(4097) + JSON.stringify({ ok: true, result: summary }))
  await refused(api.readGateHead('/fixture/gate.sock', oversized.connect), 'reply-limit')
  const failed = socketFixture('', { error: true })
  await refused(api.readGateHead('/fixture/gate.sock', failed.connect), 'unavailable')
  const stalled = socketFixture('', { stall: true })
  await refused(Promise.race([api.readGateHead('/fixture/gate.sock', stalled.connect, 1),
    new Promise((_, reject) => setTimeout(() => reject(new Error('missing timeout')), 25))]), 'timeout')
}

async function outputCustody(api) {
  const root = mkdtempSync(new URL('../.runtime/aura-collector-', import.meta.url))
  const mask = process.umask(0o077)
  const getuid = process.getuid
  try {
    const directory = join(root, 'head'); mkdirSync(directory, { mode: 0o750 })
    const file = join(directory, 'gate.json')
    await api.writeGateHead(file, { ...summary, detail: 'PRIVATE_RECORD' })
    assert.equal(lstatSync(file).mode & 0o777, 0o640)
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), summary)
    await refused(api.writeGateHead(file, { ...summary, ok: false }), 'unverified')
    chmodSync(directory, 0o770)
    await refused(api.writeGateHead(file, summary), 'output-custody')
    chmodSync(directory, 0o750)
    process.getuid = () => getuid() + 1
    await refused(api.writeGateHead(file, summary), 'output-custody')
    process.getuid = getuid
    const link = join(root, 'linked'); symlinkSync(directory, link)
    await refused(api.writeGateHead(join(link, 'gate.json'), summary), 'output-custody')
  } finally {
    process.getuid = getuid
    process.umask(mask)
    rmSync(root, { recursive: true, force: true })
  }
}

test('collector projects only a complete verified public head', () => publicProjection(collector))
test('collector sends verify only and bounds replies and time', () => socketRead(collector))
test('collector output is readable by its group and writable only by its owner', () => outputCustody(collector))
test('collector protection removals fail their regression', async () => {
  const mutations = [
    ['verified', 'ok !== true || ', '', publicProjection],
    ['integer', '!Number.isSafeInteger(entries) || ', '', publicProjection],
    ['negative', 'entries < 0', 'false', publicProjection],
    ['genesis', "head !== 'GENESIS'", 'false', publicProjection],
    ['head type', "typeof head !== 'string' || ", '', publicProjection],
    ['head shape', '!/^[a-f0-9]{64}$/u.test(head)', 'false', publicProjection],
    ['read-only op', '"op":"verify"', '"op":"log"', socketRead],
    ['reply bound', 'bytes.length + chunk.length > 4096', 'false', socketRead],
    ['reply success', 'reply?.ok !== true', 'false', socketRead],
    ['UTF-8', "new TextDecoder('utf-8', { fatal: true })", "new TextDecoder('utf-8')", socketRead],
    ['timeout', "setTimeout(() => fail('timeout'), timeoutMs)", 'setTimeout(() => {}, timeoutMs)', socketRead],
    ['directory', '!info.isDirectory() || ', '', outputCustody],
    ['owner', 'info.uid !== process.getuid() || ', '', outputCustody],
    ['writable group', 'info.mode & 0o022', 'false', outputCustody],
    ['group readable', 'await handle.chmod(0o640)', 'void 0', outputCustody],
  ]
  for (const [name, before, after, check] of mutations) {
    assert.equal(source.split(before).length - 1, 1, name)
    const module = await import('data:text/javascript;base64,' + Buffer.from(source.replace(before, after)).toString('base64'))
    await assert.rejects(check(module), undefined, name + ' removal survived')
  }
  console.log('SOURCE-ONLY Aura head collector mutations: ' + mutations.length + '/' + mutations.length + ' killed')
})
