// Source-only, synthetic stores through the actual tracked-memory append path.
// No owner keys, approval, session-source claims, network listener, or installed runtime.
// Fresh fixture roots are retained; this court never deletes files or state.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createTrackedMemory, memoryChain, readTrackedMemory, MAX_NOTE_CHARS } from '../plugins/aukora-kira/lib/tracked-memory.mjs'
import { AURA_RECORD_DOMAIN } from '../plugins/aukora-kira/lib/memory-owner.mjs'
import { STORE_PATHS } from '../plugins/aukora-kira/lib/memory-store.mjs'
import { apply } from '../plugins/aukora-kira/lib/index.js'
import { MAX_REMEMBER_INPUT_BYTES } from '../plugins/aukora-kira/lib/memory-input-bounds.mjs'
import { nextEntry } from '../plugins/aukora-kira/lib/memory-journal.mjs'
import { appendJournalLine } from '../plugins/aukora-kira/lib/strict-read.mjs'

const NOW = Date.parse('2026-10-05T22:44:00.000Z')
const SUBJECT = `aukora:1:${'3'.repeat(64)}` // synthetic subject, no credential or signing identity
const project = entry => Object.fromEntries(['op', 'id', 'index', 'sequence', 'prev', 'hash', 'entryHash', 'contentHash'].map(key => [key, entry[key]]))
function fixture(options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'd-kira-append-return-'))
  const stateDir = path.join(root, 'kira-memory')
  const memory = createTrackedMemory({ stateDir, subject: SUBJECT, now: () => NOW, ...options })
  return { root, stateDir, memory }
}
async function nativeFixture(fn) {
  const { root, stateDir } = fixture()
  const envKeys = ['AUKORA_STATE', 'AUKORA_OPENVIKING_HOME', 'AUKORA_ROOM_LOG']
  const original = new Map(envKeys.map(key => [key, process.env[key]]))
  process.env.AUKORA_STATE = root
  process.env.AUKORA_OPENVIKING_HOME = path.join(root, 'openviking')
  process.env.AUKORA_ROOM_LOG = path.join(root, 'room.log')
  const tools = new Map(), disposers = [], services = new Map()
  const ctx = {
    tools: { register(definition) { tools.set(definition.name, definition) } },
    provide(name, service) { services.set(name, service) },
    inject() {}, on() { return () => {} }, emit() {},
    logger: { warn() {}, info() {} }, sessions: { get() {} }, reflect: { get() {} },
    effect(setup, label) {
      const dispose = setup()
      // Cancel only this fixture's immediate/interval indexing; never run the
      // Room importer or retry timer against any installed input.
      if (label === 'aukora-kira: memory index retry') dispose()
      else disposers.push(dispose)
    },
  }
  try {
    await apply(ctx, { memoryOwner: { stateDir, subject: SUBJECT, permittedPrivacy: ['local'] } })
    const tool = tools.get('kira_remember')
    assert.ok(tool, 'actual apply must register the real tool')
    await fn({ tool, stateDir })
    for (const artifact of ['issuer.json', 'aura.jsonl', 'grant.json', 'approval.json', 'spent.jsonl', 'queue', 'settled']) {
      assert.equal(fs.existsSync(path.join(stateDir, artifact)), false, `no approval artifact ${artifact}`)
    }
  } finally {
    for (const dispose of disposers.reverse()) dispose?.()
    for (const [key, value] of original) { if (value === undefined) delete process.env[key]; else process.env[key] = value }
  }
}
function checkReceipt(result, stateDir) {
  assert.equal(result.receipt?.kind, 'kira.remembered-append/v1')
  assert.equal(result.receipt.signed, false)
  assert.equal(result.receipt.grantsAuthority, false)
  assert.deepEqual(Object.keys(result.receipt).sort(), ['entries', 'grantsAuthority', 'kind', 'signed'])
  const chain = memoryChain(stateDir)
  assert.equal(result.receipt.entries.length, result.remembered)
  assert.deepEqual(result.receipt.entries.map(entry => entry.id), result.notes.map(note => note.id))
  for (const entry of result.receipt.entries) {
    const actual = chain.find(row => row.hash === entry.hash)
    assert.ok(actual, 'receipt must name an actual verified durable row')
    assert.deepEqual(entry, project(actual))
    assert.equal(entry.op, 'remember')
    assert.equal(entry.sequence, entry.index + 1)
    assert.notEqual(entry.entryHash, entry.hash, 'note commitment and chain hash are distinct')
    assert.deepEqual(Object.keys(entry).sort(), ['contentHash', 'entryHash', 'hash', 'id', 'index', 'op', 'prev', 'sequence'])
  }
  assert.equal(fs.existsSync(path.join(stateDir, STORE_PATHS.aura)), false, 'unsigned capture does not create an approved chain')
  return chain
}

test('ordinary remember returns the exact committed unsigned rows and preserves UNLINKED source', async () => {
  const { memory, stateDir } = fixture()
  const text = 'Synthetic receipt sample: whitespace  and Unicode λ.\nA second line.'
  const result = await memory.remember({ text, from: 'agent', scope: 'owner' })
  const chain = checkReceipt(result, stateDir)
  assert.equal(chain.length, 1)
  assert.equal(result.receipt.entries[0].prev, AURA_RECORD_DOMAIN)
  assert.equal(result.notes[0].statement, text)
  assert.equal(result.notes[0].tier, 'remembered')
  assert.equal(result.notes[0].source.state, 'UNLINKED')
  assert.equal(result.notes[0].source.cited, false)
  assert.equal(result.notes[0].auraAssociation, undefined)
  assert.equal(result.index.added, 0)
  assert.equal(result.index.pending, 1)
  assert.deepEqual(result.index.failed, ['openviking-not-configured'])
  assert.equal(JSON.stringify(result.receipt).includes(text), false, 'append receipt contains no note body')
  assert.equal(JSON.stringify(result.receipt).includes('salt'), false)
})

test('cold reopen verifies the exact rows; dedup does not manufacture a new append receipt', async () => {
  const { memory, stateDir } = fixture()
  const input = { text: 'Synthetic cold receipt sample.', from: 'agent', scope: 'owner' }
  const first = await memory.remember(input)
  checkReceipt(first, stateDir)
  const before = fs.readFileSync(path.join(stateDir, STORE_PATHS.rememberedAura), 'utf8')
  const reopened = createTrackedMemory({ stateDir, subject: SUBJECT, now: () => NOW + 60_000 })
  const live = reopened.read()
  assert.equal(live.complete, true)
  assert.deepEqual(first.receipt.entries, live.chain.map(project))
  const repeated = await reopened.remember(input)
  assert.equal(repeated.remembered, 0)
  assert.deepEqual(repeated.ids, first.ids)
  assert.deepEqual(repeated.notes, [])
  assert.equal(repeated.receipt, null)
  assert.equal(fs.readFileSync(path.join(stateDir, STORE_PATHS.rememberedAura), 'utf8'), before)
})

test('chunked capture returns each actual append row in order, including its original hashes', async () => {
  const { memory, stateDir } = fixture()
  const text = 'λ'.repeat(MAX_NOTE_CHARS * 2 + 11)
  const result = await memory.remember({ text, from: 'agent', scope: 'owner' })
  const chain = checkReceipt(result, stateDir)
  assert.equal(result.remembered, 3)
  assert.equal(result.notes.map(note => note.statement).join(''), text)
  assert.deepEqual(result.receipt.entries.map(entry => entry.sequence), [1, 2, 3])
  assert.equal(result.receipt.entries[1].prev, chain[0].hash)
  assert.equal(result.receipt.entries[2].prev, chain[1].hash)
})

test('batch attribution returns receipts only for the inputs that actually append', async () => {
  const { memory, stateDir } = fixture()
  const firstInput = { text: 'Synthetic batch first.', from: 'agent', scope: 'owner' }
  const secondInput = { text: 'Synthetic batch second.', from: 'agent', scope: 'owner' }
  const { results } = await memory.rememberBatch([firstInput, firstInput, { text: '', from: 'agent' }, secondInput])
  checkReceipt(results[0], stateDir)
  assert.equal(results[1].remembered, 0)
  assert.equal(results[1].receipt, null)
  assert.deepEqual(results[1].ids, results[0].ids)
  assert.equal(results[2].error, 'memory-text-invalid')
  assert.equal(results[2].receipt, null)
  checkReceipt(results[3], stateDir)
  assert.equal(results[3].receipt.entries[0].sequence, 2)
  assert.equal(memoryChain(stateDir).length, 2)
})

test('index failure retains factual saved receipt without claiming indexed success', async () => {
  let requests = 0
  const { memory, stateDir } = fixture({ client: { configured: true, async sync() { requests++; throw new Error('synthetic index unavailable') } } })
  const result = await memory.remember({ text: 'Synthetic saved despite index failure.', from: 'agent' })
  checkReceipt(result, stateDir)
  assert.equal(requests, 1)
  assert.equal(result.remembered, 1)
  assert.equal(result.index.added, 0)
  assert.equal(result.index.pending, 1)
  assert.deepEqual(result.index.failed, ['index-unavailable'])
})

test('later append during awaited indexing cannot replace the first call receipt with the latest head', async () => {
  let later
  const { memory, stateDir } = fixture({ client: { configured: true, async sync() {
    const second = createTrackedMemory({ stateDir, subject: SUBJECT, now: () => NOW + 1000 })
    later = await second.remember({ text: 'Synthetic interleaved second append.', from: 'agent' })
    return { added: 0, requests: 0, pending: 2, failed: ['synthetic-index-unavailable'] }
  } } })
  const first = await memory.remember({ text: 'Synthetic interleaved first append.', from: 'agent' })
  const chain = checkReceipt(first, stateDir)
  checkReceipt(later, stateDir)
  assert.equal(chain.length, 2)
  assert.equal(first.receipt.entries[0].hash, chain[0].hash)
  assert.equal(later.receipt.entries[0].hash, chain[1].hash)
  assert.notEqual(first.receipt.entries[0].hash, chain.at(-1).hash)
})

test('capture paused by host policy and malformed text return no append receipt', async () => {
  const paused = fixture({ policyOf: async () => ({ offTheRecord: true }) })
  const blocked = await paused.memory.remember({ text: 'Synthetic paused sample.', from: 'agent' })
  assert.equal(blocked.remembered, 0)
  assert.equal(blocked.reason, 'capture-paused')
  assert.equal(blocked.receipt, null)
  assert.equal(memoryChain(paused.stateDir).length, 0)
  const normal = fixture()
  const malformed = await normal.memory.remember({ text: 'Synthetic lone surrogate \ud800', from: 'agent' })
  assert.equal(malformed.reason, 'memory-text-not-well-formed')
  assert.equal(malformed.receipt, null)
  assert.equal(memoryChain(normal.stateDir).length, 0)
})

test('host lifetime refusal precedes durable capture and returns no receipt', async () => {
  const { memory, stateDir } = fixture()
  const batch = await memory.rememberBatch([{ text: 'Synthetic unloaded capture.', from: 'agent' }], { isCaptureLive: () => false })
  assert.equal(batch.results[0].reason, 'capture-paused')
  assert.equal(batch.results[0].receipt, null)
  assert.equal(fs.existsSync(stateDir), false)
})

test('caller-supplied gate association is refused rather than echoed as receipt evidence', async () => {
  const { memory, stateDir } = fixture()
  await assert.rejects(memory.remember({ text: 'Synthetic caller association sample.', from: 'agent', auraSource: { seq: 99 } }), /memory-aura-source-host-only/u)
  assert.equal(memoryChain(stateDir).length, 0)
})

test('unreadable chain refuses save and leaves the malformed fixture unchanged', async () => {
  const { memory, stateDir } = fixture()
  fs.mkdirSync(path.join(stateDir, 'remembered'), { recursive: true, mode: 0o700 })
  const chain = path.join(stateDir, STORE_PATHS.rememberedAura)
  const damaged = '{"synthetic":"unclosed"\n'
  fs.writeFileSync(chain, damaged, { flag: 'wx', mode: 0o600 })
  await assert.rejects(memory.remember({ text: 'Synthetic refused against damaged chain.', from: 'agent' }), /memory-chain-unreadable/u)
  assert.equal(fs.readFileSync(chain, 'utf8'), damaged)
})

test('actual registered kira_remember and renderer preserve the real append receipt', async () => {
  await nativeFixture(async ({ tool, stateDir }) => {
    const args = { text: 'Synthetic registered tool receipt sample λ.' }
    const result = await tool.execute(args, { agent: { sessionId: 'synthetic-tool-session' } })
    checkReceipt(result, stateDir)
    assert.deepEqual(tool.output.render(args, result), [{ type: 'text', text: JSON.stringify(result) }])
    assert.deepEqual(JSON.parse(tool.output.render(args, result)[0].text).receipt, result.receipt)
    assert.deepEqual(tool.output.schema.required, ['receipt'])
    assert.equal(tool.output.schema.properties.receipt.oneOf[0].properties.signed.const, false)
    assert.equal(result.notes[0].source.state, 'UNLINKED')
    const repeated = await tool.execute(args, { agent: { sessionId: 'synthetic-tool-session' } })
    assert.equal(repeated.receipt, null)
    assert.equal(repeated.remembered, 0)
    assert.equal(memoryChain(stateDir).length, 1)
  })
})

test('native byte cap refuses before store resolution and supplies no receipt', async () => {
  await nativeFixture(async ({ tool, stateDir }) => {
    const text = 'λ'.repeat(Math.floor(MAX_REMEMBER_INPUT_BYTES / 2) + 1)
    const result = await tool.execute({ text }, {})
    assert.equal(result.reason, 'remember-input-too-long')
    assert.equal(result.receipt, null)
    assert.equal(result.remembered, 0)
    assert.equal(result.grantsAuthority, false)
    assert.equal(fs.existsSync(stateDir), false)
  })
})

test('captureTurn private append caller preserves saved notes, index and actual receipt', async () => {
  const { memory, stateDir } = fixture()
  const at = new Date(NOW).toISOString()
  const text = 'Remember that this synthetic capture fixture has a blue label.'
  const event = { type: 'user/message', seq: 0, data: { turn: 0, text } }
  const turn = { sessionId: 'synthetic-capture-session', seq: 0, at, turn: 0, text, canonicalEventLine: JSON.stringify(event) }
  const result = await memory.captureTurn(turn, { explicitRemember: true, attributedTo: 'owner' })
  assert.ok(result.remembered > 0)
  checkReceipt(result, stateDir)
  assert.equal(result.index.added, 0)
  assert.equal(result.index.pending, result.remembered)
  const repeated = await memory.captureTurn(turn, { explicitRemember: true, attributedTo: 'owner' })
  assert.equal(repeated.remembered, 0)
  assert.equal(repeated.receipt, null)
})

test('hidden historical IDs do not acquire a new receipt or regain recall eligibility', async () => {
  const { memory, stateDir } = fixture()
  const input = { text: 'Synthetic hidden historical receipt sample.', from: 'agent' }
  const first = await memory.remember(input)
  const journal = readTrackedMemory(stateDir).journal
  const hide = nextEntry({ previous: journal.at(-1), op: 'hide', id: first.ids[0], objectDigest: first.notes[0].contentHash,
    at: new Date(NOW + 1000).toISOString(), actor: 'synthetic-owner', reason: 'synthetic hide fixture' })
  appendJournalLine({ file: path.join(stateDir, STORE_PATHS.journal), line: JSON.stringify(hide) })
  const repeated = await memory.remember(input)
  assert.deepEqual(repeated.ids, first.ids)
  assert.equal(repeated.remembered, 0)
  assert.equal(repeated.receipt, null)
  assert.equal(memoryChain(stateDir).length, 1)
  assert.equal(memory.read().notes.length, 0)
})
