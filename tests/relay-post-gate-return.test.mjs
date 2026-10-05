// Source-only: actual relay plugin and actual signed gate ledger. Relay HTTP replies are injected;
// no server listens, operational key is read, approval is exercised or installed service is changed.
// Fresh synthetic gate state is retained under the no-delete hold.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createGate } from '../packages/boundary-gate/src/gate.mjs'
import { createRelayTools } from '../plugins/aukora-relay-auma/lib/index.mjs'
import { makeSyntheticPostPolicy } from '../plugins/aukora-relay-auma/checks/synthetic-policy.mjs'

const PUBLIC_TOKEN = 'SYNTHETIC_PUBLIC_RETURN_FIXTURE_ONLY'.padEnd(64, '_')
const ID = 'b'.repeat(64), CURSOR = '9170002', TEXT = 'Synthetic source-only relay return fixture.'
const rows = gate => gate.db.prepare("SELECT seq, hash, event, detail FROM ledger WHERE event LIKE 'relay-%' ORDER BY seq").all()

function fixture(t, { posted, intent, between } = {}) {
  const { config: postPolicy, root } = makeSyntheticPostPolicy()
  const home = path.join(root, 'retained-synthetic-gate')
  fs.mkdirSync(home, { mode: 0o700 })
  // Actual signed gate core with a fresh empty target set. Creation-time modes
  // replace the older fixture's redundant chmod; no existing state is touched.
  const gate = createGate({ home, targets: {}, store: { read: () => null, write: () => { throw new Error('no fixture target writes') } },
    now: () => Date.UTC(2026, 9, 3, 12) })
  gate.startup({ pid: 1 })
  t.after(() => gate.db.close())
  const calls = [], sent = []
  let intentReceipt
  const tools = createRelayTools({ getKey: () => PUBLIC_TOKEN, postPolicy, gateSocket: '/synthetic-only/gate.sock',
    gate: async (_socket, op, args) => {
      assert.equal(op, 'relay_record')
      calls.push(structuredClone(args))
      if (args.phase === 'intent') {
        intentReceipt = intent ? intent(gate, args) : gate.proposeOps.relay_record(args)
        return intentReceipt
      }
      return posted ? posted(gate, args, intentReceipt) : gate.proposeOps.relay_record(args)
    },
    fetchImpl: async (_url, request) => {
      sent.push(JSON.parse(request.body))
      between?.(gate)
      return { ok: true, status: 201, json: async () => ({ message: { id: ID, cursor: CURSOR, author: 'auma' } }) }
    },
  })
  return { gate, calls, sent, post: async (args = { text: TEXT }) => {
    const raw = await tools.post.execute(args)
    assert(!raw.includes(PUBLIC_TOKEN), 'fixture credential must stay outside the result')
    return JSON.parse(raw)
  } }
}

function unconfirmed(result) {
  assert.equal(result.ok, true)
  assert.equal(result.state, 'POSTED_UNRECORDED')
  assert.equal(result.anchored, false)
  assert.equal(result.id, ID)
  assert.equal(result.cursor, CURSOR)
  assert.equal(Object.hasOwn(result, 'ledger_seq'), false)
  assert.equal(Object.hasOwn(result, 'ledger_hash'), false)
}

test('actual posted row supplies sequence/hash, with unrelated rows and a distinct relay cursor', async t => {
  const f = fixture(t, { between: gate => gate.proposeOps.selfcheck({ result: { synthetic: true } }) })
  const result = await f.post(), [intent, posted] = rows(f.gate)
  assert.equal(result.state, 'POSTED')
  assert.equal(result.anchored, true)
  assert.equal(result.ledger_seq, posted.seq)
  assert.equal(result.ledger_hash, posted.hash)
  assert(posted.seq > intent.seq + 1, 'the result cannot guess intent + 1')
  assert.notEqual(String(result.ledger_seq), result.cursor)
  assert.equal(JSON.parse(posted.detail).message_id, result.id)
  assert.equal(JSON.parse(posted.detail).cursor, result.cursor)
  assert.equal(JSON.parse(posted.detail).client_request_id, f.sent[0].clientRequestId)
  assert.equal(f.sent.length, 1)
  assert.equal(f.calls.length, 2)
  assert.equal(f.gate.verify().ok, true)
  assert(!JSON.stringify(rows(f.gate)).includes(TEXT), 'the gate stores commitments, not message text')
})

test('intent refusal prevents every relay effect and supplies no gate coordinates', async t => {
  const f = fixture(t, { intent: () => { throw new Error('synthetic intent unavailable') } })
  const result = await f.post()
  assert.equal(result.state, 'REFUSED')
  assert.equal(f.sent.length, 0)
  assert.equal(rows(f.gate).length, 0)
  assert.equal(Object.hasOwn(result, 'ledger_seq'), false)
})

test('failed posted append leaves the posted message unconfirmed without retry', async t => {
  const f = fixture(t, { posted: () => { throw new Error('synthetic append unavailable') } })
  unconfirmed(await f.post())
  assert.deepEqual(rows(f.gate).map(row => row.event), ['relay-intent'])
  assert.equal(f.sent.length, 1)
  assert.equal(f.calls.length, 2)
})

test('committed posted row with lost reply stays unconfirmed; no receipt reconstruction or second send', async t => {
  const f = fixture(t, { posted: (gate, args) => {
    gate.proposeOps.relay_record(args)
    throw new Error('synthetic lost acknowledgment')
  } })
  unconfirmed(await f.post())
  assert.deepEqual(rows(f.gate).map(row => row.event), ['relay-intent', 'relay-posted'])
  assert.equal(f.gate.verify().ok, true)
  assert.equal(f.sent.length, 1)
  assert.equal(f.calls.length, 2)
})

test('an intent receipt cannot stand in for the posted event', async t => {
  const f = fixture(t, { posted: (_gate, _args, intent) => intent })
  unconfirmed(await f.post())
  assert.deepEqual(rows(f.gate).map(row => row.event), ['relay-intent'])
  assert.equal(f.sent.length, 1)
})

const malformed = [
  ['missing hash', ({ ok, seq }) => ({ ok, seq })],
  ['string sequence', receipt => ({ ...receipt, seq: String(receipt.seq) })],
  ['unsafe sequence', receipt => ({ ...receipt, seq: Number.MAX_SAFE_INTEGER + 1 })],
  ['zero sequence', receipt => ({ ...receipt, seq: 0 })],
  ['hash array', receipt => ({ ...receipt, hash: [receipt.hash] })],
  ['uppercase hash', receipt => ({ ...receipt, hash: receipt.hash.toUpperCase() })],
  ['false acknowledgment', receipt => ({ ...receipt, ok: false })],
  ['extra assertion', receipt => ({ ...receipt, approved: true })],
  ['accessor', receipt => Object.defineProperty({ ...receipt }, 'hash', {
    enumerable: true, get() { throw new Error('receipt getter must not run') },
  })],
]
for (const [label, change] of malformed) {
  test(`malformed posted acknowledgment (${label}) never supplies coordinates`, async t => {
    const f = fixture(t, { posted: (gate, args) => change(gate.proposeOps.relay_record(args)) })
    unconfirmed(await f.post())
    assert.equal(rows(f.gate).filter(row => row.event === 'relay-posted').length, 1)
    assert.equal(f.sent.length, 1)
    assert.equal(f.calls.length, 2)
  })
}

test('malformed intent acknowledgment refuses before a send despite its committed intent', async t => {
  const f = fixture(t, { intent: (gate, args) => ({ ...gate.proposeOps.relay_record(args), hash: null }) })
  const result = await f.post()
  assert.equal(result.state, 'REFUSED')
  assert.equal(f.sent.length, 0)
  assert.deepEqual(rows(f.gate).map(row => row.event), ['relay-intent'])
})

test('caller-supplied ledger coordinates are refused before gate or relay', async t => {
  const f = fixture(t)
  assert.equal((await f.post({ text: TEXT, ledger_seq: 1, ledger_hash: ID })).state, 'REFUSED')
  assert.equal(f.calls.length, 0)
  assert.equal(f.sent.length, 0)
})
