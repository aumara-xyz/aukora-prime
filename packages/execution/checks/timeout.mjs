// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable SDK protocol regressions only: no guest, gateway, keys or host exec.
// A rejecting mock broker below tests the durable delivery fence independently
// of C's evolving validator. Actual C allowance uses joined.mjs complete-null.
import assert from 'node:assert/strict'
import { rm } from 'node:fs/promises'
import { validateContract } from '../../contracts/src/runtime.mjs'
import { OwnedLedger } from '../src/index.mjs'
import { fixture, request, settings, MockedProtocolExecutor } from './harness.mjs'

const roots = [], ledgers = new Set()
const evidence = { exit_code: 124, reason: 'ambiguous_timeout_or_command_exit' }
const clone = structuredClone
let checks = 0

async function make(options = {}, hooks = {}) {
  const f = await fixture(options, hooks)
  roots.push(f.root)
  ledgers.add(f.ledger)
  return f
}
function close(ledger) { ledger.close(); ledgers.delete(ledger) }
function reopen(f) {
  close(f.ledger)
  const ledger = new OwnedLedger(f.root)
  ledgers.add(ledger)
  return { ledger, executor: new MockedProtocolExecutor({ settings, transport: f.transport, ledger, broker: f.broker }) }
}
function count(f, name) { return f.protocol.calls.filter(([method]) => method === name).length }
function assertUnknown(receipt, completion = 'complete', cleanup = 'confirmed_absent') {
  assert.equal(receipt.status, 'outcome_unknown')
  assert.equal(receipt.exit_code, null)
  assert.equal(receipt.rpc_completion, completion)
  assert.equal(receipt.cleanup, cleanup)
  assert.equal(receipt.reconciliation_required, true)
  assert.notEqual(receipt.started_at, null)
  assert.equal(validateContract('ExecutionReceipt', receipt), receipt)
}
function assertEvidence(ledger, requestId) {
  const job = ledger.lookup(requestId)
  assert.deepEqual(job.gateway_exit_evidence, evidence)
  assert.equal(job.receipt.exit_code, null)
  assert.equal(Object.hasOwn(job.receipt, 'gateway_exit_evidence'), false)
  return job
}
async function check(label, run) {
  if (process.argv[2] && process.argv[2] !== label) return
  await run()
  checks++
  console.log('PASS ' + label)
}

try {
  await check('exit124_full_rpc_is_unknown', async () => {
    // The same wire event represents either synthetic timeout or genuine124.
    // Timing or stdout cannot distinguish the two, so both stay unknown.
    const f = await make({ exit: 124, afterDelete: 3 }), r = request()
    const receipt = await f.executor.execute(r)
    assertUnknown(receipt)
    assert.equal(receipt.stdout, 'retained synthetic output')
    assert.equal(receipt.stderr, 'retained error')
    assertEvidence(f.ledger, r.request_id)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status, 'OUTCOME_UNKNOWN')
    assert.equal(count(f, 'exec'), 1)
    assert.equal(count(f, 'delete'), 1)
  })

  await check('exit124_lost_trailers_keep_raw_evidence', async () => {
    const f = await make({ exit: 124, trailerFailure: true }), r = request()
    const receipt = await f.executor.execute(r)
    assertUnknown(receipt, 'transport_failed')
    assert.equal(receipt.stdout, 'retained synthetic output')
    assertEvidence(f.ledger, r.request_id)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status, 'OUTCOME_UNKNOWN')
  })

  await check('exit124_recorded_cancel_full_rpc_stays_unknown', async () => {
    const controller = new AbortController(), f = await make({ exit: 124 })
    const original = f.transport.raw.execSandbox
    f.transport.raw.execSandbox = async function* (...args) {
      for await (const event of original(...args)) {
        yield event
        // Cancellation arrives after the terminal wire event but before the
        // RPC finishes; the mock then finishes its trailers successfully.
        if (event.payload.case === 'exit') controller.abort()
      }
    }
    const r = request({ signal: controller.signal }), receipt = await f.executor.execute(r)
    assertUnknown(receipt)
    const job = assertEvidence(f.ledger, r.request_id)
    assert.equal(job.cancel_state, 'recorded')
    assert.equal(f.executor.cancellationCause(r.request_id), 'caller')
    assert.equal(f.broker.read().calls.filter(([name]) => name === 'requestCancel').length, 1)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status, 'OUTCOME_UNKNOWN')
  })

  await check('exit124_late_cancel_after_rpc_preserves_complete', async () => {
    const controller = new AbortController(), f = await make({ exit: 124 })
    const original = f.transport.raw.deleteSandbox
    f.transport.raw.deleteSandbox = async (...args) => { controller.abort(); return original(...args) }
    const r = request({ signal: controller.signal }), receipt = await f.executor.execute(r)
    assertUnknown(receipt)
    assertEvidence(f.ledger, r.request_id)
    assert.equal(f.executor.cancellationCause(r.request_id), null)
    assert.equal(f.broker.read().calls.filter(([name]) => name === 'requestCancel').length, 0)
  })

  await check('exit124_bounded_output_and_replay_fence', async () => {
    const output = Buffer.from('bounded-output-'.repeat(100))
    const f = await make({ events: [
      { payload: { case: 'stdout', value: { data: output } } },
      { payload: { case: 'stderr', value: { data: Buffer.from('retained error') } } },
      { payload: { case: 'exit', value: { exitCode: 124 } } },
    ] }), r = request()
    const receipt = await f.executor.execute(r)
    assertUnknown(receipt)
    assert.equal(receipt.stdout, output.subarray(-r.max_output_bytes).toString('utf8'))
    assert.equal(receipt.stderr, 'retained error')
    assert.equal(receipt.output_truncated, true)
    await assert.rejects(f.executor.execute(r), error => error.code === 'RECONCILIATION_REQUIRED')
    await assert.rejects(f.executor.execute(request()), error => error.code === 'RECONCILIATION_REQUIRED')
    assert.equal(count(f, 'create'), 1)
    assert.equal(count(f, 'exec'), 1)
    assert.equal(f.broker.read().calls.filter(([name]) => name === 'claimDispatch').length, 1)
    assertEvidence(f.ledger, r.request_id)
  })

  await check('exit124_restart_cleanup_never_supplies_command_exit', async () => {
    const f = await make({ exit: 124, cleanupFailure: true }), r = request()
    const first = await f.executor.execute(r)
    assertUnknown(first, 'complete', 'unknown')
    assertEvidence(f.ledger, r.request_id)
    f.protocol.setCleanup(false)
    const { ledger, executor } = reopen(f)
    const [receipt] = await executor.reconcileOwned()
    assertUnknown(receipt)
    assert.equal(receipt.receipt_id, first.receipt_id)
    assert.equal(receipt.started_at, first.started_at)
    assert.equal(receipt.stdout, first.stdout)
    assert.equal(receipt.stderr, first.stderr)
    const job = assertEvidence(ledger, r.request_id)
    assert.equal(job.outbox.at(-1).state, 'acked')
    assert.equal(ledger.recovery().length, 1)
    await assert.rejects(executor.execute(r), error => error.code === 'RECONCILIATION_REQUIRED')
    assert.equal(count(f, 'create'), 1)
    assert.equal(count(f, 'exec'), 1)
    assert.equal(count(f, 'delete'), 1)
  })

  await check('exit124_settlement_refusal_preserves_pending_outbox', async () => {
    const f = await make({ exit: 124 }), r = request()
    const refuseSettlement = () => ({ ok: false, error_code: 'INVALID', reason: 'synthetic authority receipt refusal' })
    f.executor.broker.settle = refuseSettlement
    f.executor.broker.reconcileSettlement = refuseSettlement
    await assert.rejects(f.executor.execute(r), error => {
      assert.equal(error.code, 'RECONCILIATION_REQUIRED')
      assertUnknown(error.executionReceipt)
      assert.match(error.cause.message, /synthetic authority receipt refusal/)
      return true
    })
    const job = assertEvidence(f.ledger, r.request_id), originalReceipt = clone(job.outbox[0].receipt)
    assert.equal(job.outbox.length, 1)
    assert.equal(job.outbox[0].state, 'pending')
    assert.equal(validateContract('ExecutionReceipt', originalReceipt), originalReceipt)
    assert.equal(f.broker.read().rows[r.operation.operation_id].status, 'DISPATCHED')
    assert.equal(f.ledger.pending().length, 0)
    assert.equal(f.ledger.recovery().length, 1)
    const { ledger, executor } = reopen(f)
    executor.broker.settle = refuseSettlement
    executor.broker.reconcileSettlement = refuseSettlement
    await assert.rejects(executor.reconcileOwned(), error => error.code === 'RECONCILIATION_REQUIRED')
    const reopened = assertEvidence(ledger, r.request_id)
    assert.deepEqual(reopened.outbox[0].receipt, originalReceipt)
    assert.equal(reopened.outbox[0].state, 'pending')
    await assert.rejects(executor.execute(r), error => error.code === 'RECONCILIATION_REQUIRED')
    assert.equal(count(f, 'create'), 1)
    assert.equal(count(f, 'exec'), 1)
  })

  console.log(`PASS ${checks} scoped timeout protocol cases; runtime unavailable; C join unperformed`)
} finally {
  for (const ledger of ledgers) ledger.close()
  for (const root of roots) await rm(root, { recursive: true, force: true })
}
