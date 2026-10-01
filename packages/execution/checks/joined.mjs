// SPDX-License-Identifier: AGPL-3.0-or-later
// Actual C authority/kernel/store + F lifecycle; only the SDK protocol is mocked.
// Generated private keys live only in this process. No guest or live gateway runs.
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createAuthorityService, loginSigningBytes, approvalSigningBytes,
  executorRequestDigest as authorityRequestDigest,
  executionReceiptDigest as authorityReceiptDigest,
} from '../../authority/src/index.mjs'
import { didKeyFromEd25519PublicKey } from '../../authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs'
import { operationDigest } from '../../contracts/src/runtime.mjs'
import { OwnedLedger, executorRequestDigest, executionReceiptDigest } from '../src/index.mjs'
import { settings, request, fixture, MockedProtocolExecutor } from './harness.mjs'

const roots = [], ledgers = new Set()
let checks = 0
const clone = structuredClone
const accepted = value => {
  assert.equal(value.ok, true, JSON.stringify(value))
  return value
}
const rejected = (value, code) => {
  assert.equal(value.ok, false, JSON.stringify(value))
  if (code) assert.equal(value.error_code, code, JSON.stringify(value))
  return value
}
async function check(label, run) {
  await run()
  checks++
  console.log('PASS ' + label)
}

function authorityFixture() {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'prime-execution-joined-c-'))
  roots.push(root)
  const stateRoot = join(root, 'state')
  mkdirSync(stateRoot, { mode: 0o700 })
  const r = request()
  const keys = generateKeyPairSync('ed25519')
  const publicHex = Buffer.from(keys.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex')
  const identity = {
    owner_id: r.operation.owner_id,
    subject: 'aukora:1:' + '1'.repeat(64),
    approval_key_did: didKeyFromEd25519PublicKey(publicHex),
    control_digest: '2'.repeat(64),
    authorization_epoch: r.operation.authorization_epoch,
  }
  const task = Object.freeze({
    version: 1, task_id: r.operation.task_id, owner_id: r.operation.owner_id,
    agent_id: r.operation.agent_id, conversation_id: 'synthetic-conversation',
    status: 'running', created_at: new Date().toISOString(), route_id: null,
    allowed_data_classes: ['public'], max_input_tokens: 0, max_output_tokens: 0,
    max_requests: 0, task_spend_ceiling: { currency: 'USD', amount: '0' },
  })
  const target = clone(r.operation.target_identity)
  const config = {
    stateRoot, statePath: join(stateRoot, 'authority.json'), witnessDir: join(root, 'witness'),
    audience: r.operation.audience, identities: [identity], loginKinds: ['owner_key'],
    policy: { version: r.operation.policy_version, actions: ['shell.bash.foreground'],
      agents: [r.operation.agent_id], data_scope: ['public'], maximum_cost: { currency: 'USD', amount: '0' } },
    provisionTrustedState: true,
    authorizeTask: () => ({ authenticated: true, task }),
    observeTarget: () => ({ target_identity: clone(target), state_version: r.operation.expected_state_version }),
  }
  const service = createAuthorityService(config)
  const loginChallenge = accepted(service.loginChallenge({ owner_id: identity.owner_id, kind: 'owner_key' })).challenge
  const token = accepted(service.loginComplete({ challenge: loginChallenge,
    material: { kind: 'owner_key', signature: sign(null, loginSigningBytes(loginChallenge), keys.privateKey).toString('hex') } })).session_token
  accepted(service.propose(r.operation))
  const review = accepted(service.approvalChallenge({ session_token: token, operation: r.operation }))
  const proof = { ...review.proof_template, material: { kind: 'owner_key', request: review.approval_request,
    signature: sign(null, approvalSigningBytes(review.approval_request), keys.privateKey).toString('hex') } }
  accepted(service.approvalComplete({ session_token: token, proof }))
  const reserved = accepted(service.reserve({ operation: r.operation, approval_proof: proof }))
  assert.equal(reserved.status, 'PREPARED')
  r.consumed_grant = reserved.consumed_grant
  const durable = JSON.parse(readFileSync(config.statePath, 'utf8'))
  assert(durable.state.consumedIds.includes('approval:' + proof.nonce))
  assert(durable.prepared.some(p => p.consumptionId === 'approval:' + proof.nonce))
  return {
    root, config, service, r, token,
    status: (current = service) => accepted(current.status({ session_token: token, operation_id: r.operation.operation_id })),
    restart: () => createAuthorityService({ ...config, provisionTrustedState: false }),
    state: () => JSON.parse(readFileSync(config.statePath, 'utf8')),
  }
}

function tracedBroker(service, calls, hooks = {}) {
  return Object.fromEntries(['claimDispatch', 'requestCancel', 'settle', 'reconcileSettlement'].map(method => [method, async input => {
    const value = service[method](input)
    calls.push({ method, input: clone(input), value: clone(value) })
    await hooks[method]?.(value, input)
    return value
  }]))
}

async function joined(options = {}, hooks = {}) {
  const authority = authorityFixture(), calls = []
  const broker = tracedBroker(authority.service, calls, hooks)
  const f = await fixture(options, { broker })
  roots.push(f.root); ledgers.add(f.ledger)
  return { ...f, authority, calls, broker }
}
const count = (f, name) => f.protocol.calls.filter(([method]) => method === name).length
const claimBinding = r => ({ operation: r.operation, consumed_grant: r.consumed_grant,
  request_id: r.request_id, request_digest: executorRequestDigest(r) })
const settlementBinding = (r, receipt) => ({ ...claimBinding(r), receipt,
  receipt_digest: executionReceiptDigest(receipt) })
function closeLedger(ledger) { ledger.close(); ledgers.delete(ledger) }

try {
  await check('ordinary owner approval reaches real consumed kernel preparation and matching request/receipt digests', async () => {
    const f = await joined(), r = f.authority.r
    assert.equal(executorRequestDigest(r), authorityRequestDigest(r))
    assert.equal(executorRequestDigest({ ...r, signal: new AbortController().signal }), authorityRequestDigest(r))
    const receipt = await f.executor.execute(r)
    assert.equal(receipt.status, 'completed'); assert.equal(receipt.rpc_completion, 'complete')
    assert.equal(receipt.cleanup, 'confirmed_absent'); assert.equal(receipt.exit_code, 0)
    assert.equal(executionReceiptDigest(receipt), authorityReceiptDigest(receipt))
    assert.deepEqual(f.calls.map(c => c.method), ['claimDispatch', 'settle'])
    assert.equal(f.authority.status().status, 'COMPLETED')
    assert.equal(f.executor.availability().runtimeEnforcementVerified, false)
    assert.equal(f.executor.availability().protocol, 'mocked')
  })

  await check('altered operation or consumed grant cannot cross actual C dispatch into mocked SDK creation', async () => {
    const f = await joined(), altered = clone(f.authority.r)
    altered.operation.canonical_parameters.command = 'different synthetic inert command'
    await assert.rejects(f.executor.execute(altered), e => e.code === 'UNAUTHORIZED')
    assert.equal(f.calls.length, 0)
    // Keeping a syntactically consistent new digest cannot change C's original review.
    altered.consumed_grant.operation_digest = operationDigest(altered.operation)
    await assert.rejects(f.executor.execute(altered), e => ['TARGET_MISMATCH', 'INVALID'].includes(e.code))
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0].method, 'claimDispatch')
    assert.equal(f.calls[0].value.ok, false); assert.equal(f.authority.status().status, 'PREPARED')
    assert.equal(count(f, 'create'), 0); assert.equal(count(f, 'exec'), 0)

    const g = await joined(), changedGrant = clone(g.authority.r)
    changedGrant.consumed_grant.prepared_at = new Date(Date.now() - 10_000).toISOString()
    await assert.rejects(g.executor.execute(changedGrant), e => e.code === 'UNAUTHORIZED')
    assert.equal(g.calls[0].value.reason, 'EXACT_CONSUMED_GRANT_REQUIRED')
    assert.equal(g.authority.status().status, 'PREPARED'); assert.equal(count(g, 'create'), 0)
  })

  await check('actual one-use dispatch and exit 1 settlement survive a fresh F ledger without a second launch', async () => {
    const f = await joined({ exit: 1 }), r = f.authority.r
    const receipt = await f.executor.execute(r)
    assert.equal(receipt.status, 'failed'); assert.equal(receipt.exit_code, 1)
    assert.equal(receipt.stdout, 'retained synthetic output'); assert.equal(f.authority.status().status, 'FAILED')
    rejected(f.authority.service.claimDispatch(claimBinding(r)), 'REPLAYED')
    const duplicate = accepted(f.authority.service.settle(settlementBinding(r, receipt)))
    assert.equal(duplicate.idempotent, true); assert.equal(duplicate.status, 'FAILED')
    await assert.rejects(f.executor.execute(r), e => e.code === 'REPLAYED')
    assert.equal(count(f, 'exec'), 1)

    const fresh = await fixture({}, { broker: tracedBroker(f.authority.restart(), f.calls) })
    roots.push(fresh.root); ledgers.add(fresh.ledger)
    await assert.rejects(fresh.executor.execute(r), e => e.code === 'REPLAYED')
    assert.equal(count(fresh, 'create'), 0); assert.equal(count(fresh, 'exec'), 0)
    assert.equal(f.authority.state().prepared.length, 1)
  })

  await check('lost durable settlement reply is replayed idempotently after C/F restart without launching again', async () => {
    let lost = false
    const f = await joined({}, { settle: value => {
      assert.equal(value.ok, true)
      if (!lost) { lost = true; throw new Error('synthetic settlement reply loss after durable C commit') }
    } }), r = f.authority.r
    await assert.rejects(f.executor.execute(r), e => e.code === 'RECONCILIATION_REQUIRED' && e.executionReceipt?.status === 'completed')
    const prior = f.ledger.lookup(r.request_id)
    assert.equal(prior.outbox[0].state, 'pending'); assert.equal(f.authority.status().status, 'COMPLETED')
    closeLedger(f.ledger)
    const ledger = new OwnedLedger(f.root); ledgers.add(ledger)
    const restartedC = f.authority.restart()
    const executor = new MockedProtocolExecutor({ settings, transport: f.transport, ledger,
      broker: tracedBroker(restartedC, f.calls) })
    const receipts = await executor.reconcileOwned()
    assert.equal(receipts.length, 1)
    assert.deepEqual(receipts[0], prior.outbox[0].receipt)
    assert.equal(ledger.lookup(r.request_id).outbox[0].state, 'acked')
    assert.equal(ledger.recovery().length, 0)
    const settlements = f.calls.filter(c => c.method === 'settle')
    assert.equal(settlements.length, 2); assert.equal(settlements[1].value.idempotent, true)
    assert.equal(settlements[0].input.receipt_digest, settlements[1].input.receipt_digest)
    assert.equal(f.calls.filter(c => c.method === 'claimDispatch').length, 1)
    assert.equal(count(f, 'create'), 1); assert.equal(count(f, 'exec'), 1)
    assert.equal(f.authority.status(restartedC).status, 'COMPLETED')
  })

  await check('lost claim reply keeps the real consumed dispatch fenced and settles uncertainty without any launch', async () => {
    const f = await joined({}, { claimDispatch: value => {
      assert.equal(value.ok, true)
      throw new Error('synthetic claim reply loss after durable C dispatch')
    } }), r = f.authority.r
    const receipt = await f.executor.execute(r)
    assert.equal(receipt.status, 'outcome_unknown'); assert.equal(receipt.cleanup, 'not_created')
    assert.equal(receipt.rpc_completion, 'not_started'); assert.equal(receipt.started_at, null)
    assert.equal(f.authority.status().status, 'OUTCOME_UNKNOWN')
    assert.equal(count(f, 'create'), 0)
    const reconciled = await f.executor.reconcileOwned()
    assert.equal(reconciled[0].status, 'outcome_unknown')
    await assert.rejects(f.executor.execute(request()), e => e.code === 'RECONCILIATION_REQUIRED')
    assert.equal(f.calls.filter(c => c.method === 'claimDispatch').length, 1)
    rejected(f.authority.service.claimDispatch(claimBinding(r)), 'REPLAYED')
    assert.equal(f.authority.state().prepared.length, 1)
  })

  await check('typed exit with lost RPC trailers remains actual C OUTCOME_UNKNOWN after confirmed cleanup and reconciliation', async () => {
    const f = await joined({ exit: 1, trailerFailure: true }), r = f.authority.r
    const receipt = await f.executor.execute(r)
    assert.equal(receipt.exit_code, 1); assert.equal(receipt.stdout, 'retained synthetic output')
    assert.equal(receipt.status, 'outcome_unknown'); assert.equal(receipt.rpc_completion, 'transport_failed')
    assert.equal(receipt.cleanup, 'confirmed_absent'); assert.equal(f.authority.status().status, 'OUTCOME_UNKNOWN')
    const [reconciled] = await f.executor.reconcileOwned()
    assert.equal(reconciled.receipt_id, receipt.receipt_id)
    assert.equal(reconciled.exit_code, 1); assert.equal(reconciled.stdout, receipt.stdout)
    assert.equal(reconciled.status, 'outcome_unknown'); assert.equal(count(f, 'exec'), 1)
    await assert.rejects(f.executor.execute(request()), e => e.code === 'RECONCILIATION_REQUIRED')
    assert.equal(f.calls.filter(c => c.method === 'claimDispatch').length, 1)
    assert.equal(f.authority.status().status, 'OUTCOME_UNKNOWN')
  })

  await check('confirmed cleanup promotes drained typed completion through actual C reconciliation without exec replay', async () => {
    const f = await joined({ cleanupFailure: true }), r = f.authority.r
    const initial = await f.executor.execute(r)
    assert.equal(initial.status, 'outcome_unknown'); assert.equal(initial.cleanup, 'unknown')
    assert.equal(initial.rpc_completion, 'complete'); assert.equal(initial.exit_code, 0)
    assert.equal(initial.stdout, 'retained synthetic output')
    assert.equal(f.authority.status().status, 'OUTCOME_UNKNOWN')
    const firstDigest = executionReceiptDigest(initial)
    f.protocol.setCleanup(false)
    const [receipt] = await f.executor.reconcileOwned()
    assert.equal(receipt.status, 'completed'); assert.equal(receipt.cleanup, 'confirmed_absent')
    assert.equal(receipt.reconciliation_required, false); assert.equal(receipt.receipt_id, initial.receipt_id)
    assert.equal(receipt.started_at, initial.started_at); assert.equal(receipt.exit_code, initial.exit_code)
    assert.equal(receipt.stdout, initial.stdout); assert.equal(receipt.stderr, initial.stderr)
    assert.deepEqual(receipt.sandbox, initial.sandbox)
    assert.notEqual(executionReceiptDigest(receipt), firstDigest)
    assert.equal(f.authority.status().status, 'COMPLETED')
    assert.deepEqual(f.calls.map(c => c.method), ['claimDispatch', 'settle', 'reconcileSettlement'])
    const reconciliation = f.calls.at(-1)
    assert.equal(reconciliation.input.receipt_digest, executionReceiptDigest(receipt))
    assert.equal(reconciliation.value.idempotent, false); assert.equal(reconciliation.value.status, 'COMPLETED')
    assert.equal(f.ledger.recovery().length, 0); assert.equal(count(f, 'create'), 1); assert.equal(count(f, 'exec'), 1)
    assert.equal(f.authority.state().prepared.length, 1)
  })

  await check('cancellation after creation but before exec settles actual C CANCELLED only after observed owned absence', async () => {
    const controller = new AbortController()
    const f = await joined({ afterCreate: () => controller.abort() }), r = { ...f.authority.r, signal: controller.signal }
    const receipt = await f.executor.execute(r)
    assert.equal(count(f, 'create'), 1); assert.equal(count(f, 'exec'), 0)
    assert.equal(count(f, 'delete'), 1); assert.equal(f.protocol.getSandbox(), null)
    assert.equal(receipt.status, 'cancelled'); assert.equal(receipt.cleanup, 'confirmed_absent')
    assert.equal(receipt.rpc_completion, 'not_started'); assert.equal(receipt.started_at, null); assert.equal(receipt.exit_code, null)
    assert.equal(receipt.stdout, ''); assert.equal(receipt.stderr, ''); assert.equal(receipt.reconciliation_required, false)
    assert.equal(f.executor.cancellationCause(r.request_id), 'caller')
    const cancellation = f.calls.find(c => c.method === 'requestCancel')
    assert.equal(cancellation.value.cancel_recorded, true); assert.equal(cancellation.value.status, 'CANCEL_REQUESTED')
    assert.equal(f.calls.at(-1).method, 'settle'); assert.equal(f.calls.at(-1).value.status, 'CANCELLED')
    assert.equal(f.authority.status().status, 'CANCELLED'); assert.equal(f.authority.state().prepared.length, 1)
    assert.equal(f.ledger.recovery().length, 0)
  })

  await check('recorded cancellation after launch retains consumed grant and unknown outcome; late cancellation preserves completion', async () => {
    const f = await joined({ waitAbort: true }), controller = new AbortController()
    const r = { ...f.authority.r, signal: controller.signal }, running = f.executor.execute(r)
    while (!count(f, 'exec')) await new Promise(resolve => setImmediate(resolve))
    controller.abort()
    const receipt = await running
    assert.equal(receipt.status, 'outcome_unknown'); assert.equal(receipt.cleanup, 'confirmed_absent')
    assert.equal(receipt.rpc_completion, 'transport_failed'); assert.equal(receipt.exit_code, null)
    assert.equal(f.executor.cancellationCause(r.request_id), 'caller')
    const cancel = f.calls.find(c => c.method === 'requestCancel')
    assert.equal(cancel.value.cancel_recorded, true); assert.equal(cancel.value.status, 'CANCEL_REQUESTED')
    assert.equal(f.authority.status().status, 'OUTCOME_UNKNOWN'); assert.equal(f.authority.state().prepared.length, 1)

    const g = await joined(), completed = await g.executor.execute(g.authority.r)
    const late = accepted(g.authority.service.requestCancel({ operation: g.authority.r.operation,
      consumed_grant: g.authority.r.consumed_grant, request_id: g.authority.r.request_id, reason: 'caller' }))
    assert.equal(late.cancel_recorded, false); assert.equal(late.status, 'COMPLETED')
    assert.equal(completed.status, 'completed'); assert.equal(g.authority.status().status, 'COMPLETED')
  })

  console.log(JSON.stringify({ status: 'PASS', checks,
    scope: 'actual C approval/kernel/store and F lifecycle/settlement; mocked SDK only',
    limits: ['no real gateway or guest', 'no runtime enforcement qualification', 'same-UID disposable state',
      'in-process synthetic owner-key only; no enrollment or signing keys passed to F'] }))
} finally {
  for (const ledger of ledgers) { try { ledger.close() } catch {} }
  for (const root of roots) rmSync(root, { recursive: true, force: true })
}
