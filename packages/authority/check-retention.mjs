#!/usr/bin/env node
// Focused signed retention regression. Only disposable synthetic stores and keys are used.
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalJson } from '../contracts/src/runtime.mjs'
import { createAuthorityService, provisionNewAuthorityStore, loginSigningBytes, approvalSigningBytes, operationDigest, memoryResultDigest, memoryEffectReceiptDigest, executionReceiptDigest, executorRequestDigest } from './src/index.mjs'
import { PrimeApprovalStateStore } from './src/state-store.mjs'
import { memoryEffectReceipt } from './src/memory-effect.mjs'
import { validatedReceipt } from './src/execution.mjs'
import { validateTerminalRecord } from './src/retention.mjs'
import { ApprovalStateStore } from './upstream/scripts/aukora/approval-state-store.mjs'
import { TrustedStateStore } from './upstream/scripts/aukora/trusted-state-store.mjs'
import { didKeyFromEd25519PublicKey } from './upstream/plugins/aukora-aumlok/lib/did-key.mjs'

const hash = value => createHash('sha256').update(value).digest('hex')
const digest = (domain, value) => 'sha256:' + hash(domain + '\0' + canonicalJson(value))
const operationKey = op => hash(canonicalJson([op.owner_id, op.operation_id]))
const IMAGE = 'sha256:' + 'a'.repeat(64), POLICY = 'sha256:' + 'b'.repeat(64)

export function runRetentionChecks() {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'prime-retention-'))
  let checks = 0, lifecycles = 0
  const check = (condition, message) => { assert(condition, message); checks++ }
  const same = (actual, expected, message) => { assert.deepEqual(actual, expected, message); checks++ }
  const ok = result => { check(result.ok === true, JSON.stringify(result)); return result }
  const no = (result, code) => { check(result.ok === false, JSON.stringify(result)); if (code) same(result.error_code, code, JSON.stringify(result)); return result }
  const owners = [1, 2].map(n => {
    const keys = generateKeyPairSync('ed25519')
    const raw = Buffer.from(keys.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex')
    return { keys, identity: { owner_id: 'retention-owner-' + n, subject: 'aukora:1:' + String(n).repeat(64), approval_key_did: didKeyFromEd25519PublicKey(raw), control_digest: String(n + 2).repeat(64), authorization_epoch: 0 } }
  })
  function fixture(name) {
    const dir = join(root, name), state = join(dir, 'state')
    mkdirSync(dir, { mode: 0o700 }); mkdirSync(state, { mode: 0o700 })
    const config = {
      statePath: join(state, 'authority.json'), stateRoot: state, witnessDir: join(dir, 'witness'),
      audience: 'prime:retention-fixture', identities: owners.map(x => x.identity), loginKinds: ['owner_key'], provisionTrustedState: true,
      policy: { version: 'retention-v1', actions: ['memory.save', 'memory.erase', 'sandbox.execute'], agents: ['retention-agent'], data_scope: ['public'], maximum_cost: { currency: 'USD', amount: '0' } },
      authorizeTask: op => ({ authenticated: true, task: { version: 1, task_id: 'retention-task', owner_id: op.owner_id, agent_id: 'retention-agent', conversation_id: 'retention-conversation', status: 'running', created_at: new Date().toISOString(), route_id: null, allowed_data_classes: ['public'], max_input_tokens: 0, max_output_tokens: 0, max_requests: 0, task_spend_ceiling: { currency: 'USD', amount: '0' } } }),
      observeTarget: op => ({ target_identity: op.target_identity, state_version: 'retention-r1' }),
    }
    ok(provisionNewAuthorityStore(config))
    return { config, service: createAuthorityService(config) }
  }
  function login(service, owner = owners[0]) {
    const challenge = ok(service.loginChallenge({ owner_id: owner.identity.owner_id, kind: 'owner_key' })).challenge
    return ok(service.loginComplete({ challenge, material: { kind: 'owner_key', signature: sign(null, loginSigningBytes(challenge), owner.keys.privateKey).toString('hex') } })).session_token
  }
  function operation(id, statement, extra = {}) {
    return { version: 1, operation_id: id, task_id: 'retention-task', owner_id: owners[0].identity.owner_id, agent_id: 'retention-agent', audience: 'prime:retention-fixture', action_type: 'memory.save', target_identity: { kind: 'prime-memory', owner_subject: owners[0].identity.subject }, canonical_parameters: { statement }, data_scope: ['public'], expected_state_version: 'retention-r1', provider_and_region: { provider: 'none', region: 'local' }, maximum_cost: { currency: 'USD', amount: '0' }, expiry: new Date(Date.now() + 600000).toISOString(), nonce: randomBytes(32).toString('hex'), policy_version: 'retention-v1', authorization_epoch: 0, ...extra }
  }
  function prepare(f, token, op) {
    ok(f.service.propose({ session_token: token, operation: op }))
    const review = ok(f.service.approvalChallenge({ session_token: token, operation: op }))
    const proof = { ...review.proof_template, material: { kind: 'owner_key', request: review.approval_request, signature: sign(null, approvalSigningBytes(review.approval_request), owners[0].keys.privateKey).toString('hex') } }
    ok(f.service.approvalComplete({ session_token: token, proof }))
    const grant = ok(f.service.reserve({ operation: op, approval_proof: proof })).consumed_grant
    lifecycles++
    check(read(f).state.consumedIds.includes('approval:' + proof.nonce), 'signed lifecycle did not consume its approval')
    return { operation: op, grant, proof }
  }
  function binding(p, kind = 'memory') {
    const request_id = randomUUID(), op = p.operation
    const request_digest = kind === 'memory'
      ? digest('aukora-prime.memory.effect.v1', { version: 1, action_type: op.action_type, owner_subject: op.target_identity.owner_subject, operation_id: op.operation_id, operation_digest: operationDigest(op), parameters: op.canonical_parameters })
      : executorRequestDigest({ operation: op, consumed_grant: p.grant, request_id, image_digest: IMAGE, policy_digest: POLICY, wall_time_ms: 1000, max_output_bytes: 1048576 })
    return { operation: op, consumed_grant: p.grant, request_id, request_digest }
  }
  function memoryReceipt(b, result) {
    return { version: 1, kind: 'prime-memory-effect/v1', operation_id: b.operation.operation_id, operation_digest: operationDigest(b.operation), grant_id: b.consumed_grant.grant_id, request_id: b.request_id, request_digest: b.request_digest, owner_subject: b.operation.target_identity.owner_subject, action_type: b.operation.action_type, status: 'applied', result_digest: memoryResultDigest(result), result }
  }
  function executionReceipt(b, extra = {}) {
    const stamp = new Date().toISOString(), sandboxUid = randomUUID()
    return { version: 1, receipt_id: randomUUID(), operation_id: b.operation.operation_id, task_id: b.operation.task_id, owner_id: b.operation.owner_id, operation_digest: operationDigest(b.operation), grant_id: b.consumed_grant.grant_id, request_id: b.request_id, status: 'completed', stdout: '', stderr: '', exit_code: 0, rpc_completion: 'complete', output_truncated: false, sandbox: { uid: sandboxUid, name: 'retention-fixture', identity: 'retention-sandbox/' + sandboxUid, image_digest: IMAGE, policy_digest: POLICY }, cleanup: 'confirmed_absent', started_at: stamp, finished_at: stamp, error_code: null, reconciliation_required: false, ...extra }
  }
  const executionInput = (b, receipt) => ({ ...b, receipt, receipt_digest: executionReceiptDigest(receipt) })
  const read = f => JSON.parse(readFileSync(f.config.statePath, 'utf8'))
  const witnessPath = f => join(f.config.witnessDir, 'kernel-high-water.json')
  const kernel = record => ({ state: record.state, prepared: record.prepared })
  const row = (f, b) => read(f).broker.operations[operationKey(b.operation)]
  function unchanged(f, body, message) {
    const state = readFileSync(f.config.statePath), witness = readFileSync(witnessPath(f))
    const result = body()
    check(readFileSync(f.config.statePath).equals(state), message + ': state changed')
    check(readFileSync(witnessPath(f)).equals(witness), message + ': witness changed')
    return result
  }
  function compact(f, b, receipt, kind, expectedDigests) {
    const retained = row(f, b), expectedReceiptDigest = kind === 'memory' ? memoryEffectReceiptDigest(receipt) : executionReceiptDigest(receipt)
    same(Object.keys(retained).sort(), ['dispatch', 'grant_digest', 'operation_digest', 'owner_key', 'schema', 'status'], 'terminal row is not closed')
    same(Object.keys(retained.dispatch).sort(), ['evidence_kind', 'receipt_digest', 'request_digest', 'request_id', 'result_digest', 'settlement_digests'], 'terminal dispatch is not closed')
    same(retained.schema, 'prime-terminal-operation-v1', 'terminal schema')
    same(retained.owner_key, hash(b.operation.owner_id), 'owner binding digest')
    same(retained.operation_digest, operationDigest(b.operation), 'operation digest')
    same(retained.grant_digest, digest('aukora-prime.consumed-grant.v1', b.consumed_grant), 'grant domain digest')
    same(retained.dispatch, { request_id: b.request_id, request_digest: b.request_digest, receipt_digest: expectedReceiptDigest, settlement_digests: expectedDigests ?? [expectedReceiptDigest], evidence_kind: kind, result_digest: kind === 'memory' ? receipt.result_digest : null }, 'bounded evidence binding')
    check(retained.dispatch.settlement_digests.length >= 1 && retained.dispatch.settlement_digests.length <= 32, 'evidence digest quota')
    check(Buffer.byteLength(JSON.stringify(retained)) < 1400, 'terminal row size depends on payload bytes')
    return retained
  }
  function captureCommits(body) {
    const original = TrustedStateStore.prototype.commit, records = []
    TrustedStateStore.prototype.commit = function (record) { records.push(structuredClone(record)); return original.call(this, record) }
    try { return { result: body(), records } } finally { TrustedStateStore.prototype.commit = original }
  }
  function seedLegacy(f, entries) {
    // Only recreate the legacy shape from genuine captured dispatch and accepted receipts.
    // This explicit fixture bypass keeps original journal/witness durability, not Prime compaction.
    const store = new PrimeApprovalStateStore(f.config)
    try {
      store.open(); store.load()
      const broker = structuredClone(store.broker)
      for (const entry of entries) {
        const legacy = structuredClone(entry.captured)
        legacy.status = entry.accepted.status
        legacy.dispatch.receipt = entry.kind === 'memory' ? memoryEffectReceipt(entry.receipt) : validatedReceipt(entry.receipt)
        legacy.dispatch.receipt_digest = entry.accepted.receipt_digest
        legacy.dispatch.settlement_digests.push(entry.accepted.receipt_digest)
        broker.operations[operationKey(entry.b.operation)] = legacy
      }
      broker.revision++
      check(Number.isSafeInteger(broker.revision), 'legacy fixture revision overflow')
      const next = { ...store.currentRecord, broker }
      ApprovalStateStore.prototype.commit.call(store, next)
      store.retainBrokerRevision(broker.revision)
      store.broker = broker; store.currentRecord = next
    } finally { store.close() }
  }
  try {
    const memory = fixture('memory'), token = login(memory.service), crossToken = login(memory.service, owners[1]), saves = []
    for (let n = 0; n < 8; n++) {
      const statement = 'RETENTION_STATEMENT_' + n + '_' + 's'.repeat(n === 1 ? 12000 : 64)
      const resultText = 'RETENTION_RESULT_' + n + '_' + 'r'.repeat(n === 1 ? 16000 : 64)
      const p = prepare(memory, token, operation('memory-' + n, statement, n === 7 ? { action_type: 'memory.erase' } : {})), b = binding(p)
      ok(memory.service.claimDispatch(b))
      const before = read(memory), receipt = memoryReceipt(b, { storage_status: n === 7 ? 'erased' : 'saved', revision: 'retention-r' + (n + 2), statement: resultText })
      const captured = captureCommits(() => ok(memory.service.settleMemory({ ...b, receipt })))
      same(captured.result.status, 'COMPLETED', 'memory terminal status')
      same(captured.records.length, 1, 'terminal settlement must use one state commit')
      same(captured.records[0].broker.operations[operationKey(b.operation)].schema, 'prime-terminal-operation-v1', 'plaintext terminal reached durable commit')
      compact(memory, b, receipt, 'memory')
      same(kernel(read(memory)), kernel(before), 'memory settlement changed kernel history')
      const persisted = readFileSync(memory.config.statePath, 'utf8')
      check(!persisted.includes(statement) && !persisted.includes(resultText), 'settled statement/result persisted')
      saves.push({ p, b, receipt })
    }
    const first = saves[0], reopenedMemory = createAuthorityService(memory.config)
    const validTerminal = row(memory, first.b)
    for (const path of [
      ['schema'], ['owner_key'], ['operation_digest'], ['status'], ['grant_digest'],
      ['dispatch', 'request_id'], ['dispatch', 'request_digest'], ['dispatch', 'receipt_digest'],
      ['dispatch', 'evidence_kind'], ['dispatch', 'result_digest'],
    ]) {
      const malformed = structuredClone(validTerminal), target = path.length === 1 ? malformed : malformed.dispatch, field = path.at(-1)
      target[field] = [target[field]]
      assert.throws(() => validateTerminalRecord(malformed), TypeError, 'array coerced into compact scalar: ' + path.join('.')); checks++
    }
    for (const mutate of [
      r => { r.dispatch.settlement_digests[0] = [r.dispatch.settlement_digests[0]] },
      r => { r.dispatch.settlement_digests = [] },
      r => { r.dispatch.settlement_digests.push(r.dispatch.receipt_digest) },
      r => { r.dispatch.settlement_digests = Array.from({ length: 33 }, (_, n) => digest('retention-evidence-fixture', n)); r.dispatch.receipt_digest = r.dispatch.settlement_digests[0] },
      r => { r.dispatch.receipt_digest = 'sha256:' + '0'.repeat(64) },
      r => { r.status = 'OUTCOME_UNKNOWN' },
      r => { r.operation = first.b.operation },
      r => { r.dispatch.receipt = first.receipt },
    ]) {
      const malformed = structuredClone(validTerminal); mutate(malformed)
      assert.throws(() => validateTerminalRecord(malformed), TypeError, 'malformed compact evidence accepted'); checks++
    }
    unchanged(memory, () => same(ok(reopenedMemory.settleMemory({ ...first.b, receipt: first.receipt })).idempotent, true), 'reopened memory duplicate')
    unchanged(memory, () => same(ok(reopenedMemory.status({ session_token: token, operation_id: first.b.operation.operation_id })).status, 'COMPLETED'), 'compact owner status')
    unchanged(memory, () => no(reopenedMemory.status({ session_token: crossToken, operation_id: first.b.operation.operation_id }), 'UNAUTHORIZED'), 'cross-owner compact status')
    unchanged(memory, () => no(reopenedMemory.propose({ session_token: token, operation: first.b.operation }), 'REPLAYED'), 'operation ID replay')
    unchanged(memory, () => no(reopenedMemory.reserve({ operation: first.b.operation, approval_proof: first.p.proof }), 'REPLAYED'), 'consumed grant replay')
    unchanged(memory, () => no(reopenedMemory.claimDispatch(first.b), 'REPLAYED'), 'terminal dispatch replay')
    for (const input of [
      { ...first.b, operation: { ...first.b.operation, canonical_parameters: { statement: 'changed statement' } } },
      { ...first.b, consumed_grant: { ...first.b.consumed_grant, prepared_at: '2000-01-01T00:00:00.000Z' } },
      { ...first.b, request_id: randomUUID() },
      { ...first.b, request_digest: 'sha256:' + '0'.repeat(64) },
    ]) unchanged(memory, () => no(reopenedMemory.settleMemory({ ...input, receipt: first.receipt }), input.operation !== first.b.operation ? 'INVALID' : 'UNAUTHORIZED'), 'changed terminal binding')
    const changedMemory = memoryReceipt(first.b, { storage_status: 'saved', revision: 'different-result' })
    unchanged(memory, () => no(reopenedMemory.settleMemory({ ...first.b, receipt: changedMemory }), 'STALE'), 'changed committed memory evidence')
    same(read(memory).state.consumedIds.length, 8, 'memory history count')
    same(read(memory).prepared.length, 8, 'memory preparation count')
    same(Object.keys(read(memory).broker.operations).length, 8, 'terminal operation history count')

    const execution = fixture('execution'), executionToken = login(execution.service)
    for (const expected of ['COMPLETED', 'FAILED', 'CANCELLED', 'UNAVAILABLE']) {
      const statement = 'RETENTION_EXECUTION_STATEMENT_' + expected
      const p = prepare(execution, executionToken, operation('execution-' + expected, statement, { action_type: 'sandbox.execute', target_identity: { kind: 'sandbox', image_digest: IMAGE, policy_digest: POLICY } })), b = binding(p, 'execution')
      ok(execution.service.claimDispatch(b))
      let receipt = executionReceipt(b, { stdout: 'RETENTION_STDOUT_' + expected + '_' + 'o'.repeat(18000), stderr: 'RETENTION_STDERR_' + expected })
      if (expected === 'FAILED') receipt = { ...receipt, status: 'failed', exit_code: 9 }
      if (['CANCELLED', 'UNAVAILABLE'].includes(expected)) {
        receipt = { ...receipt, status: expected.toLowerCase(), stdout: '', stderr: '', exit_code: null, rpc_completion: 'not_started', sandbox: null, cleanup: 'not_created', started_at: null, error_code: expected }
        if (expected === 'CANCELLED') ok(execution.service.requestCancel({ operation: b.operation, consumed_grant: b.consumed_grant, request_id: b.request_id, reason: 'caller' }))
      }
      const before = read(execution), input = executionInput(b, receipt), captured = captureCommits(() => ok(execution.service.settle(input)))
      same(captured.result.status, expected, 'execution terminal status')
      same(captured.records.length, 1, 'execution terminal commit count')
      same(captured.records[0].broker.operations[operationKey(b.operation)].schema, 'prime-terminal-operation-v1', 'full execution receipt reached durable terminal commit')
      compact(execution, b, receipt, 'execution')
      same(kernel(read(execution)), kernel(before), 'execution settlement changed kernel history')
      const persisted = readFileSync(execution.config.statePath, 'utf8')
      check(!persisted.includes(statement) && !persisted.includes('RETENTION_STDOUT_' + expected) && !persisted.includes('RETENTION_STDERR_' + expected), 'terminal execution payload persisted')
      const reopened = createAuthorityService(execution.config)
      unchanged(execution, () => same(ok(reopened.settle(input)).idempotent, true), 'reopened execution duplicate')
      unchanged(execution, () => no(reopened.reconcileSettlement(executionInput(b, { ...receipt, finished_at: '2099-01-01T00:00:00.000Z' })), 'STALE'), 'changed terminal execution evidence')
      unchanged(execution, () => same(ok(reopened.requestCancel({ operation: b.operation, consumed_grant: b.consumed_grant, request_id: b.request_id, reason: 'dispose' })).cancel_recorded, false), 'terminal cancellation')
      unchanged(execution, () => same(ok(reopened.markOutcomeUnknown(b)).status, expected), 'terminal outcome fence')
    }

    const unknown = fixture('unknown'), unknownToken = login(unknown.service)
    const obligation = prepare(unknown, unknownToken, operation('prepared-obligation', 'RETENTION_PREPARED_STATEMENT'))
    const up = prepare(unknown, unknownToken, operation('unknown-execution', 'RETENTION_UNKNOWN_STATEMENT', { action_type: 'sandbox.execute', target_identity: { kind: 'sandbox', image_digest: IMAGE, policy_digest: POLICY } })), ub = binding(up, 'execution')
    ok(unknown.service.claimDispatch(ub))
    const uncertain = executionReceipt(ub, { status: 'outcome_unknown', stdout: 'RETENTION_UNKNOWN_STDOUT', stderr: 'RETENTION_UNKNOWN_STDERR', exit_code: null, rpc_completion: 'transport_failed', cleanup: 'unknown', error_code: 'OUTCOME_UNKNOWN', reconciliation_required: true })
    same(ok(unknown.service.settle(executionInput(ub, uncertain))).status, 'OUTCOME_UNKNOWN')
    check(!row(unknown, ub).schema && row(unknown, ub).operation.canonical_parameters.statement === 'RETENTION_UNKNOWN_STATEMENT', 'unknown operation was compacted')
    same(row(unknown, ub).dispatch.receipt, uncertain, 'unknown evidence was discarded')
    const certain = { ...uncertain, status: 'completed', exit_code: 0, rpc_completion: 'complete', cleanup: 'confirmed_absent', error_code: null, reconciliation_required: false }
    unchanged(unknown, () => no(unknown.service.settle(executionInput(ub, certain)), 'STALE'), 'unknown requires explicit reconciliation')
    unchanged(unknown, () => no(unknown.service.reconcileSettlement(executionInput(ub, { ...certain, stdout: 'conflicting prior output' })), 'INVALID'), 'unknown conflicting output')
    ok(unknown.service.requestCancel({ operation: ub.operation, consumed_grant: ub.consumed_grant, request_id: ub.request_id, reason: 'timeout' }))
    same(row(unknown, ub).status, 'CANCEL_REQUESTED')
    check(!row(unknown, ub).schema && row(unknown, ub).dispatch.receipt.stdout === uncertain.stdout, 'cancel-requested evidence was compacted')
    const beforeReconcile = read(unknown)
    same(ok(unknown.service.reconcileSettlement(executionInput(ub, certain))).status, 'COMPLETED')
    compact(unknown, ub, certain, 'execution', [executionReceiptDigest(uncertain), executionReceiptDigest(certain)])
    same(kernel(read(unknown)), kernel(beforeReconcile), 'reconciliation changed kernel history')
    const persistedUnknown = readFileSync(unknown.config.statePath, 'utf8')
    check(!persistedUnknown.includes('RETENTION_UNKNOWN_STATEMENT') && !persistedUnknown.includes('RETENTION_UNKNOWN_STDOUT') && !persistedUnknown.includes('RETENTION_UNKNOWN_STDERR'), 'reconciled payload persisted')
    unchanged(unknown, () => {
      const duplicate = ok(createAuthorityService(unknown.config).settle(executionInput(ub, uncertain)))
      same(duplicate.idempotent, true); same(duplicate.status, 'COMPLETED'); same(duplicate.receipt_digest, executionReceiptDigest(certain))
    }, 'prior unknown evidence duplicate after terminal reconciliation')
    const preparedRow = read(unknown).broker.operations[operationKey(obligation.operation)]
    same(preparedRow.status, 'PREPARED'); check(!preparedRow.schema && preparedRow.operation && preparedRow.approval && preparedRow.grant, 'prepared obligation was compacted')

    const legacy = fixture('legacy'), legacyToken = login(legacy.service), legacyEntries = []
    for (const kind of ['memory', 'execution']) {
      const op = operation('legacy-' + kind, 'RETENTION_LEGACY_STATEMENT_' + kind, kind === 'execution' ? { action_type: 'sandbox.execute', target_identity: { kind: 'sandbox', image_digest: IMAGE, policy_digest: POLICY } } : {})
      const p = prepare(legacy, legacyToken, op), b = binding(p, kind)
      ok(legacy.service.claimDispatch(b))
      const captured = structuredClone(row(legacy, b)), receipt = kind === 'memory' ? memoryReceipt(b, { storage_status: 'saved', statement: 'RETENTION_LEGACY_RESULT' }) : executionReceipt(b, { stdout: 'RETENTION_LEGACY_STDOUT', stderr: 'RETENTION_LEGACY_STDERR' })
      const accepted = kind === 'memory' ? ok(legacy.service.settleMemory({ ...b, receipt })) : ok(legacy.service.settle(executionInput(b, receipt)))
      legacyEntries.push({ kind, b, captured, receipt, accepted })
    }
    const genuineKernel = kernel(read(legacy))
    seedLegacy(legacy, legacyEntries)
    same(kernel(read(legacy)), genuineKernel, 'legacy fixture altered genuine kernel history')
    check(legacyEntries.every(entry => row(legacy, entry.b).operation && row(legacy, entry.b).dispatch.receipt), 'legacy fixture did not retain original full terminal shape')
    const beforeMigration = readFileSync(legacy.config.statePath), oldRecord = read(legacy), oldWitness = JSON.parse(readFileSync(witnessPath(legacy), 'utf8'))
    const reopenedLegacy = createAuthorityService(legacy.config)
    for (const entry of legacyEntries) {
      unchanged(legacy, () => same(ok(reopenedLegacy.status({ session_token: legacyToken, operation_id: entry.b.operation.operation_id })).status, 'COMPLETED'), 'legacy status read')
      unchanged(legacy, () => same(ok(entry.kind === 'memory' ? reopenedLegacy.settleMemory({ ...entry.b, receipt: entry.receipt }) : reopenedLegacy.settle(executionInput(entry.b, entry.receipt))).idempotent, true), 'legacy duplicate read')
      unchanged(legacy, () => no(reopenedLegacy.propose({ session_token: legacyToken, operation: entry.b.operation }), 'REPLAYED'), 'legacy refused write')
    }
    ok(reopenedLegacy.propose({ session_token: legacyToken, operation: operation('migration-trigger', 'Public migration trigger') }))
    const migrated = read(legacy), newWitness = JSON.parse(readFileSync(witnessPath(legacy), 'utf8'))
    same(migrated.broker.store_id, oldRecord.broker.store_id, 'migration changed history identity')
    same(migrated.broker.revision, oldRecord.broker.revision + 1, 'migration used a separate commit')
    same(kernel(migrated), genuineKernel, 'migration changed kernel history')
    const kernelKey = hash('aukora-prime.kernel-history.v1\0' + migrated.broker.store_id), brokerKey = hash('aukora-prime.broker-history.v1\0' + migrated.broker.store_id)
    same(newWitness.heads[kernelKey], oldWitness.heads[kernelKey], 'migration changed kernel witness')
    same(newWitness.heads[brokerKey], migrated.broker.revision, 'migration broker witness was not advanced')
    for (const entry of legacyEntries) compact(legacy, entry.b, entry.receipt, entry.kind)
    check(!readFileSync(legacy.config.statePath, 'utf8').includes('RETENTION_LEGACY_'), 'legacy migration retained payload')
    writeFileSync(legacy.config.statePath, beforeMigration, { mode: 0o600 })
    unchanged(legacy, () => no(createAuthorityService(legacy.config).status({ session_token: legacyToken, operation_id: legacyEntries[0].b.operation.operation_id }), 'RECONCILIATION_REQUIRED'), 'plaintext broker rollback')

    // Terminal digests cannot replace the original durable kernel preparation/consumption.
    const intactMemory = readFileSync(memory.config.statePath), intactRecord = read(memory)
    for (const field of ['prepared', 'consumedIds']) {
      const corrupted = structuredClone(intactRecord), nonce = first.p.proof.nonce
      if (field === 'prepared') corrupted.prepared = corrupted.prepared.filter(p => p.consumptionId !== 'approval:' + nonce)
      else corrupted.state.consumedIds = corrupted.state.consumedIds.filter(id => id !== 'approval:' + nonce)
      writeFileSync(memory.config.statePath, JSON.stringify(corrupted), { mode: 0o600 })
      unchanged(memory, () => no(createAuthorityService(memory.config).settleMemory({ ...first.b, receipt: first.receipt }), 'RECONCILIATION_REQUIRED'), 'missing kernel ' + field)
      writeFileSync(memory.config.statePath, intactMemory, { mode: 0o600 })
    }
    const tinyConfig = { ...memory.config, limits: { state_bytes: intactMemory.length + 128 } }, tiny = createAuthorityService(tinyConfig)
    unchanged(memory, () => no(tiny.propose({ session_token: token, operation: operation('quota-refused', 'Public quota fixture') }), 'UNAVAILABLE'), 'durable byte cap')
    same(read(memory), intactRecord, 'quota refusal evicted history')
    unchanged(memory, () => same(ok(tiny.settleMemory({ ...first.b, receipt: first.receipt })).idempotent, true), 'quota preserved duplicate evidence')
    same(lifecycles, 16, 'focused suite lifecycle count')
    return { status: 'PASS', checks, lifecycles, groups: ['terminal memory and all execution statuses compact in one commit without payloads', 'exact replay/owner/grant/request/evidence bindings survive reopening', 'unknown and prepared obligations stay full; explicit reconciliation retains prior digest idempotence', 'legacy full terminal rows migrate only on successful write with broker witness rollback protection', 'kernel consumptions/preparations remain required; byte cap fails closed without eviction'], limits: 'Synthetic signed in-process lifecycles and disposable paths only; no database, executor, application, deployment, or stopped audit.' }
  } finally { rmSync(root, { recursive: true, force: true }) }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(JSON.stringify(runRetentionChecks()) + '\n') }
  catch (error) { process.stderr.write(String(error.stack) + '\n'); process.exitCode = 1 }
}
