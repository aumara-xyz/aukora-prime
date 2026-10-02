#!/usr/bin/env node
// Narrow disposable receipt checks; no executor, network or installed runtime.
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createAuthorityService, provisionNewAuthorityStore, loginSigningBytes, approvalSigningBytes, operationDigest, executorRequestDigest, executionReceiptDigest } from './src/index.mjs'
import { validatedReceipt } from './src/execution.mjs'
import { didKeyFromEd25519PublicKey } from './upstream/plugins/aukora-aumlok/lib/did-key.mjs'

export function runExecutionReceiptChecks() {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'prime-execution-receipt-'))
  let assertions = 0
  const cases = []
  const equal = (actual, expected, message) => { assert.deepEqual(actual, expected, message); assertions++ }
  const check = (condition, message) => { assert(condition, message); assertions++ }
  const ok = result => { equal(result.ok, true, JSON.stringify(result)); return result }
  const refuse = (result, code) => { equal(result.ok, false, JSON.stringify(result)); equal(result.error_code, code, JSON.stringify(result)) }
  const test = (name, body) => { body(); cases.push(name) }
  const rejects = receipt => { assert.throws(() => validatedReceipt(receipt), /INVALID/); assertions++ }
  const keys = generateKeyPairSync('ed25519') // Synthetic private key stays in this process.
  const raw = Buffer.from(keys.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex')
  const identity = { owner_id: 'synthetic-receipt-owner', subject: 'aukora:1:' + '1'.repeat(64), approval_key_did: didKeyFromEd25519PublicKey(raw), control_digest: '2'.repeat(64), authorization_epoch: 0 }
  const image = 'sha256:' + 'a'.repeat(64), policy = 'sha256:' + 'b'.repeat(64)
  const sandbox = () => { const uid = randomUUID(); return { uid, name: 'synthetic-' + uid, identity: 'synthetic-owned/' + uid, image_digest: image, policy_digest: policy } }
  const at = new Date().toISOString()
  const shape = { version: 1, receipt_id: randomUUID(), operation_id: 'synthetic-shape', task_id: 'synthetic-task', owner_id: identity.owner_id, operation_digest: 'sha256:' + 'c'.repeat(64), grant_id: 'synthetic-grant', request_id: randomUUID(), status: 'outcome_unknown', stdout: '', stderr: '', exit_code: null, rpc_completion: 'complete', output_truncated: false, sandbox: sandbox(), cleanup: 'pending', started_at: at, finished_at: at, error_code: 'OUTCOME_UNKNOWN', reconciliation_required: true }

  function fixture(name) {
    const dir = join(root, name), state = join(dir, 'state')
    mkdirSync(dir, { mode: 0o700 }); mkdirSync(state, { mode: 0o700 })
    const config = {
      statePath: join(state, 'authority.json'), stateRoot: state, witnessDir: join(dir, 'witness'),
      audience: 'prime:execution-receipt-fixture', identities: [identity], loginKinds: ['owner_key'], provisionTrustedState: true,
      policy: { version: 'synthetic-policy-v1', actions: ['shell.bash.foreground'], agents: ['synthetic-agent'], data_scope: ['public'], maximum_cost: { currency: 'USD', amount: '0' } },
      authorizeTask: op => ({ authenticated: true, task: { version: 1, task_id: 'synthetic-task', owner_id: op.owner_id, agent_id: 'synthetic-agent', conversation_id: 'synthetic-conversation', status: 'running', created_at: new Date().toISOString(), route_id: null, allowed_data_classes: ['public'], max_input_tokens: 0, max_output_tokens: 0, max_requests: 0, task_spend_ceiling: { currency: 'USD', amount: '0' } } }),
      observeTarget: op => ({ target_identity: op.target_identity, state_version: 'synthetic-r1' }),
    }
    ok(provisionNewAuthorityStore(config)) // Setup only, before normal service open.
    const service = createAuthorityService(config)
    const challenge = ok(service.loginChallenge({ owner_id: identity.owner_id, kind: 'owner_key' })).challenge
    const session = ok(service.loginComplete({ challenge, material: { kind: 'owner_key', signature: sign(null, loginSigningBytes(challenge), keys.privateKey).toString('hex') } }))
    const operation = { version: 1, operation_id: name, task_id: 'synthetic-task', owner_id: identity.owner_id, agent_id: 'synthetic-agent', audience: config.audience, action_type: 'shell.bash.foreground', target_identity: { backend: 'openshell-linux', workspace: 'synthetic-public', image_digest: image, policy_digest: policy, logical_workspace_root: '/synthetic-public' }, canonical_parameters: { command: 'synthetic inert command', workdir: '/synthetic-public', sandbox_mode: 'read-only', stdin: '', env: {}, dsh_env: {}, timeout_ms: 1000, max_output_bytes: 1024 }, data_scope: ['public'], expected_state_version: 'synthetic-r1', provider_and_region: { provider: 'none', region: 'local' }, maximum_cost: { currency: 'USD', amount: '0' }, expiry: new Date(Date.now() + 600000).toISOString(), nonce: randomBytes(32).toString('hex'), policy_version: 'synthetic-policy-v1', authorization_epoch: 0 }
    ok(service.propose({ session_token: session.session_token, operation }))
    const review = ok(service.approvalChallenge({ session_token: session.session_token, operation }))
    const proof = { ...review.proof_template, material: { kind: 'owner_key', request: review.approval_request, signature: sign(null, approvalSigningBytes(review.approval_request), keys.privateKey).toString('hex') } }
    ok(service.approvalComplete({ session_token: session.session_token, proof }))
    const grant = ok(service.reserve({ operation, approval_proof: proof })).consumed_grant
    const request = { operation, consumed_grant: grant, request_id: randomUUID(), image_digest: image, policy_digest: policy, wall_time_ms: 1000, max_output_bytes: 1024 }
    const binding = { operation, consumed_grant: grant, request_id: request.request_id, request_digest: executorRequestDigest(request) }
    const read = () => JSON.parse(readFileSync(config.statePath, 'utf8'))
    const obligations = () => { const record = read(); return { consumedIds: record.state.consumedIds, prepared: record.prepared, receiptHead: record.state.receiptHead } }
    const prepared = obligations()
    equal(prepared.consumedIds, ['approval:' + proof.nonce], 'normal signed approval must be consumed once')
    equal(prepared.prepared.length, 1, 'normal kernel preparation must exist')
    equal(prepared.receiptHead.count, 1, 'normal kernel receipt must exist')
    check(prepared.prepared[0].consumptionId === 'approval:' + proof.nonce && prepared.prepared[0].contentHash === operationDigest(operation).slice(7), 'kernel preparation must bind exact signed operation')
    const receipt = { ...shape, receipt_id: randomUUID(), operation_id: operation.operation_id, task_id: operation.task_id, owner_id: operation.owner_id, operation_digest: operationDigest(operation), grant_id: grant.grant_id, request_id: binding.request_id, sandbox: sandbox(), started_at: new Date().toISOString(), finished_at: new Date().toISOString() }
    return { config, service, binding, receipt, read, obligations, prepared }
  }
  const input = (f, receipt) => ({ ...f.binding, receipt, receipt_digest: executionReceiptDigest(receipt) })
  const row = f => Object.values(f.read().broker.operations)[0]

  try {
    test('truthful complete RPC without typed exit is a valid unknown receipt', () => equal(validatedReceipt(shape), shape))
    test('complete/null refuses non-unknown status', () => rejects({ ...shape, status: 'failed' }))
    test('complete/null refuses absent reconciliation obligation', () => rejects({ ...shape, reconciliation_required: false }))
    test('complete/null refuses absent start evidence', () => rejects({ ...shape, started_at: null }))
    test('not_started refuses non-null start evidence', () => rejects({ ...shape, rpc_completion: 'not_started', sandbox: null, cleanup: 'unknown' }))
    test('not_started refuses typed exit evidence', () => rejects({ ...shape, rpc_completion: 'not_started', started_at: null, exit_code: 0, sandbox: null, cleanup: 'unknown' }))
    test('not_created refuses sandbox evidence', () => rejects({ ...shape, rpc_completion: 'not_started', started_at: null, cleanup: 'not_created' }))
    test('not_created refuses attempted RPC evidence', () => rejects({ ...shape, rpc_completion: 'transport_failed', started_at: null, sandbox: null, cleanup: 'not_created' }))
    test('normal signed lifecycle retains complete/null uncertainty through cancellation, cleanup and reopen', () => {
      const f = fixture('complete-null-unknown')
      equal(ok(f.service.claimDispatch(f.binding)).status, 'DISPATCHED')
      equal(ok(f.service.requestCancel({ operation: f.binding.operation, consumed_grant: f.binding.consumed_grant, request_id: f.binding.request_id, reason: 'caller' })).status, 'CANCEL_REQUESTED')
      const first = ok(f.service.settle(input(f, f.receipt)))
      equal(first.status, 'OUTCOME_UNKNOWN'); equal(first.reconciliation_required, true)
      equal(row(f).dispatch.receipt, f.receipt, 'started complete/null receipt must be stored exactly')
      check(row(f).operation !== undefined && row(f).grant !== undefined, 'unknown operation and consumed grant must remain full obligations')
      equal(f.obligations(), f.prepared, 'settlement must preserve all original kernel obligations')
      const absent = { ...f.receipt, cleanup: 'confirmed_absent', finished_at: new Date().toISOString() }
      const reconciled = ok(f.service.reconcileSettlement(input(f, absent)))
      equal(reconciled.status, 'OUTCOME_UNKNOWN'); equal(reconciled.reconciliation_required, true)
      equal(row(f).dispatch.receipt, absent, 'cleanup evidence must be stored without inventing a typed exit')
      equal(row(f).dispatch.cancel_requested, true)
      equal(f.obligations(), f.prepared, 'cleanup cannot release or replace kernel obligations')
      const reopened = createAuthorityService(f.config)
      const duplicate = ok(reopened.settle(input(f, absent)))
      equal(duplicate.idempotent, true); equal(duplicate.status, 'OUTCOME_UNKNOWN'); equal(duplicate.reconciliation_required, true)
      const stateBefore = readFileSync(f.config.statePath), witnessBefore = readFileSync(join(f.config.witnessDir, 'kernel-high-water.json'))
      refuse(reopened.claimDispatch(f.binding), 'REPLAYED')
      equal(readFileSync(f.config.statePath), stateBefore, 'dispatch replay refusal must leave state unchanged')
      equal(readFileSync(join(f.config.witnessDir, 'kernel-high-water.json')), witnessBefore, 'dispatch replay refusal must leave witness unchanged')
      equal(f.obligations(), f.prepared, 'cold duplicate and replay refusal must retain original kernel obligations')
    })
    test('independent normal signed typed-exit control still completes', () => {
      const f = fixture('typed-exit-control')
      equal(ok(f.service.claimDispatch(f.binding)).status, 'DISPATCHED')
      const receipt = { ...f.receipt, status: 'completed', exit_code: 0, rpc_completion: 'complete', cleanup: 'confirmed_absent', error_code: null, reconciliation_required: false, stdout: 'Public synthetic typed result' }
      const result = ok(f.service.settle(input(f, receipt)))
      equal(result.status, 'COMPLETED'); equal(result.reconciliation_required, false)
      equal(f.obligations(), f.prepared, 'typed completion must retain original consumed/kernel history')
      const duplicate = ok(createAuthorityService(f.config).settle(input(f, receipt)))
      equal(duplicate.idempotent, true); equal(duplicate.status, 'COMPLETED')
    })
    return { status: 'PASS', cases: cases.length, assertions, groups: cases, scope: 'Synthetic in-process Ed25519 keys and disposable real C/kernel/store only; no executor, network, enrollment, deployed UID or runtime qualification.' }
  } finally { rmSync(root, { recursive: true, force: true }) }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(runExecutionReceiptChecks())) }
  catch (error) { console.log(JSON.stringify({ status: 'FAIL', error: error.message })); process.exitCode = 1 }
}
