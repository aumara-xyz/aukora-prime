// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only worker fixture guards. No pg driver, database, process, or VM action is allowed here.
import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import Module from 'node:module'
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { planWorkerPostgresFixture, validateWorkerPostgresFixture, createWorkerPostgresPool,
  initializeWorkerPostgresSchema, validateWorkerPostgresSaveExpectation, verifyWorkerPostgresSave,
  workerPostgresSchemaPlan, expectedWorkerCaptureDigests } from './worker-postgres-fixture.mjs'
import { sha256 } from '../src/codecs.mjs'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { schemaLifecyclePlan } from './operator-postgres.mjs'

const config = { host: '/run/aukora-prime/postgres', port: 55434, database: 'aukora_prime_synthetic',
  user: 'prime_memory', max: 4, connectionTimeoutMillis: 5000 }

async function withoutPgDriver(work) {
  const original = Module._resolveFilename
  let attempts = 0
  const guard = mock.method(Module, '_resolveFilename', function (request, ...rest) {
    if (request === 'pg' || request === 'pg/package.json') {
      attempts++
      throw Object.assign(new Error('Source-only worker fixture test attempted pg resolution'), { code: 'test:unexpected-pg-use' })
    }
    return original.call(this, request, ...rest)
  })
  try { return await work() } finally { guard.mock.restore(); assert.equal(attempts, 0) }
}
async function fixturePlan(work) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'prime-memory-worker-pg-guards-')))
  try {
    return await withoutPgDriver(async () => {
      const statePath = join(dir, 'worker-fixture.json')
      const result = await planWorkerPostgresFixture({ config, statePath })
      return work({ dir, statePath, result, fixture: result.fixture })
    })
  } finally { rmSync(dir, { recursive: true, force: true }) }
}
function expectation(owner = 'primary') {
  return { version: 1, owner, operation_id: 'synthetic-worker-operation', operation_digest: 'sha256:' + '1'.repeat(64),
    record_id: 'rem:' + '2'.repeat(64), canonical_sha256: '3'.repeat(64), retained_head: '4'.repeat(64),
    storage_status: 'saved', index_status: 'pending',
    receipt: { request_id: '12345678-1234-4234-8234-123456789abc', request_digest: 'sha256:' + '5'.repeat(64),
      receipt_digest: 'sha256:' + '6'.repeat(64), grant_id: 'synthetic-grant', result_digest: 'sha256:' + '7'.repeat(64) },
    settlement_binding: { authority_settlement: 'completed', reconciliation_required: false, receipt_digest: 'sha256:' + '6'.repeat(64) } }
}
async function syntheticUIDView({ real = 54321, effective = real } = {}, work) {
  // Only mocks the source guard's process view. No OS UID is changed and no positive factory call is made.
  const realGuard = mock.method(process, 'getuid', () => real)
  const effectiveGuard = mock.method(process, 'geteuid', () => effective)
  try { return await work() } finally { realGuard.mock.restore(); effectiveGuard.mock.restore() }
}
function goldenFixture() {
  const run_id = '0123456789abcdef01234567'
  const identity = (id, task, conversation) => ({ owner_id: id + run_id,
    owner_subject: 'aukora:1:' + sha256(Buffer.from(id + run_id)), task_id: task + run_id, conversation_id: conversation + run_id })
  const fixture = { version: 1, kind: 'prime-memory-private-worker-pg-fixture/v1', synthetic_fixture: true, run_id,
    config_sha256: sha256(Buffer.from(canonicalJSON(config))), source_schema: 'prime_memory_operator_' + run_id + '_source',
    restore_schema: 'prime_memory_operator_' + run_id + '_restore', owners: {
      primary: identity('synthetic-owner:', 'synthetic-pg-task:', 'synthetic-pg-conversation:'),
      secondary: identity('synthetic-other-owner:', 'synthetic-pg-other-task:', 'synthetic-pg-other-conversation:') },
    agent_id: 'synthetic-agent', schema_plan_sha256: '' }
  const plan = schemaLifecyclePlan({ version: 1, kind: 'prime-memory-operator-pg-synthetic/v1', synthetic_fixture: true,
    phase: 'planned', run_id, config_sha256: fixture.config_sha256, source_schema: fixture.source_schema,
    restore_schema: fixture.restore_schema, owner_subject: fixture.owners.primary.owner_subject,
    other_subject: fixture.owners.secondary.owner_subject, authority_fixture: 'production-C-private-IPC-synthetic-passkey',
    driver_version: '8.16.3' }, config, 'create')
  fixture.schema_plan_sha256 = sha256(Buffer.from(canonicalJSON(plan)))
  return validateWorkerPostgresFixture(fixture, config)
}
function captureContext(fixture, owner = 'primary') {
  const bytes = Buffer.from('{"type":"turn","text":"Synthetic golden banana.","seq":0,"at":"2026-10-01T11:03:00Z"}\n')
  const host = { ...fixture.owners[owner], privacy: 'local', scope: 'owner', attributedTo: 'owner',
    source: { sessionId: 'golden-session', seq: 0, at: '2026-10-01T11:03:00Z', sha256: sha256(bytes) }, events: [bytes],
    evidence: null, bodyAtCapture: null, origin: { by: 'prime.capture/v1' }, offTheRecord: false, paused: false }
  const extraction = { category: 'fact', statement: 'Golden banana < & > exact.', validFrom: '2026-10-01',
    observedAt: '2026-10-01T11:03:00Z', confidence: 0.7, sensitivity: 'none', links: [] }
  return { config, fixture, owner, host, extraction, idempotencyKey: 'synthetic-golden-key' }
}
function documentedCapturePreimage(context) {
  return { input: context.extraction, subject: context.host.owner_subject, task: context.host.task_id,
    source: context.host.source, evidence: null, attribution: 'owner', scope: 'owner', privacy: 'local',
    origin: { by: 'prime.capture/v1' }, bodyAtCapture: null, events: context.host.events.map(bytes => sha256(Buffer.from(bytes))) }
}

test('worker planning has two distinct synthetic identities and no keys, proofs, or IPC secrets', async () => {
  await fixturePlan(async ({ statePath, result, fixture }) => {
    assert.equal(result.PostgreSQL_connected, false)
    assert.equal(result.state_path, statePath); assert.equal(result.schema_plan_path, statePath + '.schema-create-plan.json')
    assert.deepEqual(JSON.parse(readFileSync(statePath, 'utf8')), fixture)
    assert.deepEqual(JSON.parse(readFileSync(result.schema_plan_path, 'utf8')), result.plan)
    assert.equal(statSync(statePath).mode & 0o777, 0o600)
    assert.equal(statSync(result.schema_plan_path).mode & 0o777, 0o600)
    assert.equal(existsSync(statePath + '.anchors.json'), false)
    assert.deepEqual(Object.keys(fixture).sort(), ['version', 'kind', 'synthetic_fixture', 'run_id', 'config_sha256',
      'source_schema', 'restore_schema', 'owners', 'agent_id', 'schema_plan_sha256'].sort())
    assert.equal(fixture.kind, 'prime-memory-private-worker-pg-fixture/v1')
    assert.equal(fixture.synthetic_fixture, true); assert.equal(Object.isFrozen(fixture), true)
    assert.equal(Object.isFrozen(fixture.owners.primary), true)
    assert.deepEqual(Object.keys(fixture.owners).sort(), ['primary', 'secondary'])
    for (const identity of Object.values(fixture.owners)) {
      assert.deepEqual(Object.keys(identity).sort(), ['owner_id', 'owner_subject', 'task_id', 'conversation_id'].sort())
      assert.notEqual(identity.owner_id, identity.owner_subject)
      assert.equal(identity.owner_subject, 'aukora:1:' + sha256(Buffer.from(identity.owner_id)))
    }
    for (const field of ['owner_id', 'owner_subject', 'task_id', 'conversation_id']) {
      assert.notEqual(fixture.owners.primary[field], fixture.owners.secondary[field])
    }
    assert.deepEqual(validateWorkerPostgresFixture(fixture, config), fixture)
    assert.throws(() => planWorkerPostgresFixture({ config, statePath }), { code: 'worker-pg:state-already-exists' })
  })
})

test('worker schema plan keeps generic operator marker and exact scoped role privileges', async () => {
  await fixturePlan(async ({ fixture, result }) => {
    const names = ['prime_memory_operator_' + fixture.run_id + '_source', 'prime_memory_operator_' + fixture.run_id + '_restore']
    assert.deepEqual(result.plan.schema_names, names); assert.equal(result.plan.schemas.length, 2)
    assert.equal(result.plan.kind, 'prime-memory-operator-schema-plan/v1')
    assert.equal(result.plan.action, 'create'); assert.equal(result.plan.exclusive_operator_required, true)
    assert.equal(result.plan.memory_role_database_create, false); assert.equal(result.plan.memory_role_database_temp, false)
    assert.equal(result.plan.memory_role_schema_owner, false)
    for (const [index, entry] of result.plan.schemas.entries()) {
      assert.equal(entry.name, names[index])
      assert.deepEqual(entry.marker, { table: 'prime_operator_fixture_marker', run_id: fixture.run_id,
        fixture_kind: 'prime-memory-operator-pg-synthetic/v1', operator_owned: true })
      assert.deepEqual(entry.memory_role_schema_privileges, ['USAGE', 'CREATE'])
      assert.deepEqual(entry.memory_role_marker_privileges, ['SELECT'])
    }
  })
})

test('worker fixture validates closed scalar shape and exact config, schemas, owners, and plan binding', async () => {
  await fixturePlan(async ({ fixture }) => {
    const invalids = [[{ ...fixture, private_key: 'synthetic-unrequested-key' }, 'worker-pg:closed-fixture-required'],
      [{ ...fixture, run_id: [fixture.run_id] }, 'worker-pg:invalid-fixture'],
      [{ ...fixture, config_sha256: [fixture.config_sha256] }, 'worker-pg:config-binding-changed'],
      [{ ...fixture, source_schema: 'public' }, 'worker-pg:schema-binding-changed'],
      [{ ...fixture, restore_schema: fixture.source_schema }, 'worker-pg:schema-binding-changed'],
      [{ ...fixture, owners: { ...fixture.owners, primary: { ...fixture.owners.primary, owner_subject: fixture.owners.secondary.owner_subject } } }, 'worker-pg:owner-binding-changed'],
      [{ ...fixture, owners: { ...fixture.owners, primary: { ...fixture.owners.primary, task_id: fixture.owners.secondary.task_id } } }, 'worker-pg:owner-binding-changed'],
      [{ ...fixture, owners: { ...fixture.owners, primary: { ...fixture.owners.primary, proof: {} } } }, 'worker-pg:closed-owner-required'],
      [{ ...fixture, owners: { ...fixture.owners, third: fixture.owners.primary } }, 'worker-pg:closed-owners-required'],
      [{ ...fixture, schema_plan_sha256: [fixture.schema_plan_sha256] }, 'worker-pg:schema-plan-binding-changed'],
      [{ ...fixture, agent_id: 'unplanned-agent' }, 'worker-pg:schema-plan-binding-changed']]
    for (const [changed, code] of invalids) assert.throws(() => validateWorkerPostgresFixture(changed, config), { code })
    const symbol = { ...fixture, [Symbol('hidden')]: true }
    assert.throws(() => validateWorkerPostgresFixture(symbol, config), { code: 'worker-pg:closed-fixture-required' })
    const accessor = { ...fixture }; Object.defineProperty(accessor, 'kind', { get() { throw new Error('Untrusted getter must not run') }, enumerable: true })
    assert.throws(() => validateWorkerPostgresFixture(accessor, config), { code: 'worker-pg:closed-fixture-required' })
  })
})

test('worker factories refuse TCP, passwords, external target, and unplanned schema before pg', async () => {
  await fixturePlan(async ({ fixture }) => {
    for (const factory of [createWorkerPostgresPool, initializeWorkerPostgresSchema]) {
      for (const [changed, code] of [[{ ...config, host: 'localhost' }, 'operator:disposable-target-required'],
        [{ ...config, database: 'postgres' }, 'operator:disposable-target-required'],
        [{ ...config, user: 'postgres' }, 'operator:disposable-target-required'],
        [{ ...config, password: 'synthetic' }, 'worker-pg:closed-config-required'],
        [{ ...config, options: '-c search_path=public' }, 'worker-pg:closed-config-required']]) {
        await assert.rejects(factory({ config: changed, fixture, schema: 'source', memoryUid: 54321 }), { code })
      }
      const accessor = { ...config }
      Object.defineProperty(accessor, 'host', { get() { throw new Error('Untrusted config getter must not run') }, enumerable: true })
      await assert.rejects(factory({ config: accessor, fixture, schema: 'source', memoryUid: 54321 }), { code: 'worker-pg:closed-config-required' })
      for (const schema of ['public', fixture.source_schema, fixture.restore_schema, ['source'], null]) {
        await assert.rejects(factory({ config, fixture, schema, memoryUid: 54321 }), { code: 'worker-pg:schema-selection-invalid' })
      }
    }
  })
})

test('worker factories require matching real/effective memory UID and refuse PG environment before pg', async () => {
  await fixturePlan(async ({ fixture }) => {
    for (const factory of [createWorkerPostgresPool, initializeWorkerPostgresSchema]) {
      await syntheticUIDView({}, async () => {
        for (const memoryUid of [54322, '54321', 0, null]) {
          await assert.rejects(factory({ config, fixture, schema: 'source', memoryUid }), { code: 'worker-pg:assigned-memory-uid-required' })
        }
      })
      await syntheticUIDView({ real: 54321, effective: 54322 }, async () => {
        await assert.rejects(factory({ config, fixture, schema: 'restore', memoryUid: 54321 }), { code: 'worker-pg:assigned-memory-uid-required' })
      })
      for (const prefix of ['PG', 'pg']) {
        for (const value of ['synthetic', '']) {
          const name = prefix + '_PRIME_SOURCE_GUARD_' + randomUUID().replaceAll('-', '')
          assert.equal(Object.hasOwn(process.env, name), false)
          process.env[name] = value
          try {
            await syntheticUIDView({}, async () => {
              await assert.rejects(factory({ config, fixture, schema: 'source', memoryUid: 54321 }), { code: 'worker-pg:postgres-environment-refused' })
            })
          } finally { delete process.env[name] }
        }
      }
    }
  })
})

test('save expectation accepts strict immutable bindings for either fixture owner without verifying C', async () => {
  await fixturePlan(async ({ fixture }) => {
    for (const owner of ['primary', 'secondary']) {
      const expected = expectation(owner), checked = validateWorkerPostgresSaveExpectation(expected, fixture)
      assert.deepEqual(checked, expected); assert.equal(Object.isFrozen(checked), true)
      assert.equal(Object.isFrozen(checked.receipt), true); assert.equal(Object.isFrozen(checked.settlement_binding), true)
      assert.equal(Object.isFrozen(expected), false)
    }
  })
})

test('save expectation refuses coercible digests, unclosed content, invalid owner, and mismatched receipt settlement', async () => {
  await fixturePlan(async ({ fixture }) => {
    const original = expectation()
    const cases = [[{ ...original, owner: 'third' }, 'worker-pg:expectation-owner-invalid'],
      [{ ...original, proof: {} }, 'worker-pg:closed-save-expectation-required'],
      [{ ...original, operation_digest: [original.operation_digest] }, 'worker-pg:save-expectation-invalid'],
      [{ ...original, canonical_sha256: [original.canonical_sha256] }, 'worker-pg:save-expectation-invalid'],
      [{ ...original, retained_head: [original.retained_head] }, 'worker-pg:save-expectation-invalid'],
      [{ ...original, record_id: [original.record_id] }, 'worker-pg:save-expectation-invalid'],
      [{ ...original, operation_id: 'o'.repeat(129) }, 'worker-pg:save-expectation-invalid'],
      [{ ...original, operation_id: 'op\nunsafe' }, 'worker-pg:save-expectation-invalid'],
      [{ ...original, storage_status: 'pending' }, 'worker-pg:save-expectation-invalid'],
      [{ ...original, index_status: 'saved' }, 'worker-pg:save-expectation-invalid'],
      [{ ...original, receipt: { ...original.receipt, caller_result: {} } }, 'worker-pg:closed-receipt-expectation-required'],
      [{ ...original, receipt: { ...original.receipt, request_id: '12345678-1234-1234-8234-123456789abc' } }, 'worker-pg:receipt-expectation-invalid'],
      [{ ...original, receipt: { ...original.receipt, request_digest: [original.receipt.request_digest] } }, 'worker-pg:receipt-expectation-invalid'],
      [{ ...original, receipt: { ...original.receipt, grant_id: 'g'.repeat(257) } }, 'worker-pg:receipt-expectation-invalid'],
      [{ ...original, settlement_binding: { ...original.settlement_binding, C_proved: true } }, 'worker-pg:closed-settlement-binding-required'],
      [{ ...original, settlement_binding: { ...original.settlement_binding, authority_settlement: 'pending' } }, 'worker-pg:expected-completed-settlement-required'],
      [{ ...original, settlement_binding: { ...original.settlement_binding, reconciliation_required: true } }, 'worker-pg:expected-completed-settlement-required'],
      [{ ...original, settlement_binding: { ...original.settlement_binding, receipt_digest: 'sha256:' + 'f'.repeat(64) } }, 'worker-pg:expected-completed-settlement-required']]
    for (const [changed, code] of cases) assert.throws(() => validateWorkerPostgresSaveExpectation(changed, fixture), { code })
  })
})

test('worker verification refuses a caller-supplied fake pool before driver or query', async () => {
  await fixturePlan(async ({ fixture }) => {
    let queryCalls = 0
    const pool = { query() { queryCalls++; throw new Error('A negative source test must not query') } }
    await assert.rejects(verifyWorkerPostgresSave({ pool, fixture, expected: expectation(), project: false }),
      { code: 'worker-pg:factory-scoped-pool-required' })
    assert.equal(queryCalls, 0)
  })
})

test('pure worker create/drop plans retain exact generic operator schema and marker closure', async () => {
  await fixturePlan(async ({ fixture, result }) => {
    assert.deepEqual(workerPostgresSchemaPlan({ config, fixture, action: 'create' }), result.plan)
    const drop = workerPostgresSchemaPlan({ config, fixture, action: 'drop' })
    assert.equal(drop.action, 'drop'); assert.deepEqual(drop.schema_names, [fixture.source_schema, fixture.restore_schema])
    assert.equal(drop.exclusive_operator_required, true); assert.equal(drop.memory_role_schema_owner, false)
    assert.equal(drop.memory_role_database_create, false); assert.equal(drop.memory_role_database_temp, false)
    for (const entry of drop.schemas) {
      assert.equal(entry.require_exact_marker_before_drop, true)
      assert.equal(entry.marker.fixture_kind, 'prime-memory-operator-pg-synthetic/v1')
      assert.equal(entry.marker.operator_owned, true)
    }
    assert.throws(() => workerPostgresSchemaPlan({ config, fixture, action: 'execute' }))
    assert.throws(() => workerPostgresSchemaPlan({ config, fixture: { ...fixture, source_schema: 'public' }, action: 'drop' }))
  })
})

test('capture helper matches documented decimal-bearing golden preimage for both distinct owners', async () => {
  await withoutPgDriver(async () => {
    const fixture = goldenFixture()
    for (const owner of ['primary', 'secondary']) {
      const context = captureContext(fixture, owner), expected = expectedWorkerCaptureDigests(context)
      assert.deepEqual(Object.keys(expected).sort(), ['capture_sha256', 'idempotency_key_sha256', 'statement', 'attributed_to'].sort())
      assert.deepEqual(expected, { capture_sha256: sha256(Buffer.from(canonicalJSON(documentedCapturePreimage(context)))),
        idempotency_key_sha256: sha256(Buffer.from(context.idempotencyKey)), statement: context.extraction.statement, attributed_to: 'owner' })
      assert.equal(Object.isFrozen(expected), true)
      assert.match(canonicalJSON(documentedCapturePreimage(context)), /"confidence":0\.7/)
      if (owner === 'primary') {
        assert.equal(expected.capture_sha256, 'dd492d80f6f0b545e4bbccec136b9ceb3b3a8887e53586114e273eb9482c633b')
        assert.equal(expected.idempotency_key_sha256, 'd4384ffe752c03a0f62508b557ed17521545cc96a5a091fd8b3ff5b3ce3ed44b')
      }
    }
    assert.notEqual(expectedWorkerCaptureDigests(captureContext(fixture, 'primary')).capture_sha256,
      expectedWorkerCaptureDigests(captureContext(fixture, 'secondary')).capture_sha256)
  })
})

test('capture hashes bind extraction, source fields, exact event bytes, and idempotency independently', async () => {
  await withoutPgDriver(async () => {
    const base = captureContext(goldenFixture()), original = expectedWorkerCaptureDigests(base)
    for (const extraction of [{ ...base.extraction, statement: base.extraction.statement + ' changed' },
      { ...base.extraction, confidence: 0.71 }, { ...base.extraction, links: [{ relation: 'context', id: 'rem:' + 'a'.repeat(64) }] }]) {
      assert.notEqual(expectedWorkerCaptureDigests({ ...base, extraction }).capture_sha256, original.capture_sha256)
    }
    const source = { ...base.host.source, sessionId: 'changed-golden-session' }
    assert.notEqual(expectedWorkerCaptureDigests({ ...base, host: { ...base.host, source } }).capture_sha256, original.capture_sha256)
    const changedBytes = Buffer.concat([base.host.events[0], Buffer.from(' ')])
    const changedHost = { ...base.host, source: { ...base.host.source, sha256: sha256(changedBytes) }, events: [changedBytes] }
    assert.notEqual(expectedWorkerCaptureDigests({ ...base, host: changedHost }).capture_sha256, original.capture_sha256)
    const keyChanged = expectedWorkerCaptureDigests({ ...base, idempotencyKey: 'changed-golden-key' })
    assert.notEqual(keyChanged.idempotency_key_sha256, original.idempotency_key_sha256)
    assert.equal(keyChanged.capture_sha256, original.capture_sha256)
    const typedArrayHost = { ...base.host, events: [new Uint8Array(base.host.events[0])] }
    assert.deepEqual(expectedWorkerCaptureDigests({ ...base, host: typedArrayHost }), original)
  })
})

test('capture helper refuses wrong identities, nonfixed profiles, changed source hashes, malformed literals, and accessors', async () => {
  await withoutPgDriver(async () => {
    const base = captureContext(goldenFixture())
    const hostChanges = [{ owner_id: base.fixture.owners.secondary.owner_id },
      { owner_subject: base.fixture.owners.secondary.owner_subject }, { task_id: base.fixture.owners.secondary.task_id },
      { conversation_id: base.fixture.owners.secondary.conversation_id }, { privacy: 'private' }, { scope: 'task' },
      { attributedTo: 'agent' }, { evidence: [] }, { bodyAtCapture: {} }, { origin: { by: 'changed' } },
      { offTheRecord: true }, { paused: true }, { source: { ...base.host.source, sha256: 'f'.repeat(64) } },
      { events: [] }, { events: [base.host.events[0].toString('utf8')] }, { events: Array(9).fill(base.host.events[0]) },
      { unrequested: true }]
    for (const patch of hostChanges) assert.throws(() => expectedWorkerCaptureDigests({ ...base, host: { ...base.host, ...patch } }))
    for (const patch of [{ statement: 'contains\u202Ehidden' }, { statement: 'contains\u061Chidden' },
      { statement: 'contains\rreturn' }, { statement: '\ud800' }, { statement: ' ' }, { statement: 's'.repeat(4097) },
      { attributedTo: 'owner' }]) {
      assert.throws(() => expectedWorkerCaptureDigests({ ...base, extraction: { ...base.extraction, ...patch } }))
    }
    assert.throws(() => expectedWorkerCaptureDigests({ ...base, owner: 'third' }))
    assert.throws(() => expectedWorkerCaptureDigests({ ...base, idempotencyKey: '' }))
    assert.throws(() => expectedWorkerCaptureDigests({ ...base, idempotencyKey: 'k'.repeat(1025) }))
    const hostAccessor = { ...base.host }
    Object.defineProperty(hostAccessor, 'source', { get() { throw new Error('Host getter must not run') }, enumerable: true })
    assert.throws(() => expectedWorkerCaptureDigests({ ...base, host: hostAccessor }), error => error.message !== 'Host getter must not run')
    const extractionAccessor = { ...base.extraction }
    Object.defineProperty(extractionAccessor, 'statement', { get() { throw new Error('Extraction getter must not run') }, enumerable: true })
    assert.throws(() => expectedWorkerCaptureDigests({ ...base, extraction: extractionAccessor }), error => error.message !== 'Extraction getter must not run')
  })
})
