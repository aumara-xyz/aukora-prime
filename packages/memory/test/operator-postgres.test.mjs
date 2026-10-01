// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only command guards. These tests never load pg or connect to PostgreSQL.
import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import Module from 'node:module'
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { validateOperatorConfig, runOperatorPostgres, schemaLifecyclePlan } from './operator-postgres.mjs'

const config = { host: '/run/aukora-prime/postgres', port: 55434, database: 'aukora_prime_synthetic',
  user: 'prime_memory', max: 4, connectionTimeoutMillis: 5000 }

async function withoutPgDriver(work) {
  const original = Module._resolveFilename
  let attempts = 0
  const guard = mock.method(Module, '_resolveFilename', function (request, ...rest) {
    if (request === 'pg' || request === 'pg/package.json') {
      attempts++
      throw Object.assign(new Error('A source-only command attempted pg driver resolution'), { code: 'test:unexpected-pg-use' })
    }
    return original.call(this, request, ...rest)
  })
  try { return await work() } finally { guard.mock.restore(); assert.equal(attempts, 0, 'No pg driver resolution is allowed in this test') }
}
async function fixtureFiles(work) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'prime-memory-operator-guards-')))
  const configPath = join(dir, 'config.json'), statePath = join(dir, 'state.json')
  writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 })
  try { return await withoutPgDriver(() => work({ dir, configPath, statePath })) }
  finally { rmSync(dir, { recursive: true, force: true }) }
}
const readJSON = path => JSON.parse(readFileSync(path, 'utf8'))
const writeJSON = (path, value) => writeFileSync(path, JSON.stringify(value) + '\n', { mode: 0o600 })
async function plannedFixture(work) {
  return fixtureFiles(async files => {
    const result = await runOperatorPostgres(['plan', files.configPath, files.statePath])
    return work({ ...files, result, state: readJSON(files.statePath) })
  })
}

test('operator configuration permits only the explicitly supplied synthetic socket profile', () => {
  assert.deepEqual(validateOperatorConfig(config), config)
  assert.equal(Object.isFrozen(validateOperatorConfig(config)), true)
  for (const patch of [{ host: 'localhost' }, { host: '/tmp/postgres' }, { port: 5432 },
    { database: 'postgres' }, { user: 'postgres' }, { max: '4' }, { max: 0 }, { max: 5 },
    { connectionTimeoutMillis: 5001 }]) {
    assert.throws(() => validateOperatorConfig({ ...config, ...patch }), { code: 'operator:disposable-target-required' })
  }
  for (const changed of [{ ...config, password: 'synthetic' }, { ...config, connectionString: 'postgresql://localhost' },
    { ...config, options: '-c search_path=public' }, [], null, Object.create(config)]) {
    assert.throws(() => validateOperatorConfig(changed), { code: 'operator:explicit-closed-config-required' })
  }
})

test('operator help and argument refusals happen before any driver or PostgreSQL use', async () => {
  await withoutPgDriver(async () => {
    assert.match((await runOperatorPostgres(['--help'])).scope, /synthetic data/i)
    await assert.rejects(runOperatorPostgres([]), { code: 'operator:arguments-invalid' })
    await assert.rejects(runOperatorPostgres(['unknown', '/tmp/config.json', '/tmp/state.json']), { code: 'operator:arguments-invalid' })
    await assert.rejects(runOperatorPostgres(['prepare', 'relative', 'relative']), { code: 'operator:absolute-task-owned-paths-required' })
    await assert.rejects(runOperatorPostgres(['prepare', '/tmp/same.json', '/tmp/same.json']), { code: 'operator:absolute-task-owned-paths-required' })
  })
})

test('plan produces a closed source-only state and exact operator schema plan without pg', async () => {
  await plannedFixture(async ({ result, state, statePath, configPath }) => {
    assert.equal(result.phase, 'planned'); assert.equal(result.PostgreSQL_connected, false)
    assert.equal(result.state, statePath); assert.equal(result.schema_plan, statePath + '.schema-create-plan.json')
    assert.deepEqual(readJSON(result.schema_plan), result.plan)
    assert.equal(statSync(statePath).mode & 0o777, 0o600)
    assert.equal(statSync(result.schema_plan).mode & 0o777, 0o600)
    assert.equal(existsSync(statePath + '.anchors.json'), false)
    assert.equal(state.phase, 'planned'); assert.equal(state.synthetic_fixture, true)
    assert.equal(state.authority_fixture, 'private-toy-not-production-C')
    assert.equal(state.driver_version, '8.16.3')
    assert.match(state.run_id, /^[0-9a-f]{24}$/); assert.match(state.schema_plan_sha256, /^[0-9a-f]{64}$/)
    assert.deepEqual(Object.keys(state).sort(), ['version', 'kind', 'synthetic_fixture', 'phase', 'run_id',
      'config_sha256', 'source_schema', 'restore_schema', 'owner_subject', 'other_subject',
      'authority_fixture', 'driver_version', 'schema_plan_sha256'].sort())
    assert.deepEqual(result.plan, schemaLifecyclePlan(state, config, 'create'))
    await assert.rejects(runOperatorPostgres(['plan', configPath, statePath]), { code: 'operator:state-already-exists' })
  })
})

test('schema lifecycle plans grant only exact operator-owned schemas and require scoped operator drop', async () => {
  await plannedFixture(async ({ state, result }) => {
    const expectedNames = ['prime_memory_operator_' + state.run_id + '_source', 'prime_memory_operator_' + state.run_id + '_restore']
    for (const action of ['create', 'drop']) {
      const plan = schemaLifecyclePlan(state, config, action)
      assert.deepEqual(plan.schema_names, expectedNames); assert.equal(plan.schemas.length, 2)
      assert.deepEqual(plan, { version: 1, kind: 'prime-memory-operator-schema-plan/v1', action, run_id: state.run_id,
        database: 'aukora_prime_synthetic', memory_role: 'prime_memory', schema_names: expectedNames,
        exclusive_operator_required: true, memory_role_database_create: false, memory_role_database_temp: false,
        memory_role_schema_owner: false, schemas: expectedNames.map(name => ({ name,
          marker: { table: 'prime_operator_fixture_marker', run_id: state.run_id,
            fixture_kind: 'prime-memory-operator-pg-synthetic/v1', operator_owned: true },
          memory_role_schema_privileges: ['USAGE', 'CREATE'], memory_role_marker_privileges: ['SELECT'],
          ...(action === 'drop' ? { require_exact_marker_before_drop: true } : {}) })) })
    }
    assert.deepEqual(result.plan, schemaLifecyclePlan(state, config, 'create'))
    assert.throws(() => schemaLifecyclePlan(state, config, 'execute'), { code: 'operator:plan-action-invalid' })
    assert.throws(() => schemaLifecyclePlan({ ...state, source_schema: 'public' }, config, 'drop'), { code: 'operator:invalid-schema-state' })
    assert.throws(() => schemaLifecyclePlan({ ...state, restore_schema: state.source_schema }, config, 'drop'), { code: 'operator:invalid-schema-state' })
    assert.throws(() => schemaLifecyclePlan({ ...state, unexpected: true }, config, 'create'), { code: 'operator:closed-state-required' })
  })
})

test('prepare refuses absent, unplanned, unknown, or retargeted state before pg', async () => {
  await fixtureFiles(async ({ configPath, statePath }) => {
    await assert.rejects(runOperatorPostgres(['prepare', configPath, statePath]), { code: 'operator:planned-state-required' })
  })
  await plannedFixture(async ({ configPath, statePath, state }) => {
    for (const [changed, code] of [[{ ...state, phase: 'preparing' }, 'operator:planned-state-required'],
      [{ ...state, unexpected: 'unplanned' }, 'operator:closed-state-required'],
      [{ ...state, source_schema: 'public' }, 'operator:invalid-schema-state'],
      [{ ...state, config_sha256: '0'.repeat(64) }, 'operator:invalid-state'],
      [{ ...state, run_id: [state.run_id] }, 'operator:invalid-state']]) {
      writeJSON(statePath, changed)
      await assert.rejects(runOperatorPostgres(['prepare', configPath, statePath]), { code })
    }
  })
})

test('prepare refuses a changed schema lifecycle plan before any pg driver use', async () => {
  await plannedFixture(async ({ configPath, statePath, result }) => {
    const changed = { ...result.plan, memory_role_database_create: true }
    writeJSON(result.schema_plan, changed)
    await assert.rejects(runOperatorPostgres(['prepare', configPath, statePath]), { code: 'operator:schema-plan-changed' })
  })
  await plannedFixture(async ({ configPath, statePath, state }) => {
    writeJSON(statePath, { ...state, schema_plan_sha256: '0'.repeat(64) })
    await assert.rejects(runOperatorPostgres(['prepare', configPath, statePath]), { code: 'operator:schema-plan-changed' })
  })
})

test('cleanup-plan refuses unverified or unplanned state before pg; no runner drop command exists', async () => {
  await plannedFixture(async ({ configPath, statePath }) => {
    await assert.rejects(runOperatorPostgres(['cleanup-plan', configPath, statePath]), { code: 'operator:verified-state-required' })
    await assert.rejects(runOperatorPostgres(['cleanup', configPath, statePath]), { code: 'operator:arguments-invalid' })
  })
  await fixtureFiles(async ({ configPath, statePath }) => {
    await assert.rejects(runOperatorPostgres(['cleanup-plan', configPath, statePath]), { code: 'operator:planned-state-required' })
  })
})
