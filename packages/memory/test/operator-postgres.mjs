// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic PostgreSQL storage acceptance only. This file never controls a PostgreSQL process.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'
import { closeSync, constants, existsSync, fsyncSync, lstatSync, openSync, readFileSync,
  realpathSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createPostgresMemory } from '../src/index.mjs'
import { inspectSnapshot } from '../src/snapshot.mjs'
import { sha256 } from '../src/codecs.mjs'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MEMORY_AUDIENCE, memoryReceiptDigest, memoryStateVersion, memoryTarget } from '../src/authorization.mjs'

export const OPERATOR_USAGE = 'operator-postgres.mjs plan|prepare|verify|cleanup-plan CONFIG_JSON STATE_JSON'
const CONFIG_KEYS = 'connectionTimeoutMillis,database,host,max,port,user'
const KIND = 'prime-memory-operator-pg-synthetic/v1'
const ANCHOR_KIND = 'prime-memory-operator-pg-retained-heads/v1'
const PLAN_KIND = 'prime-memory-operator-schema-plan/v1'
const SCHEMA = /^prime_memory_operator_[0-9a-f]{24}_(source|restore)$/
const at = '2026-10-01T11:03:00Z'
const check = (condition, code) => { if (!condition) throw Object.assign(new Error(code), { code }) }
const digest = value => sha256(Buffer.from(canonicalJSON(value)))
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)
const quotedSchema = name => { check(typeof name === 'string' && SCHEMA.test(name), 'operator:invalid-schema'); return '"' + name + '"' }

export function validateOperatorConfig(value) {
  check(value && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).sort().join(',') === CONFIG_KEYS,
    'operator:explicit-closed-config-required')
  check(value.host === '/run/aukora-prime/postgres' && value.port === 55434
    && value.database === 'aukora_prime_synthetic' && value.user === 'prime_memory'
    && Number.isSafeInteger(value.max) && value.max >= 1 && value.max <= 4
    && value.connectionTimeoutMillis === 5000, 'operator:disposable-target-required')
  return Object.freeze({ ...value })
}

function readJSON(path) {
  check(isAbsolute(path) && lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink(), 'operator:regular-absolute-file-required')
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try { return JSON.parse(readFileSync(fd, 'utf8')) } finally { closeSync(fd) }
}
function durableJSON(path, value, { exclusive = false } = {}) {
  check(isAbsolute(path) && realpathSync(dirname(path)) === dirname(path), 'operator:task-owned-real-directory-required')
  if (exclusive) check(!existsSync(path), 'operator:state-already-exists')
  if (existsSync(path)) check(lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink(), 'operator:regular-state-required')
  const temporary = path + '.tmp-' + randomUUID()
  const fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600)
  try { writeFileSync(fd, JSON.stringify(value) + '\n'); fsyncSync(fd) } finally { closeSync(fd) }
  renameSync(temporary, path)
  const directory = openSync(dirname(path), constants.O_RDONLY)
  try { fsyncSync(directory) } finally { closeSync(directory) }
}

export async function primeLocalDriver() {
  const require = createRequire(new URL('../package.json', import.meta.url))
  const primeRoot = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '../../..'))
  let driverManifest, driverEntry
  try { driverManifest = realpathSync(require.resolve('pg/package.json')); driverEntry = realpathSync(require.resolve('pg')) }
  catch { check(false, 'operator:prime-local-pg-8.16.3-unavailable') }
  for (const path of [driverManifest, driverEntry]) {
    const rel = relative(primeRoot, path)
    check(rel && !rel.startsWith('..' + sep) && rel !== '..' && !isAbsolute(rel), 'operator:external-driver-refused')
  }
  check(JSON.parse(readFileSync(driverManifest, 'utf8')).version === '8.16.3', 'operator:pg-version-refused')
  const driver = require('pg')
  check(typeof driver.Pool === 'function', 'operator:pg-pool-unavailable')
  return { Pool: driver.Pool, driverManifest }
}
// A function prevents pg from falling back to PGPASSWORD/pgpass if the socket is misconfigured.
export const poolOptions = (config, schema) => ({ ...config,
  password: () => { check(false, 'operator:password-authentication-refused') }, ssl: false,
  options: (schema ? '-c search_path=' + schema + ' ' : '') + '-c statement_timeout=15000' })

export async function observePostgres(pool) {
  const { rows: [row] } = await pool.query(`SELECT current_database() AS database, current_user AS role,
    inet_server_addr() IS NULL AS unix_socket, current_setting('server_version') AS server_version,
    current_setting('server_version_num')::integer AS server_version_num,
    current_setting('fsync') AS fsync, current_setting('full_page_writes') AS full_page_writes,
    pg_postmaster_start_time() AS postmaster_started_at,
    has_database_privilege(current_user,current_database(),'CREATE') AS database_create,
    has_database_privilege(current_user,current_database(),'TEMPORARY') AS database_temp,
    (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
      FROM pg_roles WHERE rolname=current_user) AS privileged_role`)
  check(row.database === 'aukora_prime_synthetic' && row.role === 'prime_memory' && row.unix_socket === true,
    'operator:connected-target-mismatch')
  check(row.server_version_num >= 160000 && row.server_version_num < 170000
    && row.fsync === 'on' && row.full_page_writes === 'on', 'operator:postgres-durability-profile-refused')
  check(row.database_create === false && row.database_temp === false && row.privileged_role === false,
    'operator:memory-role-privilege-broadening-refused')
  return { ...row, postmaster_started_at: new Date(row.postmaster_started_at).toISOString() }
}
export async function checkMarker(pool, schema, run_id, { absentAllowed = false } = {}) {
  const present = (await pool.query('SELECT 1 FROM pg_namespace WHERE nspname=$1', [schema])).rows.length > 0
  if (!present && absentAllowed) return false
  check(present, 'operator:fixture-schema-missing')
  const {rows:[scope]}=await pool.query(`SELECT r.rolname AS schema_owner,
    has_schema_privilege(current_user,n.oid,'USAGE') AS schema_usage,
    has_schema_privilege(current_user,n.oid,'CREATE') AS schema_create
    FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname=$1`,[schema])
  check(scope && scope.schema_owner!=='prime_memory' && scope.schema_usage===true && scope.schema_create===true,
    'operator:operator-owned-scoped-schema-required')
  let markers
  try { markers = (await pool.query(`SELECT * FROM ${quotedSchema(schema)}.prime_operator_fixture_marker`)).rows }
  catch { check(false, 'operator:unmarked-schema-refused') }
  check(markers.length === 1 && markers[0].run_id === run_id && markers[0].fixture_kind === KIND,
    'operator:fixture-marker-mismatch')
  const {rows:[markerScope]}=await pool.query(`SELECT r.rolname AS marker_owner,
    has_table_privilege(current_user,c.oid,'SELECT') AS marker_select,
    has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS marker_write
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
    WHERE n.nspname=$1 AND c.relname='prime_operator_fixture_marker'`,[schema])
  check(markerScope && markerScope.marker_owner!=='prime_memory' && markerScope.marker_select===true && markerScope.marker_write===false,
    'operator:operator-owned-read-only-marker-required')
  return true
}

function syntheticHost(state, subject = state.owner_subject) {
  const bytes = Buffer.from(JSON.stringify({ type: 'turn', text: 'Synthetic PostgreSQL banana acceptance ' + state.run_id, seq: 0, at }) + '\n')
  return { owner_subject: subject, owner_id: 'synthetic-owner-id:' + state.run_id, task_id: 'synthetic-task:' + state.run_id,
    privacy: 'local', scope: 'owner', attributedTo: 'owner',
    source: { sessionId: 'synthetic-session:' + state.run_id, seq: 0, at, sha256: sha256(bytes) }, events: [bytes] }
}
const extractionOf = state => ({ category: 'fact', statement: 'Synthetic PostgreSQL banana acceptance ' + state.run_id,
  validFrom: '2026-10-01', observedAt: at, confidence: 0.7, sensitivity: 'none' })

// Private test fixture, NOT production C: registered toy operations exercise D's effect protocol only.
function toyFixture() {
  const registered = new Map(), prepared = new Map(), dispatched = new Map(), settled = new Map()
  const calls = { reserve: 0, dispatch: 0, settle: 0 }
  const contracts = {
    operationDigest: operation => 'sha256:' + sha256(Buffer.from('aukora-prime.operation.v1\0' + canonicalJSON(operation))),
    validateContract(kind, value) { assert.equal(value?.version, 1); assert.equal(typeof value, 'object'); return value }
  }
  const register = operation => registered.set(contracts.operationDigest(operation), structuredClone(operation))
  const grantFor = operation => ({ version: 1, grant_id: 'synthetic-grant:' + operation.operation_id,
    operation_id: operation.operation_id, operation_digest: contracts.operationDigest(operation), owner_id: operation.owner_id,
    audience: operation.audience, authorization_epoch: operation.authorization_epoch, prepared_at: at,
    reservation_id: 'synthetic-reservation:' + operation.nonce })
  const authority = {
    reserve({ operation, approval_proof }) {
      const operation_digest = contracts.operationDigest(operation)
      assert.ok(same(operation, registered.get(operation_digest)))
      assert.equal(approval_proof.operation_digest, operation_digest)
      assert.equal(prepared.has(operation_digest), false); assert.equal(dispatched.has(operation_digest), false)
      calls.reserve++; const consumed_grant = grantFor(operation); prepared.set(operation_digest, consumed_grant)
      return { ok: true, status: 'PREPARED', consumed_grant }
    },
    claimDispatch({ operation, consumed_grant, request_id, request_digest }) {
      const operation_digest = contracts.operationDigest(operation)
      assert.deepEqual(consumed_grant, prepared.get(operation_digest))
      assert.match(request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
      assert.match(request_digest, /^sha256:[0-9a-f]{64}$/); assert.equal(dispatched.has(operation_digest), false)
      calls.dispatch++; dispatched.set(operation_digest, { request_id, request_digest })
      return { ok: true, status: 'DISPATCHED', consumed_grant }
    },
    settleMemory({ operation, consumed_grant, request_id, request_digest, receipt }) {
      const operation_digest = contracts.operationDigest(operation)
      assert.ok(same(operation, registered.get(operation_digest))); assert.deepEqual(consumed_grant, grantFor(operation))
      assert.equal(receipt.operation_digest, operation_digest); assert.equal(receipt.request_id, request_id)
      assert.equal(receipt.request_digest, request_digest); assert.equal(receipt.owner_subject, operation.target_identity.owner_subject)
      assert.equal(receipt.action_type, operation.action_type); assert.equal(receipt.status, 'applied')
      const receipt_digest = memoryReceiptDigest(receipt), prior = settled.get(operation_digest)
      assert.ok(!prior || prior === receipt_digest); settled.set(operation_digest, receipt_digest); calls.settle++
      return { ok: true, status: 'COMPLETED', request_id, request_digest, receipt_digest,
        idempotent: Boolean(prior), reconciliation_required: false }
    }
  }
  function authorization(host, action_type, parameters, heads) {
    const operation = { version: 1, operation_id: randomUUID(), task_id: host.task_id, owner_id: host.owner_id,
      agent_id: 'synthetic-agent', audience: MEMORY_AUDIENCE, action_type, target_identity: memoryTarget(host.owner_subject),
      canonical_parameters: structuredClone(parameters), data_scope: ['synthetic'], expected_state_version: memoryStateVersion(heads),
      provider_and_region: { provider: 'local', region: 'local' }, maximum_cost: { currency: 'USD', amount: '0' },
      expiry: '2099-10-01T11:03:00Z', nonce: randomUUID(), policy_version: 'synthetic-policy', authorization_epoch: 0 }
    register(operation)
    return { operation, approval_proof: { version: 1, operation_id: operation.operation_id,
      operation_digest: contracts.operationDigest(operation), owner_id: operation.owner_id, audience: operation.audience,
      authorization_epoch: 0, expiry: operation.expiry, nonce: operation.nonce, material: { kind: 'owner_key', synthetic: true } } }
  }
  return { authority, contracts, calls, authorization, register }
}
function failureProjection(pool) {
  let fail = false
  const query = (target, sql, values) => fail && /^\s*INSERT INTO prime_memory_fts\b/.test(sql)
    ? Promise.reject(Object.assign(new Error('synthetic FTS projection failure'), { code: 'synthetic:index-unavailable' }))
    : target.query(sql, values)
  return { set fail(value) { fail = value }, query: (sql, values) => query(pool, sql, values),
    async connect() { const client = await pool.connect(); return { query: (sql, values) => query(client, sql, values), release: () => client.release() } } }
}
const headsOf = async (pool, owner) => Object.fromEntries((await pool.query(
  'SELECT chain_domain,hash FROM prime_memory_heads WHERE owner_subject=$1 ORDER BY chain_domain', [owner])).rows.map(r => [r.chain_domain, r.hash]))

function validateState(state, config) {
  const fields=['version','kind','synthetic_fixture','phase','run_id','config_sha256','source_schema','restore_schema',
    'owner_subject','other_subject','authority_fixture','driver_version','driver_manifest','schema_plan_sha256',
    'postgres_before','anchor_sha256','snapshot','record','operation','receipt','prepare_checks','failure_code',
    'postgres_after','verify_checks','cleanup_plan_sha256']
  check(state && Object.getPrototypeOf(state)===Object.prototype && Object.keys(state).every(key=>fields.includes(key)),
    'operator:closed-state-required')
  check(state?.version === 1 && state.kind === KIND && state.synthetic_fixture === true
    && typeof state.run_id === 'string' && /^[0-9a-f]{24}$/.test(state.run_id)
    && state.config_sha256 === digest(config), 'operator:invalid-state')
  check(state.source_schema === 'prime_memory_operator_' + state.run_id + '_source'
    && state.restore_schema === 'prime_memory_operator_' + state.run_id + '_restore', 'operator:invalid-schema-state')
  check(state.owner_subject === 'aukora:1:' + sha256(Buffer.from('synthetic-owner:' + state.run_id))
    && state.other_subject === 'aukora:1:' + sha256(Buffer.from('synthetic-other-owner:' + state.run_id)), 'operator:invalid-owner-state')
  return state
}

export function schemaLifecyclePlan(state, config, action) {
  validateOperatorConfig(config);validateState(state,config)
  check(['create','drop'].includes(action),'operator:plan-action-invalid')
  return {version:1,kind:PLAN_KIND,action,run_id:state.run_id,database:config.database,memory_role:config.user,
    schema_names:[state.source_schema,state.restore_schema],exclusive_operator_required:true,
    memory_role_database_create:false,memory_role_database_temp:false,memory_role_schema_owner:false,
    schemas:[state.source_schema,state.restore_schema].map(name=>({name,
      marker:{table:'prime_operator_fixture_marker',run_id:state.run_id,fixture_kind:KIND,operator_owned:true},
      memory_role_schema_privileges:['USAGE','CREATE'],memory_role_marker_privileges:['SELECT'],
      ...(action==='drop'?{require_exact_marker_before_drop:true}: {})}))}
}

function plan(config,statePath) {
  const run_id = randomUUID().replaceAll('-', '').slice(0, 24)
  const state = { version: 1, kind: KIND, synthetic_fixture: true, phase: 'planned', run_id,
    config_sha256: digest(config), source_schema: 'prime_memory_operator_' + run_id + '_source',
    restore_schema: 'prime_memory_operator_' + run_id + '_restore',
    owner_subject: 'aukora:1:' + sha256(Buffer.from('synthetic-owner:' + run_id)),
    other_subject: 'aukora:1:' + sha256(Buffer.from('synthetic-other-owner:' + run_id)),
    authority_fixture: 'private-toy-not-production-C', driver_version: '8.16.3' }
  check(!existsSync(statePath) && !existsSync(statePath+'.schema-create-plan.json') && !existsSync(statePath + '.anchors.json'),
    'operator:state-already-exists')
  const lifecycle=schemaLifecyclePlan(state,config,'create')
  state.schema_plan_sha256=digest(lifecycle)
  durableJSON(statePath, state, { exclusive: true })
  durableJSON(statePath+'.schema-create-plan.json',lifecycle,{exclusive:true})
  return {phase:'planned',state:statePath,schema_plan:statePath+'.schema-create-plan.json',plan:lifecycle,
    PostgreSQL_connected:false,next:'Exclusive PG operator creates only these two marked schemas and grants only their scoped privileges; then run prepare.'}
}

function checkCreatePlan(state,config,statePath) {
  check(existsSync(statePath+'.schema-create-plan.json'),'operator:schema-plan-changed')
  check(digest(schemaLifecyclePlan(state,config,'create'))===state.schema_plan_sha256
    && digest(readJSON(statePath+'.schema-create-plan.json'))===state.schema_plan_sha256,'operator:schema-plan-changed')
}

async function prepare(config, statePath, Pool, driverManifest) {
  const state=validateState(readJSON(statePath),config)
  check(state.phase==='planned','operator:planned-state-required')
  checkCreatePlan(state,config,statePath)
  const run_id=state.run_id
  check(!existsSync(statePath+'.anchors.json'),'operator:anchor-already-exists')
  const bootstrap = new Pool(poolOptions(config)); let pool
  try {
    state.postgres_before = await observePostgres(bootstrap)
    for (const schema of [state.source_schema, state.restore_schema]) await checkMarker(bootstrap, schema, run_id)
    state.driver_manifest=driverManifest
    pool = new Pool(poolOptions(config, state.source_schema))
    const fault = failureProjection(pool), toy = toyFixture()
    const memory = createPostgresMemory({ pool: fault, authority: toy.authority, contracts: toy.contracts })
    await memory.migrate()
    assert.equal(typeof memory.captureRemembered, 'undefined'); assert.equal(typeof memory.tombstoneRecord, 'undefined')
    const host = syntheticHost(state), extraction = extractionOf(state), key = 'synthetic-capture:' + run_id
    const binding = await memory.prepareCaptureBinding(host, extraction, key)
    assert.deepEqual(binding.memory_capture, { statement: extraction.statement, attributed_to: host.attributedTo })
    const authorization = toy.authorization(host, 'memory.save', binding.canonical_parameters, binding.canonical_parameters.heads)
    const saved = await Promise.all([0, 1, 2].map(() => memory.captureAuthorizedRemembered(host, extraction, key, authorization)))
    assert.deepEqual(saved[1], saved[0]); assert.deepEqual(saved[2], saved[0]); assert.deepEqual(toy.calls, { reserve: 1, dispatch: 1, settle: 1 })
    const result = saved[0]; assert.equal(result.authority_settlement, 'completed')
    assert.equal(result.record.storage_status, 'saved'); assert.equal(result.record.index_status, 'pending')
    assert.equal((await memory.status(host, result.record.record_id)).searchable, false)
    assert.equal((await memory.cite(host, result.record.record_id)).verdict, 'VERIFIED')
    assert.equal((await memory.recall(host, { query: 'banana' })).records.length, 0)
    for (const table of ['prime_memory_records', 'prime_memory_requests', 'prime_memory_effects', 'prime_memory_intents']) {
      assert.equal(Number((await pool.query('SELECT count(*) AS n FROM ' + table)).rows[0].n), 1)
    }
    const replayFenceRows=await pool.query('SELECT owner_subject,operation_id,operation_digest,grant_id,action,request_id,request_digest,status FROM prime_memory_replay_fences WHERE owner_subject=$1',[state.owner_subject])
    assert.equal(replayFenceRows.rows.length,0)
    fault.fail = true; assert.equal((await memory.drainOutbox(host)).failed, 1)
    const failed = await memory.status(host, result.record.record_id)
    assert.equal(failed.saved, true); assert.equal(failed.record.index_status, 'failed'); assert.equal(failed.searchable, false)
    fault.fail = false; assert.equal((await memory.drainOutbox(host)).indexed, 1)
    const indexed = await memory.status(host, result.record.record_id)
    assert.equal(indexed.searchable, true); assert.equal(indexed.record.canonical_bytes, result.record.canonical_bytes)
    assert.equal((await memory.recall(host, { query: 'banana' })).records[0].citation.verdict, 'VERIFIED')
    assert.equal((await memory.recall(syntheticHost(state, state.other_subject), { query: 'banana' })).records.length, 0)
    await assert.rejects(memory.cite(syntheticHost(state, state.other_subject), result.record.record_id), { code: 'memory:record-missing' })
    // Retain complete live control state separately before generating the data snapshot.
    const retainedHeads = await headsOf(pool, state.owner_subject)
    const controlState=await memory.exportControlState(host)
    durableJSON(statePath + '.anchors.json', { version: 1, kind: ANCHOR_KIND, run_id, owner_subject: state.owner_subject,
      owner_id:host.owner_id,authorization_epoch:authorization.operation.authorization_epoch,
      config_sha256: state.config_sha256, heads: retainedHeads, control_state:controlState }, { exclusive: true })
    state.anchor_sha256 = sha256(readFileSync(statePath + '.anchors.json'))
    state.snapshot = await memory.exportSnapshot(host)
    assert.deepEqual(state.snapshot.heads, retainedHeads)
    assert.equal(inspectSnapshot(state.snapshot, state.owner_subject, { expectedHeads: retainedHeads }).anchored, true)
    state.record = result.record; state.operation = authorization.operation; state.receipt = result.receipt
    state.prepare_checks = ['three-concurrent-exact-saves-one-effect', 'saved-pending-distinct', 'failed-index-still-saved',
      'FTS-retry-searchable', 'original-bytes-citation', 'owner-filter', 'independent-retained-heads']
    state.phase = 'prepared'; durableJSON(statePath, state)
    return { phase: 'prepared', state: statePath, schemas: [state.source_schema, state.restore_schema],
      checks: state.prepare_checks, postgres: state.postgres_before, authority_fixture: state.authority_fixture,
      control_retention_profile:'explicit-toy-host-provider/not-production-file-reader',new_replay_fence_schema_checked:true,
      next: 'Operator restarts the isolated PostgreSQL cluster, then runs verify with the same config and state files.' }
  } catch (error) { state.phase = 'prepare-failed'; state.failure_code = error.code ?? 'operator:check-failed'; durableJSON(statePath, state); throw error }
  finally { if (pool) await pool.end(); await bootstrap.end() }
}

async function verify(config, statePath, Pool) {
  const state = validateState(readJSON(statePath), config)
  check(['prepared', 'verified'].includes(state.phase), 'operator:prepare-incomplete')
  const anchorPath = statePath + '.anchors.json', anchor = readJSON(anchorPath)
  check(sha256(readFileSync(anchorPath)) === state.anchor_sha256 && anchor.version === 1 && anchor.kind === ANCHOR_KIND
    && anchor.run_id === state.run_id && anchor.owner_subject === state.owner_subject && anchor.config_sha256 === state.config_sha256,
    'operator:retained-anchor-changed')
  const bootstrap = new Pool(poolOptions(config)); let source, restored
  try {
    const postgres_after = await observePostgres(bootstrap)
    check(Date.parse(postgres_after.postmaster_started_at) > Date.parse(state.postgres_before.postmaster_started_at),
      'operator:restart-not-observed')
    for (const schema of [state.source_schema, state.restore_schema]) await checkMarker(bootstrap, schema, state.run_id)
    source = new Pool(poolOptions(config, state.source_schema)); restored = new Pool(poolOptions(config, state.restore_schema))
    const host = syntheticHost(state), toy = toyFixture(); toy.register(state.operation)
    const memory = createPostgresMemory({ pool: source, authority: toy.authority, contracts: toy.contracts })
    await memory.migrate()
    const cold = await memory.status(host, state.record.record_id)
    assert.equal(cold.saved, true); assert.equal(cold.searchable, true); assert.equal(cold.record.canonical_bytes, state.record.canonical_bytes)
    assert.equal((await memory.cite(host, state.record.record_id)).verdict, 'VERIFIED')
    assert.equal((await memory.recall(host, { query: 'banana' })).records[0].record.canonical_bytes, state.record.canonical_bytes)
    assert.equal((await memory.recall(syntheticHost(state, state.other_subject), { query: 'banana' })).records.length, 0)
    await assert.rejects(memory.cite(syntheticHost(state, state.other_subject), state.record.record_id), { code: 'memory:record-missing' })
    const reconciled = await memory.reconcileEffect(host, state.operation.operation_id)
    assert.equal(reconciled.authority_settlement, 'completed'); assert.deepEqual(reconciled.receipt, state.receipt)
    assert.deepEqual(toy.calls, { reserve: 0, dispatch: 0, settle: 1 })
    const exported = await memory.exportSnapshot(host)
    assert.deepEqual(exported.heads, anchor.heads)
    const checked = inspectSnapshot(exported, state.owner_subject, { expectedHeads: anchor.heads })
    assert.equal(checked.anchored, true); assert.equal(checked.records.length, 1)
    const restoreAnchorProvider = async trustedHost => {
      assert.equal(trustedHost.owner_subject, state.owner_subject)
      const independent = readJSON(anchorPath)
      check(sha256(readFileSync(anchorPath)) === state.anchor_sha256, 'operator:retained-anchor-changed')
      check(trustedHost.owner_id===independent.owner_id && independent.authorization_epoch===state.operation.authorization_epoch,
        'operator:retained-owner-epoch-changed')
      check(independent.control_state && canonicalJSON(independent.control_state.heads)===canonicalJSON(independent.heads),
        'operator:independent-control-anchor-required')
      return structuredClone(independent.control_state)
    }
    const restoredMemory = createPostgresMemory({ pool: restored, authority: toy.authority, contracts: toy.contracts, restoreAnchorProvider })
    await restoredMemory.migrate()
    const restoreHeads = await headsOf(restored, state.owner_subject)
    const authorization = toy.authorization(host, 'memory.restore', { manifest_sha256: exported.manifest_sha256,
      mode: 'prime-restore', heads: exported.heads, retained_heads: anchor.heads,
      control_anchor_sha256:anchor.control_state?.control_sha256 }, restoreHeads)
    const result = await restoredMemory.restoreSnapshot(host, exported, { ...authorization, expectedHeads: anchor.heads })
    assert.ok(result.imported === 1 || result.already_imported === true)
    const restoredStatus = await restoredMemory.status(host, state.record.record_id)
    assert.equal(restoredStatus.saved, true); assert.equal(restoredStatus.record.canonical_bytes, state.record.canonical_bytes)
    assert.equal((await restoredMemory.cite(host, state.record.record_id)).verdict, 'VERIFIED')
    await restoredMemory.drainOutbox(host)
    assert.equal((await restoredMemory.recall(host, { query: 'banana' })).records[0].record.canonical_bytes, state.record.canonical_bytes)
    state.phase = 'verified'; state.postgres_after = postgres_after
    state.verify_checks = ['operator-restart-observed', 'saved-FTS-bytes-survive-cold-process', 'cold-owner-filter-citation',
      'committed-receipt-reconcile-no-reserve-or-dispatch', 'Prime-only-independent-head-cold-verification', 'fresh-schema-anchored-restore']
    durableJSON(statePath, state)
    return { phase: 'verified', state: statePath, checks: state.verify_checks, postgres: postgres_after,
      control_retention_profile:'explicit-toy-host-provider/not-production-file-reader',new_replay_fence_schema_checked:true,
      authority_fixture: state.authority_fixture, production_C_tested: false, private_memory_imported: false }
  } finally { if (source) await source.end(); if (restored) await restored.end(); await bootstrap.end() }
}

async function cleanupPlan(config, statePath, Pool) {
  const state = validateState(readJSON(statePath), config), bootstrap = new Pool(poolOptions(config))
  check(state.phase==='verified','operator:verified-state-required')
  try {
    await observePostgres(bootstrap)
    for (const schema of [state.source_schema, state.restore_schema]) {
      await checkMarker(bootstrap,schema,state.run_id)
    }
    const lifecycle=schemaLifecyclePlan(state,config,'drop')
    durableJSON(statePath+'.schema-cleanup-plan.json',lifecycle)
    state.cleanup_plan_sha256=digest(lifecycle)
    durableJSON(statePath, state)
    return { phase: 'cleanup-planned',schemas_dropped:[],state:statePath,schema_plan:statePath+'.schema-cleanup-plan.json',
      plan:lifecycle,exclusive_operator_required:true,postgres_process_unchanged: true,
      physical_media_erasure: false, backup_or_WAL_erasure: false }
  } finally { await bootstrap.end() }
}

export async function runOperatorPostgres(argv) {
  if (argv.length === 1 && ['--help', 'help'].includes(argv[0])) return { usage: OPERATOR_USAGE,
    scope: 'Explicit operator-managed disposable PostgreSQL storage acceptance; synthetic data and private toy authority only.' }
  check(argv.length === 3 && ['plan','prepare', 'verify', 'cleanup-plan'].includes(argv[0]), 'operator:arguments-invalid')
  const [phase, configPath, statePath] = argv
  check(isAbsolute(configPath) && isAbsolute(statePath) && configPath !== statePath, 'operator:absolute-task-owned-paths-required')
  const config = validateOperatorConfig(readJSON(configPath))
  if(phase==='plan') return plan(config,statePath)
  check(existsSync(statePath),'operator:planned-state-required')
  const state=validateState(readJSON(statePath),config)
  check(phase==='prepare'?state.phase==='planned':phase==='verify'?['prepared','verified'].includes(state.phase):state.phase==='verified',
    phase==='cleanup-plan'?'operator:verified-state-required':'operator:planned-state-required')
  if(phase==='prepare') checkCreatePlan(state,config,statePath)
  const { Pool, driverManifest } = await primeLocalDriver()
  return phase === 'prepare' ? prepare(config, statePath, Pool, driverManifest)
    : phase === 'verify' ? verify(config, statePath, Pool) : cleanupPlan(config, statePath, Pool)
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runOperatorPostgres(process.argv.slice(2)).then(result => process.stdout.write(JSON.stringify(result) + '\n')).catch(error => {
    process.stderr.write(JSON.stringify({ verdict: 'REFUSED', reason: error.code ?? 'operator:check-failed',
      detail: error.code ? undefined : error.message, PostgreSQL_acceptance_passed: false }) + '\n')
    process.exitCode = 1
  })
}
