// SPDX-License-Identifier: AGPL-3.0-or-later
// Bounded storage helpers for the genuine C/D private-worker synthetic join.
// H owns test processes; the exclusive PostgreSQL operator owns schema/cluster lifecycle.
import { randomUUID } from 'node:crypto'
import { closeSync, constants, existsSync, fsyncSync, linkSync, lstatSync, openSync,
  realpathSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { createPostgresMemory } from '../src/index.mjs'
import { parseOriginal, sha256, validateOriginal } from '../src/codecs.mjs'
import { validateCaptureLiterals, validateCaptureReview } from '../src/capture-review.mjs'
import { SENSITIVITIES } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'
import { MEMORY_AUDIENCE, memoryEffectDigest, memoryReceiptDigest, memoryResultDigest,
  memoryTarget } from '../src/authorization.mjs'
import { checkMarker, observePostgres, poolOptions, primeLocalDriver,
  schemaLifecyclePlan, validateOperatorConfig } from './operator-postgres.mjs'

const KIND = 'prime-memory-private-worker-pg-fixture/v1'
const HEX = /^[0-9a-f]{64}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const poolScopes = new WeakMap()
const check = (condition, code) => { if (!condition) throw Object.assign(new Error(code), { code }) }
const digest = value => sha256(Buffer.from(canonicalJSON(value)))
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)
const hash = value => typeof value === 'string' && HEX.test(value)
const boundDigest = value => typeof value === 'string' && DIGEST.test(value)
const boundedString = (value, maximum) => typeof value === 'string' && value.length > 0
  && value.length <= maximum && !/[\u0000-\u001f\u007f]/u.test(value)

function closed(value, fields, code) {
  check(value && Object.getPrototypeOf(value) === Object.prototype && Reflect.ownKeys(value).length === fields.length
    && Object.keys(value).sort().join(',') === [...fields].sort().join(','), code)
  for (const key of fields) {
    const property = Object.getOwnPropertyDescriptor(value, key)
    check(property && Object.hasOwn(property, 'value') && property.enumerable === true, code)
  }
  return value
}
function boundedObject(value, required, optional, code) {
  check(value && Object.getPrototypeOf(value) === Object.prototype, code)
  const keys = Reflect.ownKeys(value)
  check(required.every(key => keys.includes(key)) && keys.every(key => typeof key === 'string'
    && [...required, ...optional].includes(key)), code)
  return closed(value, keys, code)
}
function denseArray(value, minimum, maximum, code) {
  check(Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype
    && value.length >= minimum && value.length <= maximum
    && Reflect.ownKeys(value).length === value.length + 1, code)
  for (let i = 0; i < value.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i))
    check(descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable === true, code)
  }
}
function immutable(value) {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) immutable(item)
    Object.freeze(value)
  }
  return value
}
function configOf(config) {
  closed(config, ['host', 'port', 'database', 'user', 'max', 'connectionTimeoutMillis'], 'worker-pg:closed-config-required')
  return validateOperatorConfig(config)
}
function identities(run_id) {
  const owner = (prefix, taskPrefix, conversationPrefix) => {
    const owner_id = prefix + run_id
    return { owner_id, owner_subject: 'aukora:1:' + sha256(Buffer.from(owner_id)),
      task_id: taskPrefix + run_id, conversation_id: conversationPrefix + run_id }
  }
  return {
    primary: owner('synthetic-owner:', 'synthetic-pg-task:', 'synthetic-pg-conversation:'),
    secondary: owner('synthetic-other-owner:', 'synthetic-pg-other-task:', 'synthetic-pg-other-conversation:')
  }
}
function operatorState(fixture) {
  return { version: 1, kind: 'prime-memory-operator-pg-synthetic/v1', synthetic_fixture: true, phase: 'planned',
    run_id: fixture.run_id, config_sha256: fixture.config_sha256, source_schema: fixture.source_schema,
    restore_schema: fixture.restore_schema, owner_subject: fixture.owners.primary.owner_subject,
    other_subject: fixture.owners.secondary.owner_subject,
    authority_fixture: 'production-C-private-IPC-synthetic-passkey', driver_version: '8.16.3' }
}
function lifecycle(fixture, config) { return schemaLifecyclePlan(operatorState(fixture), config, 'create') }
function fixtureShape(fixture) {
  closed(fixture, ['version', 'kind', 'synthetic_fixture', 'run_id', 'config_sha256', 'source_schema',
    'restore_schema', 'owners', 'agent_id', 'schema_plan_sha256'], 'worker-pg:closed-fixture-required')
  check(fixture.version === 1 && fixture.kind === KIND && fixture.synthetic_fixture === true
    && typeof fixture.run_id === 'string' && /^[0-9a-f]{24}$/.test(fixture.run_id), 'worker-pg:invalid-fixture')
  check(hash(fixture.config_sha256), 'worker-pg:config-binding-changed')
  check(fixture.source_schema === 'prime_memory_operator_' + fixture.run_id + '_source'
    && fixture.restore_schema === 'prime_memory_operator_' + fixture.run_id + '_restore', 'worker-pg:schema-binding-changed')
  closed(fixture.owners, ['primary', 'secondary'], 'worker-pg:closed-owners-required')
  const expectedOwners = identities(fixture.run_id)
  for (const name of ['primary', 'secondary']) {
    closed(fixture.owners[name], ['owner_id', 'owner_subject', 'task_id', 'conversation_id'], 'worker-pg:closed-owner-required')
    check(same(fixture.owners[name], expectedOwners[name]), 'worker-pg:owner-binding-changed')
  }
  check(fixture.agent_id === 'synthetic-agent' && hash(fixture.schema_plan_sha256), 'worker-pg:schema-plan-binding-changed')
  return expectedOwners
}

/** Pure shape/digest validation. It does not discover PostgreSQL or trust a synthetic label as authority. */
export function validateWorkerPostgresFixture(fixture, config) {
  const checkedConfig = configOf(config), expectedOwners = fixtureShape(fixture)
  check(fixture.config_sha256 === digest(checkedConfig), 'worker-pg:config-binding-changed')
  check(fixture.schema_plan_sha256 === digest(lifecycle(fixture, checkedConfig)), 'worker-pg:schema-plan-binding-changed')
  return immutable({ ...fixture, owners: expectedOwners })
}

/** Pure exact-name lifecycle adapter. Only the exclusive operator may execute its plan. */
export function workerPostgresSchemaPlan({ config, fixture, action } = {}) {
  const checkedConfig = configOf(config), checkedFixture = validateWorkerPostgresFixture(fixture, checkedConfig)
  check(action === 'create' || action === 'drop', 'worker-pg:schema-plan-action-invalid')
  return immutable(schemaLifecyclePlan(operatorState(checkedFixture), checkedConfig, action))
}

/** Synthetic controller-only private preimage comparison; no browser, C proof, builder, or new record ID. */
export function expectedWorkerCaptureDigests(arguments_) {
  closed(arguments_, ['config', 'fixture', 'owner', 'host', 'extraction', 'idempotencyKey'], 'worker-pg:closed-capture-input-required')
  const { config, fixture, owner: ownerName, host, extraction, idempotencyKey } = arguments_
  const checkedFixture = validateWorkerPostgresFixture(fixture, config)
  check(ownerName === 'primary' || ownerName === 'secondary', 'worker-pg:capture-owner-invalid')
  const owner = checkedFixture.owners[ownerName]
  boundedObject(host, ['owner_id', 'owner_subject', 'task_id', 'privacy', 'scope', 'attributedTo', 'source', 'events'],
    ['conversation_id', 'evidence', 'bodyAtCapture', 'origin', 'offTheRecord', 'paused'], 'worker-pg:closed-capture-host-required')
  check(host.owner_id === owner.owner_id && host.owner_subject === owner.owner_subject && host.task_id === owner.task_id
    && (!Object.hasOwn(host, 'conversation_id') || host.conversation_id === owner.conversation_id), 'worker-pg:capture-host-owner-changed')
  check(host.privacy === 'local' && host.scope === 'owner' && host.attributedTo === 'owner'
    && (!Object.hasOwn(host, 'offTheRecord') || host.offTheRecord === false)
    && (!Object.hasOwn(host, 'paused') || host.paused === false)
    && (!Object.hasOwn(host, 'evidence') || host.evidence === null)
    && (!Object.hasOwn(host, 'bodyAtCapture') || host.bodyAtCapture === null), 'worker-pg:capture-profile-refused')
  if (Object.hasOwn(host, 'origin')) {
    closed(host.origin, ['by'], 'worker-pg:capture-origin-refused')
    check(host.origin.by === 'prime.capture/v1', 'worker-pg:capture-origin-refused')
  }
  closed(host.source, ['sessionId', 'seq', 'at', 'sha256'], 'worker-pg:closed-capture-source-required')
  check(boundedString(host.source.sessionId, 256) && Number.isSafeInteger(host.source.seq) && host.source.seq >= 0
    && typeof host.source.at === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(host.source.at)
    && Number.isFinite(Date.parse(host.source.at)) && new Date(host.source.at).toISOString().replace('.000Z', 'Z') === host.source.at
    && hash(host.source.sha256), 'worker-pg:capture-source-invalid')
  denseArray(host.events, 1, 8, 'worker-pg:capture-events-invalid')
  const events = host.events.map(bytes => {
    check(bytes instanceof Uint8Array && bytes.byteLength > 0 && bytes.byteLength <= 65536, 'worker-pg:capture-event-bytes-invalid')
    const copy = Buffer.from(bytes), event = parseOriginal(copy)
    check(event && Object.getPrototypeOf(event) === Object.prototype && typeof event.text === 'string' && event.text.length > 0,
      'worker-pg:capture-event-text-required')
    return { bytes: copy, sha256: sha256(copy), event }
  })
  const selected = events.find(event => event.sha256 === host.source.sha256)
  check(selected && selected.event.seq === host.source.seq && selected.event.at === host.source.at, 'worker-pg:capture-source-event-mismatch')
  boundedObject(extraction, ['category', 'statement', 'validFrom', 'observedAt', 'confidence', 'sensitivity'],
    ['links'], 'worker-pg:closed-capture-extraction-required')
  const draft = validateCaptureLiterals({ statement: extraction.statement, attributed_to: 'owner' })
  check(boundedString(extraction.category, 128) && typeof extraction.validFrom === 'string'
    && /^\d{4}-\d{2}-\d{2}$/.test(extraction.validFrom) && typeof extraction.observedAt === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(extraction.observedAt)
    && Number.isFinite(extraction.confidence) && extraction.confidence >= 0 && extraction.confidence <= 1
    && SENSITIVITIES.includes(extraction.sensitivity), 'worker-pg:capture-extraction-invalid')
  if (Object.hasOwn(extraction, 'links')) {
    denseArray(extraction.links, 0, 16, 'worker-pg:capture-links-invalid')
    for (const link of extraction.links) {
      closed(link, ['relation', 'id'], 'worker-pg:capture-links-invalid')
      check(boundedString(link.relation, 128) && boundedString(link.id, 256), 'worker-pg:capture-links-invalid')
    }
  }
  check(typeof idempotencyKey === 'string' && idempotencyKey.length > 0 && idempotencyKey.length <= 1024,
    'worker-pg:capture-idempotency-key-invalid')
  const input = structuredClone(extraction), source = { ...host.source }
  const capture = { input, subject: owner.owner_subject, task: owner.task_id, source, evidence: null,
    attribution: 'owner', scope: 'owner', privacy: 'local', origin: { by: 'prime.capture/v1' }, bodyAtCapture: null,
    events: events.map(event => event.sha256) }
  return immutable({ capture_sha256: digest(capture), idempotency_key_sha256: sha256(Buffer.from(idempotencyKey)),
    statement: draft.statement, attributed_to: draft.attributed_to })
}

function durableExclusiveJSON(path, value) {
  check(typeof path === 'string' && isAbsolute(path)
    && realpathSync(dirname(path)) === dirname(path) && lstatSync(dirname(path)).isDirectory(),
  'worker-pg:real-absolute-state-directory-required')
  check(!existsSync(path), 'worker-pg:state-already-exists')
  const temporary = path + '.tmp-' + randomUUID()
  let fd
  try {
    fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)
    writeFileSync(fd, JSON.stringify(value) + '\n'); fsyncSync(fd); closeSync(fd); fd = undefined
    // Atomic no-overwrite publication after the complete mode-0600 file is durable.
    linkSync(temporary, path)
    const directory = openSync(dirname(path), constants.O_RDONLY)
    try { fsyncSync(directory) } finally { closeSync(directory) }
  } finally {
    if (fd !== undefined) closeSync(fd)
    if (existsSync(temporary)) unlinkSync(temporary)
  }
}

/** Emits only synthetic identities and an operator DDL plan; no PG import/connection or secrets. */
export function planWorkerPostgresFixture({ config, statePath } = {}) {
  const checkedConfig = configOf(config)
  check(typeof statePath === 'string' && isAbsolute(statePath), 'worker-pg:absolute-state-path-required')
  const schemaPlanPath = statePath + '.schema-create-plan.json'
  check(!existsSync(statePath) && !existsSync(schemaPlanPath), 'worker-pg:state-already-exists')
  const run_id = randomUUID().replaceAll('-', '').slice(0, 24)
  const fixture = { version: 1, kind: KIND, synthetic_fixture: true, run_id,
    config_sha256: digest(checkedConfig), source_schema: 'prime_memory_operator_' + run_id + '_source',
    restore_schema: 'prime_memory_operator_' + run_id + '_restore', owners: identities(run_id), agent_id: 'synthetic-agent',
    schema_plan_sha256: '' }
  const plan = lifecycle(fixture, checkedConfig)
  fixture.schema_plan_sha256 = digest(plan)
  const checkedFixture = validateWorkerPostgresFixture(fixture, checkedConfig)
  durableExclusiveJSON(statePath, checkedFixture)
  durableExclusiveJSON(schemaPlanPath, plan)
  return immutable({ fixture: checkedFixture, state_path: statePath, schema_plan_path: schemaPlanPath,
    plan, PostgreSQL_connected: false })
}

function assignedMemoryUID(memoryUid) {
  check(Number.isSafeInteger(memoryUid) && memoryUid > 0 && typeof process.getuid === 'function'
    && typeof process.geteuid === 'function' && process.getuid() === memoryUid && process.geteuid() === memoryUid,
  'worker-pg:assigned-memory-uid-required')
  check(!Object.keys(process.env).some(name => /^PG/i.test(name)), 'worker-pg:postgres-environment-refused')
}
function selectedSchema(fixture, schema) {
  check(schema === 'source' || schema === 'restore', 'worker-pg:schema-selection-invalid')
  return schema === 'source' ? fixture.source_schema : fixture.restore_schema
}
async function observeScope(pool, fixture, schemaName) {
  const postgres = await observePostgres(pool)
  await checkMarker(pool, schemaName, fixture.run_id)
  const { rows: [scope] } = await pool.query("SELECT current_schema() AS schema, current_setting('search_path') AS search_path")
  check(scope?.schema === schemaName && scope.search_path === schemaName, 'worker-pg:search-path-scope-changed')
  return postgres
}

/** Sole pool factory: real Prime-local pg 8.16.3, Unix socket peer role and exact marked schema. */
export async function createWorkerPostgresPool({ config, fixture, schema, memoryUid } = {}) {
  const checkedConfig = configOf(config), checkedFixture = validateWorkerPostgresFixture(fixture, checkedConfig)
  const schemaName = selectedSchema(checkedFixture, schema)
  assignedMemoryUID(memoryUid)
  const { Pool } = await primeLocalDriver()
  const pool = new Pool(poolOptions(checkedConfig, schemaName))
  try {
    await observeScope(pool, checkedFixture, schemaName)
    poolScopes.set(pool, { fixture: checkedFixture, config: checkedConfig, schema, schemaName, memoryUid })
    return pool
  } catch (error) { await pool.end().catch(() => {}); throw error }
}

/** Explicit memory-UID-only table migration. It never creates/drops a schema or alters a role. */
export async function initializeWorkerPostgresSchema(arguments_) {
  const pool = await createWorkerPostgresPool(arguments_)
  try {
    await createPostgresMemory({ pool }).migrate()
    const scope = poolScopes.get(pool), postgres = await observeScope(pool, scope.fixture, scope.schemaName)
    return immutable({ initialized: true, schema: scope.schemaName,
      checks: ['assigned-memory-uid', 'real-Prime-pg-8.16.3', 'durable-Unix-socket-endpoint',
        'no-database-CREATE-TEMP-or-elevated-role', 'operator-owned-read-only-marker', 'exact-schema-table-migration'], postgres })
  } finally { await pool.end() }
}

export function validateWorkerPostgresSaveExpectation(expected, fixture) {
  fixtureShape(fixture)
  closed(expected, ['version', 'owner', 'operation_id', 'operation_digest', 'record_id', 'canonical_sha256',
    'retained_head', 'storage_status', 'index_status', 'receipt', 'settlement_binding'], 'worker-pg:closed-save-expectation-required')
  check(expected.version === 1 && ['primary', 'secondary'].includes(expected.owner)
    && fixture?.owners?.[expected.owner], 'worker-pg:expectation-owner-invalid')
  check(boundedString(expected.operation_id, 128) && boundDigest(expected.operation_digest)
    && typeof expected.record_id === 'string' && /^rem:[0-9a-f]{64}$/.test(expected.record_id)
    && hash(expected.canonical_sha256) && hash(expected.retained_head)
    && expected.storage_status === 'saved' && ['pending', 'failed', 'indexed', 'searchable'].includes(expected.index_status),
  'worker-pg:save-expectation-invalid')
  closed(expected.receipt, ['request_id', 'request_digest', 'receipt_digest', 'grant_id', 'result_digest'],
    'worker-pg:closed-receipt-expectation-required')
  check(typeof expected.receipt.request_id === 'string' && UUID.test(expected.receipt.request_id)
    && boundDigest(expected.receipt.request_digest) && boundDigest(expected.receipt.receipt_digest)
    && boundedString(expected.receipt.grant_id, 256) && boundDigest(expected.receipt.result_digest),
  'worker-pg:receipt-expectation-invalid')
  closed(expected.settlement_binding, ['authority_settlement', 'reconciliation_required', 'receipt_digest'],
    'worker-pg:closed-settlement-binding-required')
  check(expected.settlement_binding.authority_settlement === 'completed'
    && expected.settlement_binding.reconciliation_required === false
    && expected.settlement_binding.receipt_digest === expected.receipt.receipt_digest,
  'worker-pg:expected-completed-settlement-required')
  return immutable({ ...expected, receipt: { ...expected.receipt }, settlement_binding: { ...expected.settlement_binding } })
}

function ledgerJSON(bytes, code) {
  const value = parseOriginal(bytes)
  check(Buffer.from(bytes).equals(Buffer.from(canonicalJSON(value))), code)
  return value
}
function trustedReadHost(owner) {
  return { ...owner, scope: 'owner', privacy: 'local', attributedTo: 'owner', permittedScopes: ['owner'], permittedPrivacy: ['local'] }
}
async function primeContracts() {
  try {
    const root = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), '../../..'))
    const entry = realpathSync(fileURLToPath(new URL('../../contracts/src/runtime.mjs', import.meta.url)))
    const rel = relative(root, entry)
    check(rel && rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel), 'worker-pg:external-contracts-refused')
    const contracts = await import(pathToFileURL(entry).href)
    check(typeof contracts.operationDigest === 'function' && typeof contracts.validateContract === 'function',
      'worker-pg:Prime-contracts-unavailable')
    return contracts
  } catch (error) {
    if (error.code?.startsWith('worker-pg:')) throw error
    check(false, 'worker-pg:Prime-contracts-unavailable')
  }
}

/** Verify committed D facts only. C settlement evidence comes separately from authenticated private-worker IPC. */
export async function verifyWorkerPostgresSave({ pool, fixture, expected, project = false } = {}) {
  const scope = poolScopes.get(pool)
  check(scope, 'worker-pg:factory-scoped-pool-required')
  assignedMemoryUID(scope.memoryUid)
  const checkedFixture = validateWorkerPostgresFixture(fixture, scope.config)
  check(same(checkedFixture, scope.fixture), 'worker-pg:pool-fixture-binding-changed')
  const expectation = validateWorkerPostgresSaveExpectation(expected, checkedFixture)
  check(typeof project === 'boolean', 'worker-pg:projection-option-invalid')
  await observeScope(pool, checkedFixture, scope.schemaName)
  const contracts = await primeContracts()
  const owner = checkedFixture.owners[expectation.owner], host = trustedReadHost(owner)
  const { rows: effects } = await pool.query('SELECT * FROM prime_memory_effects WHERE owner_subject=$1 AND operation_id=$2',
    [owner.owner_subject, expectation.operation_id])
  check(effects.length === 1, 'worker-pg:committed-save-effect-required')
  const effect = effects[0]
  const operation = ledgerJSON(effect.operation_bytes, 'worker-pg:operation-ledger-encoding-changed')
  const grant = ledgerJSON(effect.grant_bytes, 'worker-pg:grant-ledger-encoding-changed')
  const request = ledgerJSON(effect.request_bytes, 'worker-pg:request-ledger-encoding-changed')
  const receipt = ledgerJSON(effect.receipt_bytes, 'worker-pg:receipt-ledger-encoding-changed')
  const result = ledgerJSON(effect.result_bytes, 'worker-pg:result-ledger-encoding-changed')
  contracts.validateContract('OperationProposal', operation); contracts.validateContract('ConsumedGrant', grant)
  contracts.validateContract('MemoryRecord', result)
  check(operation.operation_id === expectation.operation_id && operation.owner_id === owner.owner_id
    && operation.owner_id !== owner.owner_subject && operation.task_id === owner.task_id
    && operation.agent_id === checkedFixture.agent_id && operation.action_type === 'memory.save'
    && operation.audience === MEMORY_AUDIENCE && same(operation.target_identity, memoryTarget(owner.owner_subject))
    && contracts.operationDigest(operation) === expectation.operation_digest && effect.operation_digest === expectation.operation_digest
    && effect.owner_subject === owner.owner_subject && effect.operation_id === expectation.operation_id && effect.action === 'memory.save',
  'worker-pg:save-operation-binding-changed')
  check(grant.grant_id === expectation.receipt.grant_id && effect.grant_id === grant.grant_id
    && grant.operation_id === expectation.operation_id && grant.operation_digest === expectation.operation_digest
    && grant.owner_id === owner.owner_id && grant.audience === operation.audience
    && grant.authorization_epoch === operation.authorization_epoch, 'worker-pg:save-grant-binding-changed')
  closed(request, ['version', 'action_type', 'owner_subject', 'operation_id', 'operation_digest', 'parameters'],
    'worker-pg:closed-effect-request-required')
  check(request.version === 1 && request.action_type === 'memory.save' && request.owner_subject === owner.owner_subject
    && request.operation_id === expectation.operation_id && request.operation_digest === expectation.operation_digest
    && same(request.parameters, operation.canonical_parameters) && memoryEffectDigest(request) === expectation.receipt.request_digest
    && effect.request_id === expectation.receipt.request_id && effect.request_digest === expectation.receipt.request_digest,
  'worker-pg:save-request-binding-changed')
  closed(receipt, ['version', 'kind', 'operation_id', 'operation_digest', 'grant_id', 'request_id', 'request_digest',
    'owner_subject', 'action_type', 'status', 'result_digest', 'result'], 'worker-pg:closed-effect-receipt-required')
  check(receipt.version === 1 && receipt.kind === 'prime-memory-effect/v1' && receipt.status === 'applied'
    && receipt.operation_id === expectation.operation_id && receipt.operation_digest === expectation.operation_digest
    && receipt.grant_id === expectation.receipt.grant_id && receipt.request_id === expectation.receipt.request_id
    && receipt.request_digest === expectation.receipt.request_digest && receipt.owner_subject === owner.owner_subject
    && receipt.action_type === 'memory.save' && receipt.result_digest === expectation.receipt.result_digest
    && memoryResultDigest(result) === expectation.receipt.result_digest && same(receipt.result, result)
    && memoryReceiptDigest(receipt) === expectation.receipt.receipt_digest, 'worker-pg:save-receipt-binding-changed')
  check(result.record_id === expectation.record_id && result.owner_subject === owner.owner_subject && result.task_id === owner.task_id
    && result.storage_status === 'saved' && result.index_status === 'pending' && result.grants_authority === false
    && result.scope === 'owner' && result.privacy === 'local' && result.chain_domain === 'remembered'
    && sha256(Buffer.from(result.canonical_bytes)) === expectation.canonical_sha256,
  'worker-pg:save-record-result-changed')
  const original = validateOriginal(Buffer.from(result.canonical_bytes), owner.owner_subject)
  check(original.id === expectation.record_id && original.digest === expectation.canonical_sha256, 'worker-pg:save-record-id-changed')
  const reviewedDraft = validateCaptureReview(operation.canonical_parameters,
    { statement: original.record.statement, attributed_to: original.record.attributedTo,
      capture_metadata: { profile: 'prime-pilot-memory-capture/v1', category: original.record.category,
        valid_from: original.record.validFrom, observed_at: original.record.observedAt,
        confidence_percent: original.record.confidence * 100, sensitivity: original.record.sensitivity },
      evidence_quote: original.record.evidence?.[0]?.quote })
  check(reviewedDraft.attributed_to === 'owner', 'worker-pg:save-record-attribution-changed')
  const { rows: intents } = await pool.query('SELECT * FROM prime_memory_intents WHERE owner_subject=$1 AND operation_id=$2',
    [owner.owner_subject, expectation.operation_id])
  check(intents.length === 1 && intents[0].operation_digest === effect.operation_digest
    && intents[0].request_id === effect.request_id && intents[0].request_digest === effect.request_digest
    && Buffer.from(intents[0].operation_bytes).equals(Buffer.from(effect.operation_bytes))
    && Buffer.from(intents[0].grant_bytes).equals(Buffer.from(effect.grant_bytes))
    && Buffer.from(intents[0].request_bytes).equals(Buffer.from(effect.request_bytes)), 'worker-pg:save-intent-binding-changed')
  const memory = createPostgresMemory({ pool })
  let projection
  if (project) projection = await memory.drainOutbox(host, 100)
  const status = await memory.status(host, expectation.record_id)
  check(status.saved === true && status.record.storage_status === expectation.storage_status
    && status.index_status === expectation.index_status && status.record.index_status === expectation.index_status
    && status.record.owner_subject === owner.owner_subject && status.record.task_id === owner.task_id
    && status.record.record_id === expectation.record_id && status.record.canonical_bytes === result.canonical_bytes
    && status.record.grants_authority === false, 'worker-pg:durable-save-status-changed')
  const citation = await memory.cite(host, expectation.record_id, null, expectation.retained_head)
  check(citation.verdict === 'VERIFIED' && citation.record_id === expectation.record_id
    && citation.verified_head === expectation.retained_head && citation.grants_authority === false,
  'worker-pg:retained-head-citation-unverified')
  return immutable({ version: 1, synthetic_fixture: true, schema: scope.schemaName, owner: expectation.owner,
    owner_subject: owner.owner_subject, task_id: owner.task_id, operation_id: expectation.operation_id,
    operation_digest: expectation.operation_digest, record_id: expectation.record_id, canonical_sha256: expectation.canonical_sha256,
    retained_head: expectation.retained_head, storage_status: status.record.storage_status, index_status: status.index_status,
    saved: status.saved, indexed: status.indexed, searchable: status.searchable,
    committed_receipt: { ...expectation.receipt }, citation: { verdict: citation.verdict, verified_head: citation.verified_head },
    expected_authority_settlement: 'completed', authority_settlement_independently_verified: false,
    ...(project ? { projection } : {}),
    checks: ['actual-D-committed-operation-grant-request-receipt', 'domain-separated-result-and-receipt-digests',
      'matching-durable-intent', 'distinct-owner-id-and-subject', 'original-record-bytes-and-ID', 'approved-literal-and-attribution-match-record',
      'saved-index-status-distinct', 'genuine-D-citation-at-retained-head'] })
}
