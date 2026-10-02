// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { sha256 } from '../src/codecs.mjs'
import { makeMemoryControlState, MEMORY_CONTROL_TABLES } from '../src/control-state.mjs'
import { memoryEffectDigest, memoryResultDigest, memoryTarget } from '../src/authorization.mjs'
import { createFileControlRetentionReader, createFileControlRetentionPublisher,
  createUnavailableControlRetention, isControlRetentionReader, MEMORY_RETENTION_SCHEMA } from '../src/control-retention.mjs'

// Ordinary synthetic file regressions. Every actual file access uses this same actual OS UID;
// process identity mocks model factory checks and do not prove a UID or group boundary.
// This macOS host strips directory setgid, so only that directory mode bit is modeled in
// lstat/fstat when absent. Linux production source still requires an actual mode 02750.
const actualUid = process.getuid(), modelReaderUid = actualUid + 100000
const host = {owner_id: 'synthetic-retention-owner', owner_subject: 'synthetic-retention-subject', authorization_epoch: 2}
const fixtureContracts = {validateContract: (_kind, value) => value,
  operationDigest: operation => 'sha256:' + sha256(Buffer.from(canonicalJSON(operation)))}
const operation = {operation_id: 'synthetic-retention-operation', operation_digest: 'sha256:' + 'e'.repeat(64)}
const emptyTables = () => Object.fromEntries(Object.keys(MEMORY_CONTROL_TABLES).map(table => [table, []]))
const bundle = (tables = emptyTables(), heads = {}) => makeMemoryControlState(host, {heads, tables}, {contracts: fixtureContracts})
const encode = value => Buffer.from(canonicalJSON(value) + '\n')
async function fixture(t) {
  const temporaryRoot = await fs.realpath('/tmp')
  const directory = await fs.mkdtemp(path.join(temporaryRoot, 'aukora-control-retention-synthetic-'))
  await fs.chmod(directory, 0o2750)
  t.after(() => fs.rm(directory, {recursive: true, force: true}))
  const rootStat = await fs.lstat(directory)
  const retentionGid = rootStat.gid
  if (process.platform === 'darwin' && (rootStat.mode & 0o2000) === 0) {
    const modelSetgid = stat => Object.assign(Object.create(Object.getPrototypeOf(stat)), stat,
      {mode: typeof stat.mode === 'bigint' ? stat.mode | 0o2000n : stat.mode | 0o2000})
    const lstat = fs.lstat, open = fs.open
    t.mock.method(fs, 'lstat', async (filename, ...args) => {
      const stat = await lstat(filename, ...args)
      return filename === directory && stat.isDirectory() ? modelSetgid(stat) : stat
    })
    t.mock.method(fs, 'open', async (filename, ...args) => {
      const handle = await open(filename, ...args)
      if (filename === directory) {
        const stat = handle.stat.bind(handle)
        t.mock.method(handle, 'stat', async (...statArgs) => modelSetgid(await stat(...statArgs)))
      }
      return handle
    })
  }
  const config = {directory, publisher_uid: actualUid, reader_uid: modelReaderUid, retention_gid: retentionGid, contracts: fixtureContracts}
  const uid = t.mock.method(process, 'getuid', () => actualUid)
  const euid = t.mock.method(process, 'geteuid', () => actualUid)
  t.mock.method(process, 'getgroups', () => [retentionGid])
  const role = value => { uid.mock.mockImplementation(() => value); euid.mock.mockImplementation(() => value) }
  return {directory, config, role, publisher: createFileControlRetentionPublisher(config)}
}
async function bootstrap(f) {
  return f.publisher.publish({host, control_state: bundle(), expected_checkpoint_sha256: null})
}
function fencedTables() {
  const tables = emptyTables()
  tables.replay_fences.push({owner_subject: host.owner_subject, ...operation, grant_id: 'synthetic-retention-grant',
    action: 'memory.forget', request_id: '00000000-0000-4000-8000-000000000001',
    request_digest: 'sha256:' + 'f'.repeat(64), status: 'payload-purged'})
  return tables
}
const begin = (f, checkpoint, nextHost = host) => f.publisher.beginUpdate({host: nextHost,
  expected_checkpoint_sha256: checkpoint, ...operation})
async function names(f) {
  const files = await fs.readdir(f.directory)
  return {files, pointer: files.find(file => file.endsWith('.current.json')),
    generation: files.find(file => /^[0-9a-f]{64}\.[0-9a-f]{64}\.json$/.test(file))}
}

test('unconfigured reader is branded and fails closed; publisher and arbitrary callbacks are unbranded', async t => {
  const unavailable = createUnavailableControlRetention()
  assert.equal(isControlRetentionReader(unavailable), true)
  assert.equal(isControlRetentionReader({restoreAnchorProvider: async () => true}), false)
  assert.equal(unavailable.status.configured, false)
  await assert.rejects(unavailable.restoreAnchorProvider(host), {code: 'memory:control-retention-unavailable'})
  const f = await fixture(t)
  assert.equal(isControlRetentionReader(f.publisher), false)
  assert.throws(() => createFileControlRetentionReader(f.config), {code: 'memory:control-retention-role-uid-mismatch'})
  assert.throws(() => createFileControlRetentionPublisher({...f.config, reader_uid: actualUid}),
    {code: 'memory:control-retention-distinct-uids-required'})
  assert.throws(() => createFileControlRetentionPublisher({...f.config, directory: 'relative'}),
    {code: 'memory:control-retention-directory-required'})
  f.role(modelReaderUid)
  const reader = createFileControlRetentionReader(f.config)
  await assert.rejects(reader.readCurrent(host), {code: 'memory:control-retention-missing'})
})

test('empty bootstrap durably publishes a closed owner-bound checkpoint and reader returns that full envelope', async t => {
  const f = await fixture(t), first = await bootstrap(f)
  assert.equal(first.schema, MEMORY_RETENTION_SCHEMA)
  assert.equal(first.sequence, 1); assert.equal(first.previous_checkpoint_sha256, null)
  assert.equal(first.owner_id, host.owner_id); assert.equal(first.authorization_epoch, 2)
  assert.deepEqual(first.control_state, bundle())
  const found = await names(f)
  assert.equal(found.files.length, 2)
  for (const filename of found.files) {
    const stat = await fs.stat(path.join(f.directory, filename))
    assert.equal(stat.mode & 0o7777, 0o640); assert.equal(stat.uid, actualUid); assert.equal(stat.gid, f.config.retention_gid)
    assert.equal(stat.nlink, 1)
  }
  assert.deepEqual(await f.publisher.readCurrent(host), first)
  f.role(modelReaderUid)
  const reader = createFileControlRetentionReader(f.config)
  assert.equal(isControlRetentionReader(reader), true)
  assert.deepEqual(await reader.readCurrent(host), first)
  assert.deepEqual(await reader.restoreAnchorProvider(host), first)
  assert.equal(reader.status.kind, 'file-reader')
  assert.equal(Object.hasOwn(reader.status, 'directory'), false)
  await assert.rejects(reader.readCurrent({...host, authorization_epoch: 3}), {code: 'memory:control-retention-epoch-mismatch'})
  await assert.rejects(reader.readCurrent({...host, owner_id: 'other-synthetic-owner'}), {code: 'memory:control-retention-missing'})
  await assert.rejects(reader.readCurrent({...host, unreviewed: true}), {code: 'memory:control-retention-host-required'})
})

test('bootstrap refuses heads or control rows and leaves no authoritative pointer', async t => {
  const f = await fixture(t), tables = emptyTables()
  tables.controls.push({owner_subject: host.owner_subject, scope: 'owner', bytes: encode({paused: true})})
  for (const control_state of [bundle(emptyTables(), {remembered: 'a'.repeat(64)}), bundle(tables)]) {
    await assert.rejects(f.publisher.publish({host, control_state, expected_checkpoint_sha256: null}),
      {code: 'memory:control-retention-bootstrap-nonempty'})
    assert.deepEqual(await fs.readdir(f.directory), [])
  }
})

test('publication requires exact checkpoint CAS, retains durable rows, and binds a nondecreasing current epoch', async t => {
  const f = await fixture(t), first = await bootstrap(f), tables = fencedTables()
  tables.requests.push({owner_subject: host.owner_subject, idempotency_key: 'synthetic-retained-request',
    request_digest: 'b'.repeat(64), record_id: 'rem:' + 'c'.repeat(64), revision: 1})
  const nextHost = {...host, authorization_epoch: 3}, nextState = bundle(tables, {remembered: 'd'.repeat(64)})
  await assert.rejects(f.publisher.publish({host: nextHost, control_state: nextState, expected_checkpoint_sha256: null}),
    {code: 'memory:control-retention-checkpoint-conflict'})
  await assert.rejects(f.publisher.publish({host: nextHost, control_state: nextState,
    expected_checkpoint_sha256: first.checkpoint_sha256}), {code: 'memory:control-retention-pending-missing'})
  await begin(f, first.checkpoint_sha256, nextHost)
  const second = await f.publisher.publish({host: nextHost, control_state: nextState,
    expected_checkpoint_sha256: first.checkpoint_sha256})
  assert.equal(second.sequence, 2); assert.equal(second.previous_checkpoint_sha256, first.checkpoint_sha256)
  assert.notEqual(second.checkpoint_sha256, first.checkpoint_sha256)
  await assert.rejects(f.publisher.publish({host: nextHost, control_state: nextState,
    expected_checkpoint_sha256: first.checkpoint_sha256}), {code: 'memory:control-retention-checkpoint-conflict'})
  await assert.rejects(f.publisher.publish({host, control_state: nextState,
    expected_checkpoint_sha256: second.checkpoint_sha256}), {code: 'memory:control-retention-epoch-mismatch'})
  await begin(f, second.checkpoint_sha256, nextHost)
  await assert.rejects(f.publisher.publish({host: nextHost, control_state: bundle(fencedTables(), nextState.heads),
    expected_checkpoint_sha256: second.checkpoint_sha256}), {code: 'memory:control-advance-retained-row-changed'})
  assert.equal((await f.publisher.readCurrent(nextHost)).checkpoint_sha256, second.checkpoint_sha256)
  await f.publisher.publish({host: nextHost, control_state: nextState, expected_checkpoint_sha256: second.checkpoint_sha256})
  f.role(modelReaderUid)
  const reader = createFileControlRetentionReader(f.config)
  assert.equal((await reader.readCurrent(nextHost)).sequence, 3)
  assert.equal((await fs.readdir(f.directory)).filter(file => file.endsWith('.lock')).length, 0)
})

test('role identity and protected preexisting canonical directory are enforced on every call', async t => {
  const f = await fixture(t)
  f.role(modelReaderUid)
  await assert.rejects(f.publisher.publish({host, control_state: bundle(), expected_checkpoint_sha256: null}),
    {code: 'memory:control-retention-role-uid-mismatch'})
  f.role(actualUid)
  await fs.chmod(f.directory, 0o2770)
  await assert.rejects(bootstrap(f), {code: 'memory:control-retention-directory-protection-invalid'})
  await fs.chmod(f.directory, 0o2750)
  const link = f.directory + '-link'
  await fs.symlink(f.directory, link); t.after(() => fs.unlink(link))
  const aliased = createFileControlRetentionPublisher({...f.config, directory: link})
  await assert.rejects(aliased.readCurrent(host), {code: 'memory:control-retention-noncanonical-directory'})
  await assert.rejects(createFileControlRetentionPublisher({...f.config, directory: f.directory + '-absent'}).readCurrent(host),
    {code: 'memory:control-retention-io'})
})

test('current and generation files reject links, permission changes and noncanonical serialization', async t => {
  const f = await fixture(t)
  await bootstrap(f)
  const found = await names(f), pointerPath = path.join(f.directory, found.pointer), generationPath = path.join(f.directory, found.generation)
  const original = await fs.readFile(pointerPath)
  await fs.chmod(pointerPath, 0o600)
  await assert.rejects(f.publisher.readCurrent(host), {code: 'memory:control-retention-file-protection-invalid'})
  await fs.chmod(pointerPath, 0o640)
  await fs.writeFile(pointerPath, Buffer.concat([original, Buffer.from(' ')]))
  await assert.rejects(f.publisher.readCurrent(host), {code: 'memory:control-retention-file-not-canonical'})
  await fs.writeFile(pointerPath, original)
  const hardlink = path.join(f.directory, 'synthetic-hardlink')
  await fs.link(generationPath, hardlink)
  await assert.rejects(f.publisher.readCurrent(host), {code: 'memory:control-retention-file-protection-invalid'})
  await fs.unlink(hardlink)
  const realPointer = path.join(f.directory, 'synthetic-pointer-target')
  await fs.rename(pointerPath, realPointer); await fs.symlink(realPointer, pointerPath)
  await assert.rejects(f.publisher.readCurrent(host), {code: 'memory:control-retention-io'})
})

test('generation digest and closed pointer binding refuse changes without importing or normalizing data', async t => {
  const f = await fixture(t)
  await bootstrap(f)
  const found = await names(f), generationPath = path.join(f.directory, found.generation), pointerPath = path.join(f.directory, found.pointer)
  const originalGeneration = await fs.readFile(generationPath), value = JSON.parse(originalGeneration)
  value.authorization_epoch = 1
  await fs.writeFile(generationPath, encode(value))
  await assert.rejects(f.publisher.readCurrent(host), {code: 'memory:control-retention-pointer-binding-invalid'})
  value.authorization_epoch = 2; value.control_state.heads = {remembered: 'a'.repeat(64)}
  await fs.writeFile(generationPath, encode(value))
  await assert.rejects(f.publisher.readCurrent(host), {code: 'memory:control-retention-checkpoint-changed'})
  await fs.writeFile(generationPath, originalGeneration)
  const pointer = JSON.parse(await fs.readFile(pointerPath)); pointer.imported_snapshot_authority = true
  await fs.writeFile(pointerPath, encode(pointer))
  await assert.rejects(f.publisher.readCurrent(host), {code: 'memory:control-retention-pointer-fields-invalid'})
})

test('existing lock remains owned by its creator and an uncertain pointer commit does not auto retry', async t => {
  const f = await fixture(t), first = await bootstrap(f), found = await names(f)
  const lockPath = path.join(f.directory, found.pointer.replace('.current.json', '.lock'))
  await fs.writeFile(lockPath, 'synthetic-external-lock', {mode: 0o600, flag: 'wx'})
  await assert.rejects(f.publisher.publish({host, control_state: bundle(), expected_checkpoint_sha256: first.checkpoint_sha256}),
    {code: 'memory:control-retention-locked'})
  assert.equal(await fs.readFile(lockPath, 'utf8'), 'synthetic-external-lock')
  await fs.unlink(lockPath)
  await begin(f, first.checkpoint_sha256)
  const rename = fs.rename
  let replacements = 0
  t.mock.method(fs, 'rename', async (...args) => {
    replacements++
    await rename(...args)
    throw Object.assign(new Error('synthetic post-replacement uncertainty'), {code: 'EIO'})
  })
  await assert.rejects(f.publisher.publish({host, control_state: bundle(fencedTables()), expected_checkpoint_sha256: first.checkpoint_sha256}),
    {code: 'memory:control-retention-commit-uncertain'})
  await assert.rejects(f.publisher.publish({host, control_state: bundle(), expected_checkpoint_sha256: first.checkpoint_sha256}),
    {code: 'memory:control-retention-commit-uncertain'})
  await assert.rejects(f.publisher.readCurrent(host), {code: 'memory:control-retention-commit-uncertain'})
  assert.equal(replacements, 1)
  assert.equal((await fs.readdir(f.directory)).some(file => file.endsWith('.lock')), false)
  f.role(modelReaderUid)
  const reader = createFileControlRetentionReader(f.config)
  await assert.rejects(reader.readCurrent(host), {code: 'memory:control-retention-update-pending'})
  f.role(actualUid)
  const recovery = createFileControlRetentionPublisher(f.config), current = await recovery.readCurrent(host)
  assert.equal(current.sequence, 2)
  await assert.rejects(recovery.completePending({host, checkpoint_sha256: first.checkpoint_sha256}),
    {code: 'memory:control-retention-checkpoint-conflict'})
  await recovery.completePending({host, checkpoint_sha256: current.checkpoint_sha256})
  f.role(modelReaderUid)
  assert.equal((await reader.readCurrent(host)).sequence, 2)
})

test('durable pending markers block reads across publisher instances until a matching retained operation is published', async t => {
  const f = await fixture(t), first = await bootstrap(f)
  const marker = await begin(f, first.checkpoint_sha256)
  assert.equal(marker.operation_digest, operation.operation_digest)
  await assert.rejects(begin(f, first.checkpoint_sha256), {code: 'memory:control-retention-update-pending'})
  f.role(modelReaderUid)
  await assert.rejects(createFileControlRetentionReader(f.config).readCurrent(host), {code: 'memory:control-retention-update-pending'})
  f.role(actualUid)
  const restarted = createFileControlRetentionPublisher(f.config)
  assert.equal((await restarted.readCurrent(host)).checkpoint_sha256, first.checkpoint_sha256)
  await assert.rejects(restarted.completePending({host, checkpoint_sha256: first.checkpoint_sha256}),
    {code: 'memory:control-retention-pending-predecessor-invalid'})
  await assert.rejects(restarted.publish({host, control_state: bundle(), expected_checkpoint_sha256: first.checkpoint_sha256}),
    {code: 'memory:control-retention-pending-operation-unretained'})
  await restarted.publish({host, control_state: bundle(fencedTables()), expected_checkpoint_sha256: first.checkpoint_sha256})
  assert.equal((await fs.readdir(f.directory)).some(file => file.endsWith('.pending.json')), false)
  f.role(modelReaderUid)
  assert.equal((await createFileControlRetentionReader(f.config).readCurrent(host)).sequence, 2)
})

function mutationFixture(parameters = {statement: 'Synthetic reviewed memory', attributed_to: 'synthetic-owner'}) {
  const proposal = {operation_id: 'synthetic-staged-memory-operation', owner_id: host.owner_id,
    task_id: 'synthetic-staged-task', action_type: 'memory.save', audience: 'aukora-prime.memory',
    authorization_epoch: host.authorization_epoch, target_identity: memoryTarget(host.owner_subject), canonical_parameters: parameters}
  const operation_digest = fixtureContracts.operationDigest(proposal)
  const request = {version: 1, action_type: proposal.action_type, owner_subject: host.owner_subject,
    operation_id: proposal.operation_id, operation_digest, parameters}
  const grant = {grant_id: 'synthetic-staged-grant', owner_id: host.owner_id, operation_id: proposal.operation_id,
    operation_digest, audience: proposal.audience, authorization_epoch: proposal.authorization_epoch}
  const tuple = {operation_id: proposal.operation_id, operation_digest,
    request_id: '00000000-0000-4000-8000-000000000002', request_digest: memoryEffectDigest(request)}
  const tables = emptyTables()
  tables.intents.push({owner_subject: host.owner_subject, ...tuple,
    grant_bytes: encode(grant), operation_bytes: encode(proposal), request_bytes: encode(request)})
  const appliedTables = () => {
    const applied = {...tables, effects: []}
    const result = {record_id: 'rem:' + '9'.repeat(64), owner_subject: host.owner_subject,
      task_id: proposal.task_id, storage_status: 'saved', index_status: 'pending'}
    const receipt = {version: 1, kind: 'prime-memory-effect/v1', ...tuple, grant_id: grant.grant_id,
      owner_subject: host.owner_subject, action_type: proposal.action_type, status: 'applied',
      result_digest: memoryResultDigest(result), result}
    applied.effects.push({...tables.intents[0], grant_id: grant.grant_id, action: proposal.action_type,
      result_bytes: encode(result), receipt_bytes: encode(receipt)})
    return applied
  }
  return {tuple, tables, appliedTables}
}
const mutationFields = (first, tuple) => ({host, expected_checkpoint_sha256: first.checkpoint_sha256, ...tuple})

test('v2 marker precedes preparation; exact scoped observation preserves the predecessor until actual final publication', async t => {
  const f = await fixture(t), first = await bootstrap(f), capture = mutationFixture()
  const fields = mutationFields(first, capture.tuple)
  const marker = await f.publisher.beginMutation(fields)
  assert.equal(marker.schema, 'aukora-prime-memory-retention-pending/v2')
  assert.equal(marker.prepared_checkpoint_sha256, null); assert.equal(marker.prepared_generation_file, null)
  assert.deepEqual(Object.keys(marker).sort(), ['schema', ...Object.keys(host), ...Object.keys(capture.tuple),
    'expected_checkpoint_sha256', 'prepared_checkpoint_sha256', 'prepared_generation_file'].sort())
  f.role(modelReaderUid)
  const reader = createFileControlRetentionReader(f.config)
  await assert.rejects(reader.readCurrent(host), {code: 'memory:control-retention-update-pending'})
  assert.deepEqual(await reader.observePredecessor(fields), first)
  const initial = await reader.readPending(fields)
  assert.equal(initial.prepared, null); assert.deepEqual(initial.predecessor, first)
  assert.deepEqual(Object.keys(initial).sort(), ['marker', 'predecessor', 'prepared'])
  const inspected = await reader.inspectPending(host)
  assert.deepEqual(Object.keys(inspected).sort(), ['current', 'marker', 'predecessor', 'prepared'])
  assert.deepEqual(inspected.current, first)
  for (const changed of [{request_id: '00000000-0000-4000-8000-000000000003'},
    {request_digest: 'sha256:' + '0'.repeat(64)}, {operation_digest: 'sha256:' + '1'.repeat(64)},
    {expected_checkpoint_sha256: '2'.repeat(64)}]) {
    await assert.rejects(reader.observePredecessor({...fields, ...changed}), {code: 'memory:control-retention-mutation-binding-conflict'})
  }
  await assert.rejects(reader.readPending({...fields, host: {...host, authorization_epoch: 3}}),
    {code: 'memory:control-retention-mutation-pending-binding-invalid'})
  f.role(actualUid)
  await assert.rejects(f.publisher.publishMutation({...fields, control_state: bundle(capture.tables)}),
    {code: 'memory:control-retention-mutation-prepared-required'})
  const prepared = await f.publisher.retainPrepared({...fields, control_state: bundle(capture.tables)})
  assert.equal(prepared.sequence, 2); assert.equal(prepared.previous_checkpoint_sha256, first.checkpoint_sha256)
  assert.equal((await f.publisher.readCurrent(host)).checkpoint_sha256, first.checkpoint_sha256)
  f.role(modelReaderUid)
  const staged = await reader.readPending(fields)
  assert.deepEqual(staged.prepared, prepared); assert.deepEqual(staged.predecessor, first)
  await assert.rejects(reader.readCurrent(host), {code: 'memory:control-retention-update-pending'})
  f.role(actualUid)
  const final = await f.publisher.publishMutation({...fields,
    control_state: bundle(capture.appliedTables(), {remembered: 'a'.repeat(64)})})
  assert.notEqual(final.checkpoint_sha256, prepared.checkpoint_sha256)
  assert.equal(final.previous_checkpoint_sha256, first.checkpoint_sha256)
  assert.equal((await fs.readdir(f.directory)).some(file => file.endsWith('.pending.json')), false)
  f.role(modelReaderUid)
  assert.deepEqual(await reader.readCurrent(host), final)
  await assert.rejects(reader.observePredecessor(fields), {code: 'memory:control-retention-pending-missing'})
})

test('v2 preparation and final publication require the exact committed intent and preserve unresolved replay state', async t => {
  const f = await fixture(t), first = await bootstrap(f), capture = mutationFixture()
  const fields = mutationFields(first, capture.tuple)
  await f.publisher.beginMutation(fields)
  await assert.rejects(f.publisher.retainPrepared({...fields, control_state: bundle()}),
    {code: 'memory:control-retention-mutation-intent-unretained'})
  const otherRequest = {...capture.tables, intents: [{...capture.tables.intents[0],
    request_id: '00000000-0000-4000-8000-000000000004'}]}
  await assert.rejects(f.publisher.retainPrepared({...fields, control_state: bundle(otherRequest)}),
    {code: 'memory:control-retention-mutation-intent-unretained'})
  await assert.rejects(f.publisher.retainPrepared({...fields, control_state: bundle(capture.appliedTables())}),
    {code: 'memory:control-retention-mutation-prepared-already-applied'})
  const prepared = await f.publisher.retainPrepared({...fields, control_state: bundle(capture.tables)})
  await assert.rejects(f.publisher.publishMutation({...fields, control_state: bundle()}),
    {code: 'memory:control-advance-unresolved-intent-missing'})
  const changed = mutationFixture({statement: 'Different synthetic statement', attributed_to: 'synthetic-owner'})
  await assert.rejects(f.publisher.publishMutation({...fields, control_state: bundle(changed.tables)}),
    {code: 'memory:control-advance-intent-changed'})
  const fenceOnly = emptyTables()
  fenceOnly.replay_fences.push({owner_subject: host.owner_subject, ...capture.tuple, grant_id: 'synthetic-staged-grant',
    action: 'memory.save', status: 'payload-purged'})
  await assert.rejects(f.publisher.publishMutation({...fields, control_state: bundle(fenceOnly)}),
    {code: 'memory:control-advance-unresolved-intent-missing'})
  // Publishing the same genuine unresolved intent is a checkpoint, not an applied receipt.
  // Prepared and final bytes coincide: the existing immutable generation must be reused.
  const preparedFilename = (await fs.readdir(f.directory)).find(file => file.includes(prepared.checkpoint_sha256))
  const before = await fs.stat(path.join(f.directory, preparedFilename))
  assert.deepEqual(await f.publisher.retainPrepared({...fields, control_state: bundle(capture.tables)}), prepared)
  const final = await f.publisher.publishMutation({...fields, control_state: bundle(capture.tables)})
  const after = await fs.stat(path.join(f.directory, preparedFilename))
  assert.equal(after.ino, before.ino); assert.equal(final.checkpoint_sha256, prepared.checkpoint_sha256)
  assert.equal(final.control_state.tables.effects.length, 0)
})

test('v1 markers cannot grant v2 scoped observation or bypass the prepared mutation stage', async t => {
  const f = await fixture(t), first = await bootstrap(f), capture = mutationFixture()
  await begin(f, first.checkpoint_sha256)
  const fields = mutationFields(first, capture.tuple)
  await assert.rejects(f.publisher.retainPrepared({...fields, control_state: bundle(capture.tables)}),
    {code: 'memory:control-retention-mutation-pending-fields-invalid'})
  f.role(modelReaderUid)
  const reader = createFileControlRetentionReader(f.config)
  await assert.rejects(reader.observePredecessor(fields), {code: 'memory:control-retention-mutation-pending-fields-invalid'})
  await assert.rejects(reader.inspectPending(host), {code: 'memory:control-retention-mutation-pending-fields-invalid'})
})

test('v2 final pointer uncertainty leaves the marker; fresh factual completion requires the exact existing final bytes', async t => {
  const f = await fixture(t), first = await bootstrap(f), capture = mutationFixture()
  const fields = mutationFields(first, capture.tuple)
  await f.publisher.beginMutation(fields)
  await f.publisher.retainPrepared({...fields, control_state: bundle(capture.tables)})
  const finalState = bundle(capture.appliedTables(), {remembered: 'b'.repeat(64)}), rename = fs.rename
  let finalReplacements = 0
  t.mock.method(fs, 'rename', async (...args) => {
    await rename(...args)
    if (args[1].endsWith('.current.json')) {
      finalReplacements++
      throw Object.assign(new Error('synthetic v2 lost pointer replacement reply'), {code: 'EIO'})
    }
  })
  await assert.rejects(f.publisher.publishMutation({...fields, control_state: finalState}),
    {code: 'memory:control-retention-commit-uncertain'})
  await assert.rejects(f.publisher.publishMutation({...fields, control_state: finalState}),
    {code: 'memory:control-retention-commit-uncertain'})
  f.role(modelReaderUid)
  const reader = createFileControlRetentionReader(f.config)
  await assert.rejects(reader.readCurrent(host), {code: 'memory:control-retention-update-pending'})
  const actual = await reader.inspectPending(host)
  assert.deepEqual(actual.current.control_state, finalState)
  assert.equal(actual.prepared.control_state.tables.effects.length, 0)
  await assert.rejects(reader.observePredecessor(fields), {code: 'memory:control-retention-checkpoint-conflict'})
  f.role(actualUid)
  const recovery = createFileControlRetentionPublisher(f.config)
  await assert.rejects(recovery.publishMutation({...fields,
    control_state: bundle(capture.appliedTables(), {remembered: 'c'.repeat(64)})}),
  {code: 'memory:control-retention-mutation-final-conflict'})
  const finalFilename = (await fs.readdir(f.directory)).find(file => file.includes(actual.current.checkpoint_sha256))
  const before = await fs.stat(path.join(f.directory, finalFilename))
  assert.deepEqual(await recovery.publishMutation({...fields, control_state: finalState}), actual.current)
  assert.equal((await fs.stat(path.join(f.directory, finalFilename))).ino, before.ino)
  assert.equal(finalReplacements, 1)
  f.role(modelReaderUid)
  assert.deepEqual(await reader.readCurrent(host), actual.current)
})
