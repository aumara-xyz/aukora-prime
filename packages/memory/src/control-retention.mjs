// SPDX-License-Identifier: AGPL-3.0-or-later
import fs from 'node:fs/promises'
import { constants } from 'node:fs'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MAX_BYTES, MemoryRefusal, parseOriginal, requireMemory, sha256 } from './codecs.mjs'
import { inspectMemoryControlState, MEMORY_CONTROL_TABLES } from './control-state.mjs'
import { assertMemoryControlAdvance } from './control-retention-advance.mjs'

export const MEMORY_RETENTION_SCHEMA = 'aukora-prime-memory-retention/v1'
const POINTER_SCHEMA = 'aukora-prime-memory-retention-current/v1'
const PENDING_SCHEMA = 'aukora-prime-memory-retention-pending/v1'
const MUTATION_SCHEMA = 'aukora-prime-memory-retention-pending/v2'
const readers = new WeakSet(), HEX = /^[0-9a-f]{64}$/
const HOST_KEYS = ['owner_id', 'owner_subject', 'authorization_epoch']
const ENVELOPE_KEYS = ['schema', ...HOST_KEYS, 'sequence', 'previous_checkpoint_sha256', 'control_state', 'checkpoint_sha256']
const POINTER_KEYS = ['schema', ...HOST_KEYS, 'sequence', 'checkpoint_sha256', 'generation_file']
const PENDING_KEYS = ['schema', ...HOST_KEYS, 'expected_checkpoint_sha256', 'operation_id', 'operation_digest']
const MUTATION_FIELDS = ['expected_checkpoint_sha256', 'operation_id', 'operation_digest', 'request_id', 'request_digest']
const MUTATION_KEYS = ['schema', ...HOST_KEYS, ...MUTATION_FIELDS, 'prepared_checkpoint_sha256', 'prepared_generation_file']
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const pointerLimit = 16384
const encode = value => Buffer.from(canonicalJSON(value) + '\n')
const fail = code => { throw new MemoryRefusal(`memory:control-retention-${code}`) }
const check = (condition, code) => requireMemory(condition, `memory:control-retention-${code}`)
const uint = value => Number.isSafeInteger(value) && value >= 0
function closedData(value, keys, code) {
  check(value && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)), code)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  check(Reflect.ownKeys(descriptors).length === keys.length && keys.every(key => descriptors[key]
    && Object.hasOwn(descriptors[key], 'value') && descriptors[key].enumerable), code)
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value]))
}
function checkedHost(host) {
  const checked = closedData(host, HOST_KEYS, 'host-required')
  check(['owner_id', 'owner_subject'].every(key => typeof checked[key] === 'string'
    && checked[key].length > 0 && checked[key].length <= 4096)
    && uint(checked.authorization_epoch), 'host-required')
  // The H/C caller must verify this current host identity and epoch independently.
  return parseOriginal(encode(checked))
}
function configuration(input, role) {
  const config = closedData(input, ['directory', 'publisher_uid', 'retention_gid', 'reader_uid', 'contracts'], 'configuration-required')
  check(typeof config.directory === 'string' && path.isAbsolute(config.directory)
    && path.normalize(config.directory) === config.directory && config.directory !== path.parse(config.directory).root
    && !config.directory.endsWith(path.sep), 'directory-required')
  check([config.publisher_uid, config.reader_uid, config.retention_gid].every(uint)
    && config.publisher_uid !== config.reader_uid, 'distinct-uids-required')
  check(typeof config.contracts?.validateContract === 'function' && typeof config.contracts?.operationDigest === 'function',
    'contracts-required')
  const checked = Object.freeze({...config, role})
  roleIdentity(checked)
  return checked
}
function roleIdentity(config) {
  check(['getuid', 'geteuid', 'getgid', 'getegid', 'getgroups'].every(key => typeof process[key] === 'function'), 'unix-identity-required')
  const uid = config.role === 'publisher' ? config.publisher_uid : config.reader_uid
  check(process.getuid() === uid && process.geteuid() === uid, 'role-uid-mismatch')
  check([process.getgid(), process.getegid(), ...process.getgroups()].includes(config.retention_gid), 'retention-group-required')
}
const identity = stat => `${stat.dev}:${stat.ino}`
const unchanged = (left, right) => identity(left) === identity(right) && left.size === right.size
  && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
const mode = stat => Number(stat.mode) & 0o7777
function regular(stat, config, wantedMode, limit) {
  check(stat.isFile() && stat.nlink === 1n && stat.uid === BigInt(config.publisher_uid)
    && stat.gid === BigInt(config.retention_gid) && mode(stat) === wantedMode
    && stat.size > 0n && stat.size <= BigInt(limit), 'file-protection-invalid')
}
async function protectedDirectory(config) {
  roleIdentity(config)
  check(await fs.realpath(config.directory) === config.directory, 'noncanonical-directory')
  let ancestor = config.directory
  while (true) {
    const stat = await fs.lstat(ancestor, {bigint: true})
    check(stat.isDirectory() && !stat.isSymbolicLink(), 'directory-protection-invalid')
    if (ancestor === config.directory) check(stat.uid === BigInt(config.publisher_uid)
      && stat.gid === BigInt(config.retention_gid) && mode(stat) === 0o2750, 'directory-protection-invalid')
    else check((stat.uid === 0n || stat.uid === BigInt(config.publisher_uid))
      && ((mode(stat) & 0o022) === 0 || (stat.uid === 0n && (mode(stat) & 0o1000) !== 0)), 'ancestor-protection-invalid')
    const parent = path.dirname(ancestor)
    if (parent === ancestor) break
    ancestor = parent
  }
  const directory = await fs.open(config.directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
  try {
    const stat = await directory.stat({bigint: true}), pathname = await fs.lstat(config.directory, {bigint: true})
    check(stat.isDirectory() && stat.uid === BigInt(config.publisher_uid) && stat.gid === BigInt(config.retention_gid)
      && mode(stat) === 0o2750 && identity(stat) === identity(pathname), 'directory-changed')
    return {handle: directory, identity: identity(stat)}
  } catch (error) { await directory.close(); throw error }
}
async function directoryUnchanged(config, directory) {
  roleIdentity(config)
  const stat = await fs.lstat(config.directory, {bigint: true})
  check(stat.isDirectory() && stat.uid === BigInt(config.publisher_uid) && stat.gid === BigInt(config.retention_gid)
    && mode(stat) === 0o2750 && identity(stat) === directory.identity, 'directory-changed')
}
function ownerKey(host) {
  return sha256(Buffer.from('aukora-prime.memory-retention-owner.v1\0'
    + canonicalJSON({owner_id: host.owner_id, owner_subject: host.owner_subject})))
}
function checkpoint(body) {
  return sha256(Buffer.from('aukora-prime.memory-retention.v1\0' + canonicalJSON(body)))
}
function mutationRequest(request, {state = false} = {}) {
  const fields = closedData(request, ['host', ...MUTATION_FIELDS, ...(state ? ['control_state'] : [])], 'mutation-fields-invalid')
  const host = checkedHost(fields.host)
  check(typeof fields.expected_checkpoint_sha256 === 'string' && HEX.test(fields.expected_checkpoint_sha256)
    && typeof fields.operation_id === 'string' && fields.operation_id.length > 0 && fields.operation_id.length <= 4096
    && typeof fields.operation_digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(fields.operation_digest)
    && typeof fields.request_id === 'string' && UUID.test(fields.request_id)
    && typeof fields.request_digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(fields.request_digest), 'mutation-binding-invalid')
  return {...fields, host}
}
const sameMutation = (marker, fields) => MUTATION_FIELDS.every(key => marker[key] === fields[key])
async function pendingAbsent(config, host) {
  try { await fs.lstat(path.join(config.directory, `${ownerKey(host)}.pending.json`)) }
  catch (error) { if (error.code === 'ENOENT') return; throw error }
  fail('update-pending')
}
async function readFile(config, filename, limit, {optional = false} = {}) {
  const filenamePath = path.join(config.directory, filename)
  let handle
  try { handle = await fs.open(filenamePath, constants.O_RDONLY | constants.O_NOFOLLOW) }
  catch (error) { if (optional && error.code === 'ENOENT') return null; throw error }
  try {
    const before = await handle.stat({bigint: true})
    regular(before, config, 0o640, limit)
    const pathname = await fs.lstat(filenamePath, {bigint: true})
    check(identity(before) === identity(pathname), 'file-changed')
    const bytes = Buffer.alloc(Number(before.size))
    let offset = 0
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset)
      check(result.bytesRead > 0, 'file-changed'); offset += result.bytesRead
    }
    const after = await handle.stat({bigint: true}), finalPath = await fs.lstat(filenamePath, {bigint: true})
    regular(after, config, 0o640, limit)
    check(unchanged(before, after) && identity(after) === identity(finalPath), 'file-changed')
    const value = parseOriginal(bytes)
    check(encode(value).equals(bytes), 'file-not-canonical')
    return {value, bytes, identity: identity(after)}
  } finally { await handle.close() }
}
function binding(value, host, pastEpoch) {
  check(value.owner_id === host.owner_id && value.owner_subject === host.owner_subject, 'owner-mismatch')
  check(uint(value.authorization_epoch) && (pastEpoch ? value.authorization_epoch <= host.authorization_epoch
    : value.authorization_epoch === host.authorization_epoch), 'epoch-mismatch')
  check(Number.isSafeInteger(value.sequence) && value.sequence >= 1
    && typeof value.checkpoint_sha256 === 'string' && HEX.test(value.checkpoint_sha256), 'checkpoint-invalid')
}
async function current(config, host, directory, {optional = false, pastEpoch = false} = {}) {
  const key = ownerKey(host), pointerName = `${key}.current.json`
  const source = await readFile(config, pointerName, pointerLimit, {optional: true})
  if (!source) {
    await directoryUnchanged(config, directory)
    check(optional, 'missing')
    return null
  }
  const pointer = closedData(source.value, POINTER_KEYS, 'pointer-fields-invalid')
  check(pointer.schema === POINTER_SCHEMA, 'pointer-schema-invalid'); binding(pointer, host, pastEpoch)
  check(pointer.generation_file === `${key}.${pointer.checkpoint_sha256}.json`, 'generation-name-invalid')
  const generation = await readFile(config, pointer.generation_file, MAX_BYTES)
  const envelope = closedData(generation.value, ENVELOPE_KEYS, 'envelope-fields-invalid')
  check(envelope.schema === MEMORY_RETENTION_SCHEMA, 'envelope-schema-invalid'); binding(envelope, host, pastEpoch)
  check(envelope.previous_checkpoint_sha256 === null || typeof envelope.previous_checkpoint_sha256 === 'string'
    && HEX.test(envelope.previous_checkpoint_sha256), 'previous-checkpoint-invalid')
  check((envelope.sequence === 1) === (envelope.previous_checkpoint_sha256 === null), 'sequence-invalid')
  check([...HOST_KEYS, 'sequence', 'checkpoint_sha256'].every(field => pointer[field] === envelope[field]), 'pointer-binding-invalid')
  const {checkpoint_sha256: digest, ...body} = envelope
  check(checkpoint(body) === digest, 'checkpoint-changed')
  inspectMemoryControlState(envelope.control_state, host, {contracts: config.contracts})
  const repeated = await readFile(config, pointerName, pointerLimit)
  check(repeated.bytes.equals(source.bytes) && repeated.identity === source.identity, 'current-changed')
  await directoryUnchanged(config, directory)
  return envelope
}
async function pending(config, host) {
  const source = await readFile(config, `${ownerKey(host)}.pending.json`, pointerLimit, {optional: true})
  check(source !== null, 'pending-missing')
  const marker = closedData(source.value, PENDING_KEYS, 'pending-fields-invalid')
  check(marker.schema === PENDING_SCHEMA && marker.owner_id === host.owner_id && marker.owner_subject === host.owner_subject
    && marker.authorization_epoch === host.authorization_epoch, 'pending-binding-invalid')
  check(typeof marker.expected_checkpoint_sha256 === 'string' && HEX.test(marker.expected_checkpoint_sha256)
    && typeof marker.operation_id === 'string' && marker.operation_id.length > 0 && marker.operation_id.length <= 4096
    && typeof marker.operation_digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(marker.operation_digest), 'pending-operation-invalid')
  return {...source, marker}
}
async function mutationPending(config, host) {
  const source = await readFile(config, `${ownerKey(host)}.pending.json`, pointerLimit, {optional: true})
  check(source !== null, 'pending-missing')
  const marker = closedData(source.value, MUTATION_KEYS, 'mutation-pending-fields-invalid')
  check(marker.schema === MUTATION_SCHEMA && marker.owner_id === host.owner_id && marker.owner_subject === host.owner_subject
    && marker.authorization_epoch === host.authorization_epoch, 'mutation-pending-binding-invalid')
  mutationRequest({host, ...Object.fromEntries(MUTATION_FIELDS.map(key => [key, marker[key]]))})
  check(marker.prepared_checkpoint_sha256 === null && marker.prepared_generation_file === null
    || typeof marker.prepared_checkpoint_sha256 === 'string' && HEX.test(marker.prepared_checkpoint_sha256)
      && marker.prepared_generation_file === `${ownerKey(host)}.${marker.prepared_checkpoint_sha256}.json`,
  'mutation-prepared-reference-invalid')
  return {...source, marker}
}
async function generation(config, host, digest, {pastEpoch = false} = {}) {
  check(typeof digest === 'string' && HEX.test(digest), 'checkpoint-invalid')
  const source = await readFile(config, `${ownerKey(host)}.${digest}.json`, MAX_BYTES)
  const envelope = closedData(source.value, ENVELOPE_KEYS, 'envelope-fields-invalid')
  check(envelope.schema === MEMORY_RETENTION_SCHEMA, 'envelope-schema-invalid'); binding(envelope, host, pastEpoch)
  check(envelope.previous_checkpoint_sha256 === null || typeof envelope.previous_checkpoint_sha256 === 'string'
    && HEX.test(envelope.previous_checkpoint_sha256), 'previous-checkpoint-invalid')
  check((envelope.sequence === 1) === (envelope.previous_checkpoint_sha256 === null), 'sequence-invalid')
  const {checkpoint_sha256, ...body} = envelope
  check(checkpoint_sha256 === digest && checkpoint(body) === digest, 'checkpoint-changed')
  inspectMemoryControlState(envelope.control_state, host, {contracts: config.contracts})
  return envelope
}
function mutationIntent(envelope, marker, host, contracts) {
  const checked = inspectMemoryControlState(envelope.control_state, host, {contracts})
  const matches = row => ['operation_id', 'operation_digest', 'request_id', 'request_digest'].every(key => row[key] === marker[key])
  check(checked.tables.intents.some(matches), 'mutation-intent-unretained')
  check(!checked.tables.effects.some(row => row.operation_id === marker.operation_id)
    && !checked.tables.replay_fences.some(row => row.operation_id === marker.operation_id), 'mutation-prepared-already-applied')
}
function retainedMutation(envelope, marker, host, contracts) {
  const checked = inspectMemoryControlState(envelope.control_state, host, {contracts})
  check(['intents', 'effects', 'replay_fences'].some(table => checked.tables[table].some(row =>
    ['operation_id', 'operation_digest', 'request_id', 'request_digest'].every(key => row[key] === marker[key]))),
  'mutation-operation-unretained')
}
async function mutationFiles(config, host, directory) {
  const source = await mutationPending(config, host), marker = source.marker
  const predecessor = await generation(config, host, marker.expected_checkpoint_sha256, {pastEpoch: true})
  let prepared = null
  if (marker.prepared_checkpoint_sha256 !== null) {
    prepared = await generation(config, host, marker.prepared_checkpoint_sha256)
    check(prepared.previous_checkpoint_sha256 === predecessor.checkpoint_sha256
      && prepared.sequence === predecessor.sequence + 1, 'mutation-prepared-predecessor-invalid')
    assertMemoryControlAdvance(predecessor.control_state, prepared.control_state, host, {contracts: config.contracts})
    mutationIntent(prepared, marker, host, config.contracts)
  }
  const retained = await current(config, host, directory, {pastEpoch: true})
  if (retained.checkpoint_sha256 !== predecessor.checkpoint_sha256) {
    check(prepared !== null && retained.authorization_epoch === host.authorization_epoch
      && retained.previous_checkpoint_sha256 === predecessor.checkpoint_sha256
      && retained.sequence === predecessor.sequence + 1, 'mutation-current-predecessor-invalid')
    assertMemoryControlAdvance(predecessor.control_state, retained.control_state, host, {contracts: config.contracts})
    assertMemoryControlAdvance(prepared.control_state, retained.control_state, host, {contracts: config.contracts})
    retainedMutation(retained, marker, host, config.contracts)
  }
  const repeated = await mutationPending(config, host)
  check(repeated.identity === source.identity && repeated.bytes.equals(source.bytes), 'pending-changed')
  await directoryUnchanged(config, directory)
  return {source, marker, predecessor, prepared, current: retained}
}
async function removeMutationPending(config, host, source, directory) {
  const repeated = await mutationPending(config, host)
  check(source.identity === repeated.identity && source.bytes.equals(repeated.bytes), 'pending-changed')
  await directoryUnchanged(config, directory)
  await fs.unlink(path.join(config.directory, `${ownerKey(host)}.pending.json`))
  await directory.handle.sync()
}
function retainedOperation(envelope, marker, host, contracts) {
  const checked = inspectMemoryControlState(envelope.control_state, host, {contracts})
  check(['intents', 'effects', 'replay_fences'].some(table => checked.tables[table].some(row =>
    row.operation_id === marker.operation_id && row.operation_digest === marker.operation_digest)), 'pending-operation-unretained')
}
async function removePending(config, host, source, directory) {
  const repeated = await pending(config, host)
  check(source.identity === repeated.identity && source.bytes.equals(repeated.bytes), 'pending-changed')
  await directoryUnchanged(config, directory)
  await fs.unlink(path.join(config.directory, `${ownerKey(host)}.pending.json`))
  await directory.handle.sync()
}
async function ownerLock(config, host, action) {
  const lockPath = path.join(config.directory, `${ownerKey(host)}.lock`)
  let lock, lockIdentity
  try {
    try { lock = await fs.open(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600) }
    catch (error) { if (error.code === 'EEXIST') fail('locked'); throw error }
    const stat = await lock.stat({bigint: true})
    lockIdentity = identity(stat)
    check(stat.isFile() && stat.nlink === 1n && stat.uid === BigInt(config.publisher_uid)
      && stat.gid === BigInt(config.retention_gid) && mode(stat) === 0o600, 'lock-protection-invalid')
    return await action()
  } finally {
    // Remove only this call's own lock inode. Never remove another publisher's lock.
    if (lock) {
      try {
        const own = await lock.stat({bigint: true}), pathname = await fs.lstat(lockPath, {bigint: true})
        roleIdentity(config)
        check(identity(own) === lockIdentity && identity(pathname) === lockIdentity && own.isFile()
          && own.uid === BigInt(config.publisher_uid) && own.nlink === 1n && mode(own) === 0o600, 'lock-changed')
        await fs.unlink(lockPath)
      } catch { fail('commit-uncertain') }
      finally {
        try { await lock.close() }
        catch { fail('commit-uncertain') }
      }
    }
  }
}
async function withDirectory(config, action) {
  let directory
  try { directory = await protectedDirectory(config); return await action(directory) }
  catch (error) { if (error instanceof MemoryRefusal) throw error; fail('io') }
  finally {
    if (directory) {
      try { await directory.handle.close() }
      catch { fail('commit-uncertain') }
    }
  }
}
export function isControlRetentionReader(adapter) { return readers.has(adapter) }
export function createUnavailableControlRetention() {
  const unavailable = async () => fail('unavailable')
  const adapter = Object.freeze({readCurrent: unavailable, restoreAnchorProvider: unavailable,
    inspectPending: unavailable, readPending: unavailable, observePredecessor: unavailable,
    status: Object.freeze({configured: false, kind: 'unavailable', schema: MEMORY_RETENTION_SCHEMA})})
  readers.add(adapter)
  return adapter
}
export function createFileControlRetentionReader(input) {
  const config = configuration(input, 'reader')
  const readCurrent = async trustedHost => {
    const host = checkedHost(trustedHost)
    return withDirectory(config, async directory => {
      await pendingAbsent(config, host)
      const retained = await current(config, host, directory)
      check(retained !== null, 'missing')
      await pendingAbsent(config, host)
      return retained
    })
  }
  const inspectPending = async trustedHost => {
    const host = checkedHost(trustedHost)
    return withDirectory(config, async directory => {
      const inspected = await mutationFiles(config, host, directory)
      return {marker: inspected.marker, predecessor: inspected.predecessor, prepared: inspected.prepared, current: inspected.current}
    })
  }
  const readPending = async request => {
    const fields = mutationRequest(request)
    return withDirectory(config, async directory => {
      const inspected = await mutationFiles(config, fields.host, directory)
      check(sameMutation(inspected.marker, fields), 'mutation-binding-conflict')
      check(inspected.current.checkpoint_sha256 === fields.expected_checkpoint_sha256, 'checkpoint-conflict')
      return {predecessor: inspected.predecessor, prepared: inspected.prepared, marker: inspected.marker}
    })
  }
  const observePredecessor = async request => (await readPending(request)).predecessor
  const adapter = Object.freeze({readCurrent, restoreAnchorProvider: readCurrent, inspectPending, readPending, observePredecessor,
    status: Object.freeze({configured: true, kind: 'file-reader', schema: MEMORY_RETENTION_SCHEMA})})
  readers.add(adapter)
  return adapter
}
async function createDurableFile(config, filename, bytes) {
  const handle = await fs.open(path.join(config.directory, filename),
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o640)
  try {
    await handle.writeFile(bytes)
    regular(await handle.stat({bigint: true}), config, 0o640, MAX_BYTES)
    await handle.sync()
  } finally { await handle.close() }
}
async function immutableGeneration(config, filename, bytes) {
  try { await createDurableFile(config, filename, bytes) }
  catch (error) {
    if (error.code !== 'EEXIST') throw error
    const retained = await readFile(config, filename, MAX_BYTES)
    check(retained.bytes.equals(bytes), 'generation-conflict')
  }
}
function mutationEnvelope(host, predecessor, control_state) {
  const sequence = predecessor.sequence + 1
  check(Number.isSafeInteger(sequence), 'sequence-invalid')
  const body = {schema: MEMORY_RETENTION_SCHEMA, ...host, sequence,
    previous_checkpoint_sha256: predecessor.checkpoint_sha256, control_state}
  const envelope = {...body, checkpoint_sha256: checkpoint(body)}
  check(encode(envelope).length <= MAX_BYTES, 'bytes-limit')
  return envelope
}
// No mkdir/chmod/chown, imported-snapshot fallback, retry or generation overwrite exists here.
export function createFileControlRetentionPublisher(input) {
  const config = configuration(input, 'publisher')
  let uncertain = false
  const readCurrent = async trustedHost => {
    check(!uncertain, 'commit-uncertain')
    const host = checkedHost(trustedHost)
    return withDirectory(config, directory => current(config, host, directory, {pastEpoch: true}))
  }
  const guarded = async action => {
    check(!uncertain, 'commit-uncertain')
    try { return await action() }
    catch (error) { if (error.code === 'memory:control-retention-commit-uncertain') uncertain = true; throw error }
  }
  const beginMutation = async request => guarded(async () => {
    const fields = mutationRequest(request), host = fields.host
    const marker = {schema: MUTATION_SCHEMA, ...host,
      ...Object.fromEntries(MUTATION_FIELDS.map(key => [key, fields[key]])),
      prepared_checkpoint_sha256: null, prepared_generation_file: null}
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      await pendingAbsent(config, host)
      const retained = await current(config, host, directory, {pastEpoch: true})
      check(retained.checkpoint_sha256 === fields.expected_checkpoint_sha256, 'checkpoint-conflict')
      try {
        await createDurableFile(config, `${ownerKey(host)}.pending.json`, encode(marker))
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
      } catch { fail('commit-uncertain') }
      return marker
    }))
  })
  const retainPrepared = async request => guarded(async () => {
    const fields = mutationRequest(request, {state: true}), host = fields.host
    inspectMemoryControlState(fields.control_state, host, {contracts: config.contracts})
    const control_state = parseOriginal(encode(fields.control_state))
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      const inspected = await mutationFiles(config, host, directory)
      check(sameMutation(inspected.marker, fields), 'mutation-binding-conflict')
      check(inspected.current.checkpoint_sha256 === fields.expected_checkpoint_sha256, 'checkpoint-conflict')
      assertMemoryControlAdvance(inspected.predecessor.control_state, control_state, host, {contracts: config.contracts})
      const envelope = mutationEnvelope(host, inspected.predecessor, control_state)
      mutationIntent(envelope, inspected.marker, host, config.contracts)
      if (inspected.prepared !== null) {
        check(encode(inspected.prepared).equals(encode(envelope)), 'mutation-prepared-conflict')
        return inspected.prepared
      }
      const generation_file = `${ownerKey(host)}.${envelope.checkpoint_sha256}.json`
      const marker = {...inspected.marker, prepared_checkpoint_sha256: envelope.checkpoint_sha256,
        prepared_generation_file: generation_file}
      try {
        await immutableGeneration(config, generation_file, encode(envelope))
        await directory.handle.sync()
        const temporary = `${ownerKey(host)}.pending.${randomUUID()}.tmp`
        await createDurableFile(config, temporary, encode(marker))
        const repeated = await mutationPending(config, host)
        check(repeated.identity === inspected.source.identity && repeated.bytes.equals(inspected.source.bytes), 'pending-changed')
        await directoryUnchanged(config, directory)
        await fs.rename(path.join(config.directory, temporary), path.join(config.directory, `${ownerKey(host)}.pending.json`))
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
      } catch { fail('commit-uncertain') }
      return envelope
    }))
  })
  const publishMutation = async request => guarded(async () => {
    const fields = mutationRequest(request, {state: true}), host = fields.host
    inspectMemoryControlState(fields.control_state, host, {contracts: config.contracts})
    const control_state = parseOriginal(encode(fields.control_state))
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      const inspected = await mutationFiles(config, host, directory)
      check(sameMutation(inspected.marker, fields), 'mutation-binding-conflict')
      check(inspected.prepared !== null, 'mutation-prepared-required')
      assertMemoryControlAdvance(inspected.predecessor.control_state, control_state, host, {contracts: config.contracts})
      assertMemoryControlAdvance(inspected.prepared.control_state, control_state, host, {contracts: config.contracts})
      const envelope = mutationEnvelope(host, inspected.predecessor, control_state)
      retainedMutation(envelope, inspected.marker, host, config.contracts)
      if (inspected.current.checkpoint_sha256 !== fields.expected_checkpoint_sha256) {
        check(encode(inspected.current).equals(encode(envelope)), 'mutation-final-conflict')
        try { await removeMutationPending(config, host, inspected.source, directory) }
        catch { fail('commit-uncertain') }
        return inspected.current
      }
      const key = ownerKey(host), generation_file = `${key}.${envelope.checkpoint_sha256}.json`
      try {
        await immutableGeneration(config, generation_file, encode(envelope))
        await directory.handle.sync()
        const pointer = {schema: POINTER_SCHEMA, ...host, sequence: envelope.sequence,
          checkpoint_sha256: envelope.checkpoint_sha256, generation_file}
        const temporary = `${key}.current.${randomUUID()}.tmp`
        await createDurableFile(config, temporary, encode(pointer))
        const repeated = await mutationFiles(config, host, directory)
        check(repeated.source.identity === inspected.source.identity && repeated.source.bytes.equals(inspected.source.bytes), 'pending-changed')
        check(repeated.current.checkpoint_sha256 === fields.expected_checkpoint_sha256, 'checkpoint-conflict')
        await directoryUnchanged(config, directory)
        await fs.rename(path.join(config.directory, temporary), path.join(config.directory, `${key}.current.json`))
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
        await removeMutationPending(config, host, inspected.source, directory)
      } catch { fail('commit-uncertain') }
      return envelope
    }))
  })
  const beginUpdate = async request => guarded(async () => {
    const fields = closedData(request, ['host', 'expected_checkpoint_sha256', 'operation_id', 'operation_digest'], 'begin-fields-invalid')
    const host = checkedHost(fields.host)
    const marker = {schema: PENDING_SCHEMA, ...host, expected_checkpoint_sha256: fields.expected_checkpoint_sha256,
      operation_id: fields.operation_id, operation_digest: fields.operation_digest}
    check(typeof marker.expected_checkpoint_sha256 === 'string' && HEX.test(marker.expected_checkpoint_sha256)
      && typeof marker.operation_id === 'string' && marker.operation_id.length > 0 && marker.operation_id.length <= 4096
      && typeof marker.operation_digest === 'string' && /^sha256:[0-9a-f]{64}$/.test(marker.operation_digest), 'pending-operation-invalid')
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      await pendingAbsent(config, host)
      const retained = await current(config, host, directory, {pastEpoch: true})
      check(retained.checkpoint_sha256 === marker.expected_checkpoint_sha256, 'checkpoint-conflict')
      try {
        await createDurableFile(config, `${ownerKey(host)}.pending.json`, encode(marker))
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
      } catch { fail('commit-uncertain') }
      return marker
    }))
  })
  const completePending = async request => guarded(async () => {
    const fields = closedData(request, ['host', 'checkpoint_sha256'], 'complete-fields-invalid'), host = checkedHost(fields.host)
    check(typeof fields.checkpoint_sha256 === 'string' && HEX.test(fields.checkpoint_sha256), 'expected-checkpoint-required')
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      const source = await pending(config, host), retained = await current(config, host, directory, {pastEpoch: true})
      check(retained.checkpoint_sha256 === fields.checkpoint_sha256, 'checkpoint-conflict')
      check(retained.authorization_epoch === host.authorization_epoch
        && retained.previous_checkpoint_sha256 === source.marker.expected_checkpoint_sha256, 'pending-predecessor-invalid')
      retainedOperation(retained, source.marker, host, config.contracts)
      try { await removePending(config, host, source, directory) }
      catch { fail('commit-uncertain') }
      return retained
    }))
  })
  const publish = async request => {
    check(!uncertain, 'commit-uncertain')
    const {host: inputHost, control_state: inputState, expected_checkpoint_sha256: expected} =
      closedData(request, ['host', 'control_state', 'expected_checkpoint_sha256'], 'publication-fields-invalid')
    const host = checkedHost(inputHost)
    check(expected === null || typeof expected === 'string' && HEX.test(expected), 'expected-checkpoint-required')
    inspectMemoryControlState(inputState, host, {contracts: config.contracts})
    const control_state = parseOriginal(encode(inputState))
    return guarded(() => withDirectory(config, directory => ownerLock(config, host, async () => {
      const key = ownerKey(host)
      let pointerAttempted = false
      try {
        const previous = await current(config, host, directory, {optional: true, pastEpoch: true})
        check((previous?.checkpoint_sha256 ?? null) === expected, 'checkpoint-conflict')
        let pendingSource
        if (previous) {
          pendingSource = await pending(config, host)
          check(pendingSource.marker.expected_checkpoint_sha256 === expected, 'checkpoint-conflict')
          assertMemoryControlAdvance(previous.control_state, control_state, host, {contracts: config.contracts})
          retainedOperation({control_state}, pendingSource.marker, host, config.contracts)
        } else {
          await pendingAbsent(config, host)
          check(Object.keys(control_state.heads).length === 0 && Object.keys(MEMORY_CONTROL_TABLES)
            .every(table => control_state.tables[table].length === 0), 'bootstrap-nonempty')
        }
        const sequence = previous ? previous.sequence + 1 : 1
        check(Number.isSafeInteger(sequence), 'sequence-invalid')
        const body = {schema: MEMORY_RETENTION_SCHEMA, ...host, sequence, previous_checkpoint_sha256: expected, control_state}
        const envelope = {...body, checkpoint_sha256: checkpoint(body)}, generation_file = `${key}.${envelope.checkpoint_sha256}.json`
        const envelopeBytes = encode(envelope)
        check(envelopeBytes.length <= MAX_BYTES, 'bytes-limit')
        await createDurableFile(config, generation_file, envelopeBytes)
        await directory.handle.sync()
        const pointer = {schema: POINTER_SCHEMA, ...host, sequence, checkpoint_sha256: envelope.checkpoint_sha256, generation_file}
        const temporary = `${key}.current.${randomUUID()}.tmp`
        await createDurableFile(config, temporary, encode(pointer))
        const repeated = await current(config, host, directory, {optional: true, pastEpoch: true})
        check((repeated?.checkpoint_sha256 ?? null) === expected, 'checkpoint-conflict')
        await directoryUnchanged(config, directory)
        pointerAttempted = true
        await fs.rename(path.join(config.directory, temporary), path.join(config.directory, `${key}.current.json`))
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
        if (pendingSource) await removePending(config, host, pendingSource, directory)
        return envelope
      } catch (error) {
        if (pointerAttempted) { uncertain = true; fail('commit-uncertain') }
        throw error
      }
    })))
  }
  return Object.freeze({publish, readCurrent, beginUpdate, completePending, beginMutation, retainPrepared, publishMutation,
    status: Object.freeze({configured: true, kind: 'file-publisher', schema: MEMORY_RETENTION_SCHEMA})})
}
