// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit private-v2 extension of the existing protected retention file protocol.
// The directory/file/lock custody algorithms below preserve control-retention.mjs.
// This module has no bootstrap, provisioning, chmod/chown, legacy conversion or effect retry.
import fs from 'node:fs/promises'
import { constants } from 'node:fs'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MAX_BYTES, MemoryRefusal, parseOriginal, requireMemory, sha256 } from './codecs.mjs'
import { assertControlV3, assertJournalTransition, journalTransitionDigest,
  assertWorkflowTransition, workflowTransitionDigest, assertNegativeTransition,
  negativeTransitionDigest, assertRestoreTransition, restoreTransitionDigest,
  assertAuthorizedEffectTransition, effectTransitionDigest, detachPrivateData } from './private-v2-control.mjs'
import { assertForwardControlV3, assertLineageCompletionsV2, assertRestoreEffectAdvance } from './private-v2-advance.mjs'

export const PRIVATE_V2_RETENTION_SCHEMA = 'aukora-prime-memory-retention/v2'
const POINTER_SCHEMA = 'aukora-prime-memory-retention-current/v2'
const readers = new WeakSet(), publishers = new WeakSet()
const HEX = /^[0-9a-f]{64}$/, DIGEST = /^sha256:[0-9a-f]{64}$/
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const HOST_KEYS = ['owner_id', 'owner_subject', 'authorization_epoch']
const FULL_HOST_KEYS = ['owner_id', 'owner_subject', 'task_id', 'authorization_epoch']
const ENVELOPE_KEYS = ['schema', ...HOST_KEYS, 'sequence', 'previous_checkpoint_sha256', 'control_state', 'checkpoint_sha256']
const POINTER_KEYS = ['schema', ...HOST_KEYS, 'sequence', 'checkpoint_sha256', 'generation_file']
const REQUEST_KEYS = ['host', 'transition_id', 'transition', 'transition_digest']
const PENDING_KEYS = ['schema', ...HOST_KEYS, 'transition_id', 'transition', 'transition_digest',
  'prepared_checkpoint_sha256', 'prepared_generation_file']
const PROFILE_KEYS = ['version', 'kind', 'expected_authority_store_id', 'expected_memory_store_id', 'retention_profile']
const CLEANUP_GUARD_SCHEMA = 'aukora-prime-memory-retention-cleanup-guard/v3'
const CLEANUP_COMPLETION_SCHEMA = 'aukora-prime-memory-retention-cleanup-completion/v3'
const CLEANUP_GUARD_KEYS = ['schema', 'pending', 'pending_sha256']
const CLEANUP_COMPLETION_KEYS = ['schema', ...HOST_KEYS, 'pending_sha256', 'checkpoint_sha256']
const pointerLimit = 16384
const encode = value => Buffer.from(canonicalJSON(value) + '\n')
const fail = code => { throw new MemoryRefusal(`memory:private-v2-retention-${code}`) }
const check = (condition, code) => requireMemory(condition, `memory:private-v2-retention-${code}`)
const uint = value => Number.isSafeInteger(value) && value >= 0
const nonempty = value => typeof value === 'string' && value.length > 0 && value.length <= 4096
const same = (left, right) => canonicalJSON(left) === canonicalJSON(right)
function closedData(value, keys, code) {
  check(value && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)), code)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  check(Reflect.ownKeys(descriptors).length === keys.length && keys.every(key => descriptors[key]
    && Object.hasOwn(descriptors[key], 'value') && descriptors[key].enumerable), code)
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value]))
}
function checkedHost(input) {
  const host = closedData(input, FULL_HOST_KEYS, 'host-required')
  check(['owner_id', 'owner_subject', 'task_id'].every(key => nonempty(host[key]))
    && uint(host.authorization_epoch), 'host-required')
  return Object.freeze(host)
}
function configuration(input, role) {
  const config = closedData(input,
    ['directory', 'publisher_uid', 'retention_gid', 'reader_uid', 'contracts', 'profile'], 'configuration-required')
  check(typeof config.directory === 'string' && path.isAbsolute(config.directory)
    && path.normalize(config.directory) === config.directory && config.directory !== path.parse(config.directory).root
    && !config.directory.endsWith(path.sep), 'directory-required')
  check([config.publisher_uid, config.reader_uid, config.retention_gid].every(uint)
    && config.publisher_uid !== config.reader_uid, 'distinct-uids-required')
  check(config.contracts && typeof config.contracts === 'object' && !types.isProxy(config.contracts), 'contracts-required')
  const contractDescriptors = Object.getOwnPropertyDescriptors(config.contracts)
  const contracts = Object.fromEntries(['validateContract', 'operationDigest', 'canonicalJson'].map(key => {
    const descriptor = contractDescriptors[key]
    check(descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function', 'contracts-required')
    return [key, descriptor.value]
  }))
  const profile = closedData(config.profile, PROFILE_KEYS, 'profile-required')
  check(profile.version === 2 && profile.kind === 'prime-private-unsent-closure/v2'
    && profile.retention_profile === 'required-retained/v2'
    && ['expected_authority_store_id', 'expected_memory_store_id'].every(key => typeof profile[key] === 'string'
      && HEX.test(profile[key])), 'profile-required')
  const checked = Object.freeze({...config, contracts: Object.freeze(contracts), profile: Object.freeze(profile), role})
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

function ownerKey(host) {
  // Preserve the existing owner namespace. A legacy pointer/pending file therefore
  // fails the explicit v2 parser instead of opening an independent continuity.
  return sha256(Buffer.from('aukora-prime.memory-retention-owner.v1\0'
    + canonicalJSON({owner_id: host.owner_id, owner_subject: host.owner_subject})))
}
function checkpoint(body) {
  return sha256(Buffer.from('aukora-prime.memory-retention.v2\0' + canonicalJSON(body)))
}
function envelopeHost(host) { return Object.fromEntries(HOST_KEYS.map(key => [key, host[key]])) }
function envelopeBinding(value, host, config, {pastEpoch = false} = {}) {
  const envelope = closedData(value, ENVELOPE_KEYS, 'envelope-fields-invalid')
  check(envelope.schema === PRIVATE_V2_RETENTION_SCHEMA && envelope.owner_id === host.owner_id
    && envelope.owner_subject === host.owner_subject && uint(envelope.authorization_epoch)
    && (pastEpoch ? envelope.authorization_epoch <= host.authorization_epoch
      : envelope.authorization_epoch === host.authorization_epoch), 'envelope-binding-invalid')
  check(Number.isSafeInteger(envelope.sequence) && envelope.sequence >= 1
    && typeof envelope.checkpoint_sha256 === 'string' && HEX.test(envelope.checkpoint_sha256)
    && (envelope.previous_checkpoint_sha256 === null || typeof envelope.previous_checkpoint_sha256 === 'string'
      && HEX.test(envelope.previous_checkpoint_sha256))
    && (envelope.sequence === 1) === (envelope.previous_checkpoint_sha256 === null), 'envelope-checkpoint-invalid')
  const control_state = assertControlV3(envelope.control_state, host, {contracts: config.contracts, profile: config.profile})
  const {checkpoint_sha256: digest, ...inputBody} = envelope
  const body = {...inputBody, control_state}
  check(checkpoint(body) === digest, 'checkpoint-changed')
  if (envelope.sequence === 1) check(Object.keys(control_state.heads).length === 0
    && Object.values(control_state.tables).every(rows => rows.length === 0), 'genesis-not-empty')
  return parseOriginal(encode({...body, checkpoint_sha256: digest}))
}
async function generation(config, host, digest, {pastEpoch = false} = {}) {
  check(typeof digest === 'string' && HEX.test(digest), 'checkpoint-invalid')
  const source = await readFile(config, `${ownerKey(host)}.${digest}.json`, MAX_BYTES)
  const envelope = envelopeBinding(source.value, host, config, {pastEpoch})
  check(envelope.checkpoint_sha256 === digest, 'generation-binding-invalid')
  return envelope
}
async function current(config, host, directory, {pastEpoch = false} = {}) {
  const key = ownerKey(host), name = `${key}.current.json`
  const source = await readFile(config, name, pointerLimit, {optional: true})
  check(source !== null, 'missing')
  const pointer = closedData(source.value, POINTER_KEYS, 'pointer-fields-invalid')
  check(pointer.schema === POINTER_SCHEMA && pointer.owner_id === host.owner_id
    && pointer.owner_subject === host.owner_subject && uint(pointer.authorization_epoch)
    && (pastEpoch ? pointer.authorization_epoch <= host.authorization_epoch
      : pointer.authorization_epoch === host.authorization_epoch)
    && Number.isSafeInteger(pointer.sequence) && pointer.sequence >= 1
    && typeof pointer.checkpoint_sha256 === 'string' && HEX.test(pointer.checkpoint_sha256)
    && pointer.generation_file === `${key}.${pointer.checkpoint_sha256}.json`, 'pointer-binding-invalid')
  const envelope = await generation(config, host, pointer.checkpoint_sha256, {pastEpoch})
  check([...HOST_KEYS, 'sequence', 'checkpoint_sha256'].every(field => pointer[field] === envelope[field]), 'pointer-binding-invalid')
  // Current flags cannot adopt a new store identity or manufacture a pre-work
  // baseline. Every authoritative current observation reaches the original empty
  // published genesis through the complete authenticated predecessor chain.
  await publishedLineage(config, host, envelope)
  const repeated = await readFile(config, name, pointerLimit)
  check(repeated.identity === source.identity && repeated.bytes.equals(source.bytes), 'current-changed')
  await directoryUnchanged(config, directory)
  return envelope
}
async function publishedLineage(config, host, head) {
  const lineage = [head], seen = new Set([head.checkpoint_sha256])
  let bytes = encode(head).length
  while (lineage.at(-1).previous_checkpoint_sha256 !== null) {
    const next = lineage.at(-1), digest = next.previous_checkpoint_sha256
    check(!seen.has(digest) && lineage.length < 10000, 'lineage-limit')
    const previous = await generation(config, host, digest, {pastEpoch: true})
    check(previous.sequence + 1 === next.sequence && previous.authorization_epoch <= next.authorization_epoch,
      'lineage-sequence-invalid')
    // Build the COMPLETE authenticated chain before interpreting any control
    // edge. A restore event may require an older original P from this history;
    // validating a partial suffix while reading cannot establish that proof.
    bytes += encode(previous).length
    check(bytes <= MAX_BYTES, 'lineage-bytes-limit')
    lineage.push(previous); seen.add(digest)
  }
  const genesis = lineage.at(-1)
  check(genesis.sequence === 1 && Object.keys(genesis.control_state.heads).length === 0
    && Object.values(genesis.control_state.tables).every(rows => rows.length === 0), 'genesis-not-empty')
  // Stored completion hashes are not accepted merely because they are well
  // formed. Authenticate every original completion against the first exact
  // marker A on this protected published chain and its predecessor's absence.
  // Recovery may inspect an earlier-epoch published predecessor. Authenticate
  // that observed chain using its actual head epoch; current() separately gates
  // normal reads on the live host epoch, and prospective candidates use the live
  // host. This inspection grants no cross-epoch closure resumption.
  assertLineageCompletionsV2(lineage, {...host, authorization_epoch: head.authorization_epoch},
    {contracts: config.contracts, profile: config.profile})
  return lineage
}
async function originalPendingAbsent(config, host) {
  try { await fs.lstat(path.join(config.directory, `${ownerKey(host)}.pending.json`)) }
  catch (error) { if (error.code === 'ENOENT') return; throw error }
  fail('update-pending')
}
async function pendingAbsent(config, host) {
  await originalPendingAbsent(config, host)
  const cleanup = await cleanupGuard(config, host)
  if (cleanup === null) return null
  const completion = await cleanupCompletion(config, host, cleanup.guard)
  check(completion !== null, 'update-pending')
  return {...cleanup, completion}
}
function assertRetiredCurrent(envelope, cleanup) {
  if (cleanup === null) check(envelope.sequence === 1, 'cleanup-evidence-missing')
  else check(cleanup.guard.pending.prepared_checkpoint_sha256 === envelope.checkpoint_sha256
    && cleanup.completion.value.checkpoint_sha256 === envelope.checkpoint_sha256, 'cleanup-current-conflict')
}
function sameCleanup(before, after) {
  check(before === null ? after === null : after !== null && before.identity === after.identity
    && before.bytes.equals(after.bytes) && before.completion.identity === after.completion.identity
    && before.completion.bytes.equals(after.completion.bytes), 'cleanup-evidence-changed')
}
function transitionBinding(input, host, config) {
  const descriptor = input && typeof input === 'object' && !types.isProxy(input)
    ? Object.getOwnPropertyDescriptor(input, 'kind') : null
  check(descriptor && Object.hasOwn(descriptor, 'value'), 'transition-required')
  const opts = {host, profile: config.profile, contracts: config.contracts}
  let transition, digest, schema
  switch (descriptor.value) {
    case 'prime-runtime-unsent-journal-transition/v3':
      transition = assertJournalTransition(input, opts)
      digest = journalTransitionDigest(transition, {contracts: config.contracts})
      schema = 'aukora-prime-memory-retention-journal-pending/v3'
      break
    case 'prime-runtime-workflow-mutation/v3':
      transition = assertWorkflowTransition(input, opts)
      digest = workflowTransitionDigest(transition, {contracts: config.contracts})
      schema = 'aukora-prime-memory-retention-workflow-pending/v3'
      break
    case 'prime-memory-negative-closure-transition/v3':
      transition = assertNegativeTransition(input, opts)
      digest = negativeTransitionDigest(transition)
      schema = 'aukora-prime-memory-retention-negative-pending/v3'
      break
    case 'prime-memory-control-restore-transition/v3':
      transition = assertRestoreTransition(input, opts)
      digest = restoreTransitionDigest(transition)
      schema = 'aukora-prime-memory-retention-restore-pending/v3'
      break
    case 'prime-memory-authorized-effect-transition/v3':
      transition = assertAuthorizedEffectTransition(input, opts)
      digest = effectTransitionDigest(transition)
      schema = 'aukora-prime-memory-retention-authorized-effect-pending/v3'
      break
    default: fail('transition-purpose-invalid')
  }
  check(typeof digest === 'string' && DIGEST.test(digest), 'transition-digest-invalid')
  return {transition, digest, schema}
}
function requestBinding(input, config, {state = false, checkpoint: withCheckpoint = false} = {}) {
  const request = closedData(input,
    [...REQUEST_KEYS, ...(state ? ['control_state'] : []), ...(withCheckpoint ? ['checkpoint_sha256'] : [])], 'request-fields-invalid')
  const host = checkedHost(request.host), checked = transitionBinding(request.transition, host, config)
  check(typeof request.transition_id === 'string' && UUID_V4.test(request.transition_id)
    && typeof request.transition_digest === 'string' && request.transition_digest === checked.digest,
  'transition-binding-invalid')
  if (withCheckpoint) check(typeof request.checkpoint_sha256 === 'string' && HEX.test(request.checkpoint_sha256), 'checkpoint-invalid')
  const control_state = state ? assertControlV3(request.control_state, host, {contracts: config.contracts, profile: config.profile}) : undefined
  return {...request, host, transition: checked.transition, schema: checked.schema, ...(state ? {control_state} : {})}
}
function matchingPending(marker, fields) {
  check(marker.transition_id === fields.transition_id && marker.transition_digest === fields.transition_digest
    && marker.schema === fields.schema && same(marker.transition, fields.transition), 'pending-binding-conflict')
}
function pendingMarker(value, host, config, {historical = false} = {}) {
  const marker = closedData(value, PENDING_KEYS, 'pending-fields-invalid')
  check(marker.owner_id === host.owner_id && marker.owner_subject === host.owner_subject
    && uint(marker.authorization_epoch) && (historical ? marker.authorization_epoch <= host.authorization_epoch
      : marker.authorization_epoch === host.authorization_epoch), 'pending-owner-epoch-invalid')
  const transition = detachPrivateData(marker.transition)
  const markerHost = historical ? {...host, task_id: transition.reference?.task_id,
    authorization_epoch: marker.authorization_epoch} : host
  const checked = transitionBinding(transition, checkedHost(markerHost), config)
  check(marker.schema === checked.schema && typeof marker.transition_id === 'string' && UUID_V4.test(marker.transition_id)
    && marker.transition_digest === checked.digest, 'pending-transition-invalid')
  check(marker.prepared_checkpoint_sha256 === null && marker.prepared_generation_file === null
    || typeof marker.prepared_checkpoint_sha256 === 'string' && HEX.test(marker.prepared_checkpoint_sha256)
      && marker.prepared_generation_file === `${ownerKey(host)}.${marker.prepared_checkpoint_sha256}.json`,
  'pending-prepared-reference-invalid')
  return {...marker, transition: checked.transition}
}
function cleanupMarkerDigest(marker) {
  return sha256(Buffer.from('aukora-prime.memory-retention-cleanup-marker.v3\0' + canonicalJSON(marker)))
}
function cleanupGuardBinding(value, host, config) {
  const guard = closedData(value, CLEANUP_GUARD_KEYS, 'cleanup-guard-fields-invalid')
  const marker = pendingMarker(guard.pending, host, config, {historical: true})
  check(guard.schema === CLEANUP_GUARD_SCHEMA && marker.prepared_checkpoint_sha256 !== null
    && typeof guard.pending_sha256 === 'string' && HEX.test(guard.pending_sha256)
    && guard.pending_sha256 === cleanupMarkerDigest(marker), 'cleanup-guard-binding-invalid')
  return {schema: CLEANUP_GUARD_SCHEMA, pending: marker, pending_sha256: guard.pending_sha256}
}
function cleanupCompletionBinding(value, guard) {
  const completion = closedData(value, CLEANUP_COMPLETION_KEYS, 'cleanup-completion-fields-invalid')
  check(completion.schema === CLEANUP_COMPLETION_SCHEMA
    && HOST_KEYS.every(key => completion[key] === guard.pending[key])
    && completion.pending_sha256 === guard.pending_sha256
    && completion.checkpoint_sha256 === guard.pending.prepared_checkpoint_sha256,
  'cleanup-completion-binding-invalid')
  return completion
}
async function cleanupGuard(config, host) {
  const source = await readFile(config, `${ownerKey(host)}.cleanup.json`, MAX_BYTES, {optional: true})
  return source === null ? null : {...source, guard: cleanupGuardBinding(source.value, host, config)}
}
async function cleanupCompletion(config, host, guard) {
  const source = await readFile(config, `${ownerKey(host)}.cleanup.${guard.pending_sha256}.complete.json`, pointerLimit, {optional: true})
  if (source === null) return null
  return {...source, value: cleanupCompletionBinding(source.value, guard)}
}
async function pending(config, host) {
  const source = await readFile(config, `${ownerKey(host)}.pending.json`, MAX_BYTES, {optional: true})
  if (source !== null) return {...source, marker: pendingMarker(source.value, host, config), location: 'pending'}
  const cleanup = await cleanupGuard(config, host)
  check(cleanup !== null && await cleanupCompletion(config, host, cleanup.guard) === null, 'pending-missing')
  // Exact retained metadata remains available to the explicit matching command
  // even after primary unlink. This is not a factual-reader cleanup or repair.
  return {...cleanup, marker: pendingMarker(cleanup.guard.pending, host, config), location: 'cleanup'}
}
async function persistCleanupGuard(config, host, inspected, directory) {
  const marker = inspected.marker, guard = {schema: CLEANUP_GUARD_SCHEMA, pending: marker,
    pending_sha256: cleanupMarkerDigest(marker)}
  const existing = await cleanupGuard(config, host)
  if (existing !== null && encode(existing.guard).equals(encode(guard))) {
    check(await cleanupCompletion(config, host, existing.guard) === null, 'cleanup-already-completed')
    // A previous reply/fsync may have been lost. Converge the exact existing
    // guard's directory durability before removing any primary marker.
    await directory.handle.sync()
    const repeated = await cleanupGuard(config, host)
    check(repeated !== null && repeated.identity === existing.identity
      && repeated.bytes.equals(existing.bytes), 'cleanup-guard-changed')
    await directoryUnchanged(config, directory)
    return repeated
  }
  check(inspected.source.location === 'pending', 'cleanup-guard-conflict')
  if (existing !== null) {
    check(await cleanupCompletion(config, host, existing.guard) !== null, 'update-pending')
    check(existing.guard.pending.prepared_checkpoint_sha256 === inspected.predecessor.checkpoint_sha256,
      'cleanup-predecessor-conflict')
  }
  const temporary = `${ownerKey(host)}.cleanup.${randomUUID()}.tmp`
  await createDurableFile(config, temporary, encode(guard))
  await directoryUnchanged(config, directory)
  await fs.rename(path.join(config.directory, temporary), path.join(config.directory, `${ownerKey(host)}.cleanup.json`))
  await directory.handle.sync()
  const retained = await cleanupGuard(config, host)
  check(retained !== null && retained.bytes.equals(encode(guard)), 'cleanup-guard-readback-conflict')
  await directoryUnchanged(config, directory)
  return retained
}
async function publishCleanupCompletion(config, host, retained, directory) {
  const guard = retained.guard
  const completion = {schema: CLEANUP_COMPLETION_SCHEMA, ...envelopeHost(guard.pending),
    pending_sha256: guard.pending_sha256, checkpoint_sha256: guard.pending.prepared_checkpoint_sha256}
  const existing = await cleanupCompletion(config, host, guard)
  if (existing === null) {
    // Publish no partial certificate. The primary unlink, directory fsync and
    // absence verification MUST have succeeded before this function is called.
    // Therefore a later certificate publication failure can reduce availability
    // after a crash, but cannot certify a failed pending-removal fsync.
    const temporary = `${ownerKey(host)}.cleanup.${randomUUID()}.complete.tmp`
    await createDurableFile(config, temporary, encode(completion))
    await directoryUnchanged(config, directory)
    await fs.rename(path.join(config.directory, temporary),
      path.join(config.directory, `${ownerKey(host)}.cleanup.${guard.pending_sha256}.complete.json`))
  }
  await directory.handle.sync()
  const proof = await cleanupCompletion(config, host, guard)
  check(proof !== null && proof.bytes.equals(encode(completion)), 'cleanup-completion-readback-conflict')
  const repeated = await cleanupGuard(config, host)
  check(repeated !== null && repeated.identity === retained.identity && repeated.bytes.equals(retained.bytes), 'cleanup-guard-changed')
  await directoryUnchanged(config, directory)
  return proof
}
async function syncPublishedCandidate(config, host, inspected, directory) {
  await directoryUnchanged(config, directory)
  await directory.handle.sync()
  const retained = await current(config, host, directory)
  check(encode(retained).equals(encode(inspected.prepared)), 'publication-readback-conflict')
  const repeated = await pending(config, host)
  check(repeated.location === inspected.source.location && repeated.identity === inspected.source.identity
    && repeated.bytes.equals(inspected.source.bytes), 'pending-changed')
  await directoryUnchanged(config, directory)
  return retained
}
function candidateEnvelope(host, predecessor, control_state) {
  const sequence = predecessor.sequence + 1
  check(Number.isSafeInteger(sequence), 'sequence-invalid')
  const body = {schema: PRIVATE_V2_RETENTION_SCHEMA, ...envelopeHost(host), sequence,
    previous_checkpoint_sha256: predecessor.checkpoint_sha256, control_state}
  const envelope = {...body, checkpoint_sha256: checkpoint(body)}
  check(encode(envelope).length <= MAX_BYTES, 'bytes-limit')
  return envelope
}
async function purposeAdvance(previous, candidate, marker, host, config, published_ancestry) {
  // The parser verifies full immutable metadata/profile and every original control
  // row, then validates only this closed purpose's target/CAS. No callback flag is
  // accepted as evidence for a candidate or for publication.
  if (marker.transition.kind === 'prime-memory-authorized-effect-transition/v3'
    && marker.transition.operation.action_type === 'memory.restore') {
    assertRestoreEffectAdvance(previous.control_state, candidate.control_state, host,
      {contracts: config.contracts, profile: config.profile, transition: marker.transition, published_ancestry})
  } else if (marker.transition.kind === 'prime-memory-control-restore-transition/v3') {
    // The retained predecessor is the independently published CURRENT restore
    // anchor. The publisher never authenticates a caller's local SQL ancestor or
    // chooses a snapshot. The participant verifies that separate committed
    // interval before SQL restore; publication only wraps the exact existing
    // anchor control in the one prepared successor envelope.
    check(marker.transition.anchor_checkpoint_sha256 === previous.checkpoint_sha256
      && same(candidate.control_state, previous.control_state), 'restore-candidate-anchor-mismatch')
    assertForwardControlV3(previous.control_state, candidate.control_state, host,
      {contracts: config.contracts, profile: config.profile})
  } else assertForwardControlV3(previous.control_state, candidate.control_state, host,
    {contracts: config.contracts, profile: config.profile, transition: marker.transition})
}
async function pendingFiles(config, host, directory) {
  const source = await pending(config, host), marker = source.marker
  const predecessor = await generation(config, host, marker.transition.expected_checkpoint_sha256, {pastEpoch: true})
  const retained = await current(config, host, directory, {pastEpoch: true})
  const published = await publishedLineage(config, host, retained)
  const previousIndex = published.findIndex(envelope => envelope.checkpoint_sha256 === predecessor.checkpoint_sha256)
  check(previousIndex >= 0 && encode(published[previousIndex]).equals(encode(predecessor)), 'pending-predecessor-unpublished')
  let prepared = null
  if (marker.prepared_checkpoint_sha256 !== null) {
    prepared = await generation(config, host, marker.prepared_checkpoint_sha256)
    check(prepared.previous_checkpoint_sha256 === predecessor.checkpoint_sha256
      && prepared.sequence === predecessor.sequence + 1, 'prepared-predecessor-invalid')
    await purposeAdvance(predecessor, prepared, marker, host, config, published.slice(previousIndex))
  }
  check(retained.checkpoint_sha256 === predecessor.checkpoint_sha256
    || prepared !== null && encode(retained).equals(encode(prepared)), 'pending-current-conflict')
  if (source.location === 'cleanup') check(prepared !== null && encode(retained).equals(encode(prepared)),
    'cleanup-publication-required')
  if (prepared !== null && retained.checkpoint_sha256 === predecessor.checkpoint_sha256) {
    // Prepared bytes establish no publication. This prospective content check
    // nevertheless prevents B from storing an invented completion before SQL
    // COMMIT: every referenced A must already be on the actual published chain.
    assertLineageCompletionsV2([prepared, ...published], host,
      {contracts: config.contracts, profile: config.profile})
  }
  const repeated = await pending(config, host)
  check(repeated.identity === source.identity && repeated.bytes.equals(source.bytes), 'pending-changed')
  await directoryUnchanged(config, directory)
  return {source, marker, predecessor, prepared, current: retained}
}
const projection = inspected => ({marker: inspected.marker, predecessor: inspected.predecessor,
  prepared: inspected.prepared, current: inspected.current})

export function isPrivateV2FileRetentionReader(adapter) { return readers.has(adapter) }
export function isPrivateV2FileRetentionPublisher(adapter) { return publishers.has(adapter) }

// Pure structural/digest inspection is useful for cold artifacts, but does not
// register a reader/publisher, attest custody, authorize restore or publish data.
export function assertRetentionV2(input, inputHost, {contracts, profile, pastEpoch = false} = {}) {
  return envelopeBinding(input, checkedHost(inputHost), {contracts, profile}, {pastEpoch})
}

export function createPrivateV2FileRetentionReader(input) {
  const config = configuration(input, 'reader')
  const readCurrent = async inputHost => {
    const host = checkedHost(inputHost)
    return withDirectory(config, async directory => {
      const cleanup = await pendingAbsent(config, host)
      const envelope = await current(config, host, directory)
      assertRetiredCurrent(envelope, cleanup)
      const repeated = await pendingAbsent(config, host)
      assertRetiredCurrent(envelope, repeated); sameCleanup(cleanup, repeated)
      await directoryUnchanged(config, directory)
      return envelope
    })
  }
  const inspectPublishedCurrent = async inputHost => {
    const host = checkedHost(inputHost)
    return withDirectory(config, directory => current(config, host, directory, {pastEpoch: true}))
  }
  const inspectPending = async inputHost => {
    const host = checkedHost(inputHost)
    return withDirectory(config, async directory => projection(await pendingFiles(config, host, directory)))
  }
  const readPending = async inputRequest => {
    const request = closedData(inputRequest, ['host', 'transition_id', 'transition_digest'], 'recovery-fields-invalid')
    const host = checkedHost(request.host)
    check(typeof request.transition_id === 'string' && UUID_V4.test(request.transition_id)
      && typeof request.transition_digest === 'string' && DIGEST.test(request.transition_digest), 'recovery-binding-invalid')
    return withDirectory(config, async directory => {
      const inspected = await pendingFiles(config, host, directory)
      check(inspected.marker.transition_id === request.transition_id
        && inspected.marker.transition_digest === request.transition_digest, 'pending-binding-conflict')
      return projection(inspected)
    })
  }
  const readPublishedLineage = async (inputHost, inputRequest) => {
    const host = checkedHost(inputHost)
    const request = closedData(inputRequest, ['checkpoint_sha256'], 'lineage-fields-invalid')
    check(request.checkpoint_sha256 === null || typeof request.checkpoint_sha256 === 'string'
      && HEX.test(request.checkpoint_sha256), 'lineage-checkpoint-invalid')
    return withDirectory(config, async directory => {
      const cleanup = await pendingAbsent(config, host)
      const head = await current(config, host, directory)
      assertRetiredCurrent(head, cleanup)
      const lineage = await publishedLineage(config, host, head)
      check(request.checkpoint_sha256 === null || lineage.some(envelope => envelope.checkpoint_sha256 === request.checkpoint_sha256),
        'lineage-checkpoint-unpublished')
      const repeated = await current(config, host, directory)
      check(encode(repeated).equals(encode(head)), 'current-changed')
      const repeatedCleanup = await pendingAbsent(config, host)
      assertRetiredCurrent(head, repeatedCleanup); sameCleanup(cleanup, repeatedCleanup)
      await directoryUnchanged(config, directory)
      return lineage
    })
  }
  const adapter = Object.freeze({readCurrent, inspectPublishedCurrent, inspectPending, readPending, readPublishedLineage,
    status: Object.freeze({configured: true, kind: 'private-v2-file-reader', schema: PRIVATE_V2_RETENTION_SCHEMA,
      expected_authority_store_id: config.profile.expected_authority_store_id,
      expected_memory_store_id: config.profile.expected_memory_store_id})})
  readers.add(adapter)
  return adapter
}

export function createPrivateV2FileRetentionPublisher(input) {
  const config = configuration(input, 'publisher')
  let uncertain = false
  const guarded = async action => {
    check(!uncertain, 'commit-uncertain')
    try { return await action() }
    catch (error) { if (error.code === 'memory:private-v2-retention-commit-uncertain') uncertain = true; throw error }
  }
  const beginTyped = async inputRequest => guarded(async () => {
    const fields = requestBinding(inputRequest, config), host = fields.host
    const marker = {schema: fields.schema, ...envelopeHost(host), transition_id: fields.transition_id,
      transition: fields.transition, transition_digest: fields.transition_digest,
      prepared_checkpoint_sha256: null, prepared_generation_file: null}
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      const cleanup = await pendingAbsent(config, host)
      const retained = await current(config, host, directory, {pastEpoch: true})
      assertRetiredCurrent(retained, cleanup)
      check(retained.checkpoint_sha256 === fields.transition.expected_checkpoint_sha256, 'checkpoint-conflict')
      try {
        await createDurableFile(config, `${ownerKey(host)}.pending.json`, encode(marker))
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
        const repeated = await pending(config, host)
        check(repeated.bytes.equals(encode(marker)), 'pending-changed')
      } catch { fail('commit-uncertain') }
      return marker
    }))
  })
  const retainPrepared = async inputRequest => guarded(async () => {
    const fields = requestBinding(inputRequest, config, {state: true}), host = fields.host
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      const inspected = await pendingFiles(config, host, directory)
      matchingPending(inspected.marker, fields)
      check(inspected.current.checkpoint_sha256 === fields.transition.expected_checkpoint_sha256, 'checkpoint-conflict')
      const envelope = candidateEnvelope(host, inspected.predecessor, fields.control_state)
      const published = await publishedLineage(config, host, inspected.current)
      await purposeAdvance(inspected.predecessor, envelope, inspected.marker, host, config, published)
      // Validate the candidate against protected CURRENT ancestry before writing
      // a prepared generation and before the participant's PG COMMIT. The
      // candidate remains unpublished and cannot qualify a factual read.
      assertLineageCompletionsV2([envelope, ...published], host,
        {contracts: config.contracts, profile: config.profile})
      if (inspected.prepared !== null) {
        check(encode(inspected.prepared).equals(encode(envelope)), 'prepared-conflict')
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
        const repeated = await pending(config, host)
        check(repeated.identity === inspected.source.identity && repeated.bytes.equals(inspected.source.bytes), 'pending-changed')
        await directoryUnchanged(config, directory)
        await fs.rename(path.join(config.directory, temporary), path.join(config.directory, `${ownerKey(host)}.pending.json`))
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
        const readback = await pendingFiles(config, host, directory)
        check(readback.prepared !== null && encode(readback.prepared).equals(encode(envelope)), 'prepared-readback-conflict')
      } catch { fail('commit-uncertain') }
      return envelope
    }))
  })
  const publishPrepared = async inputRequest => guarded(async () => {
    const fields = requestBinding(inputRequest, config, {state: true}), host = fields.host
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      const inspected = await pendingFiles(config, host, directory)
      matchingPending(inspected.marker, fields)
      check(inspected.prepared !== null && same(inspected.prepared.control_state, fields.control_state), 'prepared-required')
      // Reuse the originally retained candidate byte-for-byte. A lost reply cannot
      // allocate a replacement generation or new checkpoint.
      if (inspected.current.checkpoint_sha256 === inspected.prepared.checkpoint_sha256) {
        try { return await syncPublishedCandidate(config, host, inspected, directory) }
        catch { fail('commit-uncertain') }
      }
      const envelope = inspected.prepared, key = ownerKey(host)
      const generation_file = `${key}.${envelope.checkpoint_sha256}.json`
      try {
        const pointer = {schema: POINTER_SCHEMA, ...envelopeHost(host), sequence: envelope.sequence,
          checkpoint_sha256: envelope.checkpoint_sha256, generation_file}
        const temporary = `${key}.current.${randomUUID()}.tmp`
        await createDurableFile(config, temporary, encode(pointer))
        const repeated = await pendingFiles(config, host, directory)
        check(repeated.source.identity === inspected.source.identity && repeated.source.bytes.equals(inspected.source.bytes)
          && repeated.current.checkpoint_sha256 === fields.transition.expected_checkpoint_sha256, 'publication-conflict')
        await directoryUnchanged(config, directory)
        await fs.rename(path.join(config.directory, temporary), path.join(config.directory, `${key}.current.json`))
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
        const readback = await current(config, host, directory)
        check(encode(readback).equals(encode(envelope)), 'publication-readback-conflict')
        const stillPending = await pending(config, host)
        check(stillPending.identity === inspected.source.identity && stillPending.bytes.equals(inspected.source.bytes), 'pending-changed')
      } catch { fail('commit-uncertain') }
      return envelope
    }))
  })
  const clearMatchingPending = async inputRequest => guarded(async () => {
    const fields = requestBinding(inputRequest, config, {checkpoint: true}), host = fields.host
    return withDirectory(config, directory => ownerLock(config, host, async () => {
      const inspected = await pendingFiles(config, host, directory)
      matchingPending(inspected.marker, fields)
      check(inspected.prepared !== null && inspected.prepared.checkpoint_sha256 === fields.checkpoint_sha256
        && encode(inspected.current).equals(encode(inspected.prepared)), 'cleanup-publication-required')
      try {
        await syncPublishedCandidate(config, host, inspected, directory)
        // Never make transient primary-marker absence the admission boundary.
        // A permanent exact guard survives unlink/fsync uncertainty and restarts.
        // Factual readers accept it only with immutable completion evidence that
        // can be written after actual durable removal/absence has converged.
        const cleanup = await persistCleanupGuard(config, host, inspected, directory)
        const repeated = await pending(config, host)
        check(same(repeated.marker, inspected.marker), 'pending-changed')
        if (inspected.source.location === 'pending') check(repeated.location === 'pending'
          && repeated.identity === inspected.source.identity && repeated.bytes.equals(inspected.source.bytes), 'pending-changed')
        else check(repeated.location === 'cleanup' && repeated.identity === cleanup.identity
          && repeated.bytes.equals(cleanup.bytes), 'cleanup-guard-changed')
        await directoryUnchanged(config, directory)
        if (repeated.location === 'pending') await fs.unlink(path.join(config.directory, `${ownerKey(host)}.pending.json`))
        // Matching cleanup-only recovery performs this fsync even when the
        // primary path is already absent; it never replays SQL or effects.
        await directory.handle.sync()
        await directoryUnchanged(config, directory)
        await originalPendingAbsent(config, host)
        const readback = await current(config, host, directory)
        check(encode(readback).equals(encode(inspected.prepared)), 'cleanup-publication-changed')
        await originalPendingAbsent(config, host)
        await publishCleanupCompletion(config, host, cleanup, directory)
        const completed = await pendingAbsent(config, host)
        assertRetiredCurrent(readback, completed)
      } catch { fail('commit-uncertain') }
      return inspected.current
    }))
  })
  const adapter = Object.freeze({beginTyped, retainPrepared, publishPrepared, clearMatchingPending,
    status: Object.freeze({configured: true, kind: 'private-v2-file-publisher', schema: PRIVATE_V2_RETENTION_SCHEMA,
      expected_authority_store_id: config.profile.expected_authority_store_id,
      expected_memory_store_id: config.profile.expected_memory_store_id})})
  publishers.add(adapter)
  return adapter
}
