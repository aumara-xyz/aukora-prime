// SPDX-License-Identifier: AGPL-3.0-or-later
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MAX_BYTES, parseOriginal, requireMemory, sha256 } from './codecs.mjs'
import { MEMORY_AUDIENCE, memoryTarget } from './authorization.mjs'
import { inspectMemoryControlState } from './control-state.mjs'
import { isControlRetentionReader, MEMORY_RETENTION_SCHEMA } from './control-retention.mjs'

const coordinators = new WeakSet()
const HOST_KEYS = ['owner_id', 'owner_subject', 'authorization_epoch']
const TUPLE_FIELDS = ['expected_checkpoint_sha256', 'operation_id', 'operation_digest', 'request_id', 'request_digest']
const ENVELOPE_KEYS = ['schema', ...HOST_KEYS, 'sequence', 'previous_checkpoint_sha256', 'control_state', 'checkpoint_sha256']
const MARKER_KEYS = ['schema', ...HOST_KEYS, ...TUPLE_FIELDS, 'prepared_checkpoint_sha256', 'prepared_generation_file']
const MUTATION_SCHEMA = 'aukora-prime-memory-retention-pending/v2'
const ACTIONS = ['memory.save', 'memory.import', 'memory.restore', 'memory.backup', 'memory.forget', 'memory.purge', 'memory.erase-owner']
const HEX = /^[0-9a-f]{64}$/, DIGEST = /^sha256:[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const check = (condition, code) => requireMemory(condition, `memory:control-retention-coordinator-${code}`)
const same = (left, right) => canonicalJSON(left) === canonicalJSON(right)
const uint = value => Number.isSafeInteger(value) && value >= 0
const nonempty = value => typeof value === 'string' && value.length > 0 && value.length <= 4096

function dataFields(value, keys, code) {
  check(value && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)), code)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  check(Reflect.ownKeys(descriptors).length === keys.length && keys.every(key => descriptors[key]
    && Object.hasOwn(descriptors[key], 'value') && descriptors[key].enumerable), code)
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value]))
}

// Detach only inert bounded JSON. Never run guest getters, serializers or proxy traps.
function detached(value) {
  const active = new WeakSet()
  let size = 0, count = 0
  const charge = value => { size += Buffer.byteLength(value); check(size <= MAX_BYTES, 'bytes-limit') }
  function copy(node, depth) {
    check(depth <= 64 && ++count <= 2000000, 'json-limit')
    if (node === null || typeof node === 'boolean') return node
    if (typeof node === 'string') { charge(node); return node }
    if (typeof node === 'number') {
      check(Number.isFinite(node) && (!Number.isInteger(node) || Number.isSafeInteger(node)), 'number-invalid')
      return node
    }
    check(node && typeof node === 'object' && !types.isProxy(node) && !active.has(node), 'inert-json-required')
    const array = Array.isArray(node), proto = Object.getPrototypeOf(node)
    check(proto === (array ? Array.prototype : Object.prototype) || (!array && proto === null), 'inert-json-required')
    const descriptors = Object.getOwnPropertyDescriptors(node), result = array ? [] : Object.create(null)
    check(Reflect.ownKeys(descriptors).every(key => typeof key === 'string'), 'inert-json-required')
    if (array) check(descriptors.length && Object.hasOwn(descriptors.length, 'value')
      && descriptors.length.value <= 10000, 'json-limit')
    active.add(node)
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (array && key === 'length') continue
      check(Object.hasOwn(descriptor, 'value') && descriptor.enumerable
        && (!array || /^(?:0|[1-9][0-9]*)$/.test(key)), 'inert-json-required')
      charge(key)
      Object.defineProperty(result, key, {value: copy(descriptor.value, depth + 1), enumerable: true, writable: true, configurable: true})
    }
    if (array) check(result.length === descriptors.length.value && Object.keys(result).length === result.length,
      'inert-json-required')
    active.delete(node)
    return result
  }
  const copied = copy(value, 0), bytes = Buffer.from(canonicalJSON(copied))
  check(bytes.length <= MAX_BYTES, 'bytes-limit')
  return parseOriginal(bytes)
}
function frozen(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) frozen(child)
    Object.freeze(value)
  }
  return value
}
function hostBinding(input) {
  const host = dataFields(input, HOST_KEYS, 'host-required')
  check(nonempty(host.owner_id) && nonempty(host.owner_subject) && uint(host.authorization_epoch), 'host-required')
  return detached(host)
}
function ownMethods(input, keys, code) {
  check(input && typeof input === 'object' && !types.isProxy(input), code)
  const descriptors = Object.getOwnPropertyDescriptors(input)
  check(keys.every(key => descriptors[key] && Object.hasOwn(descriptors[key], 'value')
    && typeof descriptors[key].value === 'function'), code)
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value.bind(input)]))
}
function envelopeBinding(input, host, contracts, {pastEpoch = false} = {}) {
  const envelope = detached(input)
  dataFields(envelope, ENVELOPE_KEYS, 'envelope-fields-invalid')
  check(envelope.schema === MEMORY_RETENTION_SCHEMA && envelope.owner_id === host.owner_id
    && envelope.owner_subject === host.owner_subject && uint(envelope.authorization_epoch)
    && (pastEpoch ? envelope.authorization_epoch <= host.authorization_epoch : envelope.authorization_epoch === host.authorization_epoch),
  'envelope-binding-invalid')
  check(Number.isSafeInteger(envelope.sequence) && envelope.sequence >= 1
    && typeof envelope.checkpoint_sha256 === 'string' && HEX.test(envelope.checkpoint_sha256)
    && (envelope.previous_checkpoint_sha256 === null || typeof envelope.previous_checkpoint_sha256 === 'string'
      && HEX.test(envelope.previous_checkpoint_sha256))
    && (envelope.sequence === 1) === (envelope.previous_checkpoint_sha256 === null), 'envelope-checkpoint-invalid')
  const {checkpoint_sha256: digest, ...body} = envelope
  check(sha256(Buffer.from('aukora-prime.memory-retention.v1\0' + canonicalJSON(body))) === digest, 'envelope-digest-invalid')
  inspectMemoryControlState(envelope.control_state, host, {contracts})
  return envelope
}
function operationBinding(input, host, contracts) {
  const operation = detached(input)
  try { contracts.validateContract('OperationProposal', operation) }
  catch { check(false, 'operation-invalid') }
  check(nonempty(operation.operation_id) && operation.owner_id === host.owner_id
    && operation.authorization_epoch === host.authorization_epoch && operation.audience === MEMORY_AUDIENCE
    && ACTIONS.includes(operation.action_type) && same(operation.target_identity, memoryTarget(host.owner_subject)),
  'operation-binding-invalid')
  const digest = contracts.operationDigest(operation)
  check(typeof digest === 'string' && DIGEST.test(digest), 'operation-digest-invalid')
  return {operation, digest}
}
function requestBinding(input, contracts) {
  const request = dataFields(input, ['host', 'operation', 'request_id', 'request_digest'], 'request-fields-invalid')
  const host = hostBinding(request.host), {operation, digest} = operationBinding(request.operation, host, contracts)
  check(typeof request.request_id === 'string' && UUID.test(request.request_id)
    && typeof request.request_digest === 'string' && DIGEST.test(request.request_digest), 'request-binding-invalid')
  return {host, operation, operation_id: operation.operation_id, operation_digest: digest,
    request_id: request.request_id, request_digest: request.request_digest}
}
function markerBinding(input, tuple) {
  const marker = detached(input)
  dataFields(marker, MARKER_KEYS, 'marker-fields-invalid')
  check(marker.schema === MUTATION_SCHEMA && HOST_KEYS.every(key => marker[key] === tuple.host[key])
    && TUPLE_FIELDS.every(key => marker[key] === tuple[key]), 'marker-binding-invalid')
  check(typeof marker.expected_checkpoint_sha256 === 'string' && HEX.test(marker.expected_checkpoint_sha256)
    && nonempty(marker.operation_id) && typeof marker.operation_digest === 'string' && DIGEST.test(marker.operation_digest)
    && typeof marker.request_id === 'string' && UUID.test(marker.request_id)
    && typeof marker.request_digest === 'string' && DIGEST.test(marker.request_digest), 'marker-binding-invalid')
  check(marker.prepared_checkpoint_sha256 === null && marker.prepared_generation_file === null
    || typeof marker.prepared_checkpoint_sha256 === 'string' && HEX.test(marker.prepared_checkpoint_sha256)
      && typeof marker.prepared_generation_file === 'string', 'marker-prepared-invalid')
  if (marker.prepared_checkpoint_sha256 !== null) {
    const ownerKey = sha256(Buffer.from('aukora-prime.memory-retention-owner.v1\0'
      + canonicalJSON({owner_id: tuple.host.owner_id, owner_subject: tuple.host.owner_subject})))
    check(marker.prepared_generation_file === `${ownerKey}.${marker.prepared_checkpoint_sha256}.json`, 'marker-prepared-invalid')
  }
  return marker
}
function pendingBinding(input, tuple, predecessor, contracts, {withCurrent = false} = {}) {
  const fields = dataFields(input, withCurrent ? ['marker', 'predecessor', 'prepared', 'current']
    : ['marker', 'predecessor', 'prepared'], 'pending-fields-invalid')
  const marker = markerBinding(fields.marker, tuple)
  const observed = envelopeBinding(fields.predecessor, tuple.host, contracts, {pastEpoch: true})
  check(observed.checkpoint_sha256 === tuple.expected_checkpoint_sha256 && same(observed, predecessor), 'predecessor-changed')
  const prepared = fields.prepared === null ? null : envelopeBinding(fields.prepared, tuple.host, contracts)
  check((prepared === null) === (marker.prepared_checkpoint_sha256 === null), 'prepared-reference-invalid')
  if (prepared) check(prepared.checkpoint_sha256 === marker.prepared_checkpoint_sha256
    && prepared.previous_checkpoint_sha256 === observed.checkpoint_sha256
    && prepared.sequence === observed.sequence + 1, 'prepared-reference-invalid')
  const current = withCurrent ? envelopeBinding(fields.current, tuple.host, contracts, {pastEpoch: true}) : null
  if (current) check(same(current, observed) || prepared !== null
    && current.authorization_epoch === tuple.host.authorization_epoch
    && current.previous_checkpoint_sha256 === observed.checkpoint_sha256 && current.sequence === observed.sequence + 1,
  'current-predecessor-invalid')
  return {marker, predecessor: observed, prepared, ...(withCurrent ? {current} : {})}
}

export function isControlRetentionCoordinator(value) { return coordinators.has(value) }

/** D-owned ordering facade. The H publisher transport is private; its responses never establish retention. */
export function createControlRetentionCoordinator(input) {
  const config = dataFields(input, ['reader', 'publisher', 'contracts'], 'configuration-required')
  check(isControlRetentionReader(config.reader), 'owned-reader-required')
  const reader = config.reader
  const readerFields = Object.getOwnPropertyDescriptors(reader)
  check(readerFields.status && Object.hasOwn(readerFields.status, 'value'), 'file-reader-required')
  const status = dataFields(readerFields.status.value, ['configured', 'kind', 'schema'], 'file-reader-required')
  check(status.configured === true && status.kind === 'file-reader' && status.schema === MEMORY_RETENTION_SCHEMA,
    'file-reader-required')
  const read = ownMethods(reader, ['readCurrent', 'readPending', 'inspectPending', 'observePredecessor'], 'reader-methods-required')
  const publish = ownMethods(config.publisher, ['beginMutation', 'retainPrepared', 'publishMutation'], 'publisher-methods-required')
  const contracts = ownMethods(config.contracts, ['validateContract', 'operationDigest'], 'contracts-required')
  const contexts = new WeakSet()
  const contextFor = (tuple, predecessor) => {
    const context = frozen(detached({tuple, predecessor}))
    contexts.add(context)
    return context
  }
  const owned = context => { check(contexts.has(context), 'owned-context-required'); return context }
  const tupleFor = (request, checkpoint) => ({host: request.host, expected_checkpoint_sha256: checkpoint,
    operation_id: request.operation_id, operation_digest: request.operation_digest,
    request_id: request.request_id, request_digest: request.request_digest})
  const begin = async inputRequest => {
    const request = requestBinding(inputRequest, contracts)
    const predecessor = envelopeBinding(await read.readCurrent(request.host), request.host, contracts)
    const tuple = tupleFor(request, predecessor.checkpoint_sha256)
    await publish.beginMutation(frozen(detached(tuple)))
    const observed = pendingBinding(await read.readPending(tuple), tuple, predecessor, contracts)
    check(observed.prepared === null, 'begin-already-prepared')
    return contextFor(tuple, predecessor)
  }
  const prepared = async (inputContext, inputState) => {
    const context = owned(inputContext), control_state = detached(inputState)
    inspectMemoryControlState(control_state, context.tuple.host, {contracts})
    await publish.retainPrepared(frozen(detached({...context.tuple, control_state})))
    const observed = pendingBinding(await read.readPending(context.tuple), context.tuple, context.predecessor, contracts)
    check(observed.prepared !== null && same(observed.prepared.control_state, control_state), 'prepared-readback-mismatch')
    return frozen(observed.prepared)
  }
  const complete = async (inputContext, inputState) => {
    const context = owned(inputContext), control_state = detached(inputState)
    inspectMemoryControlState(control_state, context.tuple.host, {contracts})
    const inspected = pendingBinding(await read.inspectPending(context.tuple.host), context.tuple, context.predecessor,
      contracts, {withCurrent: true})
    check(inspected.prepared !== null, 'prepared-required')
    await publish.publishMutation(frozen(detached({...context.tuple, control_state})))
    const retained = envelopeBinding(await read.readCurrent(context.tuple.host), context.tuple.host, contracts)
    check(retained.previous_checkpoint_sha256 === context.predecessor.checkpoint_sha256
      && retained.sequence === context.predecessor.sequence + 1 && same(retained.control_state, control_state),
    'publication-readback-mismatch')
    return frozen(retained)
  }
  const observe = async inputContext => {
    const context = owned(inputContext)
    const predecessor = envelopeBinding(await read.observePredecessor(context.tuple), context.tuple.host, contracts, {pastEpoch: true})
    check(same(predecessor, context.predecessor), 'predecessor-changed')
    return frozen(predecessor)
  }
  const inspect = async inputHost => {
    const host = hostBinding(inputHost), value = await read.inspectPending(host)
    const fields = dataFields(value, ['marker', 'predecessor', 'prepared', 'current'], 'pending-fields-invalid')
    const marker = detached(fields.marker)
    dataFields(marker, MARKER_KEYS, 'marker-fields-invalid')
    const tuple = {host, ...Object.fromEntries(TUPLE_FIELDS.map(key => [key, marker[key]]))}
    const predecessor = envelopeBinding(fields.predecessor, host, contracts, {pastEpoch: true})
    return frozen(pendingBinding(value, tuple, predecessor, contracts, {withCurrent: true}))
  }
  const recover = async inputRequest => {
    const request = requestBinding(inputRequest, contracts)
    const inspected = await inspect(request.host)
    const tuple = tupleFor(request, inspected.marker.expected_checkpoint_sha256)
    markerBinding(inspected.marker, tuple)
    return contextFor(tuple, inspected.predecessor)
  }
  const coordinator = Object.freeze({reader, begin, prepared, complete, observe, inspect, recover, isContext:context=>contexts.has(context),
    status: Object.freeze({configured: true, kind: 'control-retention-coordinator', schema: MEMORY_RETENTION_SCHEMA})})
  coordinators.add(coordinator)
  return coordinator
}
