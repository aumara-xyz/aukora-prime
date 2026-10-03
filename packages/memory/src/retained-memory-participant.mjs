// SPDX-License-Identifier: AGPL-3.0-or-later
import { AsyncLocalStorage } from 'node:async_hooks'
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MAX_BYTES, parseOriginal, requireMemory, sha256 } from './codecs.mjs'
import { MEMORY_AUDIENCE, memoryTarget, memoryReceiptDigest, memoryResultDigest } from './authorization.mjs'
import { inspectMemoryControlState } from './control-state.mjs'
import { isControlRetentionCoordinator } from './control-retention-coordinator.mjs'
import { isMemoryOwnerSerializer } from './owner-serialization.mjs'
import { createPrivateV2EffectController } from './private-v2-effect-participant.mjs'

const participants = new WeakSet()
const privateV2Profiles = new WeakMap()
const HOST = ['owner_id', 'owner_subject', 'authorization_epoch']
const HEX = /^[0-9a-f]{64}$/, DIGEST = /^sha256:[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const ACTIONS = ['memory.save', 'memory.import', 'memory.restore', 'memory.backup', 'memory.forget', 'memory.purge', 'memory.erase-owner']
const check = (value, code) => requireMemory(value, `memory:retained-participant-${code}`)
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)
const nonempty = value => typeof value === 'string' && value.length > 0 && value.length <= 4096
function fields(value, keys, code) {
  check(value && typeof value === 'object' && !types.isProxy(value) && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)), code)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  check(Reflect.ownKeys(descriptors).length === keys.length && keys.every(key => descriptors[key]
    && Object.hasOwn(descriptors[key], 'value') && descriptors[key].enumerable), code)
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value]))
}
function copy(input) {
  const seen = new WeakSet(); let size = 0, count = 0
  function visit(value, depth) {
    check(depth <= 64 && ++count <= 2000000, 'json-limit')
    if (value === null || typeof value === 'boolean') return value
    if (typeof value === 'string') { size += Buffer.byteLength(value); check(size <= MAX_BYTES, 'bytes-limit'); return value }
    if (typeof value === 'number') {
      check(Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value)), 'number-invalid'); return value
    }
    check(value && typeof value === 'object' && !types.isProxy(value) && !seen.has(value), 'inert-json-required')
    const array = Array.isArray(value), proto = Object.getPrototypeOf(value)
    check(proto === (array ? Array.prototype : Object.prototype) || (!array && proto === null), 'inert-json-required')
    const ds = Object.getOwnPropertyDescriptors(value), result = array ? [] : Object.create(null)
    check(Reflect.ownKeys(ds).every(key => typeof key === 'string'), 'inert-json-required')
    if (array) check(ds.length.value <= 10000, 'json-limit')
    seen.add(value)
    for (const [key, descriptor] of Object.entries(ds)) {
      if (array && key === 'length') continue
      check(Object.hasOwn(descriptor, 'value') && descriptor.enumerable
        && (!array || /^(?:0|[1-9][0-9]*)$/.test(key)), 'inert-json-required')
      size += Buffer.byteLength(key); check(size <= MAX_BYTES, 'bytes-limit')
      Object.defineProperty(result, key, {value: visit(descriptor.value, depth + 1), enumerable: true, writable: true, configurable: true})
    }
    if (array) check(result.length === ds.length.value && Object.keys(result).length === result.length, 'inert-json-required')
    seen.delete(value); return result
  }
  const bytes = Buffer.from(canonicalJSON(visit(input, 0)))
  check(bytes.length <= MAX_BYTES, 'bytes-limit')
  return parseOriginal(bytes)
}
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value) }
  return value
}
const detached = input => freeze(copy(input))
function methods(object, keys, code) {
  check(object && typeof object === 'object' && !types.isProxy(object), code)
  const descriptors = Object.getOwnPropertyDescriptors(object)
  check(keys.every(key => descriptors[key] && Object.hasOwn(descriptors[key], 'value')
    && typeof descriptors[key].value === 'function'), code)
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value.bind(object)]))
}
export const isRetainedMemoryParticipant = value => participants.has(value)

// Controller remains trusted worker-only. Only its three phase methods cross the private C channel.
export function createRetainedMemoryParticipant(input) {
  const {coordinator, serializer, contracts: supplied} = fields(input, ['coordinator', 'serializer', 'contracts'], 'configuration-required')
  check(isControlRetentionCoordinator(coordinator), 'owned-coordinator-required')
  check(isMemoryOwnerSerializer(serializer), 'owned-serializer-required')
  const contracts = methods(supplied, ['validateContract', 'operationDigest'], 'contracts-required')
  const contextBrand = methods(coordinator, ['isContext'], 'context-brand-required').isContext
  const active = new Map(), storage = new AsyncLocalStorage()
  function operation(inputOperation) {
    const op = detached(inputOperation)
    try { contracts.validateContract('OperationProposal', op) } catch { check(false, 'operation-invalid') }
    check(nonempty(op.operation_id) && nonempty(op.owner_id) && Number.isSafeInteger(op.authorization_epoch)
      && op.authorization_epoch >= 0 && op.audience === MEMORY_AUDIENCE && ACTIONS.includes(op.action_type), 'operation-invalid')
    const digest = contracts.operationDigest(op)
    check(typeof digest === 'string' && DIGEST.test(digest), 'operation-digest-invalid')
    return {op, digest, key: canonicalJSON([op.operation_id, digest])}
  }
  function request(inputRequest) {
    const req = fields(inputRequest, ['host', 'operation', 'request_id', 'request_digest'], 'request-fields-invalid')
    const host = detached(fields(req.host, HOST, 'host-required'))
    check(nonempty(host.owner_id) && nonempty(host.owner_subject) && Number.isSafeInteger(host.authorization_epoch)
      && host.authorization_epoch >= 0, 'host-required')
    const bound = operation(req.operation)
    check(bound.op.owner_id === host.owner_id && bound.op.authorization_epoch === host.authorization_epoch
      && same(bound.op.target_identity, memoryTarget(host.owner_subject)), 'operation-binding-invalid')
    check(typeof req.request_id === 'string' && UUID.test(req.request_id)
      && typeof req.request_digest === 'string' && DIGEST.test(req.request_digest), 'request-binding-invalid')
    return {...bound, host, request_id: req.request_id, request_digest: req.request_digest}
  }
  function stateFor(inputOperation) {
    const bound = operation(inputOperation), state = active.get(bound.key)
    check(state?.active && same(state.op, bound.op), 'operation-not-active')
    return state
  }
  function current() {
    const state = storage.getStore()
    check(state?.active && serializer.current() === state.scope, 'controller-scope-inactive')
    return state
  }
  async function ownerSession(state) {
    const observed = await serializer.inspect(state.scope)
    check(state.active && HOST.every(key => observed[key] === state.host[key]), 'owner-session-binding-invalid')
    return observed
  }
  function tupleMatches(state, tuple) {
    check(tuple && same(tuple.host, state.host) && tuple.operation_id === state.op.operation_id
      && tuple.operation_digest === state.digest && tuple.request_id === state.request_id
      && tuple.request_digest === state.request_digest, 'context-binding-invalid')
  }
  function markerMatches(state, marker) {
    const tuple = state.context.tuple
    check(HOST.every(key => marker[key] === state.host[key])
      && ['operation_id', 'operation_digest', 'request_id', 'request_digest', 'expected_checkpoint_sha256']
        .every(key => marker[key] === tuple[key]), 'marker-binding-invalid')
  }
  function effectInput(inputBinding, withReceipt) {
    const bound = fields(inputBinding, ['operation', 'consumed_grant', 'request_id', 'request_digest', ...(withReceipt ? ['receipt'] : [])],
      'effect-fields-invalid')
    const state = stateFor(bound.operation), grant = detached(bound.consumed_grant)
    try { contracts.validateContract('ConsumedGrant', grant) } catch { check(false, 'grant-invalid') }
    check(grant.operation_id === state.op.operation_id && grant.operation_digest === state.digest
      && grant.owner_id === state.host.owner_id && grant.audience === state.op.audience
      && grant.authorization_epoch === state.host.authorization_epoch && nonempty(grant.grant_id), 'grant-binding-invalid')
    check(bound.request_id === state.request_id && bound.request_digest === state.request_digest, 'request-binding-invalid')
    return {state, grant, ...(withReceipt ? {receipt: detached(bound.receipt)} : {})}
  }
  function matchingIntent(state, grant, tables) {
    const row = tables.intents.find(row => row.operation_id === state.op.operation_id)
    check(row && row.operation_digest === state.digest && row.request_id === state.request_id
      && row.request_digest === state.request_digest
      && row.operation_bytes.equals(Buffer.from(canonicalJSON(state.op)))
      && row.grant_bytes.equals(Buffer.from(canonicalJSON(grant))), 'retained-intent-mismatch')
    return row
  }
  function permit(state, phase, owner_session, envelope, marker, grant = null, receipt = null, predecessor) {
    check(state.active, 'operation-not-active')
    check(typeof predecessor === 'string' && HEX.test(predecessor), 'predecessor-required')
    return detached({version: 1, kind: 'prime-retained-memory-permit/v1', phase, ...state.host,
      operation_id: state.op.operation_id, operation_digest: state.digest,
      request_id: state.request_id, request_digest: state.request_digest, owner_session,
      predecessor_checkpoint_sha256: predecessor, checkpoint_sha256: envelope.checkpoint_sha256,
      control_sha256: envelope.control_state.control_sha256,
      marker_sha256: marker === null ? null : sha256(Buffer.from('aukora-prime.memory-retention-marker.v2\0' + canonicalJSON(marker))),
      grant_digest: grant === null ? null : 'sha256:' + sha256(Buffer.from('aukora-prime.consumed-grant.v1\0' + canonicalJSON(grant))),
      receipt_digest: receipt === null ? null : memoryReceiptDigest(receipt), result_digest: receipt === null ? null : receipt.result_digest})
  }
  const prepare = async inputPrepare => {
    const {operation: op} = fields(inputPrepare, ['operation'], 'prepare-fields-invalid'), state = stateFor(op)
    await ownerSession(state)
    check(!state.prepareCalled && state.context === null, 'prepare-already-attempted')
    state.prepareCalled = true
    state.context = await coordinator.begin({host: state.host, operation: state.op, request_id: state.request_id, request_digest: state.request_digest})
    tupleMatches(state, state.context.tuple)
    const inspected = await coordinator.inspect(state.host)
    check(inspected.prepared === null && same(inspected.predecessor, state.context.predecessor), 'prepare-readback-invalid')
    markerMatches(state, inspected.marker)
    return permit(state, 'prepare', await ownerSession(state), inspected.predecessor, inspected.marker,
      null, null, state.context.predecessor.checkpoint_sha256)
  }
  const dispatch = async inputDispatch => {
    const {state, grant} = effectInput(inputDispatch, false)
    await ownerSession(state)
    check(state.context !== null && contextBrand(state.context), 'prepared-context-required')
    tupleMatches(state, state.context.tuple)
    const inspected = await coordinator.inspect(state.host)
    check(inspected.prepared !== null && same(inspected.predecessor, state.context.predecessor)
      && same(inspected.current, inspected.predecessor), 'prepared-checkpoint-required')
    const marker = inspected.marker
    markerMatches(state, marker)
    matchingIntent(state, grant, inspectMemoryControlState(inspected.prepared.control_state, state.host, {contracts}).tables)
    return permit(state, 'dispatch', await ownerSession(state), inspected.prepared, marker, grant,
      null, state.context.predecessor.checkpoint_sha256)
  }
  const settle = async inputSettle => {
    const {state, grant, receipt} = effectInput(inputSettle, true)
    await ownerSession(state)
    const retained = await coordinator.reader.readCurrent(state.host)
    const checked = inspectMemoryControlState(retained.control_state, state.host, {contracts})
    check(retained.owner_id === state.host.owner_id && retained.owner_subject === state.host.owner_subject
      && retained.authorization_epoch === state.host.authorization_epoch, 'settlement-owner-epoch-invalid')
    const predecessor = retained.previous_checkpoint_sha256
    if (state.context !== null) {
      check(contextBrand(state.context), 'owned-context-required'); tupleMatches(state, state.context.tuple)
      check(predecessor === state.context.predecessor.checkpoint_sha256
        && retained.sequence === state.context.predecessor.sequence + 1, 'settlement-predecessor-invalid')
    }
    matchingIntent(state, grant, checked.tables)
    const effect = checked.tables.effects.find(row => row.operation_id === state.op.operation_id)
    check(effect && effect.grant_id === grant.grant_id && effect.action === state.op.action_type
      && effect.operation_digest === state.digest && effect.request_id === state.request_id
      && effect.request_digest === state.request_digest && effect.receipt_bytes.equals(Buffer.from(canonicalJSON(receipt)))
      && effect.result_bytes.equals(Buffer.from(canonicalJSON(receipt.result)))
      && receipt.result_digest === memoryResultDigest(receipt.result), 'retained-effect-mismatch')
    return permit(state, 'settle', await ownerSession(state), retained, null, grant, receipt, predecessor)
  }
  const participant = Object.freeze({prepare, dispatch, settle})
  participants.add(participant)
  async function runOperation(inputRequest, fn) {
    const bound = request(inputRequest)
    check(typeof fn === 'function', 'work-required')
    try {
      return await serializer.run(bound.host, async scope => {
        check(!active.has(bound.key), 'operation-already-active')
        const state = {...bound, scope, active: true, context: null, prepareCalled: false}
        active.set(bound.key, state)
        try { return await storage.run(state, () => fn(scope)) }
        finally { state.active = false; active.delete(bound.key) }
      })
    } catch (error) {
      // Unlock/release inspection can become uncertain after a committed effect and settlement.
      // Keep the actual refusal and its cause; identify the retained operation without replaying it.
      if (typeof error?.code === 'string' && error.code.startsWith('memory:owner-session-')) {
        error.reconciliation_required = true
        error.automatic_retry = false
        error.operation_id = bound.op.operation_id
        error.request_id = bound.request_id
        error.request_digest = bound.request_digest
      }
      throw error
    }
  }
  const context = () => {
    const state = storage.getStore()
    return state?.active && serializer.current() === state.scope ? state.context : null
  }
  async function bindRecovered(inputContext) {
    const state = current()
    await ownerSession(state)
    check(state.context === null && contextBrand(inputContext), 'owned-context-required')
    tupleMatches(state, inputContext.tuple)
    state.context = inputContext
    state.prepareCalled = true
    return state.context
  }
  return Object.freeze({participant, runOperation, context, bindRecovered})
}

// Explicit private-v2 source selection. Only this internally constructed owned controller
// can join C's existing participant brand; no caller can register an arbitrary object.
export function createPrivateV2RetainedMemoryParticipant(input) {
  const controller = createPrivateV2EffectController(input)
  participants.add(controller.participant)
  privateV2Profiles.set(controller.participant, controller.profile)
  return controller
}

// Factual source identity only: the exact immutable profile belongs to this factory.
// Legacy participants and caller-created proxies have no private-v2 profile/capability.
export function privateV2RetainedMemoryParticipantProfile(participant) {
  return privateV2Profiles.get(participant) ?? null
}
