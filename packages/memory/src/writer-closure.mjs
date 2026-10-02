// SPDX-License-Identifier: AGPL-3.0-or-later
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { parseOriginal, requireMemory, sha256 } from './codecs.mjs'

// A's frozen private closure v1 is scoped to these two interrupted workflows.
const ACTIONS = ['memory.save', 'memory.forget']
const DIGEST = /^sha256:[0-9a-f]{64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const check = (condition, code) => requireMemory(condition, 'memory:writer-closure-' + code)
const text = value => typeof value === 'string' && value.length > 0 && value.length <= 4096
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)
export const MEMORY_WRITER_REFERENCE_FIELDS = Object.freeze(['owner_id','owner_subject','task_id','operation_id','operation_digest','action_type'])
export const MEMORY_WRITER_CLOSURE_FIELDS = Object.freeze(['version', 'kind', 'owner_id', 'owner_subject', 'task_id',
  'operation_id', 'operation_digest', 'action_type', 'authorization_epoch', 'closure_id', 'writer_closed',
  'intent_absent', 'effect_absent', 'grants_authority'])

// An exact reference is inert closed transport data. Reject accessors before canonicalization.
export function detachWriterClosureData(input) {
  const seen = new WeakSet(); let size = 0, count = 0
  function visit(value, depth) {
    check(depth <= 64 && ++count <= 100000, 'input-limit')
    if (value === null || typeof value === 'boolean') return value
    if (typeof value === 'string') { size += Buffer.byteLength(value); check(size <= 1048576, 'input-limit'); return value }
    if (typeof value === 'number') { check(Number.isSafeInteger(value), 'input-number-invalid'); return value }
    check(value && typeof value === 'object' && !types.isProxy(value) && !seen.has(value), 'inert-input-required')
    const array = Array.isArray(value), prototype = Object.getPrototypeOf(value), result = array ? [] : Object.create(null)
    check(prototype === (array ? Array.prototype : Object.prototype) || (!array && prototype === null), 'inert-input-required')
    seen.add(value)
    const descriptors = Object.getOwnPropertyDescriptors(value)
    check(Reflect.ownKeys(descriptors).every(key => typeof key === 'string'), 'inert-input-required')
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (array && key === 'length') continue
      check(Object.hasOwn(descriptor, 'value') && descriptor.enumerable && (!array || /^(?:0|[1-9][0-9]*)$/.test(key)), 'inert-input-required')
      size += Buffer.byteLength(key); check(size <= 1048576, 'input-limit')
      Object.defineProperty(result, key, {value: visit(descriptor.value, depth + 1), enumerable: true})
    }
    if (array) check(result.length === descriptors.length.value && Object.keys(result).length === result.length, 'inert-input-required')
    seen.delete(value); return result
  }
  return parseOriginal(Buffer.from(canonicalJSON(visit(input, 0))))
}

export function writerClosureBinding(host, inputReference) {
  check(host && typeof host === 'object' && !types.isProxy(host), 'host-required')
  const descriptors = Object.getOwnPropertyDescriptors(host), identity = {}
  for (const key of ['owner_id', 'owner_subject', 'task_id', 'authorization_epoch']) {
    const descriptor = descriptors[key]
    check(descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable, 'host-required')
    identity[key] = descriptor.value
  }
  check(['owner_id', 'owner_subject', 'task_id'].every(key => text(identity[key]))
    && Number.isSafeInteger(identity.authorization_epoch) && identity.authorization_epoch >= 0, 'host-required')
  const reference = detachWriterClosureData(inputReference)
  check(reference && typeof reference === 'object' && !Array.isArray(reference)
    && Object.keys(reference).length === MEMORY_WRITER_REFERENCE_FIELDS.length
    && MEMORY_WRITER_REFERENCE_FIELDS.every(key=>Object.hasOwn(reference,key)), 'reference-fields-invalid')
  check(text(reference.operation_id) && ['owner_id','owner_subject','task_id'].every(key=>reference[key]===identity[key])
    && ACTIONS.includes(reference.action_type), 'operation-binding-mismatch')
  check(typeof reference.operation_digest === 'string' && DIGEST.test(reference.operation_digest), 'operation-digest-invalid')
  return {host: identity, reference, digest: reference.operation_digest}
}

export const memoryWriterClosureDigest = closure => 'sha256:' + sha256(Buffer.from(
  'aukora-prime.memory-writer-closure.v1\0' + canonicalJSON(closure)))

export function makeWriterClosureRow(binding, closure_id) {
  check(typeof closure_id === 'string' && UUID.test(closure_id), 'id-invalid')
  const {host, reference, digest} = binding
  const closure = {version: 1, kind: 'prime-memory-writer-closure/v1', owner_id: host.owner_id,
    owner_subject: host.owner_subject, task_id: host.task_id, operation_id: reference.operation_id,
    operation_digest: digest, action_type: reference.action_type, authorization_epoch: host.authorization_epoch,
    closure_id, writer_closed: true, intent_absent: true, effect_absent: true, grants_authority: false}
  return {owner_subject: host.owner_subject, owner_id: host.owner_id, task_id: host.task_id,
    operation_id: reference.operation_id, operation_digest: digest, action_type: reference.action_type,
    authorization_epoch: host.authorization_epoch, reference_bytes: Buffer.from(canonicalJSON(reference)),
    closure_bytes: Buffer.from(canonicalJSON(closure)), closure_digest: memoryWriterClosureDigest(closure)}
}

export function inspectWriterClosureRow(row, binding) {
  check(row && row.reference_bytes && row.closure_bytes, 'row-required')
  const closure = parseOriginal(row.closure_bytes), expected = makeWriterClosureRow(binding, closure.closure_id)
  check(Object.keys(closure).length === MEMORY_WRITER_CLOSURE_FIELDS.length
    && MEMORY_WRITER_CLOSURE_FIELDS.every(key => Object.hasOwn(closure, key))
    && Object.keys(row).length === Object.keys(expected).length
    && Object.keys(expected).every(key => Object.hasOwn(row, key) && (key.endsWith('_bytes')
      ? Buffer.from(row[key]).equals(expected[key]) : row[key] === expected[key]))
    && same(closure, parseOriginal(expected.closure_bytes)), 'row-binding-mismatch')
  return {closure, closure_digest: row.closure_digest}
}
