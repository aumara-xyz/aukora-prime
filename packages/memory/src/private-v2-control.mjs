// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit private source v2. Legacy public/private v1 parsers are unchanged.
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { AURA_RECORD_DOMAIN, CHAIN_DOMAINS, MAX_BYTES, parseOriginal, requireMemory, sha256, verifyChain } from './codecs.mjs'
import { MEMORY_CONTROL_TABLES, MEMORY_WRITER_CLOSURE_TABLE, inspectMemoryControlState } from './control-state.mjs'
import { MEMORY_AUDIENCE, memoryTarget, memoryEffectDigest, memoryReceiptDigest } from './authorization.mjs'

export const PRIVATE_CONTROL_SCHEMA = 'aukora-prime-memory-control-state/v3'
export const PRIVATE_REFERENCE_FIELDS = Object.freeze(['owner_id','owner_subject','task_id','operation_id','operation_digest','action_type'])
export const PRIVATE_WORKFLOW_FIELDS = Object.freeze(['owner_subject','owner_id','task_id','operation_id','operation_digest','action_type',
  'idempotency_key_sha256','record_id','phase','request_id','request_digest','receipt_digest','created_at'])
export const PRIVATE_PROGRESS_FIELDS = Object.freeze(['version','kind','reference','idempotency_key_sha256','closure_attempt_id',
  'expected_authority_store_id','expected_memory_store_id','closing_authorization_epoch','stage','authority','memory'])
export const AUTHORIZED_EFFECT_TRANSITION_FIELDS = Object.freeze(['version','kind','memory_store_id','reference',
  'authorization_epoch','operation','request_id','request_digest','phase','expected_checkpoint_sha256'])
const spec = (table, key, columns, byteColumns = []) => Object.freeze({table, key: Object.freeze(key),
  columns: Object.freeze(columns), byteColumns: Object.freeze(byteColumns)})
export const PRIVATE_CONTROL_TABLES = Object.freeze({...MEMORY_CONTROL_TABLES, unsent_closures: MEMORY_WRITER_CLOSURE_TABLE,
  runtime_workflows: spec('prime_runtime_workflows',['operation_id'],PRIVATE_WORKFLOW_FIELDS),
  workflow_closure_progress: spec('prime_runtime_workflow_closure_progress_v2',['operation_id'],
    ['owner_subject','owner_id','task_id','operation_id','progress_bytes','progress_digest'],['progress_bytes'])})
const HEX = /^[0-9a-f]{64}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const ACTIONS = ['memory.save','memory.forget']
export const PRIVATE_PROGRESS_STAGES = Object.freeze(['started','authority_confirmed','memory_confirmed','complete'])
const check = (ok, reason) => requireMemory(ok, 'memory:private-v2-' + reason)
const text = value => typeof value === 'string' && Buffer.byteLength(value) > 0 && Buffer.byteLength(value) <= 1024
  && !/[\x00-\x1f\x7f]/u.test(value)
const rawHash = value => typeof value === 'string' && HEX.test(value)
const digest = value => typeof value === 'string' && DIGEST.test(value)
const epoch = value => Number.isSafeInteger(value) && value >= 0
const same = (a,b) => canonicalJSON(a) === canonicalJSON(b)
const exact = (value, fields, reason) => check(value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value,key)), reason)
const hash = (domain, value) => sha256(Buffer.from(domain + canonicalJSON(value), 'utf8'))
const prefixedHash = (domain,value) => 'sha256:' + hash(domain,value)
function hostFields(host,fields) {
  check(host && typeof host === 'object' && !types.isProxy(host) && !Array.isArray(host)
    && [Object.prototype,null].includes(Object.getPrototypeOf(host)),'host-inert-required')
  const descriptors = Object.getOwnPropertyDescriptors(host), result = {}
  for (const key of fields) {
    const descriptor = descriptors[key]
    check(descriptor && Object.hasOwn(descriptor,'value') && descriptor.enumerable,'host-inert-required')
    check(key === 'authorization_epoch' ? epoch(descriptor.value) : text(descriptor.value),'host-invalid')
    result[key] = descriptor.value
  }
  return result
}

/** Detach inert JSON before any field reads. This retains donor decimal bytes in historical control data. */
export function detachPrivateData(input) {
  let size = 0, count = 0; const active = new WeakSet()
  function copy(value,depth) {
    check(depth <= 64 && ++count <= 200000, 'input-limit')
    if (value === null || typeof value === 'boolean') return value
    if (typeof value === 'string') {size += Buffer.byteLength(value); check(size <= MAX_BYTES,'input-limit'); return value}
    if (typeof value === 'number') {check(Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value)),
      'input-number'); return value}
    check(value && typeof value === 'object' && !types.isProxy(value) && !active.has(value), 'inert-input-required')
    const array = Array.isArray(value), proto = Object.getPrototypeOf(value)
    check(proto === (array ? Array.prototype : Object.prototype) || (!array && proto === null), 'inert-input-required')
    const descriptors = Object.getOwnPropertyDescriptors(value), out = array ? [] : Object.create(null)
    check(Reflect.ownKeys(descriptors).every(key => typeof key === 'string'), 'inert-input-required')
    active.add(value)
    for (const [key,descriptor] of Object.entries(descriptors)) {
      if (array && key === 'length') continue
      check(Object.hasOwn(descriptor,'value') && descriptor.enumerable && (!array || /^(?:0|[1-9][0-9]*)$/.test(key)),
        'inert-input-required')
      size += Buffer.byteLength(key); check(size <= MAX_BYTES,'input-limit')
      Object.defineProperty(out,key,{value:copy(descriptor.value,depth+1),enumerable:true,writable:true,configurable:true})
    }
    if (array) check(out.length === descriptors.length.value && Object.keys(out).length === out.length && out.length <= 10000,
      'input-limit')
    active.delete(value); return out
  }
  return parseOriginal(Buffer.from(canonicalJSON(copy(input,0))))
}

export function assertPrivateProfile(input) {
  const value = detachPrivateData(input)
  exact(value,['version','kind','expected_authority_store_id','expected_memory_store_id','retention_profile'],'profile-fields')
  check(value.version === 2 && value.kind === 'prime-private-unsent-closure/v2'
    && rawHash(value.expected_authority_store_id) && rawHash(value.expected_memory_store_id)
    && value.retention_profile === 'required-retained/v2','profile-invalid')
  return value
}
export function assertPrivateHost(input) {
  const value = detachPrivateData(input)
  exact(value,['owner_id','owner_subject','task_id','authorization_epoch'],'host-fields')
  check(['owner_id','owner_subject','task_id'].every(key => text(value[key])) && epoch(value.authorization_epoch),'host-invalid')
  return value
}
export function assertClosureReference(input, host) {
  const value = detachPrivateData(input)
  exact(value,PRIVATE_REFERENCE_FIELDS,'reference-fields')
  check(['owner_id','owner_subject','task_id','operation_id'].every(key => text(value[key])) && digest(value.operation_digest)
    && ACTIONS.includes(value.action_type),'reference-invalid')
  if (host) {const checkedHost = hostFields(host,['owner_id','owner_subject','task_id']);
    check(['owner_id','owner_subject','task_id'].every(key => value[key] === checkedHost[key]),'reference-host-mismatch')}
  return value
}
export function assertLogicalMetadata(input) {
  const value = detachPrivateData(input)
  exact(value,['version','kind','store_id'],'logical-metadata-fields')
  check(value.version === 1 && value.kind === 'prime-memory-logical-store/v1' && rawHash(value.store_id),'logical-metadata-invalid')
  return value
}
export const logicalMetadataDigest = input => prefixedHash('aukora-prime.memory-logical-store.v1\0',assertLogicalMetadata(input))
export function assertWriterClosureV2(input, {host,reference,profile} = {}) {
  const value = detachPrivateData(input)
  exact(value,['version','kind','store_id',...PRIVATE_REFERENCE_FIELDS,'authorization_epoch','closure_id',
    'writer_closed','intent_absent','effect_absent','grants_authority'],'closure-fields')
  check(value.version === 2 && value.kind === 'prime-memory-writer-closure/v2' && rawHash(value.store_id)
    && epoch(value.authorization_epoch) && typeof value.closure_id === 'string' && UUID4.test(value.closure_id)
    && value.writer_closed === true && value.intent_absent === true && value.effect_absent === true
    && value.grants_authority === false,'closure-invalid')
  const ref = assertClosureReference(Object.fromEntries(PRIVATE_REFERENCE_FIELDS.map(key => [key,value[key]])))
  if (reference) check(same(ref,assertClosureReference(reference)),'closure-reference-mismatch')
  if (host) {const checkedHost = hostFields(host,['owner_id','owner_subject','task_id','authorization_epoch']);
    check(['owner_id','owner_subject','task_id','authorization_epoch'].every(key => value[key] === checkedHost[key]),'closure-host-mismatch')}
  if (profile) check(value.store_id === assertPrivateProfile(profile).expected_memory_store_id,'closure-store-mismatch')
  return value
}
export const writerClosureV2Digest = input => prefixedHash('aukora-prime.memory-writer-closure.v2\0',assertWriterClosureV2(input))
export function assertWriterCompletionV2(input, {closure,closure_digest,profile} = {}) {
  const value = detachPrivateData(input)
  exact(value,['version','kind','store_id','closure_digest','retention'],'completion-fields')
  check(value.version === 2 && value.kind === 'prime-memory-writer-completion/v2' && rawHash(value.store_id)
    && digest(value.closure_digest),'completion-invalid')
  exact(value.retention,['version','kind','checkpoint_sha256','control_sha256','authorization_epoch'],'retention-fields')
  check(value.retention.version === 2 && value.retention.kind === 'prime-memory-writer-retention/v2'
    && rawHash(value.retention.checkpoint_sha256) && rawHash(value.retention.control_sha256)
    && epoch(value.retention.authorization_epoch),'completion-retention-invalid')
  if (profile) check(value.store_id === assertPrivateProfile(profile).expected_memory_store_id,'completion-store-mismatch')
  if (closure) {const marker = assertWriterClosureV2(closure,{profile}); check(value.store_id === marker.store_id
    && value.closure_digest === writerClosureV2Digest(marker) && value.retention.authorization_epoch === marker.authorization_epoch,
    'completion-closure-mismatch')}
  if (closure_digest !== undefined) check(value.closure_digest === closure_digest,'completion-digest-mismatch')
  return value
}
export const writerCompletionV2Digest = input => prefixedHash('aukora-prime.memory-writer-completion.v2\0',assertWriterCompletionV2(input))

function contractsJson(value,contracts) {
  check(typeof contracts?.canonicalJson === 'function','contracts-unavailable')
  try {return contracts.canonicalJson(value)} catch {check(false,'contracts-json-invalid')}
}
const contractHash = (domain,value,contracts) => 'sha256:' + sha256(Buffer.from(domain + contractsJson(value,contracts),'utf8'))
export function assertWorkflowRow(input,{host} = {}) {
  const value = detachPrivateData(input)
  exact(value,PRIVATE_WORKFLOW_FIELDS,'workflow-fields')
  assertClosureReference(Object.fromEntries(PRIVATE_REFERENCE_FIELDS.map(key => [key,value[key]])))
  if (host) {const checkedHost = hostFields(host,['owner_id','owner_subject']);
    check(value.owner_id === checkedHost.owner_id && value.owner_subject === checkedHost.owner_subject,'workflow-owner-mismatch')}
  check(value.idempotency_key_sha256 === null || rawHash(value.idempotency_key_sha256),'workflow-key-invalid')
  check(['proposed','attempted','known_unsent','saved','forgotten'].includes(value.phase)
    && (value.record_id === null || text(value.record_id)) && (value.request_id === null || text(value.request_id))
    && (value.request_digest === null || digest(value.request_digest)) && (value.receipt_digest === null || digest(value.receipt_digest))
    && (value.request_id === null) === (value.request_digest === null)
    && typeof value.created_at === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value.created_at)
    && Number.isFinite(Date.parse(value.created_at)) && new Date(value.created_at).toISOString() === value.created_at,'workflow-invalid')
  if (['proposed','attempted','known_unsent'].includes(value.phase)) check(['request_id','request_digest','receipt_digest']
    .every(key => value[key] === null) && (value.action_type === 'memory.save' ? value.record_id === null : value.record_id !== null),
    'workflow-unsent-metadata')
  else check(value.record_id !== null && value.request_id !== null && value.receipt_digest !== null
    && value.action_type === (value.phase === 'saved' ? 'memory.save' : 'memory.forget'),'workflow-settlement-invalid')
  return value
}
export const workflowRowDigest = (input,{contracts} = {}) => contractHash('aukora-prime.runtime-workflow-row.v3\0',
  assertWorkflowRow(input),contracts)
export function closureAttemptDigest(input,{contracts} = {}) {
  const value = detachPrivateData(input)
  const body = Object.fromEntries(['reference','idempotency_key_sha256','expected_authority_store_id','expected_memory_store_id',
    'closing_authorization_epoch'].map(key => [key,value[key]]))
  assertClosureReference(body.reference)
  check((body.idempotency_key_sha256 === null || rawHash(body.idempotency_key_sha256)) && rawHash(body.expected_authority_store_id)
    && rawHash(body.expected_memory_store_id) && epoch(body.closing_authorization_epoch),'attempt-invalid')
  return contractHash('aukora-prime.runtime-unsent-closure-attempt.v2\0',body,contracts)
}
function assertAuthorityProjection(input,reference,profile,contracts) {
  exact(input,['closure','closure_digest'],'authority-fields')
  const value = input.closure
  exact(value,['version','kind','store_id','owner_id','owner_subject','task_id','operation_id','operation_digest',
    'authorization_epoch','closed_at','broker_revision','kernel_receipt_count','kernel_receipt_head'],'authority-marker-fields')
  check(value.version === 1 && value.kind === 'prime-authority-never-consumed/v1' && value.store_id === profile.expected_authority_store_id
    && PRIVATE_REFERENCE_FIELDS.filter(key => key !== 'action_type').every(key => value[key] === reference[key])
    && epoch(value.authorization_epoch) && Number.isSafeInteger(value.broker_revision) && value.broker_revision >= 1
    && epoch(value.kernel_receipt_count) && (value.kernel_receipt_count === 0 ? value.kernel_receipt_head === null : rawHash(value.kernel_receipt_head))
    && typeof value.closed_at === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value.closed_at)
    && Number.isFinite(Date.parse(value.closed_at)) && new Date(value.closed_at).toISOString() === value.closed_at
    && digest(input.closure_digest) && input.closure_digest === contractHash('aukora-prime.authority-never-consumed.v1\0',value,contracts),
    'authority-marker-invalid')
}
export function assertProgressV2(input,{host,profile,contracts} = {}) {
  const value = detachPrivateData(input)
  exact(value,PRIVATE_PROGRESS_FIELDS,'progress-fields')
  const ref = assertClosureReference(value.reference), pair = assertPrivateProfile(profile ?? {version:2,kind:'prime-private-unsent-closure/v2',
    expected_authority_store_id:value.expected_authority_store_id,expected_memory_store_id:value.expected_memory_store_id,
    retention_profile:'required-retained/v2'})
  check(value.version === 2 && value.kind === 'prime-runtime-unsent-closure-progress/v2'
    && value.expected_authority_store_id === pair.expected_authority_store_id && value.expected_memory_store_id === pair.expected_memory_store_id
    && epoch(value.closing_authorization_epoch) && PRIVATE_PROGRESS_STAGES.includes(value.stage)
    && (value.idempotency_key_sha256 === null || rawHash(value.idempotency_key_sha256))
    && value.closure_attempt_id === closureAttemptDigest(value,{contracts}),'progress-invalid')
  if (host) {const checkedHost = hostFields(host,['owner_id','owner_subject']);
    check(ref.owner_id === checkedHost.owner_id && ref.owner_subject === checkedHost.owner_subject,'progress-owner-mismatch')}
  const rank = PRIVATE_PROGRESS_STAGES.indexOf(value.stage)
  check(rank === 0 ? value.authority === null : value.authority !== null,'progress-authority-stage')
  check(rank < 2 ? value.memory === null : value.memory !== null,'progress-memory-stage')
  if (value.authority !== null) assertAuthorityProjection(value.authority,ref,pair,contracts)
  if (value.memory !== null) {
    exact(value.memory,['closure','closure_digest','completion','completion_digest'],'memory-projection-fields')
    const closure = assertWriterClosureV2(value.memory.closure,{reference:ref,profile:pair})
    check(closure.authorization_epoch === value.closing_authorization_epoch && value.memory.closure_digest === writerClosureV2Digest(closure),
      'progress-memory-marker')
    const completion = assertWriterCompletionV2(value.memory.completion,{closure,closure_digest:value.memory.closure_digest,profile:pair})
    check(value.memory.completion_digest === writerCompletionV2Digest(completion),'progress-memory-completion')
  }
  return value
}
export const progressDigest = (input,{contracts} = {}) => contractHash('aukora-prime.runtime-unsent-closure-progress.v2\0',
  assertProgressV2(input,{contracts}),contracts)

export function assertJournalTransition(input,{host,profile,contracts} = {}) {
  const value = detachPrivateData(input)
  exact(value,['version','kind','memory_store_id','reference','idempotency_key_sha256','expected_checkpoint_sha256',
    'previous_progress_digest','target_stage','target_progress'],'journal-transition-fields')
  const checkedHost = host ? assertPrivateHost(host) : null
  const pair = assertPrivateProfile(profile), ref = assertClosureReference(value.reference,checkedHost), progress = assertProgressV2(value.target_progress,{profile:pair,contracts})
  check(value.version === 3 && value.kind === 'prime-runtime-unsent-journal-transition/v3'
    && value.memory_store_id === pair.expected_memory_store_id && rawHash(value.expected_checkpoint_sha256)
    && (value.previous_progress_digest === null || digest(value.previous_progress_digest))
    && value.target_stage === progress.stage && same(ref,progress.reference)
    && value.idempotency_key_sha256 === progress.idempotency_key_sha256
    && (value.previous_progress_digest === null ? progress.stage === 'started' : progress.stage !== 'started')
    && (!checkedHost || progress.closing_authorization_epoch === checkedHost.authorization_epoch),'journal-transition-invalid')
  return value
}
export const journalTransitionDigest = (input,{contracts} = {}) => contractHash('aukora-prime.runtime-unsent-journal-transition.v3\0',
  detachPrivateData(input),contracts)
export function assertWorkflowTransition(input,{host,profile} = {}) {
  const value = detachPrivateData(input)
  exact(value,['version','kind','memory_store_id','reference','idempotency_key_sha256','expected_checkpoint_sha256',
    'previous_workflow_digest','target_workflow'],'workflow-transition-fields')
  const pair = assertPrivateProfile(profile), ref = assertClosureReference(value.reference,host), row = assertWorkflowRow(value.target_workflow,{host})
  check(value.version === 3 && value.kind === 'prime-runtime-workflow-mutation/v3' && value.memory_store_id === pair.expected_memory_store_id
    && rawHash(value.expected_checkpoint_sha256) && (value.previous_workflow_digest === null || digest(value.previous_workflow_digest))
    && same(ref,Object.fromEntries(PRIVATE_REFERENCE_FIELDS.map(key => [key,row[key]])))
    && value.idempotency_key_sha256 === row.idempotency_key_sha256 && row.phase !== 'known_unsent'
    && (value.previous_workflow_digest !== null || row.phase === 'proposed'),'workflow-transition-invalid')
  return value
}
export const workflowTransitionDigest = (input,{contracts} = {}) => contractHash('aukora-prime.runtime-workflow-mutation.v3\0',
  detachPrivateData(input),contracts)
/** Bind the actual ordinary memory effect to its original proposal and immutable request.
 * This source purpose carries no approval or authority; C still owns grant verification.
 */
export function assertAuthorizedEffectTransition(input,{host,profile,contracts} = {}) {
  const value = detachPrivateData(input)
  exact(value,AUTHORIZED_EFFECT_TRANSITION_FIELDS,'authorized-effect-transition-fields')
  const pair = assertPrivateProfile(profile), checkedHost = assertPrivateHost(host)
  const reference = assertClosureReference(value.reference,checkedHost)
  check(typeof contracts?.validateContract === 'function' && typeof contracts?.operationDigest === 'function',
    'authorized-effect-contracts-required')
  try {contracts.validateContract('OperationProposal',value.operation)} catch {check(false,'authorized-effect-operation-invalid')}
  const operation = value.operation
  check(value.version === 3 && value.kind === 'prime-memory-authorized-effect-transition/v3'
    && value.memory_store_id === pair.expected_memory_store_id && epoch(value.authorization_epoch)
    && value.authorization_epoch === checkedHost.authorization_epoch && operation.authorization_epoch === value.authorization_epoch
    && operation.owner_id === reference.owner_id && operation.task_id === reference.task_id
    && operation.operation_id === reference.operation_id && operation.action_type === reference.action_type
    && contracts.operationDigest(operation) === reference.operation_digest && operation.audience === MEMORY_AUDIENCE
    && same(operation.target_identity,memoryTarget(reference.owner_subject)) && typeof value.request_id === 'string' && UUID4.test(value.request_id)
    && digest(value.request_digest) && ['intent','applied'].includes(value.phase) && rawHash(value.expected_checkpoint_sha256),
    'authorized-effect-transition-invalid')
  const request = {version:1,action_type:reference.action_type,owner_subject:reference.owner_subject,
    operation_id:reference.operation_id,operation_digest:reference.operation_digest,parameters:operation.canonical_parameters}
  check(value.request_digest === memoryEffectDigest(request),'authorized-effect-request-mismatch')
  return value
}
export function effectTransitionDigest(input) {
  const value = detachPrivateData(input)
  exact(value,AUTHORIZED_EFFECT_TRANSITION_FIELDS,'authorized-effect-transition-fields')
  return prefixedHash('aukora-prime.memory-authorized-effect-transition.v3\0',value)
}
export const authorizedEffectTransitionDigest = effectTransitionDigest
export function assertNegativeTransition(input,{host,profile} = {}) {
  const value = detachPrivateData(input)
  exact(value,['version','kind','memory_store_id','reference','expected_checkpoint_sha256','previous_progress_digest','closure','closure_digest'],
    'negative-transition-fields')
  const pair = assertPrivateProfile(profile), ref = assertClosureReference(value.reference,host)
  const marker = assertWriterClosureV2(value.closure,{host,reference:ref,profile:pair})
  check(value.version === 3 && value.kind === 'prime-memory-negative-closure-transition/v3'
    && value.memory_store_id === pair.expected_memory_store_id && rawHash(value.expected_checkpoint_sha256)
    && digest(value.previous_progress_digest) && value.closure_digest === writerClosureV2Digest(marker),'negative-transition-invalid')
  return value
}
export const negativeTransitionDigest = input => prefixedHash('aukora-prime.memory-negative-closure-transition.v3\0',detachPrivateData(input))
export const assertNegativeClosureTransition = assertNegativeTransition
export const negativeClosureTransitionDigest = negativeTransitionDigest
export function assertRestoreTransition(input,{host,profile} = {}) {
  const value = detachPrivateData(input)
  exact(value,['version','kind','memory_store_id','reference','expected_checkpoint_sha256','anchor_checkpoint_sha256'],'restore-transition-fields')
  const pair = assertPrivateProfile(profile); assertClosureReference(value.reference,host)
  check(value.version === 3 && value.kind === 'prime-memory-control-restore-transition/v3' && value.memory_store_id === pair.expected_memory_store_id
    && rawHash(value.expected_checkpoint_sha256) && rawHash(value.anchor_checkpoint_sha256),'restore-transition-invalid')
  return value
}
export const restoreTransitionDigest = input => prefixedHash('aukora-prime.memory-control-restore-transition.v3\0',detachPrivateData(input))

const rowKey = (row,name) => canonicalJSON(PRIVATE_CONTROL_TABLES[name].key.map(key => row[key]))
const compare = (a,b) => a < b ? -1 : a > b ? 1 : 0
function decodeBytes(value) {
  exact(value,['bytes_base64','sha256'],'bytes-fields')
  check(typeof value.bytes_base64 === 'string' && rawHash(value.sha256),'bytes-invalid')
  const bytes = Buffer.from(value.bytes_base64,'base64')
  check(bytes.toString('base64') === value.bytes_base64 && sha256(bytes) === value.sha256,'bytes-changed')
  parseOriginal(bytes); return bytes
}
function historicalBundle(body) {
  const legacyClosures = body.tables.unsent_closures.filter(row => parseOriginal(decodeBytes(row.closure_bytes)).version === 1)
  const tables = Object.fromEntries(Object.keys(MEMORY_CONTROL_TABLES).map(name => [name,body.tables[name]]))
  if (legacyClosures.length) tables.unsent_closures = legacyClosures
  const value = {schema:legacyClosures.length ? 'aukora-prime-memory-control-state/v2' : 'aukora-prime-memory-control-state/v1',
    owner_subject:body.owner_subject,owner_id:body.owner_id,heads:body.heads,tables}
  return {...value,control_sha256:hash(legacyClosures.length ? 'aukora-prime.memory-control-state.v2\0' : 'aukora-prime.memory-control-state.v1\0',value)}
}
export function controlV3Digest(input) {
  const value = detachPrivateData(input), {control_sha256:ignored,...body} = value
  return hash('aukora-prime.memory-control-state.v3\0',body)
}
export function decodeControlV3(input,host,{profile,contracts} = {}) {
  const value = detachPrivateData(input), pair = assertPrivateProfile(profile ?? value.closure_profile)
  const checkedHost = host ? hostFields(host,['owner_id','owner_subject']) : null
  exact(value,['schema','owner_subject','owner_id','logical_store','closure_profile','heads','tables','control_sha256'],'control-fields')
  check(value.schema === PRIVATE_CONTROL_SCHEMA && text(value.owner_subject) && text(value.owner_id)
    && (!checkedHost || value.owner_subject === checkedHost.owner_subject && value.owner_id === checkedHost.owner_id),'control-owner-schema')
  check(same(value.closure_profile,pair),'control-profile-mismatch')
  exact(value.logical_store,['metadata','metadata_digest'],'control-logical-store-fields')
  const metadata = assertLogicalMetadata(value.logical_store.metadata)
  check(metadata.store_id === pair.expected_memory_store_id && value.logical_store.metadata_digest === logicalMetadataDigest(metadata),
    'control-logical-store-mismatch')
  check(value.heads && typeof value.heads === 'object' && !Array.isArray(value.heads) && Object.entries(value.heads)
    .every(([domain,head]) => CHAIN_DOMAINS.includes(domain) && typeof head === 'string' && (head === AURA_RECORD_DOMAIN || rawHash(head))),
    'control-head-invalid')
  check(rawHash(value.control_sha256) && value.control_sha256 === controlV3Digest(value),'control-digest-mismatch')
  exact(value.tables,Object.keys(PRIVATE_CONTROL_TABLES),'control-tables')
  const tables = {}; let rowsCount = 0, bytesCount = 0
  for (const [name,specification] of Object.entries(PRIVATE_CONTROL_TABLES)) {
    const rows = value.tables[name], keys = new Set(); let prior = null
    check(Array.isArray(rows) && (rowsCount += rows.length) <= 10000,'control-row-limit')
    tables[name] = rows.map(row => {
      exact(row,specification.columns,'control-row-fields')
      check(row.owner_subject === value.owner_subject,'control-row-owner')
      const key = rowKey(row,name); check(!keys.has(key) && (prior === null || compare(prior,key) < 0),'control-row-order')
      keys.add(key); prior = key
      const decoded = {...row}
      for (const column of specification.byteColumns) {decoded[column] = decodeBytes(row[column]); bytesCount += decoded[column].length}
      check(bytesCount <= MAX_BYTES,'control-bytes-limit'); return decoded
    })
  }
  // Reuse the exact historical parser without adding fields to its v1/v2 grammar.
  inspectMemoryControlState(historicalBundle(value),{owner_subject:value.owner_subject,owner_id:value.owner_id},{contracts})
  const workflows = new Map(), keyBindings = new Set(), progresses = new Map()
  for (const row of tables.runtime_workflows) {
    assertWorkflowRow(row,{host:value}); workflows.set(row.operation_id,row)
    if (row.idempotency_key_sha256 !== null) {const key = canonicalJSON([row.task_id,row.idempotency_key_sha256]);
      check(!keyBindings.has(key),'control-workflow-key-conflict'); keyBindings.add(key)}
  }
  for (const row of tables.workflow_closure_progress) {
    check(row.owner_id === value.owner_id && text(row.task_id) && text(row.operation_id) && digest(row.progress_digest),'control-progress-row')
    const progress = assertProgressV2(parseOriginal(row.progress_bytes),{profile:pair,contracts,host:value})
    const workflow = workflows.get(row.operation_id)
    check(row.progress_bytes.equals(Buffer.from(contractsJson(progress,contracts))) && row.progress_digest === progressDigest(progress,{contracts})
      && workflow && ['owner_subject','owner_id','task_id','operation_id','operation_digest','action_type']
        .every(key => workflow[key] === progress.reference[key])
      && ['owner_subject','owner_id','task_id','operation_id'].every(key => row[key] === progress.reference[key])
      && workflow.idempotency_key_sha256 === progress.idempotency_key_sha256 && ['attempted','known_unsent'].includes(workflow.phase)
      && (progress.stage === 'complete') === (workflow.phase === 'known_unsent'),'control-progress-binding')
    progresses.set(row.operation_id,{progress,progress_digest:row.progress_digest})
  }
  const closures = new Map(), effectOps = new Set(['intents','effects','replay_fences'].flatMap(name => tables[name].map(row => row.operation_id)))
  for (const row of tables.unsent_closures) {
    const marker = parseOriginal(row.closure_bytes)
    if (marker.version === 1) continue // Fully validated above; original bytes remain original.
    const ref = assertClosureReference(parseOriginal(row.reference_bytes))
    assertWriterClosureV2(marker,{reference:ref,profile:pair})
    check(row.owner_id === value.owner_id && PRIVATE_REFERENCE_FIELDS.every(key => row[key] === ref[key])
      && row.authorization_epoch === marker.authorization_epoch && row.closure_digest === writerClosureV2Digest(marker)
      && row.reference_bytes.equals(Buffer.from(canonicalJSON(ref))) && row.closure_bytes.equals(Buffer.from(canonicalJSON(marker)))
      && !effectOps.has(row.operation_id),'control-closure-binding')
    const pairProgress = progresses.get(row.operation_id), workflow = workflows.get(row.operation_id)
    check(workflow && pairProgress && pairProgress.progress.stage !== 'started'
      && pairProgress.progress.closing_authorization_epoch === marker.authorization_epoch,'control-closure-progress-missing')
    if (pairProgress.progress.memory) check(same(pairProgress.progress.memory.closure,marker)
      && pairProgress.progress.memory.closure_digest === row.closure_digest,'control-closure-progress-conflict')
    closures.set(row.operation_id,marker)
  }
  for (const {progress} of progresses.values()) if (progress.memory) check(closures.has(progress.reference.operation_id),'control-progress-closure-missing')
  for (const row of workflows.values()) {
    if (row.phase === 'known_unsent') check(progresses.get(row.operation_id)?.progress.stage === 'complete' && closures.has(row.operation_id),
      'control-known-unsent-incomplete')
    if (['saved','forgotten'].includes(row.phase)) {
      const effect = tables.effects.find(item => item.operation_id === row.operation_id)
      // A later payload purge may retain only the exact permanent replay fence. The historical
      // advance validator proves the effect-to-fence transition; a fence alone does not create a receipt.
      const fence = tables.replay_fences.find(item => item.operation_id === row.operation_id)
      check(effect || fence,'control-workflow-effect-missing')
      const factual = effect ?? fence
      check(factual.operation_digest === row.operation_digest && factual.action === row.action_type
        && factual.request_id === row.request_id && factual.request_digest === row.request_digest,'control-workflow-effect-binding')
      if (effect) {
        const operation = parseOriginal(effect.operation_bytes), result = parseOriginal(effect.result_bytes)
        check(memoryReceiptDigest(parseOriginal(effect.receipt_bytes)) === row.receipt_digest
          && operation.task_id === row.task_id && result.record_id === row.record_id
          && (row.action_type !== 'memory.forget' || operation.canonical_parameters.record_id === row.record_id),
          'control-workflow-receipt-binding')
      }
    }
  }
  return {digest:value.control_sha256,heads:value.heads,tables,logical_store:value.logical_store,closure_profile:pair}
}
export function assertControlV3(input,host,options = {}) {decodeControlV3(input,host,options); return detachPrivateData(input)}
export const inspectMemoryControlStateV3 = decodeControlV3
export function parseWriterClosureV2Row(row,host,reference,profile) {
  check(row && typeof row === 'object' && !types.isProxy(row),'closure-row-required')
  exact(row,MEMORY_WRITER_CLOSURE_TABLE.columns,'closure-row-fields')
  const fields = Object.getOwnPropertyDescriptors(row)
  check(MEMORY_WRITER_CLOSURE_TABLE.columns.every(key => fields[key] && Object.hasOwn(fields[key],'value')),'closure-row-inert-required')
  check(Buffer.isBuffer(row.reference_bytes) && Buffer.isBuffer(row.closure_bytes),'closure-row-bytes')
  const ref = assertClosureReference(parseOriginal(row.reference_bytes),host)
  const marker = assertWriterClosureV2(parseOriginal(row.closure_bytes),{host,reference:reference ?? ref,profile})
  check(same(ref,reference ?? ref) && PRIVATE_REFERENCE_FIELDS.every(key => row[key] === ref[key])
    && row.authorization_epoch === marker.authorization_epoch && row.closure_digest === writerClosureV2Digest(marker)
    && row.reference_bytes.equals(Buffer.from(canonicalJSON(ref))) && row.closure_bytes.equals(Buffer.from(canonicalJSON(marker))),
    'closure-row-binding')
  return {closure:marker,closure_digest:row.closure_digest}
}
export function createControlV3(host,state,{profile,contracts} = {}) {
  check(host && typeof host === 'object' && !types.isProxy(host),'control-host-required')
  const owner = {}
  for (const name of ['owner_subject','owner_id']) {const d = Object.getOwnPropertyDescriptor(host,name);
    check(d && Object.hasOwn(d,'value') && text(d.value),'control-host-required'); owner[name] = d.value}
  const pair = assertPrivateProfile(profile), encoded = {}
  check(state && typeof state === 'object' && !types.isProxy(state),'control-source-required')
  const descriptors = Object.getOwnPropertyDescriptors(state)
  check(['heads','tables','logical_store'].every(name => descriptors[name] && Object.hasOwn(descriptors[name],'value')),'control-source-required')
  const rawTables = descriptors.tables.value
  check(rawTables && typeof rawTables === 'object' && !types.isProxy(rawTables),'control-source-required')
  exact(rawTables,Object.keys(PRIVATE_CONTROL_TABLES),'control-tables')
  for (const [name,specification] of Object.entries(PRIVATE_CONTROL_TABLES)) {
    const d = Object.getOwnPropertyDescriptor(rawTables,name); check(d && Object.hasOwn(d,'value'),'control-source-required')
    const rows = d.value; check(Array.isArray(rows) && !types.isProxy(rows) && rows.length <= 10000,'control-row-limit')
    encoded[name] = Array.from({length:rows.length},(_,i) => {
      const descriptor = Object.getOwnPropertyDescriptor(rows,String(i)); check(descriptor && Object.hasOwn(descriptor,'value'),'control-source-required')
      const row = descriptor.value; check(row && typeof row === 'object' && !types.isProxy(row),'control-source-required')
      exact(row,specification.columns,'control-row-fields'); const fields = Object.getOwnPropertyDescriptors(row)
      return Object.fromEntries(specification.columns.map(column => {
        const field = fields[column]; check(field && Object.hasOwn(field,'value') && field.enumerable,'control-source-required')
        if (!specification.byteColumns.includes(column)) return [column,field.value]
        check(field.value && typeof field.value === 'object' && !types.isProxy(field.value)
          && [Buffer.prototype,Uint8Array.prototype].includes(Object.getPrototypeOf(field.value)),'control-source-bytes')
        const bytes = Buffer.from(field.value); return [column,{bytes_base64:bytes.toString('base64'),sha256:sha256(bytes)}]
      }))
    }).sort((a,b) => compare(rowKey(a,name),rowKey(b,name)))
  }
  const body = detachPrivateData({schema:PRIVATE_CONTROL_SCHEMA,...owner,logical_store:descriptors.logical_store.value,
    closure_profile:pair,heads:descriptors.heads.value,tables:encoded})
  const value = {...body,control_sha256:controlV3Digest(body)}; assertControlV3(value,owner,{profile:pair,contracts}); return value
}
/** Read full actual projection on the supplied SAME live owner PoolClient. No provisioning or schema fallback. */
export async function readControlV3(client,input,{contracts} = {}) {
  const identity = detachPrivateData(input)
  exact(identity,['owner_subject','owner_id','profile'],'control-read-fields')
  const {owner_subject,owner_id,profile} = identity
  check(typeof client?.query === 'function' && text(owner_subject) && text(owner_id),'control-client-required')
  const pair = assertPrivateProfile(profile), query = async(sql,values=[]) => {
    const result = await client.query(sql,values); check(Array.isArray(result?.rows),'control-sql-result'); return result.rows
  }
  const metadataRows = await query('SELECT singleton,metadata_bytes,metadata_digest FROM prime_memory_logical_store')
  check(metadataRows.length === 1 && metadataRows[0].singleton === true
    && Object.keys(metadataRows[0]).length === 3 && Object.hasOwn(metadataRows[0],'metadata_bytes')
    && Object.hasOwn(metadataRows[0],'metadata_digest'),'logical-metadata-missing-or-ambiguous')
  const metadataBytes = metadataRows[0].metadata_bytes
  check(Buffer.isBuffer(metadataBytes) || metadataBytes instanceof Uint8Array,'logical-metadata-bytes')
  const metadata = assertLogicalMetadata(parseOriginal(metadataBytes))
  check(Buffer.from(metadataBytes).equals(Buffer.from(canonicalJSON(metadata))) && metadata.store_id === pair.expected_memory_store_id
    && metadataRows[0].metadata_digest === logicalMetadataDigest(metadata),'logical-metadata-binding')
  const headRows = await query('SELECT chain_domain,sequence,hash FROM prime_memory_heads WHERE owner_subject=$1 ORDER BY chain_domain',[owner_subject])
  const chainRows = await query('SELECT chain_domain,sequence,bytes,hash,prev FROM prime_memory_chain WHERE owner_subject=$1 ORDER BY chain_domain,sequence',[owner_subject])
  check(chainRows.length <= 10000,'control-chain-row-limit')
  const heads = {}, chains = new Map(); let chainSize = 0
  for (const row of headRows) {
    exact(row,['chain_domain','sequence','hash'],'control-head-row-fields')
    check(CHAIN_DOMAINS.includes(row.chain_domain) && !Object.hasOwn(heads,row.chain_domain)
      && epoch(row.sequence) && (row.hash === AURA_RECORD_DOMAIN || rawHash(row.hash)),'control-head-invalid')
    heads[row.chain_domain] = row.hash; chains.set(row.chain_domain,[])
  }
  for (const row of chainRows) {
    exact(row,['chain_domain','sequence','bytes','hash','prev'],'control-chain-row-fields')
    check(chains.has(row.chain_domain) && Number.isSafeInteger(row.sequence) && row.sequence > 0
      && Buffer.isBuffer(row.bytes) && rawHash(row.hash) && (row.prev === AURA_RECORD_DOMAIN || rawHash(row.prev)),
      'control-chain-row-invalid')
    chainSize += row.bytes.length; check(chainSize <= MAX_BYTES,'control-chain-bytes-limit')
    const entry = parseOriginal(row.bytes)
    check(entry.sequence === row.sequence && entry.hash === row.hash && entry.prev === row.prev,'control-chain-row-binding')
    chains.get(row.chain_domain).push(row)
  }
  for (const head of headRows) {
    const rows = chains.get(head.chain_domain), bytes = Buffer.concat(rows.map(row => row.bytes))
    const verified = verifyChain(bytes,head.hash)
    check(verified.sequence === head.sequence,'control-chain-head-sequence')
  }
  const tables = {}
  for (const [name,specification] of Object.entries(PRIVATE_CONTROL_TABLES)) tables[name] = await query(
    `SELECT ${specification.columns.join(',')} FROM ${specification.table} WHERE owner_subject=$1 ORDER BY ${specification.key.join(',')}`,[owner_subject])
  return createControlV3({owner_subject,owner_id},{heads,tables,logical_store:{metadata,metadata_digest:metadataRows[0].metadata_digest}},
    {profile:pair,contracts})
}
// Both modules initialize without reading each other's bindings. This compatibility export keeps
// private composition imports small; the edge implementation remains owned by the separate module.
export { assertForwardControlV3, assertMemoryControlAdvanceV3, assertLineageCompletionsV2 } from './private-v2-advance.mjs'
