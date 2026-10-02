// SPDX-License-Identifier: AGPL-3.0-or-later
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MAX_BYTES, parseOriginal, requireMemory, sha256 } from './codecs.mjs'
import {
  assertPrivateProfile, assertPrivateHost, assertControlV3, assertJournalTransition,
  assertWorkflowTransition, assertNegativeTransition, assertRestoreTransition,
  journalTransitionDigest, workflowTransitionDigest, negativeTransitionDigest, restoreTransitionDigest,
  assertAuthorizedEffectTransition, effectTransitionDigest,
} from './private-v2-control.mjs'
import { assertForwardControlV3 } from './private-v2-advance.mjs'
import { isPrivateV2FileRetentionReader } from './private-v2-retention.mjs'

const coordinators = new WeakSet()
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const HEX = /^[0-9a-f]{64}$/
const check = (ok, code) => requireMemory(ok, `memory:private-v2-coordinator-${code}`)
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)

export function privateV2Fields(value, keys, code = 'fields-invalid') {
  check(value && typeof value === 'object' && !Array.isArray(value) && !types.isProxy(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)), code)
  const ds = Object.getOwnPropertyDescriptors(value)
  check(Reflect.ownKeys(ds).length === keys.length && keys.every(key => ds[key]
    && Object.hasOwn(ds[key], 'value') && ds[key].enumerable), code)
  return Object.fromEntries(keys.map(key => [key, ds[key].value]))
}
export function privateV2Detach(value) {
  const active = new WeakSet(); let size = 0, count = 0
  function visit(node, depth) {
    check(depth <= 64 && ++count <= 2000000, 'json-limit')
    if (typeof node === 'string') { size += Buffer.byteLength(node); check(size <= MAX_BYTES, 'bytes-limit'); return node }
    if (node === null || typeof node === 'boolean') return node
    if (typeof node === 'number') { check(Number.isFinite(node) && (!Number.isInteger(node) || Number.isSafeInteger(node)), 'number-invalid'); return node }
    check(node && typeof node === 'object' && !types.isProxy(node) && !active.has(node), 'inert-json-required')
    const array = Array.isArray(node), proto = Object.getPrototypeOf(node)
    check(proto === (array ? Array.prototype : Object.prototype) || (!array && proto === null), 'inert-json-required')
    const ds = Object.getOwnPropertyDescriptors(node), out = array ? [] : Object.create(null)
    check(Reflect.ownKeys(ds).every(key => typeof key === 'string'), 'inert-json-required')
    if (array) check(ds.length && Object.hasOwn(ds.length, 'value') && ds.length.value <= 10000, 'json-limit')
    active.add(node)
    for (const [key, d] of Object.entries(ds)) {
      if (array && key === 'length') continue
      check(Object.hasOwn(d, 'value') && d.enumerable && (!array || /^(?:0|[1-9][0-9]*)$/.test(key)), 'inert-json-required')
      size += Buffer.byteLength(key); check(size <= MAX_BYTES, 'bytes-limit')
      Object.defineProperty(out, key, {value: visit(d.value, depth + 1), enumerable: true, configurable: true})
    }
    if (array) check(out.length === ds.length.value && Object.keys(out).length === out.length, 'inert-json-required')
    active.delete(node); return out
  }
  const bytes = Buffer.from(canonicalJSON(visit(value, 0)))
  check(bytes.length <= MAX_BYTES, 'bytes-limit')
  const parsed = parseOriginal(bytes)
  function freeze(node) { if (node && typeof node === 'object') { Object.values(node).forEach(freeze); Object.freeze(node) }; return node }
  return freeze(parsed)
}
export const isPrivateV2Coordinator = value => coordinators.has(value)
export const privateV2Checkpoint = envelope => Object.freeze({checkpoint_sha256: envelope.checkpoint_sha256,
  control_sha256: envelope.control_state.control_sha256, authorization_epoch: envelope.authorization_epoch})

// Each purpose has its own closed grammar. Journal work cannot impersonate a negative fence or restore.
export function checkedPrivateV2Transition(input, host, profile, contracts) {
  const transition = privateV2Detach(input), options = {host, profile, contracts}
  const purpose = transition.kind
  const validators = {
    'prime-runtime-unsent-journal-transition/v3': [assertJournalTransition, journalTransitionDigest],
    'prime-runtime-workflow-mutation/v3': [assertWorkflowTransition, workflowTransitionDigest],
    'prime-memory-negative-closure-transition/v3': [assertNegativeTransition, negativeTransitionDigest],
    'prime-memory-control-restore-transition/v3': [assertRestoreTransition, restoreTransitionDigest],
    'prime-memory-authorized-effect-transition/v3': [assertAuthorizedEffectTransition, effectTransitionDigest],
  }
  check(Object.hasOwn(validators, purpose), 'purpose-invalid')
  const pair = validators[purpose]
  check(pair, 'purpose-invalid')
  pair[0](transition, options)
  return {transition, digest: pair[1](transition, {contracts}), purpose}
}

export function createPrivateV2Coordinator(input) {
  const {reader, publisher, profile: rawProfile, contracts: suppliedContracts} = privateV2Fields(input,
    ['reader', 'publisher', 'profile', 'contracts'], 'configuration-required')
  check(isPrivateV2FileRetentionReader(reader), 'owned-retention-reader-required')
  check(suppliedContracts && typeof suppliedContracts === 'object' && !types.isProxy(suppliedContracts), 'contracts-required')
  const cds = Object.getOwnPropertyDescriptors(suppliedContracts)
  const contractNames = ['canonicalJson','validateContract','operationDigest']
  check(contractNames.every(key => cds[key] && Object.hasOwn(cds[key], 'value')
    && typeof cds[key].value === 'function'), 'contracts-required')
  const contracts = Object.freeze(Object.fromEntries(contractNames.map(key => [key, cds[key].value.bind(suppliedContracts)])))
  // H may own the publisher under a different UID/process. Its closed transport responses
  // establish no evidence: every preparation/publication/cleanup is independently reread.
  check(publisher && typeof publisher === 'object' && !types.isProxy(publisher), 'publisher-transport-required')
  const pds = Object.getOwnPropertyDescriptors(publisher)
  const methodNames = ['beginTyped', 'retainPrepared', 'publishPrepared', 'clearMatchingPending']
  check(Reflect.ownKeys(pds).every(key => methodNames.includes(key) || key === 'status')
    && methodNames.every(key => pds[key] && Object.hasOwn(pds[key], 'value')
      && typeof pds[key].value === 'function'), 'publisher-transport-required')
  if (pds.status) { check(Object.hasOwn(pds.status, 'value'), 'publisher-transport-required'); privateV2Detach(pds.status.value) }
  const transport = Object.freeze(Object.fromEntries(methodNames.map(key => [key, pds[key].value.bind(publisher)])))
  const profile = privateV2Detach(assertPrivateProfile(rawProfile)), contexts = new WeakMap()
  function request(inputRequest) {
    const r = privateV2Fields(inputRequest, ['host', 'transition_id', 'transition', 'transition_digest'], 'request-fields-invalid')
    const host = privateV2Detach(assertPrivateHost(r.host)), bound = checkedPrivateV2Transition(r.transition, host, profile, contracts)
    check(typeof r.transition_id === 'string' && UUID4.test(r.transition_id), 'transition-id-invalid')
    check(r.transition_digest === bound.digest, 'transition-digest-invalid')
    return privateV2Detach({...r, host, transition: bound.transition})
  }
  function checkedEnvelope(envelope, host) {
    const e = privateV2Detach(envelope)
    privateV2Fields(e, ['schema', 'owner_id', 'owner_subject', 'authorization_epoch', 'sequence',
      'previous_checkpoint_sha256', 'control_state', 'checkpoint_sha256'], 'envelope-fields-invalid')
    check(e.schema === 'aukora-prime-memory-retention/v2' && e.owner_id === host.owner_id
      && e.owner_subject === host.owner_subject && e.authorization_epoch === host.authorization_epoch
      && Number.isSafeInteger(e.sequence) && e.sequence >= 1
      && typeof e.checkpoint_sha256 === 'string' && HEX.test(e.checkpoint_sha256)
      && (e.previous_checkpoint_sha256 === null || typeof e.previous_checkpoint_sha256 === 'string' && HEX.test(e.previous_checkpoint_sha256))
      && (e.sequence === 1) === (e.previous_checkpoint_sha256 === null), 'envelope-binding-invalid')
    const {checkpoint_sha256, ...body} = e
    check(sha256(Buffer.from('aukora-prime.memory-retention.v2\0' + canonicalJSON(body))) === checkpoint_sha256, 'envelope-digest-invalid')
    assertControlV3(e.control_state, host, {profile, contracts})
    return e
  }
  function context(inputContext) {
    const s = contexts.get(inputContext)
    check(s && s.active, 'context-inactive')
    return s
  }
  function pendingTuple(pending, r, predecessor) {
    const p = privateV2Fields(pending, ['marker', 'predecessor', 'prepared', 'current'], 'pending-fields-invalid')
    check(p.marker.owner_id === r.host.owner_id && p.marker.owner_subject === r.host.owner_subject
      && p.marker.authorization_epoch === r.host.authorization_epoch && p.marker.transition_id === r.transition_id
      && p.marker.transition_digest === r.transition_digest && same(p.marker.transition, r.transition), 'pending-binding-invalid')
    const prior = checkedEnvelope(p.predecessor, r.host), current = checkedEnvelope(p.current, r.host)
    check(prior.checkpoint_sha256 === r.transition.expected_checkpoint_sha256
      && (!predecessor || same(prior, predecessor)), 'predecessor-mismatch')
    const prepared = p.prepared === null ? null : checkedEnvelope(p.prepared, r.host)
    check((prepared === null) === (p.marker.prepared_checkpoint_sha256 === null), 'pending-prepared-mismatch')
    if (prepared) check(prepared.checkpoint_sha256 === p.marker.prepared_checkpoint_sha256
      && prepared.previous_checkpoint_sha256 === prior.checkpoint_sha256 && prepared.sequence === prior.sequence + 1,
    'prepared-predecessor-mismatch')
    check(same(current, prior) || prepared !== null && same(current, prepared), 'published-pending-mismatch')
    return {marker: p.marker, predecessor: prior, prepared, current}
  }
  async function readVerifiedCurrent(hostInput, actualControl) {
    const host = privateV2Detach(assertPrivateHost(hostInput))
    const control = assertControlV3(actualControl, host, {profile, contracts})
    const current = checkedEnvelope(await reader.readCurrent(host), host)
    check(same(current.control_state, control), 'sql-retained-mismatch')
    return current
  }
  async function readVerifiedRestoreCurrent(hostInput, actualControl) {
    const host = privateV2Detach(assertPrivateHost(hostInput)), control = assertControlV3(actualControl, host, {profile, contracts})
    const current = checkedEnvelope(await reader.readCurrent(host), host)
    const raw = await reader.readPublishedLineage(host, {checkpoint_sha256: null})
    check(Array.isArray(raw) && raw.length > 0, 'published-lineage-required')
    const lineage = raw.map(e => checkedEnvelope(e, {...host, authorization_epoch: e.authorization_epoch}))
    check(same(lineage[0], current), 'published-lineage-head-mismatch')
    const index = lineage.findIndex(e => same(e.control_state, control))
    check(index >= 0, 'sql-not-published-ancestor')
    for (let i = index; i > 0; --i) {
      check(lineage[i - 1].previous_checkpoint_sha256 === lineage[i].checkpoint_sha256
        && lineage[i - 1].sequence === lineage[i].sequence + 1, 'published-lineage-adjacency-invalid')
      assertForwardControlV3(lineage[i].control_state, lineage[i - 1].control_state, host, {profile, contracts})
    }
    return Object.freeze({current, lineage:Object.freeze(lineage)})
  }
  async function beginTyped(inputRequest, actualControl) {
    const r = request(inputRequest)
    let predecessor
    if (r.transition.kind === 'prime-memory-control-restore-transition/v3') {
      predecessor = (await readVerifiedRestoreCurrent(r.host, actualControl)).current
      check(r.transition.anchor_checkpoint_sha256 === predecessor.checkpoint_sha256, 'restore-anchor-mismatch')
    } else predecessor = await readVerifiedCurrent(r.host, actualControl)
    check(predecessor.checkpoint_sha256 === r.transition.expected_checkpoint_sha256, 'expected-checkpoint-mismatch')
    await transport.beginTyped(r)
    const pending = pendingTuple(await reader.readPending({host: r.host, transition_id: r.transition_id,
      transition_digest: r.transition_digest}), r, predecessor)
    check(pending.prepared === null && same(pending.current, predecessor), 'unexpected-preparation')
    const owned = Object.freeze({request: r, predecessor})
    contexts.set(owned, {active: true, request: r, predecessor, prepared: null})
    return owned
  }
  async function prepareTyped(inputContext, actualControl) {
    const s = context(inputContext), control = assertControlV3(actualControl, s.request.host, {profile, contracts})
    check(s.prepared === null, 'already-prepared')
    if (s.request.transition.kind === 'prime-memory-control-restore-transition/v3') {
      check(same(control, s.predecessor.control_state), 'restore-candidate-anchor-mismatch')
    } else assertForwardControlV3(s.predecessor.control_state, control, s.request.host,
      {profile, contracts, transition: s.request.transition})
    const before = pendingTuple(await reader.readPending({host: s.request.host, transition_id: s.request.transition_id,
      transition_digest: s.request.transition_digest}), s.request, s.predecessor)
    check(before.prepared === null && same(before.current, s.predecessor), 'unexpected-preparation')
    await transport.retainPrepared({...s.request, control_state: control})
    const after = pendingTuple(await reader.readPending({host: s.request.host, transition_id: s.request.transition_id,
      transition_digest: s.request.transition_digest}), s.request, s.predecessor)
    check(after.prepared !== null && same(after.prepared.control_state, control) && same(after.current, s.predecessor), 'prepared-readback-mismatch')
    s.prepared = after.prepared
    return after.prepared
  }
  async function finishPrepared(r, predecessor, prepared, actualControl) {
    const control = assertControlV3(actualControl, r.host, {profile, contracts})
    check(same(prepared.control_state, control), 'committed-prepared-mismatch')
    const pending = pendingTuple(await reader.readPending({host: r.host, transition_id: r.transition_id,
      transition_digest: r.transition_digest}), r, predecessor)
    check(pending.prepared !== null && same(pending.prepared, prepared), 'prepared-changed')
    check(same(pending.current, predecessor) || same(pending.current, prepared), 'published-candidate-mismatch')
    // An already-visible pointer may follow a lost directory-fsync reply. The
    // explicit publisher command must converge the SAME candidate's durability
    // and exact marker readback; factual reads cannot finish that work.
    await transport.publishPrepared({...r, control_state: control})
    const published = checkedEnvelope(await reader.inspectPublishedCurrent(r.host), r.host)
    check(same(published, prepared) && same(published.control_state, control), 'publication-readback-mismatch')
    await transport.clearMatchingPending({...r, checkpoint_sha256: prepared.checkpoint_sha256})
    const completed = checkedEnvelope(await reader.readCurrent(r.host), r.host)
    check(same(completed, prepared) && same(completed.control_state, control), 'cleanup-readback-mismatch')
    return completed
  }
  async function completeTyped(inputContext, actualControl) {
    const s = context(inputContext)
    check(s.prepared !== null, 'prepared-required')
    const completed = await finishPrepared(s.request, s.predecessor, s.prepared, actualControl)
    s.active = false
    return completed
  }
  async function recoverTyped(inputRequest, actualControl) {
    const r = request(inputRequest)
    const p = pendingTuple(await reader.readPending({host: r.host, transition_id: r.transition_id,
      transition_digest: r.transition_digest}), r)
    check(p.prepared !== null, 'prepared-recovery-required')
    // Never replay SQL, generate a replacement candidate, or select a different checkpoint.
    return finishPrepared(r, p.predecessor, p.prepared, actualControl)
  }
  async function recoverJournal(inputRequest, actualControl) {
    const r = privateV2Fields(inputRequest, ['host', 'transition_id', 'transition_digest'], 'recovery-fields-invalid')
    const host = privateV2Detach(assertPrivateHost(r.host))
    check(typeof r.transition_id === 'string' && UUID4.test(r.transition_id), 'transition-id-invalid')
    const pending = await reader.readPending({host, transition_id: r.transition_id, transition_digest: r.transition_digest})
    const bound = request({...r, host, transition: pending.marker.transition})
    check(bound.transition.kind === 'prime-runtime-unsent-journal-transition/v3', 'journal-purpose-required')
    return recoverTyped(bound, actualControl)
  }
  async function beginJournal(inputRequest, actualControl) {
    const r = request(inputRequest)
    check(r.transition.kind === 'prime-runtime-unsent-journal-transition/v3', 'journal-purpose-required')
    return beginTyped(r, actualControl)
  }
  async function prepareJournal(inputContext, actualControl) {
    check(context(inputContext).request.transition.kind === 'prime-runtime-unsent-journal-transition/v3', 'journal-purpose-required')
    return prepareTyped(inputContext, actualControl)
  }
  async function completeJournal(inputContext, actualControl) {
    check(context(inputContext).request.transition.kind === 'prime-runtime-unsent-journal-transition/v3', 'journal-purpose-required')
    return completeTyped(inputContext, actualControl)
  }
  const coordinator = Object.freeze({reader, profile, contracts, isContext: value => contexts.has(value) && contexts.get(value).active,
    readVerifiedCurrent, readVerifiedRestoreCurrent, beginTyped, prepareTyped, completeTyped, recoverTyped,
    beginJournal, prepareJournal, completeJournal, recoverJournal,
    readPublishedLineage: (host, options) => reader.readPublishedLineage(host, options)})
  coordinators.add(coordinator)
  return coordinator
}
