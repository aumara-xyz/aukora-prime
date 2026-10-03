// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit source-only retained effect participant. Existing C permits stay byte-profile v1.
import { AsyncLocalStorage } from 'node:async_hooks'
import { randomUUID } from 'node:crypto'
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MemoryRefusal, parseOriginal, requireMemory, sha256 } from './codecs.mjs'
import { MEMORY_AUDIENCE, memoryTarget, memoryStateVersion, memoryEffectDigest, memoryReceiptDigest, memoryResultDigest } from './authorization.mjs'
import { isMemoryOwnerSerializer } from './owner-serialization.mjs'
import { isPrivateV2Coordinator, privateV2Fields, privateV2Detach } from './private-v2-coordinator.mjs'
import { assertPrivateHost, assertPrivateProfile, assertEffectReference, assertRestoreEffectParameters, readControlV3, decodeControlV3,
  effectTransitionDigest } from './private-v2-control.mjs'
import { assertForwardControlV3, assertRestoreEffectAdvance } from './private-v2-advance.mjs'
import { requirePrivateV2Guards } from './private-v2-guards.mjs'
import { inspectPrivateV2ColdBundle } from './private-v2-restore.mjs'
import { createPrivateV2RecordAccess } from './private-v2-records.mjs'

const controllers = new WeakSet()
const ownerClients = new WeakMap()
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const check = (ok, reason) => requireMemory(ok, 'memory:private-v2-effect-' + reason)
const same = (a, b) => canonicalJSON(a) === canonicalJSON(b)
const referenceOf = op => ({owner_id:op.owner_id,owner_subject:op.target_identity.owner_subject,task_id:op.task_id,
  operation_id:op.operation_id,operation_digest:null,action_type:op.action_type})
const markerDigest = marker => sha256(Buffer.from('aukora-prime.memory-retention-marker.v2\0' + canonicalJSON(marker)))
const grantDigest = grant => 'sha256:' + sha256(Buffer.from('aukora-prime.consumed-grant.v1\0' + canonicalJSON(grant)))
export const isPrivateV2EffectController = value => controllers.has(value)

// No caller can register a client. The raw client is usable by the fixed D-owned
// physical restore algorithms only during this factory's genuine held restore scope.
export function isPrivateV2EffectOwnerClient(client, host, access = 'read') {
  if (!host || types.isProxy(host) || !['read','write'].includes(access)) return false
  const ds = Object.getOwnPropertyDescriptors(host), states = ownerClients.get(client)
  return Boolean(states && [...states].some(state => state.active && !state.recovered
    && state.op.action_type === 'memory.restore' && state.restoreBundle !== null
    && state.scope.client === client
    && ['owner_id','owner_subject','task_id','authorization_epoch'].every(key => ds[key]
      && Object.hasOwn(ds[key],'value') && ds[key].value === state.host[key])
    && (access === 'read' || state.serializer.current() === state.scope && state.phase === 'applied' && state.dispatched
      && state.context !== null && state.effectPrepared === null)))
}

export function createPrivateV2EffectController(input) {
  const config = privateV2Fields(input, ['coordinator','serializer','contracts','profile'], 'effect-configuration-required')
  const {coordinator,serializer} = config
  check(isPrivateV2Coordinator(coordinator) && isMemoryOwnerSerializer(serializer), 'owned-participants-required')
  const profile = privateV2Detach(assertPrivateProfile(config.profile))
  check(same(profile, coordinator.profile), 'profile-mismatch')
  check(config.contracts && typeof config.contracts === 'object' && !types.isProxy(config.contracts), 'contracts-required')
  const ds = Object.getOwnPropertyDescriptors(config.contracts), keys = ['validateContract','operationDigest','canonicalJson']
  check(keys.every(key => ds[key] && Object.hasOwn(ds[key],'value') && typeof ds[key].value === 'function'), 'contracts-required')
  const contracts = Object.freeze(Object.fromEntries(keys.map(key => [key,ds[key].value.bind(config.contracts)])))
  const records = createPrivateV2RecordAccess({})
  const storage = new AsyncLocalStorage(), ownerLifetimes = new AsyncLocalStorage(), active = new Map()
  function operation(inputOperation) {
    const op = privateV2Detach(inputOperation)
    try {contracts.validateContract('OperationProposal',op)} catch {check(false,'operation-invalid')}
    check(['memory.save','memory.forget','memory.restore'].includes(op.action_type) && op.audience === MEMORY_AUDIENCE
      && same(op.target_identity,memoryTarget(op.target_identity?.owner_subject)), 'operation-profile-invalid')
    const digest = contracts.operationDigest(op)
    check(typeof digest === 'string' && DIGEST.test(digest), 'operation-digest-invalid')
    return {op,digest,key:canonicalJSON([op.operation_id,digest])}
  }
  function request(inputRequest) {
    const r = privateV2Fields(inputRequest,['host','operation','request_id','request_digest'],'effect-request-fields-invalid')
    const host = privateV2Detach(assertPrivateHost(r.host)), bound = operation(r.operation)
    check(bound.op.owner_id === host.owner_id && bound.op.task_id === host.task_id
      && bound.op.authorization_epoch === host.authorization_epoch
      && same(bound.op.target_identity,memoryTarget(host.owner_subject)), 'operation-host-mismatch')
    check(typeof r.request_id === 'string' && UUID.test(r.request_id)
      && typeof r.request_digest === 'string' && DIGEST.test(r.request_digest), 'request-binding-invalid')
    check(r.request_digest === memoryEffectDigest({version:1,action_type:bound.op.action_type,owner_subject:host.owner_subject,
      operation_id:bound.op.operation_id,operation_digest:bound.digest,parameters:bound.op.canonical_parameters}),
    'request-digest-mismatch')
    const reference = assertEffectReference({...referenceOf(bound.op),operation_digest:bound.digest},host)
    if (bound.op.action_type === 'memory.restore') restoreParameters(bound.op)
    return {...bound,host,reference:privateV2Detach(reference),request_id:r.request_id,request_digest:r.request_digest}
  }
  function restoreParameters(op) {
    const params = assertRestoreEffectParameters(op.canonical_parameters)
    check(params.retention_epoch === op.authorization_epoch, 'restore-parameters-invalid')
    return params
  }
  function current() {
    const state = storage.getStore()
    check(state?.active && serializer.current() === state.scope, 'scope-inactive')
    return state
  }
  function stateFor(inputOperation) {
    const bound = operation(inputOperation), state = active.get(bound.key)
    check(state?.active && same(state.op,bound.op), 'operation-not-active')
    return state
  }
  async function session(state) {
    check(state.active, 'scope-inactive')
    const observed = await serializer.inspect(state.scope)
    check(state.active && ['owner_id','owner_subject','authorization_epoch'].every(key => observed[key] === state.host[key]), 'session-binding-invalid')
    return observed
  }
  async function read(client, state) {
    // Fixed private C phase handlers may run outside origin ALS while that origin awaits C.
    // The exact active operation and serializer's genuine still-held scope establish custody.
    check(state.active && state.scope.client === client, 'owner-client-required')
    await session(state)
    await requirePrivateV2Guards(client,{owner_subject:state.host.owner_subject,owner_id:state.host.owner_id,
      expected_store_id:profile.expected_memory_store_id,profile})
    const actual = privateV2Detach(await readControlV3(client,{owner_subject:state.host.owner_subject,owner_id:state.host.owner_id,profile},{contracts}))
    check(state.active, 'scope-inactive')
    return actual
  }
  const decoded = (control, state) => decodeControlV3(control,state.host,{profile,contracts})
  function eligible(control, state) {
    const tables = decoded(control,state).tables
    if (state.op.action_type === 'memory.restore') {
      check(!['runtime_workflows','workflow_closure_progress','unsent_closures','replay_fences']
        .some(name => tables[name].some(row => row.operation_id === state.op.operation_id)), 'restore-operation-fenced')
      return tables
    }
    const workflow = tables.runtime_workflows.find(row => row.operation_id === state.op.operation_id)
    check(workflow && Object.entries(state.reference).every(([key,value]) => workflow[key] === value)
      && workflow.phase === 'attempted', 'retained-attempted-workflow-required')
    if (Object.hasOwn(state.op.canonical_parameters,'idempotency_key_sha256'))
      check(workflow.idempotency_key_sha256 === state.op.canonical_parameters.idempotency_key_sha256, 'workflow-key-mismatch')
    check(!tables.workflow_closure_progress.some(row => row.operation_id === state.op.operation_id)
      && !tables.unsent_closures.some(row => row.operation_id === state.op.operation_id)
      && !tables.replay_fences.some(row => row.operation_id === state.op.operation_id), 'operation-fenced')
    return tables
  }
  function checkedGrant(rawGrant, state) {
    const grant = privateV2Detach(rawGrant)
    try {contracts.validateContract('ConsumedGrant',grant)} catch {check(false,'grant-invalid')}
    check(grant.operation_id === state.op.operation_id && grant.operation_digest === state.digest
      && grant.owner_id === state.host.owner_id && grant.audience === state.op.audience
      && grant.authorization_epoch === state.host.authorization_epoch, 'grant-binding-invalid')
    return grant
  }
  function intent(control, state, grant) {
    const tables = decoded(control,state).tables, row = tables.intents.find(r => r.operation_id === state.op.operation_id)
    check(row && row.operation_digest === state.digest && row.request_id === state.request_id
      && row.request_digest === state.request_digest && row.operation_bytes.equals(Buffer.from(canonicalJSON(state.op)))
      && (!grant || row.grant_bytes.equals(Buffer.from(canonicalJSON(grant)))), 'intent-binding-mismatch')
    const storedGrant = checkedGrant(parseOriginal(row.grant_bytes),state), req = parseOriginal(row.request_bytes)
    privateV2Fields(req,['version','action_type','owner_subject','operation_id','operation_digest','parameters'],
      'intent-request-fields-invalid')
    check(req.version === 1 && memoryEffectDigest(req) === state.request_digest && req.owner_subject === state.host.owner_subject
      && req.operation_id === state.op.operation_id && req.operation_digest === state.digest
      && req.action_type === state.op.action_type && same(req.parameters,state.op.canonical_parameters), 'intent-request-mismatch')
    return {row,grant:storedGrant,tables}
  }
  function effect(control, state, supplied) {
    const i = intent(control,state), row = i.tables.effects.find(r => r.operation_id === state.op.operation_id)
    check(row && row.operation_digest === state.digest && row.grant_id === i.grant.grant_id
      && row.action === state.op.action_type && row.request_id === state.request_id && row.request_digest === state.request_digest
      && row.operation_bytes.equals(Buffer.from(canonicalJSON(state.op))) && row.grant_bytes.equals(Buffer.from(canonicalJSON(i.grant)))
      && row.request_bytes.equals(i.row.request_bytes), 'effect-binding-mismatch')
    const receipt = parseOriginal(row.receipt_bytes), result = parseOriginal(row.result_bytes)
    privateV2Fields(receipt,['version','kind','operation_id','operation_digest','grant_id','request_id','request_digest',
      'owner_subject','action_type','status','result_digest','result'],'effect-receipt-fields-invalid')
    check(receipt.version === 1 && receipt.kind === 'prime-memory-effect/v1' && receipt.status === 'applied'
      && receipt.operation_id === state.op.operation_id && receipt.operation_digest === state.digest
      && receipt.grant_id === i.grant.grant_id && receipt.request_id === state.request_id
      && receipt.request_digest === state.request_digest && receipt.owner_subject === state.host.owner_subject
      && receipt.action_type === state.op.action_type && receipt.result_digest === memoryResultDigest(result)
      && same(receipt.result,result), 'effect-receipt-mismatch')
    const factual = {operation:state.op,grant:i.grant,receipt:privateV2Detach(receipt),result:privateV2Detach(result)}
    if (supplied) check(same(factual,privateV2Detach(supplied)), 'supplied-effect-mismatch')
    return factual
  }
  function transition(state, phase, checkpoint) {
    return privateV2Detach({version:3,kind:'prime-memory-authorized-effect-transition/v3',memory_store_id:profile.expected_memory_store_id,
      reference:state.reference,authorization_epoch:state.host.authorization_epoch,operation:state.op,
      request_id:state.request_id,request_digest:state.request_digest,phase,expected_checkpoint_sha256:checkpoint})
  }
  function restoreFacts(control, state, protectedState) {
    check(state.op.action_type === 'memory.restore' && !state.recovered && state.restoreBundle !== null,
      'restore-bundle-required')
    const {current:anchor,lineage} = protectedState, params = restoreParameters(state.op)
    const checked = inspectPrivateV2ColdBundle(state.restoreBundle,state.host,{profile,contracts})
    check(same(checked.published_lineage,lineage) && same(checked.published_lineage[0],anchor),
      'restore-protected-bundle-mismatch')
    const local = decoded(control,state), retained = decoded(anchor.control_state,state)
    check(params.manifest_sha256 === checked.bundle.snapshot.manifest_sha256
      && params.retention_checkpoint_sha256 === anchor.checkpoint_sha256
      && params.control_anchor_sha256 === anchor.control_state.control_sha256
      && params.retention_epoch === anchor.authorization_epoch
      && same(params.heads,checked.bundle.snapshot.heads) && same(params.retained_heads,retained.heads)
      && state.op.expected_state_version === memoryStateVersion(local.heads), 'restore-reviewed-binding-mismatch')
    const at = lineage.findIndex(envelope => same(envelope.control_state,control))
    check(at >= 0, 'restore-local-ancestor-required')
    // The reviewed fixed journal adapter performs ordinary monotone per-edge CAS.
    // A protected exceptional restore edge may be valid history, yet unsupported
    // by that adapter. Refuse the actual chronological interval BEFORE C consumes;
    // never skip an edge or supply archive ancestry to weaken this compatibility check.
    for (let n = at; n > 0; --n) assertForwardControlV3(lineage[n].control_state,
      lineage[n - 1].control_state,state.host,{profile,contracts})
    for (const envelope of lineage) {
      const tables = eligible(envelope.control_state,state)
      check(!['intents','effects','replay_fences'].some(name => tables[name].some(row =>
        row.operation_id === state.op.operation_id || row.request_id === state.request_id)), 'restore-durable-operation-present')
    }
    return {anchor,localControl:control,lineage:privateV2Detach(lineage),
      ancestry:privateV2Detach(lineage.slice(0,at + 1).reverse().map(envelope => envelope.control_state)),
      snapshot:privateV2Detach(checked.bundle.snapshot),retained}
  }
  async function start(state, phase, control, predecessor) {
    await session(state)
    const body = transition(state,phase,predecessor.checkpoint_sha256), transition_id = randomUUID()
    check(!state.ids.has(transition_id), 'transition-id-reused'); state.ids.add(transition_id)
    const req = {host:state.host,transition_id,transition:body,transition_digest:effectTransitionDigest(body)}
    state.pendingMayExist = true; state.lastRequest = req; state.phase = phase
    const context = await coordinator.beginTyped(req,control)
    const observed = await coordinator.reader.readPending({host:state.host,transition_id,transition_digest:req.transition_digest})
    check(observed.prepared === null && same(observed.current,predecessor), 'new-pending-readback-invalid')
    state.context = context; state.phase = phase; state.marker = privateV2Detach(observed.marker)
    return context
  }
  function permit(state, phase, owner_session, envelope, marker, grant = null, receipt = null) {
    check(state.active && active.get(state.key) === state && state.original !== null, 'original-checkpoint-required')
    return privateV2Detach({version:1,kind:'prime-retained-memory-permit/v1',phase,
      owner_id:state.host.owner_id,owner_subject:state.host.owner_subject,authorization_epoch:state.host.authorization_epoch,
      operation_id:state.op.operation_id,operation_digest:state.digest,request_id:state.request_id,request_digest:state.request_digest,
      owner_session,predecessor_checkpoint_sha256:state.original.checkpoint_sha256,checkpoint_sha256:envelope.checkpoint_sha256,
      control_sha256:envelope.control_state.control_sha256,marker_sha256:marker === null ? null : markerDigest(marker),
      grant_digest:grant === null ? null : grantDigest(grant),receipt_digest:receipt === null ? null : memoryReceiptDigest(receipt),
      result_digest:receipt === null ? null : receipt.result_digest})
  }
  async function prepare(inputPrepare) {
    const r = privateV2Fields(inputPrepare,['operation'],'prepare-fields-invalid'), state = stateFor(r.operation)
    check(!state.recovered && !state.prepareCalled && state.context === null, 'prepare-already-attempted')
    state.prepareCalled = true
    const control = await read(state.scope.client,state), tables = eligible(control,state)
    check(!tables.intents.some(row => row.operation_id === state.op.operation_id)
      && !tables.effects.some(row => row.operation_id === state.op.operation_id), 'durable-operation-present')
    let predecessor
    if (state.op.action_type === 'memory.restore') {
      const protectedState = await coordinator.readVerifiedRestoreCurrent(state.host,control)
      const factual = restoreFacts(control,state,protectedState)
      // Fixed owned SQL checks actual local physical records against the signed full
      // snapshot and protected anchor BEFORE C receives a prepare permit or consumes.
      await records.preflight(state.scope.client,state.host,factual.snapshot,factual.retained)
      const reread = await read(state.scope.client,state)
      check(same(reread,control), 'restore-preflight-state-changed')
      const protectedAgain = await coordinator.readVerifiedRestoreCurrent(state.host,reread)
      check(same(protectedAgain,protectedState), 'restore-preflight-publication-changed')
      state.restoreLocalControl = factual.localControl
      state.restorePublishedLineage = factual.lineage
      state.restoreAncestry = factual.ancestry
      state.restoreSnapshot = factual.snapshot
      predecessor = factual.anchor
    } else predecessor = await coordinator.readVerifiedCurrent(state.host,control)
    state.original = predecessor
    await start(state,'intent',control,predecessor)
    return permit(state,'prepare',await session(state),predecessor,state.marker)
  }
  async function prepareIntent(client, rawGrant) {
    const state = current(), grant = rawGrant === undefined ? undefined : checkedGrant(rawGrant,state)
    check(state.phase === 'intent' && state.context && !state.intentPrepared, 'intent-context-required')
    const candidate = await read(client,state), factual = intent(candidate,state,grant)
    state.intentPrepared = await coordinator.prepareTyped(state.context,candidate)
    state.grant = factual.grant
    return state.intentPrepared
  }
  async function completeIntent(client) {
    const state = current()
    check(state.phase === 'intent' && state.intentPrepared && state.context, 'intent-prepared-required')
    const actual = await read(client,state); intent(actual,state,state.grant)
    const published = await coordinator.completeTyped(state.context,actual)
    check(same(published,state.intentPrepared), 'intent-publication-mismatch')
    state.intentCheckpoint = published; state.context = null
    // A new typed applied marker follows completed I, never an unretained post-checkpoint SQL write.
    await start(state,'applied',actual,published)
    return published
  }
  async function dispatch(inputDispatch) {
    const r = privateV2Fields(inputDispatch,['operation','consumed_grant','request_id','request_digest'],'dispatch-fields-invalid')
    const state = stateFor(r.operation), grant = checkedGrant(r.consumed_grant,state)
    check(state.phase === 'applied' && state.context && state.intentCheckpoint && !state.dispatched
      && r.request_id === state.request_id && r.request_digest === state.request_digest, 'dispatch-context-required')
    const actual = await read(state.scope.client,state); intent(actual,state,grant)
    const pending = await coordinator.reader.readPending({host:state.host,...Object.fromEntries(['transition_id','transition_digest']
      .map(key => [key,state.context.request[key]]))})
    check(pending.prepared === null && same(pending.current,state.intentCheckpoint)
      && same(pending.current.control_state,actual) && same(pending.marker,state.marker), 'dispatch-retention-mismatch')
    const owner_session = await session(state)
    state.dispatched = true
    return permit(state,'dispatch',owner_session,state.intentCheckpoint,state.marker,grant)
  }
  async function prepareEffect(client, suppliedEffect) {
    const state = current()
    check(state.phase === 'applied' && state.context && state.dispatched && !state.effectPrepared, 'applied-context-required')
    const candidate = await read(client,state), factual = effect(candidate,state,suppliedEffect)
    check(same(factual.grant,state.grant), 'effect-grant-changed')
    state.effectPrepared = await coordinator.prepareTyped(state.context,candidate)
    return state.effectPrepared
  }
  async function restoreEvidence(client) {
    const state = current()
    check(state.op.action_type === 'memory.restore' && !state.recovered && state.restoreBundle !== null,
      'restore-bundle-required')
    const actual = await read(client,state)
    let facts
    if (state.original === null) {
      check(state.context === null && !state.prepareCalled, 'restore-evidence-context-invalid')
      facts = restoreFacts(actual,state,await coordinator.readVerifiedRestoreCurrent(state.host,actual))
      await records.preflight(client,state.host,facts.snapshot,facts.retained)
      check(same(await read(client,state),actual), 'restore-preflight-state-changed')
    } else {
      check(state.context && ['intent','applied'].includes(state.phase) && state.restoreLocalControl !== null
        && state.restorePublishedLineage !== null && same(state.restorePublishedLineage[0],state.original),
      'restore-evidence-context-invalid')
      const pending = await coordinator.reader.readPending({host:state.host,
        transition_id:state.context.request.transition_id,transition_digest:state.context.request.transition_digest})
      const expected = state.phase === 'intent' ? state.original : state.intentCheckpoint
      check(pending.prepared === null && same(pending.current,expected) && same(pending.predecessor,expected)
        && same(pending.marker,state.marker) && same(pending.marker.transition,state.context.request.transition),
      'restore-evidence-pending-mismatch')
      if (state.phase === 'intent') check(same(actual,state.restoreLocalControl), 'restore-evidence-local-changed')
      else {
        check(state.intentCheckpoint !== null && same(actual,state.intentCheckpoint.control_state)
          && state.intentCheckpoint.previous_checkpoint_sha256 === state.original.checkpoint_sha256,
        'restore-evidence-intent-changed')
        intent(actual,state,state.grant)
        assertRestoreEffectAdvance(state.original.control_state,actual,state.host,{profile,contracts,
          transition:transition(state,'intent',state.original.checkpoint_sha256),
          published_ancestry:state.restorePublishedLineage})
      }
      facts = {anchor:state.original,localControl:state.restoreLocalControl,ancestry:state.restoreAncestry,
        snapshot:state.restoreSnapshot}
    }
    return privateV2Detach({anchor:facts.anchor,localControl:facts.localControl,ancestry:facts.ancestry,
      snapshot:facts.snapshot,operation:state.op})
  }
  async function restoreIntent(client) {
    const state = current()
    check(state.op.action_type === 'memory.restore' && state.phase === 'applied' && state.dispatched
      && state.effectPrepared === null, 'restore-intent-context-required')
    await restoreEvidence(client)
    const actual = await read(client,state)
    check(same(actual,state.intentCheckpoint.control_state), 'restore-evidence-intent-changed')
    intent(actual,state,state.grant)
    // A portable copy of the ACTUAL I row is evidence for preserving X. It is not
    // a target control projection or a caller-provided instruction to omit a row.
    return privateV2Detach(actual.tables.intents.find(row => row.operation_id === state.op.operation_id))
  }
  const verifiedEffectCurrent = (state,control) => state.op.action_type === 'memory.restore'
    ? coordinator.readVerifiedEffectCurrent(state.host,control,state.op)
    : coordinator.readVerifiedCurrent(state.host,control)
  async function archiveLineage(state, control, currentEnvelope) {
    const lineage = await coordinator.reader.readPublishedLineage(state.host,{checkpoint_sha256:null})
    check(Array.isArray(lineage) && lineage.length > 0 && same(lineage[0],currentEnvelope), 'published-lineage-required')
    let firstIntent = -1, firstEffect = -1
    for (let n = 0; n < lineage.length; ++n) {
      const tables = decoded(lineage[n].control_state,state).tables
      if (tables.intents.some(row => row.operation_id === state.op.operation_id)) {
        intent(lineage[n].control_state,state); firstIntent = n
      }
      if (tables.effects.some(row => row.operation_id === state.op.operation_id)) {
        effect(lineage[n].control_state,state); firstEffect = n
      }
    }
    check(firstIntent >= 0 && firstEffect >= 0 && firstIntent > firstEffect && firstIntent + 1 < lineage.length,
      'first-effect-lineage-missing')
    const I = lineage[firstIntent], E = lineage[firstEffect]
    const P = state.op.action_type === 'memory.restore'
      ? lineage.find(envelope => envelope.checkpoint_sha256 === restoreParameters(state.op).retention_checkpoint_sha256)
      : lineage[firstIntent + 1]
    check(P && same(P,lineage[firstIntent + 1]), 'effect-original-checkpoint-missing')
    check(I.previous_checkpoint_sha256 === P.checkpoint_sha256 && I.sequence === P.sequence + 1
      && E.previous_checkpoint_sha256 === I.checkpoint_sha256 && E.sequence === I.sequence + 1,
    'effect-lineage-adjacency-invalid')
    const originalTables = eligible(P.control_state,state)
    check(!originalTables.intents.some(row => row.operation_id === state.op.operation_id)
      && !originalTables.effects.some(row => row.operation_id === state.op.operation_id), 'intent-predecessor-not-absent')
    const intentBody = transition(state,'intent',P.checkpoint_sha256), appliedBody = transition(state,'applied',I.checkpoint_sha256)
    if (state.op.action_type === 'memory.restore') {
      assertRestoreEffectAdvance(P.control_state,I.control_state,state.host,{profile,contracts,
        transition:intentBody,published_ancestry:lineage.slice(firstIntent + 1)})
      assertRestoreEffectAdvance(I.control_state,E.control_state,state.host,{profile,contracts,
        transition:appliedBody,published_ancestry:lineage.slice(firstIntent)})
    } else {
      assertForwardControlV3(P.control_state,I.control_state,state.host,{profile,contracts,transition:intentBody})
      assertForwardControlV3(I.control_state,E.control_state,state.host,{profile,contracts,transition:appliedBody})
    }
    effect(control,state)
    return {P,I,E}
  }
  async function recoverApplied(client, state, actual) {
    let pending
    try {pending = await coordinator.reader.inspectPending(state.host)}
    catch (error) {if(error.code !== 'memory:private-v2-retention-pending-missing') throw error; return null}
    const marker = pending.marker, body = marker.transition
    check(body.kind === 'prime-memory-authorized-effect-transition/v3' && body.phase === 'applied'
      && same(body.operation,state.op) && same(body.reference,state.reference)
      && body.request_id === state.request_id && body.request_digest === state.request_digest
      && body.authorization_epoch === state.host.authorization_epoch && pending.prepared !== null, 'matching-applied-recovery-required')
    effect(actual,state)
    state.pendingMayExist = true; state.phase = 'applied'
    state.lastRequest = {host:state.host,transition_id:marker.transition_id,transition:body,transition_digest:marker.transition_digest}
    return coordinator.recoverTyped(state.lastRequest,actual)
  }
  async function completeEffect(client) {
    const state = current(), actual = await read(client,state)
    effect(actual,state); state.effectObserved = true
    let envelope
    if (state.context) {
      check(state.phase === 'applied' && state.effectPrepared, 'effect-prepared-required')
      envelope = await coordinator.completeTyped(state.context,actual)
      check(same(envelope,state.effectPrepared), 'effect-publication-mismatch')
      state.context = null
    } else {
      await recoverApplied(client,state,actual)
      envelope = await verifiedEffectCurrent(state,actual)
      const archived = await archiveLineage(state,actual,envelope)
      state.original = archived.P; state.intentCheckpoint = archived.I; state.effectPrepared = archived.E
    }
    state.effectCheckpoint = envelope; state.phase = 'completed'
    return envelope
  }
  async function settle(inputSettle) {
    const r = privateV2Fields(inputSettle,['operation','consumed_grant','request_id','request_digest','receipt'],'settle-fields-invalid')
    const state = stateFor(r.operation), grant = checkedGrant(r.consumed_grant,state)
    check(r.request_id === state.request_id && r.request_digest === state.request_digest, 'settle-request-mismatch')
    const actual = await read(state.scope.client,state), factual = effect(actual,state)
    state.effectObserved = true
    check(same(factual.grant,grant) && same(factual.receipt,privateV2Detach(r.receipt)), 'settle-factual-receipt-mismatch')
    const retained = await verifiedEffectCurrent(state,actual)
    const archived = await archiveLineage(state,actual,retained)
    state.original = archived.P; state.intentCheckpoint = archived.I
    return permit(state,'settle',await session(state),retained,null,grant,factual.receipt)
  }
  async function assertCurrent(client, inputHost) {
    const host = privateV2Detach(assertPrivateHost(inputHost)), scope = serializer.current()
    check(scope && scope.client === client && ['owner_id','owner_subject','authorization_epoch']
      .every(key => scope.host[key] === host[key]), 'owner-client-required')
    const state = storage.getStore()
    if (state?.active) check(state.scope === scope && same(host,state.host), 'current-host-mismatch')
    await serializer.inspect(scope)
    await requirePrivateV2Guards(client,{owner_subject:host.owner_subject,owner_id:host.owner_id,
      expected_store_id:profile.expected_memory_store_id,profile})
    const actual = privateV2Detach(await readControlV3(client,{owner_subject:host.owner_subject,owner_id:host.owner_id,profile},{contracts}))
    if (state?.active && state.op.action_type === 'memory.restore') {
      if (state.recovered || state.intentCheckpoint !== null || decoded(actual,state).tables.intents
        .some(row => row.operation_id === state.op.operation_id)) return verifiedEffectCurrent(state,actual)
      return (await coordinator.readVerifiedRestoreCurrent(host,actual)).current
    }
    return coordinator.readVerifiedCurrent(host,actual)
  }

  const participant = Object.freeze({prepare,dispatch,settle})
  const uncertainState = state => Boolean(state?.pendingMayExist || state?.effectCheckpoint || state?.effectObserved)
  const ownerSessionFailure = cause => typeof cause?.code === 'string' && cause.code.startsWith('memory:owner-session-')
  function outcomeUnknown(cause, host, state = null) {
    const error = new MemoryRefusal('memory:private-v2-effect-outcome-unknown')
    error.cause = cause; error.cause_code = cause?.code ?? null
    error.reconciliation_required = true; error.automatic_retry = false
    error.owner_id = host.owner_id; error.owner_subject = host.owner_subject
    error.task_id = host.task_id; error.authorization_epoch = host.authorization_epoch
    if (state) {
      // Only internally detached/validated operation state supplies these identifiers.
      error.operation_id = state.op.operation_id; error.operation_digest = state.digest
      error.request_id = state.request_id; error.request_digest = state.request_digest
      if (state.lastRequest) {
        error.retention_transition_id = state.lastRequest.transition_id
        error.retention_transition_digest = state.lastRequest.transition_digest
        error.retention_phase = state.lastRequest.transition.phase
      }
    }
    return error
  }
  async function withOwnerLifetime(inputHost, fn) {
    const host = privateV2Detach(assertPrivateHost(inputHost))
    check(typeof fn === 'function', 'work-required')
    const prior = ownerLifetimes.getStore(), held = serializer.current()
    if (prior) {
      // An escaped asynchronous frame cannot create a fresh owner lifetime or use old state.
      check(prior.active && held && held === prior.scope && same(host,prior.host), 'owner-lifetime-inactive')
      return serializer.run({owner_id:host.owner_id,owner_subject:host.owner_subject,
        authorization_epoch:host.authorization_epoch}, fn)
    }
    // A caller-owned outer lifetime could fail after this nested call has returned. It must
    // enter through this source-owned boundary so its final inspection/cleanup is covered.
    check(held === null, 'untracked-owner-lifetime')
    const lifetime = {host,scope:null,active:true,states:[]}
    return ownerLifetimes.run(lifetime, async () => {
      try {
        return await serializer.run({owner_id:host.owner_id,owner_subject:host.owner_subject,
          authorization_epoch:host.authorization_epoch}, async scope => {
          lifetime.scope = scope
          return fn(scope)
        })
      } catch (cause) {
        const affected = lifetime.states.findLast(uncertainState)
        if (affected || ownerSessionFailure(cause)) {
          // Keep the most recent factual/retention attempt. A pure owner-session failure
          // carries the trusted owner binding without fabricating an operation or request.
          throw outcomeUnknown(cause,host,affected ?? lifetime.states.at(-1) ?? null)
        }
        throw cause
      } finally {lifetime.active = false}
    })
  }
  async function runBound(bound, fn, {bundle = null,recovered = false} = {}) {
    check(typeof fn === 'function', 'work-required')
    let state = null
    try {
      return await serializer.run({owner_id:bound.host.owner_id,owner_subject:bound.host.owner_subject,
        authorization_epoch:bound.host.authorization_epoch}, async scope => {
        check(!active.has(bound.key), 'operation-already-active')
        const lifetime = ownerLifetimes.getStore()
        if (lifetime) check(lifetime.active && lifetime.scope === scope && same(lifetime.host,bound.host), 'owner-lifetime-inactive')
        state = {...bound,scope,serializer,active:true,context:null,phase:null,original:null,marker:null,grant:null,
          ids:new Set(),pendingMayExist:false,lastRequest:null,prepareCalled:false,intentPrepared:null,intentCheckpoint:null,
          dispatched:false,effectPrepared:null,effectCheckpoint:null,effectObserved:false,recovered,
          restoreBundle:bundle,restoreLocalControl:null,restorePublishedLineage:null,restoreAncestry:null,restoreSnapshot:null}
        if (lifetime) lifetime.states.push(state)
        active.set(bound.key,state)
        let owned = ownerClients.get(scope.client)
        if (!owned) {owned = new Set(); ownerClients.set(scope.client,owned)}
        owned.add(state)
        try {return await storage.run(state,() => fn(scope))}
        finally {
          state.active = false; active.delete(bound.key); owned.delete(state)
          if (owned.size === 0) ownerClients.delete(scope.client)
        }
      })
    } catch (cause) {
      if (uncertainState(state) || ownerSessionFailure(cause)) throw outcomeUnknown(cause,bound.host,state)
      throw cause
    }
  }
  async function runOperation(inputRequest, fn) {
    const bound = request(inputRequest)
    check(bound.op.action_type !== 'memory.restore', 'restore-bundle-required')
    return runBound(bound,fn)
  }
  async function runRestoreOperation(inputRequest, fn) {
    const supplied = privateV2Fields(inputRequest,['host','operation','request_id','request_digest','bundle'],
      'restore-request-fields-invalid')
    const bound = request(Object.fromEntries(['host','operation','request_id','request_digest'].map(key => [key,supplied[key]])))
    check(bound.op.action_type === 'memory.restore', 'restore-operation-required')
    const bundle = privateV2Detach(supplied.bundle)
    // This first byte inspection is deliberately not a publication assertion. prepare
    // repeats it against the protected reader and actual owner SQL before C consumes.
    inspectPrivateV2ColdBundle(bundle,bound.host,{profile,contracts})
    return runBound(bound,fn,{bundle})
  }
  async function runRecoveredOperation(inputRequest, fn) {
    const bound = request(inputRequest)
    check(bound.op.action_type === 'memory.restore', 'restore-operation-required')
    // A restart can settle an actual already committed receipt without retaining its
    // input snapshot. This scope cannot prepare, dispatch, or write physical records.
    return runBound(bound,fn,{recovered:true})
  }
  const context = () => {const state = storage.getStore(); return state?.active && serializer.current() === state.scope ? state.context : null}
  const controller = Object.freeze({participant,runOperation,runRestoreOperation,runRecoveredOperation,restoreEvidence,restoreIntent,
    withOwnerLifetime,context,prepareIntent,completeIntent,prepareEffect,completeEffect,
    finalizeRecovered:completeEffect,assertCurrent,profile})
  controllers.add(controller)
  return controller
}
