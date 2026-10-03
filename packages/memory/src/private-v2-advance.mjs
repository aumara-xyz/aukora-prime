// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { types } from 'node:util'
import { MAX_BYTES, parseOriginal, requireMemory, sha256, validateOriginal } from './codecs.mjs'
import { assertMemoryControlAdvance } from './control-retention-advance.mjs'
import { makeMemoryControlState, MEMORY_CONTROL_TABLES } from './control-state.mjs'
import { memoryStateVersion, memoryResultDigest } from './authorization.mjs'
import { PRIVATE_CONTROL_TABLES, PRIVATE_REFERENCE_FIELDS, PRIVATE_PROGRESS_STAGES, decodeControlV3,
  assertProgressV2, progressDigest, workflowRowDigest, assertJournalTransition, assertWorkflowTransition,
  assertNegativeTransition, assertRestoreTransition, assertAuthorizedEffectTransition, assertPrivateHost,
  detachPrivateData, writerCompletionV2Digest, assertRestoreEffectParameters } from './private-v2-control.mjs'

const check = (ok,reason) => requireMemory(ok,'memory:private-v2-advance-' + reason)
const same = (a,b) => canonicalJSON(a) === canonicalJSON(b)
const rowKey = (row,name) => canonicalJSON(PRIVATE_CONTROL_TABLES[name].key.map(column => row[column]))
const byKey = (rows,name) => new Map(rows.map(row => [rowKey(row,name),row]))
const rowSame = (a,b,name) => b !== undefined && PRIVATE_CONTROL_TABLES[name].columns.every(column =>
  PRIVATE_CONTROL_TABLES[name].byteColumns.includes(column) ? a[column].equals(b[column]) : a[column] === b[column])
const referenceOf = row => Object.fromEntries(PRIVATE_REFERENCE_FIELDS.map(column => [column,row[column]]))
const WORKFLOW_IMMUTABLE = ['owner_id','owner_subject','task_id','operation_id','operation_digest','action_type',
  'idempotency_key_sha256','created_at']
const RECEIPT_FIELDS = ['record_id','request_id','request_digest','receipt_digest']
const PROGRESS_IMMUTABLE = ['version','kind','reference','idempotency_key_sha256','closure_attempt_id',
  'expected_authority_store_id','expected_memory_store_id','closing_authorization_epoch']
function progressMap(tables,{profile,contracts}) {
  return new Map(tables.workflow_closure_progress.map(row => [row.operation_id,
    {row,progress:assertProgressV2(parseOriginal(row.progress_bytes),{profile,contracts})}]))
}
function legacy(control,host,contracts) {
  const tables = Object.fromEntries(Object.keys(MEMORY_CONTROL_TABLES).map(name => [name,control.tables[name]]))
  tables.unsent_closures = control.tables.unsent_closures.filter(row => parseOriginal(row.closure_bytes).version === 1)
  return makeMemoryControlState(host,{heads:control.heads,tables},{contracts})
}
function assertProgressEdge(before,after,contracts) {
  const old = before.progress, next = after.progress
  check(PROGRESS_IMMUTABLE.every(key => same(old[key],next[key])),'progress-binding-changed')
  const oldRank = PRIVATE_PROGRESS_STAGES.indexOf(old.stage), nextRank = PRIVATE_PROGRESS_STAGES.indexOf(next.stage)
  check(nextRank === oldRank || nextRank === oldRank + 1,'progress-stage-skipped-or-regressed')
  if (old.authority !== null) check(same(old.authority,next.authority),'authority-proof-changed')
  if (old.memory !== null) check(same(old.memory,next.memory),'memory-proof-changed')
  if (nextRank === oldRank) check(before.row.progress_bytes.equals(after.row.progress_bytes)
    && before.row.progress_digest === after.row.progress_digest,'same-stage-proof-changed')
  check(after.row.progress_digest === progressDigest(next,{contracts}),'progress-digest-changed')
}
function assertWorkflowEdge(old,next,oldProgress,nextProgress) {
  check(WORKFLOW_IMMUTABLE.every(key => old[key] === next[key]),'workflow-binding-changed')
  for (const column of RECEIPT_FIELDS) if (old[column] !== null) check(old[column] === next[column],'workflow-receipt-changed')
  if (old.phase === next.phase) check(RECEIPT_FIELDS.every(column => old[column] === next[column]),'same-phase-receipt-changed')
  else {
    check(old.phase === 'proposed' && next.phase === 'attempted' || old.phase === 'attempted'
      && ['saved','forgotten','known_unsent'].includes(next.phase),'workflow-phase-skipped-or-regressed')
    if (next.phase === 'known_unsent') check(oldProgress?.progress.stage === 'memory_confirmed'
      && nextProgress?.progress.stage === 'complete' && RECEIPT_FIELDS.every(column => old[column] === next[column]),
      'known-unsent-without-terminal-cas')
    else check(!oldProgress && !nextProgress,'ordinary-phase-during-closure')
  }
  if (oldProgress || nextProgress) {
    const terminal = oldProgress?.progress.stage === 'memory_confirmed' && nextProgress?.progress.stage === 'complete'
    check(terminal ? old.phase === 'attempted' && next.phase === 'known_unsent'
      : rowSame(old,next,'runtime_workflows'),'nonterminal-workflow-changed')
  }
}
function assertOnlyRows(previous,next,allowed,{allowHeadAdvance=false} = {}) {
  if (!allowHeadAdvance) check(same(previous.heads,next.heads),'typed-transition-head-change')
  for (const name of Object.keys(PRIVATE_CONTROL_TABLES)) {
    if (!allowed.has(name)) check(previous.tables[name].length === next.tables[name].length
      && previous.tables[name].every((row,index) => rowSame(row,next.tables[name][index],name)),'typed-transition-unrelated-table-change')
  }
}
function assertSingleChangedRow(previous,next,name,operation_id,{mayInsert=false} = {}) {
  const before = byKey(previous.tables[name],name), after = byKey(next.tables[name],name)
  const targetKey = canonicalJSON([operation_id])
  for (const [key,row] of before) if (key !== targetKey) check(rowSame(row,after.get(key),name),'typed-transition-unrelated-row-change')
  for (const [key,row] of after) if (key !== targetKey) check(before.has(key) && rowSame(before.get(key),row,name),
    'typed-transition-unrelated-row-insert')
  check(after.has(targetKey) && (before.has(targetKey) || mayInsert),'typed-transition-target-missing')
  return {before:before.get(targetKey),after:after.get(targetKey)}
}
function authorizedEffectRequest(body) {
  const {reference,operation} = body
  return {version:1,action_type:reference.action_type,owner_subject:reference.owner_subject,
    operation_id:reference.operation_id,operation_digest:reference.operation_digest,parameters:operation.canonical_parameters}
}
function assertBoundEffectIntent(row,body,contracts) {
  check(row && row.owner_subject === body.reference.owner_subject && row.operation_id === body.reference.operation_id
    && row.operation_digest === body.reference.operation_digest && row.request_id === body.request_id
    && row.request_digest === body.request_digest,'effect-intent-binding')
  const grant = parseOriginal(row.grant_bytes)
  try {contracts.validateContract('ConsumedGrant',grant)} catch {check(false,'effect-intent-grant-invalid')}
  check(grant.operation_id === body.reference.operation_id && grant.operation_digest === body.reference.operation_digest
    && grant.owner_id === body.reference.owner_id && grant.audience === body.operation.audience
    && grant.authorization_epoch === body.authorization_epoch
    && row.operation_bytes.equals(Buffer.from(canonicalJSON(body.operation)))
    && row.request_bytes.equals(Buffer.from(canonicalJSON(authorizedEffectRequest(body))))
    && row.grant_bytes.equals(Buffer.from(canonicalJSON(grant))),'effect-intent-bytes-or-grant-mismatch')
  return grant
}
function assertEffectWorkflow(previous,body) {
  const workflow = previous.tables.runtime_workflows.find(row => row.operation_id === body.reference.operation_id)
  check(workflow?.phase === 'attempted' && same(referenceOf(workflow),body.reference)
    && !['workflow_closure_progress','unsent_closures','effects','replay_fences'].some(name =>
      previous.tables[name].some(row => row.operation_id === body.reference.operation_id)),
    'effect-retained-attempted-required')
  check(same(previous.heads,body.operation.canonical_parameters.heads)
    && body.operation.expected_state_version === memoryStateVersion(previous.heads),'effect-reviewed-heads-mismatch')
  if (body.reference.action_type === 'memory.save') check(workflow.idempotency_key_sha256 !== null
    && workflow.idempotency_key_sha256 === body.operation.canonical_parameters.idempotency_key_sha256,
    'effect-original-save-key-mismatch')
  else check(workflow.idempotency_key_sha256 === null && workflow.record_id === body.operation.canonical_parameters.record_id,
    'effect-original-forget-target-mismatch')
  return workflow
}
function assertOnlyBoundSaveRequest(previous,next,workflow,body,result) {
  const before = byKey(previous.tables.requests,'requests'), after = byKey(next.tables.requests,'requests')
  for (const [key,row] of before) check(rowSame(row,after.get(key),'requests'),'effect-unrelated-request-changed')
  const inserted = [...after].filter(([key]) => !before.has(key)).map(([,row]) => row)
  check(inserted.length === 1,'effect-save-request-count')
  const row = inserted[0]
  check(sha256(Buffer.from(row.idempotency_key)) === workflow.idempotency_key_sha256
    && row.record_id === result.record_id && String(row.revision) === result.revision
    && row.request_digest === body.operation.canonical_parameters.capture_sha256,'effect-save-request-binding')
}
function assertOnlyBoundForgetTombstone(previous,next,body,result) {
  const before = byKey(previous.tables.tombstones,'tombstones'), after = byKey(next.tables.tombstones,'tombstones')
  for (const [key,row] of before) check(rowSame(row,after.get(key),'tombstones'),'effect-unrelated-tombstone-changed')
  const inserted = [...after].filter(([key]) => !before.has(key)).map(([,row]) => row)
  const id = body.operation.canonical_parameters.record_id, original = previous.tables.tombstones.find(row => row.record_id === id)
  check(Object.keys(result).length === 8 && ['record_id','state','canonical_payload_retained','physical_media_erasure',
    'authority_approval_history_erased','backups_erased','wal_erased','grants_authority'].every(key => Object.hasOwn(result,key))
    && result.record_id === id && result.state === 'tombstoned' && result.canonical_payload_retained === true
    && ['physical_media_erasure','authority_approval_history_erased','backups_erased','wal_erased','grants_authority']
      .every(key => result[key] === false)
    && inserted.length === (original ? 0 : 1),'effect-forget-tombstone-count-or-result')
  if (!original) {
    const row = inserted[0], tombstone = {kind:'tombstone',recordId:id,at:body.operation.canonical_parameters.at}
    const bytes = Buffer.from(canonicalJSON(tombstone)+'\n')
    check(row.record_id === id && row.bytes.equals(bytes) && row.sha256 === sha256(bytes),'effect-forget-tombstone-binding')
  }
  return Boolean(original)
}
function assertAuthorizedEffectDelta(previous,next,host,{profile,contracts,transition}) {
  const body = assertAuthorizedEffectTransition(transition,{host,profile,contracts}), operation_id = body.reference.operation_id
  const workflow = assertEffectWorkflow(previous,body)
  if (body.phase === 'intent') {
    assertOnlyRows(previous,next,new Set(['intents']))
    const rows = assertSingleChangedRow(previous,next,'intents',operation_id,{mayInsert:true})
    check(rows.before === undefined,'effect-intent-already-retained')
    assertBoundEffectIntent(rows.after,body,contracts)
    return
  }
  const intent = previous.tables.intents.find(row => row.operation_id === operation_id)
  const grant = assertBoundEffectIntent(intent,body,contracts)
  const allowed = new Set(['effects',body.reference.action_type === 'memory.save' ? 'requests' : 'tombstones'])
  assertOnlyRows(previous,next,allowed,{allowHeadAdvance:true})
  const rows = assertSingleChangedRow(previous,next,'effects',operation_id,{mayInsert:true})
  check(rows.before === undefined,'effect-already-retained')
  const effect = rows.after, result = parseOriginal(effect.result_bytes), receipt = parseOriginal(effect.receipt_bytes)
  check(effect.operation_id === operation_id && effect.operation_digest === body.reference.operation_digest && effect.grant_id === grant.grant_id
    && effect.action === body.reference.action_type && effect.request_id === body.request_id && effect.request_digest === body.request_digest
    && ['operation_bytes','grant_bytes','request_bytes'].every(column => effect[column].equals(intent[column]))
    && effect.result_bytes.equals(Buffer.from(canonicalJSON(result))) && effect.receipt_bytes.equals(Buffer.from(canonicalJSON(receipt)))
    && receipt.result_digest === memoryResultDigest(result) && same(receipt.result,result),'effect-applied-binding')
  const changedHeads = [...new Set([...Object.keys(previous.heads),...Object.keys(next.heads)])]
    .filter(domain => previous.heads[domain] !== next.heads[domain])
  if (body.reference.action_type === 'memory.save') {
    try {contracts.validateContract('MemoryRecord',result)} catch {check(false,'effect-save-result-invalid')}
    const record = validateOriginal(Buffer.from(result.canonical_bytes),body.reference.owner_subject)
    check(result.owner_subject === body.reference.owner_subject && result.task_id === body.reference.task_id
      && result.storage_status === 'saved' && result.grants_authority === false && result.chain_domain === 'remembered'
      && record.id === result.record_id && record.statement === body.operation.canonical_parameters.statement
      && record.record.attributedTo === body.operation.canonical_parameters.attributed_to
      && record.format === result.record_format && record.canon === result.canonicalizer && record.tier === 'remembered'
      && changedHeads.length === 1 && changedHeads[0] === 'remembered','effect-save-result-or-head-binding')
    assertOnlyBoundSaveRequest(previous,next,workflow,body,result)
  } else {
    const alreadyTombstoned = assertOnlyBoundForgetTombstone(previous,next,body,result)
    check(changedHeads.length === (alreadyTombstoned ? 0 : 1),'effect-forget-head-count')
  }
}
function restoreIntents(control) {
  return control.tables.intents.filter(row => parseOriginal(row.operation_bytes).action_type === 'memory.restore')
}
function unresolvedRestores(control) {
  return restoreIntents(control).filter(row => !control.tables.effects.some(effect => effect.operation_id === row.operation_id)
    && !control.tables.replay_fences.some(fence => fence.operation_id === row.operation_id))
}
function hasRestoreEdge(previous,next) {
  return unresolvedRestores(previous).length > 0 || restoreIntents(next)
    .some(row => !previous.tables.intents.some(old => old.operation_id === row.operation_id))
}
function restoreEdge(previous,next,checkpoint) {
  const inserted = restoreIntents(next).filter(row => !previous.tables.intents.some(old => old.operation_id === row.operation_id)
    && (checkpoint === undefined || parseOriginal(row.operation_bytes).canonical_parameters.retention_checkpoint_sha256 === checkpoint))
  const unresolved = unresolvedRestores(previous)
  check(unresolved.length <= 1,'restore-event-overlap')
  if (unresolved.length) return {phase:'applied',row:unresolved[0]}
  check(inserted.length <= 1,'restore-event-overlap')
  if (inserted.length) return {phase:'intent',row:inserted[0]}
  return null
}
function sameControlRows(actual,expected,{omitIntent,omitEffect} = {}) {
  if (!same(actual.heads,expected.heads) || !same(actual.logical_store,expected.logical_store)
    || !same(actual.closure_profile,expected.closure_profile)) return false
  return Object.keys(PRIVATE_CONTROL_TABLES).every(name => {
    const rows = actual.tables[name].filter(row => !(name === 'intents' && row.operation_id === omitIntent)
      && !(name === 'effects' && row.operation_id === omitEffect))
    return rows.length === expected.tables[name].length && rows.every((row,n) => rowSame(row,expected.tables[name][n],name))
  })
}
function restoreBody(event,lineage,host,{profile,contracts,transition}) {
  const operation = parseOriginal(event.row.operation_bytes)
  const factualHost = transition ? host : {owner_id:operation.owner_id,owner_subject:event.row.owner_subject,
    task_id:operation.task_id,authorization_epoch:operation.authorization_epoch}
  const inferred = {version:3,kind:'prime-memory-authorized-effect-transition/v3',
    memory_store_id:lineage.controls[0].closure_profile.expected_memory_store_id,reference:{owner_id:operation.owner_id,
      owner_subject:event.row.owner_subject,task_id:operation.task_id,operation_id:operation.operation_id,
      operation_digest:event.row.operation_digest,action_type:operation.action_type},
    authorization_epoch:operation.authorization_epoch,operation,request_id:event.row.request_id,
    request_digest:event.row.request_digest,phase:event.phase,expected_checkpoint_sha256:lineage.envelopes[0].checkpoint_sha256}
  const body = assertAuthorizedEffectTransition(transition ?? inferred,{host:factualHost,profile,contracts})
  check(body.reference.action_type === 'memory.restore' && same(body,inferred),'restore-event-transition-mismatch')
  return body
}
function assertRestoreResult(result,parameters) {
  check(result && typeof result === 'object' && !Array.isArray(result) && Object.keys(result).length === 5
    && ['state','manifest_sha256','heads','restored_records','grants_authority'].every(key => Object.hasOwn(result,key))
    && result.state === 'restored' && result.manifest_sha256 === parameters.manifest_sha256
    && same(result.heads,parameters.heads) && Number.isSafeInteger(result.restored_records)
    && result.restored_records >= 0 && result.restored_records <= 10000 && !Object.is(result.restored_records,-0)
    && result.grants_authority === false,'restore-effect-result-invalid')
}
// Only actual reprojections are accepted. Removing the one newly observed event
// row here is a comparison with archived state, never a projected SQL candidate.
function assertRestoreDecoded(previous,next,host,{profile,contracts,transition},lineage) {
  check(lineage && lineage.envelopes.length > 0,'restore-published-ancestry-required')
  const event = restoreEdge(previous,next,lineage.envelopes[0].checkpoint_sha256)
  check(event,'restore-event-missing')
  const body = restoreBody(event,lineage,host,{profile,contracts,transition})
  const parameters = assertRestoreEffectParameters(body.operation.canonical_parameters), operation_id = body.reference.operation_id
  const anchorIndex = lineage.envelopes.findIndex(envelope => envelope.checkpoint_sha256 === parameters.retention_checkpoint_sha256)
  check(anchorIndex >= 0,'restore-anchor-unpublished')
  const anchor = lineage.controls[anchorIndex], anchorEnvelope = lineage.envelopes[anchorIndex]
  check(anchor.digest === parameters.control_anchor_sha256 && anchorEnvelope.authorization_epoch === parameters.retention_epoch
    && parameters.retention_epoch === body.authorization_epoch && same(parameters.heads,anchor.heads)
    && same(parameters.retained_heads,anchor.heads),'restore-original-anchor-mismatch')
  check(Object.keys(PRIVATE_CONTROL_TABLES).every(name => !PRIVATE_CONTROL_TABLES[name].columns.includes('operation_id')
    || !anchor.tables[name].some(row => row.operation_id === operation_id)),'restore-operation-already-archived')
  const local = event.phase === 'intent' ? next : previous
  const ancestorIndex = lineage.controls.findIndex((control,n) => n >= anchorIndex
    && sameControlRows(local,control,{omitIntent:operation_id}))
  check(ancestorIndex >= anchorIndex,'restore-local-not-published-ancestor')
  const ancestor = lineage.controls[ancestorIndex]
  check(unresolvedRestores(ancestor).length === 0 && unresolvedRestores(anchor).length === 0
    && body.operation.expected_state_version === memoryStateVersion(ancestor.heads),'restore-reviewed-local-mismatch')
  const intent = local.tables.intents.find(row => row.operation_id === operation_id)
  const grant = assertBoundEffectIntent(intent,body,contracts)
  check(local.tables.intents.length === ancestor.tables.intents.length + 1
    && !local.tables.effects.some(row => row.operation_id === operation_id)
    && !local.tables.replay_fences.some(row => row.operation_id === operation_id),'restore-local-ledger-mismatch')
  if (event.phase === 'intent') {
    // The new archived edge is P -> I. Actual older SQL A is proven only by
    // stripping the sole observed X intent and matching this complete archive.
    check(anchorIndex === 0 && body.expected_checkpoint_sha256 === anchorEnvelope.checkpoint_sha256
      && previous.digest === anchor.digest && sameControlRows(previous,anchor),'restore-intent-predecessor-mismatch')
  } else {
    const intentEnvelope = lineage.envelopes[0]
    check(anchorIndex === 1 && sameControlRows(previous,lineage.controls[0])
      && body.expected_checkpoint_sha256 === intentEnvelope.checkpoint_sha256
      && intentEnvelope.previous_checkpoint_sha256 === anchorEnvelope.checkpoint_sha256
      && intentEnvelope.sequence === anchorEnvelope.sequence + 1,'restore-applied-predecessor-mismatch')
    check(sameControlRows(next,anchor,{omitIntent:operation_id,omitEffect:operation_id})
      && next.tables.intents.length === anchor.tables.intents.length + 1
      && next.tables.effects.length === anchor.tables.effects.length + 1,'restore-applied-anchor-mismatch')
    const retainedIntent = next.tables.intents.find(row => row.operation_id === operation_id)
    check(rowSame(intent,retainedIntent,'intents'),'restore-intent-changed')
    const effect = next.tables.effects.find(row => row.operation_id === operation_id)
    const result = effect && parseOriginal(effect.result_bytes), receipt = effect && parseOriginal(effect.receipt_bytes)
    check(effect && effect.operation_digest === body.reference.operation_digest && effect.grant_id === grant.grant_id
      && effect.action === 'memory.restore' && effect.request_id === body.request_id && effect.request_digest === body.request_digest
      && ['operation_bytes','grant_bytes','request_bytes'].every(column => effect[column].equals(intent[column]))
      && effect.result_bytes.equals(Buffer.from(canonicalJSON(result))) && effect.receipt_bytes.equals(Buffer.from(canonicalJSON(receipt)))
      && receipt.version === 1 && receipt.kind === 'prime-memory-effect/v1' && receipt.status === 'applied'
      && receipt.operation_id === operation_id && receipt.operation_digest === body.reference.operation_digest
      && receipt.grant_id === grant.grant_id && receipt.request_id === body.request_id && receipt.request_digest === body.request_digest
      && receipt.owner_subject === body.reference.owner_subject && receipt.action_type === 'memory.restore'
      && receipt.result_digest === memoryResultDigest(result) && same(receipt.result,result),'restore-applied-receipt-mismatch')
    assertRestoreResult(result,parameters)
  }
  return {next,body,phase:event.phase,anchor,ancestor,anchorEnvelope}
}
/** Content validation only. Compare published P -> actual I, then I -> actual E.
 * Actual older SQL A is proved from the sole observed intent and archived state.
 * The caller independently authenticates the COMPLETE P/I
 * predecessor envelopes and the actual owner client; this helper supplies neither
 * publication nor authorization. No caller-selected ancestor or permissive flag
 * replaces the exact archived comparison. */
export function assertRestoreEffectAdvance(previousBundle,nextBundle,host,{profile,contracts,transition,published_ancestry} = {}) {
  const lineage = validatePublishedLineage(published_ancestry,host,{profile,contracts})
  const previous = decodeControlV3(previousBundle,host,{profile,contracts}), next = decodeControlV3(nextBundle,host,{profile,contracts})
  return assertRestoreDecoded(previous,next,host,{profile,contracts,transition},lineage).next
}
function assertTypedDelta(previous,next,host,{profile,contracts,transition,restore_ancestry}) {
  const operation_id = transition?.reference?.operation_id
  if (transition.kind === 'prime-memory-authorized-effect-transition/v3') {
    assertAuthorizedEffectDelta(previous,next,host,{profile,contracts,transition})
  } else if (transition.kind === 'prime-runtime-unsent-journal-transition/v3') {
    const body = assertJournalTransition(transition,{host,profile,contracts})
    assertOnlyRows(previous,next,new Set(['runtime_workflows','workflow_closure_progress']))
    const progressRows = assertSingleChangedRow(previous,next,'workflow_closure_progress',operation_id,{mayInsert:body.previous_progress_digest === null})
    const workflowRows = assertSingleChangedRow(previous,next,'runtime_workflows',operation_id)
    check(progressRows.after.progress_digest === progressDigest(body.target_progress,{contracts})
      && same(parseOriginal(progressRows.after.progress_bytes),body.target_progress),'journal-target-mismatch')
    check(body.previous_progress_digest === null ? progressRows.before === undefined
      : progressRows.before?.progress_digest === body.previous_progress_digest,'journal-previous-cas-mismatch')
    check(workflowRows.before.idempotency_key_sha256 === body.idempotency_key_sha256
      && same(referenceOf(workflowRows.before),body.reference),'journal-original-reference-mismatch')
  } else if (transition.kind === 'prime-runtime-workflow-mutation/v3') {
    const body = assertWorkflowTransition(transition,{host,profile,contracts})
    assertOnlyRows(previous,next,new Set(['runtime_workflows']))
    const rows = assertSingleChangedRow(previous,next,'runtime_workflows',operation_id,{mayInsert:body.previous_workflow_digest === null})
    check(same(rows.after,body.target_workflow),'workflow-target-mismatch')
    check(body.previous_workflow_digest === null ? rows.before === undefined
      : rows.before && workflowRowDigest(rows.before,{contracts}) === body.previous_workflow_digest,'workflow-previous-cas-mismatch')
  } else if (transition.kind === 'prime-memory-negative-closure-transition/v3') {
    const body = assertNegativeTransition(transition,{host,profile})
    assertOnlyRows(previous,next,new Set(['unsent_closures']))
    const rows = assertSingleChangedRow(previous,next,'unsent_closures',operation_id,{mayInsert:true})
    check(same(parseOriginal(rows.after.closure_bytes),body.closure) && rows.after.closure_digest === body.closure_digest
      && same(parseOriginal(rows.after.reference_bytes),body.reference),'negative-target-mismatch')
    const progress = previous.tables.workflow_closure_progress.find(row => row.operation_id === operation_id)
    check(progress?.progress_digest === body.previous_progress_digest
      && parseOriginal(progress.progress_bytes).stage === 'authority_confirmed','negative-authority-stage-mismatch')
    if (rows.before) check(rowSame(rows.before,rows.after,'unsent_closures'),'negative-existing-marker-changed')
  } else if (transition.kind === 'prime-memory-control-restore-transition/v3') {
    assertRestoreTransition(transition,{host,profile})
    // The retained predecessor already is the independently current anchor. Restoring older
    // SQL to that same full anchor publishes an unchanged control through a new ordered purpose.
    if (previous.digest === next.digest) return
    // Shape/rank is never ancestry. The restore owner must pass the independently authenticated
    // COMPLETE published controls for this exact interval; each edge is checked recursively below.
    check(Array.isArray(restore_ancestry) && restore_ancestry.length >= 1,'restore-published-ancestry-required')
    let cursor = previous
    for (const control of restore_ancestry) {
      const checked = decodeControlV3(control,host,{profile,contracts})
      assertDecodedEdge(cursor,checked,host,{profile,contracts}); cursor = checked
    }
    check(cursor.digest === next.digest,'restore-ancestry-target-mismatch')
  } else check(false,'typed-transition-kind-invalid')
}
function assertDecodedEdge(previous,next,host,{profile,contracts}) {
  check(same(previous.logical_store,next.logical_store) && same(previous.closure_profile,next.closure_profile),'logical-identity-changed')
  assertMemoryControlAdvance(legacy(previous,host,contracts),legacy(next,host,contracts),host,{contracts})
  const oldClosures = byKey(previous.tables.unsent_closures,'unsent_closures'), newClosures = byKey(next.tables.unsent_closures,'unsent_closures')
  for (const [key,row] of oldClosures) check(rowSame(row,newClosures.get(key),'unsent_closures'),'closure-history-changed')
  const oldProgress = progressMap(previous.tables,{profile,contracts}), newProgress = progressMap(next.tables,{profile,contracts})
  const oldWorkflows = new Map(previous.tables.runtime_workflows.map(row => [row.operation_id,row]))
  const newWorkflows = new Map(next.tables.runtime_workflows.map(row => [row.operation_id,row]))
  for (const [operation_id,row] of oldWorkflows) {
    const retained = newWorkflows.get(operation_id); check(retained,'workflow-history-removed')
    assertWorkflowEdge(row,retained,oldProgress.get(operation_id),newProgress.get(operation_id))
  }
  for (const [operation_id,row] of newWorkflows) if (!oldWorkflows.has(operation_id)) {
    check(row.phase === 'proposed' && !newProgress.has(operation_id)
      && !['intents','effects','replay_fences','unsent_closures'].some(name => previous.tables[name].some(item => item.operation_id === operation_id)),
      'registration-not-pre-work')
  }
  for (const [operation_id,item] of oldProgress) {
    const retained = newProgress.get(operation_id); check(retained,'progress-history-removed'); assertProgressEdge(item,retained,contracts)
  }
  for (const [operation_id,item] of newProgress) if (!oldProgress.has(operation_id)) {
    const workflow = oldWorkflows.get(operation_id)
    check(item.progress.stage === 'started' && workflow?.phase === 'attempted'
      && rowSame(workflow,newWorkflows.get(operation_id),'runtime_workflows'),'started-without-retained-attempted')
  }
  for (const [key,row] of newClosures) if (!oldClosures.has(key)) {
    const marker = parseOriginal(row.closure_bytes)
    check(marker.version === 2 && oldProgress.get(row.operation_id)?.progress.stage === 'authority_confirmed'
      && newProgress.get(row.operation_id)?.progress.stage === 'authority_confirmed'
      && rowSame(oldProgress.get(row.operation_id).row,newProgress.get(row.operation_id).row,'workflow_closure_progress'),
      'new-marker-without-retained-authority')
  }
}
/** Verify one actual full control edge. It proves continuity grammar, never publication or authority.
 * Restore callers must verify EVERY protected committed predecessor edge before accepting endpoint state.
 */
export function assertForwardControlV3(previousBundle,nextBundle,host,{profile,contracts,transition,restore_ancestry,published_ancestry} = {}) {
  const previous = decodeControlV3(previousBundle,host,{profile,contracts}), next = decodeControlV3(nextBundle,host,{profile,contracts})
  if (transition !== undefined) transition = detachPrivateData(transition)
  if (transition?.operation?.action_type === 'memory.restore' || hasRestoreEdge(previous,next))
    return assertRestoreEffectAdvance(previousBundle,nextBundle,host,{profile,contracts,transition,published_ancestry})
  if (transition?.kind === 'prime-memory-control-restore-transition/v3') {
    assertTypedDelta(previous,next,host,{profile,contracts,transition,restore_ancestry}); return next
  }
  assertDecodedEdge(previous,next,host,{profile,contracts})
  if (transition) assertTypedDelta(previous,next,host,{profile,contracts,transition})
  return next
}
export const assertMemoryControlAdvanceV3 = assertForwardControlV3

/** Content-only full-lineage verifier. A caller must independently authenticate this as the
 * actual PUBLISHED current predecessor chain; this helper cannot qualify an orphan generation.
 * Input is complete newest-first, ending at the original marker-free sequence-one baseline.
 */
function validatePublishedLineage(input,host,{profile,contracts} = {}) {
  const currentHost = assertPrivateHost(host)
  check(Array.isArray(input) && !types.isProxy(input) && Object.getPrototypeOf(input) === Array.prototype
    && input.length > 0 && input.length <= 10000,'lineage-array-invalid')
  const descriptors = Object.getOwnPropertyDescriptors(input)
  check(Reflect.ownKeys(descriptors).every(key => typeof key === 'string'
    && (key === 'length' || /^(?:0|[1-9][0-9]*)$/.test(key) && Number(key) < input.length))
    && Reflect.ownKeys(descriptors).length === input.length + 1 && Object.keys(input).length === input.length,
    'lineage-array-inert-required')
  const controls = [], envelopes = [], seen = new Set(); let bytes = 0
  for (let index = 0; index < input.length; index++) {
    const descriptor = descriptors[String(index)]
    check(descriptor && Object.hasOwn(descriptor,'value') && descriptor.enumerable,'lineage-array-inert-required')
    const envelope = detachPrivateData(descriptor.value)
    check(Object.keys(envelope).length === 8 && ['schema','owner_id','owner_subject','authorization_epoch','sequence',
      'previous_checkpoint_sha256','control_state','checkpoint_sha256'].every(key => Object.hasOwn(envelope,key)),'lineage-envelope-fields')
    const {checkpoint_sha256,...body} = envelope
    check(envelope.schema === 'aukora-prime-memory-retention/v2' && envelope.owner_id === currentHost.owner_id
      && envelope.owner_subject === currentHost.owner_subject && Number.isSafeInteger(envelope.authorization_epoch)
      && envelope.authorization_epoch >= 0 && envelope.authorization_epoch <= currentHost.authorization_epoch
      && (index !== 0 || envelope.authorization_epoch === currentHost.authorization_epoch)
      && Number.isSafeInteger(envelope.sequence) && envelope.sequence >= 1
      && typeof checkpoint_sha256 === 'string' && /^[0-9a-f]{64}$/.test(checkpoint_sha256)
      && (envelope.previous_checkpoint_sha256 === null || typeof envelope.previous_checkpoint_sha256 === 'string'
        && /^[0-9a-f]{64}$/.test(envelope.previous_checkpoint_sha256))
      && (envelope.sequence === 1) === (envelope.previous_checkpoint_sha256 === null)
      && checkpoint_sha256 === sha256(Buffer.from('aukora-prime.memory-retention.v2\0'+canonicalJSON(body)))
      && !seen.has(checkpoint_sha256),'lineage-envelope-invalid')
    seen.add(checkpoint_sha256)
    bytes += Buffer.byteLength(canonicalJSON(envelope))
    check(bytes <= MAX_BYTES,'lineage-byte-limit')
    controls.push(decodeControlV3(envelope.control_state,currentHost,{profile,contracts})); envelopes.push(envelope)
    if (index > 0) {
      const successor = envelopes[index-1]
      check(successor.sequence === envelope.sequence + 1 && successor.previous_checkpoint_sha256 === checkpoint_sha256
        && successor.authorization_epoch >= envelope.authorization_epoch,
        'lineage-predecessor-mismatch')
    }
  }
  check(envelopes.at(-1).sequence === 1 && envelopes.at(-1).previous_checkpoint_sha256 === null,'lineage-baseline-missing')
  check(Object.keys(controls.at(-1).heads).length === 0
    && Object.keys(PRIVATE_CONTROL_TABLES).every(name => controls.at(-1).tables[name].length === 0),
    'lineage-original-pre-work-baseline-missing')
  // Validate oldest to newest. The internal predecessor view contains only
  // already-checked published edges; no caller flag can substitute for it.
  for (let index = controls.length - 2; index >= 0; index--) {
    const previous = controls[index+1], next = controls[index]
    let restore = null
    if (hasRestoreEdge(previous,next)) restore = assertRestoreDecoded(previous,next,currentHost,{profile,contracts},
      {envelopes:envelopes.slice(index+1),controls:controls.slice(index+1)})
    else assertDecodedEdge(previous,next,currentHost,{profile,contracts})
    if (restore) check(restore.body.authorization_epoch === envelopes[index].authorization_epoch,
      'lineage-restore-event-epoch-mismatch')
    const previousProgress = new Map(previous.tables.workflow_closure_progress.map(row => [row.operation_id,row]))
    const archived = restore && (restore.phase === 'intent' ? restore.ancestor : restore.anchor)
    for (const row of next.tables.workflow_closure_progress) {
      const old = previousProgress.get(row.operation_id)
      if (old && old.progress_digest === row.progress_digest) continue
      const original = archived?.tables.workflow_closure_progress.find(item => item.operation_id === row.operation_id)
      if (original && rowSame(row,original,'workflow_closure_progress')) continue
      check(parseOriginal(row.progress_bytes).closing_authorization_epoch === envelopes[index].authorization_epoch,
        'lineage-stage-closing-epoch-mismatch')
    }
  }
  const proofs = new Map(), originalByOperation = new Map()
  // An unresolved restore I may contain an older SQL ancestor. Original
  // closure A evidence remains on its protected P predecessor chain.
  for (const control of controls) for (const row of control.tables.unsent_closures) {
    if (parseOriginal(row.closure_bytes).version !== 2) continue
    const existing = originalByOperation.get(row.operation_id)
    check(!existing || rowSame(existing,row,'unsent_closures'),'lineage-marker-bytes-changed')
    originalByOperation.set(row.operation_id,row)
  }
  const originalRows = [...originalByOperation.values()]
  for (const row of originalRows) {
    const marker = parseOriginal(row.closure_bytes)
    let first = -1
    // The greatest index is the earliest committed occurrence on this current-head chain.
    for (let index = 0; index < controls.length; index++) {
      const retained = controls[index].tables.unsent_closures.find(item => item.operation_id === row.operation_id)
      if (retained) {
        check(rowSame(row,retained,'unsent_closures'),'lineage-marker-bytes-changed'); first = index
      }
    }
    check(first >= 0 && first + 1 < controls.length
      && !controls[first+1].tables.unsent_closures.some(item => item.operation_id === row.operation_id),
      'lineage-first-marker-predecessor-absence-missing')
    const checkpoint = envelopes[first], firstProgressRow = controls[first].tables.workflow_closure_progress.find(item => item.operation_id === row.operation_id)
    const firstProgress = firstProgressRow && parseOriginal(firstProgressRow.progress_bytes)
    check(checkpoint.authorization_epoch === marker.authorization_epoch && firstProgress?.stage === 'authority_confirmed'
      && firstProgress.memory === null && firstProgress.closing_authorization_epoch === marker.authorization_epoch
      && controls[first].tables.runtime_workflows.find(item => item.operation_id === row.operation_id)?.phase === 'attempted',
      'lineage-first-marker-stage-or-epoch-mismatch')
    const completion = {version:2,kind:'prime-memory-writer-completion/v2',store_id:marker.store_id,
      closure_digest:row.closure_digest,retention:{version:2,kind:'prime-memory-writer-retention/v2',
        checkpoint_sha256:checkpoint.checkpoint_sha256,control_sha256:checkpoint.control_state.control_sha256,
        authorization_epoch:marker.authorization_epoch}}
    const proof = {closure:marker,closure_digest:row.closure_digest,completion,completion_digest:writerCompletionV2Digest(completion)}
    proofs.set(row.operation_id,proof)
  }
  for (const control of controls) for (const row of control.tables.workflow_closure_progress) {
    const progress = parseOriginal(row.progress_bytes)
    if (progress.memory === null) continue
    const proof = proofs.get(row.operation_id)
    check(proof && same(progress.memory,proof) && progress.closing_authorization_epoch === proof.closure.authorization_epoch,
      'lineage-original-completion-mismatch')
  }
  return {envelopes,controls,proofs}
}
export function assertLineageCompletionsV2(input,host,options = {}) {
  return validatePublishedLineage(input,host,options).proofs
}
