// SPDX-License-Identifier: AGPL-3.0-or-later
// Local source adapter for D's existing exact pending recovery. No new ledger,
// caller-selected identity, SQL replay, original effect retry or public route.
import {types} from 'node:util'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {closedClosureData,validateClosureHost,validateClosureProfile,validateClosureReference,
  validateNormalTransition,normalTransitionDigest,validateJournalTransition,journalTransitionDigest,
  validateClosureProgress} from './closure-v2.mjs'

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const DIGEST=/^sha256:[a-f0-9]{64}$/
const HEX=/^[a-f0-9]{64}$/
const MARKER_FIELDS=['schema','owner_id','owner_subject','authorization_epoch','transition_id','transition',
  'transition_digest','prepared_checkpoint_sha256','prepared_generation_file']
// Ephemeral error context only. A serialized field cannot brand a reference,
// and this map carries no permission, closure proof or retained journal state.
const errorReferences=new WeakMap()
const fail=reason=>{throw Object.assign(new Error(reason),{error_code:'OUTCOME_UNKNOWN',
  reconciliation_required:true,automatic_retry:false})}
function own(object,key) {
  if(!object||typeof object!=='object'||types.isProxy(object)
    ||![Object.prototype,null].includes(Object.getPrototypeOf(object)))fail('RETAINED_PENDING_SOURCE_REQUIRED')
  const descriptor=Object.getOwnPropertyDescriptor(object,key)
  if(!descriptor||!Object.hasOwn(descriptor,'value')||!descriptor.enumerable)fail('RETAINED_PENDING_SOURCE_REQUIRED')
  return descriptor.value
}
const method=(object,key)=>{const value=own(object,key);if(typeof value!=='function')fail('RETAINED_PENDING_SOURCE_REQUIRED');return value.bind(object)}

/** Pure binding checks only; this is not a protected-reader or custody proof. */
export function validateRetainedPendingMarker(input,inputHost,inputProfile,operationId=null) {
  const host=validateClosureHost(inputHost),profile=validateClosureProfile(inputProfile)
  const marker=closedClosureData(input,MARKER_FIELDS)
  if(marker.owner_id!==host.owner_id||marker.owner_subject!==host.owner_subject
    ||marker.authorization_epoch!==host.authorization_epoch||typeof marker.transition_id!=='string'
    ||!UUID.test(marker.transition_id)||typeof marker.prepared_checkpoint_sha256!=='string'
    ||!HEX.test(marker.prepared_checkpoint_sha256)||typeof marker.prepared_generation_file!=='string'
    ||!marker.prepared_generation_file.endsWith('.'+marker.prepared_checkpoint_sha256+'.json'))
    fail('RETAINED_PENDING_OWNER_OR_PREPARATION_CHANGED')
  if(!marker.transition||typeof marker.transition!=='object')fail('RETAINED_PENDING_PURPOSE_UNSUPPORTED')
  let transition,digest
  if(marker.transition.kind==='prime-runtime-unsent-journal-transition/v3') {
    if(marker.schema!=='aukora-prime-memory-retention-journal-pending/v3')fail('RETAINED_PENDING_PURPOSE_CHANGED')
    transition=validateJournalTransition(marker.transition,profile)
    validateClosureProgress(transition.target_progress,profile,host)
    digest=journalTransitionDigest(transition)
  } else if(marker.transition.kind==='prime-runtime-workflow-mutation/v3') {
    if(marker.schema!=='aukora-prime-memory-retention-workflow-pending/v3')fail('RETAINED_PENDING_PURPOSE_CHANGED')
    transition=validateNormalTransition(marker.transition,profile)
    digest=normalTransitionDigest(transition)
  } else fail('RETAINED_PENDING_PURPOSE_UNSUPPORTED')
  const reference=validateClosureReference(transition.reference,host)
  if(marker.transition_digest!==digest||operationId!==null&&reference.operation_id!==operationId)
    fail('RETAINED_PENDING_ORIGINAL_IDENTITY_CHANGED')
  return closedClosureData({host,reference,transition_kind:transition.kind,
    transition_id:marker.transition_id,transition_digest:digest},
    ['host','reference','transition_kind','transition_id','transition_digest'])
}

// Snapshot the actual local participant before the public memory facade is
// narrowed. Missing source is no evidence of pending absence: census still
// independently refuses it. These captured functions are never guest inputs.
export function captureRetainedPendingRecovery(memory,inputProfile) {
  if(!memory||types.isProxy(memory)||!Object.hasOwn(memory,'participant'))return null
  const participant=own(memory,'participant'),coordinator=own(participant,'coordinator'),reader=own(coordinator,'reader')
  const profile=validateClosureProfile(inputProfile)
  const inspect=method(reader,'inspectPending'),journal=method(participant,'recoverJournal'),normal=method(participant,'recoverRetainedPurpose')
  return async(inputHost,operationId=null)=>{
    const host=validateClosureHost(inputHost)
    // Genuine brands belong to the assembled Prime D modules. A generic proxy,
    // Boolean verifier or copied shape cannot register itself as a participant.
    const [p,c,r]=await Promise.all([import('../../memory/src/private-v2-participant.mjs'),
      import('../../memory/src/private-v2-coordinator.mjs'),import('../../memory/src/private-v2-retention.mjs')])
    if(!p.isPrivateV2Participant(participant)||!c.isPrivateV2Coordinator(coordinator)
      ||!r.isPrivateV2FileRetentionReader(reader)||canonicalJson(own(participant,'profile'))!==canonicalJson(profile)
      ||canonicalJson(own(coordinator,'profile'))!==canonicalJson(profile))fail('RETAINED_PENDING_GENUINE_D_SOURCE_REQUIRED')
    let observed
    try {observed=await inspect(host)}
    catch(error){if(error?.code==='memory:private-v2-retention-pending-missing')return;throw error}
    // D has already authenticated the full candidate/predecessor/current bytes.
    // Do not copy those potentially large projections or interpret their SQL.
    const marker=own(observed,'marker'),prepared=own(observed,'prepared')
    const identity=validateRetainedPendingMarker(marker,host,profile,operationId)
    if(prepared===null||own(prepared,'checkpoint_sha256')!==marker.prepared_checkpoint_sha256)
      fail('RETAINED_PENDING_PREPARED_CANDIDATE_REQUIRED')
    const request={transition_id:identity.transition_id,transition_digest:identity.transition_digest}
    try {
      const result=identity.transition_kind==='prime-runtime-unsent-journal-transition/v3'
        ?await journal({host,...request}):await normal(host,request)
      const {checkpoint}=closedClosureData(result,['checkpoint'])
      closedClosureData(checkpoint,['checkpoint_sha256','control_sha256','authorization_epoch'])
      if(checkpoint.checkpoint_sha256!==marker.prepared_checkpoint_sha256
        ||typeof checkpoint.control_sha256!=='string'||!HEX.test(checkpoint.control_sha256)
        ||checkpoint.authorization_epoch!==host.authorization_epoch)fail('RETAINED_PENDING_RECOVERY_CHECKPOINT_CHANGED')
    } catch(error) {
      const failure=Object.assign(new Error('RETAINED_PENDING_RECOVERY_UNRESOLVED'),{error_code:'OUTCOME_UNKNOWN',
        reconciliation_required:true,automatic_retry:false,...request,operation_id:identity.reference.operation_id,
        operation_digest:identity.reference.operation_digest,cause:error})
      errorReferences.set(failure,identity.reference)
      throw failure
    }
    // The caller must now obtain a NEW factual census. This private reference
    // only binds a later unknown reply; it supplies no admission/effect evidence
    // and adds no pending tuple to the existing wire schema.
    return identity.reference
  }
}

/** Preserve only bounded content-free diagnostic identity on private errors. */
export function retainedUnknown(error,request=null) {
  const result=Object.assign(new Error('RETAINED_WORKFLOW_UNRESOLVED'),{error_code:'OUTCOME_UNKNOWN',
    reconciliation_required:true,automatic_retry:false,cause:error})
  for(const key of ['transition_id','transition_digest','retention_transition_id','retention_transition_digest',
    'operation_id','operation_digest','retention_phase']) {
    const descriptor=error&&typeof error==='object'&&!types.isProxy(error)?Object.getOwnPropertyDescriptor(error,key):null
    const value=descriptor&&Object.hasOwn(descriptor,'value')?descriptor.value:null
    if(typeof value!=='string')continue
    const valid=key==='retention_phase'?['intent','applied'].includes(value)
      :key.endsWith('_id')&&key!=='operation_id'?UUID.test(value)
      :key.endsWith('_digest')?DIGEST.test(value)
      :value.length>0&&Buffer.byteLength(value)<=1024&&!/[\x00-\x1f\x7f]/u.test(value)
    if(!valid)continue
    result[key]=value
  }
  if(request)Object.assign(result,{transition_id:request.transition_id,transition_digest:request.transition_digest,
    operation_id:request.transition.reference.operation_id,operation_digest:request.transition.reference.operation_digest})
  const reference=request?validateClosureReference(request.transition.reference):errorReferences.get(error)
  if(reference)errorReferences.set(result,reference)
  return result
}
export const retainedUnknownReference=error=>errorReferences.get(error)??null
