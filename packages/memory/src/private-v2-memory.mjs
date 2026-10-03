// SPDX-License-Identifier: AGPL-3.0-or-later
// Trusted local worker composition only. This module adds no guest routes.
import { randomUUID } from 'node:crypto'
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MemoryRefusal, parseOriginal, requireMemory } from './codecs.mjs'
import { createMemoryOwnerSerializer } from './owner-serialization.mjs'
import { createPrivateV2Participant } from './private-v2-participant.mjs'
import { createPostgresMemory } from './index.mjs'
import { createPrivateV2RecordAccess } from './private-v2-records.mjs'
import { createPrivateV2Restore } from './private-v2-restore.mjs'
import { isPrivateV2Coordinator, privateV2Checkpoint, privateV2Fields } from './private-v2-coordinator.mjs'
import { assertPrivateProfile, assertPrivateHost, assertClosureReference, assertWriterClosureV2,
  assertLineageCompletionsV2, writerClosureV2Digest, decodeControlV3,
  detachPrivateData, negativeTransitionDigest, PRIVATE_REFERENCE_FIELDS } from './private-v2-control.mjs'

const check = (ok, code) => requireMemory(ok, 'memory:private-v2-' + code)
const same = (a,b) => canonicalJSON(a) === canonicalJSON(b)
const ownReference = row => Object.fromEntries(PRIVATE_REFERENCE_FIELDS.map(key => [key,row[key]]))
const closureRow = (host, reference, closure) => ({owner_subject:host.owner_subject, owner_id:host.owner_id,
  task_id:host.task_id, operation_id:reference.operation_id, operation_digest:reference.operation_digest,
  action_type:reference.action_type, authorization_epoch:host.authorization_epoch,
  reference_bytes:Buffer.from(canonicalJSON(reference)), closure_bytes:Buffer.from(canonicalJSON(closure)),
  closure_digest:writerClosureV2Digest(closure)})

function unknown(error, reference) {
  const refusal = new MemoryRefusal('memory:writer-closure-outcome-unknown')
  refusal.cause = error; refusal.cause_code = error?.cause_code ?? error?.code ?? 'memory:store-unavailable'
  refusal.reconciliation_required = true; refusal.automatic_retry = false
  if (reference) {refusal.operation_id=reference.operation_id; refusal.operation_digest=reference.operation_digest}
  for(const key of ['transition_id','transition_digest','retention_transition_id','retention_transition_digest','retention_phase']) {
    const descriptor=error && Object.getOwnPropertyDescriptor(error,key)
    if(descriptor && Object.hasOwn(descriptor,'value') && typeof descriptor.value==='string')refusal[key]=descriptor.value
  }
  return refusal
}

/** Explicit trusted worker source composition. Construction supplies no host
 * qualification, provisioning or guest route. Every actual call still requires
 * the native guards and independently protected full-entry v3 current evidence.
 * H must leave this unreachable until the configured host is independently qualified.
 */
export function createPrivateV2Memory(input) {
  // Preserve refusal of the older five-field unqualified skeleton configuration.
  if(input && !types.isProxy(input) && !Object.hasOwn(input,'authority')) {
    privateV2Fields(input,['pool','coordinator','profile','contracts','statements'],'memory-configuration-required')
    throw new MemoryRefusal('memory:private-v2-host-qualification-unavailable')
  }
  const configurationKeys=['pool','coordinator','profile','contracts','statements','authority']
  if(input && !types.isProxy(input) && Object.hasOwn(input,'journalRestore')) configurationKeys.push('journalRestore')
  const configured=privateV2Fields(input,configurationKeys,
    'memory-configuration-required')
  if(Object.hasOwn(configured,'journalRestore')) check(typeof configured.journalRestore==='function'
    && !types.isProxy(configured.journalRestore),'restore-journal-source-required')
  const authority=configured.authority
  check(authority && typeof authority==='object' && !types.isProxy(authority),'retained-authority-unavailable')
  const ds=Object.getOwnPropertyDescriptors(authority), required=['reserveRetained','claimDispatchRetained','settleMemoryRetained']
  check(required.every(key=>ds[key] && Object.hasOwn(ds[key],'value') && typeof ds[key].value==='function'),
    'retained-authority-unavailable')
  const captured=Object.fromEntries(required.map(key=>[key,ds[key].value.bind(authority)]))
  if(ds.markOutcomeUnknown) {
    check(Object.hasOwn(ds.markOutcomeUnknown,'value') && typeof ds.markOutcomeUnknown.value==='function','retained-authority-unavailable')
    captured.markOutcomeUnknown=ds.markOutcomeUnknown.value.bind(authority)
  }
  const serializer=createMemoryOwnerSerializer({pool:configured.pool})
  const closure=buildClosureParticipant(Object.fromEntries(['pool','coordinator','profile','contracts','statements']
    .map(key=>[key,configured[key]])),serializer)
  const records=createPrivateV2RecordAccess({})
  const cold=createPrivateV2Restore({participant:closure.participant,reader:configured.coordinator.reader,
    profile:closure.participant.profile,contracts:closure.participant.contracts,records,
    ...(Object.hasOwn(configured,'journalRestore')?{journalRestore:configured.journalRestore}:{})})
  const effects=createPostgresMemory({pool:configured.pool,authority:Object.freeze(captured),contracts:closure.participant.contracts,
    privateV2:Object.freeze({coordinator:configured.coordinator,profile:closure.participant.profile,serializer,
      ...(Object.hasOwn(configured,'journalRestore')?{restoreSource:cold}:{})})})
  return Object.freeze({...closure,...cold,...effects,
    controlRetentionStatus:()=>Object.freeze({configured:true,kind:'private-v2-source-composition',qualified_runtime:false})})
}

/** Unmounted source-owned closure participant, for the reviewed private H composition.
 * It neither migrates nor provisions a baseline, and supplies no qualification capability.
 * H must keep it unreachable until the independent host qualification join is adopted.
 */
export function createPrivateV2ClosureParticipant(input) {
  return buildClosureParticipant(input,null)
}
function buildClosureParticipant(input,sharedSerializer) {
  const {pool, coordinator, profile: configured, contracts: suppliedContracts, statements} = privateV2Fields(input,
    ['pool','coordinator','profile','contracts','statements'],'memory-configuration-required')
  const profile = Object.freeze(assertPrivateProfile(configured))
  check(isPrivateV2Coordinator(coordinator) && same(coordinator.profile,profile),'owned-v2-coordinator-required')
  const serializer = sharedSerializer ?? createMemoryOwnerSerializer({pool})
  const participant = createPrivateV2Participant({pool,serializer,coordinator,profile,contracts:suppliedContracts,statements})
  const contracts=participant.contracts

  function checked(hostInput, referenceInput) {
    const host=assertPrivateHost(hostInput), reference=assertClosureReference(referenceInput,host)
    return {host,reference}
  }
  function facts(control, host, reference, {needClosure=false}={}) {
    const decoded=decodeControlV3(control,host,{profile,contracts})
    const workflow=decoded.tables.runtime_workflows.find(row=>row.operation_id===reference.operation_id)
    check(workflow && same(ownReference(workflow),reference),'closure-workflow-mismatch')
    const progressRow=decoded.tables.workflow_closure_progress.find(row=>row.operation_id===reference.operation_id)
    check(progressRow,'closure-progress-missing')
    const progress=parseOriginal(progressRow.progress_bytes)
    check(same(progress.reference,reference) && progress.closing_authorization_epoch===host.authorization_epoch
      && progress.expected_authority_store_id===profile.expected_authority_store_id
      && progress.expected_memory_store_id===profile.expected_memory_store_id
      && progress.idempotency_key_sha256===workflow.idempotency_key_sha256,'closure-progress-binding')
    check(progress.stage!=='started' && progress.authority!==null,'closure-authority-not-retained')
    check(workflow.phase==='attempted' || (workflow.phase==='known_unsent' && progress.stage==='complete'),
      'closure-workflow-ineligible')
    for (const name of ['intents','effects','replay_fences']) check(!decoded.tables[name].some(
      row=>row.operation_id===reference.operation_id),'writer-closure-durable-operation-present')
    const row=decoded.tables.unsent_closures.find(row=>row.operation_id===reference.operation_id)
    if (needClosure) check(row,'closure-not-committed')
    let closure=null
    if (row) {
      closure=assertWriterClosureV2(parseOriginal(row.closure_bytes),{host,reference,profile})
      const expected=closureRow(host,reference,closure)
      check(Object.keys(row).length===Object.keys(expected).length && Object.keys(expected).every(key=>
        key.endsWith('_bytes') ? Buffer.from(row[key]).equals(expected[key]) : row[key]===expected[key]),
      'closure-row-binding')
    }
    return {decoded,workflow,progress,progressRow,row,closure}
  }

  // The lineage capability starts at the protected published pointer. A prepared
  // generation that is not reachable from that pointer cannot establish first A.
  async function completionFor(host,reference,control) {
    const current=facts(control,host,reference,{needClosure:true}), digest=writerClosureV2Digest(current.closure)
    const lineage=await coordinator.reader.readPublishedLineage(host,{checkpoint_sha256:null})
    check(Array.isArray(lineage) && lineage.length>1 && same(lineage[0].control_state,control),
      'closure-published-lineage-unavailable')
    const proof=assertLineageCompletionsV2(lineage,host,{profile,contracts}).get(reference.operation_id)
    check(proof && same(proof.closure,current.closure) && proof.closure_digest===digest,
      'closure-original-completion-conflict')
    return proof
  }

  async function readUnsentClosure(hostInput,referenceInput) {
    const {host,reference}=checked(hostInput,referenceInput)
    try {
      return await participant.withVerifiedControl(host,async(_client,control)=>({status:'closed-unsent',
        ...await completionFor(host,reference,control),idempotent:true,grants_authority:false}))
    } catch(error) {throw unknown(error,reference)}
  }

  async function closeUnsentOperation(hostInput,referenceInput) {
    const {host,reference}=checked(hostInput,referenceInput)
    let started=false
    try {
      let pending
      try {pending=await coordinator.reader.inspectPending(host)}
      catch(error) {if(error.code!=='memory:private-v2-retention-pending-missing')throw error}
      if(pending) {
        const marker=pending.marker ?? pending
        check(marker.transition?.kind==='prime-memory-negative-closure-transition/v3'
          && same(marker.transition.reference,reference),'closure-other-purpose-pending')
        started=true
        if(marker.prepared_checkpoint_sha256!==null) {
          await participant.recoverRetainedPurpose(host,{transition_id:marker.transition_id,
            transition_digest:marker.transition_digest})
          return await readUnsentClosure(host,reference)
        }
        // A predecessor-only pending does not prove a committed candidate. Keep
        // it unresolved; explicit recovery never reapplies SQL or makes a new A.
        check(false,'closure-prepared-candidate-missing')
      }
      const prepared=await participant.withVerifiedControl(host,async(_client,control,envelope)=>{
        const observed=facts(control,host,reference)
        if(observed.row)return null
        check(observed.progress.stage==='authority_confirmed' && observed.progress.memory===null,
          'closure-wrong-stage')
        const closure=assertWriterClosureV2({version:2,kind:'prime-memory-writer-closure/v2',
          store_id:profile.expected_memory_store_id,...reference,authorization_epoch:host.authorization_epoch,
          closure_id:randomUUID(),writer_closed:true,intent_absent:true,effect_absent:true,grants_authority:false},
        {host,reference,profile})
        const transition={version:3,kind:'prime-memory-negative-closure-transition/v3',
          memory_store_id:profile.expected_memory_store_id,reference,
          expected_checkpoint_sha256:envelope.checkpoint_sha256,
          previous_progress_digest:observed.progressRow.progress_digest,closure,closure_digest:writerClosureV2Digest(closure)}
        return {transition_id:randomUUID(),transition,transition_digest:negativeTransitionDigest(transition)}
      })
      if(prepared===null)return await readUnsentClosure(host,reference)
      started=true
      await insertClosure(host,reference,prepared)
      return {...await readUnsentClosure(host,reference),idempotent:false}
    } catch(error) {if(started)throw unknown(error,reference); throw error}
  }

  async function insertClosure(host,reference,request) {
    await participant.runRetainedPurpose(host,request,async(client,transition,control)=>{
      const observed=facts(control,host,reference)
      check(!observed.row && observed.progress.stage==='authority_confirmed'
        && observed.progressRow.progress_digest===transition.previous_progress_digest,'closure-stage-changed')
      const row=closureRow(host,reference,assertWriterClosureV2(transition.closure,{host,reference,profile}))
      const columns=Object.keys(row)
      await client.query('INSERT INTO prime_memory_unsent_closures('+columns.join(',')+') VALUES('
        +columns.map((_,i)=>'$'+(i+1)).join(',')+')',columns.map(key=>row[key]))
    })
  }

  async function readRetainedWorkflowJournal(hostInput,inputRequest) {
    const host=assertPrivateHost(hostInput), {reference:inputReference}=privateV2Fields(inputRequest,['reference'],'read-fields')
    const reference=inputReference===null ? null : assertClosureReference(inputReference,host)
    try {
      return await participant.withVerifiedControl(host,async(_client,control,envelope)=>{
        const data=decodeControlV3(control,host,{profile,contracts})
        const workflows=[...data.tables.runtime_workflows].sort((a,b)=>
          Buffer.compare(Buffer.from(a.task_id),Buffer.from(b.task_id)) || Buffer.compare(Buffer.from(a.operation_id),Buffer.from(b.operation_id)))
        const progressMap=new Map(data.tables.workflow_closure_progress.map(row=>[row.operation_id,
          {progress:parseOriginal(row.progress_bytes),progress_digest:row.progress_digest}]))
        const checkpoint=privateV2Checkpoint(envelope)
        if(reference===null)return detachPrivateData({workflow_references:workflows,
          closure_progress:workflows.filter(row=>progressMap.has(row.operation_id)).map(row=>progressMap.get(row.operation_id)),checkpoint})
        const row=workflows.find(item=>item.operation_id===reference.operation_id)
        check(row && same(ownReference(row),reference),'journal-reference-missing')
        const progress=progressMap.get(row.operation_id) ?? {progress:null,progress_digest:null}
        return detachPrivateData({workflow_reference:row,...progress,checkpoint})
      })
    } catch(error) {throw unknown(error,reference)}
  }

  return Object.freeze({closeUnsentOperation,readUnsentClosure,readRetainedWorkflowJournal,
    withRetainedJournalTransition:participant.withRetainedJournalTransition,
    withRetainedWorkflowMutation:participant.withRetainedWorkflowMutation,
    recoverJournal:participant.recoverJournal,
    // Only source-owned H/Bridge adapters receive this participant. A guest facade
    // must select its closed methods; it must never expose a SQL/callback endpoint.
    participant,controlRetentionStatus:()=>Object.freeze({configured:true,kind:'private-source-v2',
      qualified:false,grants_authority:false})})
}
