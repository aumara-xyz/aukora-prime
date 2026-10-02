// SPDX-License-Identifier: AGPL-3.0-or-later
// Private v2 adapter. D owns the actual owner transaction and retained lifecycle.
// This module never opens a pool/client or creates a baseline. Explicit recovery
// delegates matching publication cleanup to D's existing protected participant.
import {randomUUID} from 'node:crypto'
import {types} from 'node:util'
import {canonicalJson,operationDigest,validateContract} from '../../contracts/src/runtime.mjs'
import {copy,closed} from './registry.mjs'
import {memoryReceiptDigest,memoryResultDigest} from '../../memory/src/authorization.mjs'
import {validateClosureProfile,validateClosureHost,validateWorkflowRow,workflowDigest,
  validateClosureProgress,progressDigest,closureAttemptId,validateNormalTransition,normalTransitionDigest,
  validateJournalTransition,journalTransitionDigest,REFERENCE_FIELDS,validateAuthorityClosureReply,validateMemoryClosureReply} from './closure-v2.mjs'
import {mutateRetainedWorkflow,mutateRetainedClosure,assertRetainedAdmission} from './retained-journal-sql.mjs'
import {captureRetainedPendingRecovery,retainedUnknown} from './retained-pending.mjs'

const stores=new WeakMap(),certificates=new WeakMap()
const fail=reason=>{throw Object.assign(new Error(reason),{error_code:'OUTCOME_UNKNOWN',reconciliation_required:true,automatic_retry:false})}
const same=(a,b)=>canonicalJson(a)===canonicalJson(b)
const refOf=row=>Object.fromEntries(REFERENCE_FIELDS.map(k=>[k,row[k]]))
function hostOf(host) {
  // Memory source bytes are intentionally not retained or passed to the journal.
  const result={}
  if(!host||typeof host!=='object'||types.isProxy(host)||![Object.prototype,null].includes(Object.getPrototypeOf(host)))fail('RETAINED_TRUSTED_HOST_REQUIRED')
  for(const k of ['owner_id','owner_subject','task_id','authorization_epoch']) {
    const d=host&&Object.getOwnPropertyDescriptor(host,k)
    if(!d||!Object.hasOwn(d,'value'))fail('RETAINED_TRUSTED_HOST_REQUIRED')
    result[k]=d.value
  }
  return validateClosureHost(result)
}
function checkpoint(value,host) {
  closed(value,['checkpoint_sha256','control_sha256','authorization_epoch'])
  if(!['checkpoint_sha256','control_sha256'].every(k=>typeof value[k]==='string'&&/^[a-f0-9]{64}$/.test(value[k]))
    ||value.authorization_epoch!==host.authorization_epoch)fail('RETAINED_CHECKPOINT_REQUIRED')
  return copy(value)
}
function progressPair(value,profile,host) {
  closed(value,['progress','progress_digest'])
  const progress=validateClosureProgress(value.progress,profile,host)
  if(value.progress_digest!==progressDigest(progress))fail('RETAINED_PROGRESS_DIGEST_REQUIRED')
  return copy({progress,progress_digest:value.progress_digest})
}
function order(a,b) {
  // Locale-independent order is shared with fixed SQL's bytewise identifiers.
  for(const k of ['task_id','operation_id'])if(a[k]!==b[k])return Buffer.compare(Buffer.from(a[k]),Buffer.from(b[k]))
  return 0
}

/** A brand for a freshly revalidated complete retained C/D pair, not an effect
 * grant or deployment attestation. No serialized object can stand in for it. */
export function certifyRetainedAdmission(host,row,inputPair,authorityReply,memoryReply,profile) {
  const bound=hostOf(host)
  row=validateWorkflowRow(row,bound)
  const pair=progressPair(inputPair,profile,bound),reference=refOf(row)
  const c=validateAuthorityClosureReply(authorityReply,reference,profile)
  const d=validateMemoryClosureReply(memoryReply,reference,profile,bound.authorization_epoch)
  if(row.phase!=='known_unsent'||pair.progress.stage!=='complete'
    ||!same(refOf(row),pair.progress.reference)||row.idempotency_key_sha256!==pair.progress.idempotency_key_sha256
    ||pair.progress.closing_authorization_epoch!==bound.authorization_epoch
    ||pair.progress_digest!==progressDigest(pair.progress)
    ||!same(pair.progress.authority,{closure:c.closure,closure_digest:c.closure_digest})
    ||!same(pair.progress.memory,{closure:d.closure,closure_digest:d.closure_digest,completion:d.completion,completion_digest:d.completion_digest})
    ||c.idempotent!==true||d.idempotent!==true)fail('RETAINED_COMPLETE_PAIR_REQUIRED')
  const certificate=Object.freeze({})
  certificates.set(certificate,copy({host:bound,reference:refOf(row),progress_digest:pair.progress_digest}))
  return certificate
}

/** Explicit selection only. Availability of these methods is not PG, lineage
 * or custody qualification: D must enforce those on EVERY actual invocation. */
export function createRetainedWorkflowStore({memory,closureProfile,taskRegistry}={}) {
  const profile=validateClosureProfile(closureProfile)
  for(const name of ['readRetainedWorkflowJournal','withRetainedWorkflowMutation','withRetainedJournalTransition'])
    if(typeof memory?.[name]!=='function')fail('RETAINED_D_PARTICIPANT_UNMOUNTED:'+name)
  const recoverProtectedPending=captureRetainedPendingRecovery(memory,profile)
  memory=Object.freeze(Object.fromEntries(['readRetainedWorkflowJournal','withRetainedWorkflowMutation','withRetainedJournalTransition']
    .map(name=>[name,memory[name].bind(memory)])))
  if(typeof taskRegistry?.snapshot!=='function')fail('RETAINED_AUTHENTICATED_REGISTRY_REQUIRED')
  const registered=taskRegistry.snapshot()
  function registeredTask(row,owner) {
    if(!registered.some(e=>e.task.owner_id===owner.owner_id&&e.task.task_id===row.task_id&&e.audience==='aukora-prime.memory'))
      fail('RETAINED_REGISTERED_OWNER_TASK_REQUIRED')
  }
  async function recoverPending(inputHost,operationId=null) {
    const owner=hostOf(inputHost),entry=taskRegistry.getOwned?.(owner.task_id,owner.owner_id)
    if(!entry||entry.audience!=='aukora-prime.memory')fail('RETAINED_REGISTERED_OWNER_TASK_REQUIRED')
    const reference=recoverProtectedPending?await recoverProtectedPending(owner,operationId):undefined
    // No source or no pending is not an admission fact. Explicit recovery must
    // now obtain the current authoritative census through the ordinary reader.
    return reference
  }
  function certFacts(host,closures) {
    if(!Array.isArray(closures))fail('RETAINED_CERTIFICATES_REQUIRED')
    return closures.map(c=>{
      const found=certificates.get(c)
      if(!found||found.host.owner_id!==host.owner_id||found.host.owner_subject!==host.owner_subject
        ||found.host.authorization_epoch!==host.authorization_epoch)fail('RETAINED_CERTIFICATE_BINDING_REQUIRED')
      return copy({reference:found.reference,progress_digest:found.progress_digest})
    })
  }
  function snapshotCertificates(host,closures) {
    if(!Array.isArray(closures)||types.isProxy(closures)||closures.length>10000)fail('RETAINED_CERTIFICATES_REQUIRED')
    const snapshot=[]
    for(let i=0;i<closures.length;i++) {
      const descriptor=Object.getOwnPropertyDescriptor(closures,String(i))
      if(!descriptor||!Object.hasOwn(descriptor,'value'))fail('RETAINED_CERTIFICATES_REQUIRED')
      snapshot.push(descriptor.value)
    }
    certFacts(host,snapshot)
    return Object.freeze(snapshot)
  }
  async function census(inputHost) {
    const host=hostOf(inputHost),reply=await memory.readRetainedWorkflowJournal(host,{reference:null})
    closed(reply,['workflow_references','closure_progress','checkpoint'])
    if(!Array.isArray(reply.workflow_references)||!Array.isArray(reply.closure_progress))fail('RETAINED_CENSUS_REQUIRED')
    const rows=reply.workflow_references.map(r=>{
      const row=validateWorkflowRow(r)
      if(row.owner_id!==host.owner_id||row.owner_subject!==host.owner_subject)fail('RETAINED_CENSUS_OWNER_CHANGED')
      registeredTask(row,host);return row
    })
    for(let i=1;i<rows.length;i++)if(order(rows[i-1],rows[i])>=0)fail('RETAINED_CENSUS_ORDER_REQUIRED')
    const ids=new Set(rows.map(r=>r.operation_id))
    if(ids.size!==rows.length)fail('RETAINED_CENSUS_DUPLICATE_REFERENCE')
    const pairs=reply.closure_progress.map(p=>{
      const bound={...host,task_id:p?.progress?.reference?.task_id}
      const pair=progressPair(p,profile,bound),row=rows.find(r=>same(refOf(r),pair.progress.reference))
      if(!row||row.idempotency_key_sha256!==pair.progress.idempotency_key_sha256
        ||(pair.progress.stage==='complete'?row.phase!=='known_unsent':row.phase!=='attempted'))fail('RETAINED_CENSUS_PROGRESS_CORRELATION')
      return pair
    })
    for(let i=1;i<pairs.length;i++)if(order(pairs[i-1].progress.reference,pairs[i].progress.reference)>=0)fail('RETAINED_CENSUS_PROGRESS_ORDER')
    for(const row of rows)if(row.phase==='known_unsent'&&!pairs.some(p=>p.progress.reference.operation_id===row.operation_id&&p.progress.stage==='complete'))
      fail('RETAINED_CENSUS_COMPLETION_MISSING')
    return copy({workflow_references:rows,closure_progress:pairs,checkpoint:checkpoint(reply.checkpoint,host)})
  }
  function selected(found,host,id) {
    const row=found.workflow_references.find(r=>r.operation_id===id&&r.task_id===host.task_id)
    if(!row)fail('RETAINED_REFERENCE_UNAVAILABLE')
    return row
  }
  async function get(host,id){const owner=hostOf(host);return selected(await census(owner),owner,id)}
  async function list(host,input) {
    input=copy(input)
    closed(input,Object.hasOwn(input??{},'limit')?['active','limit']:['active'])
    if(typeof input.active!=='boolean'||input.limit!==undefined&&(!Number.isSafeInteger(input.limit)||input.limit<1||input.limit>256))fail('RETAINED_LIST_BOUND')
    const owner=hostOf(host),found=await census(owner),limit=input.limit??256
    const all=found.workflow_references.filter(r=>r.task_id===owner.task_id&&(!input.active||!['known_unsent','saved','forgotten'].includes(r.phase)))
      .sort((a,b)=>input.active?(a.created_at<b.created_at?-1:a.created_at>b.created_at?1:order(a,b)):(a.created_at>b.created_at?-1:a.created_at<b.created_at?1:-order(a,b)))
    if(input.active&&all.length>limit)fail('RETAINED_LIST_OVERFLOW')
    return copy({items:all.slice(0,limit),overflow:all.length>limit})
  }
  async function admissionCandidates(host) {
    const found=await census(host)
    // Deliberately owner-wide, including historical known_unsent proof labels.
    return copy({items:found.workflow_references.filter(r=>!['saved','forgotten'].includes(r.phase)),overflow:false})
  }
  async function normal(host,found,prior,target,{closures=[],exclude=null,admission=false}={}) {
    const owner=hostOf(host),facts=certFacts(owner,closures)
    const transition=validateNormalTransition({version:3,kind:'prime-runtime-workflow-mutation/v3',memory_store_id:profile.expected_memory_store_id,
      reference:refOf(target),idempotency_key_sha256:target.idempotency_key_sha256,expected_checkpoint_sha256:found.checkpoint.checkpoint_sha256,
      previous_workflow_digest:prior?workflowDigest(prior):null,target_workflow:target},profile)
    const request=Object.freeze({transition_id:randomUUID(),transition,transition_digest:normalTransitionDigest(transition)})
    try {
      const reply=await memory.withRetainedWorkflowMutation(owner,request,async(tx,actual)=>{
        if(!same(actual,transition))fail('RETAINED_D_TRANSITION_CHANGED')
        if(admission)await assertRetainedAdmission(tx,owner,facts,{exclude})
        await mutateRetainedWorkflow(tx,transition)
        // D trusts only its actual reread/publication, never a callback flag.
      })
      closed(reply,['checkpoint','workflow_reference'])
      checkpoint(reply.checkpoint,owner)
      if(!same(validateWorkflowRow(reply.workflow_reference,owner),target))fail('RETAINED_NORMAL_POSTIMAGE_CHANGED')
      return copy(reply.workflow_reference)
    } catch(error){throw retainedUnknown(error,request)}
  }
  async function insertForAdmission(host,input,{closures=[],authority_reply}={}) {
    const owner=hostOf(host)
    input=copy(input);authority_reply=copy(authority_reply);closures=snapshotCertificates(owner,closures)
    closed(input,['operation','idempotency_key_sha256','record_id'])
    const operation=copy(input.operation);validateContract('OperationProposal',operation)
    const digest=operationDigest(operation)
    // Source callers must hand the actual C proposal response to this private
    // adapter. The original C service still authenticates and stores the body.
    closed(authority_reply,['ok','operation','operation_digest','status'])
    if(authority_reply.ok!==true||authority_reply.status!=='PROPOSED'||authority_reply.operation_digest!==digest
      ||!same(authority_reply.operation,operation)||taskRegistry.authorizeTask(operation)?.authenticated!==true
      ||operation.authorization_epoch!==owner.authorization_epoch||operation.owner_id!==owner.owner_id
      ||operation.task_id!==owner.task_id||operation.audience!=='aukora-prime.memory'
      ||!same(operation.target_identity,{kind:'prime-memory',owner_subject:owner.owner_subject}))fail('RETAINED_AUTHENTICATED_PROPOSAL_REQUIRED')
    const found=await census(owner)
    if(found.workflow_references.some(r=>r.operation_id===operation.operation_id))fail('RETAINED_REGISTRATION_REPLAYED')
    const target=validateWorkflowRow({owner_subject:owner.owner_subject,owner_id:owner.owner_id,task_id:owner.task_id,
      operation_id:operation.operation_id,operation_digest:digest,action_type:operation.action_type,
      idempotency_key_sha256:input.idempotency_key_sha256,record_id:input.record_id,phase:'proposed',request_id:null,
      request_digest:null,receipt_digest:null,created_at:new Date().toISOString()},owner)
    if(operation.action_type==='memory.save'&&target.idempotency_key_sha256!==operation.canonical_parameters.idempotency_key_sha256
      ||operation.action_type==='memory.forget'&&(target.idempotency_key_sha256!==null||target.record_id!==operation.canonical_parameters.record_id))
      fail('RETAINED_ORIGINAL_KEY_REQUIRED')
    return normal(owner,found,null,target,{closures,admission:true})
  }
  async function attemptForAdmission(host,id,digest,{closures=[]}={}) {
    const owner=hostOf(host)
    closures=snapshotCertificates(owner,closures)
    const found=await census(owner),row=selected(found,owner,id)
    if(row.operation_digest!==digest||row.phase!=='proposed')fail('RETAINED_ATTEMPT_REPLAYED')
    return normal(owner,found,row,{...row,phase:'attempted'},{closures,exclude:id,admission:true})
  }
  async function mark(host,id,phase,metadata,verification) {
    const owner=hostOf(host)
    if(!verification)fail('RETAINED_FACTUAL_SETTLEMENT_REQUIRED')
    metadata=copy(metadata);verification=copy(verification)
    const found=await census(owner),row=selected(found,owner,id)
    closed(metadata,['record_id','request_id','request_digest','receipt_digest'])
    if(!['saved','forgotten'].includes(phase)||!verification||verification.authority_status?.ok!==true
      ||verification.authority_status.status!=='COMPLETED'||verification.authority_status.operation_digest!==row.operation_digest
      ||verification.authority_status.reconciliation_required!==false)fail('RETAINED_FACTUAL_SETTLEMENT_REQUIRED')
    const e=verification.effect,r=e?.receipt
    if(!e||e.authority_settlement!=='completed'||e.reconciliation_required!==false||!r||r.operation_id!==id||r.operation_digest!==row.operation_digest
      ||r.owner_subject!==owner.owner_subject||r.action_type!==row.action_type||r.status!=='applied'
      ||r.request_id!==metadata.request_id||r.request_digest!==metadata.request_digest
      ||e.receipt_digest!==metadata.receipt_digest||memoryReceiptDigest(r)!==metadata.receipt_digest
      ||r.result_digest!==memoryResultDigest(e.result)||!same(r.result,e.result)
      ||e.result?.record_id!==metadata.record_id)fail('RETAINED_RECEIPT_BINDING_REQUIRED')
    const target=validateWorkflowRow({...row,...metadata,phase},owner)
    if(same(target,row))return row // factual census already validated publication.
    return normal(owner,found,row,target)
  }
  async function journal(host,found,previous,target) {
    const owner=hostOf(host),reference=target.reference
    const transition=validateJournalTransition({version:3,kind:'prime-runtime-unsent-journal-transition/v3',memory_store_id:profile.expected_memory_store_id,
      reference,idempotency_key_sha256:target.idempotency_key_sha256,expected_checkpoint_sha256:found.checkpoint.checkpoint_sha256,
      previous_progress_digest:previous?.progress_digest??null,target_stage:target.stage,target_progress:target},profile)
    const request=Object.freeze({transition_id:randomUUID(),transition,transition_digest:journalTransitionDigest(transition)})
    try {
      const reply=await memory.withRetainedJournalTransition(owner,request,async(tx,actual)=>{
        if(!same(actual,transition))fail('RETAINED_D_TRANSITION_CHANGED')
        await mutateRetainedClosure(tx,transition)
      })
      closed(reply,['checkpoint','workflow_reference','progress','progress_digest'])
      checkpoint(reply.checkpoint,owner)
      const pair=progressPair({progress:reply.progress,progress_digest:reply.progress_digest},profile,owner)
      if(!same(pair.progress,target)||!same(refOf(reply.workflow_reference),reference)
        ||reply.workflow_reference.phase!==(target.stage==='complete'?'known_unsent':'attempted'))fail('RETAINED_JOURNAL_POSTIMAGE_CHANGED')
      validateWorkflowRow(reply.workflow_reference,owner)
      return copy({workflow_reference:reply.workflow_reference,...pair})
    } catch(error){throw retainedUnknown(error,request)}
  }
  async function readProgress(host,reference) {
    const owner=hostOf(host)
    reference=copy(reference)
    const found=await census(owner),row=selected(found,owner,reference.operation_id)
    if(!same(refOf(row),reference))fail('RETAINED_REFERENCE_CHANGED')
    return {found,row,pair:found.closure_progress.find(p=>same(p.progress.reference,reference))??null}
  }
  async function beginClosure(host,input) {
    input=copy(input)
    closed(input,['reference','expected_authority_store_id','expected_memory_store_id','closing_authorization_epoch'])
    const owner=hostOf(host)
    if(input.expected_authority_store_id!==profile.expected_authority_store_id||input.expected_memory_store_id!==profile.expected_memory_store_id
      ||input.closing_authorization_epoch!==owner.authorization_epoch)fail('RETAINED_CLOSING_PROFILE_CHANGED')
    const {found,row,pair}=await readProgress(owner,input.reference)
    if(pair)return pair
    if(row.phase!=='attempted'||row.request_id!==null||row.request_digest!==null||row.receipt_digest!==null)fail('RETAINED_INTERRUPTED_ATTEMPT_REQUIRED')
    const immutable={reference:input.reference,idempotency_key_sha256:row.idempotency_key_sha256,
      expected_authority_store_id:profile.expected_authority_store_id,expected_memory_store_id:profile.expected_memory_store_id,closing_authorization_epoch:owner.authorization_epoch}
    const target=validateClosureProgress({version:2,kind:'prime-runtime-unsent-closure-progress/v2',...immutable,
      closure_attempt_id:closureAttemptId(immutable),stage:'started',authority:null,memory:null},profile,owner)
    const result=await journal(owner,found,null,target)
    return copy({progress:result.progress,progress_digest:result.progress_digest})
  }
  async function advance(host,input,stage) {
    input=copy(input)
    closed(input,stage==='authority_confirmed'?['reference','progress_digest','authority']:stage==='memory_confirmed'?['reference','progress_digest','memory']:['reference','progress_digest'])
    const owner=hostOf(host),{found,row,pair}=await readProgress(owner,input.reference)
    if(!pair||pair.progress_digest!==input.progress_digest)fail('RETAINED_PROGRESS_CAS_REQUIRED')
    if(pair.progress.stage===stage) {
      const identical=stage==='authority_confirmed'?same(input.authority,pair.progress.authority)
        :stage==='memory_confirmed'?same(input.memory,pair.progress.memory):true
      if(!identical||row.phase!==(stage==='complete'?'known_unsent':'attempted'))fail('RETAINED_IDEMPOTENT_STAGE_CHANGED')
      return stage==='complete'?copy({workflow_reference:row,...pair}):pair
    }
    if(row.phase!=='attempted')fail('RETAINED_PROGRESS_CAS_REQUIRED')
    const expected={authority_confirmed:'started',memory_confirmed:'authority_confirmed',complete:'memory_confirmed'}[stage]
    if(pair.progress.stage!==expected)fail('RETAINED_STAGE_ADVANCE_REQUIRED')
    const target=validateClosureProgress({...pair.progress,stage,...(stage==='authority_confirmed'?{authority:input.authority}:stage==='memory_confirmed'?{memory:input.memory}:{})},profile,owner)
    const result=await journal(owner,found,pair,target)
    return stage==='complete'?result:copy({progress:result.progress,progress_digest:result.progress_digest})
  }
  const methods={ownerCensus:census,list,get,admissionCandidates,recoverPending,insertForAdmission,attemptForAdmission,mark,
    beginClosure,saveAuthorityClosure:(h,i)=>advance(h,i,'authority_confirmed'),saveMemoryClosure:(h,i)=>advance(h,i,'memory_confirmed'),
    completeClosure:(h,i)=>advance(h,i,'complete'),async getClosureProgress(host,input){input=copy(input);closed(input,['reference']);return (await readProgress(host,input.reference)).pair}}
  const store=Object.freeze(Object.fromEntries(Object.entries(methods).map(([name,method])=>[name,async(...args)=>{
    // Malformed/lost D replies after a transaction can never become a known
    // ordinary refusal. The protected participant alone resolves its pending.
    try{return await method(...args)}
    catch(error){throw retainedUnknown(error)}
  }])))
  stores.set(store,profile);return store
}
export const isRetainedWorkflowStore=value=>stores.has(value)
export function retainedWorkflowProfile(value){if(!stores.has(value))fail('RETAINED_STORE_REQUIRED');return stores.get(value)}
