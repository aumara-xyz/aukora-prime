// SPDX-License-Identifier: AGPL-3.0-or-later
// Private v2 recovery: each stage is D-retained before the next service call.
// No original effect is dispatched, repeated or implicitly abandoned here.
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {createRecovery} from './recovery.mjs'
import {validateAuthorityClosureReply,validateMemoryClosureReply,REFERENCE_FIELDS} from './closure-v2.mjs'
import {retainedWorkflowProfile,certifyRetainedAdmission} from './retained-workflow-store.mjs'
import {retainedUnknownReference} from './retained-pending.mjs'

const same=(a,b)=>canonicalJson(a)===canonicalJson(b)
const refOf=row=>Object.fromEntries(REFERENCE_FIELDS.map(k=>[k,row[k]]))
const unknown=reason=>{throw Object.assign(new Error(reason),{error_code:'OUTCOME_UNKNOWN'})}
const reply=(host,row,state)=>({ok:true,owner_id:host.owner_id,owner_subject:host.owner_subject,task_id:row?.task_id??host.task_id,
  operation_id:row?.operation_id??null,operation_digest:row?.operation_digest??null,action_type:row?.action_type??null,state,
  reconciliation_required:state==='unknown',result:null,receipt:null,receipt_digest:null,authority_settlement:null,citation:null,index:null})

export function createRetainedRecovery({authority,memory,workflowStore,inFlight,authorizeTask}={}) {
  const profile=retainedWorkflowProfile(workflowStore)
  const {verifiedEffect}=createRecovery({authority,memory,workflowStore,inFlight,authorizeTask})
  function ownerHost(host,row){return {...host,task_id:row.task_id}}
  function authorized(result) {
    if(typeof authorizeTask!=='function'||authorizeTask(result.operation)?.authenticated!==true)unknown('RETAINED_RECOVERY_AUTHENTICATED_TASK_REQUIRED')
    return result
  }
  async function authorityFact(host,token,row,{command=false}={}) {
    const method=command?'closeUnconsumedOperation':'readUnconsumedClosure'
    if(typeof authority?.[method]!=='function')unknown('RETAINED_C_CLOSURE_UNAVAILABLE')
    return authorized(validateAuthorityClosureReply(await authority[method]({session_token:token,reference:refOf(row)}),refOf(row),profile))
  }
  async function memoryFact(host,row,{command=false}={}) {
    const method=command?'closeUnsentOperation':'readUnsentClosure'
    if(typeof memory?.[method]!=='function')unknown('RETAINED_D_CLOSURE_UNAVAILABLE')
    const h={owner_id:host.owner_id,owner_subject:host.owner_subject,task_id:row.task_id,authorization_epoch:host.authorization_epoch}
    return validateMemoryClosureReply(await memory[method](h,refOf(row)),refOf(row),profile,h.authorization_epoch)
  }
  const cProjection=c=>({closure:c.closure,closure_digest:c.closure_digest})
  const dProjection=d=>({closure:d.closure,closure_digest:d.closure_digest,completion:d.completion,completion_digest:d.completion_digest})
  async function closedFact(host,token,row) {
    const pair=await workflowStore.getClosureProgress(host,{reference:refOf(row)})
    if(row.phase!=='known_unsent'||!pair||pair.progress.stage!=='complete')unknown('RETAINED_COMPLETE_PROGRESS_REQUIRED')
    // Both queries are factual, and D independently verifies current full SQL,
    // its actual fence and published first-A lineage. No cache exempts a row.
    const c=await authorityFact(host,token,row),d=await memoryFact(host,row)
    if(c.idempotent!==true||d.idempotent!==true||!same(pair.progress.authority,cProjection(c))||!same(pair.progress.memory,dProjection(d)))
      unknown('RETAINED_COMPLETED_PROOF_CHANGED')
    return {reply:reply(host,row,'known_unsent'),certificate:certifyRetainedAdmission(host,row,pair,c,d,profile)}
  }
  async function closeInterrupted(host,token,row) {
    if(row.phase==='proposed'||row.phase!=='attempted'||row.request_id!==null||row.request_digest!==null||row.receipt_digest!==null)
      unknown('RETAINED_INTERRUPTED_ATTEMPT_REQUIRED')
    const reference=refOf(row)
    let pair=await workflowStore.getClosureProgress(host,{reference})
    if(!pair)pair=await workflowStore.beginClosure(host,{reference,
      expected_authority_store_id:profile.expected_authority_store_id,expected_memory_store_id:profile.expected_memory_store_id,
      closing_authorization_epoch:host.authorization_epoch})
    if(pair.progress.stage==='started') {
      // This is the explicit negative command, outside D's transaction. Its
      // exact successful C2 is retained before D is asked to fence writers.
      const c=await authorityFact(host,token,row,{command:true})
      pair=await workflowStore.saveAuthorityClosure(host,{reference,progress_digest:pair.progress_digest,authority:cProjection(c)})
    }
    if(pair.progress.stage==='authority_confirmed') {
      // A retained successful C2 already required C pending cleanup. Its live
      // factual read cannot renew that marker or repair a mismatching witness.
      const c=await authorityFact(host,token,row)
      if(!same(pair.progress.authority,cProjection(c)))unknown('RETAINED_C_CLOSURE_CHANGED')
      const d=await memoryFact(host,row,{command:true}) // D publishes A first.
      pair=await workflowStore.saveMemoryClosure(host,{reference,progress_digest:pair.progress_digest,memory:dProjection(d)}) // B
    }
    if(pair.progress.stage==='memory_confirmed') {
      const c=await authorityFact(host,token,row),d=await memoryFact(host,row)
      if(!same(pair.progress.authority,cProjection(c))||!same(pair.progress.memory,dProjection(d)))unknown('RETAINED_PRECOMPLETE_FACT_CHANGED')
      await workflowStore.completeClosure(host,{reference,progress_digest:pair.progress_digest}) // C + old row atomic
    }
    const current=await workflowStore.get(host,row.operation_id)
    return closedFact(host,token,current)
  }
  async function effectFact(host,token,row,{read=true}={}) {
    // D reconciles only a locally committed immutable receipt; this is never
    // the original reserve/claim/effect path. Absence/throw proves nothing.
    const effect=await memory.reconcileEffect(host,row.operation_id)
    const fact=verifiedEffect(host,row,effect)
    const status=await authority.status({session_token:token,operation_id:row.operation_id})
    if(status?.ok!==true||status.status!=='COMPLETED'||status.operation_digest!==row.operation_digest||status.reconciliation_required!==false)
      unknown('RETAINED_FACTUAL_C_SETTLEMENT_REQUIRED')
    const phase=row.action_type==='memory.save'?'saved':'forgotten'
    await workflowStore.mark(host,row.operation_id,phase,{record_id:fact.result.record_id,request_id:fact.receipt.request_id,
      request_digest:fact.receipt.request_digest,receipt_digest:fact.receiptDigest},{effect,authority_status:status})
    const found={...reply(host,row,phase),result:fact.result,receipt:fact.receipt,receipt_digest:fact.receiptDigest,authority_settlement:'completed'}
    if(read&&phase==='saved') {
      try{found.index=await memory.status(host,fact.result.record_id,fact.result.revision)}catch{}
      try{found.citation=await memory.cite(host,fact.result.record_id,fact.result.revision)}catch{}
    }
    return {reply:found,certificate:null}
  }
  async function rowState(host,token,row,{explicit=false,read=true}={}) {
    host=ownerHost(host,row)
    if(inFlight.has(row.owner_subject+'\0'+row.operation_id))return {reply:reply(host,row,'unknown'),certificate:null}
    if(row.phase==='proposed')return {reply:reply(host,row,'unknown'),certificate:null}
    try {
      if(row.phase==='known_unsent')return await closedFact(host,token,row)
      const progress=await workflowStore.getClosureProgress(host,{reference:refOf(row)})
      if(progress)return explicit?await closeInterrupted(host,token,row):{reply:reply(host,row,'unknown'),certificate:null}
      try{return await effectFact(host,token,row,{read})}
      catch {
        // A known applied/pending settlement cannot be mistaken for absence:
        // C's real close and D's ledger/guard checks independently refuse it.
        if(explicit&&row.phase==='attempted')return await closeInterrupted(host,token,row)
        throw unknown('RETAINED_EFFECT_UNRESOLVED')
      }
    } catch{return {reply:reply(host,row,'unknown'),certificate:null}}
  }
  async function pending(host,token,{exclude=null,allowLiveProposals=false}={}) {
    const found=await workflowStore.admissionCandidates(host),closures=[]
    for(const row of found.items) {
      // Exclude only this task's selected ordinary effect candidate. It still
      // must be a retained proposed row before attemptForAdmission succeeds.
      if(row.operation_id===exclude&&row.task_id===host.task_id)continue
      if(allowLiveProposals&&row.phase==='proposed') {
        const status=await authority.status({session_token:token,operation_id:row.operation_id})
        if(status?.ok===true&&status.operation_digest===row.operation_digest&&['PROPOSED','APPROVED','DENIED'].includes(status.status)
          &&status.reconciliation_required===false)continue
      }
      const state=await rowState(host,token,row,{read:false})
      if(state.reply.state==='unknown')return {blocked:state.reply,closures:Object.freeze([])}
      if(state.certificate)closures.push(state.certificate)
    }
    return {blocked:null,closures:Object.freeze(closures)}
  }
  async function recover(host,token,id) {
    let row,pendingReference
    try {
      // Explicit owner recovery alone may finish D's matching prepared pending
      // publication. This yields no evidence: the next read is a fresh census.
      pendingReference=await workflowStore.recoverPending(host,id)
      if(id!==null) {
        row=await workflowStore.get(host,id)
        if(pendingReference&&!same(refOf(row),pendingReference))unknown('RETAINED_PENDING_REFERENCE_CHANGED')
      }
      else {
        const found=await workflowStore.ownerCensus(host)
        if(pendingReference&&!found.workflow_references.some(r=>same(refOf(r),pendingReference)))
          unknown('RETAINED_PENDING_REFERENCE_UNAVAILABLE')
        row=found.workflow_references.find(r=>r.phase==='attempted')
          ??found.workflow_references.find(r=>r.phase==='known_unsent')
          ??found.workflow_references.filter(r=>r.task_id===host.task_id&&r.phase!=='proposed').sort((a,b)=>b.created_at.localeCompare(a.created_at))[0]
        if(!row)return reply(host,null,'idle') // only a verified full census.
      }
      // A read or target/default UI call supplies no abandonment intent.
      if(row.phase==='proposed')return reply(host,row,'unknown')
      const state=await rowState(host,token,row,{explicit:true})
      if(state.reply.state==='unknown')return state.reply
      const checked=await pending(host,token,{exclude:row.operation_id,allowLiveProposals:true})
      return checked.blocked??state.reply
    } catch(error) {
      let original=retainedUnknownReference(error)??pendingReference
      if(original&&(original.owner_id!==host.owner_id||original.owner_subject!==host.owner_subject
        ||original.task_id!==host.task_id||id!==null&&original.operation_id!==id))original=null
      return reply(host,row??original??(id===null?null:{operation_id:id}),'unknown')
    }
  }
  return Object.freeze({pending,recover,verifiedEffect})
}
