// SPDX-License-Identifier: AGPL-3.0-or-later
// C and D retain authority/effect facts. This layer reads their durable state
// using the host's content-free references; it never reserves or repeats effects.
import {createHash} from 'node:crypto'
import {canonicalJson,validateContract} from '../../contracts/src/runtime.mjs'
import {validateUnsentReference,validateAuthorityUnconsumedClosure,certifyUnsentClosure,getUnsentClosureCertificate} from './unsent-closure.mjs'

const hash=(domain,value)=>'sha256:'+createHash('sha256').update(domain+'\0'+canonicalJson(value)).digest('hex')
const fail=reason=>{throw Object.assign(new Error(reason),{error_code:'OUTCOME_UNKNOWN'})}
const empty=(host,row,state)=>({ok:true,owner_id:host.owner_id,owner_subject:host.owner_subject,task_id:host.task_id,
  operation_id:row?.operation_id??null,operation_digest:row?.operation_digest??null,
  action_type:row?.action_type??null,state,reconciliation_required:state==='unknown',result:null,receipt:null,
  receipt_digest:null,authority_settlement:null,citation:null,index:null})

export function createRecovery({authority,memory,workflowStore,inFlight,authorizeTask,retentionRequired=true}) {
  const confirmedClosures=new Map()
  const closureKey=(host,row)=>canonicalJson([host.owner_id,host.owner_subject,host.task_id,host.authorization_epoch,row.operation_id,row.operation_digest,row.action_type])
  const referenceOf=(host,row)=>validateUnsentReference(Object.fromEntries(
    ['owner_id','owner_subject','task_id','operation_id','operation_digest','action_type'].map(key=>[key,row[key]])),host)
  async function unsent(host,session_token,row,{create=false}={}) {
    // A legacy reference journal cannot preflight the required retained D
    // closure. Do not permanently close C before D can accept its own scope.
    // The separate retained adapter persists genuine D progress before C;
    // an explicitly selected non-retained source profile keeps its old path.
    if(create&&retentionRequired)return null
    // The journal supplies lookup candidates, never absence evidence. C closes
    // the original operation permanently before D fences its actual writers.
    // A missing response at either boundary leaves the journal unresolved.
    const reference=referenceOf(host,row)
    const method=create?'closeUnconsumedOperation':'readUnconsumedClosure'
    if(typeof authority?.[method]!=='function'||typeof memory?.closeUnsentOperation!=='function')return null
    const authorityResult=validateAuthorityUnconsumedClosure(reference,
      await authority[method]({session_token,reference}))
    if(typeof authorizeTask!=='function'||authorizeTask(authorityResult.operation)?.authenticated!==true)return null
    const memoryResult=await memory.closeUnsentOperation(host,reference)
    const certificate=certifyUnsentClosure(host,reference,authorityResult,memoryResult,{retentionRequired})
    if(row.request_id!==null||row.request_digest!==null||row.receipt_digest!==null)return null
    const marked=await workflowStore.markClosed(host,certificate)
    if(marked.operation_digest!==reference.operation_digest||marked.action_type!==reference.action_type)return null
    confirmedClosures.set(closureKey(host,row),certificate)
    // Eviction only removes an admission exemption. The durable reference and
    // both original fences remain; an evicted pair needs explicit recovery.
    while(confirmedClosures.size>256)confirmedClosures.delete(confirmedClosures.keys().next().value)
    return {reply:empty(host,row,'known_unsent'),certificate}
  }
  function verifiedEffect(host,row,effect) {
    const receipt=effect?.receipt,result=effect?.result
    if(!receipt||receipt.version!==1||receipt.kind!=='prime-memory-effect/v1'
      ||receipt.operation_id!==row.operation_id||receipt.operation_digest!==row.operation_digest
      ||receipt.owner_subject!==host.owner_subject||receipt.action_type!==row.action_type||receipt.status!=='applied'
      ||typeof receipt.request_id!=='string'||!/^sha256:[a-f0-9]{64}$/.test(receipt.request_digest??'')
      ||receipt.result_digest!==hash('aukora-prime.memory-result.v1',result)
      ||canonicalJson(receipt.result)!==canonicalJson(result))fail('RECOVERY_EFFECT_BINDING_REQUIRED')
    const receiptDigest=hash('aukora-prime.memory-receipt.v1',receipt)
    if(effect.authority_settlement!=='completed'||effect.reconciliation_required!==false||effect.receipt_digest!==receiptDigest)fail('RECOVERY_SETTLEMENT_PENDING')
    for(const key of ['request_id','request_digest','receipt_digest'])if(row[key]!==null&&row[key]!==({receipt_digest:receiptDigest,...receipt})[key])fail('RECOVERY_REFERENCE_CHANGED')
    if(row.action_type==='memory.save') {
      validateContract('MemoryRecord',result)
      if(result.owner_subject!==host.owner_subject||result.task_id!==host.task_id||result.storage_status!=='saved'
        ||result.grants_authority!==false)fail('RECOVERY_RECORD_BINDING_REQUIRED')
    } else if(result?.record_id!==row.record_id||result.state!=='tombstoned'||result.grants_authority!==false
      ||result.canonical_payload_retained!==true||result.physical_media_erasure!==false)fail('RECOVERY_FORGET_BINDING_REQUIRED')
    return {receiptDigest,result,receipt}
  }
  async function rowState(host,session_token,row,{read=true,closeInterrupted=false,onClosure=()=>{}}={}) {
    if(inFlight.has(row.owner_subject+'\0'+row.operation_id))return empty(host,row,'unknown')
    if(row.phase==='known_unsent') {
      try {
        if(closeInterrupted) {
          const closed=await unsent(host,session_token,row)
          if(!closed)return empty(host,row,'unknown')
          onClosure(closed.certificate);return closed.reply
        }
        // Admission can use only a pair this instance actually confirmed.
        // Cold or legacy labels require explicit recovery; they cannot trigger
        // a D mutation or automatically retry an uncertain writer closure.
        const key=closureKey(host,row),certificate=confirmedClosures.get(key)
        if(!certificate)return empty(host,row,'unknown')
        const facts=getUnsentClosureCertificate(certificate)
        const current=validateAuthorityUnconsumedClosure(facts.reference,
          await authority.readUnconsumedClosure({session_token,reference:facts.reference}))
        if(current.closure_digest!==facts.authority.closure_digest
          ||canonicalJson(current.closure)!==canonicalJson(facts.authority.closure)) {
          confirmedClosures.delete(key);return empty(host,row,'unknown')
        }
        onClosure(certificate);return empty(host,row,'known_unsent')
      } catch {return empty(host,row,'unknown')}
    }
    let effect
    try {effect=await memory.reconcileEffect(host,row.operation_id)}
    catch {/* Neither a thrown read nor an absent effect proves non-execution. */}
    if(effect?.status==='unresolved'||effect?.authority_settlement!=='completed') {
      if(closeInterrupted)try {
        // Use C's locked retained-operation lookup directly. An ordinary status
        // read may prune an expired pending row and cannot supply this proof.
        const closed=await unsent(host,session_token,row,{create:true})
        if(closed){onClosure(closed.certificate);return closed.reply}
      } catch {/* Missing/uncertain C or D facts keep the durable attempt open. */}
      return empty(host,row,'unknown')
    }
    try {
      const factual=verifiedEffect(host,row,effect)
      // Receipt delivery above is factual settlement only. Confirm C's durable
      // status even when its terminal row has compacted payload/proof fields.
      const settled=await authority.status({session_token,operation_id:row.operation_id})
      if(settled?.ok!==true||settled.status!=='COMPLETED'||settled.operation_digest!==row.operation_digest
        ||settled.reconciliation_required!==false)return empty(host,row,'unknown')
      const phase=row.action_type==='memory.save'?'saved':'forgotten'
      await workflowStore.mark(host,row.operation_id,phase,{record_id:factual.result.record_id,
        request_id:factual.receipt.request_id,request_digest:factual.receipt.request_digest,receipt_digest:factual.receiptDigest})
      const reply={...empty(host,row,phase),result:factual.result,receipt:factual.receipt,receipt_digest:factual.receiptDigest,authority_settlement:'completed'}
      if(read&&phase==='saved') {
        try {reply.index=await memory.status(host,factual.result.record_id,factual.result.revision)}catch{/* Read availability cannot undo a completed save. */}
        try {reply.citation=await memory.cite(host,factual.result.record_id,factual.result.revision)}catch{/* Preserve confirmed effect facts. */}
      }
      return reply
    } catch {return empty(host,row,'unknown')}
  }
  async function pending(host,session_token,{exclude=null,allowLiveProposals=false}={}) {
    const listed=await workflowStore.admissionCandidates(host),closures=[]
    for(const row of listed.items) {
      if(row.operation_id===exclude)continue
      if(allowLiveProposals&&row.phase==='proposed') {
        // A live draft may coexist with other drafts. This does not close its
        // writer, prove non-execution or permit another effect. Attempted and
        // uncertain references still go through factual recovery below.
        const status=await authority.status({session_token,operation_id:row.operation_id})
        if(status?.ok===true&&status.operation_digest===row.operation_digest
          &&['PROPOSED','APPROVED','DENIED'].includes(status.status)
          &&status.reconciliation_required===false)continue
      }
      // Ordinary admission never retries a C/D closure whose reply was lost.
      // An interrupted attempt needs an explicit authenticated recovery call.
      const recovered=await rowState(host,session_token,row,{read:false,onClosure:certificate=>closures.push(certificate)})
      if(recovered.state==='unknown')return {blocked:recovered,closures:Object.freeze([])}
    }
    return {blocked:null,closures:Object.freeze(closures)}
  }
  async function recover(host,session_token,operation_id) {
    // Explicit recovery closes only its requested operation. Other delivered
    // live drafts remain reviewable; unresolved effect attempts still block.
    let row
    if(operation_id!==null)row=await workflowStore.get(host,operation_id)
    else {
      const candidates=(await workflowStore.admissionCandidates(host)).items
      row=candidates.find(candidate=>candidate.phase!=='proposed'
        &&!confirmedClosures.has(closureKey(host,candidate)))
        ??(await workflowStore.list(host,{active:false,limit:1})).items[0]
      if(!row||row.phase==='proposed')return empty(host,null,'idle')
    }
    if(row.phase==='proposed') {
      // A requested lookup does not establish an interrupted effect attempt.
      // Leave the delivered proposal and its review/decline path intact. Only
      // an already durable attempted reference can initiate private closure.
      return empty(host,row,'unknown')
    }
    const recovered=await rowState(host,session_token,row,{closeInterrupted:true})
    if(recovered.state==='unknown')return recovered
    // Completing this exact closure may help a later explicit recovery, but
    // cannot hide another unresolved effect or admit any fresh operation.
    const checked=await pending(host,session_token,{exclude:row.operation_id,allowLiveProposals:true})
    return checked.blocked??recovered
  }
  return Object.freeze({pending,recover,verifiedEffect})
}
