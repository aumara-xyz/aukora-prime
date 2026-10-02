// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe logical-forget coordinator. H/B must explicitly hand off this
// separate workflow through B's distinct logical-forget approval hook.
import {canonicalJson,parseStrictJson,validateContract,ERROR_CODES} from '../../contracts/src/shared.mjs'

const DIGEST=/^sha256:[a-f0-9]{64}$/,HEX=/^[a-f0-9]{64}$/
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
const codes=new Set(ERROR_CODES),uncertainCodes=new Set(['UNAVAILABLE','OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED'])
const fault=(code,reason)=>Object.assign(new Error(reason),{code})
const requireValue=(condition,reason)=>{if(!condition)throw fault('INVALID',reason)}
const copy=value=>parseStrictJson(canonicalJson(value),{maxBytes:65_536,maxDepth:32})
async function digest(domain,value){
  const bytes=new TextEncoder().encode(domain+'\0'+canonicalJson(value))
  const result=await globalThis.crypto.subtle.digest('SHA-256',bytes)
  return 'sha256:'+Array.from(new Uint8Array(result),byte=>byte.toString(16).padStart(2,'0')).join('')
}
function closed(value,required,optional=[]){
  requireValue(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>[...required,...optional].includes(key))
    &&required.every(key=>Object.hasOwn(value,key)),'OWNER_FORGET_CLOSED_FIELDS_REQUIRED')
  return value
}
function immutable(value){if(value&&typeof value==='object'){for(const child of Object.values(value))immutable(child);Object.freeze(value)}return value}
const text=(value,max)=>typeof value==='string'&&value.length>0&&new TextEncoder().encode(value).length<=max
const errorCode=value=>codes.has(value?.error_code)?value.error_code:codes.has(value?.code)?value.code:value instanceof TypeError?'INVALID':'UNAVAILABLE'
const initial=()=>({phase:'idle',operation:null,record_summary:null,operation_digest:null,approval:'not_requested',forget:'not_attempted',forgotten:false,
  result:null,receipt:null,receipt_digest:null,authority_settlement:null,reconciliation_required:false,error_code:null,
  recovery_status:'not_requested',recovery_operation_id:null,recovery_operation_digest:null})

function requestOf(input){const request=closed(copy(input),['record_id']);requireValue(text(request.record_id,1024),'OWNER_FORGET_RECORD_REFERENCE_REQUIRED');return immutable(request)}
function proposalOf(value,entry){
  const proposed=closed(copy(value),['ok','operation','operation_digest','record_summary'],['status'])
  requireValue(proposed.ok===true&&(proposed.status===undefined||proposed.status==='PROPOSED'),'OWNER_FORGET_PROPOSAL_REQUIRED')
  const operation=proposed.operation,parameters=operation?.canonical_parameters,summary=proposed.record_summary
  validateContract('OperationProposal',operation)
  closed(operation.target_identity,['kind','owner_subject'])
  closed(parameters,['profile','record_id','revision','canonical_sha256','at','heads','statement','attributed_to'])
  closed(summary,['record_id','revision','statement','attributed_to'])
  requireValue(operation.action_type==='memory.forget'&&operation.audience==='aukora-prime.memory'&&operation.target_identity.kind==='prime-memory'
    &&/^aukora:1:[a-f0-9]{64}$/.test(operation.target_identity.owner_subject)&&operation.owner_id===entry.owner.owner_id
    &&DIGEST.test(operation.expected_state_version)&&Date.parse(operation.expiry)>Date.now()
    &&Date.parse(operation.expiry)<=Date.parse(entry.owner.expiry),'OWNER_FORGET_OPERATION_BINDING_REQUIRED')
  requireValue(parameters.profile==='prime-logical-forget/v1'&&parameters.record_id===entry.request.record_id&&text(parameters.revision,1024)
    &&HEX.test(parameters.canonical_sha256)&&typeof parameters.at==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(parameters.at)
    &&Number.isFinite(Date.parse(parameters.at))&&new Date(parameters.at).toISOString().slice(0,19)+'Z'===parameters.at,'OWNER_FORGET_PARAMETERS_REQUIRED')
  closed(parameters.heads,[],['remembered','approved','legacy-presplit'])
  for(const head of Object.values(parameters.heads))requireValue(head==='aukora:aura-record:v1'||typeof head==='string'&&HEX.test(head),'OWNER_FORGET_HEADS_REQUIRED')
  requireValue(summary.record_id===parameters.record_id&&summary.revision===parameters.revision&&text(parameters.statement,16_384)
    &&(parameters.attributed_to===null||text(parameters.attributed_to,1024))&&summary.statement===parameters.statement
    &&summary.attributed_to===parameters.attributed_to,'OWNER_FORGET_SUMMARY_BINDING_REQUIRED')
  requireValue(DIGEST.test(proposed.operation_digest),'OWNER_FORGET_OPERATION_DIGEST_REQUIRED')
  return immutable(proposed)
}
function logicalResult(value,recordId=null){
  const result=closed(value,['record_id','state','canonical_payload_retained','physical_media_erasure','authority_approval_history_erased','backups_erased','wal_erased','grants_authority'])
  requireValue(text(result.record_id,1024)&&(recordId===null||result.record_id===recordId)&&result.state==='tombstoned'&&result.canonical_payload_retained===true
    &&result.physical_media_erasure===false&&result.authority_approval_history_erased===false&&result.backups_erased===false
    &&result.wal_erased===false&&result.grants_authority===false,'OWNER_FORGET_LOGICAL_RESULT_REQUIRED')
  return result
}
async function receiptFacts(reply,entry,stillCurrent,binding){
  const result=logicalResult(reply.result,binding.record_id??null)
  const receipt=closed(reply.receipt,['version','kind','operation_id','operation_digest','grant_id','request_id','request_digest','owner_subject','action_type','status','result_digest','result'])
  requireValue(receipt.version===1&&receipt.kind==='prime-memory-effect/v1'&&receipt.operation_id===binding.operation_id
    &&receipt.operation_digest===binding.operation_digest&&/^grant:[a-f0-9]{64}$/.test(receipt.grant_id)
    &&(binding.grant_id===undefined||receipt.grant_id===binding.grant_id)&&/^aukora:1:[a-f0-9]{64}$/.test(receipt.owner_subject)
    &&(binding.owner_subject===undefined||receipt.owner_subject===binding.owner_subject)
    &&receipt.action_type==='memory.forget'&&receipt.status==='applied'&&UUID.test(receipt.request_id)&&DIGEST.test(receipt.request_digest)
    &&DIGEST.test(receipt.result_digest)&&canonicalJson(receipt.result)===canonicalJson(result),'OWNER_FORGET_RECEIPT_BINDING_REQUIRED')
  const resultDigest=await digest('aukora-prime.memory-result.v1',result)
  if(!stillCurrent(entry))throw fault('OUTCOME_UNKNOWN','OWNER_FORGET_OWNER_CHANGED')
  requireValue(receipt.result_digest===resultDigest,'OWNER_FORGET_RESULT_DIGEST_REQUIRED')
  if(binding.operation){
    const requestDigest=await digest('aukora-prime.memory.effect.v1',{version:1,action_type:'memory.forget',
      owner_subject:binding.operation.target_identity.owner_subject,operation_id:binding.operation_id,
      operation_digest:binding.operation_digest,parameters:binding.operation.canonical_parameters})
    if(!stillCurrent(entry))throw fault('OUTCOME_UNKNOWN','OWNER_FORGET_OWNER_CHANGED')
    requireValue(receipt.request_digest===requestDigest,'OWNER_FORGET_REQUEST_DIGEST_REQUIRED')
  }
  if(reply.receipt_digest!==undefined){
    const receiptDigest=await digest('aukora-prime.memory-receipt.v1',receipt)
    if(!stillCurrent(entry))throw fault('OUTCOME_UNKNOWN','OWNER_FORGET_OWNER_CHANGED')
    requireValue(reply.receipt_digest===receiptDigest,'OWNER_FORGET_RECEIPT_DIGEST_REQUIRED')
  }
}
const entryBinding=entry=>({operation_id:entry.operation.operation_id,operation_digest:entry.digest,task_id:entry.operation.task_id,record_id:entry.request.record_id,
  owner_subject:entry.operation.target_identity.owner_subject,grant_id:entry.grant_id,operation:entry.operation})
async function forgottenReply(value,entry,stillCurrent){
  const reply=closed(copy(value),['ok','result','receipt','authority_settlement','reconciliation_required'],['receipt_digest','settlement_reason'])
  requireValue(reply.ok===true,'OWNER_FORGET_REPLY_REQUIRED')
  requireValue((reply.authority_settlement==='completed'&&reply.reconciliation_required===false&&DIGEST.test(reply.receipt_digest))
    ||(reply.authority_settlement==='pending'&&reply.reconciliation_required===true
      &&(reply.receipt_digest===undefined||DIGEST.test(reply.receipt_digest))),'OWNER_FORGET_SETTLEMENT_BINDING_REQUIRED')
  if(reply.settlement_reason!==undefined)requireValue(text(reply.settlement_reason,1024),'OWNER_FORGET_SETTLEMENT_REASON_REQUIRED')
  await receiptFacts(reply,entry,stillCurrent,entryBinding(entry))
  return immutable(reply)
}
async function recoveryReply(value,entry,stillCurrent,retained){
  const reply=closed(copy(value),['ok','owner_id','owner_subject','task_id','operation_id','operation_digest','action_type','state','reconciliation_required',
    'result','receipt','receipt_digest','authority_settlement','citation','index'])
  requireValue(reply.ok===true&&['idle','known_unsent','saved','forgotten','unknown'].includes(reply.state)
    &&reply.reconciliation_required===(reply.state==='unknown'),'OWNER_FORGET_RECOVERY_REQUIRED')
  requireValue(reply.owner_id===entry.owner.owner_id&&/^aukora:1:[a-f0-9]{64}$/.test(reply.owner_subject)&&text(reply.task_id,1024),
    'OWNER_FORGET_RECOVERY_OWNER_REQUIRED')
  if(reply.state!=='unknown'&&entry.request.operation_id!==null)requireValue(reply.operation_id===entry.request.operation_id,'OWNER_FORGET_RECOVERY_REQUEST_REQUIRED')
  if(retained&&retained.operation_id===reply.operation_id&&retained.operation_digest===reply.operation_digest){
    requireValue((retained.task_id===undefined||retained.task_id===reply.task_id)
      &&(retained.owner_subject===undefined||retained.owner_subject===reply.owner_subject),'OWNER_FORGET_RECOVERY_CONTEXT_REQUIRED')
  }
  if(reply.state==='idle'){
    requireValue(reply.operation_id===null&&reply.operation_digest===null&&reply.action_type===null,'OWNER_FORGET_RECOVERY_IDLE_REQUIRED')
  }else{
    requireValue(text(reply.operation_id,1024)&&DIGEST.test(reply.operation_digest)&&['memory.save','memory.forget'].includes(reply.action_type),'OWNER_FORGET_RECOVERY_REFERENCE_REQUIRED')
  }
  if(['idle','known_unsent','unknown'].includes(reply.state)){
    requireValue(['result','receipt','receipt_digest','authority_settlement','citation','index'].every(key=>reply[key]===null),'OWNER_FORGET_RECOVERY_NO_EFFECT_REQUIRED')
  }else if(reply.state==='forgotten'){
    requireValue(reply.action_type==='memory.forget'&&reply.authority_settlement==='completed'&&DIGEST.test(reply.receipt_digest)
      &&reply.citation===null&&reply.index===null,'OWNER_FORGET_RECOVERY_SETTLEMENT_REQUIRED')
    const binding={operation_id:reply.operation_id,operation_digest:reply.operation_digest,owner_subject:reply.owner_subject}
    if(retained&&retained.operation_id===reply.operation_id&&retained.operation_digest===reply.operation_digest)Object.assign(binding,retained)
    await receiptFacts(reply,entry,stillCurrent,binding)
  }else requireValue(reply.action_type==='memory.save','OWNER_FORGET_RECOVERY_ACTION_REQUIRED')
  return immutable(reply)
}

/** The same adapter's authority belongs to the injected controller. H prepares
 * its exact review after proposeForget; this helper calls raw approve once.
 * Local fences supplement C/D authorization and durable server recovery APIs;
 * they do not persist recovery state or qualify a transport or host. */
export function createOwnerForgetWorkflow({controller,memory,contracts}={}){
  if(['getSnapshot','subscribe','setOperation','approve'].some(name=>typeof controller?.[name]!=='function')
    ||['proposeForget','forget'].some(name=>typeof memory?.[name]!=='function')||typeof contracts?.operationDigest!=='function')throw fault('UNAVAILABLE','OWNER_FORGET_INJECTED_SERVICES_REQUIRED')
  const listeners=new Set(),usedOperations=new Set()
  let state=immutable(initial()),active=null,proposalFlight=null,actionFlight=null,recoveryFlight=null,disposed=false,blocked=false,blockedReference=null,generation=0,owner=controller.getSnapshot().owner
  const publish=patch=>{if(disposed)return;state=immutable({...state,...patch});for(const listener of listeners){try{listener()}catch{/* Presentation does not control dispatch. */}}}
  const current=entry=>!disposed&&entry.generation===generation&&controller.getSnapshot().owner===entry.owner
  const ownerReady=()=>{
    const snapshot=controller.getSnapshot()
    if(!snapshot.owner||!text(snapshot.owner.owner_id,1024)||snapshot.authority_available!==true||snapshot.expired===true
      ||!Number.isFinite(Date.parse(snapshot.owner.expiry))||Date.parse(snapshot.owner.expiry)<=Date.now())throw fault('UNAUTHORIZED','OWNER_FORGET_CURRENT_OWNER_REQUIRED')
    return snapshot
  }
  const refuse=(code='UNAVAILABLE')=>{publish({error_code:code});return Promise.resolve(state)}
  const reference=entry=>entry?.operation?immutable({operation_id:entry.operation.operation_id,operation_digest:entry.digest,action_type:'memory.forget',
    task_id:entry.operation.task_id,record_id:entry.request.record_id,owner_id:entry.owner.owner_id,
    owner_subject:entry.operation.target_identity.owner_subject,...(entry.grant_id?{grant_id:entry.grant_id}:{})}):null
  const sameReference=(value,ref)=>ref&&value.operation_id===ref.operation_id&&value.operation_digest===ref.operation_digest&&value.action_type===ref.action_type
    &&(ref.task_id===undefined||value.task_id===ref.task_id)&&(ref.owner_subject===undefined||value.owner_subject===ref.owner_subject)
  function unknown(entry){
    blocked=true;blockedReference??=reference(entry)
    if(current(entry))publish({phase:'outcome_unknown',approval:entry.proofReceived?'approved':'unknown',forget:entry.invoked?'unknown':'not_attempted',
      forgotten:entry.invoked?null:false,reconciliation_required:true,error_code:'OUTCOME_UNKNOWN'})
    return state
  }
  function cleared(phase){
    const entry=actionFlight?.entry??active,confirmed=entry?.confirmed??(state.forgotten===true?{authority_settlement:state.authority_settlement}:null)
    if(entry?.approvalUncertain||entry?.proofReceived||entry?.invoked||state.reconciliation_required){
      if(!confirmed||state.reconciliation_required)blocked=true
      if(blocked)blockedReference??=reference(entry)
    }
    return {...initial(),phase:blocked&&!confirmed?'outcome_unknown':phase,approval:confirmed||entry?.proofReceived?'approved':blocked?'unknown':'not_requested',
      forget:confirmed?'forgotten':entry?.invoked?'unknown':'not_attempted',forgotten:confirmed?true:entry?.invoked?null:false,
      authority_settlement:confirmed?.authority_settlement??null,reconciliation_required:blocked,error_code:blocked?'RECONCILIATION_REQUIRED':null}
  }
  const off=controller.subscribe(()=>{
    const next=controller.getSnapshot().owner
    if(next===owner)return
    const reset=cleared('idle');owner=next;generation++;active=null;publish(reset)
  })

  const api={
    getSnapshot:()=>state,
    subscribe(listener){if(typeof listener!=='function')throw new TypeError('INVALID: owner forget listener');if(disposed)return ()=>{};listeners.add(listener);return ()=>listeners.delete(listener)},
    proposeForget(input){
      if(disposed)return Promise.resolve(state)
      if(blocked)return refuse('RECONCILIATION_REQUIRED')
      if(actionFlight||recoveryFlight)return refuse()
      let request,snapshot
      try{request=requestOf(input);snapshot=ownerReady()}catch(error){publish({phase:'refused',error_code:errorCode(error)});return Promise.resolve(state)}
      if(proposalFlight)return current(proposalFlight.entry)&&request.record_id===proposalFlight.entry.request.record_id?proposalFlight.promise:refuse()
      const entry={request,owner:snapshot.owner,generation,approvalUncertain:false,proofReceived:false,invoked:false,confirmed:null},flight={entry,promise:null}
      proposalFlight=flight;active=null
      flight.promise=Promise.resolve().then(async()=>{
        try{
          if(!current(entry))return state
          ownerReady();publish({...initial(),phase:'proposal_pending'})
          if(!current(entry))return state
          ownerReady();const value=await memory.proposeForget(request)
          if(!current(entry))return state
          if(value?.ok!==true)throw fault(errorCode(value),'OWNER_FORGET_PROPOSAL_REFUSED')
          const proposed=proposalOf(value,entry),digest=await contracts.operationDigest(proposed.operation)
          if(!current(entry))return state
          ownerReady();requireValue(digest===proposed.operation_digest&&DIGEST.test(digest),'OWNER_FORGET_OPERATION_DIGEST_REQUIRED')
          if(usedOperations.has(proposed.operation.operation_id))throw fault('REPLAYED','OWNER_FORGET_OPERATION_ALREADY_USED')
          Object.assign(entry,{operation:proposed.operation,summary:proposed.record_summary,digest,operation_json:canonicalJson(proposed.operation)})
          controller.setOperation(entry.operation,{recordSummary:entry.summary})
          if(!current(entry))return state
          active=entry;publish({phase:'proposed',operation:entry.operation,record_summary:entry.summary,operation_digest:digest,error_code:null})
          return state
        }catch(error){if(current(entry))publish({phase:'refused',error_code:errorCode(error)});return state}
        finally{if(proposalFlight===flight)proposalFlight=null}
      })
      return flight.promise
    },
    approveAndForget(){
      if(disposed)return Promise.resolve(state)
      if(actionFlight)return actionFlight.promise
      if(blocked)return refuse('RECONCILIATION_REQUIRED')
      if(proposalFlight||recoveryFlight||!active)return refuse()
      const entry=active
      if(entry.proofReceived||entry.invoked||usedOperations.has(entry.operation.operation_id))return refuse('REPLAYED')
      try{
        const snapshot=ownerReady(),view=snapshot.presentation
        requireValue(current(entry)&&snapshot.phase==='review_ready'&&view&&canonicalJson(view.operation)===entry.operation_json
          &&view.operation_digest===entry.digest&&Date.parse(entry.operation.expiry)>Date.now(),'OWNER_FORGET_EXACT_REVIEW_REQUIRED')
      }catch(error){publish({phase:'refused',error_code:errorCode(error)});return Promise.resolve(state)}
      const flight={entry,promise:null};actionFlight=flight
      flight.promise=Promise.resolve().then(async()=>{
        try{
          if(!current(entry))return state
          ownerReady();publish({phase:'approval_pending',approval:'pending',error_code:null})
          if(!current(entry))return state
          ownerReady();entry.approvalUncertain=true;const approved=await controller.approve()
          if(approved)entry.proofReceived=true
          if(!current(entry))return unknown(entry)
          if(!approved){
            const snapshot=controller.getSnapshot(),code=errorCode(snapshot)
            if(snapshot.phase==='outcome_unknown'||uncertainCodes.has(code))return unknown(entry)
            entry.approvalUncertain=false;publish({phase:'refused',approval:'refused',error_code:code});return state
          }
          const answer=closed(copy(approved),['status','approval_proof']),proof=answer.approval_proof
          validateContract('ApprovalProof',proof)
          const snapshot=ownerReady(),view=snapshot.presentation
          requireValue(answer.status==='APPROVED'&&snapshot.phase==='approved'&&view&&canonicalJson(view.operation)===entry.operation_json
            &&view.operation_digest===entry.digest&&proof.operation_id===entry.operation.operation_id&&proof.operation_digest===entry.digest
            &&proof.owner_id===entry.operation.owner_id&&proof.owner_id===entry.owner.owner_id&&proof.audience===entry.operation.audience
            &&proof.authorization_epoch===entry.operation.authorization_epoch&&Date.parse(proof.expiry)>Date.now()
            &&Date.parse(proof.expiry)<=Date.parse(entry.operation.expiry)&&Date.parse(entry.operation.expiry)>Date.now(),'OWNER_FORGET_EXACT_APPROVAL_REQUIRED')
          entry.approvalUncertain=false;entry.grant_id='grant:'+proof.nonce;usedOperations.add(entry.operation.operation_id)
          publish({approval:'approved'})
          if(!current(entry))return state
          ownerReady();publish({phase:'forget_pending',forget:'pending',forgotten:null})
          if(!current(entry))return state
          ownerReady();entry.invoked=true
          const value=await memory.forget({operation:entry.operation,approval_proof:immutable(proof)})
          if(!current(entry))return unknown(entry)
          if(value?.ok!==true)return unknown(entry)
          const confirmed=await forgottenReply(value,entry,current)
          if(!current(entry))return unknown(entry)
          entry.confirmed=confirmed
          if(confirmed.reconciliation_required){blocked=true;blockedReference??=reference(entry)}
          publish({phase:'forgotten',forget:'forgotten',forgotten:true,result:confirmed.result,receipt:confirmed.receipt,
            receipt_digest:confirmed.receipt_digest??null,authority_settlement:confirmed.authority_settlement,
            reconciliation_required:confirmed.reconciliation_required,error_code:confirmed.reconciliation_required?'RECONCILIATION_REQUIRED':null})
          return state
        }catch(error){
          if(entry.proofReceived||entry.invoked||entry.approvalUncertain&&uncertainCodes.has(errorCode(error)))return unknown(entry)
          entry.approvalUncertain=false;if(current(entry))publish({phase:'refused',approval:'refused',error_code:errorCode(error)});return state
        }finally{if(actionFlight===flight)actionFlight=null}
      })
      return flight.promise
    },
    recover(input={operation_id:null}){
      if(disposed)return Promise.resolve(state)
      if(actionFlight||proposalFlight)return refuse()
      if(typeof memory.recover!=='function')return refuse()
      let request,snapshot
      try{
        request=closed(copy(input),['operation_id'])
        requireValue(request.operation_id===null||text(request.operation_id,1024),'OWNER_FORGET_RECOVERY_REFERENCE_REQUIRED')
        snapshot=ownerReady()
        if(blockedReference&&blockedReference.owner_id!==snapshot.owner.owner_id)return refuse('RECONCILIATION_REQUIRED')
        if(blockedReference){
          if(request.operation_id!==null&&request.operation_id!==blockedReference.operation_id)return refuse('RECONCILIATION_REQUIRED')
          request.operation_id=blockedReference.operation_id
        }
        immutable(request)
      }catch(error){return refuse(errorCode(error))}
      if(recoveryFlight)return current(recoveryFlight.entry)&&request.operation_id===recoveryFlight.request.operation_id?recoveryFlight.promise:refuse()
      const retained=active?.operation&&active.owner.owner_id===snapshot.owner.owner_id?entryBinding(active):blockedReference
      const entry={owner:snapshot.owner,generation,request},flight={entry,request,promise:null};recoveryFlight=flight
      flight.promise=Promise.resolve().then(async()=>{
        try{
          if(!current(entry))return state
          ownerReady();publish({recovery_status:'pending',error_code:null})
          if(!current(entry))return state
          ownerReady();const value=await memory.recover(request)
          if(!current(entry))return state
          ownerReady()
          if(value?.ok!==true)throw fault(errorCode(value),'OWNER_FORGET_RECOVERY_REFUSED')
          const recovered=await recoveryReply(value,entry,current,retained)
          if(!current(entry))return state
          ownerReady()
          const patch={recovery_status:recovered.state,recovery_operation_id:recovered.operation_id,recovery_operation_digest:recovered.operation_digest}
          if(recovered.state==='unknown'||recovered.action_type==='memory.save'||blocked&&(recovered.state==='idle'||!sameReference(recovered,blockedReference))){
            blocked=true
            if(!blockedReference&&recovered.operation_id!==null)blockedReference=sameReference(recovered,reference(active))?reference(active):immutable({operation_id:recovered.operation_id,
              operation_digest:recovered.operation_digest,action_type:recovered.action_type,owner_id:entry.owner.owner_id,
              owner_subject:recovered.owner_subject,task_id:recovered.task_id})
            const uncertainForget=state.forgotten!==true&&recovered.state==='unknown'&&recovered.action_type==='memory.forget'
            publish({...patch,...(uncertainForget?{approval:'unknown',forget:'unknown',forgotten:null}:{}),
              phase:state.forgotten===true?'forgotten':'outcome_unknown',reconciliation_required:true,error_code:'RECONCILIATION_REQUIRED'})
            return state
          }
          if(recovered.state==='forgotten'){
            usedOperations.add(recovered.operation_id);blocked=false;blockedReference=null
            if(!active||active.operation.operation_id!==recovered.operation_id)active=null
            else active.confirmed=immutable({result:recovered.result,receipt:recovered.receipt,receipt_digest:recovered.receipt_digest,
              authority_settlement:'completed',reconciliation_required:false})
            publish({...(!active?initial():{}),...patch,phase:'forgotten',approval:'approved',forget:'forgotten',forgotten:true,
              result:recovered.result,receipt:recovered.receipt,receipt_digest:recovered.receipt_digest,authority_settlement:'completed',
              reconciliation_required:false,error_code:null})
          }else{
            if(recovered.operation_id!==null)usedOperations.add(recovered.operation_id)
            blocked=false;blockedReference=null;active=null
            publish({...initial(),...patch})
          }
          return state
        }catch(error){
          if(current(entry))publish({recovery_status:'refused',error_code:blocked?'RECONCILIATION_REQUIRED':errorCode(error)})
          return state
        }finally{if(recoveryFlight===flight)recoveryFlight=null}
      })
      return flight.promise
    },
    dispose(){
      if(disposed)return
      const reset=cleared('unavailable');disposed=true;generation++;active=null;off()
      state=immutable({...reset,error_code:reset.error_code??'UNAVAILABLE'})
      for(const listener of listeners){try{listener()}catch{}}
      listeners.clear()
    },
  }
  return Object.freeze(api)
}
