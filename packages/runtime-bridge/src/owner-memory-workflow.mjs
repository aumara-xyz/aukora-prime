// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe owner action seam. H injects the existing authenticated adapter;
// B owns the controller, signer, review display and approval-action hook.
import {canonicalJson,validateContract,ERROR_CODES} from '../../contracts/src/shared.mjs'
import {validateCaptureDraft,validateCaptureReview} from '../../memory/src/capture-review.mjs'
import {validatePilotMetadata} from './pilot-capture.mjs'

const DIGEST=/^sha256:[a-f0-9]{64}$/, HEX=/^[a-f0-9]{64}$/
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
const codes=new Set(ERROR_CODES)
const fault=(code,reason)=>Object.assign(new Error(reason),{code})
const requireValue=(condition,reason)=>{if(!condition)throw fault('INVALID',reason)}
function closed(value,required,optional=[]){requireValue(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).every(key=>[...required,...optional].includes(key))&&required.every(key=>Object.hasOwn(value,key)),'OWNER_MEMORY_CLOSED_FIELDS_REQUIRED');return value}
const copy=value=>JSON.parse(canonicalJson(value))
function immutable(value){if(value&&typeof value==='object'){for(const child of Object.values(value))immutable(child);Object.freeze(value)}return value}
const boundedString=(value,max)=>typeof value==='string'&&value.length>0&&new TextEncoder().encode(value).length<=max
const errorCode=value=>codes.has(value?.error_code)?value.error_code:codes.has(value?.code)?value.code:'UNAVAILABLE'
async function recoveryReply(value,owner){
  const reply=copy(closed(value,['ok','owner_id','owner_subject','task_id','operation_id','operation_digest','action_type','state','reconciliation_required','result','receipt','receipt_digest','authority_settlement','citation','index']))
  requireValue(reply.ok===true&&['idle','known_unsent','saved','forgotten','unknown'].includes(reply.state)
    &&reply.reconciliation_required===(reply.state==='unknown')&&reply.owner_id===owner.owner_id
    &&/^aukora:1:[a-f0-9]{64}$/.test(reply.owner_subject)&&boundedString(reply.task_id,1024),'OWNER_MEMORY_RECOVERY_REQUIRED')
  requireValue(reply.state==='idle'?[reply.operation_id,reply.operation_digest,reply.action_type].every(value=>value===null)
    :boundedString(reply.operation_id,1024)&&DIGEST.test(reply.operation_digest)&&['memory.save','memory.forget'].includes(reply.action_type),'OWNER_MEMORY_RECOVERY_REFERENCE_REQUIRED')
  if(!['saved','forgotten'].includes(reply.state)){
    requireValue(['result','receipt','receipt_digest','authority_settlement','citation','index'].every(key=>reply[key]===null),'OWNER_MEMORY_RECOVERY_NO_EFFECT_REQUIRED')
    return immutable(reply)
  }
  const record=reply.result,receipt=reply.receipt
  closed(receipt,['version','kind','operation_id','operation_digest','grant_id','request_id','request_digest','owner_subject','action_type','status','result_digest','result'])
  requireValue(reply.action_type===(reply.state==='saved'?'memory.save':'memory.forget')&&receipt.version===1&&receipt.kind==='prime-memory-effect/v1'
    &&receipt.operation_id===reply.operation_id&&receipt.operation_digest===reply.operation_digest&&DIGEST.test(reply.operation_digest)
    &&receipt.owner_subject===reply.owner_subject&&receipt.action_type===reply.action_type&&receipt.status==='applied'
    &&UUID.test(receipt.request_id)&&DIGEST.test(receipt.request_digest)&&DIGEST.test(receipt.result_digest)
    &&record.grants_authority===false&&canonicalJson(receipt.result)===canonicalJson(record)
    &&reply.authority_settlement==='completed'&&DIGEST.test(reply.receipt_digest),'OWNER_MEMORY_RECOVERY_BINDING_REQUIRED')
  if(reply.state==='saved'){
    validateContract('MemoryRecord',record)
    requireValue(record.owner_subject===reply.owner_subject&&record.task_id===reply.task_id&&record.storage_status==='saved','OWNER_MEMORY_RECOVERY_RECORD_REQUIRED')
  }else requireValue(record.state==='tombstoned'&&boundedString(record.record_id,1024)&&record.canonical_payload_retained===true
    &&record.physical_media_erasure===false&&record.authority_approval_history_erased===false&&record.backups_erased===false&&record.wal_erased===false
    &&reply.index===null&&reply.citation===null,'OWNER_MEMORY_RECOVERY_FORGET_REQUIRED')
  const digest=async(domain,data)=>'sha256:'+Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',new TextEncoder().encode(domain+'\0'+canonicalJson(data)))),byte=>byte.toString(16).padStart(2,'0')).join('')
  requireValue(receipt.result_digest===await digest('aukora-prime.memory-result.v1',record)
    &&reply.receipt_digest===await digest('aukora-prime.memory-receipt.v1',receipt),'OWNER_MEMORY_RECOVERY_DIGEST_REQUIRED')
  const saved={record},entry={saved}
  if(reply.index!==null){try{reply.index=indexReply({ok:true,...reply.index},entry)}catch{reply.index=null}}
  if(reply.citation!==null){try{reply.citation=citeReply({ok:true,citation:reply.citation},entry)}catch{reply.citation=null}}
  return immutable(reply)
}
const initial=()=>({phase:'idle',operation:null,memory_capture:null,operation_digest:null,approval:'not_requested',save:'not_attempted',saved:false,
  record:null,receipt:null,receipt_digest:null,citation:null,citation_status:'not_requested',index:{status:'unconfirmed',indexed:null,searchable:null},authority_settlement:null,
  reconciliation_required:false,error_code:null,read_error_code:null})

function draftOf(input){
  const draft=copy(closed(input,['extraction_json','idempotency_key']))
  requireValue(boundedString(draft.extraction_json,16_384)&&boundedString(draft.idempotency_key,1024),'OWNER_MEMORY_DRAFT_BOUND')
  const extraction=JSON.parse(draft.extraction_json)
  requireValue(extraction&&typeof extraction==='object'&&!Array.isArray(extraction)&&typeof extraction.statement==='string','OWNER_MEMORY_STATEMENT_REQUIRED')
  return immutable(draft)
}
function savedReply(reply,entry){
  const result=copy(closed(reply,['ok','record','receipt','authority_settlement','reconciliation_required'],['receipt_digest','settlement_reason']))
  requireValue(result.ok===true,'OWNER_MEMORY_SAVE_REPLY_REQUIRED')
  const record=result.record,receipt=result.receipt,operation=entry.operation
  validateContract('MemoryRecord',record)
  requireValue(record.storage_status==='saved'&&record.grants_authority===false&&record.owner_subject===operation.target_identity.owner_subject&&record.task_id===operation.task_id,'OWNER_MEMORY_SAVED_RECORD_BINDING_REQUIRED')
  const original=JSON.parse(record.canonical_bytes)
  requireValue(original.statement===entry.memory_capture.statement&&original.attributedTo===entry.memory_capture.attributed_to,'OWNER_MEMORY_SAVED_LITERAL_BINDING_REQUIRED')
  closed(receipt,['version','kind','operation_id','operation_digest','grant_id','request_id','request_digest','owner_subject','action_type','status','result_digest','result'])
  requireValue(receipt.version===1&&receipt.kind==='prime-memory-effect/v1'&&receipt.operation_id===operation.operation_id&&receipt.operation_digest===entry.digest
    &&receipt.owner_subject===record.owner_subject&&receipt.action_type==='memory.save'&&receipt.status==='applied'&&receipt.grant_id===entry.grant_id
    &&UUID.test(receipt.request_id)&&DIGEST.test(receipt.request_digest)&&DIGEST.test(receipt.result_digest)&&canonicalJson(receipt.result)===canonicalJson(record),'OWNER_MEMORY_RECEIPT_BINDING_REQUIRED')
  requireValue((result.authority_settlement==='completed'&&result.reconciliation_required===false&&DIGEST.test(result.receipt_digest))
    ||(result.authority_settlement==='pending'&&result.reconciliation_required===true),'OWNER_MEMORY_SETTLEMENT_BINDING_REQUIRED')
  return immutable(result)
}
function indexReply(reply,entry){
  const result=copy(closed(reply,['ok','record','saved','indexed','searchable','index_status']))
  validateContract('MemoryRecord',result.record)
  requireValue(result.ok===true&&result.saved===true&&typeof result.indexed==='boolean'&&typeof result.searchable==='boolean'
    &&['pending','failed','indexed','searchable'].includes(result.index_status)&&result.record.index_status===result.index_status
    &&result.indexed===['indexed','searchable'].includes(result.index_status)&&result.searchable===(result.index_status==='searchable')
    &&canonicalJson({...result.record,index_status:entry.saved.record.index_status})===canonicalJson(entry.saved.record),'OWNER_MEMORY_STATUS_BINDING_REQUIRED')
  return immutable({status:result.index_status,indexed:result.indexed,searchable:result.searchable})
}
function citeReply(reply,entry){
  closed(reply,['ok','citation']);const citation=copy(reply.citation),record=entry.saved.record
  closed(citation,['record_id','revision','chain_domain','chain_sequence','aura_entry_hash','verified_head','verdict','grants_authority'],['reason','source_digest','source_span','source_span_integrity'])
  requireValue(reply.ok===true&&citation.record_id===record.record_id&&citation.revision===record.revision&&citation.chain_domain===record.chain_domain
    &&Number.isSafeInteger(citation.chain_sequence)&&citation.chain_sequence>0&&HEX.test(citation.aura_entry_hash)&&HEX.test(citation.verified_head)
    &&['VERIFIED','UNVERIFIED','MISSING'].includes(citation.verdict)&&citation.grants_authority===false,'OWNER_MEMORY_CITATION_BINDING_REQUIRED')
  if(citation.verdict==='VERIFIED')requireValue('sha256:'+citation.source_digest===record.source_event_digest&&canonicalJson(citation.source_span)===canonicalJson(record.source_span),'OWNER_MEMORY_CITATION_SOURCE_REQUIRED')
  return immutable(citation)
}

/** Pair this memory facade with the same adapter instance's authority in B's
 * controller. This helper creates no transport, owner/session/source context,
 * proof, receipt, enrollment or qualification. Methods resolve frozen snapshots. */
export function createOwnerMemoryWorkflow({controller,memory,contracts}={}){
  if(['getSnapshot','subscribe','setOperation','approve'].some(name=>typeof controller?.[name]!=='function')
    ||['proposeSave','save','status','cite'].some(name=>typeof memory?.[name]!=='function')||typeof contracts?.operationDigest!=='function')throw fault('UNAVAILABLE','OWNER_MEMORY_INJECTED_SERVICES_REQUIRED')
  const listeners=new Set(),usedKeys=new Set()
  let state=immutable(initial()),active=null,proposalFlight=null,actionFlight=null,readFlight=null,disposed=false,blocked=false,blockedRef=null,generation=0,owner=controller.getSnapshot().owner
  const publish=patch=>{if(disposed)return;state=immutable({...state,...patch});for(const listener of listeners){try{listener()}catch{ /* Presentation listeners cannot change dispatch. */ }} }
  const current=entry=>!disposed&&entry.generation===generation&&controller.getSnapshot().owner===entry.owner
  const ownerReady=()=>{const snapshot=controller.getSnapshot();if(!snapshot.owner||snapshot.authority_available!==true||snapshot.expired===true||Date.parse(snapshot.owner.expiry)<=Date.now())throw fault('UNAUTHORIZED','OWNER_MEMORY_CURRENT_OWNER_REQUIRED');return snapshot}
  const unavailable=()=>{publish({error_code:'UNAVAILABLE'});return Promise.resolve(state)}
  const refuse=(code='INVALID')=>{publish({error_code:code});return Promise.resolve(state)}
  const unknown=entry=>{blocked=true;if(entry.operation)blockedRef={operation_id:entry.operation.operation_id,digest:entry.digest,owner_id:entry.owner.owner_id};if(current(entry))publish({phase:'outcome_unknown',save:entry.attempted?'unknown':state.save,saved:entry.attempted?null:state.saved,
    approval:entry.attempted?'approved':'unknown',reconciliation_required:true,error_code:'OUTCOME_UNKNOWN'});return state}
  function cleared(phase){
    const confirmed=actionFlight?.entry.saved??active?.saved??(state.save==='saved'&&state.saved===true?{authority_settlement:state.authority_settlement}:null)
    const uncertain=(actionFlight?.entry.attempted===true&&!confirmed)||(state.save==='unknown'&&state.saved===null)
    if(uncertain)blocked=true
    if(blocked&&!blockedRef){const entry=actionFlight?.entry??active;if(entry?.operation)blockedRef={operation_id:entry.operation.operation_id,digest:entry.digest,owner_id:entry.owner.owner_id}}
    // Hide the previous owner's record/receipt while retaining content-free
    // facts. Ending a session during reads cannot undo a confirmed save.
    return {...initial(),phase:blocked&&!confirmed?'outcome_unknown':phase,approval:confirmed||uncertain?'approved':blocked?'unknown':'not_requested',
      save:confirmed?'saved':uncertain?'unknown':'not_attempted',saved:confirmed?true:uncertain?null:false,
      authority_settlement:confirmed?.authority_settlement??null,reconciliation_required:blocked,error_code:blocked?'RECONCILIATION_REQUIRED':null}
  }
  const off=controller.subscribe(()=>{
    const next=controller.getSnapshot().owner
    if(next===owner)return
    const reset=cleared('idle');owner=next;generation++;active=null;publish(reset)
  })

  async function readSaved(entry){
    if(!current(entry))return state
    const read={record_id:entry.saved.record.record_id,revision:entry.saved.record.revision}
    publish({citation_status:'pending',read_error_code:null})
    if(!current(entry))return state
    const answers=await Promise.allSettled([Promise.resolve().then(()=>memory.status(read)),Promise.resolve().then(()=>memory.cite({...read,retained_head:entry.citation?.verified_head??null}))])
    if(!current(entry))return state
    let failed=null
    for(const [index,answer] of answers.entries()){
      if(!current(entry))return state
      try{
        if(answer.status==='rejected')throw answer.reason
        if(answer.value?.ok!==true)throw fault(errorCode(answer.value),'OWNER_MEMORY_READ_UNAVAILABLE')
        if(index===0)publish({index:indexReply(answer.value,entry)})
        else{entry.citation=citeReply(answer.value,entry);publish({citation:entry.citation,citation_status:entry.citation.verdict.toLowerCase()})}
      }catch(error){failed=errorCode(error);if(index===1)publish({citation_status:'unavailable'})}
    }
    if(!current(entry))return state
    publish({read_error_code:failed});return state
  }

  const api={
    getSnapshot:()=>state,
    /** Fixed server pilot metadata, separate from the B save-result contract. */
    getCaptureMetadata:()=>active&&current(active)?active.metadata??null:null,
    subscribe(listener){if(typeof listener!=='function')throw new TypeError('INVALID: owner memory listener');if(disposed)return ()=>{};listeners.add(listener);return ()=>listeners.delete(listener)},
    proposeSave(input){
      if(disposed)return unavailable()
      if(blocked)return refuse('RECONCILIATION_REQUIRED')
      if(actionFlight||readFlight)return refuse('UNAVAILABLE')
      let draft,snapshot
      try{draft=draftOf(input);snapshot=ownerReady()}catch(error){publish({phase:'refused',error_code:errorCode(error)});return Promise.resolve(state)}
      if(proposalFlight)return canonicalJson(draft)===canonicalJson(proposalFlight.entry.draft)?proposalFlight.promise:refuse('UNAVAILABLE')
      if(usedKeys.has(draft.idempotency_key))return refuse('REPLAYED')
      const entry={draft,owner:snapshot.owner,generation,attempted:false},flight={entry,promise:null};proposalFlight=flight;active=null
      flight.promise=Promise.resolve().then(async()=>{
        try{
          if(!current(entry))return state
          publish({...initial(),phase:'proposal_pending'})
          if(!current(entry))return state
          const proposed=await memory.proposeSave(draft)
          if(!current(entry))return state
          if(proposed?.ok!==true)throw fault(errorCode(proposed),'OWNER_MEMORY_PROPOSAL_REFUSED')
          const operation=immutable(copy(proposed.operation)),capture=immutable(validateCaptureDraft(copy(proposed.memory_capture)))
          validateContract('OperationProposal',operation);closed(operation.target_identity,['kind','owner_subject'])
          requireValue(operation.action_type==='memory.save'&&operation.audience==='aukora-prime.memory'&&operation.target_identity.kind==='prime-memory'&&operation.owner_id===entry.owner.owner_id,'OWNER_MEMORY_OPERATION_BINDING_REQUIRED')
          requireValue(capture.statement===JSON.parse(draft.extraction_json).statement,'OWNER_MEMORY_REQUESTED_LITERAL_REQUIRED');validateCaptureReview(operation.canonical_parameters,capture)
          const digest=await contracts.operationDigest(operation)
          if(!current(entry))return state
          requireValue(DIGEST.test(digest),'OWNER_MEMORY_OPERATION_DIGEST_REQUIRED')
          const metadata=proposed.capture_metadata?validatePilotMetadata(copy(proposed.capture_metadata)):null
          Object.assign(entry,{operation,memory_capture:capture,digest,operation_json:canonicalJson(operation),metadata})
          controller.setOperation(operation,{memoryCapture:capture})
          if(!current(entry))return state
          active=entry
          publish({phase:'proposed',operation,memory_capture:capture,operation_digest:digest,error_code:null});return state
        }catch(error){if(current(entry))publish({phase:'refused',error_code:errorCode(error)});return state}
        finally{if(proposalFlight===flight)proposalFlight=null}
      });return flight.promise
    },
    approveAndSave(){
      if(disposed)return unavailable()
      if(actionFlight)return actionFlight.promise
      if(blocked)return refuse('RECONCILIATION_REQUIRED')
      if(proposalFlight||readFlight||!active)return refuse('UNAVAILABLE')
      const entry=active
      if(entry.attempted)return refuse('REPLAYED')
      try{
        const snapshot=ownerReady(),view=snapshot.presentation
        requireValue(current(entry)&&snapshot.phase==='review_ready'&&view&&canonicalJson(view.operation)===entry.operation_json&&view.operation_digest===entry.digest,'OWNER_MEMORY_EXACT_REVIEW_REQUIRED')
        validateCaptureReview(entry.operation.canonical_parameters,{statement:view.memory_review?.statement,attributed_to:view.memory_review?.attributed_to})
        requireValue(view.memory_review.capture_sha256===entry.operation.canonical_parameters.capture_sha256,'OWNER_MEMORY_EXACT_REVIEW_CAPTURE_REQUIRED')
      }catch(error){publish({phase:'refused',error_code:errorCode(error)});return Promise.resolve(state)}
      const flight={entry,promise:null};actionFlight=flight
      flight.promise=Promise.resolve().then(async()=>{
        try{
          if(!current(entry))return state
          publish({phase:'approval_pending',approval:'pending',error_code:null})
          if(!current(entry))return state
          // Direct controller API: calling B's submitApproval hook here recurses.
          const approved=await controller.approve()
          if(!current(entry))return state
          if(!approved){const snapshot=controller.getSnapshot();if(snapshot.phase==='outcome_unknown')return unknown(entry);publish({phase:'refused',approval:'refused',error_code:codes.has(snapshot.error_code)?snapshot.error_code:'UNAVAILABLE'});return state}
          entry.approvalReturned=true
          const result=copy(closed(approved,['status','approval_proof'])),proof=result.approval_proof
          validateContract('ApprovalProof',proof)
          const snapshot=ownerReady()
          requireValue(result.status==='APPROVED'&&snapshot.phase==='approved'&&snapshot.presentation&&canonicalJson(snapshot.presentation.operation)===entry.operation_json
            &&proof.operation_id===entry.operation.operation_id&&proof.operation_digest===entry.digest&&proof.owner_id===entry.operation.owner_id
            &&proof.audience===entry.operation.audience&&proof.authorization_epoch===entry.operation.authorization_epoch
            &&Date.parse(proof.expiry)>Date.now()&&Date.parse(proof.expiry)<=Date.parse(entry.operation.expiry),'OWNER_MEMORY_EXACT_APPROVAL_REQUIRED')
          publish({approval:'approved'})
          if(!current(entry))return state
          entry.grant_id='grant:'+proof.nonce
          publish({phase:'save_pending',save:'pending',saved:null})
          if(!current(entry))return state
          entry.attempted=true;usedKeys.add(entry.draft.idempotency_key)
          const reply=await memory.save({...entry.draft,operation:entry.operation,approval_proof:proof})
          if(!current(entry))return state
          if(reply?.ok!==true){const code=errorCode(reply);if(['UNAVAILABLE','OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED'].includes(code)||reply?.reconciliation_required===true)return unknown(entry);publish({phase:'refused',save:'refused',saved:false,error_code:code});return state}
          entry.saved=savedReply(reply,entry)
          if(entry.saved.reconciliation_required){blocked=true;blockedRef={operation_id:entry.operation.operation_id,digest:entry.digest,owner_id:entry.owner.owner_id}}
          publish({phase:'saved',save:'saved',saved:true,record:entry.saved.record,receipt:entry.saved.receipt,receipt_digest:entry.saved.receipt_digest??null,index:{status:entry.saved.record.index_status,indexed:null,searchable:null},
            authority_settlement:entry.saved.authority_settlement,reconciliation_required:entry.saved.reconciliation_required,error_code:entry.saved.reconciliation_required?'RECONCILIATION_REQUIRED':null})
          return await readSaved(entry)
        }catch(error){if(entry.attempted||entry.approvalReturned||['OUTCOME_UNKNOWN','RECONCILIATION_REQUIRED'].includes(errorCode(error)))return unknown(entry);if(current(entry))publish({phase:'refused',approval:'refused',error_code:errorCode(error)});return state}
        finally{if(actionFlight===flight)actionFlight=null}
      });return flight.promise
    },
    refresh(){
      if(disposed)return unavailable()
      if(actionFlight)return actionFlight.promise
      if(readFlight)return readFlight.promise
      if(proposalFlight||!active?.saved||!current(active))return refuse('UNAVAILABLE')
      try{ownerReady()}catch(error){return refuse(errorCode(error))}
      const entry=active,flight={promise:null};readFlight=flight
      flight.promise=Promise.resolve().then(()=>readSaved(entry)).finally(()=>{if(readFlight===flight)readFlight=null});return flight.promise
    },
    recover(input={operation_id:null}){
      if(disposed)return unavailable()
      if(actionFlight||proposalFlight)return refuse('UNAVAILABLE')
      if(readFlight)return readFlight.promise
      if(typeof memory.recover!=='function')return refuse('UNAVAILABLE')
      let request,snapshot
      try {
        request=copy(closed(input,['operation_id']));snapshot=ownerReady()
        requireValue(request.operation_id===null||boundedString(request.operation_id,1024),'OWNER_MEMORY_RECOVERY_REFERENCE_REQUIRED')
        // A retained uncertain operation must be resolved by its own durable
        // reference; unrelated history or an empty result cannot clear it.
        if(blockedRef){requireValue(blockedRef.owner_id===snapshot.owner.owner_id,'OWNER_MEMORY_RECOVERY_OWNER_REQUIRED');request.operation_id=blockedRef.operation_id}
      } catch(error){return refuse(errorCode(error))}
      const entry={owner:snapshot.owner,generation},flight={promise:null};readFlight=flight
      flight.promise=Promise.resolve().then(async()=>{
        try {
          const reply=await memory.recover(request)
          if(!current(entry))return state
          if(reply?.ok!==true)throw fault(errorCode(reply),'OWNER_MEMORY_RECOVERY_REFUSED')
          const recovered=await recoveryReply(reply,entry.owner)
          if(!current(entry))return state
          if(recovered.state!=='unknown'&&request.operation_id!==null)requireValue(recovered.operation_id===request.operation_id,'OWNER_MEMORY_RECOVERY_REFERENCE_REQUIRED')
          if(blockedRef&&recovered.state!=='unknown')requireValue(recovered.operation_id===blockedRef.operation_id&&recovered.operation_digest===blockedRef.digest,'OWNER_MEMORY_RECOVERY_RETAINED_REFERENCE_REQUIRED')
          if(recovered.state==='unknown'||blocked&&recovered.state==='idle'){
            if(recovered.state==='unknown'&&!blockedRef)blockedRef={operation_id:recovered.operation_id,digest:recovered.operation_digest,owner_id:recovered.owner_id}
            blocked=true;publish({phase:'outcome_unknown',reconciliation_required:true,error_code:'RECONCILIATION_REQUIRED'});return state
          }
          blocked=false;blockedRef=null;active=null
          if(recovered.state==='saved')publish({...initial(),phase:'saved',approval:'approved',save:'saved',saved:true,
            operation_digest:recovered.operation_digest,record:recovered.result,receipt:recovered.receipt,receipt_digest:recovered.receipt_digest,
            authority_settlement:'completed',citation:recovered.citation,citation_status:recovered.citation?.verdict.toLowerCase()??'unavailable',
            index:recovered.index??{status:recovered.result.index_status,indexed:null,searchable:null},read_error_code:recovered.index===null||recovered.citation===null?'UNAVAILABLE':null})
          else publish({...initial(),phase:'idle'})
          return state
        } catch(error){if(current(entry)){blocked=true;publish({reconciliation_required:true,error_code:errorCode(error)})}return state}
        finally{if(readFlight===flight)readFlight=null}
      });return flight.promise
    },
    async logout(){
      // The controller removes local owner state before the existing adapter
      // revokes C's durable token. Ending access never cancels a dispatched save.
      controller.logout?.()
      if(typeof memory.logout!=='function')return {ok:false,error_code:'UNAVAILABLE',reason:'OWNER_LOGOUT_UNMOUNTED'}
      return memory.logout()
    },
    dispose(){if(disposed)return;const reset=cleared('unavailable');generation++;active=null;off();state=immutable({...reset,error_code:reset.error_code??'UNAVAILABLE'});disposed=true;for(const listener of listeners){try{listener()}catch{}}listeners.clear()},
  }
  return Object.freeze(api)
}
