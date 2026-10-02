// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe injection seam for the existing Prime UI transport. No URLs,
// owner signing material, enrollment or face redesign lives in this adapter.
import {canonicalJson,validateContract} from '../../contracts/src/shared.mjs'
import {validateCaptureDraft,validateCaptureReview} from '../../memory/src/capture-review.mjs'

export function createUiAdapters({call}={}) {
  if(typeof call!=='function')throw new TypeError('UNAVAILABLE: injected bridge call required')
  const reviews=new Map()
  const captures=new Map()
  // Bounded context for factual retries only. C/D and the workflow journal
  // retain replay/receipt evidence; these entries confer no authority.
  const completedCaptures=new Map()
  const forgets=new Map()
  const pendingCaptures=new Set(),pendingReviews=new Set()
  let sessionToken=null,authRevision=0,loginPending=null
  let logoutFlight=null
  const copy=value=>JSON.parse(canonicalJson(value))
  const key=(session,operationId)=>session+'\0'+operationId
  const captureRefusal=()=>({ok:false,error_code:'INVALID',reason:'UI_EXACT_CAPTURE_REQUIRED'})
  const sessionRefusal=()=>({ok:false,error_code:'UNAUTHORIZED',reason:'UI_SESSION_CHANGED'})
  function invalidate(){authRevision++;sessionToken=null;loginPending=null;reviews.clear();captures.clear();completedCaptures.clear();forgets.clear()}
  const sameSession=(revision,session)=>revision===authRevision&&session===sessionToken
  function logout(){
    if(logoutFlight)return logoutFlight
    const current=sessionToken;invalidate()
    if(typeof current!=='string')return Promise.resolve({ok:false,error_code:'UNAUTHORIZED',reason:'UI_NO_OWNER_SESSION'})
    // Remove local access immediately, then revoke this exact real C session.
    // One request only; a lost reply is not proof of server logout.
    const flight=Promise.resolve().then(()=>call('owner.logout',{session_token:current}))
      .then(result=>result?.ok===true&&result.status==='LOGGED_OUT'?result:result?.ok===false?result:{ok:false,error_code:'OUTCOME_UNKNOWN',reason:'UI_OWNER_LOGOUT_NOT_CONFIRMED'},
        ()=>({ok:false,error_code:'OUTCOME_UNKNOWN',reason:'UI_OWNER_LOGOUT_NOT_CONFIRMED'}))
      .finally(()=>{if(logoutFlight===flight)logoutFlight=null})
    logoutFlight=flight;return flight
  }
  function prune(){for(const collection of [captures,forgets,completedCaptures])for(const [id,capture] of collection)if(!capture.attempted&&Date.parse(capture.expiry)<=Date.now()){collection.delete(id);reviews.delete(id)}}
  function requireCapture(session,operation,{completed=false}={}) {
    if(operation.action_type==='memory.forget'){
      const retained=forgets.get(key(session,operation.operation_id))
      if(!retained||retained.operation_json!==canonicalJson(operation))throw new TypeError('INVALID: immutable forget proposal required')
      return retained
    }
    if(operation.action_type!=='memory.save')return
    const id=key(session,operation.operation_id),capture=captures.get(id)??(completed?completedCaptures.get(id):undefined)
    if(!capture||capture.operation_json!==canonicalJson(operation))throw new TypeError('INVALID: immutable memory capture required')
    validateCaptureReview(operation.canonical_parameters,capture.memory_capture)
    return capture
  }
  const digest=async(domain,value)=>'sha256:'+Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(domain+'\0'+canonicalJson(value)))),byte=>byte.toString(16).padStart(2,'0')).join('')
  async function retireCompleted(session,revision,capture,value,{recovered=false}={}) {
    // Only an unchanged, exact completed receipt releases the pending slot.
    // Missing, refused, lost or unsettled replies keep their attempt context.
    try {
      const reply=copy(value),operation=JSON.parse(capture.operation_json),record=recovered?reply.result:reply.record,receipt=reply.receipt
      if(reply.ok!==true||reply.authority_settlement!=='completed'||reply.reconciliation_required!==false
        ||recovered&&(reply.state!=='saved'||reply.operation_id!==operation.operation_id||reply.operation_digest!==receipt?.operation_digest))return
      validateContract('MemoryRecord',record)
      validateContract('OperationProposal',operation)
      const expectedDigest=await digest('aukora-prime.operation.v1',operation)
      const fields=['version','kind','operation_id','operation_digest','grant_id','request_id','request_digest','owner_subject','action_type','status','result_digest','result']
      if(!receipt||Object.keys(receipt).length!==fields.length||fields.some(field=>!Object.hasOwn(receipt,field))
        ||receipt.version!==1||receipt.kind!=='prime-memory-effect/v1'||receipt.operation_id!==operation.operation_id
        ||receipt.operation_digest!==expectedDigest||receipt.grant_id!=='grant:'+capture.proof_nonce
        ||receipt.owner_subject!==operation.target_identity.owner_subject||receipt.action_type!=='memory.save'||receipt.status!=='applied'
        ||!/^([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/i.test(receipt.request_id)
        ||record.owner_subject!==receipt.owner_subject||record.task_id!==operation.task_id||record.storage_status!=='saved'
        ||record.grants_authority!==false||canonicalJson(receipt.result)!==canonicalJson(record))return
      const original=JSON.parse(record.canonical_bytes)
      if(original.statement!==capture.memory_capture.statement||original.attributedTo!==capture.memory_capture.attributed_to)return
      const request={version:1,action_type:'memory.save',owner_subject:receipt.owner_subject,operation_id:operation.operation_id,
        operation_digest:expectedDigest,parameters:operation.canonical_parameters}
      if(receipt.request_digest!==await digest('aukora-prime.memory.effect.v1',request)
        ||receipt.result_digest!==await digest('aukora-prime.memory-result.v1',record)
        ||reply.receipt_digest!==await digest('aukora-prime.memory-receipt.v1',receipt))return
      const id=key(session,operation.operation_id)
      if(!sameSession(revision,session)||captures.get(id)!==capture&&completedCaptures.get(id)!==capture)return
      captures.delete(id);reviews.delete(id);completedCaptures.delete(id)
      completedCaptures.set(id,{...capture,attempted:false})
      while(completedCaptures.size>16)completedCaptures.delete(completedCaptures.keys().next().value)
    }catch{/* Unverified completion cannot release a pending capture. */}
  }
  const authority=Object.freeze({
    logout:()=>logout(),
    async loginChallenge(input) {
      if(logoutFlight)return {ok:false,error_code:'UNAVAILABLE',reason:'UI_OWNER_LOGOUT_PENDING'}
      invalidate();const revision=authRevision
      const result=await call('owner.loginChallenge',copy(input))
      if(revision!==authRevision)return sessionRefusal()
      if(result?.ok===true)loginPending={revision,challenge_json:canonicalJson(result.challenge)}
      return result
    },
    async loginComplete(input) {
      const detached=copy(input),revision=authRevision
      if(loginPending?.revision!==revision||loginPending.challenge_json!==canonicalJson(detached.challenge))return sessionRefusal()
      loginPending=null
      const result=await call('owner.loginComplete',detached)
      if(revision!==authRevision)return sessionRefusal()
      if(result?.ok===true){sessionToken=result.session_token;reviews.clear();captures.clear();completedCaptures.clear();forgets.clear()}
      return result
    },
    async approvalChallenge(input) {
      validateContract('OperationProposal',input.operation)
      prune()
      const revision=authRevision,session=input.session_token
      if(session!==sessionToken)return sessionRefusal()
      try {requireCapture(input.session_token,input.operation)} catch{return captureRefusal()}
      if(reviews.size+pendingReviews.size>=16)return {ok:false,error_code:'UNAVAILABLE',reason:'UI_REVIEW_QUOTA'}
      const detached=copy(input),reservation={revision,session};pendingReviews.add(reservation)
      try {
        const result=await call('owner.approvalChallenge',detached)
        if(!sameSession(revision,session))return sessionRefusal()
        if(result?.ok===true && canonicalJson(result.operation)===canonicalJson(detached.operation))reviews.set(key(session,detached.operation.operation_id),{operation:detached.operation,digest:result.operation_digest})
        return result
      } finally {pendingReviews.delete(reservation)}
    },
    async approvalComplete(input) {
      validateContract('ApprovalProof',input.proof)
      if(input.session_token!==sessionToken)return sessionRefusal()
      const review=reviews.get(key(input.session_token,input.proof.operation_id)),operation=review?.operation
      if(!operation)return {ok:false,error_code:'UNAUTHORIZED',reason:'UI_EXACT_REVIEW_REQUIRED'}
      try {requireCapture(input.session_token,operation)} catch{return captureRefusal()}
      if(input.proof.operation_digest!==review.digest||input.proof.owner_id!==operation.owner_id||input.proof.audience!==operation.audience||input.proof.authorization_epoch!==operation.authorization_epoch)return {ok:false,error_code:'INVALID',reason:'UI_EXACT_PROOF_REQUIRED'}
      // The service and C recheck the entire operation/proof; this attachment
      // only supplies D's scoped observation for the existing UI method shape.
      reviews.delete(key(input.session_token,input.proof.operation_id))
      return call('owner.approvalComplete',copy({...input,operation}))
    },
    async declineApproval(input){if(input.session_token!==sessionToken)return sessionRefusal();const id=key(input.session_token,input.operation_id);reviews.delete(id);if(!captures.get(id)?.attempted)captures.delete(id);if(!forgets.get(id)?.attempted)forgets.delete(id);return call('owner.declineApproval',copy(input))},
    status:input=>call('owner.status',copy(input)),
  })
  const withSession=input=>{
    if(typeof sessionToken!=='string')throw new Error('UNAUTHORIZED: owner login required')
    if(Object.hasOwn(input,'session_token'))throw new TypeError('INVALID: injected session only')
    return copy({...input,session_token:sessionToken})
  }
  const memory=Object.freeze({
    logout:()=>logout(),
    async proposeForget(input){
      prune();if(forgets.size+pendingCaptures.size>=16)return {ok:false,error_code:'UNAVAILABLE',reason:'UI_FORGET_QUOTA'}
      if(!input||Object.keys(input).join(',')!=='record_id'||typeof input.record_id!=='string')return captureRefusal()
      const detached=withSession(input),revision=authRevision,session=detached.session_token,reservation={revision,session};pendingCaptures.add(reservation)
      try{
        const result=await call('memory.proposeForget',detached)
        if(!sameSession(revision,session))return sessionRefusal()
        if(result?.ok===true){
          try{
            validateContract('OperationProposal',result.operation)
            const params=result.operation.canonical_parameters,summary=result.record_summary
            if(result.operation.action_type!=='memory.forget'||params?.profile!=='prime-logical-forget/v1'
              ||params.record_id!==detached.record_id||summary?.record_id!==params.record_id||summary.revision!==params.revision
              ||summary.statement!==params.statement||summary.attributed_to!==params.attributed_to)throw new TypeError('INVALID: exact forget record required')
            forgets.set(key(session,result.operation.operation_id),{operation_json:canonicalJson(result.operation),expiry:result.operation.expiry,record_summary:copy(summary)})
          }catch{return captureRefusal()}
        }
        return result
      }finally{pendingCaptures.delete(reservation)}
    },
    forget(input){
      const detached=withSession(input)
      let retained
      try{
        if(!input||Object.keys(input).sort().join(',')!=='approval_proof,operation'||detached.operation.action_type!=='memory.forget')throw new TypeError('INVALID: approved forget required')
        retained=requireCapture(detached.session_token,detached.operation)
      }catch{return Promise.resolve(captureRefusal())}
      if(retained.attempted)return Promise.resolve({ok:false,error_code:'RECONCILIATION_REQUIRED',reason:'UI_FORGET_ALREADY_ATTEMPTED'})
      retained.attempted=true
      return call('memory.forget',detached)
    },
    async proposeSave(input) {
      prune();if(captures.size+pendingCaptures.size>=16)return {ok:false,error_code:'UNAVAILABLE',reason:'UI_CAPTURE_QUOTA'}
      const detached=withSession(input),revision=authRevision,session=detached.session_token,reservation={revision,session};pendingCaptures.add(reservation)
      try {
        const result=await call('memory.proposeSave',detached)
        if(!sameSession(revision,session))return sessionRefusal()
        if(result?.ok===true) {
          try {
            validateContract('OperationProposal',result.operation)
            const memory_capture=validateCaptureDraft(result.memory_capture)
            if(memory_capture.statement!==JSON.parse(detached.extraction_json).statement)throw new TypeError('INVALID: exact requested statement required')
            validateCaptureReview(result.operation.canonical_parameters,memory_capture)
            captures.set(key(session,result.operation.operation_id),{operation_json:canonicalJson(result.operation),expiry:result.operation.expiry,memory_capture})
          } catch{return captureRefusal()}
        }
        return result
      } finally {pendingCaptures.delete(reservation)}
    },
    async save(input) {
      const detached=withSession(input),revision=authRevision,session=detached.session_token
      let capture
      try {
        capture=requireCapture(session,detached.operation,{completed:true})
        validateContract('ApprovalProof',detached.approval_proof)
        if(!capture||JSON.parse(detached.extraction_json).statement!==capture.memory_capture.statement)throw new TypeError('INVALID: exact capture required')
        if(capture.proof_nonce!==undefined&&capture.proof_nonce!==detached.approval_proof.nonce)throw new TypeError('INVALID: exact original proof required')
      } catch{return captureRefusal()}
      if(capture.attempted)return {ok:false,error_code:'RECONCILIATION_REQUIRED',reason:'UI_SAVE_ALREADY_ATTEMPTED'}
      if(captures.get(key(session,detached.operation.operation_id))===capture)capture.attempted=true
      capture.proof_nonce=detached.approval_proof.nonce
      const result=await call('memory.save',detached)
      await retireCompleted(session,revision,capture,result)
      return result
    },
    status:input=>call('memory.status',withSession(input)),
    cite:input=>call('memory.cite',withSession(input)),
    recall:input=>call('memory.recall',withSession(input)),
    recover:async input=>{
      if(!input||Object.keys(input).join(',')!=='operation_id'||!(input.operation_id===null||typeof input.operation_id==='string'))return captureRefusal()
      const detached=withSession(input),revision=authRevision,session=detached.session_token
      const result=await call('memory.recover',detached),capture=captures.get(key(session,result?.operation_id))
      if(capture)await retireCompleted(session,revision,capture,result,{recovered:true})
      return result
    },
  })
  return Object.freeze({authority,memory,logout})
}
