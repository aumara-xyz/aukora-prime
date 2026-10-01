// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser-safe injection seam for the existing Prime UI transport. No URLs,
// owner signing material, enrollment or face redesign lives in this adapter.
import {canonicalJson,validateContract} from '../../contracts/src/shared.mjs'

export function createUiAdapters({call}={}) {
  if(typeof call!=='function')throw new TypeError('UNAVAILABLE: injected bridge call required')
  const reviews=new Map()
  let sessionToken=null
  const copy=value=>JSON.parse(canonicalJson(value))
  const key=(session,operationId)=>session+'\0'+operationId
  const authority=Object.freeze({
    loginChallenge:input=>call('owner.loginChallenge',copy(input)),
    async loginComplete(input) {
      const result=await call('owner.loginComplete',copy(input))
      if(result?.ok===true){sessionToken=result.session_token;reviews.clear()}
      return result
    },
    async approvalChallenge(input) {
      validateContract('OperationProposal',input.operation)
      if(reviews.size>=16)return {ok:false,error_code:'UNAVAILABLE',reason:'UI_REVIEW_QUOTA'}
      const detached=copy(input),result=await call('owner.approvalChallenge',detached)
      if(result?.ok===true && canonicalJson(result.operation)===canonicalJson(detached.operation))reviews.set(key(detached.session_token,detached.operation.operation_id),{operation:detached.operation,digest:result.operation_digest})
      return result
    },
    async approvalComplete(input) {
      validateContract('ApprovalProof',input.proof)
      const review=reviews.get(key(input.session_token,input.proof.operation_id)),operation=review?.operation
      if(!operation)return {ok:false,error_code:'UNAUTHORIZED',reason:'UI_EXACT_REVIEW_REQUIRED'}
      if(input.proof.operation_digest!==review.digest||input.proof.owner_id!==operation.owner_id||input.proof.audience!==operation.audience||input.proof.authorization_epoch!==operation.authorization_epoch)return {ok:false,error_code:'INVALID',reason:'UI_EXACT_PROOF_REQUIRED'}
      // The service and C recheck the entire operation/proof; this attachment
      // only supplies D's scoped observation for the existing UI method shape.
      reviews.delete(key(input.session_token,input.proof.operation_id))
      return call('owner.approvalComplete',copy({...input,operation}))
    },
    async declineApproval(input){reviews.delete(key(input.session_token,input.operation_id));return call('owner.declineApproval',copy(input))},
    status:input=>call('owner.status',copy(input)),
  })
  const withSession=input=>{
    if(typeof sessionToken!=='string')throw new Error('UNAUTHORIZED: owner login required')
    if(Object.hasOwn(input,'session_token'))throw new TypeError('INVALID: injected session only')
    return copy({...input,session_token:sessionToken})
  }
  const memory=Object.freeze({
    proposeSave:input=>call('memory.proposeSave',withSession(input)),
    save:input=>call('memory.save',withSession(input)),
    status:input=>call('memory.status',withSession(input)),
    cite:input=>call('memory.cite',withSession(input)),
    recall:input=>call('memory.recall',withSession(input)),
  })
  return Object.freeze({authority,memory,logout(){sessionToken=null;reviews.clear()}})
}
